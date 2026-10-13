"""Real-time tailer for IIS W3C extended log files.

* Watches one or more IIS log directories (one per site, e.g. ...\\LogFiles\\W3SVC1) with watchdog, plus a
  polling fallback (IIS buffers log writes and network shares don't always raise change events).
* Follows the newest file matching the pattern; on daily rollover it drains the old file to EOF before
  switching to the new one, so no lines are lost at midnight.
* Detects truncation / file replacement and honours `#Fields:` directives (re-emitted on IIS restarts).
* Never holds the file open between polls, so IIS log cleanup jobs can delete/rotate files freely.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from database import DEMO_LOG_DIR, ConfigStore

log = logging.getLogger("sentinel.tailer")

DEFAULT_FIELDS = [
    "date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username",
    "c-ip", "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
]

_STR_FIELDS = {
    "s-sitename": ("site", 128),
    "s-ip": ("s_ip", 64),
    "cs-method": ("cs_method", 16),
    "cs-uri-stem": ("cs_uri_stem", 2048),
    "cs-uri-query": ("cs_uri_query", 4096),
    "cs-username": ("cs_username", 256),
    "c-ip": ("c_ip", 64),
    "cs(User-Agent)": ("user_agent", 1024),
}
_INT_FIELDS = {
    "s-port": "s_port",
    "sc-status": "sc_status",
    "sc-substatus": "sc_substatus",
    "sc-win32-status": "sc_win32_status",
    "time-taken": "time_taken",
    "sc-bytes": "sc_bytes",
    "cs-bytes": "cs_bytes",
}
MAX_READ_BYTES = 4 * 1024 * 1024
MAX_PENDING = 1024 * 1024


def _int(v: str) -> int:
    if not v or v == "-":
        return 0
    try:
        return int(v)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return 0


def parse_w3c_line(line: str, fields: list[str], site: str = "") -> dict[str, Any] | None:
    parts = line.split(" ")
    if len(parts) != len(fields):
        return None
    raw = dict(zip(fields, parts))
    try:
        ts = datetime.strptime(f"{raw.get('date', '')} {raw.get('time', '')}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    entry: dict[str, Any] = {"ts": ts, "site": site}
    for f, (key, limit) in _STR_FIELDS.items():
        v = raw.get(f, "")
        entry[key] = "" if v == "-" else v[:limit]
    for f, key in _INT_FIELDS.items():
        entry[key] = _int(raw.get(f, ""))
    if entry["user_agent"]:
        entry["user_agent"] = entry["user_agent"].replace("+", " ")
    if not entry["c_ip"]:
        entry["c_ip"] = "0.0.0.0"
    if not entry["site"]:
        entry["site"] = site
    return entry


class DirectoryTailer:
    def __init__(self, directory: Path, pattern: str, start_at_end: bool) -> None:
        self.directory = directory
        self.pattern = pattern
        self.start_at_end = start_at_end
        self.site = directory.name
        self.current: Path | None = None
        self.offset = 0
        self.file_id: tuple[int, int] | None = None
        self.fields: list[str] = list(DEFAULT_FIELDS)
        self.pending = b""
        self.lines_parsed = 0
        self.parse_errors = 0
        self.rollovers = 0
        self.status = "initialising"
        self.last_line_at: float | None = None
        self._has_more = False

    @property
    def has_more(self) -> bool:
        return self._has_more

    def info(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "file": str(self.current) if self.current else None,
            "offset": self.offset,
            "status": self.status,
            "lines_parsed": self.lines_parsed,
            "parse_errors": self.parse_errors,
            "rollovers": self.rollovers,
            "last_line_at": self.last_line_at,
        }

    def _newest(self) -> Path | None:
        best: tuple[float, str, Path] | None = None
        try:
            for p in self.directory.glob(self.pattern):
                try:
                    st = p.stat()
                except OSError:
                    continue
                if not p.is_file():
                    continue
                key = (st.st_mtime, p.name, p)
                if best is None or key[:2] > best[:2]:
                    best = key
        except OSError as exc:
            log.warning("Cannot list %s: %s", self.directory, exc)
        return best[2] if best else None

    @staticmethod
    def _fid(st: os.stat_result) -> tuple[int, int]:
        return (st.st_ino, st.st_dev)

    def _find_last_fields(self, path: Path, end: int) -> list[str] | None:
        """Scan backwards from `end` for the most recent #Fields: directive."""
        chunk = 65536
        marker = b"#Fields:"
        try:
            with open(path, "rb") as f:
                pos = end
                carry = b""
                while pos > 0:
                    start = max(0, pos - chunk)
                    f.seek(start)
                    block = f.read(pos - start) + carry
                    idx = block.rfind(marker)
                    if idx != -1:
                        line_end = block.find(b"\n", idx)
                        line = block[idx: line_end if line_end != -1 else len(block)]
                        return line.decode("utf-8", "replace")[len("#Fields:"):].split()
                    carry = block[: len(marker)]
                    pos = start
        except OSError as exc:
            log.warning("Could not scan %s for #Fields: %s", path, exc)
        return None

    def _open(self, path: Path, initial: bool) -> None:
        st = path.stat()
        self.current = path
        self.file_id = self._fid(st)
        self.pending = b""
        if initial and self.start_at_end:
            self.offset = st.st_size
            self.fields = self._find_last_fields(path, st.st_size) or list(DEFAULT_FIELDS)
            log.info("Tailing %s from end (offset %d)", path, self.offset)
        else:
            self.offset = 0
            self.fields = list(DEFAULT_FIELDS)
            log.info("Tailing %s from start", path)

    def poll(self) -> list[dict[str, Any]]:
        self._has_more = False
        if not self.directory.is_dir():
            if self.status != "missing":
                log.warning("Log directory %s does not exist (will keep retrying)", self.directory)
            self.status = "missing"
            return []
        newest = self._newest()
        if newest is None:
            self.status = "no log files"
            return []
        out: list[dict[str, Any]] = []
        try:
            if self.current is None:
                self._open(newest, initial=True)
            elif newest != self.current:
                if self.current.exists():
                    out.extend(self._read())
                    if self._has_more:
                        return out
                log.info("Log rollover detected in %s: %s -> %s", self.directory, self.current.name, newest.name)
                self.rollovers += 1
                self._open(newest, initial=False)
            out.extend(self._read())
            self.status = "tailing"
        except FileNotFoundError:
            self.current = None
        except PermissionError as exc:
            self.status = "access denied"
            log.error("Permission denied reading %s: %s", self.current, exc)
        except OSError as exc:
            self.status = f"error: {exc}"
            log.error("Error reading %s: %s", self.current, exc)
        return out

    def _read(self) -> list[dict[str, Any]]:
        assert self.current is not None
        st = os.stat(self.current)
        fid = self._fid(st)
        if (self.file_id and fid != self.file_id and fid[0] != 0) or st.st_size < self.offset:
            log.warning("%s was truncated or replaced; restarting from offset 0", self.current)
            self.offset = 0
            self.pending = b""
            self.fields = list(DEFAULT_FIELDS)
            self.file_id = fid
        if st.st_size == self.offset:
            return []
        to_read = min(MAX_READ_BYTES, st.st_size - self.offset)
        with open(self.current, "rb") as f:
            f.seek(self.offset)
            data = f.read(to_read)
        self.offset += len(data)
        self._has_more = self.offset < st.st_size
        buf = self.pending + data
        lines = buf.split(b"\n")
        self.pending = lines.pop()
        if len(self.pending) > MAX_PENDING:
            log.warning("Discarding %d bytes of unterminated data in %s", len(self.pending), self.current)
            self.pending = b""

        out: list[dict[str, Any]] = []
        for raw in lines:
            line = raw.decode("utf-8", "replace").rstrip("\r")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    self.fields = line[len("#Fields:"):].split()
                continue
            entry = parse_w3c_line(line, self.fields, self.site)
            if entry is None:
                self.parse_errors += 1
                if self.parse_errors % 1000 == 1:
                    log.warning("Unparseable W3C line in %s (total %d): %.200s", self.current, self.parse_errors, line)
                continue
            out.append(entry)
        if out:
            self.lines_parsed += len(out)
            self.last_line_at = time.time()
        return out


class LogTailer:
    def __init__(self, config: ConfigStore, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self.config = config
        self.queue = queue
        self._tailers: dict[str, DirectoryTailer] = {}
        self._wake: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._observer: Any = None
        self._watches: dict[str, Any] = {}
        self._last_watch_attempt: dict[str, float] = {}
        self._cfg_sig: tuple[Any, ...] | None = None

    def status(self) -> list[dict[str, Any]]:
        return [t.info() for t in self._tailers.values()]

    def _notify(self) -> None:
        loop, wake = self._loop, self._wake
        if loop is None or wake is None:
            return
        try:
            loop.call_soon_threadsafe(wake.set)
        except RuntimeError:
            pass

    def _ensure_observer(self) -> bool:
        if self._observer is not None:
            return True
        try:
            from watchdog.observers import Observer

            self._observer = Observer()
            self._observer.daemon = True
            self._observer.start()
            return True
        except Exception:  # noqa: BLE001
            log.exception("watchdog unavailable; falling back to polling only")
            self._observer = None
            return False

    def _watch(self, directory: str) -> None:
        if directory in self._watches or not self._ensure_observer():
            return
        now = time.monotonic()
        if now - self._last_watch_attempt.get(directory, 0) < 30:
            return
        self._last_watch_attempt[directory] = now
        if not Path(directory).is_dir():
            return
        try:
            from watchdog.events import FileSystemEventHandler

            tailer = self

            class _Handler(FileSystemEventHandler):
                def on_any_event(self, event: Any) -> None:  # noqa: D401
                    tailer._notify()

            self._watches[directory] = self._observer.schedule(_Handler(), directory, recursive=False)
            log.info("watchdog watching %s", directory)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not watch %s (%s); polling only", directory, exc)

    def _sync_config(self) -> None:
        cfg = self.config.get("watchers")
        dirs = [str(Path(d)) for d in cfg.get("log_dirs") or []]
        sig = (tuple(dirs), cfg.get("file_pattern"), cfg.get("start_at_end"))
        if sig != self._cfg_sig:
            self._cfg_sig = sig
            for d in list(self._tailers):
                if d not in dirs:
                    del self._tailers[d]
                    watch = self._watches.pop(d, None)
                    if watch is not None and self._observer is not None:
                        try:
                            self._observer.unschedule(watch)
                        except Exception:  # noqa: BLE001
                            pass
                    log.info("Stopped tailing %s", d)
            for d in dirs:
                t = self._tailers.get(d)
                if t is None:
                    self._tailers[d] = DirectoryTailer(Path(d), cfg.get("file_pattern") or "*.log", bool(cfg.get("start_at_end", True)))
                else:
                    t.pattern = cfg.get("file_pattern") or "*.log"
        for d in self._tailers:
            self._watch(d)

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        try:
            while True:
                self._sync_config()
                more = False
                for tailer in list(self._tailers.values()):
                    try:
                        entries = await asyncio.to_thread(tailer.poll)
                    except Exception:  # noqa: BLE001
                        log.exception("Tailer for %s failed", tailer.directory)
                        continue
                    for e in entries:
                        await self.queue.put(e)
                    more = more or tailer.has_more
                if more:
                    await asyncio.sleep(0)
                    continue
                interval = float(self.config.value("watchers", "poll_interval", 2))
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()
        finally:
            self.stop()

    def stop(self) -> None:
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            self._observer = None
            self._watches.clear()


# --------------------------------------------------------------------------------------
# Demo traffic generator (SENTINEL_DEMO=1) - writes genuine W3C files so the full pipeline is exercised.
# --------------------------------------------------------------------------------------
DEMO_FIELDS = (
    "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) "
    "cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken"
)
_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
_PAGES = [
    ("/", 200, 18000), ("/default.aspx", 200, 22000), ("/api/orders", 200, 3400), ("/api/customers", 200, 5200),
    ("/css/site.css", 200, 9100), ("/js/app.js", 200, 41000), ("/images/logo.png", 304, 0), ("/login.aspx", 200, 7600),
    ("/reports/q3.pdf", 200, 480000), ("/api/health", 200, 120), ("/favicon.ico", 404, 1245),
]
_SQLI = [
    "id=1'+UNION+SELECT+username,password+FROM+users--",
    "id=1'+OR+'1'='1",
    "q=" + quote("'; DROP TABLE orders;--"),
    "id=1;WAITFOR+DELAY+'0:0:5'--",
    "cat=" + quote("1 AND 1=1 --"),
    "user=admin'+AND+SLEEP(5)%23",
]
_XSS = [
    "q=" + quote("<script>alert(document.cookie)</script>"),
    "name=" + quote('"><img src=x onerror=alert(1)>'),
    "redirect=javascript:alert(1)",
    "s=" + quote("<svg/onload=prompt(1)>"),
]
_SCAN = ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin/config.php", "/backup.zip", "/.git/config",
         "/cgi-bin/test.cgi", "/xmlrpc.php", "/server-status", "/actuator/env"]


class DemoTrafficGenerator:
    def __init__(self, directory: Path = DEMO_LOG_DIR) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.normal_ips = [f"10.20.{random.randint(0, 9)}.{random.randint(2, 250)}" for _ in range(25)] + [
            f"{random.choice([52, 73, 98, 142, 172, 203])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(20)
        ]
        self.attackers = ["185.220.101.47", "45.155.205.233", "103.75.190.12", "91.240.118.172", "193.142.146.35"]
        self.rollover_seconds = float(os.environ.get("SENTINEL_DEMO_ROLLOVER_SECONDS", "0") or 0)
        self._segment = 0
        self._segment_started = time.monotonic()
        self._campaign: dict[str, Any] | None = None
        self._next_campaign = time.monotonic() + 20

    def _path(self) -> Path:
        now = datetime.now(timezone.utc)
        if self.rollover_seconds and time.monotonic() - self._segment_started > self.rollover_seconds:
            self._segment += 1
            self._segment_started = time.monotonic()
        suffix = f"_{self._segment}" if self._segment else ""
        return self.directory / f"u_ex{now:%y%m%d}{suffix}.log"

    def _line(self, ip: str, method: str, stem: str, query: str, status: int, nbytes: int, tt: int, ua: str, user: str = "-") -> str:
        now = datetime.now(timezone.utc)
        sub = 0 if status != 401 else 2
        win32 = 0 if status < 400 else (2 if status == 404 else 5)
        return (
            f"{now:%Y-%m-%d %H:%M:%S} 10.0.0.15 {method} {stem} {query or '-'} 443 {user} {ip} "
            f"{ua.replace(' ', '+')} - {status} {sub} {win32} {nbytes} {random.randint(300, 900)} {tt}"
        )

    def _normal(self) -> str:
        stem, status, size = random.choice(_PAGES)
        if random.random() < 0.02:
            status, size = 500, 1208
        tt = max(1, int(random.lognormvariate(3.6, 0.7)))
        if random.random() < 0.005:
            tt = random.randint(4000, 12000)
        return self._line(random.choice(self.normal_ips), random.choice(["GET"] * 8 + ["POST"]), stem, "", status,
                          max(0, int(size * random.uniform(0.8, 1.2))), tt, random.choice(_UAS))

    def _attack(self) -> str:
        c = self._campaign
        assert c is not None
        kind = c["kind"]
        ip = c["ip"]
        if kind == "sqli":
            return self._line(ip, "GET", random.choice(["/products.aspx", "/api/orders", "/search.aspx"]),
                              random.choice(_SQLI), random.choice([500, 200, 403]), 1400, random.randint(20, 900),
                              "sqlmap/1.8.2#stable (https://sqlmap.org)")
        if kind == "xss":
            return self._line(ip, "GET", "/search.aspx", random.choice(_XSS), 200, 6100, random.randint(10, 120), random.choice(_UAS))
        if kind == "scan":
            return self._line(ip, "GET", random.choice(_SCAN), "", 404, 1245, random.randint(1, 15), "Mozilla/5.0 zgrab/0.x")
        if kind == "brute":
            return self._line(ip, "POST", "/login.aspx", "", 401, 1293, random.randint(30, 200), random.choice(_UAS))
        return self._line(ip, "GET", "/reports/q3.pdf", "", 200, 480000, random.randint(40, 300), "python-requests/2.32")

    async def run(self) -> None:
        log.warning("DEMO MODE: generating synthetic IIS traffic into %s", self.directory)
        current: Path | None = None
        while True:
            try:
                path = self._path()
                lines: list[str] = []
                if path != current or not path.exists():
                    current = path
                    if not path.exists():
                        now = datetime.now(timezone.utc)
                        lines += [
                            "#Software: Microsoft Internet Information Services 10.0",
                            "#Version: 1.0",
                            f"#Date: {now:%Y-%m-%d %H:%M:%S}",
                            f"#Fields: {DEMO_FIELDS}",
                        ]
                mono = time.monotonic()
                if self._campaign is None and mono >= self._next_campaign:
                    self._campaign = {
                        "kind": random.choice(["sqli", "xss", "scan", "brute", "flood", "sqli", "scan"]),
                        "ip": random.choice(self.attackers),
                        "until": mono + random.uniform(15, 45),
                    }
                    log.info("DEMO: attack campaign %s from %s", self._campaign["kind"], self._campaign["ip"])
                if self._campaign and mono > self._campaign["until"]:
                    self._campaign = None
                    self._next_campaign = mono + random.uniform(30, 90)

                for _ in range(random.randint(1, 6)):
                    lines.append(self._normal())
                if self._campaign:
                    burst = 12 if self._campaign["kind"] == "flood" else random.randint(1, 4)
                    lines.extend(self._attack() for _ in range(burst))

                with open(path, "a", encoding="utf-8", newline="") as f:
                    f.write("\r\n".join(lines) + "\r\n")
            except Exception:  # noqa: BLE001
                log.exception("Demo generator error")
            await asyncio.sleep(random.uniform(0.3, 0.9))
