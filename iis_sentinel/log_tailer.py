"""Real-time tailer for IIS W3C extended log files.

* A log path can be one site's folder (...\\LogFiles\\W3SVC1) or the parent holding every site's W3SVC<n>
  folder; SiteSetTailer discovers the sites (and new ones created later) and tails them all.
* Watches local directories with watchdog, plus a polling fallback (IIS buffers log writes and network
  shares don't always raise change events).
* Follows the newest file matching the pattern; on daily rollover it drains the old file to EOF before
  switching to the new one, so no lines are lost at midnight.
* Start modes for a file seen for the first time: `end` (new lines only), `tail` (last N lines) or `full`
  (the whole current file). Read positions are persisted, so a restart resumes exactly where it stopped.
* Detects truncation / file replacement and honours `#Fields:` directives (re-emitted on IIS restarts).
* Never holds the file open between polls, so IIS log cleanup jobs can delete/rotate files freely.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from urllib.parse import quote

from database import DEMO_LOG_ROOT, DEMO_SERVERS, IS_WINDOWS, Config, ConfigStore, run_db, utcnow

if TYPE_CHECKING:
    from database import ServerRegistry
    from remote_manager import RemoteManager

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
# W3SVC<n> per site; a bare W3SVC folder is IIS centralised (server-level) W3C logging.
SITE_DIR_RE = re.compile(r"^W3SVC\d*$", re.IGNORECASE)


class OffsetStore:
    """Last fully-consumed byte offset per log file, persisted in the config table so restarts resume."""

    KEY = "_tail_offsets"
    MAX_AGE = 14 * 86400

    def __init__(self) -> None:
        self._data: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()
        self._dirty = False
        self.loaded = False

    @staticmethod
    def _key(path: Path | str) -> str:
        key = str(path)
        return key.lower() if IS_WINDOWS else key

    def get(self, path: Path | str) -> int | None:
        with self._lock:
            rec = self._data.get(self._key(path))
        return int(rec["offset"]) if rec else None

    def put(self, path: Path | str, offset: int) -> None:
        with self._lock:
            key = self._key(path)
            rec = self._data.get(key)
            if rec is None or rec["offset"] != offset:
                self._data[key] = {"offset": offset, "at": time.time()}
                self._dirty = True

    async def load(self) -> None:
        if self.loaded:
            return

        async def _op(s):  # type: ignore[no-untyped-def]
            row = await s.get(Config, self.KEY)
            return row.value if row else None

        try:
            raw = await run_db(_op)
            data = json.loads(raw) if raw else {}
            with self._lock:
                for k, v in data.items():
                    self._data.setdefault(k, v)
        except Exception:  # noqa: BLE001
            log.exception("Could not load saved log offsets; files start per their start mode")
        self.loaded = True

    async def flush(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            cutoff = time.time() - self.MAX_AGE
            self._data = {k: v for k, v in self._data.items() if v["at"] >= cutoff}
            payload = json.dumps(self._data)
            self._dirty = False

        async def _op(s):  # type: ignore[no-untyped-def]
            row = await s.get(Config, self.KEY)
            if row is None:
                s.add(Config(key=self.KEY, value=payload, updated_at=utcnow()))
            else:
                row.value = payload
                row.updated_at = utcnow()

        try:
            await run_db(_op)
        except Exception:  # noqa: BLE001
            self._dirty = True
            log.exception("Could not persist log offsets")


OFFSETS = OffsetStore()


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
    def __init__(self, directory: Path, pattern: str, start_mode: str = "end", tail_lines: int = 1000,
                 resume: bool = True) -> None:
        self.directory = directory
        self.pattern = pattern
        self.start_mode = start_mode if start_mode in ("end", "tail", "full") else "end"
        self.tail_lines = max(1, int(tail_lines))
        self.resume = resume
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
        self._born_empty = False

    @property
    def has_more(self) -> bool:
        return self._has_more

    def info(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "site": self.site,
            "file": str(self.current) if self.current else None,
            "offset": self.offset,
            "start_mode": self.start_mode,
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

    @staticmethod
    def _tail_offset(path: Path, size: int, lines: int) -> int:
        """Byte offset where the last `lines` complete lines of the file begin."""
        chunk = 65536
        pos, found = size, 0
        with open(path, "rb") as f:
            while pos > 0:
                start = max(0, pos - chunk)
                f.seek(start)
                block = f.read(pos - start)
                idx = len(block)
                while True:
                    idx = block.rfind(b"\n", 0, idx)
                    if idx == -1:
                        break
                    found += 1
                    if found == lines + 1:
                        return start + idx + 1
                pos = start
        return 0

    def _open(self, path: Path, initial: bool) -> None:
        st = path.stat()
        self.current = path
        self.file_id = self._fid(st)
        self.pending = b""
        saved = OFFSETS.get(path) if initial and self.resume else None
        if initial and self._born_empty:
            initial = False
        if saved is not None and saved <= st.st_size:
            self.offset = saved
            self.fields = (self._find_last_fields(path, saved) if saved else None) or list(DEFAULT_FIELDS)
            log.info("Resuming %s at saved offset %d of %d", path, saved, st.st_size)
        elif initial and self.start_mode == "end":
            self.offset = st.st_size
            self.fields = self._find_last_fields(path, st.st_size) or list(DEFAULT_FIELDS)
            log.info("Tailing %s from end (offset %d)", path, self.offset)
        elif initial and self.start_mode == "tail":
            self.offset = self._tail_offset(path, st.st_size, self.tail_lines)
            self.fields = (self._find_last_fields(path, self.offset) if self.offset else None) or list(DEFAULT_FIELDS)
            log.info("Tailing %s from the last %d lines (offset %d of %d)", path, self.tail_lines, self.offset, st.st_size)
        else:
            self.offset = 0
            self.fields = list(DEFAULT_FIELDS)
            log.info("Tailing %s from start", path)
        OFFSETS.put(path, self.offset)

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
            # The first file to appear was created after we started watching: read it from the start.
            self._born_empty = True
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
        OFFSETS.put(self.current, self.offset - len(self.pending))

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


class SiteSetTailer:
    """Tails every IIS site under one log root.

    * Root holds log files itself -> it is a single site's folder (W3SVC1); tail it directly.
    * Otherwise tail every W3SVC<n> sub-folder (falling back to any sub-folder holding matching files).
    The root is rescanned periodically so sites created later are picked up without a restart; their
    first file is read from the start so nothing logged since the site was created is missed.
    """

    RESCAN_SECONDS = 60.0

    def __init__(self, root: Path, pattern: str, start_mode: str = "end", tail_lines: int = 1000,
                 resume: bool = True) -> None:
        self.root = root
        self.pattern = pattern
        self.start_mode = start_mode
        self.tail_lines = tail_lines
        self.resume = resume
        self.tailers: dict[str, DirectoryTailer] = {}
        self.layout = "unknown"
        self.status = "initialising"
        self._scanned_at = 0.0
        self._scanned_ok = False
        self._discovered: list[str] = []
        self._has_more = False

    @property
    def directory(self) -> Path:
        return self.root

    @property
    def has_more(self) -> bool:
        return self._has_more

    def take_discovered(self) -> list[str]:
        """Site folders that appeared after the first successful scan (for 'new site' notifications)."""
        out, self._discovered = self._discovered, []
        return out

    def _has_logs(self, directory: Path) -> bool:
        try:
            return any(p.is_file() for p in directory.glob(self.pattern))
        except OSError:
            return False

    def _scan(self) -> None:
        self._scanned_at = time.monotonic()
        if not self.root.is_dir():
            self.status = "missing"
            return
        if self._has_logs(self.root):
            dirs, layout = [self.root], "single site"
        else:
            try:
                subs = sorted((p for p in self.root.iterdir() if p.is_dir()), key=lambda p: (len(p.name), p.name.lower()))
            except OSError as exc:
                self.status = "access denied" if isinstance(exc, PermissionError) else f"error: {exc}"
                return
            sites = [p for p in subs if SITE_DIR_RE.match(p.name)]
            dirs = sites or [p for p in subs if self._has_logs(p)]
            layout = "multi-site"
        self.layout = layout
        current = {str(d): d for d in dirs}
        for key in list(self.tailers):
            if key not in current:
                log.info("Site log folder %s disappeared; no longer tailing it", key)
                del self.tailers[key]
        for key, d in current.items():
            if key in self.tailers:
                continue
            if self._scanned_ok:
                # A site created while we were running: read its first file from the start.
                self.tailers[key] = DirectoryTailer(d, self.pattern, "full", self.tail_lines, self.resume)
                self._discovered.append(d.name)
                log.info("New IIS site log folder discovered: %s", d)
            else:
                self.tailers[key] = DirectoryTailer(d, self.pattern, self.start_mode, self.tail_lines, self.resume)
        self._scanned_ok = True
        if layout == "multi-site" and dirs:
            log.debug("%s: tailing %d site folder(s)", self.root, len(dirs))

    def poll(self) -> list[dict[str, Any]]:
        self._has_more = False
        if not self.tailers or time.monotonic() - self._scanned_at >= self.RESCAN_SECONDS:
            self._scan()
        if not self.root.is_dir():
            self.status = "missing"
            return []
        if not self.tailers:
            if not self.status.startswith(("error", "access denied")):
                self.status = "no log files"
            return []
        out: list[dict[str, Any]] = []
        statuses: list[str] = []
        for tailer in list(self.tailers.values()):
            out.extend(tailer.poll())
            self._has_more = self._has_more or tailer.has_more
            statuses.append(tailer.status)
        if any(s == "tailing" for s in statuses):
            self.status = "tailing"
        elif "access denied" in statuses:
            self.status = "access denied"
        else:
            self.status = next((s for s in statuses if s.startswith("error")), statuses[0] if statuses else "no log files")
        return out

    def info(self) -> dict[str, Any]:
        sites = [t.info() for t in self.tailers.values()]
        last = [s["last_line_at"] for s in sites if s.get("last_line_at")]
        return {
            "directory": str(self.root),
            "layout": self.layout,
            "file": sites[0]["file"] if len(sites) == 1 else (f"{len(sites)} sites" if sites else None),
            "status": self.status,
            "start_mode": self.start_mode,
            "site_count": len(sites),
            "sites": sites,
            "lines_parsed": sum(s["lines_parsed"] for s in sites),
            "parse_errors": sum(s["parse_errors"] for s in sites),
            "rollovers": sum(s["rollovers"] for s in sites),
            "last_line_at": max(last) if last else None,
        }


def discover_sites(root: Path, pattern: str) -> dict[str, Any]:
    """Read-only probe of a log root (used by the connection test): which site folders would be tailed."""
    probe = SiteSetTailer(root, pattern)
    probe._scan()  # noqa: SLF001
    if probe.status in ("missing", "access denied") or probe.status.startswith("error"):
        return {"ok": False, "error": f"{root}: {probe.status}"}
    sites = []
    for t in probe.tailers.values():
        newest = t._newest()  # noqa: SLF001
        try:
            files = sum(1 for p in t.directory.glob(pattern) if p.is_file())
        except OSError:
            files = 0
        sites.append({"site": t.directory.name, "files": files, "newest": newest.name if newest else None})
    return {"ok": True, "layout": probe.layout, "sites": sites, "files": sum(s["files"] for s in sites),
            "newest": next((s["newest"] for s in sites if s["newest"]), None)}


StatusCallback = Callable[[int, str, bool, "str | None"], Awaitable[None]]
SiteCallback = Callable[[int, list[str]], Awaitable[None]]


class LogTailer:
    """Runs one independent task per monitored server.

    Remote servers are read over their UNC path through RemoteManager.read_remote_logs(); the optional local
    server (Sentinel co-located on an IIS box) is read from `watchers.log_dirs`. A failing server only backs
    off its own task, so one offline IIS box never delays the others.
    """

    RECONCILE_SECONDS = 5.0

    def __init__(self, config: ConfigStore, registry: "ServerRegistry", remote: "RemoteManager",
                 queue: asyncio.Queue[dict[str, Any]], on_status: StatusCallback | None = None,
                 on_sites: SiteCallback | None = None) -> None:
        self.config = config
        self.registry = registry
        self.remote = remote
        self.queue = queue
        self.on_status = on_status
        self.on_sites = on_sites
        self._tasks: dict[int, tuple[tuple[Any, ...], asyncio.Task[None]]] = {}
        self._reconcile = asyncio.Event()
        self._local_tailers: dict[str, SiteSetTailer] = {}
        self._local_wake: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._observer: Any = None
        self._watches: dict[str, Any] = {}
        self._last_watch_attempt: dict[str, float] = {}
        self._cfg_sig: tuple[Any, ...] | None = None

    def reload(self) -> None:
        self._reconcile.set()

    def status(self) -> list[dict[str, Any]]:
        out = []
        for server in self.registry.all(enabled_only=False):
            sid = server["id"]
            base = {"server_id": sid, "server_name": server["server_name"],
                    "connection": self.registry.status.get(sid, {}).get("logs")}
            if server.get("local"):
                out.extend({**base, **t.info()} for t in list(self._local_tailers.values()))
            else:
                info = self.remote.tailer_status(sid) or {"directory": server.get("log_unc_path") or None,
                                                          "status": "not configured" if not server.get("log_unc_path") else "initialising",
                                                          "lines_parsed": 0, "parse_errors": 0, "rollovers": 0}
                out.append({**base, **info})
        return out

    # ------------------------------------------------------------------ orchestration
    @staticmethod
    def _signature(server: dict[str, Any]) -> tuple[Any, ...]:
        return (server.get("log_unc_path"), tuple(server.get("log_dirs") or ()), server.get("ip_address"),
                server.get("winrm_username"), server.get("winrm_password"), server.get("log_start_mode"),
                server.get("log_tail_lines"))

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._local_wake = asyncio.Event()
        await OFFSETS.load()
        try:
            while True:
                self._reconcile_tasks()
                try:
                    await asyncio.wait_for(self._reconcile.wait(), timeout=self.RECONCILE_SECONDS)
                except asyncio.TimeoutError:
                    pass
                self._reconcile.clear()
                await OFFSETS.flush()
        finally:
            for _sig, task in self._tasks.values():
                task.cancel()
            await asyncio.gather(*(t for _s, t in self._tasks.values()), return_exceptions=True)
            self._tasks.clear()
            self.stop()
            try:
                await OFFSETS.flush()
            except BaseException:  # noqa: BLE001
                pass

    def _reconcile_tasks(self) -> None:
        desired = {s["id"]: s for s in self.registry.all(enabled_only=True)}
        for sid in list(self._tasks):
            sig, task = self._tasks[sid]
            server = desired.get(sid)
            if server is None or sig != self._signature(server) or task.done():
                if task.done() and not task.cancelled() and task.exception():
                    log.error("Log task for server %s died: %r (restarting)", sid, task.exception())
                task.cancel()
                del self._tasks[sid]
                if server is None:
                    self.remote.forget(sid)
                    log.info("Stopped log monitoring for server %s", sid)
        for sid, server in desired.items():
            if sid not in self._tasks:
                task = asyncio.create_task(self._server_loop(sid), name=f"logs:{server['server_name']}")
                self._tasks[sid] = (self._signature(server), task)
                log.info("Started log monitoring for %s", server["server_name"])

    async def _report(self, server_id: int, ok: bool, error: str | None) -> None:
        if self.registry.set_status(server_id, "logs", ok, error):
            name = self.registry.name(server_id)
            if ok:
                log.info("[%s] log feed online", name)
            else:
                log.error("[%s] log feed offline: %s", name, error)
            if self.on_status is not None:
                try:
                    await self.on_status(server_id, "logs", ok, error)
                except Exception:  # noqa: BLE001
                    log.exception("Log status callback failed")

    async def _server_loop(self, server_id: int) -> None:
        backoff = 2.0
        while True:
            server = self.registry.get(server_id)
            if server is None:
                return
            name = server["server_name"]
            try:
                if server.get("local"):
                    entries, more = await self._poll_local()
                    discovered = [s for t in list(self._local_tailers.values()) for s in t.take_discovered()]
                else:
                    entries, more = await self.remote.read_remote_logs(server_id)
                    discovered = self.remote.take_discovered(server_id)
                await self._report(server_id, True, None)
                backoff = 2.0
                if discovered and self.on_sites is not None:
                    try:
                        await self.on_sites(server_id, discovered)
                    except Exception:  # noqa: BLE001
                        log.exception("Site discovery callback failed")
                for e in entries:
                    e["server_id"] = server_id
                    e["server_name"] = name
                    await self.queue.put(e)
                if more:
                    await asyncio.sleep(0)
                    continue
                await self._idle(bool(server.get("local")))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                await self._report(server_id, False, f"{type(exc).__name__}: {exc}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    async def _idle(self, local: bool) -> None:
        interval = float(self.config.value("watchers", "poll_interval", 2))
        if local and self._local_wake is not None:
            try:
                await asyncio.wait_for(self._local_wake.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            self._local_wake.clear()
        else:
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------ local server (watchdog + polling)
    async def _poll_local(self) -> tuple[list[dict[str, Any]], bool]:
        self._sync_local()
        out: list[dict[str, Any]] = []
        more = False
        for tailer in list(self._local_tailers.values()):
            try:
                out.extend(await asyncio.to_thread(tailer.poll))
            except Exception:  # noqa: BLE001
                log.exception("Local tailer for %s failed", tailer.directory)
                continue
            more = more or tailer.has_more
        return out, more

    def _notify(self) -> None:
        loop, wake = self._loop, self._local_wake
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

            # Recursive: the directory may be the parent of every site's W3SVC<n> folder.
            self._watches[directory] = self._observer.schedule(_Handler(), directory, recursive=True)
            log.info("watchdog watching %s", directory)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not watch %s (%s); polling only", directory, exc)

    def _sync_local(self) -> None:
        cfg = self.config.get("watchers")
        dirs = [str(Path(d)) for d in cfg.get("log_dirs") or []]
        pattern = cfg.get("file_pattern") or "*.log"
        mode = (cfg.get("log_start_mode") or "end", int(cfg.get("log_tail_lines") or 1000))
        sig = (tuple(dirs), pattern, mode)
        if sig != self._cfg_sig:
            # Changing the start mode is an explicit request to re-read; otherwise resume saved offsets.
            mode_changed = self._cfg_sig is not None and self._cfg_sig[2] != mode
            self._cfg_sig = sig
            for d in list(self._local_tailers):
                if d not in dirs or mode_changed or self._local_tailers[d].pattern != pattern:
                    del self._local_tailers[d]
                if d not in dirs:
                    watch = self._watches.pop(d, None)
                    if watch is not None and self._observer is not None:
                        try:
                            self._observer.unschedule(watch)
                        except Exception:  # noqa: BLE001
                            pass
            for d in dirs:
                if d not in self._local_tailers:
                    self._local_tailers[d] = SiteSetTailer(Path(d), pattern, mode[0], mode[1], resume=not mode_changed)
        for d in self._local_tailers:
            self._watch(d)

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


_PORTAL_PAGES = [
    ("/portal/", 200, 26000), ("/portal/news.aspx", 200, 31000), ("/portal/directory.aspx", 200, 18000),
    ("/portal/hr/timesheet.aspx", 200, 14000), ("/portal/search.aspx", 200, 9000), ("/portal/css/portal.css", 304, 0),
]
_API_PAGES = [
    ("/api/v2/orders", 200, 2400), ("/api/v2/orders/submit", 201, 600), ("/api/v2/inventory", 200, 8800),
    ("/api/v2/pricing", 200, 1900), ("/api/v2/health", 200, 90),
]
# W3SVC id -> (IIS site name, pages, campaign interval multiplier, error incidents, slow-response rate)
DEMO_SITES: dict[int, tuple[str, list[tuple[str, int, int]], float, bool, float]] = {
    1: ("Default Web Site", _PAGES, 1.0, False, 0.004),
    2: ("Portal", _PORTAL_PAGES, 4.0, False, 0.02),
    3: ("OrdersAPI", _API_PAGES, 3.0, True, 0.004),
}


class DemoTrafficGenerator:
    def __init__(self, directory: Path, server_ip: str = "10.0.0.15", pages: list[tuple[str, int, int]] | None = None,
                 campaign_scale: float = 1.0, incidents: bool = False, slow_rate: float = 0.005) -> None:
        self.directory = directory
        self.server_ip = server_ip
        self.pages = pages or _PAGES
        self.campaign_scale = campaign_scale
        self.incidents = incidents
        self.slow_rate = slow_rate
        self._incident_until = 0.0
        self._next_incident = time.monotonic() + random.uniform(60, 240)
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
        self._next_campaign = time.monotonic() + random.uniform(15, 60) * campaign_scale

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
            f"{now:%Y-%m-%d %H:%M:%S} {self.server_ip} {method} {stem} {query or '-'} 443 {user} {ip} "
            f"{ua.replace(' ', '+')} - {status} {sub} {win32} {nbytes} {random.randint(300, 900)} {tt}"
        )

    def _normal(self) -> str:
        stem, status, size = random.choice(self.pages)
        mono = time.monotonic()
        if self.incidents and mono >= self._next_incident:
            # A broken deploy / backend outage: a burst of 500/503s on this site.
            self._incident_until = mono + random.uniform(10, 25)
            self._next_incident = mono + random.uniform(180, 420)
            log.info("DEMO: HTTP 5xx incident on %s", self.directory)
        if mono < self._incident_until and random.random() < 0.7:
            status, size = random.choice([500, 503, 500]), 1208
        elif random.random() < 0.002:
            status, size = 500, 1208
        tt = max(1, int(random.lognormvariate(3.6, 0.7)))
        if random.random() < self.slow_rate:
            tt = random.randint(10500, 30000)
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
                    self._next_campaign = mono + random.uniform(30, 90) * self.campaign_scale

                for _ in range(random.randint(1, 4)):
                    lines.append(self._normal())
                if self._campaign:
                    burst = 12 if self._campaign["kind"] == "flood" else random.randint(1, 4)
                    lines.extend(self._attack() for _ in range(burst))

                with open(path, "a", encoding="utf-8", newline="") as f:
                    f.write("\r\n".join(lines) + "\r\n")
            except Exception:  # noqa: BLE001
                log.exception("Demo generator error")
            await asyncio.sleep(random.uniform(0.3, 0.9))


def demo_site_ids(server_name: str) -> list[int]:
    """IIS-03 hosts two sites, the other demo servers three (so per-server site lists differ)."""
    return [1, 2] if server_name.endswith("03") else [1, 2, 3]


async def run_demo_fleet() -> None:
    """Generators for every site of every simulated demo server, writing <server>\\W3SVC<id> folders under the
    parent log root each MonitoredServer row points at."""
    gens = []
    for i, (name, ip) in enumerate(DEMO_SERVERS, start=1):
        if not ip.startswith("127."):
            continue
        for site_id in demo_site_ids(name):
            _site, pages, scale, incidents, slow = DEMO_SITES[site_id]
            gens.append(DemoTrafficGenerator(DEMO_LOG_ROOT / name / f"W3SVC{site_id}", server_ip=f"10.0.{i}.15",
                                             pages=pages, campaign_scale=scale, incidents=incidents, slow_rate=slow))
    await asyncio.gather(*(g.run() for g in gens))
