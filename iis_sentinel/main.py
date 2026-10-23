"""IIS Sentinel - FastAPI application: REST API, WebSocket push and background task orchestration.

Run:  python main.py            (or: uvicorn main:app --host 0.0.0.0 --port 1337)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from typing import Any, AsyncIterator, Awaitable, Callable, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, desc, func, insert, or_, select, text, update

from ad_auth import ADAuthenticator
from alert_catalog import ANOMALY_EVENTS, SIGNATURE_EVENTS
from alert_catalog import catalog as alert_catalog
from baseliner import Baseliner
from database import (
    BASE_DIR,
    DATA_DIR,
    DEFAULT_CONFIG,
    DEMO_MODE,
    FTS_COLUMNS,
    FTS_STATE,
    FTS_TABLE,
    LOCAL_SERVER_ID,
    SECRET_FIELDS,
    SECRET_MASK,
    ActionableAlert,
    AllowlistEntry,
    BannedIP,
    BannedRange,
    allowlist_overlaps,
    parse_network,
    ConfigStore,
    LogEntry,
    ScheduledReport,
    ServerRegistry,
    SessionLocal,
    SystemMetric,
    engine,
    fts_backfill_step,
    get_or_create_session_secret,
    init_db,
    iso,
    kv_get,
    kv_put,
    run_db,
    utcnow,
)
from events import AlertManager, Hub
from firewall import PROVIDERS as FIREWALL_PROVIDERS
from firewall import FirewallError, FirewallManager
import sonicwall_api
from geoip import GeoResolver
from http_monitor import HttpMonitor
from log_tailer import LogTailer, run_demo_fleet
from abuseipdb import AbuseIPDB
from abuseipdb import normalize_ip as normalize_abuse_ip
from defense_engine import DefenseEngine
from whois_lookup import WhoisClient, calculate_escalation_cidr, network_for_scope
from mailer import Mailer, render_alert_html
from remote_manager import RemoteError, RemoteManager, validate_ban_ip
from reporter import Reporter
from system_health import HealthMonitor
from threat_rules import ThreatEngine

STATIC_DIR = BASE_DIR / "static"
COOKIE_NAME = "sentinel_session"
SESSION_TTL = int(os.environ.get("SENTINEL_SESSION_HOURS", "12")) * 3600
COOKIE_SECURE = os.environ.get("SENTINEL_COOKIE_SECURE", "0").lower() in ("1", "true", "yes")


# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------
def _setup_logging() -> None:
    root = logging.getLogger()
    if any(getattr(h, "_sentinel", False) for h in root.handlers):
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)-20s %(message)s")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console._sentinel = True  # type: ignore[attr-defined]
    fileh = RotatingFileHandler(DATA_DIR / "sentinel.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fileh.setFormatter(fmt)
    fileh._sentinel = True  # type: ignore[attr-defined]
    root.addHandler(console)
    root.addHandler(fileh)
    root.setLevel(os.environ.get("SENTINEL_LOG_LEVEL", "INFO").upper())
    for noisy in ("exchangelib", "apscheduler.executors", "watchdog", "aiosqlite", "ldap3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


_setup_logging()
log = logging.getLogger("sentinel.main")


# --------------------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------------------
class SessionSigner:
    def __init__(self, secret: bytes, ttl: int) -> None:
        self._key = hashlib.sha256(secret).digest()
        self.ttl = ttl
        self._revoked: dict[str, float] = {}

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

    def issue(self, username: str, display: str, source: str) -> str:
        payload = {"u": username, "d": display, "s": source, "exp": int(time.time()) + self.ttl, "n": secrets.token_hex(8)}
        body = self._b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str | None) -> dict[str, Any] | None:
        if not token or token.count(".") != 1:
            return None
        body, sig = token.split(".")
        expected = self._b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            payload = json.loads(self._unb64(body))
        except (ValueError, json.JSONDecodeError):
            return None
        if payload.get("exp", 0) < time.time() or payload.get("n") in self._revoked:
            return None
        return payload

    def revoke(self, token: str | None) -> None:
        payload = self.verify(token)
        if payload:
            self._revoked[payload["n"]] = payload["exp"]
            now = time.time()
            self._revoked = {k: v for k, v in self._revoked.items() if v > now}


class LoginThrottle:
    def __init__(self, max_failures: int = 5, window: int = 300) -> None:
        self.max = max_failures
        self.window = window
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def blocked(self, key: str) -> int:
        q = self._fails[key]
        now = time.time()
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            return int(self.window - (now - q[0])) + 1
        return 0

    def fail(self, key: str) -> None:
        self._fails[key].append(time.time())

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)


# --------------------------------------------------------------------------------------
# Processing pipeline: tailer queue -> threat engine + baseliner -> DB + WebSocket + alerts
# --------------------------------------------------------------------------------------
class Pipeline:
    FLUSH_SIZE = 500
    FLUSH_SECONDS = 5.0
    WS_SECONDS = 0.3
    MAX_BUFFER = 50000

    def __init__(self, queue: asyncio.Queue[dict[str, Any]], threats: ThreatEngine, baseliner: Baseliner,
                 alerts: AlertManager, hub: Hub, http: HttpMonitor,
                 site_name: Callable[[int, str], str] = lambda _sid, _site: "",
                 enrich: Callable[[str], Awaitable[dict[str, Any]]] | None = None) -> None:
        self.queue = queue
        self.threats = threats
        self.baseliner = baseliner
        self.alerts = alerts
        self.hub = hub
        self.http = http
        self.site_name = site_name
        self.enrich = enrich
        self._bg: set[asyncio.Task[Any]] = set()
        self.recent: deque[dict[str, Any]] = deque(maxlen=300)
        self._db_buffer: list[dict[str, Any]] = []
        self._ws_buffer: list[dict[str, Any]] = []
        self._seq = 0
        self.processed = 0
        self.dropped = 0
        self.db_errors = 0
        self._rate: deque[tuple[float, int]] = deque(maxlen=120)

    def stats(self) -> dict[str, Any]:
        now = time.monotonic()
        recent = [n for t, n in self._rate if now - t <= 60]
        return {
            "processed": self.processed,
            "queue_depth": self.queue.qsize(),
            "db_buffer": len(self._db_buffer),
            "dropped": self.dropped,
            "db_errors": self.db_errors,
            "lines_per_min": sum(recent),
        }

    @staticmethod
    def _view(entry: dict[str, Any], seq: int) -> dict[str, Any]:
        status = int(entry.get("sc_status") or 0)
        tags = entry.get("threat_tags") or ""
        level = "critical" if (status >= 500 or any(t in tags for t in ("SQLI", "XSS", "TRAVERSAL"))) else (
            "warn" if status >= 400 or tags else "normal"
        )
        return {
            "seq": seq,
            "ts": iso(entry["ts"]),
            "server_id": entry.get("server_id", LOCAL_SERVER_ID),
            "server": entry.get("server_name", ""),
            "site": entry.get("site", ""),
            "site_name": entry.get("site_name", ""),
            "ip": entry.get("c_ip", ""),
            "method": entry.get("cs_method", ""),
            "uri": entry.get("cs_uri_stem", ""),
            "query": (entry.get("cs_uri_query") or "")[:300],
            "status": status,
            "substatus": entry.get("sc_substatus", 0),
            "tt": entry.get("time_taken", 0),
            "bytes": entry.get("sc_bytes", 0),
            "user": entry.get("cs_username", ""),
            "ua": (entry.get("user_agent") or "")[:160],
            "tags": tags,
            "level": level,
        }

    async def _handle_events(self, events: list[dict[str, Any]], occurred_at: Any = None) -> None:
        for ev in events:
            kind = ev["kind"]
            ip = ev.get("ip")
            sid = int(ev.get("server_id") or LOCAL_SERVER_ID)
            if kind == "signature":
                tags = "/".join(ev["tags"])
                await self.alerts.raise_alert(
                    "WARNING", "attack", f"{tags} attempt from {ip}",
                    f"Request matched {tags} signature(s) (HTTP {ev.get('status')}).",
                    source_ip=ip, details={"payload": ev["payload"], "tags": ev["tags"]},
                    dedup_key=f"sig:{sid}:{ip}:{tags}", cooldown=600, server_id=sid,
                    event=[SIGNATURE_EVENTS[t] for t in ev["tags"] if t in SIGNATURE_EVENTS], occurred_at=occurred_at,
                )
            elif kind == "spike":
                await self.alerts.raise_alert(
                    "WARNING", "attack", f"HTTP {ev['spike']} spike from {ip}",
                    f"{ev['count']} {ev['spike']} responses within {int(ev['window'])}s.",
                    source_ip=ip, details={"count": ev["count"], "window_seconds": ev["window"]},
                    dedup_key=f"spike:{sid}:{ip}:{ev['spike']}", cooldown=300, server_id=sid,
                    event="spike_404" if ev["spike"] == "404" else "spike_auth", occurred_at=occurred_at,
                )
            elif kind == "active_threat":
                st = ev["state"]
                await self.alerts.raise_alert(
                    "HIGH", "threat", f"ACTIVE THREAT: {ip} (score {st['score']:.0f})",
                    f"Source {ip} ({st['geo']}) exceeded the threat threshold of {st['threshold']:.0f}. "
                    f"Signals: {', '.join(f'{k}x{v}' for k, v in st['tags'].items())}. "
                    f"Approve the ban to block it on {ev.get('server_name') or 'the target server'}'s Windows Firewall.",
                    source_ip=ip,
                    details={"score": st["score"], "geo": st["geo"], "tags": st["tags"], "last_payload": st["last_payload"],
                             "requests": st["requests"]},
                    dedup_key=f"active:{sid}:{ip}", cooldown=1800, server_id=sid, event="active_threat",
                    occurred_at=occurred_at,
                )
            elif kind == "dir_enum":
                # WHOIS can take seconds; never hold up the log pipeline for it.
                task = asyncio.create_task(self._raise_dir_enum(ev, sid, occurred_at))
                self._bg.add(task)
                task.add_done_callback(self._bg.discard)
            elif kind == "threat_cleared":
                await self.alerts.raise_alert(
                    "INFO", "recovery", f"Threat cleared: {ip}", "Threat score decayed below the threshold.",
                    details={"ip": ip}, dedup_key=f"cleared:{sid}:{ip}", cooldown=1800, server_id=sid,
                    event="threat_cleared",
                )

    async def _raise_dir_enum(self, ev: dict[str, Any], sid: int, occurred_at: Any) -> None:
        ip = ev["ip"]
        whois: dict[str, Any] = {}
        if self.enrich is not None:
            try:
                whois = await asyncio.wait_for(self.enrich(ip), timeout=6)
            except Exception as exc:  # noqa: BLE001
                whois = {"error": f"WHOIS unavailable: {type(exc).__name__}"}
        owner = whois.get("summary") or whois.get("organization") or whois.get("network_name") or ""
        uris: list[str] = ev["uris"]
        reason = "Directory Enumeration (404 Scan)"
        try:
            await self.alerts.raise_alert(
                "WARNING", "attack", f"{reason} from {ip}",
                f"{ip}{f' ({owner})' if owner else ''} requested {ev['distinct']} different missing paths "
                f"({ev['count']} 404s) within {ev['window_minutes']:.0f} min on {ev.get('server_name') or 'the server'}: "
                f"{', '.join(uris[-5:])}{' ...' if len(uris) > 5 else ''}. Approve the ban to block it.",
                source_ip=ip,
                details={"reason": reason, "payload": "\n".join(uris), "uris": uris, "count": ev["count"],
                         "distinct": ev["distinct"], "window_minutes": ev["window_minutes"],
                         "whois": {k: whois.get(k) for k in ("summary", "organization", "network_name", "country",
                                                               "registry", "cidr", "abuse_email", "reverse_dns", "error")
                                   if whois.get(k)}},
                dedup_key=f"enum:{sid}:{ip}", cooldown=int(ev["window_minutes"] * 60), server_id=sid, event="dir_enum",
                occurred_at=occurred_at,
            )
        except Exception:  # noqa: BLE001
            log.exception("Directory enumeration alert for %s failed", ip)

    async def _handle_http(self, ev: dict[str, Any]) -> None:
        sid = ev["server_id"]
        where = f"{ev['site_name']} ({ev['site']})" if ev["site_name"] else (ev["site"] or "site")
        kind = ev["kind"]
        common = {"site": ev["site"], "site_name": ev["site_name"], "log_time": iso(ev["ts"]) if ev["ts"] else None}
        if kind == "http_error":
            repeats = f" {ev['repeats']} more since the last alert." if ev["repeats"] else ""
            await self.alerts.raise_alert(
                "WARNING", "http", f"HTTP {ev['status']} on {where}: {ev['uri'][:120]}",
                f"{ev['method']} {ev['uri']}{('?' + ev['query']) if ev['query'] else ''} returned {ev['status']}."
                f"{ev['substatus']} (win32 {ev['win32']}) to {ev['ip']} in {ev['time_taken']} ms.{repeats} "
                f"Further {ev['status']}s on this URL are rolled up for {ev['cooldown_minutes']:.0f} min.",
                details={**common, "status": ev["status"], "substatus": ev["substatus"], "win32_status": ev["win32"],
                         "uri": ev["uri"], "client_ip": ev["ip"], "time_taken_ms": ev["time_taken"], "repeats": ev["repeats"]},
                server_id=sid, event="http_5xx", occurred_at=ev["ts"],
            )
        elif kind == "http_error_burst":
            codes = ", ".join(f"{k}x{v}" for k, v in ev["statuses"].items())
            await self.alerts.raise_alert(
                "HIGH", "http", f"Server error burst on {where}: {ev['count']} errors in {ev['window_minutes']:.0f} min",
                f"{ev['count']} error responses ({codes}) within {ev['window_minutes']:.0f} minutes. "
                f"Most affected: {', '.join(ev['top_uris'])}.",
                details={**common, "count": ev["count"], "statuses": ev["statuses"], "top_uris": ev["top_uris"]},
                server_id=sid, event="http_5xx_burst", occurred_at=ev["ts"],
            )
        elif kind == "status_watch":
            repeats = f" {ev['repeats']} more since the last alert." if ev["repeats"] else ""
            await self.alerts.raise_alert(
                "WARNING", "http", f"HTTP {ev['status']} on {where}: {ev['uri'][:120]}",
                f"{ev['method']} {ev['uri']} returned watched status {ev['status']}.{ev['substatus']} to {ev['ip']}.{repeats}",
                details={**common, "status": ev["status"], "uri": ev["uri"], "client_ip": ev["ip"], "repeats": ev["repeats"]},
                server_id=sid, event="http_status_watch", occurred_at=ev["ts"],
            )
        elif kind == "slow":
            worst = ", ".join(f"{w['uri']} ({w['ms'] / 1000:.1f}s)" for w in ev["worst"][:3])
            await self.alerts.raise_alert(
                "WARNING", "http", f"Slow responses on {where}: {ev['count']} over {ev['threshold_ms'] / 1000:.1f}s",
                f"{ev['count']} requests took longer than {ev['threshold_ms']} ms within {ev['window_minutes']:.0f} minutes "
                f"(average {ev['avg_ms']} ms). Slowest: {worst}.",
                details={**common, "count": ev["count"], "avg_ms": ev["avg_ms"], "worst": ev["worst"]},
                server_id=sid, event="slow_response", occurred_at=ev["ts"],
            )

    async def _handle_anomalies(self, anomalies: list[dict[str, Any]], entry: dict[str, Any] | None) -> None:
        labels = {
            "rpm": "Request volume", "bpm": "Bandwidth", "time_taken": "Response time",
            "global_rpm": "Server-wide request volume", "global_bpm": "Server-wide bandwidth",
            "global_rpm_drop": "Server-wide traffic DROP",
        }
        occurred_at = entry.get("ts") if entry is not None else None
        for a in anomalies:
            metric, ip = a["metric"], a.get("ip")
            sid = int(a.get("server_id") or LOCAL_SERVER_ID)
            if ip and metric in ("rpm", "bpm"):
                delta, events = self.threats.apply_anomaly(sid, ip, metric, a["z"])
                if entry is not None:
                    entry["threat_score"] = int(entry.get("threat_score") or 0) + delta
                    tag = "ZSCORE"
                    entry["threat_tags"] = ",".join(t for t in (entry.get("threat_tags") or "").split(",") + [tag] if t)
                await self._handle_events(events, occurred_at)
            unit = {"rpm": "req/min", "bpm": "bytes/min", "time_taken": "ms"}.get(metric.replace("global_", "").replace("_drop", ""), "")
            await self.alerts.raise_alert(
                "WARNING", "anomaly",
                f"{labels.get(metric, metric)} anomaly{f' from {ip}' if ip else ''} (z={a['z']:+.1f})",
                f"Observed {a['value']:,.0f} {unit} vs baseline mean {a['mean']:,.1f} (std {a['std']:,.1f}, basis: {a['basis']}).",
                source_ip=ip, details=a, dedup_key=f"anomaly:{sid}:{metric}:{ip or '*'}", cooldown=600, server_id=sid,
                event=ANOMALY_EVENTS.get(metric, "anomaly_server"), occurred_at=occurred_at,
            )

    async def _process(self, entry: dict[str, Any]) -> None:
        sid = int(entry.get("server_id") or LOCAL_SERVER_ID)
        entry["site_name"] = self.site_name(sid, entry.get("site") or "")
        result = self.threats.inspect(entry)
        entry["threat_tags"] = ",".join(result.tags)
        entry["threat_score"] = result.delta
        await self._handle_events(result.events, entry.get("ts"))
        for ev in self.http.observe(entry):
            await self._handle_http(ev)
        await self._handle_anomalies(self.baseliner.observe(entry), entry)
        self._seq += 1
        view = self._view(entry, self._seq)
        self.recent.append(view)
        self._ws_buffer.append(view)
        self._db_buffer.append(entry)
        self.processed += 1

    async def _flush_db(self) -> None:
        if not self._db_buffer:
            return
        batch, self._db_buffer = self._db_buffer, []
        rows = [{k: e.get(k) for k in _LOG_COLUMNS if k in e} for e in batch]

        async def _op(s):  # type: ignore[no-untyped-def]
            await s.execute(insert(LogEntry), rows)

        try:
            # Bulk insert of up to FLUSH_SIZE rows (plus the FTS trigger) in one transaction; run_db retries on
            # "database is locked" with backoff, and a batch that still fails is put back for the next flush.
            await run_db(_op, retries=6)
        except Exception:  # noqa: BLE001
            self.db_errors += 1
            log.exception("Failed to write %d log entries; will retry", len(batch))
            self._db_buffer = batch + self._db_buffer
            if len(self._db_buffer) > self.MAX_BUFFER:
                excess = len(self._db_buffer) - self.MAX_BUFFER
                self.dropped += excess
                self._db_buffer = self._db_buffer[excess:]
            await asyncio.sleep(2)

    def _flush_ws(self) -> None:
        if self._ws_buffer:
            self.hub.broadcast({"type": "logs", "data": self._ws_buffer[-250:]})
            self._ws_buffer = []

    async def run(self) -> None:
        last_db = last_ws = last_tick = time.monotonic()
        while True:
            try:
                entry = await asyncio.wait_for(self.queue.get(), timeout=0.25)
            except asyncio.TimeoutError:
                entry = None
            count = 0
            while entry is not None:
                try:
                    await self._process(entry)
                except Exception:  # noqa: BLE001
                    log.exception("Failed to process log entry")
                count += 1
                if count >= 1000:
                    break
                try:
                    entry = self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    entry = None
            now = time.monotonic()
            if count:
                self._rate.append((now, count))
            if len(self._db_buffer) >= self.FLUSH_SIZE or (self._db_buffer and now - last_db >= self.FLUSH_SECONDS):
                await self._flush_db()
                last_db = time.monotonic()
            if now - last_ws >= self.WS_SECONDS:
                self._flush_ws()
                last_ws = now
            if now - last_tick >= 5:
                last_tick = now
                try:
                    await self._handle_anomalies(self.baseliner.tick(), None)
                except Exception:  # noqa: BLE001
                    log.exception("Baseliner tick failed")

    async def shutdown(self) -> None:
        while not self.queue.empty():
            try:
                await self._process(self.queue.get_nowait())
            except Exception:  # noqa: BLE001
                break
        await self._flush_db()


_LOG_COLUMNS = [c.name for c in LogEntry.__table__.columns if c.name != "id"]


# --------------------------------------------------------------------------------------
# Application state & supervisor
# --------------------------------------------------------------------------------------
class State:
    config: ConfigStore
    registry: ServerRegistry
    remote: RemoteManager
    hub: Hub
    mailer: Mailer
    alerts: AlertManager
    auth: ADAuthenticator
    threats: ThreatEngine
    baseliner: Baseliner
    health: HealthMonitor
    tailer: LogTailer
    pipeline: Pipeline
    http: HttpMonitor
    whois: WhoisClient
    geo: GeoResolver
    firewall: FirewallManager
    defense: DefenseEngine
    abuse: AbuseIPDB
    reporter: Reporter
    signer: SessionSigner
    throttle: LoginThrottle
    ip_throttle: LoginThrottle
    ban_locks: defaultdict[tuple[int, str], asyncio.Lock]
    started_at: float
    tasks: list[asyncio.Task[Any]]


S = State()


async def supervise(name: str, factory: Callable[[], Awaitable[Any]]) -> None:
    """Keep a background coroutine alive forever; crashes are logged and restarted with backoff."""
    delay = 1.0
    while True:
        started = time.monotonic()
        try:
            await factory()
            log.warning("Task %s exited unexpectedly; restarting", name)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("Task %s crashed; restarting in %.0fs", name, delay)
        if time.monotonic() - started > 120:
            delay = 1.0
        await asyncio.sleep(delay)
        delay = min(delay * 2, 60.0)


async def periodic_broadcast() -> None:
    n = 0
    while True:
        await asyncio.sleep(2)
        n += 1
        S.hub.broadcast({"type": "threats", "data": S.threats.active_threats(), "counts": S.threats.counts()})
        S.hub.broadcast({"type": "tick", "server_time": time.time(), "pipeline": S.pipeline.stats(), "clients": S.hub.client_count})
        if n % 3 == 0:
            S.hub.broadcast({"type": "baseline", "data": S.baseliner.snapshot()})
        if n % 300 == 0:
            pruned = S.threats.prune()
            if pruned:
                log.info("Pruned %d idle IP states", pruned)


async def geo_enricher() -> None:
    """Fill in locations the instant lookup could not answer (no GeoIP database yet: RDAP country, rate-limited)."""
    db = None
    while True:
        await asyncio.sleep(5)
        current = S.geo.status()["database"]
        if current != db:
            db = current
            S.threats.refresh_geo()
        for ip in S.threats.missing_geo(limit=50 if db else 4):
            geo = await S.geo.resolve(ip)
            if geo:
                S.threats.set_geo(ip, geo)


async def persist_enum_counters() -> None:
    """Flush the in-memory 404 enumeration counters to the DB every 60s (reloaded at startup)."""
    last = None
    while True:
        await asyncio.sleep(60)
        data = S.threats.export_enum()
        if data != last:
            await kv_put("_enum404", data)
            last = data


async def fts_backfill() -> None:
    """Index log rows written before the full-text index existed, in small chunks so logging never stalls."""
    while FTS_STATE["enabled"]:
        try:
            progress = await fts_backfill_step()
        except Exception:  # noqa: BLE001
            log.exception("Full-text backfill chunk failed; retrying")
            await asyncio.sleep(30)
            continue
        FTS_STATE["backfill"] = progress
        if progress is None:
            log.info("Full-text log index is complete")
            break
        await asyncio.sleep(0.2)
    await asyncio.Event().wait()


async def _whois_enrich(ip: str) -> dict[str, Any]:
    return await S.whois.lookup(ip)


def _servers_payload() -> list[dict[str, Any]]:
    return S.registry.list_public()


def _on_servers_changed() -> None:
    S.tailer.reload()
    S.health.reload()
    known = {srv["id"] for srv in S.registry.all(enabled_only=False)}
    for srv in S.registry.all(enabled_only=False):
        S.threats.rename_server(srv["id"], srv["server_name"])
    _LOG_FEEDS_DOWN.intersection_update(known)
    for sid in S.threats.server_ids() - known:
        S.threats.forget_server(sid)
        S.baseliner.forget_server(sid)
        S.http.forget_server(sid)
    S.hub.broadcast({"type": "servers", "data": _servers_payload()})


_LOG_FEEDS_DOWN: set[int] = set()


async def _log_feed_status(server_id: int, component: str, ok: bool, error: str | None) -> None:
    """Called by the log tailer when a server's log feed goes up or down (state changes only)."""
    S.hub.broadcast({"type": "server_status", "server_id": server_id, "server_name": S.registry.name(server_id),
                     "component": component, "ok": ok, "error": error})
    was_down = server_id in _LOG_FEEDS_DOWN
    if ok:
        _LOG_FEEDS_DOWN.discard(server_id)
    else:
        _LOG_FEEDS_DOWN.add(server_id)
    if ok and not was_down:
        return
    if ok:
        await S.alerts.raise_alert("INFO", "recovery", "Log feed restored", "Sentinel is reading this server's IIS logs again.",
                                   server_id=server_id, dedup_key=f"{server_id}:logs:up", cooldown=60, event="log_feed_restored")
    else:
        await S.alerts.raise_alert(
            "HIGH", "system", "Log feed offline",
            f"Cannot read IIS logs: {error}. Attacks against this server are not being detected until the feed "
            "recovers. Monitoring of the other servers continues.",
            details={"error": error}, server_id=server_id, dedup_key=f"{server_id}:logs:down", cooldown=1800,
            event="log_feed_offline",
        )


async def _sites_discovered(server_id: int, folders: list[str]) -> None:
    names = [f"{n} ({f})" if (n := S.health.site_name(server_id, f)) else f for f in folders]
    await S.alerts.raise_alert(
        "INFO", "system", f"Now tailing {len(folders)} new site log folder(s)",
        f"New IIS site log folder(s) appeared and are now monitored: {', '.join(names)}.",
        details={"folders": folders}, server_id=server_id, event="site_discovered",
    )


async def _report_failed(kind: str, error: str) -> None:
    await S.alerts.raise_alert("WARNING", "system", f"Scheduled {kind} report failed", error,
                               details={"kind": kind, "error": error}, event="report_failed")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    S.started_at = time.time()
    await init_db()
    S.config = ConfigStore()
    await S.config.load()
    S.registry = ServerRegistry(S.config)
    await S.registry.load()
    S.remote = RemoteManager(S.config, S.registry)
    S.hub = Hub()
    S.mailer = Mailer(S.config)
    S.alerts = AlertManager(S.hub, S.config, S.mailer)
    S.alerts.server_name = S.registry.name
    S.auth = ADAuthenticator(S.config)
    S.whois = WhoisClient()
    S.geo = GeoResolver(DATA_DIR, S.whois, lambda: bool(S.config.value("watchers", "geoip_auto_download", True)))
    S.threats = ThreatEngine(S.config, S.registry.name, S.geo.quick)
    S.firewall = FirewallManager(S.config, S.remote)
    S.defense = DefenseEngine(S.config, S.registry, S.remote, S.firewall)
    S.abuse = AbuseIPDB(S.config, lambda r: S.hub.broadcast({"type": "abuseipdb", "data": {r["ip"]: r}}))
    S.baseliner = Baseliner(S.config)
    S.health = HealthMonitor(S.config, S.alerts, S.hub, S.registry, S.remote)
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=50000)
    S.tailer = LogTailer(S.config, S.registry, S.remote, queue, on_status=_log_feed_status, on_sites=_sites_discovered)
    S.ban_locks = defaultdict(asyncio.Lock)
    S.http = HttpMonitor(S.config)
    S.pipeline = Pipeline(queue, S.threats, S.baseliner, S.alerts, S.hub, S.http, S.health.site_name, _whois_enrich)
    try:
        restored = S.threats.import_enum(await kv_get("_enum404", {}))
        if restored:
            log.info("Restored 404 enumeration counters for %d source IP(s)", restored)
    except Exception:  # noqa: BLE001
        log.exception("Could not restore 404 enumeration counters")
    S.reporter = Reporter(S.config, S.mailer)
    S.reporter.on_failure = _report_failed
    S.signer = SessionSigner(await get_or_create_session_secret(), SESSION_TTL)
    S.throttle = LoginThrottle(max_failures=5, window=300)
    S.ip_throttle = LoginThrottle(max_failures=20, window=300)

    def _on_config(section: str) -> None:
        if section == "reports":
            S.reporter.reschedule()
        elif section == "watchers":
            # log_dirs toggles the optional local server (id 0).
            _on_servers_changed()
        elif section == "firewall":
            S.hub.broadcast({"type": "firewall", "data": S.firewall.summary()})
        elif section == "general":
            S.abuse.settings_changed()
            S.hub.broadcast({"type": "general", "default_theme": S.config.value("general", "default_theme", "cyber"),
                             "abuseipdb": S.abuse.status()})

    S.config.on_change(_on_config)
    S.registry.on_change(_on_servers_changed)
    try:
        S.reporter.start()
    except Exception:  # noqa: BLE001
        log.exception("Report scheduler failed to start; reports disabled until restart")

    jobs: dict[str, Callable[[], Awaitable[Any]]] = {
        "log_tailer": S.tailer.run,
        "pipeline": S.pipeline.run,
        "system_health": S.health.run,
        "baseliner": S.baseliner.run,
        "broadcaster": periodic_broadcast,
        "geoip": S.geo.run,
        "geo_enricher": geo_enricher,
        "enum_persist": persist_enum_counters,
        "fts_backfill": fts_backfill,
        "abuseipdb": S.abuse.run,
    }
    if DEMO_MODE:
        jobs["demo_traffic"] = run_demo_fleet
    S.tasks = [asyncio.create_task(supervise(name, fn), name=name) for name, fn in jobs.items()]
    log.info("IIS Sentinel SOC online%s. Monitoring %d server(s): %s", " [DEMO MODE]" if DEMO_MODE else "",
             len(S.registry.all()), ", ".join(srv["server_name"] for srv in S.registry.all()) or "none (add one under CONFIG > SERVERS)")
    try:
        await S.alerts.raise_alert(
            "INFO", "system", "IIS Sentinel started",
            f"Sentinel {app.version} started and is monitoring {len(S.registry.all())} server(s).",
            details={"servers": [srv["server_name"] for srv in S.registry.all()]}, event="sentinel_started",
        )
    except Exception:  # noqa: BLE001
        log.exception("Startup alert failed")
    try:
        yield
    finally:
        log.info("IIS Sentinel shutting down")
        for t in S.tasks:
            t.cancel()
        await asyncio.gather(*S.tasks, return_exceptions=True)
        S.tailer.stop()
        try:
            await asyncio.wait_for(S.pipeline.shutdown(), timeout=15)
        except Exception:  # noqa: BLE001
            log.exception("Pipeline flush on shutdown failed")
        try:
            await kv_put("_enum404", S.threats.export_enum())
        except Exception:  # noqa: BLE001
            log.exception("Saving 404 enumeration counters on shutdown failed")
        try:
            await sonicwall_api.close_shared_client()
        except Exception:  # noqa: BLE001
            pass
        S.reporter.shutdown()
        await S.alerts.drain(5)
        await engine.dispose()


app = FastAPI(title="IIS Sentinel", version="2.0.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        response = JSONResponse({"detail": "Internal server error"}, status_code=500)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'"
    )
    if request.url.path.startswith(("/api", "/login", "/config", "/threats", "/system", "/alerts", "/reports", "/stats",
                                    "/servers", "/defense", "/banned-ranges", "/allowlist", "/intel", "/logs", "/firewall")):
        response.headers["Cache-Control"] = "no-store"
    elif "Cache-Control" not in response.headers:
        # Revalidate (ETag / 304) so a new dashboard.html never runs against a cached older app.js.
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo submitted values back: for /login they would include the password.
    errors = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------------------
def current_user(request: Request) -> dict[str, Any]:
    user = S.signer.verify(request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _same_origin(origin: str | None, host: str | None) -> bool:
    if not origin:
        return True
    try:
        return urlparse(origin).netloc.lower() == (host or "").lower()
    except ValueError:
        return False


def same_origin_guard(request: Request) -> None:
    if not _same_origin(request.headers.get("origin"), request.headers.get("host")):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)


class ReportRunBody(BaseModel):
    kind: str = Field(default="weekly", pattern="^(weekly|monthly)$")
    send: bool = True


class TestMailBody(BaseModel):
    recipients: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def index(request: Request) -> Response:
    if S.signer.verify(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse("/dashboard", status_code=303)
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request) -> Response:
    if not S.signer.verify(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "uptime": round(time.time() - S.started_at), "tasks": {t.get_name(): not t.done() for t in S.tasks}}


# --------------------------------------------------------------------------------------
# Auth API
# --------------------------------------------------------------------------------------
@app.post("/login")
async def login(body: LoginBody, request: Request) -> Response:
    if not _same_origin(request.headers.get("origin"), request.headers.get("host")):
        raise HTTPException(status_code=403, detail="Cross-origin login refused")
    ip_key = _client_ip(request)
    key = f"{ip_key}|{body.username.strip().lower()}"
    wait = max(S.throttle.blocked(key), S.ip_throttle.blocked(ip_key))
    if wait:
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Retry in {wait}s")
    user_label = body.username.strip()[:64]
    result = await S.auth.authenticate(body.username, body.password)
    if not result.ok:
        S.throttle.fail(key)
        S.ip_throttle.fail(ip_key)
        log.warning("Failed login for '%s' from %s: %s", body.username, _client_ip(request), result.error)
        await S.alerts.raise_alert(
            "INFO", "access", f"Failed sign-in for '{user_label}' from {ip_key}", result.error or "Authentication failed",
            details={"username": user_label, "client_ip": ip_key}, event="login_failed",
            dedup_key=f"loginfail:{key}", cooldown=60, actionable=False,
        )
        locked = max(S.throttle.blocked(key), S.ip_throttle.blocked(ip_key))
        if locked:
            await S.alerts.raise_alert(
                "WARNING", "access", f"Sign-in lockout: '{user_label}' from {ip_key}",
                f"Too many failed sign-ins; further attempts from {ip_key} are refused for {locked}s. "
                "If this was not an operator, someone may be guessing dashboard passwords.",
                details={"username": user_label, "client_ip": ip_key, "lockout_seconds": locked},
                event="login_lockout", dedup_key=f"lockout:{key}", cooldown=300, actionable=False,
            )
        await asyncio.sleep(0.5)
        status = 503 if "unreachable" in result.error.lower() or "not configured" in result.error.lower() else 401
        raise HTTPException(status_code=status, detail=result.error or "Authentication failed")
    S.throttle.reset(key)
    token = S.signer.issue(result.username, result.display_name, result.source)
    resp = JSONResponse({"ok": True, "user": result.username, "display_name": result.display_name, "source": result.source})
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True, secure=COOKIE_SECURE, samesite="strict", path="/")
    log.info("Login: %s (%s) from %s", result.username, result.source, _client_ip(request))
    if result.source == "local":
        await S.alerts.raise_alert(
            "HIGH", "access", f"Break-glass login by '{result.username}' from {ip_key}",
            "The local emergency account was used to sign in. This is expected only while Active Directory is "
            "unreachable or not yet configured.", details={"username": result.username, "client_ip": ip_key},
            event="breakglass_login", actionable=False,
        )
    else:
        await S.alerts.raise_alert(
            "INFO", "access", f"{result.username} signed in from {ip_key}", f"Signed in as {result.display_name} ({result.source}).",
            details={"username": result.username, "client_ip": ip_key}, event="login_success", actionable=False,
        )
    return resp


@app.post("/logout")
async def logout(request: Request) -> Response:
    S.signer.revoke(request.cookies.get(COOKIE_NAME))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/me")
async def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"user": user["u"], "display_name": user["d"], "source": user["s"], "demo": DEMO_MODE}


# --------------------------------------------------------------------------------------
# Config API
# --------------------------------------------------------------------------------------
@app.get("/config")
async def get_config(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {
        "config": S.config.public_view(),
        "report_next_runs": S.reporter.next_runs(),
        "watchers_status": S.tailer.status(),
        "mailer": S.mailer.status(),
    }


@app.post("/config")
async def post_config(request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if not _same_origin(request.headers.get("origin"), request.headers.get("host")):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")
    try:
        payload = await request.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Body must be JSON") from exc
    if not isinstance(payload, dict) or not payload:
        raise HTTPException(status_code=400, detail="Expected an object keyed by section (ad, exchange, watchers, reports, alerts, firewall)")
    errors: dict[str, str] = {}
    changed: dict[str, list[str]] = {}
    for section, values in payload.items():
        try:
            before = S.config.public_view().get(section, {})
            after = await S.config.update(section, values)
            keys = [k for k in after if after.get(k) != before.get(k)]
            if keys:
                changed[section] = keys
        except ValueError as exc:
            errors[section] = str(exc)
    if errors:
        raise HTTPException(status_code=400, detail=errors)
    log.info("Config updated by %s: %s", user["u"], ", ".join(payload))
    if changed:
        summary = "; ".join(f"{sec}: {', '.join(keys[:8])}{' ...' if len(keys) > 8 else ''}" for sec, keys in changed.items())
        await S.alerts.raise_alert("INFO", "config", f"Configuration changed by {user['u']}", summary,
                                   details={"changed": changed, "user": user["u"]}, event="config_changed")
    return await get_config(user)


class FirewallTestBody(BaseModel):
    provider: Literal["windows", "pfsense", "sonicwall", "paloalto"] | None = None
    # Unsaved form values (firewall section keys); masked secrets keep the saved value.
    settings: dict[str, Any] | None = None


class FirewallConfigBody(BaseModel):
    model_config = {"extra": "forbid"}

    firewall_type: Literal["windows", "pfsense", "sonicwall", "paloalto"] | None = None
    api_url: str | None = Field(default=None, max_length=512)
    username: str | None = Field(default=None, max_length=256)
    api_key: str | None = Field(default=None, max_length=512)
    default_group_name: str | None = Field(default=None, max_length=63)
    zone: str | None = Field(default=None, max_length=63)
    also_windows: bool | None = None


class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=63)
    description: str = Field(default="", max_length=256)


class GroupMemberBody(BaseModel):
    address: str = Field(min_length=1, max_length=64)


def _firewall_overrides(settings: dict[str, Any] | None) -> dict[str, Any] | None:
    if not settings:
        return None
    clean = {k: v for k, v in settings.items() if k in DEFAULT_CONFIG["firewall"]
             and not (("firewall", k) in SECRET_FIELDS and v in ("", SECRET_MASK, None))}
    try:
        return S.config.preview("firewall", clean)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _firewall_config_view() -> dict[str, Any]:
    c = S.config.public_view()["firewall"]
    return {"id": 1, "firewall_type": c["provider"], "api_url": c["sonicwall_url"], "username": c["sonicwall_username"],
            "api_key": c["sonicwall_password"], "default_group_name": c["sonicwall_group"], "zone": c["sonicwall_zone"],
            "also_windows": c["also_windows"], "verify_ssl": False, "summary": S.firewall.summary()}


async def _sonicwall(op: Callable[[Any], Awaitable[Any]], what: str) -> Any:
    try:
        return await S.firewall.sonicwall(op)
    except FirewallError as exc:
        raise HTTPException(status_code=502, detail=f"{what}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        log.exception("SonicWall %s failed", what)
        raise HTTPException(status_code=502, detail=f"{what}: {type(exc).__name__}: {exc}") from exc


@app.get("/firewall")
async def firewall_summary(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {**S.firewall.summary(), "providers": FIREWALL_PROVIDERS}


@app.post("/firewall/test", dependencies=[Depends(same_origin_guard)])
async def firewall_test(body: FirewallTestBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return await S.firewall.test(body.provider, _firewall_overrides(body.settings))


@app.get("/firewall/config")
async def firewall_config(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return _firewall_config_view()


@app.post("/firewall/config", dependencies=[Depends(same_origin_guard)])
async def save_firewall_config(body: FirewallConfigBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    mapping = {"firewall_type": "provider", "api_url": "sonicwall_url", "username": "sonicwall_username",
               "api_key": "sonicwall_password", "default_group_name": "sonicwall_group", "zone": "sonicwall_zone",
               "also_windows": "also_windows"}
    values = {mapping[k]: v for k, v in body.model_dump(exclude_none=True).items()}
    if not values:
        raise HTTPException(status_code=400, detail="Nothing to update")
    try:
        await S.config.update("firewall", values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log.info("Firewall config updated by %s: %s", user["u"], ", ".join(values))
    await S.alerts.raise_alert("INFO", "config", f"Firewall settings changed by {user['u']}",
                               f"Changed: {', '.join(sorted(values))}.", details={"user": user["u"], "changed": sorted(values)},
                               event="config_changed")
    return _firewall_config_view()


@app.get("/firewall/groups")
async def firewall_groups(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    groups = await _sonicwall(lambda api: api.list_groups(), "List address groups")
    default = S.config.value("firewall", "sonicwall_group", "")
    for g in groups:
        g["default"] = g["name"].lower() == default.lower()
    return {"groups": groups, "default_group": default}


@app.post("/firewall/groups", status_code=201, dependencies=[Depends(same_origin_guard)])
async def create_firewall_group(body: GroupBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    msg = await _sonicwall(lambda api: api.create_address_group(body.name.strip(), body.description), "Create group")
    log.warning("SonicWall group %s created by %s", body.name, user["u"])
    return {"ok": True, "message": msg}


@app.delete("/firewall/groups", dependencies=[Depends(same_origin_guard)])
async def delete_firewall_group(name: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    msg = await _sonicwall(lambda api: api.delete_address_group(name.strip()), "Delete group")
    log.warning("SonicWall group %s deleted by %s", name, user["u"])
    return {"ok": True, "message": msg}


@app.post("/firewall/groups/{name}/members", dependencies=[Depends(same_origin_guard)])
async def add_group_member(name: str, body: GroupMemberBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    msg = await _sonicwall(lambda api: api.add_ip_to_group(name, body.address.strip()), "Add address")
    log.warning("%s added to SonicWall group %s by %s", body.address, name, user["u"])
    return {"ok": True, "message": msg}


@app.delete("/firewall/groups/{name}/members", dependencies=[Depends(same_origin_guard)])
async def remove_group_member(name: str, address: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    msg = await _sonicwall(lambda api: api.remove_ip_from_group(name, address.strip()), "Remove address")
    log.warning("%s removed from SonicWall group %s by %s", address, name, user["u"])
    return {"ok": True, "message": msg}


@app.get("/geoip")
async def geoip_status(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return S.geo.status()


@app.post("/config/test/exchange")
async def test_exchange(body: TestMailBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ok, err = await S.mailer.send_test(body.recipients or None)
    return {"ok": ok, "error": err}


# --------------------------------------------------------------------------------------
# Threats / system API
# --------------------------------------------------------------------------------------
@app.get("/threats/live")
async def threats_live(limit: int = 100, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    async with SessionLocal() as s:
        rows = (
            await s.execute(select(LogEntry).where(LogEntry.threat_tags != "").order_by(desc(LogEntry.id)).limit(limit))
        ).scalars().all()
        alerts = (
            await s.execute(
                select(ActionableAlert).where(ActionableAlert.category.in_(("attack", "threat", "anomaly"))).order_by(desc(ActionableAlert.id)).limit(limit)
            )
        ).scalars().all()
    return {
        "events": [
            {
                "ts": iso(r.ts), "server_id": r.server_id, "server_name": S.registry.name(r.server_id), "ip": r.c_ip, "method": r.cs_method, "uri": r.cs_uri_stem, "query": r.cs_uri_query[:500],
                "status": r.sc_status, "tags": r.threat_tags, "score": r.threat_score, "ua": r.user_agent[:200],
            }
            for r in rows
        ],
        "alerts": [_alert_dict(a) for a in alerts],
    }


_TOKEN_RE = re.compile(r'(\w+):("[^"]*"|\S+)|"([^"]*)"|(\S+)')
_STATUS_FILTERS = {"4xx": (400, 499), "5xx": (500, 599), "404": (404, 404), "3xx": (300, 399), "2xx": (200, 299)}
SEARCH_COUNT_CAP = 10000


def _parse_when(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{name} must be an ISO date/time") from exc
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _fts_query(terms: list[str]) -> str:
    """Each term becomes a quoted phrase with a prefix match, so punctuation in URIs / IPs is never FTS syntax."""
    parts = []
    for t in terms:
        if re.search(r"\w", t):
            parts.append('"' + t.replace('"', '""') + '"*')
    return " ".join(parts)


def _log_row_view(r: LogEntry) -> dict[str, Any]:
    status = r.sc_status or 0
    tags = r.threat_tags or ""
    level = "critical" if (status >= 500 or any(t in tags for t in ("SQLI", "XSS", "TRAVERSAL"))) else (
        "warn" if status >= 400 or tags else "normal")
    return {
        "seq": -r.id, "id": r.id, "ts": iso(r.ts), "server_id": r.server_id, "server": S.registry.name(r.server_id),
        "site": r.site, "site_name": S.health.site_name(r.server_id, r.site), "ip": r.c_ip, "method": r.cs_method,
        "uri": r.cs_uri_stem, "query": (r.cs_uri_query or "")[:300], "status": status, "substatus": r.sc_substatus,
        "tt": r.time_taken, "bytes": r.sc_bytes, "user": r.cs_username, "ua": (r.user_agent or "")[:160],
        "tags": tags, "level": level,
    }


@app.get("/logs/search")
async def logs_search(q: str = "", status: str = "all", ip: str = "", uri: str = "", server_id: int | None = None,
                      since: str | None = None, until: str | None = None, page: int = 1, page_size: int = 50,
                      _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """Search stored IIS log lines. `q` is free text (URI, query string, user agent, IP, method, user) plus optional
    field tokens: ip:1.2.3.4  status:404  uri:/admin  method:POST  server:IIS-01."""
    page = max(1, min(page, 10000))
    page_size = max(10, min(page_size, 200))
    q = (q or "")[:300]
    conds: list[Any] = []
    terms: list[str] = []
    for m in _TOKEN_RE.finditer(q):
        field_name, field_val, quoted, bare = m.groups()
        if field_name:
            val = field_val.strip('"')
            f = field_name.lower()
            if f == "ip":
                ip = ip or val
                continue
            if f == "uri":
                uri = uri or val
                continue
            if f == "status":
                status = val
                continue
            if f == "method":
                conds.append(func.upper(LogEntry.cs_method) == val.upper())
                continue
            if f == "server":
                sid = next((x["id"] for x in S.registry.all(enabled_only=False) if x["server_name"].lower() == val.lower()), None)
                conds.append(LogEntry.server_id == (sid if sid is not None else -999))
                continue
            terms.append(m.group(0))
        else:
            terms.append(quoted if quoted is not None else bare)
    st = (status or "all").lower().strip()
    if st in _STATUS_FILTERS:
        lo, hi = _STATUS_FILTERS[st]
        conds.append(LogEntry.sc_status.between(lo, hi))
    elif re.fullmatch(r"\d{3}", st):
        conds.append(LogEntry.sc_status == int(st))
    elif st != "all":
        raise HTTPException(status_code=400, detail="status must be all, 2xx, 3xx, 4xx, 5xx, 404 or a 3-digit code")
    if ip:
        ip = ip.strip()
        conds.append(LogEntry.c_ip == ip if re.fullmatch(r"[0-9a-fA-F:.]+", ip) and (ip.count(".") == 3 or ip.count(":") >= 2)
                     else LogEntry.c_ip.like(ip.replace("*", "") + "%"))
    if uri:
        conds.append(LogEntry.cs_uri_stem.like(_like(uri.strip()), escape="\\"))
    if server_id is not None:
        conds.append(LogEntry.server_id == server_id)
    t_since, t_until = _parse_when(since, "since"), _parse_when(until, "until")
    if t_since:
        conds.append(LogEntry.ts >= t_since)
    if t_until:
        conds.append(LogEntry.ts <= t_until)
    mode = "filter"
    fts = _fts_query(terms)
    if fts and FTS_STATE["enabled"]:
        mode = "fts"
        conds.append(LogEntry.id.in_(
            text(f"SELECT rowid FROM {FTS_TABLE} WHERE {FTS_TABLE} MATCH :fts").bindparams(fts=fts).columns(rowid=Integer)))
    elif terms:
        mode = "like"
        for t in terms:
            pat = _like(t)
            conds.append(or_(*(getattr(LogEntry, c).like(pat, escape="\\") for c in FTS_COLUMNS)))
    where = and_(*conds) if conds else None
    q_rows = select(LogEntry).order_by(desc(LogEntry.id)).offset((page - 1) * page_size).limit(page_size)
    q_ids = select(LogEntry.id).order_by(desc(LogEntry.id)).limit(SEARCH_COUNT_CAP + 1)
    if where is not None:
        q_rows, q_ids = q_rows.where(where), q_ids.where(where)
    started = time.perf_counter()
    try:
        async with SessionLocal() as s:
            rows = (await s.execute(q_rows)).scalars().all()
            total = (await s.execute(select(func.count()).select_from(q_ids.subquery()))).scalar_one()
    except Exception as exc:  # noqa: BLE001
        log.warning("Log search failed (%s): %s", q, exc)
        raise HTTPException(status_code=400, detail=f"Search failed: {str(exc).splitlines()[0][:200]}") from exc
    capped = total > SEARCH_COUNT_CAP
    total = min(total, SEARCH_COUNT_CAP)
    return {
        "results": [_log_row_view(r) for r in rows], "total": total, "total_capped": capped, "page": page,
        "page_size": page_size, "pages": max(1, -(-total // page_size)), "mode": mode,
        "took_ms": round((time.perf_counter() - started) * 1000, 1),
        "index": {"enabled": FTS_STATE["enabled"], "backfill": FTS_STATE["backfill"]},
        "unflushed": len(S.pipeline._db_buffer),
    }


@app.get("/threats/active")
async def threats_active(server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"threats": S.threats.active_threats(limit=200, server_id=server_id), "counts": S.threats.counts()}


@app.get("/threats/ip/{ip}")
async def threat_ip(ip: str, server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    detail = S.threats.ip_detail(ip, server_id)
    q = select(LogEntry).where(LogEntry.c_ip == ip)
    if server_id is not None:
        q = q.where(LogEntry.server_id == server_id)
    async with SessionLocal() as s:
        rows = (await s.execute(q.order_by(desc(LogEntry.id)).limit(50))).scalars().all()
    return {
        "state": detail,
        "recent": [{"ts": iso(r.ts), "server_id": r.server_id, "server_name": S.registry.name(r.server_id),
                    "site": r.site, "site_name": S.health.site_name(r.server_id, r.site),
                    "method": r.cs_method, "uri": r.cs_uri_stem, "query": r.cs_uri_query[:300],
                    "status": r.sc_status, "tags": r.threat_tags, "ua": r.user_agent[:200]} for r in rows],
    }


@app.get("/threats/whois/{ip}")
async def threat_whois(ip: str, refresh: bool = False, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        result = await S.whois.lookup(ip, refresh=refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"'{ip[:64]}' is not a valid IP address") from exc
    async with SessionLocal() as s:
        bans = (await s.execute(select(BannedIP).where(BannedIP.ip_address == result["ip"], BannedIP.active.is_(True)))).scalars().all()
        alert_count = (await s.execute(
            select(func.count(ActionableAlert.id)).where(ActionableAlert.source_ip == result["ip"]))).scalar_one()
    try:
        history = await ban_history(result["ip"])
    except Exception:  # noqa: BLE001
        log.exception("Ban history for %s failed", result["ip"])
        history = {"total": 0, "events": [], "error": "ban history unavailable"}
    return {"whois": result, "bans": [_ban_dict(b) for b in bans], "alert_count": alert_count, "history": history}


async def ban_history(ip: str) -> dict[str, Any]:
    """Every ban Sentinel has ever applied to `ip`: single-IP bans (active and lifted) plus range bans that covered it."""
    addr = parse_network(ip).network_address
    async with SessionLocal() as s:
        ip_rows = (await s.execute(select(BannedIP).where(BannedIP.ip_address == str(addr))
                                   .order_by(desc(BannedIP.banned_at)).limit(1000))).scalars().all()
        range_rows = (await s.execute(select(BannedRange).order_by(desc(BannedRange.banned_at)).limit(20000))).scalars().all()
        alert_ids = {r.alert_id for r in ip_rows if r.alert_id}
        titles = dict((await s.execute(select(ActionableAlert.id, ActionableAlert.title)
                                       .where(ActionableAlert.id.in_(alert_ids)))).all()) if alert_ids else {}

    def _dur(start: datetime | None, end: datetime | None) -> int | None:
        return int((end - start).total_seconds()) if start and end else None

    events: list[dict[str, Any]] = []
    for b in ip_rows:
        provider = b.provider or "windows"
        events.append({
            "kind": "ip", "id": b.id, "target": b.ip_address, "scope": "single IP",
            "where": FIREWALL_PROVIDERS.get(provider, provider) if provider != "windows" else f"Windows Firewall · {S.registry.name(b.server_id)}",
            "server_name": S.registry.name(b.server_id), "reason": titles.get(b.alert_id, ""), "rule": b.rule_name,
            "banned_at": iso(b.banned_at), "banned_by": b.banned_by, "active": bool(b.active),
            "lifted_at": iso(b.lifted_at), "lifted_by": b.lifted_by or "", "duration_seconds": _dur(b.banned_at, b.lifted_at),
        })
    for r in range_rows:
        try:
            net = parse_network(r.cidr_notation)
        except ValueError:
            continue
        if net.version != addr.version or addr not in net:
            continue
        where = {"windows": "Windows Firewall", "sonicwall": "SonicWall group", "both": "Windows Firewall + SonicWall"}
        events.append({
            "kind": "range", "id": r.id, "target": r.cidr_notation, "scope": r.scope,
            "where": where.get(r.firewall_target, r.firewall_target),
            "server_name": S.registry.name(r.server_id) if r.server_id is not None else "", "reason": r.reason or "",
            "rule": f"SENTINEL BAN: {r.cidr_notation}", "banned_at": iso(r.banned_at), "banned_by": r.banned_by or "",
            "active": bool(r.is_active), "lifted_at": iso(r.lifted_at), "lifted_by": r.lifted_by or "",
            "duration_seconds": _dur(r.banned_at, r.lifted_at),
        })
    events.sort(key=lambda e: e["banned_at"] or "", reverse=True)
    return {
        "total": len(events), "ip_bans": sum(e["kind"] == "ip" for e in events),
        "range_bans": sum(e["kind"] == "range" for e in events), "active": sum(e["active"] for e in events),
        "first_banned": events[-1]["banned_at"] if events else None, "last_banned": events[0]["banned_at"] if events else None,
        "events": events[:200],
    }


@app.get("/threats/ban-history/{ip}")
async def threat_ban_history(ip: str, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        return await ban_history(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"'{ip[:64]}' is not a valid IP address") from exc


class AbuseLookupBody(BaseModel):
    ips: list[str] = Field(default_factory=list, max_length=500)


class AbuseTestBody(BaseModel):
    api_key: str | None = Field(default=None, max_length=256)


@app.get("/intel/abuseipdb")
async def abuseipdb_status(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return S.abuse.status()


@app.post("/intel/abuseipdb/lookup")
async def abuseipdb_lookup(body: AbuseLookupBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """Cached scores now; uncached public IPs are queued and arrive later as WS `abuseipdb` messages."""
    status = S.abuse.status()
    if not status["enabled"]:
        return {**status, "results": {}}
    return {**status, "results": S.abuse.request(body.ips)}


@app.get("/intel/abuseipdb/{ip}")
async def abuseipdb_check(ip: str, refresh: bool = False, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        ip = normalize_abuse_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"'{ip[:64]}' is not a valid IP address") from exc
    if not S.abuse.enabled():
        return {"ip": ip, "score": None, "disabled": True,
                "error": "AbuseIPDB lookups are turned off (CONFIG > GENERAL)" if S.abuse.configured()
                else "AbuseIPDB is not configured (CONFIG > GENERAL)"}
    result = await S.abuse.check(ip, refresh=refresh)
    if result.get("score") is not None:
        S.hub.broadcast({"type": "abuseipdb", "data": {result["ip"]: result}})
    return result


@app.post("/intel/abuseipdb/test", dependencies=[Depends(same_origin_guard)])
async def abuseipdb_test(body: AbuseTestBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """Check a well-known public address with the given (or saved) key, without saving anything."""
    result = await S.abuse.check("8.8.8.8", api_key=body.api_key if body.api_key else "")
    status = S.abuse.status()
    if result.get("error"):
        return {"ok": False, "error": result["error"], **{k: status[k] for k in ("limit", "remaining")}}
    return {"ok": True, "message": f"API key accepted: 8.8.8.8 scores {result.get('score')}% "
                                   f"({result.get('reports', 0)} reports, {result.get('isp') or 'unknown ISP'})",
            "limit": status["limit"], "remaining": status["remaining"]}


@app.get("/system/health")
async def system_health(server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    servers = S.health.snapshot()
    if server_id is not None:
        servers = [x for x in servers if x["server_id"] == server_id]
        if not servers and S.registry.get(server_id) is None:
            raise HTTPException(status_code=404, detail="Server not found")
    for sample in servers:
        if sample.get("cpu_percent") is not None:
            continue
        # Nothing collected since startup (or the server is offline): fall back to the last persisted sample.
        async with SessionLocal() as s:
            row = (await s.execute(
                select(SystemMetric).where(SystemMetric.server_id == sample["server_id"]).order_by(desc(SystemMetric.id)).limit(1)
            )).scalar_one_or_none()
        if row is not None:
            pools = json.loads(row.app_pools or "{}")
            sample.update({
                "ts": iso(row.ts), "cpu_percent": row.cpu_percent, "ram_percent": row.ram_percent,
                "disk_percent": row.disk_percent, "disk_free_percent": row.disk_free_percent,
                "disk_free_gb": row.disk_free_gb, "disk_path": row.disk_path,
                "app_pools": [{"name": k, "state": v, "running": v == "Started"} for k, v in pools.items()],
                "w3svc_state": row.w3svc_state, "uptime_seconds": row.uptime_seconds, "stale": True,
            })
    return {"servers": servers}


@app.get("/stats/baseline")
async def stats_baseline(server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"baseline": S.baseliner.snapshot(server_id), "pipeline": S.pipeline.stats(), "watchers": S.tailer.status()}


def _alert_dict(a: ActionableAlert) -> dict[str, Any]:
    try:
        details = json.loads(a.details or "{}")
    except json.JSONDecodeError:
        details = {}
    return {
        "id": a.id, "ts": iso(a.ts), "server_id": a.server_id, "server_name": S.registry.name(a.server_id),
        "status": a.status, "severity": a.severity, "category": a.category, "event": a.event or "", "title": a.title,
        "message": a.message, "source_ip": a.source_ip, "details": details, "acknowledged": a.acknowledged, "emailed": a.emailed,
    }


@app.get("/alerts")
async def list_alerts(limit: int = 100, severity: str | None = None, server_id: int | None = None,
                      status: str | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    q = select(ActionableAlert).order_by(desc(ActionableAlert.id)).limit(max(1, min(limit, 1000)))
    if severity:
        q = q.where(ActionableAlert.severity == severity.upper())
    if server_id is not None:
        q = q.where(ActionableAlert.server_id == server_id)
    if status:
        q = q.where(ActionableAlert.status == status.capitalize())
    async with SessionLocal() as s:
        rows = (await s.execute(q)).scalars().all()
    return {"alerts": [_alert_dict(a) for a in rows]}


class AlertTestBody(BaseModel):
    desktop: bool = True
    email: bool = True
    severity: Literal["INFO", "WARNING", "HIGH", "CRITICAL"] = "HIGH"


@app.get("/alerts/catalog")
async def alerts_catalog(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    exch = S.config.value
    return {**alert_catalog(), "exchange": {"enabled": bool(exch("exchange", "enabled", False)),
                                            "recipients": S.alerts.recipients(), "mailer": S.mailer.status()}}


@app.post("/alerts/test", dependencies=[Depends(same_origin_guard)])
async def alerts_test(body: AlertTestBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    record = await S.alerts.raise_alert(
        body.severity, "test", f"Test notification from {user['u']}",
        "If you can see this, Sentinel notifications reach you. Choose which events notify you in CONFIG > ALERTS.",
        details={"requested_by": user["u"]}, event="test", actionable=False,
        notify={"desktop": body.desktop, "email": False},
    )
    out: dict[str, Any] = {"ok": True, "alert": record, "email": None}
    if body.email:
        if not S.config.value("exchange", "enabled", False):
            out["email"] = {"ok": False, "error": "Exchange delivery is disabled (CONFIG > EXCHANGE)"}
        elif not S.alerts.recipients():
            out["email"] = {"ok": False, "error": "No alert recipients configured"}
        else:
            ok, err = await S.mailer.send(f"[IIS Sentinel][{body.severity}] Test notification",
                                          render_alert_html(record or {}), recipients=S.alerts.recipients(),
                                          retries=1, bypass_circuit=True)
            out["email"] = {"ok": ok, "error": err, "recipients": S.alerts.recipients()}
    return out


@app.post("/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async def _op(s):  # type: ignore[no-untyped-def]
        res = await s.execute(update(ActionableAlert).where(ActionableAlert.id == alert_id).values(acknowledged=True))
        return res.rowcount

    if not await run_db(_op):
        raise HTTPException(status_code=404, detail="Alert not found")
    S.hub.broadcast({"type": "alert_ack", "id": alert_id})
    return {"ok": True}


# --------------------------------------------------------------------------------------
# Monitored servers API
# --------------------------------------------------------------------------------------
class ServerBody(BaseModel):
    model_config = {"extra": "forbid"}

    server_name: str = Field(min_length=1, max_length=64)
    ip_address: str = Field(min_length=1, max_length=255)
    winrm_username: str = Field(default="", max_length=256)
    winrm_password: str = Field(default="", max_length=512)
    log_unc_path: str = Field(default="", max_length=1024)
    log_start_mode: Literal["end", "tail", "full"] = "end"
    log_tail_lines: int = Field(default=1000, ge=1, le=1_000_000)
    winrm_transport: Literal["ntlm", "kerberos", "credssp", "basic"] = "ntlm"
    winrm_port: int | None = Field(default=None, ge=1, le=65535)
    winrm_use_ssl: bool = False
    winrm_verify_ssl: bool = True
    enabled: bool = True


class ServerPatch(BaseModel):
    model_config = {"extra": "forbid"}

    server_name: str | None = Field(default=None, min_length=1, max_length=64)
    ip_address: str | None = Field(default=None, min_length=1, max_length=255)
    winrm_username: str | None = Field(default=None, max_length=256)
    winrm_password: str | None = Field(default=None, max_length=512)
    log_unc_path: str | None = Field(default=None, max_length=1024)
    log_start_mode: Literal["end", "tail", "full"] | None = None
    log_tail_lines: int | None = Field(default=None, ge=1, le=1_000_000)
    winrm_transport: Literal["ntlm", "kerberos", "credssp", "basic"] | None = None
    winrm_port: int | None = Field(default=None, ge=1, le=65535)
    winrm_use_ssl: bool | None = None
    winrm_verify_ssl: bool | None = None
    enabled: bool | None = None


@app.get("/servers")
async def list_servers(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"servers": _servers_payload(), "health": S.health.snapshot(), "logs": S.tailer.status()}


@app.post("/servers", status_code=201, dependencies=[Depends(same_origin_guard)])
async def add_server(body: ServerBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        server = await S.registry.add(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log.info("Server %s (%s) added by %s", server["server_name"], server["ip_address"], user["u"])
    await S.alerts.raise_alert("INFO", "config", f"Server {server['server_name']} added by {user['u']}",
                               f"{server['server_name']} ({server['ip_address']}) is now monitored. Logs: {server['log_unc_path'] or 'not configured'}.",
                               details={"user": user["u"], "ip_address": server["ip_address"]}, server_id=server["id"],
                               event="server_config_changed")
    return {"server": server}


@app.put("/servers/{server_id}", dependencies=[Depends(same_origin_guard)])
async def update_server(server_id: int, body: ServerPatch, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    before = S.registry.get(server_id)
    try:
        server = await S.registry.update(server_id, body.model_dump(exclude_none=True))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Server not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log.info("Server %s updated by %s", server["server_name"], user["u"])
    after = S.registry.get(server_id) or {}
    changed = sorted(k for k in after if k not in ("status",) and before and after.get(k) != before.get(k))
    if changed:
        await S.alerts.raise_alert("INFO", "config", f"Server {server['server_name']} edited by {user['u']}",
                                   f"Changed: {', '.join(changed)}.", details={"user": user["u"], "changed": changed},
                                   server_id=server_id, event="server_config_changed")
    return {"server": server}


@app.delete("/servers/{server_id}", dependencies=[Depends(same_origin_guard)])
async def delete_server(server_id: int, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if server_id == LOCAL_SERVER_ID:
        raise HTTPException(status_code=400, detail="The local server is controlled by watchers.log_dirs")
    name = S.registry.name(server_id)
    try:
        await S.registry.remove(server_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Server not found") from exc
    log.info("Server %s removed by %s", name, user["u"])
    await S.alerts.raise_alert("INFO", "config", f"Server {name} removed by {user['u']}",
                               f"{name} is no longer monitored.", details={"user": user["u"], "server": name},
                               event="server_config_changed")
    return {"ok": True}


@app.post("/servers/{server_id}/test", dependencies=[Depends(same_origin_guard)])
async def test_server(server_id: int, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if S.registry.get(server_id) is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return await S.remote.test(server_id)


# --------------------------------------------------------------------------------------
# Active defense (manual, operator-approved firewall bans)
# --------------------------------------------------------------------------------------
class BanBody(BaseModel):
    alert_id: int | None = Field(default=None, ge=1)
    server_id: int | None = Field(default=None, ge=0)
    ip: str | None = Field(default=None, max_length=64)


class DismissBody(BaseModel):
    alert_id: int = Field(ge=1)


def _ban_dict(b: BannedIP) -> dict[str, Any]:
    return {
        "id": b.id, "server_id": b.server_id, "server_name": S.registry.name(b.server_id), "ip_address": b.ip_address,
        "alert_id": b.alert_id, "rule_name": b.rule_name, "banned_by": b.banned_by, "banned_at": iso(b.banned_at),
        "active": b.active, "provider": b.provider or "windows", "windows_rule": b.windows_rule or "",
        "provider_label": FIREWALL_PROVIDERS.get(b.provider or "windows", b.provider),
    }


async def _set_alert_status(server_id: int, ip: str, status: str, primary_id: int | None) -> list[int]:
    """Mark the approved alert, plus every other pending alert for the same attacker on the same server."""
    async def _op(s):  # type: ignore[no-untyped-def]
        cond = and_(ActionableAlert.server_id == server_id, ActionableAlert.source_ip == ip, ActionableAlert.status == "Pending")
        if primary_id is not None:
            cond = cond | (ActionableAlert.id == primary_id)
        ids = (await s.execute(select(ActionableAlert.id).where(cond))).scalars().all()
        if ids:
            await s.execute(update(ActionableAlert).where(ActionableAlert.id.in_(ids)).values(status=status, acknowledged=True))
        return list(ids)

    ids = await run_db(_op)
    for alert_id in ids:
        S.alerts.update_recent(alert_id, status=status, acknowledged=True)
    return ids


async def _execute_ban(server_id: int, ip: str, alert_id: int | None, user: str) -> dict[str, Any]:
    """Block `ip` with the configured provider, record it and approve the attacker's pending alerts.
    Raises HTTPException (after raising a ban_failed alert) when the block could not be created."""
    try:
        ip = validate_ban_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    server = S.registry.get(server_id)
    if server is None:
        raise HTTPException(status_code=409, detail=f"Target server {S.registry.name(server_id)} is no longer monitored")
    allowed = await allowlist_overlaps(ip)
    if allowed:
        raise HTTPException(status_code=409, detail=f"{ip} is allowlisted ({allowed[0]['ip_or_cidr']}"
                                                    f"{': ' + allowed[0]['description'] if allowed[0]['description'] else ''})")

    provider = S.firewall.provider()
    perimeter = provider != "windows"
    where = FIREWALL_PROVIDERS[provider] if perimeter else server["server_name"]
    windows_rule = ""
    async with S.ban_locks[(-1 if perimeter else server_id, ip)]:
        log.warning("BAN requested by %s: %s via %s (target %s, alert %s)", user, ip, where, server["server_name"], alert_id)
        try:
            try:
                ok, output = await S.firewall.ban(provider, server_id, ip)
            except asyncio.TimeoutError as exc:
                raise HTTPException(status_code=504, detail=f"{where} did not respond in time") from exc
            except (RemoteError, FirewallError, ValueError) as exc:
                raise HTTPException(status_code=502, detail=f"Ban failed on {where}: {exc}") from exc
            except Exception as exc:  # noqa: BLE001
                log.exception("Ban of %s via %s failed", ip, where)
                raise HTTPException(status_code=502, detail=f"Ban failed on {where}: {type(exc).__name__}: {exc}") from exc
            if not ok:
                log.error("netsh on %s refused ban of %s: %s", server["server_name"], ip, output)
                raise HTTPException(status_code=502, detail=f"netsh on {server['server_name']} failed: {output[:400]}")
        except HTTPException as exc:
            await S.alerts.raise_alert(
                "HIGH", "defense", f"Firewall ban FAILED: {ip}",
                f"{user} approved banning {ip} but the block could not be created on {where}: {exc.detail}. "
                "The attacker is NOT blocked.", details={"ip": ip, "error": str(exc.detail), "alert_id": alert_id,
                                                         "provider": provider},
                server_id=server_id, event="ban_failed", actionable=False,
            )
            raise

        if perimeter and S.firewall.also_windows(provider):
            # Add-on rule on the attacked server; the perimeter block already succeeded, so a failure here is reported only.
            try:
                w_ok, w_out = await S.firewall.ban("windows", server_id, ip)
            except Exception as exc:  # noqa: BLE001
                w_ok, w_out = False, f"{type(exc).__name__}: {exc}"
            if w_ok:
                windows_rule = f"SENTINEL BAN: {ip}"
                output = f"{output}; Windows Firewall rule '{windows_rule}' added on {server['server_name']}"
            else:
                output = f"{output}; WARNING: the Windows Firewall rule on {server['server_name']} failed: {str(w_out)[:200]}"

        rule = S.firewall.rule_name(provider, ip)

        async def _op(s):  # type: ignore[no-untyped-def]
            cond = and_(BannedIP.ip_address == ip, BannedIP.active.is_(True), BannedIP.provider == provider)
            if not perimeter:
                cond = and_(cond, BannedIP.server_id == server_id)
            row = (await s.execute(select(BannedIP).where(cond))).scalars().first()
            if row is None:
                row = BannedIP(server_id=server_id, ip_address=ip, alert_id=alert_id, rule_name=rule, provider=provider,
                               windows_rule=windows_rule, banned_by=user, banned_at=utcnow(), active=True)
                s.add(row)
                await s.flush()
            elif windows_rule and not row.windows_rule:
                row.windows_rule = windows_rule
            return _ban_dict(row)

        ban = await run_db(_op)
        # A perimeter block covers every server, so the attacker's pending alerts everywhere are resolved.
        targets = [server_id] + ([x["id"] for x in S.registry.all(enabled_only=False) if x["id"] != server_id] if perimeter else [])
        alert_ids: list[int] = []
        for sid in targets:
            alert_ids += await _set_alert_status(sid, ip, "Approved", alert_id if sid == server_id else None)
    for sid in targets:
        S.threats.clear(sid, ip)
    S.hub.broadcast({"type": "ban", "data": ban, "alert_ids": alert_ids, "status": "Approved", "output": output[:500]})
    msg = (f"{user} approved the ban. Windows Firewall rule '{rule}' is now blocking {ip} on {server['server_name']}."
           if not perimeter else
           f"{user} approved the ban. {output}. {ip} is now blocked at the {where} perimeter for every server.")
    await S.alerts.raise_alert(
        "INFO", "defense", f"Firewall ban executed: {ip}", msg,
        details={"ip": ip, "rule": rule, "provider": provider, "alert_ids": alert_ids, "output": output[:500]},
        server_id=server_id, event="ban_executed",
    )
    return {"ok": True, "ban": ban, "alert_ids": alert_ids, "output": output}


@app.post("/defense/ban", dependencies=[Depends(same_origin_guard)])
async def defense_ban(body: BanBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if body.alert_id is not None:
        async with SessionLocal() as s:
            alert = await s.get(ActionableAlert, body.alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        if not alert.source_ip:
            raise HTTPException(status_code=400, detail="This alert has no source IP to ban")
        if alert.status == "Approved":
            raise HTTPException(status_code=409, detail="This alert has already been approved and the IP banned")
        server_id, ip = alert.server_id, alert.source_ip
    elif body.server_id is not None and body.ip:
        server_id, ip = body.server_id, body.ip.strip()
    else:
        raise HTTPException(status_code=400, detail="Provide alert_id (or server_id + ip)")
    return await _execute_ban(server_id, ip, body.alert_id, user["u"])


class BanAllBody(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)


@app.post("/defense/ban-all", dependencies=[Depends(same_origin_guard)])
async def defense_ban_all(body: BanAllBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ids = sorted({i for i in body.alert_ids if i > 0})
    async with SessionLocal() as s:
        alerts = (await s.execute(select(ActionableAlert).where(ActionableAlert.id.in_(ids)))).scalars().all()
    perimeter = S.firewall.provider() != "windows"
    targets: dict[tuple[int, str], dict[str, Any]] = {}
    skipped: list[dict[str, Any]] = []
    found = {a.id for a in alerts}
    skipped += [{"alert_id": i, "reason": "alert not found"} for i in ids if i not in found]
    for a in alerts:
        if a.status != "Pending" or not a.source_ip:
            skipped.append({"alert_id": a.id, "reason": f"status {a.status}" if a.source_ip else "no source IP"})
            continue
        # A perimeter block covers every server, so one firewall call per IP; Windows bans are per server.
        key = (-1 if perimeter else a.server_id, a.source_ip)
        t = targets.setdefault(key, {"server_id": a.server_id, "ip": a.source_ip, "alert_id": a.id, "alert_ids": [],
                                     "servers": set()})
        t["alert_ids"].append(a.id)
        t["servers"].add(a.server_id)
    if not targets:
        raise HTTPException(status_code=409, detail="None of the selected alerts are pending with a source IP")
    log.warning("BAN ALL requested by %s: %d IP(s) from %d alert(s)", user["u"], len(targets), len(ids))

    sem = asyncio.Semaphore(4)
    banned: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    approved: set[int] = set()
    servers: set[int] = set()

    async def one(t: dict[str, Any]) -> None:
        async with sem:
            try:
                res = await _execute_ban(t["server_id"], t["ip"], t["alert_id"], user["u"])
            except HTTPException as exc:
                failed.append({"ip": t["ip"], "server_id": t["server_id"], "server_name": S.registry.name(t["server_id"]),
                               "alert_ids": t["alert_ids"], "error": str(exc.detail)})
                return
            except Exception as exc:  # noqa: BLE001
                log.exception("BAN ALL: ban of %s failed", t["ip"])
                failed.append({"ip": t["ip"], "server_id": t["server_id"], "server_name": S.registry.name(t["server_id"]),
                               "alert_ids": t["alert_ids"], "error": f"{type(exc).__name__}: {exc}"})
                return
            approved.update(res["alert_ids"])
            approved.update(t["alert_ids"])
            servers.update(t["servers"])
            banned.append({"ip": t["ip"], "server_id": t["server_id"], "server_name": S.registry.name(t["server_id"]),
                           "alert_ids": res["alert_ids"], "output": res["output"][:300]})

    await asyncio.gather(*(one(t) for t in targets.values()))
    if len(banned) > 1 or failed:
        await S.alerts.raise_alert(
            "WARNING" if failed else "INFO", "defense", f"BAN ALL by {user['u']}: {len(banned)} banned, {len(failed)} failed",
            f"Banned {len(banned)} IP(s) across {len(servers)} server(s)."
            + (f" Failed: {', '.join(f['ip'] for f in failed[:10])}." if failed else ""),
            details={"banned": [b["ip"] for b in banned], "failed": failed[:50], "user": user["u"]},
            event="ban_failed" if failed else "ban_executed", actionable=False,
        )
    return {"ok": not failed, "banned": banned, "failed": failed, "skipped": skipped, "alert_ids": sorted(approved),
            "ip_count": len(banned), "server_count": len(servers)}


@app.post("/defense/dismiss", dependencies=[Depends(same_origin_guard)])
async def defense_dismiss(body: DismissBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async def _op(s):  # type: ignore[no-untyped-def]
        row = await s.get(ActionableAlert, body.alert_id)
        if row is None:
            return None
        if row.status == "Pending":
            row.status = "Dismissed"
            row.acknowledged = True
        return row.status

    status = await run_db(_op)
    if status is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    S.alerts.update_recent(body.alert_id, status=status, acknowledged=True)
    S.hub.broadcast({"type": "alert_status", "ids": [body.alert_id], "status": status})
    log.info("Alert %s dismissed by %s", body.alert_id, user["u"])
    return {"ok": True, "status": status}


@app.get("/defense/bans")
async def list_bans(active: bool = True, server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    q = select(BannedIP).order_by(desc(BannedIP.id)).limit(500)
    if active:
        q = q.where(BannedIP.active.is_(True))
    if server_id is not None:
        q = q.where(BannedIP.server_id == server_id)
    async with SessionLocal() as s:
        rows = (await s.execute(q)).scalars().all()
    return {"bans": [_ban_dict(b) for b in rows]}


@app.delete("/defense/bans/{ban_id}", dependencies=[Depends(same_origin_guard)])
async def lift_ban(ban_id: int, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async with SessionLocal() as s:
        ban = await s.get(BannedIP, ban_id)
    if ban is None or not ban.active:
        raise HTTPException(status_code=404, detail="Active ban not found")
    provider = ban.provider or "windows"
    name = S.registry.name(ban.server_id) if provider == "windows" else FIREWALL_PROVIDERS.get(provider, provider)
    if provider != "windows" or S.registry.get(ban.server_id) is not None:
        try:
            ok, output = await S.firewall.unban(provider, ban.server_id, ban.ip_address)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"Unban failed on {name}: {type(exc).__name__}: {exc}") from exc
        if not ok and "No rules match" not in output:
            raise HTTPException(status_code=502, detail=f"netsh on {name} failed: {output[:400]}")
    extra = ""
    if provider != "windows" and ban.windows_rule and S.registry.get(ban.server_id) is not None:
        try:
            w_ok, w_out = await S.remote.unban(ban.server_id, ban.ip_address)
            if not w_ok and "No rules match" not in w_out:
                extra = f" The Windows Firewall rule on {S.registry.name(ban.server_id)} could not be removed: {w_out[:200]}"
        except Exception as exc:  # noqa: BLE001
            extra = f" The Windows Firewall rule on {S.registry.name(ban.server_id)} could not be removed: {exc}"

    async def _op(s):  # type: ignore[no-untyped-def]
        await s.execute(update(BannedIP).where(BannedIP.id == ban_id).values(active=False, lifted_at=utcnow(), lifted_by=user["u"]))

    await run_db(_op)
    log.warning("Ban %s (%s on %s) lifted by %s", ban_id, ban.ip_address, name, user["u"])
    S.hub.broadcast({"type": "unban", "id": ban_id, "server_id": ban.server_id, "ip_address": ban.ip_address})
    await S.alerts.raise_alert("INFO", "defense", f"Firewall ban lifted: {ban.ip_address}",
                               f"{user['u']} removed the Sentinel block for {ban.ip_address} on {name}.{extra}",
                               details={"ip": ban.ip_address, "user": user["u"]}, server_id=ban.server_id,
                               event="ban_lifted", actionable=False)
    return {"ok": True}


# --------------------------------------------------------------------------------------
# CIDR range bans, subnet escalation and the allowlist
# --------------------------------------------------------------------------------------
class RangeBanBody(BaseModel):
    model_config = {"extra": "forbid"}

    alert_id: int | None = Field(default=None, ge=1)
    ip: str | None = Field(default=None, max_length=64)
    server_id: int | None = Field(default=None, ge=0)
    scope: str | None = Field(default=None, max_length=8)
    firewall_target: Literal["windows", "sonicwall", "both"] | None = None


class AllowlistBody(BaseModel):
    ip_or_cidr: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=256)


def _clean_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"'{str(ip)[:64]}' is not a valid IP address") from exc
    return str(addr.ipv4_mapped if addr.version == 6 and addr.ipv4_mapped else addr)


def _range_dict(r: BannedRange) -> dict[str, Any]:
    try:
        ips = json.loads(r.source_ips or "[]")
    except ValueError:
        ips = []
    try:
        applied = json.loads(r.applied or "{}")
    except ValueError:
        applied = {}
    return {
        "id": r.id, "cidr": r.cidr_notation, "cidr_notation": r.cidr_notation, "scope": r.scope, "reason": r.reason,
        "threat_score": r.threat_score, "banned_at": iso(r.banned_at), "is_active": r.is_active,
        "source_ip_count": r.source_ip_count, "source_ips": ips, "server_id": r.server_id,
        "server_name": S.registry.name(r.server_id) if r.server_id is not None else "",
        "firewall_target": r.firewall_target, "applied": applied, "alert_id": r.alert_id, "banned_by": r.banned_by,
        "output": r.output, "lifted_at": iso(r.lifted_at), "lifted_by": r.lifted_by,
        "size": parse_network(r.cidr_notation).num_addresses if r.cidr_notation else 0,
    }


@app.get("/intel/recommend-cidr")
async def recommend_cidr(ip: str, server_id: int | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """Everything the BAN THREAT dialog needs: escalation advice, WHOIS, allowlist / self-ban pre-flight per scope."""
    ip = _clean_ip(ip)
    rec, whois = await asyncio.gather(calculate_escalation_cidr(ip), S.whois.enrich_ip(ip))
    for opt in rec["options"]:
        pre = await S.defense.preflight(opt["cidr"])
        opt.update({"recommended": opt["cidr"] == rec["recommended_cidr"], "blocked": not pre["ok"], "error": pre["error"],
                    "allowlist": pre["allowlist"]})
    w = whois or {}
    have_whois = not w.get("error") and any(w.get(k) for k in ("organization", "network_name", "country", "origin_as"))
    sw = S.defense.sonicwall_status()
    threat = S.threats.ip_detail(ip, server_id) or {}
    return {
        **rec,
        "whois": ({"organization": w.get("organization") or w.get("network_name"), "network_name": w.get("network_name"),
                   "asn": ", ".join(w.get("origin_as") or []), "country": w.get("country"), "registry": w.get("registry"),
                   "abuse_email": w.get("abuse_email"), "abuse_phone": w.get("abuse_phone"), "cidr_range": w.get("cidr_range"),
                   "reverse_dns": w.get("reverse_dns"), "summary": w.get("summary")} if have_whois else None),
        "whois_error": None if have_whois else (w.get("error") or "No WHOIS data available"),
        "allowlisted": any(o["allowlist"] for o in rec["options"] if o["recommended"]),
        "default_target": S.defense.default_target(),
        "targets": {"windows": {"ready": bool(S.registry.all()), "error": None if S.registry.all() else "no monitored servers"},
                    "sonicwall": {"ready": sw["ready"], "error": sw["error"], "group": sw["group"]}},
        "threat_score": threat.get("score"),
    }


async def _approve_alerts_in(net: Any, server_ids: list[int] | None, primary_id: int | None) -> list[int]:
    """Approve every Pending alert whose source IP falls in `net` (on the given servers, or all when None)."""
    async def _op(s):  # type: ignore[no-untyped-def]
        q = select(ActionableAlert.id, ActionableAlert.source_ip, ActionableAlert.server_id).where(
            ActionableAlert.status == "Pending", ActionableAlert.source_ip.is_not(None)).limit(20000)
        ids = []
        for aid, src, sid in (await s.execute(q)).all():
            if server_ids is not None and sid not in server_ids:
                continue
            try:
                if parse_network(src).network_address in net:
                    ids.append(aid)
            except ValueError:
                continue
        if primary_id is not None and primary_id not in ids:
            ids.append(primary_id)
        if ids:
            await s.execute(update(ActionableAlert).where(ActionableAlert.id.in_(ids)).values(status="Approved", acknowledged=True))
        return ids

    ids = await run_db(_op)
    for alert_id in ids:
        S.alerts.update_recent(alert_id, status="Approved", acknowledged=True)
    return ids


@app.post("/defense/ban-range", dependencies=[Depends(same_origin_guard)])
async def defense_ban_range(body: RangeBanBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    alert: ActionableAlert | None = None
    if body.alert_id is not None:
        async with SessionLocal() as s:
            alert = await s.get(ActionableAlert, body.alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        if not alert.source_ip:
            raise HTTPException(status_code=400, detail="This alert has no source IP to ban")
        ip, server_id = alert.source_ip, alert.server_id
    elif body.ip:
        ip, server_id = body.ip, body.server_id
    else:
        raise HTTPException(status_code=400, detail="Provide alert_id (or ip)")
    ip = _clean_ip(ip)
    rec = await calculate_escalation_cidr(ip)
    try:
        net = network_for_scope(ip, body.scope) if body.scope else parse_network(rec["recommended_cidr"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scope = f"/{net.prefixlen}"
    target = body.firewall_target or S.defense.default_target()
    if str(net) == rec["recommended_cidr"]:
        reason = rec["reason"]
    else:
        reason = f"operator chose {scope} (recommended {rec['scope']}: {rec['reason']})"
    sources = [ip] + [x for x in rec["attacker_ips"] if parse_network(x).network_address in net]
    threat = S.threats.ip_detail(ip, server_id) or {}
    result = await S.defense.execute_range_ban(
        str(net), scope, target, server_id, reason=reason,
        threat_score=float(threat.get("score") or 0), source_ips=sources, alert_id=body.alert_id, user=user["u"])
    where = {"windows": "Windows Firewall", "sonicwall": "the SonicWall group", "both": "Windows Firewall + SonicWall"}[target]
    if not result["success"]:
        await S.alerts.raise_alert(
            "HIGH", "defense", f"Range ban FAILED: {net}",
            f"{user['u']} approved banning {net} ({scope}) on {where} but it was not applied: {result['error']}. "
            "The range is NOT blocked.", details={"cidr": str(net), "error": result["error"], "alert_id": body.alert_id,
                                                  "results": result.get("results", [])},
            server_id=server_id if server_id is not None else LOCAL_SERVER_ID, event="ban_failed", actionable=False,
        )
        code = 409 if (result.get("allowlist") or result.get("protected")) else 502
        raise HTTPException(status_code=code, detail=result["error"])
    if result.get("already"):
        return {"ok": True, **result, "alert_ids": []}

    applied = result["applied"]
    scope_servers = None if applied.get("sonicwall") else list(applied.get("windows") or [])
    alert_ids = await _approve_alerts_in(net, scope_servers, body.alert_id)
    for srv in S.registry.all(enabled_only=False):
        if scope_servers is None or srv["id"] in scope_servers:
            for src_ip in sources:
                S.threats.clear(srv["id"], src_ip)
    async with SessionLocal() as s:
        row = await s.get(BannedRange, result["id"])
    data = _range_dict(row) if row else {}
    S.hub.broadcast({"type": "alert_status", "ids": alert_ids, "status": "Approved"})
    S.hub.broadcast({"type": "range_ban_notification", "cidr": str(net), "scope": scope, "reason": reason,
                     "firewall_target": target, "data": data, "alert_ids": alert_ids})
    partial = "; ".join(f"{r['target']}{' ' + r['server'] if r['server'] else ''}: {r['message']}"
                        for r in result["results"] if not r["ok"])
    await S.alerts.raise_alert(
        "WARNING" if partial else "INFO", "defense", f"Range ban executed: {net} ({scope})",
        f"{user['u']} banned {net} ({net.num_addresses:,} address{'es' if net.num_addresses != 1 else ''}) on {where}. "
        f"Reason: {reason}." + (f" Partially failed: {partial}" if partial else ""),
        details={"cidr": str(net), "scope": scope, "firewall_target": target, "reason": reason, "source_ips": sources[:50],
                 "alert_ids": alert_ids, "results": result["results"]},
        server_id=server_id if server_id is not None else LOCAL_SERVER_ID, event="range_ban_executed", actionable=False,
    )
    return {"ok": True, **result, "reason": reason, "alert_ids": alert_ids, "range": data}


@app.get("/banned-ranges")
async def list_banned_ranges(active: bool | None = None, page: int = 1, page_size: int = 50,
                             _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    q = select(BannedRange)
    cq = select(func.count(BannedRange.id))
    if active is not None:
        q, cq = q.where(BannedRange.is_active.is_(active)), cq.where(BannedRange.is_active.is_(active))
    async with SessionLocal() as s:
        total = (await s.execute(cq)).scalar_one()
        rows = (await s.execute(q.order_by(desc(BannedRange.id)).offset((page - 1) * page_size).limit(page_size))).scalars().all()
    return {"ranges": [_range_dict(r) for r in rows], "total": total, "page": page, "page_size": page_size,
            "pages": max(1, -(-total // page_size))}


@app.delete("/banned-ranges/{range_id}", dependencies=[Depends(same_origin_guard)])
async def lift_banned_range(range_id: int, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    result = await S.defense.lift_range_ban(range_id, user["u"])
    if not result["success"]:
        raise HTTPException(status_code=404 if result.get("not_found") else 502, detail=result["error"])
    S.hub.broadcast({"type": "range_unban", "id": range_id, "cidr": result["cidr"]})
    await S.alerts.raise_alert(
        "INFO", "defense", f"Range ban lifted: {result['cidr']}",
        f"{user['u']} removed the Sentinel block for {result['cidr']} ({result['firewall_target']}).",
        details={"cidr": result["cidr"], "user": user["u"], "results": result["results"]},
        server_id=result["server_id"] if result["server_id"] is not None else LOCAL_SERVER_ID,
        event="range_ban_lifted", actionable=False,
    )
    return {"ok": True, **result}


def _allow_dict(r: AllowlistEntry) -> dict[str, Any]:
    return {"id": r.id, "ip_or_cidr": r.ip_or_cidr, "description": r.description, "added_by": r.added_by,
            "added_at": iso(r.added_at), "is_active": r.is_active}


@app.get("/allowlist")
async def list_allowlist(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async with SessionLocal() as s:
        rows = (await s.execute(select(AllowlistEntry).where(AllowlistEntry.is_active.is_(True))
                                .order_by(desc(AllowlistEntry.id)))).scalars().all()
    return {"entries": [_allow_dict(r) for r in rows]}


@app.post("/allowlist", status_code=201, dependencies=[Depends(same_origin_guard)])
async def add_allowlist(body: AllowlistBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        net = parse_network(body.ip_or_cidr)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"'{body.ip_or_cidr}' is not a valid IP address or CIDR range") from exc
    value = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    entry = AllowlistEntry(ip_or_cidr=value, description=body.description.strip(), added_by=user["u"],
                           added_at=utcnow(), is_active=True)

    async def _op(s):  # type: ignore[no-untyped-def]
        s.add(entry)
        await s.flush()
        return _allow_dict(entry)

    data = await run_db(_op)
    async with SessionLocal() as s:
        overlapping = [r.cidr_notation for r in (await s.execute(select(BannedRange).where(BannedRange.is_active.is_(True)))).scalars()
                       if parse_network(r.cidr_notation).version == net.version and parse_network(r.cidr_notation).overlaps(net)]
    log.info("Allowlist: %s added by %s", value, user["u"])
    S.hub.broadcast({"type": "allowlist", "action": "add", "data": data})
    return {"ok": True, "entry": data, "overlapping_bans": overlapping}


@app.delete("/allowlist/{entry_id}", dependencies=[Depends(same_origin_guard)])
async def delete_allowlist(entry_id: int, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async def _op(s):  # type: ignore[no-untyped-def]
        res = await s.execute(update(AllowlistEntry).where(AllowlistEntry.id == entry_id, AllowlistEntry.is_active.is_(True))
                              .values(is_active=False))
        return res.rowcount

    if not await run_db(_op):
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    log.info("Allowlist entry %s removed by %s", entry_id, user["u"])
    S.hub.broadcast({"type": "allowlist", "action": "delete", "id": entry_id})
    return {"ok": True}


# --------------------------------------------------------------------------------------
# Reports API
# --------------------------------------------------------------------------------------
@app.get("/reports")
async def list_reports(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async with SessionLocal() as s:
        rows = (await s.execute(select(ScheduledReport).order_by(desc(ScheduledReport.id)).limit(50))).scalars().all()
    return {
        "next_runs": S.reporter.next_runs(),
        "reports": [
            {"id": r.id, "type": r.report_type, "generated_at": iso(r.generated_at), "period_start": iso(r.period_start),
             "period_end": iso(r.period_end), "subject": r.subject, "status": r.status, "error": r.error,
             "total_requests": r.total_requests, "threat_count": r.threat_count}
            for r in rows
        ],
    }


@app.post("/reports/run")
async def run_report(body: ReportRunBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        return await S.reporter.run_report(body.kind, send=body.send)
    except Exception as exc:  # noqa: BLE001
        log.exception("Manual report failed")
        raise HTTPException(status_code=500, detail=f"Report failed: {type(exc).__name__}: {exc}") from exc


@app.get("/reports/{report_id}/html", response_class=HTMLResponse)
async def report_html(report_id: int, _user: dict[str, Any] = Depends(current_user)) -> HTMLResponse:
    async with SessionLocal() as s:
        row = await s.get(ScheduledReport, report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found")
    resp = HTMLResponse(row.html)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    return resp


# --------------------------------------------------------------------------------------
# WebSocket
# --------------------------------------------------------------------------------------
@app.websocket("/ws/dashboard")
async def ws_dashboard(ws: WebSocket) -> None:
    await ws.accept()
    user = S.signer.verify(ws.cookies.get(COOKIE_NAME))
    if not user:
        await ws.close(code=4401, reason="unauthenticated")
        return
    if not _same_origin(ws.headers.get("origin"), ws.headers.get("host")):
        await ws.close(code=4403, reason="cross-origin")
        return

    client_id, queue = S.hub.register()
    hello = {
        "type": "hello",
        "server_time": time.time(),
        "user": user["u"],
        "display_name": user["d"],
        "demo": DEMO_MODE,
        "logs": list(S.pipeline.recent)[-200:],
        "servers": _servers_payload(),
        "health": S.health.snapshot(),
        "threats": S.threats.active_threats(),
        "counts": S.threats.counts(),
        "alerts": S.alerts.recent(50),
        "baseline": S.baseliner.snapshot(),
        "pipeline": S.pipeline.stats(),
        "firewall": S.firewall.summary(),
        "default_theme": S.config.value("general", "default_theme", "cyber"),
        "abuseipdb": S.abuse.status(),
    }

    async def sender() -> None:
        await ws.send_text(json.dumps(hello, default=str))
        while True:
            await ws.send_text(await queue.get())

    send_task = asyncio.create_task(sender())
    try:
        while True:
            recv = asyncio.create_task(ws.receive_text())
            done, _ = await asyncio.wait({recv, send_task}, return_when=asyncio.FIRST_COMPLETED)
            if send_task in done:
                recv.cancel()
                break
            msg = recv.result()
            if msg == "ping":
                await queue.put(json.dumps({"type": "pong", "server_time": time.time()}))
            if not S.signer.verify(ws.cookies.get(COOKIE_NAME)):
                break
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:  # noqa: BLE001
        log.exception("WebSocket error")
    finally:
        S.hub.unregister(client_id)
        send_task.cancel()
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("SENTINEL_HOST", "0.0.0.0")
    port = int(os.environ.get("SENTINEL_PORT", "1337"))
    ssl_cert = os.environ.get("SENTINEL_SSL_CERT")
    ssl_key = os.environ.get("SENTINEL_SSL_KEY")
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        log_level="info",
        ws_ping_interval=20,
        ws_ping_timeout=20,
        ssl_certfile=ssl_cert or None,
        ssl_keyfile=ssl_key or None,
        proxy_headers=False,
    )
