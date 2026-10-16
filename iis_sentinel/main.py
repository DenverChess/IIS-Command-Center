"""IIS Sentinel - FastAPI application: REST API, WebSocket push and background task orchestration.

Run:  python main.py            (or: uvicorn main:app --host 0.0.0.0 --port 1337)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from typing import Any, AsyncIterator, Awaitable, Callable, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, func, insert, select, update

from ad_auth import ADAuthenticator
from alert_catalog import ANOMALY_EVENTS, SIGNATURE_EVENTS
from alert_catalog import catalog as alert_catalog
from baseliner import Baseliner
from database import (
    BASE_DIR,
    DATA_DIR,
    DEMO_MODE,
    LOCAL_SERVER_ID,
    ActionableAlert,
    BannedIP,
    ConfigStore,
    LogEntry,
    ScheduledReport,
    ServerRegistry,
    SessionLocal,
    SystemMetric,
    engine,
    get_or_create_session_secret,
    init_db,
    iso,
    run_db,
    utcnow,
)
from events import AlertManager, Hub
from firewall import PROVIDERS as FIREWALL_PROVIDERS
from firewall import FirewallError, FirewallManager
from geoip import GeoResolver
from http_monitor import HttpMonitor
from log_tailer import LogTailer, run_demo_fleet
from whois_lookup import WhoisClient
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
    FLUSH_SECONDS = 1.0
    WS_SECONDS = 0.3
    MAX_BUFFER = 50000

    def __init__(self, queue: asyncio.Queue[dict[str, Any]], threats: ThreatEngine, baseliner: Baseliner,
                 alerts: AlertManager, hub: Hub, http: HttpMonitor,
                 site_name: Callable[[int, str], str] = lambda _sid, _site: "") -> None:
        self.queue = queue
        self.threats = threats
        self.baseliner = baseliner
        self.alerts = alerts
        self.hub = hub
        self.http = http
        self.site_name = site_name
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
            elif kind == "threat_cleared":
                await self.alerts.raise_alert(
                    "INFO", "recovery", f"Threat cleared: {ip}", "Threat score decayed below the threshold.",
                    details={"ip": ip}, dedup_key=f"cleared:{sid}:{ip}", cooldown=1800, server_id=sid,
                    event="threat_cleared",
                )

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
            await run_db(_op)
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
    S.baseliner = Baseliner(S.config)
    S.health = HealthMonitor(S.config, S.alerts, S.hub, S.registry, S.remote)
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=50000)
    S.tailer = LogTailer(S.config, S.registry, S.remote, queue, on_status=_log_feed_status, on_sites=_sites_discovered)
    S.ban_locks = defaultdict(asyncio.Lock)
    S.http = HttpMonitor(S.config)
    S.pipeline = Pipeline(queue, S.threats, S.baseliner, S.alerts, S.hub, S.http, S.health.site_name)
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
                                    "/servers", "/defense")):
        response.headers["Cache-Control"] = "no-store"
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


@app.get("/firewall")
async def firewall_summary(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {**S.firewall.summary(), "providers": FIREWALL_PROVIDERS}


@app.post("/firewall/test", dependencies=[Depends(same_origin_guard)])
async def firewall_test(body: FirewallTestBody, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return await S.firewall.test(body.provider)


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
    return {"whois": result, "bans": [_ban_dict(b) for b in bans], "alert_count": alert_count}


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
        "active": b.active, "provider": b.provider or "windows",
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


@app.post("/defense/ban", dependencies=[Depends(same_origin_guard)])
async def defense_ban(body: BanBody, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    alert: ActionableAlert | None = None
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

    try:
        ip = validate_ban_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    server = S.registry.get(server_id)
    if server is None:
        raise HTTPException(status_code=409, detail=f"Target server {S.registry.name(server_id)} is no longer monitored")

    provider = S.firewall.provider()
    perimeter = provider != "windows"
    where = FIREWALL_PROVIDERS[provider] if perimeter else server["server_name"]
    async with S.ban_locks[(-1 if perimeter else server_id, ip)]:
        log.warning("BAN requested by %s: %s via %s (target %s, alert %s)", user["u"], ip, where, server["server_name"], body.alert_id)
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
                f"{user['u']} approved banning {ip} but the block could not be created on {where}: {exc.detail}. "
                "The attacker is NOT blocked.", details={"ip": ip, "error": str(exc.detail), "alert_id": body.alert_id,
                                                         "provider": provider},
                server_id=server_id, event="ban_failed", actionable=False,
            )
            raise

        rule = S.firewall.rule_name(provider, ip)

        async def _op(s):  # type: ignore[no-untyped-def]
            cond = and_(BannedIP.ip_address == ip, BannedIP.active.is_(True), BannedIP.provider == provider)
            if not perimeter:
                cond = and_(cond, BannedIP.server_id == server_id)
            row = (await s.execute(select(BannedIP).where(cond))).scalars().first()
            if row is None:
                row = BannedIP(server_id=server_id, ip_address=ip, alert_id=body.alert_id, rule_name=rule, provider=provider,
                               banned_by=user["u"], banned_at=utcnow(), active=True)
                s.add(row)
                await s.flush()
            return _ban_dict(row)

        ban = await run_db(_op)
        # A perimeter block covers every server, so the attacker's pending alerts everywhere are resolved.
        targets = [server_id] + ([x["id"] for x in S.registry.all(enabled_only=False) if x["id"] != server_id] if perimeter else [])
        alert_ids: list[int] = []
        for sid in targets:
            alert_ids += await _set_alert_status(sid, ip, "Approved", body.alert_id if sid == server_id else None)
    for sid in targets:
        S.threats.clear(sid, ip)
    S.hub.broadcast({"type": "ban", "data": ban, "alert_ids": alert_ids, "status": "Approved", "output": output[:500]})
    msg = (f"{user['u']} approved the ban. Windows Firewall rule '{rule}' is now blocking {ip} on {server['server_name']}."
           if not perimeter else
           f"{user['u']} approved the ban. {output}. {ip} is now blocked at the {where} perimeter for every server.")
    await S.alerts.raise_alert(
        "INFO", "defense", f"Firewall ban executed: {ip}", msg,
        details={"ip": ip, "rule": rule, "provider": provider, "alert_ids": alert_ids, "output": output[:500]},
        server_id=server_id, event="ban_executed",
    )
    return {"ok": True, "ban": ban, "alert_ids": alert_ids, "output": output}


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

    async def _op(s):  # type: ignore[no-untyped-def]
        await s.execute(update(BannedIP).where(BannedIP.id == ban_id).values(active=False))

    await run_db(_op)
    log.warning("Ban %s (%s on %s) lifted by %s", ban_id, ban.ip_address, name, user["u"])
    S.hub.broadcast({"type": "unban", "id": ban_id, "server_id": ban.server_id, "ip_address": ban.ip_address})
    await S.alerts.raise_alert("INFO", "defense", f"Firewall ban lifted: {ban.ip_address}",
                               f"{user['u']} removed the Sentinel block for {ban.ip_address} on {name}.",
                               details={"ip": ban.ip_address, "user": user["u"]}, server_id=ban.server_id,
                               event="ban_lifted", actionable=False)
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
