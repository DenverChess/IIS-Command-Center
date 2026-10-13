"""IIS Sentinel - FastAPI application: REST API, WebSocket push and background task orchestration.

Run:  python main.py            (or: uvicorn main:app --host 0.0.0.0 --port 8443)
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
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import desc, insert, select, update

from ad_auth import ADAuthenticator
from baseliner import Baseliner
from database import (
    BASE_DIR,
    DATA_DIR,
    DEMO_MODE,
    Alert,
    ConfigStore,
    LogEntry,
    ScheduledReport,
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
from log_tailer import DemoTrafficGenerator, LogTailer
from mailer import Mailer
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
                 alerts: AlertManager, hub: Hub) -> None:
        self.queue = queue
        self.threats = threats
        self.baseliner = baseliner
        self.alerts = alerts
        self.hub = hub
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
            "site": entry.get("site", ""),
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

    async def _handle_events(self, events: list[dict[str, Any]]) -> None:
        for ev in events:
            kind = ev["kind"]
            ip = ev.get("ip")
            if kind == "signature":
                tags = "/".join(ev["tags"])
                await self.alerts.raise_alert(
                    "WARNING", "attack", f"{tags} attempt from {ip}",
                    f"Request matched {tags} signature(s) (HTTP {ev.get('status')}).",
                    source_ip=ip, details={"payload": ev["payload"], "tags": ev["tags"]},
                    dedup_key=f"sig:{ip}:{tags}", cooldown=600,
                )
            elif kind == "spike":
                await self.alerts.raise_alert(
                    "WARNING", "attack", f"HTTP {ev['spike']} spike from {ip}",
                    f"{ev['count']} {ev['spike']} responses within {int(ev['window'])}s.",
                    source_ip=ip, details={"count": ev["count"], "window_seconds": ev["window"]},
                    dedup_key=f"spike:{ip}:{ev['spike']}", cooldown=300,
                )
            elif kind == "active_threat":
                st = ev["state"]
                await self.alerts.raise_alert(
                    "HIGH", "threat", f"ACTIVE THREAT: {ip} (score {st['score']:.0f})",
                    f"Source {ip} ({st['geo']}) exceeded the threat threshold of {st['threshold']:.0f}. "
                    f"Signals: {', '.join(f'{k}x{v}' for k, v in st['tags'].items())}. "
                    "Consider blocking this address (IIS IP Restrictions / firewall).",
                    source_ip=ip,
                    details={"score": st["score"], "geo": st["geo"], "tags": st["tags"], "last_payload": st["last_payload"],
                             "requests": st["requests"]},
                    dedup_key=f"active:{ip}", cooldown=1800,
                )
            elif kind == "threat_cleared":
                await self.alerts.raise_alert(
                    "INFO", "recovery", f"Threat cleared: {ip}", "Threat score decayed below the threshold.",
                    source_ip=ip, dedup_key=f"cleared:{ip}", cooldown=1800,
                )

    async def _handle_anomalies(self, anomalies: list[dict[str, Any]], entry: dict[str, Any] | None) -> None:
        labels = {
            "rpm": "Request volume", "bpm": "Bandwidth", "time_taken": "Response time",
            "global_rpm": "Server-wide request volume", "global_bpm": "Server-wide bandwidth",
            "global_rpm_drop": "Server-wide traffic DROP",
        }
        for a in anomalies:
            metric, ip = a["metric"], a.get("ip")
            if ip and metric in ("rpm", "bpm"):
                delta, events = self.threats.apply_anomaly(ip, metric, a["z"])
                if entry is not None:
                    entry["threat_score"] = int(entry.get("threat_score") or 0) + delta
                    tag = "ZSCORE"
                    entry["threat_tags"] = ",".join(t for t in (entry.get("threat_tags") or "").split(",") + [tag] if t)
                await self._handle_events(events)
            unit = {"rpm": "req/min", "bpm": "bytes/min", "time_taken": "ms"}.get(metric.replace("global_", "").replace("_drop", ""), "")
            await self.alerts.raise_alert(
                "WARNING", "anomaly",
                f"{labels.get(metric, metric)} anomaly{f' from {ip}' if ip else ''} (z={a['z']:+.1f})",
                f"Observed {a['value']:,.0f} {unit} vs baseline mean {a['mean']:,.1f} (std {a['std']:,.1f}, basis: {a['basis']}).",
                source_ip=ip, details=a, dedup_key=f"anomaly:{metric}:{ip or '*'}", cooldown=600,
            )

    async def _process(self, entry: dict[str, Any]) -> None:
        result = self.threats.inspect(entry)
        entry["threat_tags"] = ",".join(result.tags)
        entry["threat_score"] = result.delta
        await self._handle_events(result.events)
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
    hub: Hub
    mailer: Mailer
    alerts: AlertManager
    auth: ADAuthenticator
    threats: ThreatEngine
    baseliner: Baseliner
    health: HealthMonitor
    tailer: LogTailer
    pipeline: Pipeline
    reporter: Reporter
    signer: SessionSigner
    throttle: LoginThrottle
    ip_throttle: LoginThrottle
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


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    S.started_at = time.time()
    await init_db()
    S.config = ConfigStore()
    await S.config.load()
    S.hub = Hub()
    S.mailer = Mailer(S.config)
    S.alerts = AlertManager(S.hub, S.config, S.mailer)
    S.auth = ADAuthenticator(S.config)
    S.threats = ThreatEngine(S.config)
    S.baseliner = Baseliner(S.config)
    S.health = HealthMonitor(S.config, S.alerts, S.hub)
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=50000)
    S.tailer = LogTailer(S.config, queue)
    S.pipeline = Pipeline(queue, S.threats, S.baseliner, S.alerts, S.hub)
    S.reporter = Reporter(S.config, S.mailer)
    S.signer = SessionSigner(await get_or_create_session_secret(), SESSION_TTL)
    S.throttle = LoginThrottle(max_failures=5, window=300)
    S.ip_throttle = LoginThrottle(max_failures=20, window=300)

    def _on_config(section: str) -> None:
        if section == "reports":
            S.reporter.reschedule()

    S.config.on_change(_on_config)
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
    }
    if DEMO_MODE:
        jobs["demo_traffic"] = DemoTrafficGenerator().run
    S.tasks = [asyncio.create_task(supervise(name, fn), name=name) for name, fn in jobs.items()]
    log.info("IIS Sentinel online%s. Watching: %s", " [DEMO MODE]" if DEMO_MODE else "",
             ", ".join(S.config.value("watchers", "log_dirs", [])))
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


app = FastAPI(title="IIS Sentinel", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


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
    if request.url.path.startswith(("/api", "/login", "/config", "/threats", "/system", "/alerts", "/reports", "/stats")):
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
    result = await S.auth.authenticate(body.username, body.password)
    if not result.ok:
        S.throttle.fail(key)
        S.ip_throttle.fail(ip_key)
        log.warning("Failed login for '%s' from %s: %s", body.username, _client_ip(request), result.error)
        await asyncio.sleep(0.5)
        status = 503 if "unreachable" in result.error.lower() or "not configured" in result.error.lower() else 401
        raise HTTPException(status_code=status, detail=result.error or "Authentication failed")
    S.throttle.reset(key)
    token = S.signer.issue(result.username, result.display_name, result.source)
    resp = JSONResponse({"ok": True, "user": result.username, "display_name": result.display_name, "source": result.source})
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True, secure=COOKIE_SECURE, samesite="strict", path="/")
    log.info("Login: %s (%s) from %s", result.username, result.source, _client_ip(request))
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
        raise HTTPException(status_code=400, detail="Expected an object keyed by section (ad, exchange, watchers, reports)")
    errors: dict[str, str] = {}
    for section, values in payload.items():
        try:
            await S.config.update(section, values)
        except ValueError as exc:
            errors[section] = str(exc)
    if errors:
        raise HTTPException(status_code=400, detail=errors)
    log.info("Config updated by %s: %s", user["u"], ", ".join(payload))
    return await get_config(user)


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
                select(Alert).where(Alert.category.in_(("attack", "threat", "anomaly"))).order_by(desc(Alert.id)).limit(limit)
            )
        ).scalars().all()
    return {
        "events": [
            {
                "ts": iso(r.ts), "ip": r.c_ip, "method": r.cs_method, "uri": r.cs_uri_stem, "query": r.cs_uri_query[:500],
                "status": r.sc_status, "tags": r.threat_tags, "score": r.threat_score, "ua": r.user_agent[:200],
            }
            for r in rows
        ],
        "alerts": [_alert_dict(a) for a in alerts],
    }


@app.get("/threats/active")
async def threats_active(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"threats": S.threats.active_threats(limit=200), "counts": S.threats.counts()}


@app.get("/threats/ip/{ip}")
async def threat_ip(ip: str, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    detail = S.threats.ip_detail(ip)
    async with SessionLocal() as s:
        rows = (
            await s.execute(select(LogEntry).where(LogEntry.c_ip == ip).order_by(desc(LogEntry.id)).limit(50))
        ).scalars().all()
    return {
        "state": detail,
        "recent": [{"ts": iso(r.ts), "method": r.cs_method, "uri": r.cs_uri_stem, "query": r.cs_uri_query[:300],
                    "status": r.sc_status, "tags": r.threat_tags} for r in rows],
    }


@app.get("/system/health")
async def system_health(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if S.health.latest:
        return S.health.latest
    async with SessionLocal() as s:
        row = (await s.execute(select(SystemMetric).order_by(desc(SystemMetric.id)).limit(1))).scalar_one_or_none()
    if row is None:
        return {"status": "pending", "detail": "First health sample not collected yet"}
    pools = json.loads(row.app_pools or "{}")
    return {
        "ts": iso(row.ts), "cpu_percent": row.cpu_percent, "ram_percent": row.ram_percent, "disk_percent": row.disk_percent,
        "disk_free_percent": row.disk_free_percent, "disk_free_gb": row.disk_free_gb, "disk_path": row.disk_path,
        "app_pools": [{"name": k, "state": v, "running": v == "Started"} for k, v in pools.items()],
        "w3svc_state": row.w3svc_state, "uptime_seconds": row.uptime_seconds, "stale": True,
    }


@app.get("/stats/baseline")
async def stats_baseline(_user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"baseline": S.baseliner.snapshot(), "pipeline": S.pipeline.stats(), "watchers": S.tailer.status()}


def _alert_dict(a: Alert) -> dict[str, Any]:
    try:
        details = json.loads(a.details or "{}")
    except json.JSONDecodeError:
        details = {}
    return {
        "id": a.id, "ts": iso(a.ts), "severity": a.severity, "category": a.category, "title": a.title,
        "message": a.message, "source_ip": a.source_ip, "details": details, "acknowledged": a.acknowledged, "emailed": a.emailed,
    }


@app.get("/alerts")
async def list_alerts(limit: int = 100, severity: str | None = None, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    q = select(Alert).order_by(desc(Alert.id)).limit(max(1, min(limit, 1000)))
    if severity:
        q = q.where(Alert.severity == severity.upper())
    async with SessionLocal() as s:
        rows = (await s.execute(q)).scalars().all()
    return {"alerts": [_alert_dict(a) for a in rows]}


@app.post("/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int, _user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    async def _op(s):  # type: ignore[no-untyped-def]
        res = await s.execute(update(Alert).where(Alert.id == alert_id).values(acknowledged=True))
        return res.rowcount

    if not await run_db(_op):
        raise HTTPException(status_code=404, detail="Alert not found")
    S.hub.broadcast({"type": "alert_ack", "id": alert_id})
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
        "health": S.health.latest,
        "threats": S.threats.active_threats(),
        "counts": S.threats.counts(),
        "alerts": S.alerts.recent(50),
        "baseline": S.baseliner.snapshot(),
        "pipeline": S.pipeline.stats(),
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
    port = int(os.environ.get("SENTINEL_PORT", "8443"))
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
