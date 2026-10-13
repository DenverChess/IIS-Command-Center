"""Async SQLAlchemy models, engine/session management and the persistent config store."""
from __future__ import annotations

import asyncio
import base64
import copy
import json
import logging
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    delete,
    event,
    select,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

log = logging.getLogger("sentinel.db")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", str(BASE_DIR / "data"))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("SENTINEL_DB_PATH", str(DATA_DIR / "sentinel.db"))).resolve()
DEMO_MODE = os.environ.get("SENTINEL_DEMO", "0").strip().lower() in ("1", "true", "yes", "on")
IS_WINDOWS = sys.platform.startswith("win")
DEMO_LOG_DIR = DATA_DIR / "demo_logs" / "W3SVC1"

T = TypeVar("T")


def utcnow() -> datetime:
    """Naive UTC timestamp. IIS W3C logs are always written in UTC, so everything is stored in UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    site: Mapped[str] = mapped_column(String(128), default="")
    s_ip: Mapped[str] = mapped_column(String(64), default="")
    cs_method: Mapped[str] = mapped_column(String(16), default="")
    cs_uri_stem: Mapped[str] = mapped_column(String(2048), default="")
    cs_uri_query: Mapped[str] = mapped_column(Text, default="")
    s_port: Mapped[int] = mapped_column(Integer, default=0)
    cs_username: Mapped[str] = mapped_column(String(256), default="")
    c_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    user_agent: Mapped[str] = mapped_column(String(1024), default="")
    sc_status: Mapped[int] = mapped_column(Integer, default=0)
    sc_substatus: Mapped[int] = mapped_column(Integer, default=0)
    sc_win32_status: Mapped[int] = mapped_column(BigInteger, default=0)
    time_taken: Mapped[int] = mapped_column(Integer, default=0)
    sc_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    cs_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    threat_tags: Mapped[str] = mapped_column(String(256), default="")
    threat_score: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_log_ip_ts", "c_ip", "ts"),
        Index("ix_log_status_ts", "sc_status", "ts"),
    )


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    ram_percent: Mapped[float] = mapped_column(Float, default=0.0)
    disk_percent: Mapped[float] = mapped_column(Float, default=0.0)
    disk_free_percent: Mapped[float] = mapped_column(Float, default=100.0)
    disk_free_gb: Mapped[float] = mapped_column(Float, default=0.0)
    disk_path: Mapped[str] = mapped_column(String(260), default="")
    app_pools: Mapped[str] = mapped_column(Text, default="{}")
    pools_all_started: Mapped[bool] = mapped_column(Boolean, default=True)
    w3svc_state: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    uptime_seconds: Mapped[float] = mapped_column(Float, default=0.0)


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scope: Mapped[str] = mapped_column(String(16))  # global | population | ip
    key: Mapped[str] = mapped_column(String(64))  # '*' or the client IP
    metric: Mapped[str] = mapped_column(String(32))  # rpm | bpm | time_taken
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    std: Mapped[float] = mapped_column(Float, default=0.0)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime)

    __table_args__ = (UniqueConstraint("scope", "key", "metric", name="uq_baseline"),)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(256))
    message: Mapped[str] = mapped_column(Text, default="")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, default="{}")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    emailed: Mapped[bool] = mapped_column(Boolean, default=False)


class Config(Base):
    __tablename__ = "config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_type: Mapped[str] = mapped_column(String(16))
    period_start: Mapped[datetime] = mapped_column(DateTime)
    period_end: Mapped[datetime] = mapped_column(DateTime)
    generated_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    subject: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")  # sent | failed | generated
    error: Mapped[str] = mapped_column(Text, default="")
    total_requests: Mapped[int] = mapped_column(BigInteger, default=0)
    threat_count: Mapped[int] = mapped_column(Integer, default=0)
    html: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------------------
# Engine / sessions
# --------------------------------------------------------------------------------------
engine = create_async_engine(
    f"sqlite+aiosqlite:///{DB_PATH.as_posix()}",
    connect_args={"timeout": 30},
)


@event.listens_for(engine.sync_engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=10000")
    cur.execute("PRAGMA temp_store=MEMORY")
    cur.close()


SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("Database ready at %s", DB_PATH)


async def run_db(op: Callable[[AsyncSession], Awaitable[T]], retries: int = 4) -> T:
    """Run `op` in a session + commit, retrying when SQLite reports a transient lock."""
    delay = 0.25
    for attempt in range(retries):
        try:
            async with SessionLocal() as session:
                result = await op(session)
                await session.commit()
                return result
        except OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == retries - 1:
                raise
            log.warning("SQLite busy (attempt %d/%d), retrying", attempt + 1, retries)
            await asyncio.sleep(delay)
            delay *= 2
    raise RuntimeError("unreachable")


async def purge_old_data(retention_days: int) -> dict[str, int]:
    cutoff = utcnow() - timedelta(days=max(1, retention_days))
    metric_cutoff = utcnow() - timedelta(days=max(31, retention_days))

    async def _op(s: AsyncSession) -> dict[str, int]:
        r1 = await s.execute(delete(LogEntry).where(LogEntry.ts < cutoff))
        r2 = await s.execute(delete(SystemMetric).where(SystemMetric.ts < metric_cutoff))
        r3 = await s.execute(delete(Alert).where(Alert.ts < metric_cutoff))
        return {"logs": r1.rowcount or 0, "metrics": r2.rowcount or 0, "alerts": r3.rowcount or 0}

    return await run_db(_op)


# --------------------------------------------------------------------------------------
# Secret protection (DPAPI on Windows)
# --------------------------------------------------------------------------------------
_CRYPTPROTECT_LOCAL_MACHINE = 0x4
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


def protect_secret(plain: str) -> str:
    if not plain:
        return ""
    if IS_WINDOWS:
        try:
            import win32crypt  # type: ignore

            blob = win32crypt.CryptProtectData(
                plain.encode("utf-8"),
                "IIS Sentinel",
                None,
                None,
                None,
                _CRYPTPROTECT_LOCAL_MACHINE | _CRYPTPROTECT_UI_FORBIDDEN,
            )
            return "dpapi:" + base64.b64encode(blob).decode("ascii")
        except Exception:  # noqa: BLE001
            log.exception("DPAPI protection failed; falling back to base64 encoding")
    return "b64:" + base64.b64encode(plain.encode("utf-8")).decode("ascii")


def unprotect_secret(stored: str) -> str:
    if not stored:
        return ""
    try:
        if stored.startswith("dpapi:"):
            import win32crypt  # type: ignore

            _desc, data = win32crypt.CryptUnprotectData(
                base64.b64decode(stored[6:]), None, None, None, _CRYPTPROTECT_UI_FORBIDDEN
            )
            return data.decode("utf-8")
        if stored.startswith("b64:"):
            return base64.b64decode(stored[4:]).decode("utf-8")
    except Exception:  # noqa: BLE001
        log.exception("Unable to decrypt stored secret; it must be re-entered")
        return ""
    return stored


# --------------------------------------------------------------------------------------
# Config store
# --------------------------------------------------------------------------------------
SECRET_MASK = "********"
SECRET_FIELDS: set[tuple[str, str]] = {("exchange", "password")}
SEVERITIES = ["INFO", "WARNING", "HIGH", "CRITICAL"]

DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    "ad": {
        "servers": [],
        "port": 636,
        "use_ssl": True,
        "start_tls": False,
        "verify_ssl": True,
        "domain": "",
        "upn_suffix": "",
        "base_dn": "",
        "required_group": "",
        "timeout": 8,
    },
    "exchange": {
        "enabled": False,
        "server": "",
        "autodiscover": False,
        "email": "",
        "username": "",
        "password": "",
        "auth_type": "NTLM",
        "verify_ssl": True,
        "timeout": 30,
        "alert_recipients": [],
        "alert_min_severity": "HIGH",
        "max_alerts_per_hour": 20,
    },
    "watchers": {
        "log_dirs": [r"C:\inetpub\logs\LogFiles\W3SVC1"],
        "file_pattern": "u_ex*.log",
        "start_at_end": True,
        "poll_interval": 2,
        "health_interval": 60,
        "cpu_threshold": 90,
        "ram_threshold": 92,
        "disk_free_critical": 5,
        "app_pools": [],
        "baseline_interval": 300,
        "baseline_min_samples": 30,
        "zscore_threshold": 3.0,
        "spike_window_seconds": 60,
        "spike_404_threshold": 20,
        "spike_auth_threshold": 10,
        "threat_score_threshold": 50,
        "threat_half_life_minutes": 30,
        "retention_days": 45,
    },
    "reports": {
        "schedule": "weekly",
        "day_of_week": "mon",
        "day_of_month": 1,
        "hour": 7,
        "minute": 0,
        "recipients": [],
    },
}

_DOW = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _range(lo: float, hi: float) -> Callable[[Any], None]:
    def check(v: Any) -> None:
        if not (lo <= v <= hi):
            raise ValueError(f"must be between {lo} and {hi}")

    return check


def _choice(*opts: str) -> Callable[[Any], None]:
    def check(v: Any) -> None:
        if v not in opts:
            raise ValueError(f"must be one of {', '.join(opts)}")

    return check


def _emails(v: list[str]) -> None:
    bad = [e for e in v if not _EMAIL_RE.match(e)]
    if bad:
        raise ValueError(f"invalid email address(es): {', '.join(bad)}")


VALIDATORS: dict[tuple[str, str], Callable[[Any], None]] = {
    ("ad", "port"): _range(1, 65535),
    ("ad", "timeout"): _range(1, 120),
    ("exchange", "auth_type"): _choice("NTLM", "basic", "digest", "GSSAPI", "SSPI"),
    ("exchange", "alert_min_severity"): _choice(*SEVERITIES),
    ("exchange", "max_alerts_per_hour"): _range(1, 1000),
    ("exchange", "timeout"): _range(5, 300),
    ("exchange", "alert_recipients"): _emails,
    ("watchers", "poll_interval"): _range(0.5, 60),
    ("watchers", "health_interval"): _range(5, 3600),
    ("watchers", "cpu_threshold"): _range(1, 100),
    ("watchers", "ram_threshold"): _range(1, 100),
    ("watchers", "disk_free_critical"): _range(0, 100),
    ("watchers", "baseline_interval"): _range(30, 86400),
    ("watchers", "baseline_min_samples"): _range(2, 10000),
    ("watchers", "zscore_threshold"): _range(0.5, 50),
    ("watchers", "spike_window_seconds"): _range(5, 3600),
    ("watchers", "spike_404_threshold"): _range(1, 100000),
    ("watchers", "spike_auth_threshold"): _range(1, 100000),
    ("watchers", "threat_score_threshold"): _range(1, 100000),
    ("watchers", "threat_half_life_minutes"): _range(1, 10080),
    ("watchers", "retention_days"): _range(1, 3650),
    ("reports", "schedule"): _choice("weekly", "monthly", "both", "disabled"),
    ("reports", "day_of_week"): _choice(*sorted(_DOW)),
    ("reports", "day_of_month"): _range(1, 28),
    ("reports", "hour"): _range(0, 23),
    ("reports", "minute"): _range(0, 59),
    ("reports", "recipients"): _emails,
}


def _coerce(default: Any, value: Any, name: str) -> Any:
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if isinstance(default, int):
        try:
            return int(float(value))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc
    if isinstance(default, float):
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a number") from exc
    if isinstance(default, list):
        if isinstance(value, str):
            items = re.split(r"[,;\n]", value)
        elif isinstance(value, (list, tuple)):
            items = [str(v) for v in value]
        else:
            raise ValueError(f"{name} must be a list")
        return [i.strip() for i in items if i and i.strip()]
    return "" if value is None else str(value).strip()


def _env_seed() -> dict[str, dict[str, Any]]:
    seed: dict[str, dict[str, Any]] = {}

    def put(section: str, key: str, env: str) -> None:
        if os.environ.get(env):
            seed.setdefault(section, {})[key] = os.environ[env]

    put("watchers", "log_dirs", "SENTINEL_LOG_DIRS")
    put("ad", "servers", "SENTINEL_AD_SERVERS")
    put("ad", "domain", "SENTINEL_AD_DOMAIN")
    put("ad", "upn_suffix", "SENTINEL_AD_UPN_SUFFIX")
    put("ad", "base_dn", "SENTINEL_AD_BASE_DN")
    put("ad", "required_group", "SENTINEL_AD_GROUP")
    put("exchange", "server", "SENTINEL_EXCHANGE_SERVER")
    put("exchange", "email", "SENTINEL_EXCHANGE_EMAIL")
    if DEMO_MODE:
        seed.setdefault("watchers", {}).update(
            {
                "log_dirs": [str(DEMO_LOG_DIR)],
                "start_at_end": False,
                "health_interval": 10,
                "baseline_interval": 60,
                "baseline_min_samples": 3,
                "app_pools": [],
            }
        )
    return seed


class ConfigStore:
    """In-memory cached, DB-persisted config, split into sections (ad, exchange, watchers, reports)."""

    def __init__(self) -> None:
        self._cache: dict[str, dict[str, Any]] = copy.deepcopy(DEFAULT_CONFIG)
        self._lock = asyncio.Lock()
        self._listeners: list[Callable[[str], Any]] = []

    def on_change(self, callback: Callable[[str], Any]) -> None:
        self._listeners.append(callback)

    async def load(self) -> None:
        async with SessionLocal() as s:
            rows = {r.key: r.value for r in (await s.execute(select(Config))).scalars()}
        seed = _env_seed()
        for section, defaults in DEFAULT_CONFIG.items():
            stored: dict[str, Any] = {}
            if section in rows:
                try:
                    stored = json.loads(rows[section])
                except json.JSONDecodeError:
                    log.error("Corrupt config section %s, reverting to defaults", section)
            elif section in seed:
                stored = seed[section]
            merged = copy.deepcopy(defaults)
            for k, v in stored.items():
                if k not in defaults:
                    continue
                try:
                    merged[k] = _coerce(defaults[k], v, f"{section}.{k}")
                except ValueError:
                    log.warning("Ignoring invalid stored value for %s.%s", section, k)
            for k in defaults:
                if (section, k) in SECRET_FIELDS:
                    merged[k] = unprotect_secret(str(merged.get(k, "")))
            self._cache[section] = merged
            if section not in rows:
                await self._persist(section)

    def get(self, section: str) -> dict[str, Any]:
        return copy.deepcopy(self._cache[section])

    def value(self, section: str, key: str, default: Any = None) -> Any:
        return self._cache.get(section, {}).get(key, default)

    def public_view(self) -> dict[str, dict[str, Any]]:
        view = copy.deepcopy(self._cache)
        for section, key in SECRET_FIELDS:
            view[section][key] = SECRET_MASK if view[section].get(key) else ""
        return view

    async def update(self, section: str, values: dict[str, Any]) -> dict[str, Any]:
        if section not in DEFAULT_CONFIG:
            raise ValueError(f"unknown config section '{section}'")
        if not isinstance(values, dict):
            raise ValueError("section payload must be an object")
        defaults = DEFAULT_CONFIG[section]
        async with self._lock:
            candidate = copy.deepcopy(self._cache[section])
            for k, v in values.items():
                if k not in defaults:
                    continue
                if (section, k) in SECRET_FIELDS and v == SECRET_MASK:
                    continue
                coerced = _coerce(defaults[k], v, f"{section}.{k}")
                validator = VALIDATORS.get((section, k))
                if validator:
                    try:
                        validator(coerced)
                    except ValueError as exc:
                        raise ValueError(f"{section}.{k} {exc}") from exc
                candidate[k] = coerced
            self._cache[section] = candidate
            await self._persist(section)
        for cb in self._listeners:
            try:
                res = cb(section)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:  # noqa: BLE001
                log.exception("Config listener failed for section %s", section)
        return self.public_view()[section]

    async def _persist(self, section: str) -> None:
        data = copy.deepcopy(self._cache[section])
        for sec, key in SECRET_FIELDS:
            if sec == section:
                data[key] = protect_secret(str(data.get(key, "")))
        payload = json.dumps(data)

        async def _op(s: AsyncSession) -> None:
            row = await s.get(Config, section)
            if row is None:
                s.add(Config(key=section, value=payload, updated_at=utcnow()))
            else:
                row.value = payload
                row.updated_at = utcnow()

        await run_db(_op)


async def get_or_create_session_secret() -> bytes:
    env = os.environ.get("SENTINEL_SECRET_KEY")
    if env:
        return env.encode("utf-8")

    async def _op(s: AsyncSession) -> bytes:
        row = await s.get(Config, "_session_secret")
        if row is not None:
            raw = unprotect_secret(row.value)
            if raw:
                return raw.encode("utf-8")
        new = secrets.token_urlsafe(48)
        if row is None:
            s.add(Config(key="_session_secret", value=protect_secret(new), updated_at=utcnow()))
        else:
            row.value = protect_secret(new)
            row.updated_at = utcnow()
        return new.encode("utf-8")

    return await run_db(_op)
