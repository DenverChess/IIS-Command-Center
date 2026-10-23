"""Async SQLAlchemy models, engine/session management and the persistent config store."""
from __future__ import annotations

import asyncio
import base64
import copy
import ipaddress
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
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    delete,
    event,
    select,
    text,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from alert_catalog import EVENTS as ALERT_EVENTS
from alert_catalog import SEVERITIES, default_event_settings

log = logging.getLogger("sentinel.db")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", str(BASE_DIR / "data"))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("SENTINEL_DB_PATH", str(DATA_DIR / "sentinel.db"))).resolve()
DEMO_MODE = os.environ.get("SENTINEL_DEMO", "0").strip().lower() in ("1", "true", "yes", "on")
IS_WINDOWS = sys.platform.startswith("win")
DEMO_LOG_ROOT = DATA_DIR / "demo_logs"
# Demo fleet: servers on 127.x are simulated by remote_manager (no WinRM); IIS-04 is deliberately unreachable.
DEMO_SERVERS = [
    ("IIS-01", "127.0.0.11"),
    ("IIS-02", "127.0.0.12"),
    ("IIS-03", "127.0.0.13"),
    ("IIS-04", "10.255.255.14"),
]


def is_simulated(ip_address: str) -> bool:
    return DEMO_MODE and ip_address.startswith("127.")

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


# server_id 0 is the workstation Sentinel itself runs on (local log dirs / local health). SQLite FK
# enforcement is left off, so 0 can be stored without a matching monitored_servers row.
LOCAL_SERVER_ID = 0


class MonitoredServer(Base):
    __tablename__ = "monitored_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_name: Mapped[str] = mapped_column(String(64), unique=True)
    ip_address: Mapped[str] = mapped_column(String(255))
    winrm_username: Mapped[str] = mapped_column(String(256), default="")
    # Stored through protect_secret(): DPAPI-encrypted on Windows, base64 elsewhere.
    winrm_password: Mapped[str] = mapped_column(Text, default="")
    # Either one site's folder (...\W3SVC1) or the parent holding every site's W3SVC<n> folder.
    log_unc_path: Mapped[str] = mapped_column(String(1024), default="")
    log_start_mode: Mapped[str] = mapped_column(String(8), default="end")
    log_tail_lines: Mapped[int] = mapped_column(Integer, default=1000)
    winrm_transport: Mapped[str] = mapped_column(String(16), default="ntlm")
    winrm_port: Mapped[int] = mapped_column(Integer, default=5985)
    winrm_use_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    winrm_verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: utcnow())


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("monitored_servers.id"), default=LOCAL_SERVER_ID, index=True)
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
        Index("ix_log_server_ts", "server_id", "ts"),
    )


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("monitored_servers.id"), default=LOCAL_SERVER_ID, index=True)
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


class ActionableAlert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("monitored_servers.id"), default=LOCAL_SERVER_ID, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    event: Mapped[str] = mapped_column(String(48), default="")
    title: Mapped[str] = mapped_column(String(256))
    message: Mapped[str] = mapped_column(Text, default="")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, default="{}")
    # Pending -> Approved (ban executed) | Dismissed
    status: Mapped[str] = mapped_column(String(16), default="Pending", index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    emailed: Mapped[bool] = mapped_column(Boolean, default=False)


class BannedIP(Base):
    __tablename__ = "banned_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("monitored_servers.id"), default=LOCAL_SERVER_ID, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("alerts.id"), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(256), default="")
    provider: Mapped[str] = mapped_column(String(16), default="windows")
    # Set when a perimeter ban also added a Windows Firewall rule on the attacked server (firewall.also_windows).
    windows_rule: Mapped[str] = mapped_column(String(256), default="")
    banned_by: Mapped[str] = mapped_column(String(256), default="")
    banned_at: Mapped[datetime] = mapped_column(DateTime)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lifted_by: Mapped[str] = mapped_column(String(256), default="")

    __table_args__ = (Index("ix_ban_server_ip", "server_id", "ip_address"),)


class AbuseScore(Base):
    """Cached AbuseIPDB /check result per IP (keeps the daily API quota for new addresses)."""
    __tablename__ = "abuse_scores"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    data: Mapped[str] = mapped_column(Text, default="{}")
    checked_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class BannedRange(Base):
    """A CIDR block (single /32 or /128 included) pushed to Windows Firewall and/or the SonicWall group."""
    __tablename__ = "banned_ranges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr_notation: Mapped[str] = mapped_column(String(64), index=True)
    scope: Mapped[str] = mapped_column(String(8))  # "/32" "/24" "/16" (IPv6: "/128" "/64" "/48")
    reason: Mapped[str] = mapped_column(Text, default="")
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    banned_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source_ip_count: Mapped[int] = mapped_column(Integer, default=0)
    source_ips: Mapped[str] = mapped_column(Text, default="[]")  # JSON array of the attacker IPs behind the ban
    # Attacked server (Windows rule target); NULL = perimeter-only, or every server for windows bans without one.
    server_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("monitored_servers.id"), nullable=True)
    firewall_target: Mapped[str] = mapped_column(String(16), default="windows")  # windows | sonicwall | both
    # JSON {"windows": [server ids with a rule], "sonicwall": "<group>"}: exactly what UNBAN has to remove.
    applied: Mapped[str] = mapped_column(Text, default="{}")
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    banned_by: Mapped[str] = mapped_column(String(256), default="")
    output: Mapped[str] = mapped_column(Text, default="")
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lifted_by: Mapped[str] = mapped_column(String(256), default="")


class AllowlistEntry(Base):
    """Addresses / ranges Sentinel must never block (partners, monitoring, your own egress)."""
    __tablename__ = "allowlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_or_cidr: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(256), default="")
    added_by: Mapped[str] = mapped_column(String(256), default="")
    added_at: Mapped[datetime] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


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


# Columns added after the first schema; create_all() never alters existing tables.
_ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    "log_entries": {"server_id": "INTEGER NOT NULL DEFAULT 0"},
    "system_metrics": {"server_id": "INTEGER NOT NULL DEFAULT 0"},
    "alerts": {"server_id": "INTEGER NOT NULL DEFAULT 0", "status": "VARCHAR(16) NOT NULL DEFAULT 'Pending'",
               "event": "VARCHAR(48) NOT NULL DEFAULT ''"},
    "banned_ips": {"provider": "VARCHAR(16) NOT NULL DEFAULT 'windows'",
                   "windows_rule": "VARCHAR(256) NOT NULL DEFAULT ''",
                   "lifted_at": "DATETIME", "lifted_by": "VARCHAR(256) NOT NULL DEFAULT ''"},
    "monitored_servers": {"log_start_mode": "VARCHAR(8) NOT NULL DEFAULT 'end'",
                          "log_tail_lines": "INTEGER NOT NULL DEFAULT 1000"},
}


def _migrate(sync_conn: Any) -> None:
    for table, columns in _ADDITIVE_COLUMNS.items():
        existing = {row[1] for row in sync_conn.exec_driver_sql(f"PRAGMA table_info({table})")}
        for name, ddl in columns.items():
            if existing and name not in existing:
                sync_conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                log.info("Migrated %s: added column %s", table, name)
                if (table, name) == ("alerts", "status"):
                    # Pre-SOC alerts were never approved; only open attacker alerts belong in the approval queue.
                    sync_conn.exec_driver_sql(
                        "UPDATE alerts SET status = 'Info' WHERE source_ip IS NULL OR source_ip = '' "
                        "OR category NOT IN ('attack', 'threat') OR acknowledged = 1"
                    )
    for ddl in (
        "CREATE INDEX IF NOT EXISTS ix_log_entries_server_id ON log_entries (server_id)",
        "CREATE INDEX IF NOT EXISTS ix_log_server_ts ON log_entries (server_id, ts)",
        "CREATE INDEX IF NOT EXISTS ix_system_metrics_server_id ON system_metrics (server_id)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_server_id ON alerts (server_id)",
        "CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status)",
    ):
        sync_conn.exec_driver_sql(ddl)
    _create_fts(sync_conn)


# Full-text index over the searchable log columns (external content: the text lives once, in log_entries).
FTS_TABLE = "log_fts"
FTS_COLUMNS = ("cs_uri_stem", "cs_uri_query", "user_agent", "c_ip", "cs_method", "cs_username")
FTS_STATE: dict[str, Any] = {"enabled": False, "backfill": None}


def _create_fts(sync_conn: Any) -> None:
    cols = ", ".join(FTS_COLUMNS)
    new_cols = ", ".join(f"new.{c}" for c in FTS_COLUMNS)
    old_cols = ", ".join(f"old.{c}" for c in FTS_COLUMNS)
    exists = sync_conn.exec_driver_sql(
        f"SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{FTS_TABLE}'").first() is not None
    try:
        # Rows that existed before the index are indexed in the background (main.fts_backfill), ascending; the
        # pending id range lives in log_fts_backfill so the delete trigger never "deletes" an unindexed row.
        sync_conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS log_fts_backfill (next INTEGER NOT NULL, target INTEGER NOT NULL)")
        if not exists:
            sync_conn.exec_driver_sql(
                f"CREATE VIRTUAL TABLE {FTS_TABLE} USING fts5({cols}, content='log_entries', content_rowid='id')")
            row = sync_conn.exec_driver_sql("SELECT MIN(id), MAX(id) FROM log_entries").first()
            sync_conn.exec_driver_sql("DELETE FROM log_fts_backfill")
            if row and row[1]:
                sync_conn.exec_driver_sql("INSERT INTO log_fts_backfill (next, target) VALUES (?, ?)", (int(row[0]), int(row[1])))
                log.info("Created the full-text log index; %d existing rows will be indexed in the background",
                         int(row[1]) - int(row[0]) + 1)
        sync_conn.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS log_fts_ai AFTER INSERT ON log_entries BEGIN "
            f"INSERT INTO {FTS_TABLE}(rowid, {cols}) VALUES (new.id, {new_cols}); END")
        sync_conn.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS log_fts_ad AFTER DELETE ON log_entries "
            f"WHEN NOT EXISTS (SELECT 1 FROM log_fts_backfill WHERE old.id >= next AND old.id <= target) BEGIN "
            f"INSERT INTO {FTS_TABLE}({FTS_TABLE}, rowid, {cols}) VALUES ('delete', old.id, {old_cols}); END")
        FTS_STATE["enabled"] = True
    except Exception as exc:  # noqa: BLE001
        # SQLite without FTS5: search falls back to LIKE scans.
        log.warning("Full-text search unavailable (%s); log search will use slower LIKE matching", exc)
        FTS_STATE["enabled"] = False


async def fts_backfill_step(chunk: int = 5000) -> dict[str, int] | None:
    """Index the next chunk of pre-existing rows. Returns progress, or None when nothing is pending."""
    cols = ", ".join(FTS_COLUMNS)

    async def _op(s: AsyncSession) -> dict[str, int] | None:
        row = (await s.execute(text("SELECT next, target FROM log_fts_backfill LIMIT 1"))).first()
        if row is None:
            return None
        nxt, target = int(row[0]), int(row[1])
        hi = min(nxt + chunk, target + 1)
        await s.execute(text(f"INSERT INTO {FTS_TABLE}(rowid, {cols}) SELECT id, {cols} FROM log_entries "
                             "WHERE id >= :lo AND id < :hi"), {"lo": nxt, "hi": hi})
        if hi > target:
            await s.execute(text("DELETE FROM log_fts_backfill"))
        else:
            await s.execute(text("UPDATE log_fts_backfill SET next = :n"), {"n": hi})
        return {"next": hi, "target": target}

    return await run_db(_op)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate)
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
        r3 = await s.execute(delete(ActionableAlert).where(ActionableAlert.ts < metric_cutoff))
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
SECRET_FIELDS: set[tuple[str, str]] = {
    ("exchange", "password"),
    ("firewall", "pfsense_api_key"), ("firewall", "pfsense_api_secret"),
    ("firewall", "sonicwall_password"),
    ("firewall", "paloalto_api_key"), ("firewall", "paloalto_password"),
    ("general", "abuseipdb_api_key"),
}
FIREWALL_PROVIDERS = ("windows", "pfsense", "sonicwall", "paloalto")
UI_THEMES = ("cyber", "dark", "lite", "large")
LOG_START_MODES = ("end", "tail", "full")

DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    "general": {
        # Theme for consoles that haven't picked one (each browser can override it).
        "default_theme": "cyber",
        "abuseipdb_enabled": False,
        "abuseipdb_api_key": "",
        # Look up every IP in PENDING THREATS / THREAT MATRIX automatically (uses the daily quota).
        "abuseipdb_auto_lookup": True,
        "abuseipdb_max_age_days": 90,
        "abuseipdb_cache_hours": 24,
    },
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
        # Only set when Sentinel itself runs on an IIS box; remote servers live in monitored_servers.
        "log_dirs": [],
        "local_server_name": "",
        "remote_timeout": 30,
        "file_pattern": "u_ex*.log",
        # Legacy switch (pre-2.1); log_start_mode supersedes it.
        "start_at_end": True,
        "log_start_mode": "end",
        "log_tail_lines": 1000,
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
        # Directory enumeration: more than (threshold - 1) 404s from one IP within the window raises a Pending alert.
        "enum_404_threshold": 3,
        "enum_404_window_minutes": 5,
        "threat_score_threshold": 50,
        "threat_half_life_minutes": 30,
        "retention_days": 45,
        "geoip_auto_download": True,
    },
    "reports": {
        "schedule": "weekly",
        "day_of_week": "mon",
        "day_of_month": 1,
        "hour": 7,
        "minute": 0,
        "recipients": [],
    },
    "alerts": {
        "events": default_event_settings(),
        # Empty = exchange.alert_recipients.
        "email_recipients": [],
        "desktop_notifications": True,
        "sound": True,
        "quiet_hours_enabled": False,
        "quiet_start": "22:00",
        "quiet_end": "07:00",
        "quiet_bypass_critical": True,
        "muted_servers": [],
        # Log lines older than this (backfill of tail/full start modes) are recorded but never notify.
        "live_window_minutes": 15,
        "http_error_codes": ["500-599"],
        "http_error_cooldown_minutes": 10,
        "http_error_burst_threshold": 10,
        "http_error_burst_window_minutes": 5,
        "watched_status_codes": ["413", "429"],
        "watched_status_cooldown_minutes": 15,
        "slow_response_ms": 10000,
        "slow_response_threshold": 5,
        "slow_response_window_minutes": 5,
        "http_ignore_paths": [],
        "cert_warning_days": 21,
    },
    "firewall": {
        # Where APPROVE BAN pushes the block. windows = netsh on the attacked server (per-server bans).
        "provider": "windows",
        "timeout": 15,
        "pfsense_platform": "opnsense",
        "pfsense_url": "",
        "pfsense_api_key": "",
        "pfsense_api_secret": "",
        "pfsense_alias": "SENTINEL_BANS",
        "pfsense_verify_ssl": True,
        "sonicwall_url": "",
        "sonicwall_username": "",
        "sonicwall_password": "",
        "sonicwall_group": "SENTINEL_BANS",
        "sonicwall_zone": "WAN",
        "paloalto_url": "",
        "paloalto_api_key": "",
        "paloalto_username": "",
        "paloalto_password": "",
        "paloalto_tag": "sentinel-ban",
        "paloalto_vsys": "vsys1",
        "paloalto_timeout_minutes": 0,
        "paloalto_verify_ssl": True,
        # Perimeter providers: also add the Windows Firewall rule on the attacked server.
        "also_windows": False,
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


_STATUS_TOKEN_RE = re.compile(r"^(?:(\d)xx|(\d{3})(?:\s*-\s*(\d{3}))?)$", re.IGNORECASE)


def parse_status_codes(tokens: list[str]) -> list[tuple[int, int]]:
    """'500', '500-599' or '5xx' -> inclusive (lo, hi) ranges."""
    ranges: list[tuple[int, int]] = []
    for raw in tokens:
        tok = str(raw).strip()
        m = _STATUS_TOKEN_RE.match(tok)
        if not m:
            raise ValueError(f"'{tok}' is not a status code, range (500-599) or class (5xx)")
        if m.group(1):
            lo = int(m.group(1)) * 100
            hi = lo + 99
        else:
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
        if not (100 <= lo <= hi <= 999):
            raise ValueError(f"'{tok}' is not a valid HTTP status range")
        ranges.append((lo, hi))
    return ranges


def _status_codes(v: list[str]) -> None:
    parse_status_codes(v)


def _hhmm(v: str) -> None:
    m = re.match(r"^(\d{1,2}):(\d{2})$", v)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ValueError("must be a 24h time like 22:00")


def _mgmt_url(v: str) -> None:
    if v and not re.match(r"^(https?://)?[A-Za-z0-9.\-\[\]:]+(:\d+)?(/[^\s]*)?$", v):
        raise ValueError("must be a management URL like https://192.0.2.1 or https://fw.corp.local:8443")


def _http_url(v: str) -> None:
    """Any http:// or https:// URL (or a bare host). The scheme is stored exactly as entered."""
    if not v:
        return
    from urllib.parse import urlsplit

    if re.match(r"^[a-z][a-z0-9+.\-]*://", v, re.IGNORECASE) and not re.match(r"^https?://", v, re.IGNORECASE):
        raise ValueError("must start with http:// or https://")
    try:
        parts = urlsplit(v if "://" in v else "https://" + v)
        ok = bool(parts.hostname) and " " not in v
        parts.port  # noqa: B018 - raises on an invalid port
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("must be a URL like http://192.0.2.1 or https://fw.corp.local:8443")


def _object_name(v: str) -> None:
    if not re.match(r"^[A-Za-z0-9_.\-]{1,63}$", v):
        raise ValueError("must be 1-63 letters, digits, '.', '_' or '-'")


def _alert_events(v: dict[str, dict[str, Any]]) -> None:
    for eid, s in v.items():
        if s.get("severity") not in ("default", *SEVERITIES):
            raise ValueError(f"{eid}.severity must be default or one of {', '.join(SEVERITIES)}")


VALIDATORS: dict[tuple[str, str], Callable[[Any], None]] = {
    ("general", "default_theme"): _choice(*UI_THEMES),
    ("general", "abuseipdb_max_age_days"): _range(1, 365),
    ("general", "abuseipdb_cache_hours"): _range(1, 720),
    ("ad", "port"): _range(1, 65535),
    ("ad", "timeout"): _range(1, 120),
    ("exchange", "auth_type"): _choice("NTLM", "basic", "digest", "GSSAPI", "SSPI"),
    ("exchange", "alert_min_severity"): _choice(*SEVERITIES),
    ("exchange", "max_alerts_per_hour"): _range(1, 1000),
    ("exchange", "timeout"): _range(5, 300),
    ("exchange", "alert_recipients"): _emails,
    ("watchers", "poll_interval"): _range(0.5, 60),
    ("watchers", "health_interval"): _range(5, 3600),
    ("watchers", "remote_timeout"): _range(5, 300),
    ("watchers", "cpu_threshold"): _range(1, 100),
    ("watchers", "ram_threshold"): _range(1, 100),
    ("watchers", "disk_free_critical"): _range(0, 100),
    ("watchers", "baseline_interval"): _range(30, 86400),
    ("watchers", "baseline_min_samples"): _range(2, 10000),
    ("watchers", "zscore_threshold"): _range(0.5, 50),
    ("watchers", "spike_window_seconds"): _range(5, 3600),
    ("watchers", "spike_404_threshold"): _range(1, 100000),
    ("watchers", "spike_auth_threshold"): _range(1, 100000),
    ("watchers", "enum_404_threshold"): _range(2, 100000),
    ("watchers", "enum_404_window_minutes"): _range(1, 1440),
    ("watchers", "threat_score_threshold"): _range(1, 100000),
    ("watchers", "threat_half_life_minutes"): _range(1, 10080),
    ("watchers", "retention_days"): _range(1, 3650),
    ("watchers", "log_start_mode"): _choice(*LOG_START_MODES),
    ("watchers", "log_tail_lines"): _range(1, 1_000_000),
    ("alerts", "events"): _alert_events,
    ("alerts", "email_recipients"): _emails,
    ("alerts", "quiet_start"): _hhmm,
    ("alerts", "quiet_end"): _hhmm,
    ("alerts", "live_window_minutes"): _range(1, 10080),
    ("alerts", "http_error_codes"): _status_codes,
    ("alerts", "http_error_cooldown_minutes"): _range(0, 1440),
    ("alerts", "http_error_burst_threshold"): _range(2, 100000),
    ("alerts", "http_error_burst_window_minutes"): _range(1, 1440),
    ("alerts", "watched_status_codes"): _status_codes,
    ("alerts", "watched_status_cooldown_minutes"): _range(0, 1440),
    ("alerts", "slow_response_ms"): _range(100, 3_600_000),
    ("alerts", "slow_response_threshold"): _range(1, 100000),
    ("alerts", "slow_response_window_minutes"): _range(1, 1440),
    ("alerts", "cert_warning_days"): _range(1, 365),
    ("firewall", "provider"): _choice(*FIREWALL_PROVIDERS),
    ("firewall", "pfsense_platform"): _choice("pfsense", "opnsense"),
    ("firewall", "timeout"): _range(3, 120),
    ("firewall", "pfsense_url"): _mgmt_url,
    ("firewall", "sonicwall_url"): _http_url,
    ("firewall", "paloalto_url"): _mgmt_url,
    ("firewall", "pfsense_alias"): _object_name,
    ("firewall", "sonicwall_group"): _object_name,
    ("firewall", "paloalto_tag"): _object_name,
    ("firewall", "paloalto_timeout_minutes"): _range(0, 43200),
    ("reports", "schedule"): _choice("weekly", "monthly", "both", "disabled"),
    ("reports", "day_of_week"): _choice(*sorted(_DOW)),
    ("reports", "day_of_month"): _range(1, 28),
    ("reports", "hour"): _range(0, 23),
    ("reports", "minute"): _range(0, 59),
    ("reports", "recipients"): _emails,
}


def _coerce(default: Any, value: Any, name: str, base: Any = None) -> Any:
    """Coerce `value` to the type of `default`. Dicts are merged key-by-key onto `base` (or the default),
    so a partial update only touches the keys it sends and unknown keys are dropped."""
    if isinstance(default, dict):
        if not isinstance(value, dict):
            raise ValueError(f"{name} must be an object")
        merged = copy.deepcopy(base if isinstance(base, dict) else default)
        merged = {k: merged.get(k, copy.deepcopy(dv)) for k, dv in default.items()}
        for k, v in value.items():
            if k in default:
                merged[k] = _coerce(default[k], v, f"{name}.{k}", merged.get(k))
        return merged
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
                "log_dirs": [],
                "start_at_end": False,
                "log_start_mode": "tail",
                "health_interval": 10,
                "baseline_interval": 60,
                "baseline_min_samples": 3,
                "app_pools": [],
            }
        )
    return seed


class ConfigStore:
    """In-memory cached, DB-persisted config, split into sections (ad, exchange, watchers, reports, alerts, firewall)."""

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
            if section == "alerts" and section not in rows and "exchange" in rows:
                merged["events"] = self._legacy_email_events()
            if section == "watchers" and "log_start_mode" not in stored and stored.get("start_at_end") is False:
                stored = {**stored, "log_start_mode": "full"}
            for k, v in stored.items():
                if k not in defaults:
                    continue
                try:
                    merged[k] = _coerce(defaults[k], v, f"{section}.{k}", merged.get(k))
                except ValueError:
                    log.warning("Ignoring invalid stored value for %s.%s", section, k)
            for k in defaults:
                if (section, k) in SECRET_FIELDS:
                    merged[k] = unprotect_secret(str(merged.get(k, "")))
            self._enforce(section, merged)
            self._cache[section] = merged
            if section not in rows:
                await self._persist(section)

    def _legacy_email_events(self) -> dict[str, dict[str, Any]]:
        """First start after upgrading: email exactly what exchange.alert_min_severity used to email."""
        min_sev = self._cache.get("exchange", {}).get("alert_min_severity", "HIGH")
        rank = SEVERITIES.index(min_sev) if min_sev in SEVERITIES else 2
        return default_event_settings(email_min_rank=rank)

    @staticmethod
    def _enforce(section: str, values: dict[str, Any]) -> None:
        if section == "alerts":
            for eid, ev in ALERT_EVENTS.items():
                if ev["core"]:
                    values["events"][eid]["enabled"] = True

    def get(self, section: str) -> dict[str, Any]:
        return copy.deepcopy(self._cache[section])

    def value(self, section: str, key: str, default: Any = None) -> Any:
        return self._cache.get(section, {}).get(key, default)

    def public_view(self) -> dict[str, dict[str, Any]]:
        view = copy.deepcopy(self._cache)
        for section, key in SECRET_FIELDS:
            view[section][key] = SECRET_MASK if view[section].get(key) else ""
        return view

    def preview(self, section: str, values: dict[str, Any]) -> dict[str, Any]:
        """The section as it would be after `values` were saved (validated, secrets unmasked), without saving."""
        if section not in DEFAULT_CONFIG:
            raise ValueError(f"unknown config section '{section}'")
        if not isinstance(values, dict):
            raise ValueError("section payload must be an object")
        defaults = DEFAULT_CONFIG[section]
        candidate = copy.deepcopy(self._cache[section])
        for k, v in values.items():
            if k not in defaults:
                continue
            if (section, k) in SECRET_FIELDS and v == SECRET_MASK:
                continue
            coerced = _coerce(defaults[k], v, f"{section}.{k}", candidate.get(k))
            validator = VALIDATORS.get((section, k))
            if validator:
                try:
                    validator(coerced)
                except ValueError as exc:
                    raise ValueError(f"{section}.{k} {exc}") from exc
            candidate[k] = coerced
        self._enforce(section, candidate)
        return candidate

    async def update(self, section: str, values: dict[str, Any]) -> dict[str, Any]:
        if section not in DEFAULT_CONFIG:
            raise ValueError(f"unknown config section '{section}'")
        if not isinstance(values, dict):
            raise ValueError("section payload must be an object")
        async with self._lock:
            candidate = self.preview(section, values)
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


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """'1.2.3.4', '1.2.3.0/24', '2001:db8::/48' -> network (host bits masked, IPv4-mapped IPv6 unwrapped)."""
    net = ipaddress.ip_network(str(value).strip(), strict=False)
    if net.version == 6 and net.network_address.ipv4_mapped is not None and net.prefixlen >= 96:
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}", strict=False)
    return net


async def allowlist_overlaps(cidr: str) -> list[dict[str, Any]]:
    """Active allowlist entries that overlap `cidr` in either direction (nested ranges included)."""
    net = parse_network(cidr)
    async with SessionLocal() as s:
        rows = (await s.execute(select(AllowlistEntry).where(AllowlistEntry.is_active.is_(True)))).scalars().all()
    hits = []
    for r in rows:
        try:
            other = parse_network(r.ip_or_cidr)
        except ValueError:
            continue
        if other.version == net.version and net.overlaps(other):
            hits.append({"id": r.id, "ip_or_cidr": r.ip_or_cidr, "description": r.description})
    return hits


async def is_cidr_allowlisted(cidr: str) -> bool:
    return bool(await allowlist_overlaps(cidr))


async def kv_get(key: str, default: Any = None) -> Any:
    """JSON value stored in a private config row (keys start with '_' and never collide with sections)."""
    async with SessionLocal() as s:
        row = await s.get(Config, key)
    if row is None:
        return default
    try:
        return json.loads(row.value)
    except json.JSONDecodeError:
        return default


async def kv_put(key: str, value: Any) -> None:
    payload = json.dumps(value)

    async def _op(s: AsyncSession) -> None:
        row = await s.get(Config, key)
        if row is None:
            s.add(Config(key=key, value=payload, updated_at=utcnow()))
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


# --------------------------------------------------------------------------------------
# Monitored server registry
# --------------------------------------------------------------------------------------
WINRM_TRANSPORTS = ("ntlm", "kerberos", "credssp", "basic")
_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")


def _valid_host(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


class ServerRegistry:
    """Cached view of monitored_servers plus the optional local (id 0) server, with live connectivity status."""

    def __init__(self, config: ConfigStore) -> None:
        self.config = config
        self._servers: dict[int, dict[str, Any]] = {}
        self._listeners: list[Callable[[], Any]] = []
        self.status: dict[int, dict[str, Any]] = {}

    def on_change(self, callback: Callable[[], Any]) -> None:
        self._listeners.append(callback)

    async def _notify(self) -> None:
        for cb in self._listeners:
            try:
                res = cb()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:  # noqa: BLE001
                log.exception("Server registry listener failed")

    @staticmethod
    def _to_dict(row: MonitoredServer) -> dict[str, Any]:
        return {
            "id": row.id,
            "server_name": row.server_name,
            "ip_address": row.ip_address,
            "winrm_username": row.winrm_username,
            "winrm_password": unprotect_secret(row.winrm_password),
            "log_unc_path": row.log_unc_path,
            "log_start_mode": row.log_start_mode or "end",
            "log_tail_lines": int(row.log_tail_lines or 1000),
            "winrm_transport": row.winrm_transport,
            "winrm_port": row.winrm_port,
            "winrm_use_ssl": row.winrm_use_ssl,
            "winrm_verify_ssl": row.winrm_verify_ssl,
            "enabled": row.enabled,
            "local": False,
            "simulated": is_simulated(row.ip_address),
            "created_at": iso(row.created_at),
        }

    async def _seed_demo(self) -> None:
        async def _op(s: AsyncSession) -> None:
            if (await s.execute(select(MonitoredServer.id).limit(1))).first():
                return
            for name, ip in DEMO_SERVERS:
                # The parent of the per-site W3SVC<n> folders: every site on the server is tailed.
                path = str(DEMO_LOG_ROOT / name) if ip.startswith("127.") else rf"\\{ip}\IISLogs"
                s.add(MonitoredServer(server_name=name, ip_address=ip, winrm_username="CORP\\svc_sentinel",
                                      winrm_password=protect_secret("demo"), log_unc_path=path, log_start_mode="tail",
                                      log_tail_lines=500, created_at=utcnow()))

        await run_db(_op)

    async def load(self) -> None:
        if DEMO_MODE:
            await self._seed_demo()
        async with SessionLocal() as s:
            rows = (await s.execute(select(MonitoredServer).order_by(MonitoredServer.id))).scalars().all()
        self._servers = {r.id: self._to_dict(r) for r in rows}
        log.info("Monitoring %d remote server(s): %s", len(self._servers),
                 ", ".join(f"{s['server_name']} ({s['ip_address']})" for s in self._servers.values()) or "none")

    def local(self) -> dict[str, Any] | None:
        dirs = self.config.value("watchers", "log_dirs", []) or []
        if not dirs:
            return None
        import socket

        return {
            "id": LOCAL_SERVER_ID,
            "server_name": self.config.value("watchers", "local_server_name") or socket.gethostname().upper(),
            "ip_address": "127.0.0.1",
            "log_dirs": list(dirs),
            "log_unc_path": "",
            "log_start_mode": self.config.value("watchers", "log_start_mode", "end"),
            "log_tail_lines": int(self.config.value("watchers", "log_tail_lines", 1000)),
            "enabled": True,
            "local": True,
            "simulated": False,
        }

    def all(self, enabled_only: bool = True) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        local = self.local()
        if local:
            out.append(local)
        out.extend(copy.deepcopy(s) for s in self._servers.values() if s["enabled"] or not enabled_only)
        return out

    def get(self, server_id: int) -> dict[str, Any] | None:
        if server_id == LOCAL_SERVER_ID:
            return self.local()
        s = self._servers.get(server_id)
        return copy.deepcopy(s) if s else None

    def name(self, server_id: int | None) -> str:
        if server_id is None:
            return ""
        if server_id == LOCAL_SERVER_ID:
            local = self.local()
            return local["server_name"] if local else "LOCAL"
        s = self._servers.get(server_id)
        return s["server_name"] if s else f"SRV-{server_id}"

    def set_status(self, server_id: int, component: str, ok: bool, error: str | None = None) -> bool:
        """Record connectivity for a component ('health' / 'logs'); returns True when the state changed."""
        st = self.status.setdefault(server_id, {})
        prev = st.get(component, {}).get("ok")
        st[component] = {"ok": ok, "error": error, "at": iso(utcnow())}
        return prev is not ok

    def public(self, s: dict[str, Any]) -> dict[str, Any]:
        view = {k: v for k, v in s.items() if k != "winrm_password"}
        view["winrm_password_set"] = bool(s.get("winrm_password"))
        view["status"] = self.status.get(s["id"], {})
        return view

    def list_public(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        return [self.public(s) for s in self.all(enabled_only=enabled_only)]

    def _validate(self, data: dict[str, Any], existing_id: int | None = None) -> dict[str, Any]:
        def text(key: str, limit: int) -> str:
            v = data.get(key)
            v = "" if v is None else str(v).strip()
            if len(v) > limit or any(ord(c) < 32 for c in v):
                raise ValueError(f"{key} is invalid")
            return v

        name = text("server_name", 64)
        if not _SERVER_NAME_RE.match(name):
            raise ValueError("server_name must be 1-64 chars: letters, digits, '.', '_' or '-'")
        if any(s["server_name"].lower() == name.lower() and s["id"] != existing_id for s in self._servers.values()):
            raise ValueError(f"a server named '{name}' already exists")
        ip = text("ip_address", 255)
        if not _valid_host(ip):
            raise ValueError("ip_address must be an IP address or DNS hostname")
        username = text("winrm_username", 256)
        password = data.get("winrm_password")
        password = "" if password is None else str(password)
        if len(password) > 512:
            raise ValueError("winrm_password is too long")
        if existing_id is None and (not username or not password):
            raise ValueError("winrm_username and winrm_password are required")
        unc = text("log_unc_path", 1024)
        transport = (text("winrm_transport", 16) or "ntlm").lower()
        if transport not in WINRM_TRANSPORTS:
            raise ValueError(f"winrm_transport must be one of {', '.join(WINRM_TRANSPORTS)}")
        use_ssl = _coerce(False, data.get("winrm_use_ssl", False), "winrm_use_ssl")
        if transport == "basic" and not use_ssl:
            raise ValueError("basic WinRM auth sends credentials in clear text; enable winrm_use_ssl")
        try:
            port = int(data.get("winrm_port") or (5986 if use_ssl else 5985))
        except (TypeError, ValueError) as exc:
            raise ValueError("winrm_port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("winrm_port must be between 1 and 65535")
        mode = (text("log_start_mode", 8) or "end").lower()
        if mode not in LOG_START_MODES:
            raise ValueError(f"log_start_mode must be one of {', '.join(LOG_START_MODES)}")
        try:
            tail_lines = int(data.get("log_tail_lines") or 1000)
        except (TypeError, ValueError) as exc:
            raise ValueError("log_tail_lines must be an integer") from exc
        if not 1 <= tail_lines <= 1_000_000:
            raise ValueError("log_tail_lines must be between 1 and 1000000")
        return {
            "server_name": name,
            "ip_address": ip,
            "winrm_username": username,
            "winrm_password": password,
            "log_unc_path": unc,
            "log_start_mode": mode,
            "log_tail_lines": tail_lines,
            "winrm_transport": transport,
            "winrm_port": port,
            "winrm_use_ssl": use_ssl,
            "winrm_verify_ssl": _coerce(True, data.get("winrm_verify_ssl", True), "winrm_verify_ssl"),
            "enabled": _coerce(True, data.get("enabled", True), "enabled"),
        }

    async def add(self, data: dict[str, Any]) -> dict[str, Any]:
        clean = self._validate(data)

        async def _op(s: AsyncSession) -> int:
            row = MonitoredServer(**{**clean, "winrm_password": protect_secret(clean["winrm_password"])}, created_at=utcnow())
            s.add(row)
            await s.flush()
            return row.id

        new_id = await run_db(_op)
        await self.load()
        await self._notify()
        return self.public(self._servers[new_id])

    async def update(self, server_id: int, data: dict[str, Any]) -> dict[str, Any]:
        current = self._servers.get(server_id)
        if current is None:
            raise KeyError(server_id)
        merged = {**current, **data}
        if not data.get("winrm_password") or data.get("winrm_password") == SECRET_MASK:
            merged["winrm_password"] = current["winrm_password"]
        clean = self._validate(merged, existing_id=server_id)

        async def _op(s: AsyncSession) -> None:
            row = await s.get(MonitoredServer, server_id)
            if row is None:
                raise KeyError(server_id)
            for k, v in clean.items():
                setattr(row, k, protect_secret(v) if k == "winrm_password" else v)

        await run_db(_op)
        await self.load()
        await self._notify()
        return self.public(self._servers[server_id])

    async def remove(self, server_id: int) -> None:
        async def _op(s: AsyncSession) -> bool:
            row = await s.get(MonitoredServer, server_id)
            if row is None:
                return False
            await s.delete(row)
            return True

        if not await run_db(_op):
            raise KeyError(server_id)
        self.status.pop(server_id, None)
        await self.load()
        await self._notify()
