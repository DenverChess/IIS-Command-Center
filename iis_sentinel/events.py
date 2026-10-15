"""WebSocket broadcast hub and the central alert pipeline (persist -> broadcast -> email)."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable, Sequence

from sqlalchemy import update

from alert_catalog import EVENTS as ALERT_EVENTS
from database import LOCAL_SERVER_ID, SEVERITIES, ActionableAlert, ConfigStore, iso, run_db, utcnow

if TYPE_CHECKING:
    from mailer import Mailer

log = logging.getLogger("sentinel.events")

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Hub:
    """Fan-out to WebSocket clients. Each client gets a bounded queue so a slow browser never blocks producers."""

    def __init__(self, client_queue_size: int = 500) -> None:
        self._clients: dict[int, asyncio.Queue[str]] = {}
        self._size = client_queue_size
        self._next_id = 0

    def register(self) -> tuple[int, asyncio.Queue[str]]:
        self._next_id += 1
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self._size)
        self._clients[self._next_id] = q
        return self._next_id, q

    def unregister(self, client_id: int) -> None:
        self._clients.pop(client_id, None)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def broadcast(self, message: dict[str, Any]) -> None:
        if not self._clients:
            return
        try:
            data = json.dumps(message, default=str)
        except (TypeError, ValueError):
            log.exception("Unserialisable broadcast dropped: %s", message.get("type"))
            return
        for q in list(self._clients.values()):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                pass


class AlertManager:
    def __init__(self, hub: Hub, config: ConfigStore, mailer: "Mailer") -> None:
        self.hub = hub
        self.config = config
        self.mailer = mailer
        self._cooldowns: dict[str, float] = {}
        self._recent: deque[dict[str, Any]] = deque(maxlen=200)
        self._tasks: set[asyncio.Task[Any]] = set()
        self.server_name: Callable[[int], str] = lambda sid: f"SRV-{sid}"

    def update_recent(self, alert_id: int, **fields: Any) -> dict[str, Any] | None:
        for rec in self._recent:
            if rec.get("id") == alert_id:
                rec.update(fields)
                return rec
        return None

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(self._recent)[:limit]

    def _cooling(self, key: str | None, cooldown: float) -> bool:
        if not key or cooldown <= 0:
            return False
        now = time.monotonic()
        last = self._cooldowns.get(key)
        if last is not None and now - last < cooldown:
            return True
        self._cooldowns[key] = now
        if len(self._cooldowns) > 20000:
            cutoff = now - 86400
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v > cutoff}
        return False

    @staticmethod
    def _in_quiet_hours(start: str, end: str, now: datetime | None = None) -> bool:
        """Quiet hours use the Sentinel host's local clock; start > end spans midnight (22:00-07:00)."""
        def mins(v: str) -> int:
            h, m = v.split(":")
            return int(h) * 60 + int(m)

        now = now or datetime.now()
        cur, lo, hi = now.hour * 60 + now.minute, mins(start), mins(end)
        if lo == hi:
            return False
        return lo <= cur < hi if lo < hi else (cur >= lo or cur < hi)

    def route(self, events: list[str], severity: str, server_id: int,
              occurred_at: datetime | None = None) -> dict[str, Any] | None:
        """Apply the ALERTS tab settings. Returns None when every event is disabled (nothing is recorded)."""
        cfg = self.config.get("alerts")
        settings = cfg.get("events") or {}
        if events:
            active = []
            for eid in events:
                s = settings.get(eid)
                if s is None:
                    ev = ALERT_EVENTS.get(eid)
                    s = {"enabled": True, "desktop": bool(ev and ev["desktop"]), "email": bool(ev and ev["email"]),
                         "severity": "default"}
                if s.get("enabled", True):
                    active.append(s)
            if not active:
                return None
            overrides = [s["severity"] for s in active if s.get("severity") in SEVERITY_RANK]
            if overrides:
                severity = max(overrides, key=lambda v: SEVERITY_RANK[v])
            desktop = any(s.get("desktop") for s in active)
            email = any(s.get("email") for s in active)
        else:
            min_sev = self.config.value("exchange", "alert_min_severity", "HIGH")
            desktop = SEVERITY_RANK[severity] >= SEVERITY_RANK["HIGH"]
            email = SEVERITY_RANK[severity] >= SEVERITY_RANK.get(min_sev, 2)
        suppressed = None
        if occurred_at is not None and (utcnow() - occurred_at).total_seconds() > 60 * float(cfg.get("live_window_minutes") or 15):
            suppressed = "historical log line"
        elif self.server_name(server_id).lower() in {m.lower() for m in cfg.get("muted_servers") or []}:
            suppressed = "server muted"
        elif cfg.get("quiet_hours_enabled") and self._in_quiet_hours(cfg.get("quiet_start", "22:00"), cfg.get("quiet_end", "07:00")):
            if not (severity == "CRITICAL" and cfg.get("quiet_bypass_critical", True)):
                suppressed = "quiet hours"
        if not cfg.get("desktop_notifications", True):
            desktop = False
        return {"severity": severity, "desktop": desktop and not suppressed, "email": email and not suppressed,
                "sound": bool(cfg.get("sound", True)), "suppressed": suppressed}

    def recipients(self) -> list[str]:
        return list(self.config.value("alerts", "email_recipients", []) or []) or list(
            self.config.value("exchange", "alert_recipients", []) or [])

    async def raise_alert(
        self,
        severity: str,
        category: str,
        title: str,
        message: str = "",
        source_ip: str | None = None,
        details: dict[str, Any] | None = None,
        dedup_key: str | None = None,
        cooldown: float = 0,
        server_id: int = LOCAL_SERVER_ID,
        actionable: bool | None = None,
        event: str | Sequence[str] | None = None,
        occurred_at: datetime | None = None,
        notify: dict[str, bool] | None = None,
    ) -> dict[str, Any] | None:
        """Persist -> broadcast -> notify. `event` names the ALERTS-tab event(s) this alert belongs to;
        `occurred_at` is the log timestamp (old backfilled lines never notify); `notify` forces the routing."""
        severity = severity if severity in SEVERITY_RANK else "INFO"
        events = [event] if isinstance(event, str) else list(event or [])
        route = self.route(events, severity, server_id, occurred_at)
        if route is None:
            return None
        if notify is not None:
            route.update(notify, suppressed=None)
        severity = route["severity"]
        if self._cooling(dedup_key, cooldown):
            return None
        ts = utcnow()
        details = details or {}
        # Actionable alerts (an attacker IP that can be approved for a firewall ban) start as Pending.
        if actionable is None:
            actionable = bool(source_ip) and category in ("attack", "threat")
        status = "Pending" if actionable and source_ip else "Info"
        server_name = self.server_name(server_id)
        record: dict[str, Any] = {
            "id": None,
            "ts": iso(ts),
            "server_id": server_id,
            "server_name": server_name,
            "status": status,
            "severity": severity,
            "category": category,
            "event": events[0] if events else "",
            "title": title[:256],
            "message": message,
            "source_ip": source_ip,
            "details": details,
            "acknowledged": False,
            "notify": {"desktop": route["desktop"], "email": route["email"], "sound": route["sound"],
                       "suppressed": route["suppressed"]},
        }
        try:
            payload = json.dumps(details, default=str)

            async def _op(s):  # type: ignore[no-untyped-def]
                row = ActionableAlert(
                    server_id=server_id,
                    status=status,
                    ts=ts,
                    severity=severity,
                    category=category,
                    event=record["event"],
                    title=title[:256],
                    message=message,
                    source_ip=source_ip,
                    details=payload,
                )
                s.add(row)
                await s.flush()
                return row.id

            record["id"] = await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Failed to persist alert '%s'", title)

        log.log(
            logging.CRITICAL if severity == "CRITICAL" else logging.WARNING if severity in ("HIGH", "WARNING") else logging.INFO,
            "ALERT [%s/%s] [%s] %s %s",
            severity,
            category,
            server_name,
            title,
            f"({source_ip})" if source_ip else "",
        )
        self._recent.appendleft(record)
        self.hub.broadcast({"type": "alert", "data": record})

        if route["email"] and self.config.value("exchange", "enabled", False):
            task = asyncio.create_task(self._email(record))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return record

    async def _email(self, record: dict[str, Any]) -> None:
        try:
            ok = await self.mailer.send_alert(record, recipients=self.recipients())
            if ok and record.get("id"):
                alert_id = record["id"]

                async def _op(s):  # type: ignore[no-untyped-def]
                    await s.execute(update(ActionableAlert).where(ActionableAlert.id == alert_id).values(emailed=True))

                await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Alert email task failed")

    async def drain(self, timeout: float = 10.0) -> None:
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)
