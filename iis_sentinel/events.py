"""WebSocket broadcast hub and the central alert pipeline (persist -> broadcast -> email)."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from sqlalchemy import update

from database import SEVERITIES, Alert, ConfigStore, iso, run_db, utcnow

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
    ) -> dict[str, Any] | None:
        severity = severity if severity in SEVERITY_RANK else "INFO"
        if self._cooling(dedup_key, cooldown):
            return None
        ts = utcnow()
        details = details or {}
        record: dict[str, Any] = {
            "id": None,
            "ts": iso(ts),
            "severity": severity,
            "category": category,
            "title": title[:256],
            "message": message,
            "source_ip": source_ip,
            "details": details,
            "acknowledged": False,
        }
        try:
            payload = json.dumps(details, default=str)

            async def _op(s):  # type: ignore[no-untyped-def]
                row = Alert(
                    ts=ts,
                    severity=severity,
                    category=category,
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
            "ALERT [%s/%s] %s %s",
            severity,
            category,
            title,
            f"({source_ip})" if source_ip else "",
        )
        self._recent.appendleft(record)
        self.hub.broadcast({"type": "alert", "data": record})

        min_sev = self.config.value("exchange", "alert_min_severity", "HIGH")
        if self.config.value("exchange", "enabled", False) and SEVERITY_RANK[severity] >= SEVERITY_RANK.get(min_sev, 2):
            task = asyncio.create_task(self._email(record))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return record

    async def _email(self, record: dict[str, Any]) -> None:
        try:
            ok = await self.mailer.send_alert(record)
            if ok and record.get("id"):
                alert_id = record["id"]

                async def _op(s):  # type: ignore[no-untyped-def]
                    await s.execute(update(Alert).where(Alert.id == alert_id).values(emailed=True))

                await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Alert email task failed")

    async def drain(self, timeout: float = 10.0) -> None:
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)
