"""AbuseIPDB reputation lookups (https://docs.abuseipdb.com/#check-endpoint).

Results are cached in memory and in the abuse_scores table so the daily quota (1,000 checks on the free plan) is only
spent on addresses Sentinel has not seen recently. Lookups for the dashboard go through a single background worker that
pauses on HTTP 429 until AbuseIPDB's reset time. Nothing here raises into the caller: failures become an `error` field.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import httpx
from sqlalchemy import select

from database import SECRET_MASK, AbuseScore, ConfigStore, SessionLocal, run_db, utcnow

log = logging.getLogger("sentinel.abuseipdb")

API_URL = os.environ.get("SENTINEL_ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/check")
ERROR_TTL = 600
AUTH_PAUSE = 600
MAX_QUEUE = 2000


def report_url(ip: str) -> str:
    return f"https://www.abuseipdb.com/check/{ip}"


def _iso(epoch: float | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_ip(ip: str) -> str:
    addr = ipaddress.ip_address(str(ip).strip())
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


class AbuseIPDB:
    def __init__(self, config: ConfigStore, on_result: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.config = config
        self.on_result = on_result
        self._cache: dict[str, dict[str, Any]] = {}
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=MAX_QUEUE)
        self._queued: set[str] = set()
        self._inflight: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._paused_until = 0.0
        self._pause_reason = ""
        self.last_error: str | None = None
        self.limit: int | None = None
        self.remaining: int | None = None
        self.checks = 0
        self.loaded = False

    # ------------------------------------------------------------------ settings
    def _s(self) -> dict[str, Any]:
        return self.config.get("general")

    def configured(self) -> bool:
        return bool(self._s().get("abuseipdb_api_key"))

    def enabled(self) -> bool:
        s = self._s()
        return bool(s.get("abuseipdb_enabled") and s.get("abuseipdb_api_key"))

    def status(self) -> dict[str, Any]:
        s = self._s()
        paused = self._paused_until > time.time()
        return {
            "enabled": self.enabled(), "configured": self.configured(), "auto_lookup": bool(s.get("abuseipdb_auto_lookup")),
            "limit": self.limit, "remaining": self.remaining, "checks": self.checks, "cached": len(self._cache),
            "queued": self._queue.qsize(), "paused_until": _iso(self._paused_until) if paused else None,
            "error": (self._pause_reason if paused else None) or self.last_error,
        }

    # ------------------------------------------------------------------ cache
    def _fresh(self, entry: dict[str, Any] | None) -> bool:
        if not entry:
            return False
        ttl = ERROR_TTL if entry.get("error") else float(self._s().get("abuseipdb_cache_hours") or 24) * 3600
        return time.time() - float(entry.get("_ts") or 0) < ttl

    @staticmethod
    def _public(entry: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in entry.items() if not k.startswith("_")}

    def cached(self, ip: str) -> dict[str, Any] | None:
        entry = self._cache.get(ip)
        return self._public(entry) if self._fresh(entry) else None

    async def load(self) -> None:
        """Warm the memory cache from the abuse_scores table (entries still inside the cache window)."""
        hours = float(self._s().get("abuseipdb_cache_hours") or 24)
        cutoff = utcnow() - timedelta(hours=hours)
        try:
            async with SessionLocal() as s:
                rows = (await s.execute(select(AbuseScore).where(AbuseScore.checked_at >= cutoff)
                                        .order_by(AbuseScore.checked_at.desc()).limit(50000))).scalars().all()
            for r in rows:
                try:
                    data = json.loads(r.data or "{}")
                except ValueError:
                    continue
                data["_ts"] = r.checked_at.replace(tzinfo=timezone.utc).timestamp()
                self._cache[r.ip] = data
            log.info("AbuseIPDB cache: %d address(es) restored", len(rows))
        except Exception:  # noqa: BLE001
            log.exception("Could not restore the AbuseIPDB cache")
        self.loaded = True

    async def _store(self, entry: dict[str, Any]) -> None:
        payload = json.dumps(self._public(entry))
        when = datetime.fromtimestamp(entry["_ts"], timezone.utc).replace(tzinfo=None)

        async def _op(s):  # type: ignore[no-untyped-def]
            row = await s.get(AbuseScore, entry["ip"])
            if row is None:
                s.add(AbuseScore(ip=entry["ip"], data=payload, checked_at=when))
            else:
                row.data, row.checked_at = payload, when

        try:
            await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Could not persist AbuseIPDB result for %s", entry["ip"])

    # ------------------------------------------------------------------ lookups
    def request(self, ips: list[str]) -> dict[str, dict[str, Any]]:
        """Cached results for `ips`; the rest are queued for the background worker (when auto lookup is on)."""
        out: dict[str, dict[str, Any]] = {}
        auto = self.enabled() and bool(self._s().get("abuseipdb_auto_lookup"))
        for raw in ips:
            try:
                ip = normalize_ip(raw)
            except ValueError:
                continue
            hit = self.cached(ip)
            if hit is not None:
                out[raw] = hit
                continue
            if not ipaddress.ip_address(ip).is_global:
                out[raw] = self._local(ip)
                continue
            if auto and ip not in self._queued and ip not in self._inflight:
                try:
                    self._queue.put_nowait(ip)
                    self._queued.add(ip)
                except asyncio.QueueFull:
                    break
        return out

    @staticmethod
    def _local(ip: str) -> dict[str, Any]:
        return {"ip": ip, "public": False, "score": None, "error": None, "note": "private / reserved address (not looked up)"}

    async def check(self, raw_ip: str, refresh: bool = False, api_key: str | None = None) -> dict[str, Any]:
        """One lookup, from cache unless `refresh`. Concurrent calls for the same IP share one API request."""
        ip = normalize_ip(raw_ip)
        if not refresh and api_key is None:
            hit = self.cached(ip)
            if hit is not None:
                return hit
        if not ipaddress.ip_address(ip).is_global:
            return self._local(ip)
        key = api_key if api_key not in (None, "", SECRET_MASK) else self._s().get("abuseipdb_api_key")
        if not key:
            return {"ip": ip, "score": None, "error": "AbuseIPDB API key is not configured (CONFIG > GENERAL)"}
        if self._paused_until > time.time() and api_key is None:
            old = self._cache.get(ip)
            return {**(self._public(old) if old else {"ip": ip, "score": None}), "error": self._pause_reason, "stale": bool(old)}
        if ip in self._inflight and api_key is None:
            return await asyncio.shield(self._inflight[ip])
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        if api_key is None:
            self._inflight[ip] = fut
        try:
            entry = await self._fetch(ip, str(key), probe=api_key is not None)
            if api_key is None or not entry.get("error"):
                self._cache[ip] = entry
                if not entry.get("error"):
                    await self._store(entry)
            result = self._public(entry)
            fut.set_result(result)
            return result
        except Exception as exc:  # noqa: BLE001
            log.exception("AbuseIPDB lookup of %s failed", ip)
            result = {"ip": ip, "score": None, "error": f"{type(exc).__name__}: {exc}"}
            fut.set_result(result)
            return result
        finally:
            if self._inflight.get(ip) is fut:
                del self._inflight[ip]

    async def _fetch(self, ip: str, key: str, probe: bool = False) -> dict[str, Any]:
        """`probe` (a key test) reports errors without pausing or flagging the saved configuration."""
        days = int(self._s().get("abuseipdb_max_age_days") or 90)
        now = time.time()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=6.0)) as client:
                resp = await client.get(API_URL, params={"ipAddress": ip, "maxAgeInDays": days},
                                        headers={"Key": key, "Accept": "application/json", "User-Agent": "IIS-Sentinel"})
        except httpx.HTTPError as exc:
            err = f"AbuseIPDB unreachable: {type(exc).__name__}: {exc}"[:300]
            if not probe:
                self.last_error = err
            return {"ip": ip, "score": None, "error": err, "_ts": now}
        self._rate(resp)
        if probe and resp.status_code != 200:
            if resp.status_code in (401, 403):
                return {"ip": ip, "score": None, "error": f"AbuseIPDB rejected the API key (HTTP {resp.status_code})", "_ts": now}
            return {"ip": ip, "score": None, "error": f"AbuseIPDB HTTP {resp.status_code}: {resp.text[:200]}", "_ts": now}
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After")
            reset = resp.headers.get("X-RateLimit-Reset")
            until = now + (float(retry) if retry and retry.isdigit() else 3600)
            if reset and reset.isdigit():
                until = max(until, float(reset))
            self._paused_until = until
            self._pause_reason = f"AbuseIPDB daily limit reached; lookups resume {_iso(until)}"
            log.warning(self._pause_reason)
            return {"ip": ip, "score": None, "error": self._pause_reason, "_ts": now}
        if resp.status_code in (401, 403):
            self._paused_until = now + AUTH_PAUSE
            self._pause_reason = f"AbuseIPDB rejected the API key (HTTP {resp.status_code})"
            self.last_error = self._pause_reason
            return {"ip": ip, "score": None, "error": self._pause_reason, "_ts": now}
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200:
            detail = "; ".join(str(e.get("detail", "")) for e in body.get("errors", []) if isinstance(e, dict)) or resp.text[:200]
            self.last_error = f"AbuseIPDB HTTP {resp.status_code}: {detail}"
            return {"ip": ip, "score": None, "error": self.last_error, "_ts": now}
        d = body.get("data") or {}
        self.checks += 1
        self.last_error = None
        return {
            "ip": ip, "public": bool(d.get("isPublic", True)), "score": d.get("abuseConfidenceScore"),
            "reports": d.get("totalReports") or 0, "users": d.get("numDistinctUsers") or 0,
            "last_reported": d.get("lastReportedAt"), "country": d.get("countryCode"), "usage": d.get("usageType"),
            "isp": d.get("isp"), "domain": d.get("domain"), "tor": bool(d.get("isTor")),
            "whitelisted": bool(d.get("isWhitelisted")), "max_age_days": days, "checked_at": _iso(now),
            "url": report_url(ip), "error": None, "_ts": now,
        }

    def _rate(self, resp: httpx.Response) -> None:
        try:
            if resp.headers.get("X-RateLimit-Limit"):
                self.limit = int(resp.headers["X-RateLimit-Limit"])
            if resp.headers.get("X-RateLimit-Remaining"):
                self.remaining = int(resp.headers["X-RateLimit-Remaining"])
        except ValueError:
            pass

    # ------------------------------------------------------------------ worker
    async def run(self) -> None:
        if not self.loaded:
            await self.load()
        while True:
            ip = await self._queue.get()
            try:
                wait = self._paused_until - time.time()
                if wait > 0:
                    await asyncio.sleep(min(wait, 3600))
                if not self.enabled() or self.cached(ip) is not None:
                    continue
                result = await self.check(ip)
                if self.on_result:
                    try:
                        self.on_result(result)
                    except Exception:  # noqa: BLE001
                        log.exception("AbuseIPDB result callback failed")
                await asyncio.sleep(0.3)
            finally:
                self._queued.discard(ip)

    def settings_changed(self) -> None:
        """A new key or re-enable clears an auth/limit pause so the next lookup tries again."""
        if self._pause_reason.startswith("AbuseIPDB rejected"):
            self._paused_until = 0.0
            self._pause_reason = ""
        self.last_error = None
        self._cache = {ip: e for ip, e in self._cache.items() if not e.get("error")}
