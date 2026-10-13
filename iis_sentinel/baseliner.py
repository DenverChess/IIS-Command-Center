"""Statistical traffic baselining and Z-score anomaly detection.

Every `baseline_interval` seconds (default 5 min) the last 24h of *clean* traffic (requests that did not
match an attack signature, so attackers can't poison the model) is aggregated into:

  * per server  - requests/min, bytes/min, time-taken for each monitored IIS server (idle minutes count as 0)
  * per IP      - requests/min, bytes/min (over that IP's active minutes) and time-taken
  * population  - the distribution of a "typical client minute", used for IPs with no history yet

Incoming entries are bucketed per server by their *log* minute (each IIS server buffers log writes on its own
schedule, so wall-clock or fleet-wide bucketing would create false spikes). Z = (x - mean) / max(std, floor); Z above `zscore_threshold` (default 3.0) is an anomaly.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, insert, select

from database import LOCAL_SERVER_ID, Baseline, ConfigStore, LogEntry, SessionLocal, iso, run_db, utcnow

log = logging.getLogger("sentinel.baseliner")

STD_FLOOR = {"rpm": 1.0, "bpm": 4096.0, "time_taken": 50.0}
MIN_IP_REQUESTS_FOR_VOLUME = 30
MIN_IP_BYTES_FOR_BANDWIDTH = 1_048_576
# Unknown clients are compared against the whole population, which is noisy; require a bigger transfer.
MIN_POPULATION_BYTES_FOR_BANDWIDTH = 10 * 1_048_576
MIN_TIME_TAKEN_MS = 1000
LATENCY_COOLDOWN = 300.0


@dataclass
class Stat:
    mean: float
    std: float
    samples: int

    def z(self, value: float, metric: str) -> float:
        return (value - self.mean) / max(self.std, STD_FLOOR.get(metric, 1.0), 1e-9)

    def to_dict(self) -> dict[str, float]:
        return {"mean": round(self.mean, 2), "std": round(self.std, 2), "samples": self.samples}


def _stat(n: int, s: float, ss: float) -> Stat:
    if n <= 0:
        return Stat(0.0, 0.0, 0)
    mean = s / n
    var = max(0.0, ss / n - mean * mean)
    return Stat(mean, math.sqrt(var), n)


class _Live:
    """Live per-minute bucket for one server."""

    def __init__(self) -> None:
        self.minute: datetime | None = None
        self.last_finalized: datetime | None = None
        self.ip_counts: dict[str, int] = defaultdict(int)
        self.ip_bytes: dict[str, int] = defaultdict(int)
        self.total = 0
        self.total_bytes = 0
        self.tt_sum = 0
        self.flagged: set[tuple[str, str]] = set()
        self.current: dict[str, Any] = {
            "minute": None, "rpm": 0, "bpm": 0, "avg_time_taken": 0.0,
            "z_rpm": 0.0, "z_bpm": 0.0, "z_time_taken": 0.0, "live_count": 0,
        }

    def reset(self) -> None:
        self.minute = None
        self.ip_counts.clear()
        self.ip_bytes.clear()
        self.flagged.clear()
        self.total = self.total_bytes = self.tt_sum = 0


class Baseliner:
    def __init__(self, config: ConfigStore) -> None:
        self.config = config
        self.server_stats: dict[int, dict[str, Stat]] = {}
        self.population: dict[str, Stat] = {}
        self.ip_stats: dict[str, dict[str, Stat]] = {}
        self.last_computed: datetime | None = None
        self.compute_seconds = 0.0
        self._live: dict[int, _Live] = {}
        self._latency_last: dict[tuple[int, str], float] = {}

    @property
    def global_stats(self) -> dict[str, Stat]:
        """Fleet view: the busiest server's baseline (used for display only)."""
        if not self.server_stats:
            return {}
        return max(self.server_stats.values(), key=lambda m: m.get("rpm", Stat(0, 0, 0)).mean)

    # ------------------------------------------------------------------ background loop
    async def run(self) -> None:
        await self.load_persisted()
        next_compute = 0.0
        while True:
            now = time.monotonic()
            if now >= next_compute:
                try:
                    await self.recompute()
                except Exception:  # noqa: BLE001
                    log.exception("Baseline recompute failed")
                next_compute = time.monotonic() + float(self.config.value("watchers", "baseline_interval", 300))
            await asyncio.sleep(5)

    async def load_persisted(self) -> None:
        try:
            async with SessionLocal() as s:
                rows = (await s.execute(select(Baseline))).scalars().all()
            for r in rows:
                st = Stat(r.mean, r.std, r.samples)
                if r.scope == "server":
                    try:
                        self.server_stats.setdefault(int(r.key), {})[r.metric] = st
                    except ValueError:
                        continue
                elif r.scope == "population":
                    self.population[r.metric] = st
                elif r.scope == "ip":
                    self.ip_stats.setdefault(r.key, {})[r.metric] = st
            if rows:
                self.last_computed = max(r.computed_at for r in rows)
                log.info("Loaded %d persisted baseline rows", len(rows))
        except Exception:  # noqa: BLE001
            log.exception("Could not load persisted baselines")

    async def recompute(self) -> None:
        started = time.monotonic()
        now = utcnow()
        since = now - timedelta(hours=24)
        minute_expr = func.strftime("%Y-%m-%d %H:%M", LogEntry.ts)
        clean = (LogEntry.ts >= since) & (LogEntry.threat_tags == "")

        ip_acc: dict[str, list[float]] = {}
        ip_minutes: dict[tuple[str, str], tuple[int, int]] = {}
        server_minutes: dict[int, dict[str, tuple[int, int]]] = {}
        tt_rows: list[Any] = []
        tt_server_rows: list[Any] = []
        async with SessionLocal() as s:
            stream = await s.stream(
                select(LogEntry.server_id, LogEntry.c_ip, minute_expr, func.count(), func.coalesce(func.sum(LogEntry.sc_bytes), 0))
                .where(clean)
                .group_by(LogEntry.server_id, LogEntry.c_ip, minute_expr)
            )
            async for sid, ip, minute, cnt, nbytes in stream:
                # Per-IP behaviour is fleet-wide (a client's habits don't change per server), but an IP's
                # activity on several servers in the same minute is one sample per server.
                key = (ip, f"{sid}|{minute}")
                c = ip_minutes.get(key, (0, 0))
                ip_minutes[key] = (c[0] + cnt, c[1] + int(nbytes))
                g = server_minutes.setdefault(int(sid or LOCAL_SERVER_ID), {}).get(minute, (0, 0))
                server_minutes[int(sid or LOCAL_SERVER_ID)][minute] = (g[0] + cnt, g[1] + int(nbytes))
            tt_rows = (
                await s.execute(
                    select(
                        LogEntry.c_ip,
                        func.count(),
                        func.coalesce(func.sum(LogEntry.time_taken), 0),
                        func.coalesce(func.sum(LogEntry.time_taken * LogEntry.time_taken), 0),
                    )
                    .where(clean)
                    .group_by(LogEntry.c_ip)
                )
            ).all()
            tt_server_rows = (
                await s.execute(
                    select(
                        LogEntry.server_id,
                        func.count(),
                        func.coalesce(func.sum(LogEntry.time_taken), 0),
                        func.coalesce(func.sum(LogEntry.time_taken * LogEntry.time_taken), 0),
                    )
                    .where(clean)
                    .group_by(LogEntry.server_id)
                )
            ).all()

        for (ip, _k), (cnt, nbytes) in ip_minutes.items():
            a = ip_acc.setdefault(ip, [0, 0.0, 0.0, 0.0, 0.0])
            a[0] += 1
            a[1] += cnt
            a[2] += cnt * cnt
            a[3] += nbytes
            a[4] += float(nbytes) * float(nbytes)

        ip_stats: dict[str, dict[str, Stat]] = {}
        pop = [0, 0.0, 0.0, 0.0, 0.0]
        for ip, (n, s1, s2, b1, b2) in ip_acc.items():
            ip_stats[ip] = {"rpm": _stat(int(n), s1, s2), "bpm": _stat(int(n), b1, b2)}
            for i, v in enumerate((n, s1, s2, b1, b2)):
                pop[i] += v
        tt_pop = [0, 0.0, 0.0]
        for ip, n, s1, s2 in tt_rows:
            ip_stats.setdefault(ip, {})["time_taken"] = _stat(int(n), float(s1), float(s2))
            tt_pop[0] += n
            tt_pop[1] += float(s1)
            tt_pop[2] += float(s2)

        population = {
            "rpm": _stat(int(pop[0]), pop[1], pop[2]),
            "bpm": _stat(int(pop[0]), pop[3], pop[4]),
            "time_taken": _stat(int(tt_pop[0]), tt_pop[1], tt_pop[2]),
        }
        tt_by_server = {int(sid or LOCAL_SERVER_ID): _stat(int(n), float(s1), float(s2)) for sid, n, s1, s2 in tt_server_rows}

        last_full = now.replace(second=0, microsecond=0) - timedelta(minutes=1)
        server_stats: dict[int, dict[str, Stat]] = {}
        for sid, minutes in server_minutes.items():
            first = min(datetime.strptime(m, "%Y-%m-%d %H:%M") for m in minutes)
            span = max(1, int((last_full - first).total_seconds() // 60) + 1, len(minutes))
            r1 = sum(c for c, _ in minutes.values())
            r2 = sum(c * c for c, _ in minutes.values())
            b1 = sum(b for _, b in minutes.values())
            b2 = sum(float(b) * b for _, b in minutes.values())
            server_stats[sid] = {
                "rpm": _stat(span, r1, r2),
                "bpm": _stat(span, b1, b2),
                "time_taken": tt_by_server.get(sid, population["time_taken"]),
            }

        self.ip_stats = ip_stats
        self.population = population
        self.server_stats = server_stats
        self.last_computed = now
        await self._persist(now)
        self.compute_seconds = round(time.monotonic() - started, 3)
        log.info(
            "Baseline recomputed: %d IPs, %d server(s) [%s] (%.2fs)",
            len(ip_stats),
            len(server_stats),
            ", ".join(f"{sid}: rpm {st['rpm'].mean:.1f}±{st['rpm'].std:.1f}" for sid, st in server_stats.items()),
            self.compute_seconds,
        )

    async def _persist(self, now: datetime) -> None:
        rows: list[dict[str, Any]] = []
        for sid, metrics in self.server_stats.items():
            for metric, st in metrics.items():
                rows.append({"scope": "server", "key": str(sid), "metric": metric, "mean": st.mean, "std": st.std, "samples": st.samples, "computed_at": now})
        for metric, st in self.population.items():
            rows.append({"scope": "population", "key": "*", "metric": metric, "mean": st.mean, "std": st.std, "samples": st.samples, "computed_at": now})
        for ip, metrics in self.ip_stats.items():
            for metric, st in metrics.items():
                rows.append({"scope": "ip", "key": ip[:64], "metric": metric, "mean": st.mean, "std": st.std, "samples": st.samples, "computed_at": now})

        async def _op(s):  # type: ignore[no-untyped-def]
            await s.execute(delete(Baseline))
            for i in range(0, len(rows), 2000):
                await s.execute(insert(Baseline), rows[i : i + 2000])

        try:
            await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Failed to persist baselines")

    # ------------------------------------------------------------------ live scoring
    def _min_samples(self) -> int:
        return int(self.config.value("watchers", "baseline_min_samples", 30))

    def _threshold(self) -> float:
        return float(self.config.value("watchers", "zscore_threshold", 3.0))

    def _ip_stat(self, ip: str, metric: str) -> tuple[Stat | None, str]:
        min_samples = self._min_samples()
        st = self.ip_stats.get(ip, {}).get(metric)
        if st and st.samples >= min(10, min_samples):
            return st, "ip"
        pop = self.population.get(metric)
        if pop and pop.samples >= min_samples:
            return pop, "population"
        return None, "none"

    def observe(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        ts = entry.get("ts")
        if not isinstance(ts, datetime):
            return anomalies
        sid = int(entry.get("server_id") or LOCAL_SERVER_ID)
        live = self._live.setdefault(sid, _Live())
        minute = ts.replace(second=0, microsecond=0)
        ip = entry.get("c_ip") or "0.0.0.0"
        nbytes = int(entry.get("sc_bytes") or 0) + int(entry.get("cs_bytes") or 0)
        tt = int(entry.get("time_taken") or 0)
        threshold = self._threshold()

        late = live.last_finalized is not None and minute <= live.last_finalized
        if not late:
            if live.minute is None:
                live.minute = minute
            elif minute > live.minute:
                anomalies.extend(self._finalize(sid, live))
                live.minute = minute
            if minute == live.minute:
                live.ip_counts[ip] += 1
                live.ip_bytes[ip] += nbytes
                live.total += 1
                live.total_bytes += nbytes
                live.tt_sum += tt
                live.current["live_count"] = live.total
                cnt = live.ip_counts[ip]

                if cnt >= MIN_IP_REQUESTS_FOR_VOLUME and (ip, "rpm") not in live.flagged:
                    st, basis = self._ip_stat(ip, "rpm")
                    if st:
                        z = st.z(cnt, "rpm")
                        if z > threshold:
                            live.flagged.add((ip, "rpm"))
                            anomalies.append(self._anomaly(sid, "rpm", ip, cnt, st, z, basis))
                b = live.ip_bytes[ip]
                if b >= MIN_IP_BYTES_FOR_BANDWIDTH and (ip, "bpm") not in live.flagged:
                    st, basis = self._ip_stat(ip, "bpm")
                    if st and (basis == "ip" or b >= MIN_POPULATION_BYTES_FOR_BANDWIDTH):
                        z = st.z(b, "bpm")
                        if z > threshold:
                            live.flagged.add((ip, "bpm"))
                            anomalies.append(self._anomaly(sid, "bpm", ip, b, st, z, basis))

        if tt >= MIN_TIME_TAKEN_MS:
            st, basis = self._ip_stat(ip, "time_taken")
            if st:
                z = st.z(tt, "time_taken")
                now = time.monotonic()
                if z > threshold and now - self._latency_last.get((sid, ip), 0.0) > LATENCY_COOLDOWN:
                    self._latency_last[(sid, ip)] = now
                    if len(self._latency_last) > 20000:
                        self._latency_last.clear()
                    anomalies.append(self._anomaly(sid, "time_taken", ip, tt, st, z, basis, uri=entry.get("cs_uri_stem", "")))
        return anomalies

    @staticmethod
    def _anomaly(server_id: int, metric: str, ip: str | None, value: float, st: Stat, z: float, basis: str,
                 **extra: Any) -> dict[str, Any]:
        return {
            "server_id": server_id,
            "metric": metric,
            "ip": ip,
            "value": value,
            "mean": round(st.mean, 2),
            "std": round(st.std, 2),
            "z": round(z, 2),
            "basis": basis,
            **extra,
        }

    def _finalize(self, sid: int, live: _Live) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        if live.minute is None:
            return anomalies
        rpm, bpm = live.total, live.total_bytes
        avg_tt = (live.tt_sum / rpm) if rpm else 0.0
        min_samples = self._min_samples()
        threshold = self._threshold()
        z_rpm = z_bpm = z_tt = 0.0
        stats = self.server_stats.get(sid, {})
        g_rpm, g_bpm, g_tt = stats.get("rpm"), stats.get("bpm"), stats.get("time_taken")
        if g_rpm and g_rpm.samples >= min_samples:
            z_rpm = g_rpm.z(rpm, "rpm")
            if z_rpm > threshold and rpm >= 30:
                anomalies.append(self._anomaly(sid, "global_rpm", None, rpm, g_rpm, z_rpm, "server"))
            elif z_rpm < -threshold and g_rpm.mean >= 20:
                anomalies.append(self._anomaly(sid, "global_rpm_drop", None, rpm, g_rpm, z_rpm, "server"))
        if g_bpm and g_bpm.samples >= min_samples:
            z_bpm = g_bpm.z(bpm, "bpm")
            if z_bpm > threshold and bpm >= MIN_IP_BYTES_FOR_BANDWIDTH:
                anomalies.append(self._anomaly(sid, "global_bpm", None, bpm, g_bpm, z_bpm, "server"))
        if g_tt and g_tt.samples >= min_samples and rpm:
            z_tt = g_tt.z(avg_tt, "time_taken")

        live.current = {
            "minute": iso(live.minute),
            "rpm": rpm,
            "bpm": bpm,
            "avg_time_taken": round(avg_tt, 1),
            "z_rpm": round(z_rpm, 2),
            "z_bpm": round(z_bpm, 2),
            "z_time_taken": round(z_tt, 2),
            "live_count": 0,
        }
        live.last_finalized = live.minute
        live.reset()
        return anomalies

    def tick(self) -> list[dict[str, Any]]:
        """Finalize buckets that haven't seen traffic for a while (IIS flushes logs ~every 60s)."""
        now = utcnow().replace(second=0, microsecond=0)
        out: list[dict[str, Any]] = []
        for sid, live in list(self._live.items()):
            if live.minute is not None and now - live.minute >= timedelta(minutes=3):
                out.extend(self._finalize(sid, live))
            elif live.minute is None and live.last_finalized is not None and now - live.last_finalized >= timedelta(minutes=5):
                # Server has gone quiet: report idle minutes as zero traffic.
                live.minute = now - timedelta(minutes=3)
                out.extend(self._finalize(sid, live))
        return out

    def forget_server(self, server_id: int) -> None:
        self._live.pop(server_id, None)
        self.server_stats.pop(server_id, None)

    def _fleet_current(self) -> dict[str, Any]:
        currents = [lv.current for lv in self._live.values()]
        if not currents:
            return _Live().current
        rpm = sum(c["rpm"] for c in currents)
        weighted_tt = sum(c["avg_time_taken"] * c["rpm"] for c in currents)
        return {
            "minute": max((c["minute"] for c in currents if c["minute"]), default=None),
            "rpm": rpm,
            "bpm": sum(c["bpm"] for c in currents),
            "avg_time_taken": round(weighted_tt / rpm, 1) if rpm else 0.0,
            "z_rpm": max((c["z_rpm"] for c in currents), key=abs, default=0.0),
            "z_bpm": max((c["z_bpm"] for c in currents), key=abs, default=0.0),
            "z_time_taken": max((c["z_time_taken"] for c in currents), key=abs, default=0.0),
            "live_count": sum(c["live_count"] for c in currents),
        }

    @property
    def current(self) -> dict[str, Any]:
        return self._fleet_current()

    def snapshot(self, server_id: int | None = None) -> dict[str, Any]:
        if server_id is not None:
            live = self._live.get(server_id)
            current = live.current if live else _Live().current
            glob = self.server_stats.get(server_id, {})
        else:
            current = self._fleet_current()
            glob = self.global_stats
        return {
            "current": current,
            "per_server": {
                sid: {"current": (self._live[sid].current if sid in self._live else _Live().current),
                      "global": {k: v.to_dict() for k, v in self.server_stats.get(sid, {}).items()}}
                for sid in set(self._live) | set(self.server_stats)
            },
            "global": {k: v.to_dict() for k, v in glob.items()},
            "population": {k: v.to_dict() for k, v in self.population.items()},
            "tracked_ips": len(self.ip_stats),
            "last_computed": iso(self.last_computed),
            "compute_seconds": self.compute_seconds,
            "threshold": self._threshold(),
        }
