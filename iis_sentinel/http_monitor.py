"""Per-site HTTP health detectors fed from the IIS log stream.

* http_error        - each response whose status matches alerts.http_error_codes (default 500-599); repeats of
                      the same (site, status, URL) are rolled up for the cooldown and reported as a count.
* http_error_burst  - at least N matching errors on one site within the burst window.
* status_watch      - each response with one of alerts.watched_status_codes (e.g. 413, 429), rolled up per code.
* slow              - at least N requests slower than alerts.slow_response_ms on one site within the window.

Windows run on log timestamps, so a backlog read in `tail`/`full` start mode is judged on when the
requests happened rather than when Sentinel read them.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Any

from database import LOCAL_SERVER_ID, ConfigStore, parse_status_codes


def _matches(ranges: list[tuple[int, int]], status: int) -> bool:
    return any(lo <= status <= hi for lo, hi in ranges)


class HttpMonitor:
    def __init__(self, config: ConfigStore) -> None:
        self.config = config
        self._ranges: dict[tuple[str, ...], list[tuple[int, int]]] = {}
        self._errors: defaultdict[tuple[int, str], deque[tuple[float, int, str]]] = defaultdict(deque)
        self._slow: defaultdict[tuple[int, str], deque[tuple[float, int, str]]] = defaultdict(deque)
        self._rollup: dict[tuple[Any, ...], list[float]] = {}
        self._burst_at: dict[tuple[Any, ...], float] = {}
        self._seen = 0

    def _codes(self, key: str) -> list[tuple[int, int]]:
        tokens = tuple(self.config.value("alerts", key, []) or [])
        cached = self._ranges.get(tokens)
        if cached is None:
            try:
                cached = parse_status_codes(list(tokens))
            except ValueError:
                cached = []
            self._ranges[tokens] = cached
        return cached

    def _roll(self, key: tuple[Any, ...], t: float, cooldown: float) -> int | None:
        """Returns how many repeats were rolled up since the last report, or None while still cooling down."""
        rec = self._rollup.get(key)
        if rec is None or t - rec[0] >= cooldown or t < rec[0]:
            suppressed = int(rec[1]) if rec else 0
            self._rollup[key] = [t, 0]
            return suppressed
        rec[1] += 1
        return None

    def _burst_ready(self, key: tuple[Any, ...], t: float, rearm: float) -> bool:
        last = self._burst_at.get(key)
        if last is not None and 0 <= t - last < rearm:
            return False
        self._burst_at[key] = t
        return True

    def observe(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        status = int(entry.get("sc_status") or 0)
        tt = int(entry.get("time_taken") or 0)
        val = self.config.value
        slow_ms = int(val("alerts", "slow_response_ms", 10000))
        err_codes = self._codes("http_error_codes")
        watch_codes = self._codes("watched_status_codes")
        is_err = _matches(err_codes, status)
        is_watch = not is_err and _matches(watch_codes, status)
        is_slow = tt >= slow_ms
        if not (is_err or is_watch or is_slow):
            return []
        stem = entry.get("cs_uri_stem") or ""
        lowered = stem.lower()
        if any(lowered.startswith(p.lower()) for p in val("alerts", "http_ignore_paths", []) or []):
            return []

        self._seen += 1
        if self._seen % 5000 == 0:
            self._prune()
        sid = int(entry.get("server_id") or LOCAL_SERVER_ID)
        site = entry.get("site") or ""
        ts = entry.get("ts")
        t = ts.timestamp() if isinstance(ts, datetime) else 0.0
        base = {"server_id": sid, "site": site, "site_name": entry.get("site_name") or "", "ts": ts,
                "status": status, "substatus": int(entry.get("sc_substatus") or 0),
                "win32": int(entry.get("sc_win32_status") or 0), "uri": stem, "method": entry.get("cs_method") or "",
                "query": (entry.get("cs_uri_query") or "")[:300], "ip": entry.get("c_ip") or "", "time_taken": tt}
        events: list[dict[str, Any]] = []

        if is_err:
            cooldown = 60 * float(val("alerts", "http_error_cooldown_minutes", 10))
            rolled = self._roll(("err", sid, site, status, lowered), t, cooldown)
            if rolled is not None:
                events.append({**base, "kind": "http_error", "repeats": rolled, "cooldown_minutes": cooldown / 60})
            window = 60 * float(val("alerts", "http_error_burst_window_minutes", 5))
            q = self._errors[(sid, site)]
            q.append((t, status, stem))
            while q and t - q[0][0] > window:
                q.popleft()
            if len(q) >= int(val("alerts", "http_error_burst_threshold", 10)) and self._burst_ready(("errb", sid, site), t, window):
                events.append({**base, "kind": "http_error_burst", "count": len(q), "window_minutes": window / 60,
                               "statuses": dict(Counter(s for _t, s, _u in q).most_common(5)),
                               "top_uris": [u for u, _n in Counter(u for _t, _s, u in q).most_common(5)]})
        elif is_watch:
            cooldown = 60 * float(val("alerts", "watched_status_cooldown_minutes", 15))
            rolled = self._roll(("watch", sid, site, status), t, cooldown)
            if rolled is not None:
                events.append({**base, "kind": "status_watch", "repeats": rolled, "cooldown_minutes": cooldown / 60})

        if is_slow:
            window = 60 * float(val("alerts", "slow_response_window_minutes", 5))
            q = self._slow[(sid, site)]
            q.append((t, tt, stem))
            while q and t - q[0][0] > window:
                q.popleft()
            if len(q) >= int(val("alerts", "slow_response_threshold", 5)) and self._burst_ready(("slow", sid, site), t, window):
                worst = sorted(q, key=lambda x: x[1], reverse=True)[:5]
                events.append({**base, "kind": "slow", "count": len(q), "window_minutes": window / 60, "threshold_ms": slow_ms,
                               "worst": [{"uri": u, "ms": ms} for _t, ms, u in worst],
                               "avg_ms": round(sum(ms for _t, ms, _u in q) / len(q))})
        return events

    def _prune(self) -> None:
        newest = max((rec[0] for rec in self._rollup.values()), default=0.0)
        cutoff = newest - 86400
        self._rollup = {k: v for k, v in self._rollup.items() if v[0] >= cutoff}
        self._burst_at = {k: v for k, v in self._burst_at.items() if v >= cutoff}
        for store in (self._errors, self._slow):
            for key in [k for k, q in store.items() if not q or q[-1][0] < cutoff]:
                del store[key]

    def forget_server(self, server_id: int) -> None:
        for store in (self._errors, self._slow):
            for key in [k for k in store if k[0] == server_id]:
                del store[key]
        self._rollup = {k: v for k, v in self._rollup.items() if k[1] != server_id}
        self._burst_at = {k: v for k, v in self._burst_at.items() if k[1] != server_id}
