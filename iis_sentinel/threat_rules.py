"""Signature + behaviour threat detection and per-(server, source IP) threat scoring.

An attacker hitting IIS-01 and IIS-02 is tracked independently on each server, so a ban is executed on the
server that is actually under attack. Scoring (decays with a configurable half-life):
    +10  SQL injection signature           +10  XSS signature
    +10  path traversal / LFI signature    +5   known scanner user-agent
    +5   404 spike within the spike window +5   401/403 spike within the spike window
    +5   directory enumeration (distinct 404 paths >= enum_404_threshold within enum_404_window_minutes)
    +20  Z-score volume/bandwidth anomaly (reported by baseliner)
Score above `threat_score_threshold` (default 50) flags the IP as an ACTIVE THREAT.
"""
from __future__ import annotations

import html
import re
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from urllib.parse import unquote_plus

from database import LOCAL_SERVER_ID, ConfigStore
from geoip import special_label

SCORE_SQLI = 10
SCORE_XSS = 10
SCORE_TRAVERSAL = 10
SCORE_SCANNER = 5
SCORE_404_SPIKE = 5
SCORE_AUTH_SPIKE = 5
SCORE_DIR_ENUM = 5
SCORE_ZSCORE = 20
MAX_SCORE_FACTOR = 4

_F = re.IGNORECASE | re.DOTALL

SQLI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, _F)
    for p in (
        r"\bunion(\s|/\*[\s\S]*?\*/)+((all|distinct)(\s|/\*[\s\S]*?\*/)+)?select\b",
        r"\bselect\b[\s\S]{1,200}?\bfrom\b[\s\S]{1,100}?\b(information_schema|sys\.|sysobjects|syscolumns|mysql\.|pg_catalog|dual)\b",
        r"['\"`)]\s*(or|and)\s+['\"`(]?\s*\w+\s*['\"`)]?\s*(=|<|>|like)\s*['\"`(]?\s*\w+",
        r"['\"`]\s*(or|and)\s+\d+\s*=\s*\d+",
        r"\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)",
        r"['\"`]\s*;\s*(drop|delete|insert|update|exec|execute|shutdown|truncate|alter|create)\b",
        r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d",
        r"\bwaitfor\s+delay\s+['\"]",
        r"\bxp_cmdshell\b|\bsp_executesql\b|\bsp_oacreate\b",
        r"@@(version|servername|datadir)\b",
        r"\b(cast|convert)\s*\([\s\S]{0,60}?\bas\b\s*(n?varchar|int|char)",
        r"\b(concat|group_concat|char|nchar|chr)\s*\(\s*(0x[0-9a-f]+|\d+\s*,)",
        r"\border\s+by\s+\d+\s*(--|#|/\*)",
        r"\b(extractvalue|updatexml)\s*\(",
        r"\bload_file\s*\(|\binto\s+(out|dump)file\b",
        r"/\*![0-9]{0,5}|'\s*--\s*$|'\s*#\s*$",
        r"\bdeclare\s+@\w+\s",
    )
]

XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, _F)
    for p in (
        r"<\s*script\b",
        r"<\s*/\s*script\s*>",
        r"\bjavascript\s*:",
        r"\bvbscript\s*:",
        r"\bon(error|load|mouseover|focus|click|mouseenter|toggle|animationstart|pointerover|begin)\s*=",
        r"<\s*(iframe|frame|object|embed|svg|math|base|link|meta|style)\b",
        r"<\s*img\b[^>]*\bsrc\s*=",
        r"\bdocument\s*\.\s*(cookie|domain|write|location)",
        r"\b(alert|prompt|confirm)\s*[(`]",
        r"\beval\s*\(|\bstring\s*\.\s*fromcharcode\b",
        r"\bdata\s*:\s*text/html",
        r"\bsrcdoc\s*=",
    )
]

TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, _F)
    for p in (
        r"(\.\.[/\\]){2,}",
        r"\b(etc/passwd|etc/shadow|win\.ini|boot\.ini|system32[/\\]config)\b",
        r"\bcmd\.exe\b|\bpowershell(\.exe)?\s+-\w+",
        r"\.\./.*\.(config|ini|log|bak)\b",
        r"\bweb\.config\b.*\.\.",
        r"\$\{jndi:",
    )
]

SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|acunetix|netsparker|nessus|openvas|wpscan|dirbuster|gobuster|"
    r"feroxbuster|nuclei|zgrab|havij|w3af|arachni|burp|zap/|commix|whatweb|jaeles|xsstrike",
    re.IGNORECASE,
)

# 404s every browser produces on its own; they never count towards directory enumeration.
BENIGN_404 = re.compile(
    r"^/(favicon\.ico|robots\.txt|apple-touch-icon[^/]*\.png|sitemap[^/]*\.xml|browserconfig\.xml|ads\.txt|"
    r"crossdomain\.xml|\.well-known/.*)$",
    re.IGNORECASE,
)
ENUM_MAX_URIS = 50


def normalize_payload(*parts: str) -> str:
    """Decode the request the way an app would see it, defeating double URL / HTML-entity encoding tricks."""
    text = " ".join(p for p in parts if p)[:8192]
    for _ in range(3):
        decoded = html.unescape(unquote_plus(text))
        if decoded == text:
            break
        text = decoded
    return text.replace("\x00", "")


def _match_any(patterns: list[re.Pattern[str]], text: str) -> bool:
    return any(p.search(text) for p in patterns)


@dataclass
class IPState:
    ip: str
    geo: str
    server_id: int = LOCAL_SERVER_ID
    server_name: str = ""
    score: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_attack: float = 0.0
    last_decay: float = field(default_factory=time.time)
    requests: int = 0
    attack_hits: int = 0
    tags: Counter[str] = field(default_factory=Counter)
    last_payload: str = ""
    last_status: int = 0
    w404: deque[float] = field(default_factory=deque)
    wauth: deque[float] = field(default_factory=deque)
    last_404_spike: float = 0.0
    last_auth_spike: float = 0.0
    enum404: deque[tuple[float, str]] = field(default_factory=deque)
    last_enum: float = 0.0
    active: bool = False
    peak_score: float = 0.0

    def to_dict(self, threshold: float) -> dict[str, Any]:
        now = time.time()
        return {
            "key": f"{self.server_id}|{self.ip}",
            "ip": self.ip,
            "geo": self.geo,
            "server_id": self.server_id,
            "server_name": self.server_name,
            "score": round(self.score, 1),
            "peak_score": round(self.peak_score, 1),
            "threshold": threshold,
            "status": "ACTIVE THREAT" if self.active else ("SUSPICIOUS" if self.score >= 10 else "WATCH"),
            "active": self.active,
            "attacking": now - self.last_attack < 20,
            "requests": self.requests,
            "attack_hits": self.attack_hits,
            "tags": dict(self.tags.most_common(6)),
            "last_payload": self.last_payload,
            "last_status": self.last_status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Inspection:
    tags: list[str]
    delta: int
    events: list[dict[str, Any]]


class ThreatEngine:
    MAX_TRACKED = 50000

    def __init__(self, config: ConfigStore, server_name: Callable[[int], str] | None = None,
                 geo: Callable[[str], str] | None = None) -> None:
        self.config = config
        self._server_name = server_name or (lambda sid: f"SRV-{sid}")
        self._geo = geo or (lambda ip: special_label(ip) or "")
        self._ips: dict[tuple[int, str], IPState] = {}
        self.total_attacks = 0

    # ------------------------------------------------------------------ helpers
    def _cfg(self) -> dict[str, Any]:
        return self.config.get("watchers")

    def _state(self, server_id: int, ip: str) -> IPState:
        key = (server_id, ip)
        st = self._ips.get(key)
        if st is None:
            if len(self._ips) >= self.MAX_TRACKED:
                self.prune(force=True)
            st = IPState(ip=ip, geo=self._geo(ip), server_id=server_id, server_name=self._server_name(server_id))
            self._ips[key] = st
        return st

    @staticmethod
    def _event(st: IPState, **kw: Any) -> dict[str, Any]:
        return {"ip": st.ip, "server_id": st.server_id, "server_name": st.server_name, **kw}

    def _decay(self, st: IPState, now: float, half_life_min: float) -> None:
        elapsed = now - st.last_decay
        if elapsed > 1 and st.score > 0:
            st.score *= 0.5 ** (elapsed / (half_life_min * 60.0))
            if st.score < 0.5:
                st.score = 0.0
        st.last_decay = now

    def _add(self, st: IPState, points: float, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        # Capped so a finished attack decays back below the threshold in a bounded time.
        st.score = min(st.score + points, float(cfg["threat_score_threshold"]) * MAX_SCORE_FACTOR)
        st.peak_score = max(st.peak_score, st.score)
        return self._check_escalation(st, cfg)

    def _check_escalation(self, st: IPState, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        threshold = float(cfg["threat_score_threshold"])
        if not st.active and st.score > threshold:
            st.active = True
            return [self._event(st, kind="active_threat", state=st.to_dict(threshold))]
        if st.active and st.score < threshold * 0.6:
            st.active = False
            return [self._event(st, kind="threat_cleared", state=st.to_dict(threshold))]
        return []

    # ------------------------------------------------------------------ public API
    def inspect(self, entry: dict[str, Any]) -> Inspection:
        cfg = self._cfg()
        now = time.time()
        ip = entry.get("c_ip") or "0.0.0.0"
        st = self._state(int(entry.get("server_id") or LOCAL_SERVER_ID), ip)
        self._decay(st, now, float(cfg["threat_half_life_minutes"]))
        st.requests += 1
        st.last_seen = now
        status = int(entry.get("sc_status") or 0)
        st.last_status = status

        stem = entry.get("cs_uri_stem") or ""
        query = entry.get("cs_uri_query") or ""
        ua = entry.get("user_agent") or ""
        payload = normalize_payload(stem, query)

        tags: list[str] = []
        delta = 0
        if _match_any(SQLI_PATTERNS, payload):
            tags.append("SQLI")
            delta += SCORE_SQLI
        if _match_any(XSS_PATTERNS, payload) or _match_any(XSS_PATTERNS, normalize_payload(ua)):
            tags.append("XSS")
            delta += SCORE_XSS
        if _match_any(TRAVERSAL_PATTERNS, payload):
            tags.append("TRAVERSAL")
            delta += SCORE_TRAVERSAL
        if SCANNER_UA.search(ua):
            tags.append("SCANNER")
            delta += SCORE_SCANNER

        events: list[dict[str, Any]] = []
        ts = entry.get("ts")
        log_t = ts.timestamp() if isinstance(ts, datetime) else now
        window = float(cfg["spike_window_seconds"])

        if status == 404:
            st.w404.append(log_t)
        elif status in (401, 403):
            st.wauth.append(log_t)
        while st.w404 and log_t - st.w404[0] > window:
            st.w404.popleft()
        while st.wauth and log_t - st.wauth[0] > window:
            st.wauth.popleft()

        if status == 404 and len(st.w404) >= int(cfg["spike_404_threshold"]) and log_t - st.last_404_spike >= window:
            st.last_404_spike = log_t
            tags.append("404_SPIKE")
            delta += SCORE_404_SPIKE
            events.append(self._event(st, kind="spike", spike="404", count=len(st.w404), window=window))
        if status in (401, 403) and len(st.wauth) >= int(cfg["spike_auth_threshold"]) and log_t - st.last_auth_spike >= window:
            st.last_auth_spike = log_t
            tags.append("AUTH_SPIKE")
            delta += SCORE_AUTH_SPIKE
            events.append(self._event(st, kind="spike", spike="401/403", count=len(st.wauth), window=window))
        enum = self._enumeration(st, status, stem, log_t, cfg)
        if enum:
            tags.append("DIR_ENUM")
            delta += SCORE_DIR_ENUM
            events.append(enum)

        if tags:
            st.last_attack = now
            st.attack_hits += 1
            st.tags.update(tags)
            raw = f"{entry.get('cs_method', '')} {stem}{('?' + query) if query else ''}"
            st.last_payload = raw[:240]
            signature_tags = [t for t in tags if t in ("SQLI", "XSS", "TRAVERSAL", "SCANNER")]
            if signature_tags:
                self.total_attacks += 1
                events.append(self._event(st, kind="signature", tags=signature_tags, payload=raw[:500], status=status))
            events.extend(self._add(st, delta, cfg))
        else:
            events.extend(self._check_escalation(st, cfg))
        return Inspection(tags=tags, delta=delta, events=events)

    def _enumeration(self, st: IPState, status: int, stem: str, log_t: float, cfg: dict[str, Any]) -> dict[str, Any] | None:
        window = float(cfg.get("enum_404_window_minutes", 5)) * 60.0
        if status == 404 and stem and not BENIGN_404.match(stem):
            st.enum404.append((log_t, stem[:300]))
            if len(st.enum404) > ENUM_MAX_URIS * 4:
                st.enum404.popleft()
        while st.enum404 and log_t - st.enum404[0][0] > window:
            st.enum404.popleft()
        if status != 404 or log_t - st.last_enum < window:
            return None
        uris = list(dict.fromkeys(u for _, u in st.enum404))
        if len(uris) < int(cfg.get("enum_404_threshold", 3)):
            return None
        st.last_enum = log_t
        return self._event(st, kind="dir_enum", count=len(st.enum404), distinct=len(uris), uris=uris[-ENUM_MAX_URIS:],
                           window_minutes=window / 60.0)

    def export_enum(self) -> dict[str, Any]:
        """404 enumeration counters, persisted every 60s so a restart does not reset an in-progress scan."""
        out: dict[str, Any] = {}
        for (sid, ip), st in self._ips.items():
            if st.enum404 or st.last_enum:
                out[f"{sid}|{ip}"] = {"hits": [[t, u] for t, u in st.enum404], "last": st.last_enum}
        return out

    def import_enum(self, data: dict[str, Any], max_age: float = 3600.0) -> int:
        now = time.time()
        n = 0
        for key, rec in (data or {}).items():
            try:
                sid_s, ip = key.split("|", 1)
                hits = [(float(t), str(u)) for t, u in rec.get("hits", []) if now - float(t) <= max_age]
                last = float(rec.get("last") or 0.0)
            except (ValueError, TypeError, AttributeError):
                continue
            if not hits and now - last > max_age:
                continue
            st = self._state(int(sid_s), ip)
            known = set(st.enum404)
            st.enum404.extend(h for h in hits if h not in known)
            st.enum404 = deque(sorted(st.enum404)[-ENUM_MAX_URIS * 4:])
            st.last_enum = max(st.last_enum, last)
            n += 1
        return n

    def apply_anomaly(self, server_id: int, ip: str, metric: str, zscore: float) -> tuple[int, list[dict[str, Any]]]:
        cfg = self._cfg()
        st = self._state(server_id, ip)
        now = time.time()
        self._decay(st, now, float(cfg["threat_half_life_minutes"]))
        st.last_attack = now
        tag = "ZSCORE_VOLUME" if metric == "rpm" else "ZSCORE_BANDWIDTH"
        st.tags.update([tag])
        st.last_payload = st.last_payload or f"[{tag}] z={zscore:.1f}"
        return SCORE_ZSCORE, self._add(st, SCORE_ZSCORE, cfg)

    def active_threats(self, limit: int = 50, min_score: float = 5.0, server_id: int | None = None) -> list[dict[str, Any]]:
        cfg = self._cfg()
        threshold = float(cfg["threat_score_threshold"])
        now = time.time()
        half_life = float(cfg["threat_half_life_minutes"])
        out = []
        for st in self._ips.values():
            if server_id is not None and st.server_id != server_id:
                continue
            if st.score <= 0 and not st.active:
                continue
            self._decay(st, now, half_life)
            if st.score >= min_score or st.active:
                out.append(st.to_dict(threshold))
        out.sort(key=lambda d: (d["active"], d["score"]), reverse=True)
        return out[:limit]

    def ip_detail(self, ip: str, server_id: int | None = None) -> dict[str, Any] | None:
        threshold = float(self._cfg()["threat_score_threshold"])
        if server_id is not None:
            st = self._ips.get((server_id, ip))
            return st.to_dict(threshold) if st else None
        matches = [st for (sid, sip), st in self._ips.items() if sip == ip]
        if not matches:
            return None
        best = max(matches, key=lambda s: s.score)
        out = best.to_dict(threshold)
        out["servers"] = [s.to_dict(threshold) for s in sorted(matches, key=lambda s: s.score, reverse=True)]
        return out

    def missing_geo(self, limit: int = 50) -> list[str]:
        """IPs shown in the threat matrix whose location is still unknown, highest score first."""
        out: list[str] = []
        for st in sorted(self._ips.values(), key=lambda s: s.score, reverse=True):
            if st.score <= 0 and not st.active:
                break
            if not st.geo and st.ip not in out:
                out.append(st.ip)
                if len(out) >= limit:
                    break
        return out

    def set_geo(self, ip: str, geo: str) -> None:
        for st in self._ips.values():
            if st.ip == ip:
                st.geo = geo

    def refresh_geo(self) -> None:
        for st in self._ips.values():
            st.geo = self._geo(st.ip)

    def rename_server(self, server_id: int, name: str) -> None:
        for st in self._ips.values():
            if st.server_id == server_id:
                st.server_name = name

    def server_ids(self) -> set[int]:
        return {k[0] for k in self._ips}

    def forget_server(self, server_id: int) -> None:
        for key in [k for k in self._ips if k[0] == server_id]:
            del self._ips[key]

    def clear(self, server_id: int, ip: str) -> None:
        """Reset scoring after a ban so the IP drops off the pending list."""
        st = self._ips.get((server_id, ip))
        if st:
            st.score = 0.0
            st.active = False

    def counts(self) -> dict[str, int]:
        active = sum(1 for s in self._ips.values() if s.active)
        return {"tracked_ips": len(self._ips), "active_threats": active, "attacks_detected": self.total_attacks}

    def prune(self, force: bool = False) -> int:
        now = time.time()
        idle = 600 if force else 3600
        stale = [k for k, s in self._ips.items() if not s.active and s.score < 1 and now - s.last_seen > idle]
        if force and len(stale) < len(self._ips) // 10:
            by_age = sorted(self._ips.items(), key=lambda kv: kv[1].last_seen)
            stale = [k for k, s in by_age[: len(self._ips) // 5] if not s.active]
        for k in stale:
            del self._ips[k]
        return len(stale)
