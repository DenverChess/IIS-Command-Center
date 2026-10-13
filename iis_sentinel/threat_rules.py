"""Signature + behaviour threat detection and per-IP threat scoring.

Scoring (per source IP, decays with a configurable half-life):
    +10  SQL injection signature           +10  XSS signature
    +10  path traversal / LFI signature    +5   known scanner user-agent
    +5   404 spike within the spike window +5   401/403 spike within the spike window
    +20  Z-score volume/bandwidth anomaly (reported by baseliner)
Score above `threat_score_threshold` (default 50) flags the IP as an ACTIVE THREAT.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import re
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

from database import ConfigStore

SCORE_SQLI = 10
SCORE_XSS = 10
SCORE_TRAVERSAL = 10
SCORE_SCANNER = 5
SCORE_404_SPIKE = 5
SCORE_AUTH_SPIKE = 5
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

_GEO_POOL = [
    ("US", "Ashburn"), ("US", "Dallas"), ("US", "San Jose"), ("CN", "Shanghai"), ("CN", "Beijing"),
    ("RU", "Moscow"), ("RU", "St Petersburg"), ("DE", "Frankfurt"), ("NL", "Amsterdam"), ("GB", "London"),
    ("FR", "Paris"), ("BR", "Sao Paulo"), ("IN", "Mumbai"), ("SG", "Singapore"), ("KR", "Seoul"),
    ("JP", "Tokyo"), ("VN", "Hanoi"), ("IR", "Tehran"), ("UA", "Kyiv"), ("RO", "Bucharest"),
    ("TR", "Istanbul"), ("ID", "Jakarta"), ("ZA", "Johannesburg"), ("CA", "Toronto"), ("AU", "Sydney"),
]


def simulate_geo(ip: str) -> str:
    """Deterministic pseudo-geolocation (no external GeoIP DB). Private/reserved ranges are labelled as such."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "??"
    if addr.is_loopback:
        return "LOCALHOST"
    if addr.is_private or addr.is_link_local:
        return "LAN / INTERNAL"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "RESERVED"
    idx = int(hashlib.sha1(ip.encode()).hexdigest()[:8], 16) % len(_GEO_POOL)
    cc, city = _GEO_POOL[idx]
    return f"{cc} / {city}"


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
    active: bool = False
    peak_score: float = 0.0

    def to_dict(self, threshold: float) -> dict[str, Any]:
        now = time.time()
        return {
            "ip": self.ip,
            "geo": self.geo,
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

    def __init__(self, config: ConfigStore) -> None:
        self.config = config
        self._ips: dict[str, IPState] = {}
        self.total_attacks = 0

    # ------------------------------------------------------------------ helpers
    def _cfg(self) -> dict[str, Any]:
        return self.config.get("watchers")

    def _state(self, ip: str) -> IPState:
        st = self._ips.get(ip)
        if st is None:
            if len(self._ips) >= self.MAX_TRACKED:
                self.prune(force=True)
            st = IPState(ip=ip, geo=simulate_geo(ip))
            self._ips[ip] = st
        return st

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
            return [{"kind": "active_threat", "ip": st.ip, "state": st.to_dict(threshold)}]
        if st.active and st.score < threshold * 0.6:
            st.active = False
            return [{"kind": "threat_cleared", "ip": st.ip, "state": st.to_dict(threshold)}]
        return []

    # ------------------------------------------------------------------ public API
    def inspect(self, entry: dict[str, Any]) -> Inspection:
        cfg = self._cfg()
        now = time.time()
        ip = entry.get("c_ip") or "0.0.0.0"
        st = self._state(ip)
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
            events.append({"kind": "spike", "ip": ip, "spike": "404", "count": len(st.w404), "window": window})
        if status in (401, 403) and len(st.wauth) >= int(cfg["spike_auth_threshold"]) and log_t - st.last_auth_spike >= window:
            st.last_auth_spike = log_t
            tags.append("AUTH_SPIKE")
            delta += SCORE_AUTH_SPIKE
            events.append({"kind": "spike", "ip": ip, "spike": "401/403", "count": len(st.wauth), "window": window})

        if tags:
            st.last_attack = now
            st.attack_hits += 1
            st.tags.update(tags)
            raw = f"{entry.get('cs_method', '')} {stem}{('?' + query) if query else ''}"
            st.last_payload = raw[:240]
            signature_tags = [t for t in tags if t in ("SQLI", "XSS", "TRAVERSAL", "SCANNER")]
            if signature_tags:
                self.total_attacks += 1
                events.append({"kind": "signature", "ip": ip, "tags": signature_tags, "payload": raw[:500], "status": status})
            events.extend(self._add(st, delta, cfg))
        else:
            events.extend(self._check_escalation(st, cfg))
        return Inspection(tags=tags, delta=delta, events=events)

    def apply_anomaly(self, ip: str, metric: str, zscore: float) -> tuple[int, list[dict[str, Any]]]:
        cfg = self._cfg()
        st = self._state(ip)
        now = time.time()
        self._decay(st, now, float(cfg["threat_half_life_minutes"]))
        st.last_attack = now
        tag = "ZSCORE_VOLUME" if metric == "rpm" else "ZSCORE_BANDWIDTH"
        st.tags.update([tag])
        st.last_payload = st.last_payload or f"[{tag}] z={zscore:.1f}"
        return SCORE_ZSCORE, self._add(st, SCORE_ZSCORE, cfg)

    def active_threats(self, limit: int = 50, min_score: float = 5.0) -> list[dict[str, Any]]:
        cfg = self._cfg()
        threshold = float(cfg["threat_score_threshold"])
        now = time.time()
        half_life = float(cfg["threat_half_life_minutes"])
        out = []
        for st in self._ips.values():
            if st.score <= 0 and not st.active:
                continue
            self._decay(st, now, half_life)
            if st.score >= min_score or st.active:
                out.append(st.to_dict(threshold))
        out.sort(key=lambda d: (d["active"], d["score"]), reverse=True)
        return out[:limit]

    def ip_detail(self, ip: str) -> dict[str, Any] | None:
        st = self._ips.get(ip)
        return st.to_dict(float(self._cfg()["threat_score_threshold"])) if st else None

    def counts(self) -> dict[str, int]:
        active = sum(1 for s in self._ips.values() if s.active)
        return {"tracked_ips": len(self._ips), "active_threats": active, "attacks_detected": self.total_attacks}

    def prune(self, force: bool = False) -> int:
        now = time.time()
        idle = 600 if force else 3600
        stale = [ip for ip, s in self._ips.items() if not s.active and s.score < 1 and now - s.last_seen > idle]
        if force and len(stale) < len(self._ips) // 10:
            by_age = sorted(self._ips.values(), key=lambda s: s.last_seen)
            stale = [s.ip for s in by_age[: len(self._ips) // 5] if not s.active]
        for ip in stale:
            del self._ips[ip]
        return len(stale)
