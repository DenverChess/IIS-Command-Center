"""WHOIS for client IPs via RDAP (the JSON successor to port-43 WHOIS), plus reverse DNS.

rdap.org redirects each query to the authoritative registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Results
are cached; private / reserved addresses are answered locally without any network call. Every failure
(no internet, proxy, registry rate limit) comes back as an `error` field rather than an exception.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import time
from typing import Any

log = logging.getLogger("sentinel.whois")

RDAP_URL = "https://rdap.org/ip/{ip}"
CACHE_TTL = 6 * 3600
ERROR_TTL = 300
CACHE_MAX = 2000

_SPECIAL_NETS = [
    ("10.0.0.0/8", "RFC 1918 private network"),
    ("172.16.0.0/12", "RFC 1918 private network"),
    ("192.168.0.0/16", "RFC 1918 private network"),
    ("100.64.0.0/10", "RFC 6598 carrier-grade NAT"),
    ("127.0.0.0/8", "Loopback"),
    ("169.254.0.0/16", "Link-local (APIPA)"),
    ("fc00::/7", "IPv6 unique local address"),
    ("fe80::/10", "IPv6 link-local"),
    ("::1/128", "IPv6 loopback"),
]


def _vcard(entity: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    arr = entity.get("vcardArray")
    if not (isinstance(arr, list) and len(arr) > 1 and isinstance(arr[1], list)):
        return out
    for prop in arr[1]:
        if not (isinstance(prop, list) and len(prop) >= 4):
            continue
        name, params, value = prop[0], prop[1] if isinstance(prop[1], dict) else {}, prop[3]
        if name == "fn" and value:
            out["name"] = str(value)
        elif name == "org" and value:
            out["org"] = str(value[0] if isinstance(value, list) else value)
        elif name == "kind":
            out["kind"] = str(value)
        elif name == "email" and value:
            out.setdefault("email", str(value))
        elif name == "tel" and value:
            out.setdefault("phone", str(value).replace("tel:", ""))
        elif name == "adr":
            label = params.get("label")
            if label:
                out["address"] = " ".join(str(label).split())
            elif isinstance(value, list):
                parts = [p if isinstance(p, str) else " ".join(map(str, p)) for p in value]
                out["address"] = ", ".join(p for p in parts if p)
    return out


def _flatten_entities(entities: list[dict[str, Any]] | None, depth: int = 0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        card = _vcard(ent)
        out.append({"handle": ent.get("handle"), "roles": list(ent.get("roles") or []), **card})
        if depth < 3:
            out.extend(_flatten_entities(ent.get("entities"), depth + 1))
    return out


def _rir(data: dict[str, Any]) -> str:
    port43 = str(data.get("port43") or "").lower()
    for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
        if rir in port43:
            return rir.upper()
    for link in data.get("links") or []:
        href = str(link.get("href") or "").lower() if isinstance(link, dict) else ""
        for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
            if rir in href:
                return rir.upper()
    return ""


def parse_rdap(data: dict[str, Any]) -> dict[str, Any]:
    entities = _flatten_entities(data.get("entities"))

    def first(role: str, key: str) -> str | None:
        for e in entities:
            if role in e["roles"] and e.get(key):
                return str(e[key])
        return None

    cidrs = []
    for c in data.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        if prefix and c.get("length") is not None:
            cidrs.append(f"{prefix}/{c['length']}")
    events = {str(e.get("eventAction")): str(e.get("eventDate")) for e in data.get("events") or [] if isinstance(e, dict)}
    remarks = []
    for r in data.get("remarks") or []:
        if isinstance(r, dict):
            text = " ".join(str(d) for d in r.get("description") or [])
            if text:
                remarks.append(((r.get("title") + ": ") if r.get("title") else "") + text)
    origin_as = data.get("arin_originas0_originautnums") or []
    org = first("registrant", "org") or first("registrant", "name") or next((e.get("name") for e in entities if e.get("name")), None)
    return {
        "handle": data.get("handle"),
        "network_name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "cidr": cidrs,
        "parent_handle": data.get("parentHandle"),
        "status": list(data.get("status") or []),
        "registry": _rir(data),
        "organization": org,
        "abuse_email": first("abuse", "email"),
        "abuse_phone": first("abuse", "phone"),
        "registrant_address": first("registrant", "address"),
        "origin_as": [f"AS{a}" for a in origin_as],
        "registered": events.get("registration"),
        "last_changed": events.get("last changed"),
        "remarks": remarks[:6],
        "entities": [e for e in entities if e.get("name") or e.get("email")][:12],
    }


def _special(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    for net, label in _SPECIAL_NETS:
        try:
            if addr in ipaddress.ip_network(net):
                return f"{label} ({net})"
        except TypeError:
            continue
    if addr.is_multicast:
        return "Multicast address"
    if addr.is_unspecified:
        return "Unspecified address"
    if addr.is_reserved or not addr.is_global:
        return "Reserved / non-routable address"
    return None


def _fetch_rdap(ip: str, timeout: float) -> dict[str, Any]:
    import requests

    resp = requests.get(RDAP_URL.format(ip=ip), headers={"Accept": "application/rdap+json, application/json",
                                                         "User-Agent": "IIS-Sentinel/2.1 (+rdap)"},
                        timeout=(5, timeout), allow_redirects=True)
    if resp.status_code == 404:
        raise LookupError("no registry record for this address")
    if resp.status_code == 429:
        raise LookupError("the registry is rate-limiting lookups; try again in a minute")
    resp.raise_for_status()
    data = resp.json()
    result = parse_rdap(data)
    result["source_url"] = resp.url
    return result


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


class WhoisClient:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._inflight: dict[str, asyncio.Future[dict[str, Any]]] = {}

    async def lookup(self, ip: str, refresh: bool = False) -> dict[str, Any]:
        addr = ipaddress.ip_address(ip.strip())
        key = str(addr)
        cached = self._cache.get(key)
        if cached and not refresh and cached[0] > time.time():
            return {**cached[1], "cached": True}
        pending = self._inflight.get(key)
        if pending is not None:
            return await asyncio.shield(pending)
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._inflight[key] = fut
        try:
            result = await self._lookup(addr)
            fut.set_result(result)
            ttl = ERROR_TTL if result.get("error") else CACHE_TTL
            if len(self._cache) >= CACHE_MAX:
                now = time.time()
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= CACHE_MAX:
                    self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (time.time() + ttl, result)
            return result
        except BaseException as exc:
            if not fut.done():
                fut.set_exception(exc)
                fut.exception()
            raise
        finally:
            self._inflight.pop(key, None)

    async def _lookup(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, Any]:
        ip = str(addr)
        result: dict[str, Any] = {"ip": ip, "version": addr.version, "looked_up_at": time.time()}
        rdns_task = asyncio.create_task(asyncio.wait_for(asyncio.to_thread(_reverse_dns, ip), timeout=4))
        special = _special(addr)
        if special:
            result.update({"scope": "private", "network_name": special,
                           "summary": f"{special}: not registered in public WHOIS; this client is on an internal or reserved network."})
        else:
            result["scope"] = "public"
            try:
                result.update(await asyncio.wait_for(asyncio.to_thread(_fetch_rdap, ip, self.timeout), timeout=self.timeout + 8))
            except asyncio.TimeoutError:
                result["error"] = "WHOIS registry did not answer in time (is outbound HTTPS to rdap.org allowed?)"
            except LookupError as exc:
                result["error"] = str(exc)
            except Exception as exc:  # noqa: BLE001
                name = type(exc).__name__
                hint = " (no internet access from the Sentinel host?)" if "Connection" in name or "Timeout" in name else ""
                result["error"] = f"WHOIS lookup failed: {name}: {str(exc)[:200]}{hint}"
                log.warning("RDAP lookup for %s failed: %s", ip, result["error"])
            if not result.get("error"):
                bits = [result.get("organization") or result.get("network_name"), result.get("country"), result.get("registry")]
                result["summary"] = " / ".join(str(b) for b in bits if b)
        try:
            result["reverse_dns"] = await rdns_task
        except Exception:  # noqa: BLE001
            result["reverse_dns"] = None
        result["cidr_range"] = registry_cidr(addr, result)
        return result

    async def enrich_ip(self, ip: str, timeout: float = 8.0) -> dict[str, Any]:
        """WHOIS for the ban dialog. Never raises: a failed or slow lookup returns {'error': ...}."""
        try:
            data = await asyncio.wait_for(self.lookup(ip), timeout=timeout)
        except asyncio.TimeoutError:
            return {"ip": ip, "error": "WHOIS registry did not answer in time", "cidr_range": None}
        except Exception as exc:  # noqa: BLE001
            return {"ip": ip, "error": f"WHOIS lookup failed: {type(exc).__name__}", "cidr_range": None}
        if "cidr_range" not in data:
            try:
                data = {**data, "cidr_range": registry_cidr(ipaddress.ip_address(ip), data)}
            except ValueError:
                data = {**data, "cidr_range": None}
        return data


def registry_cidr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, whois: dict[str, Any]) -> str | None:
    """Most specific registry-allocated block that contains `addr` (from the RDAP cidr list or start/end range)."""
    nets: list[Any] = []
    for c in whois.get("cidr") or []:
        try:
            nets.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    start, end = whois.get("start_address"), whois.get("end_address")
    if not nets and start and end:
        try:
            nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
        except (ValueError, TypeError):
            nets = []
    inside = [n for n in nets if n.version == addr.version and addr in n]
    return str(max(inside, key=lambda n: n.prefixlen)) if inside else None


# --------------------------------------------------------------------------------------
# Subnet escalation: how wide should a ban be?
# --------------------------------------------------------------------------------------
# (single, subnet, large subnet) prefix per IP version. /8 (or an IPv6 /32) is never recommended.
SCOPE_TIERS = {4: (32, 24, 16), 6: (128, 64, 48)}
SUBNET_WINDOW = 3600
LARGE_WINDOW = 24 * 3600
SUBNET_MIN_OTHER_IPS = 2
LARGE_MIN_OTHER_IPS = 3


def scope_options(ip: str) -> list[dict[str, Any]]:
    addr = ipaddress.ip_address(ip)
    labels = ("Single IP", "Subnet", "Large Subnet")
    out = []
    for tier, (label, prefix) in enumerate(zip(labels, SCOPE_TIERS[addr.version])):
        net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        out.append({"tier": ("single", "subnet", "large")[tier], "label": label, "scope": f"/{prefix}",
                    "cidr": str(net), "size": net.num_addresses})
    return out


def network_for_scope(ip: str, scope: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """'/24' (or a tier name: single / subnet / large) applied to `ip`. Only the three tiers are allowed."""
    addr = ipaddress.ip_address(ip)
    tiers = SCOPE_TIERS[addr.version]
    named = {"single": tiers[0], "subnet": tiers[1], "large": tiers[2]}
    s = str(scope).strip().lower()
    if s in named:
        prefix = named[s]
    else:
        try:
            prefix = int(s.lstrip("/"))
        except ValueError as exc:
            raise ValueError(f"scope must be one of {', '.join('/' + str(t) for t in tiers)}") from exc
        v4 = SCOPE_TIERS[4]
        # The UI's IPv4 scope names map to the same tier on an IPv6 address (/32 -> /128, /24 -> /64, /16 -> /48).
        if addr.version == 6 and prefix in v4 and prefix not in tiers:
            prefix = tiers[v4.index(prefix)]
        if prefix not in tiers:
            raise ValueError(f"scope must be one of {', '.join('/' + str(t) for t in tiers)}")
    return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)


def _fmt_age(seconds: float) -> str:
    minutes = max(1, int(round(seconds / 60)))
    if minutes < 120:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{minutes // 60} hours"


async def calculate_escalation_cidr(ip_address: str, now: Any = None) -> dict[str, Any]:
    """Recommend /32, /24 or /16 (IPv6: /128, /64, /48) from attacks seen in the same subnet.

    Evidence is every attack/threat alert and every Sentinel ban (single IP or range) from the last 24 h.
    Attackers are counted as distinct *other* IPs, so one noisy IP never widens its own ban:
      /16  >= 3 other attacking IPs in the /16 within 24 h, spread over more than this /24
      /24  >= 2 other attacking IPs in the /24 within 1 h
      /32  otherwise, and always for private / reserved addresses
    """
    from datetime import timedelta

    from sqlalchemy import select

    from database import ActionableAlert, BannedIP, BannedRange, SessionLocal, parse_network, utcnow

    addr = ipaddress.ip_address(ip_address.strip())
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    single, subnet, large = SCOPE_TIERS[addr.version]
    net_s = ipaddress.ip_network(f"{addr}/{subnet}", strict=False)
    net_l = ipaddress.ip_network(f"{addr}/{large}", strict=False)
    now = now or utcnow()
    since = now - timedelta(seconds=LARGE_WINDOW)

    async with SessionLocal() as s:
        alerts = (await s.execute(
            select(ActionableAlert.source_ip, ActionableAlert.ts)
            .where(ActionableAlert.ts >= since, ActionableAlert.source_ip.is_not(None),
                   ActionableAlert.category.in_(("attack", "threat"))).limit(50000))).all()
        bans = (await s.execute(select(BannedIP.ip_address, BannedIP.banned_at)
                                .where(BannedIP.banned_at >= since))).all()
        ranges = (await s.execute(select(BannedRange.source_ips, BannedRange.banned_at)
                                  .where(BannedRange.banned_at >= since))).all()

    events: list[tuple[Any, Any]] = []  # (address, timestamp)
    for raw, ts in [*alerts, *bans]:
        try:
            a = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        events.append((a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a, ts))
    for raw_ips, ts in ranges:
        try:
            ips = json.loads(raw_ips or "[]")
        except ValueError:
            ips = []
        for raw in ips:
            try:
                events.append((parse_network(raw).network_address, ts))
            except ValueError:
                continue

    in_large = [(a, ts) for a, ts in events if a.version == addr.version and a in net_l]
    attack_count = len(in_large)
    others_large: dict[Any, Any] = {}
    others_subnet_1h: dict[Any, Any] = {}
    for a, ts in in_large:
        if a == addr:
            continue
        others_large[a] = min(ts, others_large.get(a, ts))
        if a in net_s and (now - ts).total_seconds() <= SUBNET_WINDOW:
            others_subnet_1h[a] = min(ts, others_subnet_1h.get(a, ts))
    outside_subnet = [a for a in others_large if a not in net_s]

    def result(net: Any, reason: str, ips: dict[Any, Any]) -> dict[str, Any]:
        attackers = sorted((str(a) for a in ips), key=lambda x: ipaddress.ip_address(x))
        return {"ip": str(addr), "recommended_cidr": str(net), "scope": f"/{net.prefixlen}", "reason": reason,
                "attack_count": attack_count, "attacker_ips": attackers[:200], "attacker_ip_count": len(attackers),
                "options": scope_options(str(addr))}

    if not addr.is_global:
        return result(ipaddress.ip_network(f"{addr}/{single}"),
                      "internal / reserved address: only the single IP is ever recommended", {})
    if len(others_large) >= LARGE_MIN_OTHER_IPS and outside_subnet:
        age = (now - min(others_large.values())).total_seconds()
        return result(net_l, f"{len(others_large)} other attacking IPs from this /{large} in the last {_fmt_age(age)} "
                             f"({len(outside_subnet)} outside this /{subnet})", others_large)
    if len(others_subnet_1h) >= SUBNET_MIN_OTHER_IPS:
        age = (now - min(others_subnet_1h.values())).total_seconds()
        return result(net_s, f"{len(others_subnet_1h)} prior attacks from this /{subnet} in the last {_fmt_age(age)}",
                      others_subnet_1h)
    if others_large:
        return result(ipaddress.ip_network(f"{addr}/{single}"),
                      f"{len(others_large)} other attacking IP(s) nearby in 24 h: not enough to widen the ban", others_large)
    return result(ipaddress.ip_network(f"{addr}/{single}"), "only this IP has attacked: single-address ban", {})
