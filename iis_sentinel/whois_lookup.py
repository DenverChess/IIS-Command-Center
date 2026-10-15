"""WHOIS for client IPs via RDAP (the JSON successor to port-43 WHOIS), plus reverse DNS.

rdap.org redirects each query to the authoritative registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Results
are cached; private / reserved addresses are answered locally without any network call. Every failure
(no internet, proxy, registry rate limit) comes back as an `error` field rather than an exception.
"""
from __future__ import annotations

import asyncio
import ipaddress
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
        return result
