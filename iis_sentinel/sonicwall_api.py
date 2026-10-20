"""Async SonicOS 7 REST API client for address-object / address-group management.

Management interfaces are routinely reached over plain HTTP or HTTPS with the factory self-signed certificate,
so TLS verification is disabled and the URL scheme is used exactly as configured (never upgraded).

    api = await authenticate("http://192.168.168.168", "admin", "password")
    try:
        await api.add_ip_to_group("SENTINEL_BANS", "203.0.113.7")
    finally:
        await api.close()

or ``async with SonicWallSession(url, user, password) as api: ...``.

SonicOS allows a single admin configuration session, so every session holds a module-wide lock from login to
logout: concurrent bans queue instead of kicking each other out. Group writes always PUT the complete member
list (SonicOS PUT replaces members) and are committed before the result is verified (reads return committed
configuration on SonicOS 7.x).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("sentinel.sonicwall")

OBJECT_PREFIX = "SENTINEL_"
DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 3
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,63}$")


class SonicWallError(Exception):
    pass


class SonicWallAuthError(SonicWallError):
    pass


class SonicWallNotFound(SonicWallError):
    pass


class SonicWallRateLimited(SonicWallError):
    pass


_clients: dict[int, httpx.AsyncClient] = {}
_locks: dict[int, asyncio.Lock] = {}


def _shared_client() -> httpx.AsyncClient:
    """One AsyncClient per event loop (connection pools are loop-bound)."""
    loop_id = id(asyncio.get_running_loop())
    client = _clients.get(loop_id)
    if client is None or client.is_closed:
        client = httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT, follow_redirects=False,
                                   headers={"Accept": "application/json", "Content-Type": "application/json"})
        _clients[loop_id] = client
    return client


def _session_lock() -> asyncio.Lock:
    loop_id = id(asyncio.get_running_loop())
    lock = _locks.get(loop_id)
    if lock is None:
        lock = _locks[loop_id] = asyncio.Lock()
    return lock


async def close_shared_client() -> None:
    client = _clients.pop(id(asyncio.get_running_loop()), None)
    if client is not None:
        await client.aclose()


def normalize_base_url(base_url: str) -> str:
    """Strip whitespace, trailing slashes and a pasted /api/sonicos suffix. http:// stays http://; a bare host
    (no scheme at all) defaults to https://."""
    url = (base_url or "").strip().rstrip("/")
    if not url:
        raise SonicWallError("SonicWall API URL is not configured")
    if re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE):
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise SonicWallError("SonicWall API URL must start with http:// or https://")
    else:
        url = "https://" + url
    url = re.sub(r"/api/sonicos$", "", url, flags=re.IGNORECASE)
    if not httpx.URL(url).host:
        raise SonicWallError(f"'{base_url}' is not a valid URL")
    return url


def object_name(ip_or_cidr: str) -> str:
    return f"{OBJECT_PREFIX}{ip_or_cidr.replace(':', '_').replace('/', '_')}"[:63]


def check_name(name: str, what: str = "group name") -> str:
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise SonicWallError(f"{what} must be 1-63 letters, digits, '.', '_' or '-'")
    return name


def parse_target(ip_or_cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network((ip_or_cidr or "").strip(), strict=False)
    except ValueError as exc:
        raise SonicWallError(f"'{ip_or_cidr}' is not a valid IPv4 address or CIDR") from exc
    if net.version != 4:
        raise SonicWallError("only IPv4 addresses are supported in SonicWall address groups")
    return net  # type: ignore[return-value]


def _status_info(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    infos = (data.get("status") or {}).get("info") or []
    return "; ".join(str(i.get("message")) for i in infos if isinstance(i, dict) and i.get("message"))


def _group_body(data: Any) -> dict[str, Any]:
    try:
        g = data["address_groups"][0]["ipv4"]
    except (KeyError, IndexError, TypeError):
        return {}
    return g if isinstance(g, dict) else {}


def _member_names(group: dict[str, Any]) -> list[str]:
    items = (group.get("address_object") or {}).get("ipv4") or []
    return [str(m["name"]) for m in items if isinstance(m, dict) and m.get("name")]


def _describe_object(obj: dict[str, Any]) -> str:
    if obj.get("host"):
        return str(obj["host"].get("ip", ""))
    if obj.get("network"):
        n = obj["network"]
        try:
            return str(ipaddress.ip_network(f"{n.get('subnet')}/{n.get('mask')}", strict=False))
        except ValueError:
            return f"{n.get('subnet')}/{n.get('mask')}"
    if obj.get("range"):
        r = obj["range"]
        return f"{r.get('begin')}-{r.get('end')}"
    if obj.get("fqdn"):
        return str(obj["fqdn"].get("domain", "") if isinstance(obj["fqdn"], dict) else obj["fqdn"])
    return ""


class SonicWallSession:
    def __init__(self, base_url: str, username: str, password: str, *, timeout: float = DEFAULT_TIMEOUT,
                 zone: str = "WAN", protected_group: str = "") -> None:
        self.base_url = normalize_base_url(base_url)
        self.api = self.base_url + "/api/sonicos"
        self.username = username or ""
        self.password = password or ""
        self.timeout = float(timeout or DEFAULT_TIMEOUT)
        self.zone = (zone or "WAN").strip() or "WAN"
        self.protected_group = protected_group
        self._token: str | None = None
        self._authenticated = False
        self._lock_held = False
        if not (self.username and self.password):
            raise SonicWallAuthError("SonicWall admin username and password are not configured")

    async def __aenter__(self) -> "SonicWallSession":
        await self.authenticate()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    # transport -------------------------------------------------------------------------------
    async def _request(self, method: str, path: str, what: str, *, json: Any = None, allow_404: bool = False) -> Any:
        client = _shared_client()
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else None
        auth = None if self._token else (self.username, self.password)
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await client.request(method, self.api + path, json=json, auth=auth, headers=headers,
                                            timeout=self.timeout)
            except httpx.TimeoutException as exc:
                raise SonicWallError(f"{what}: the SonicWall at {self.base_url} did not answer within "
                                     f"{self.timeout:.0f}s") from exc
            except httpx.HTTPError as exc:
                raise SonicWallError(f"{what}: cannot reach the SonicWall at {self.base_url}: "
                                     f"{type(exc).__name__}: {str(exc)[:200]}") from exc
            if resp.status_code == 429:
                retry = resp.headers.get("Retry-After", "")
                delay = float(retry) if retry.replace(".", "", 1).isdigit() else 2.0 * attempt
                if attempt < MAX_RETRIES:
                    log.warning("SonicWall rate-limited %s; retrying in %.1fs", what, delay)
                    await asyncio.sleep(min(delay, 30.0))
                    continue
                raise SonicWallRateLimited(f"{what}: the SonicWall is rate-limiting API calls (HTTP 429); try again shortly")
            break
        data: Any = None
        try:
            data = resp.json()
        except ValueError:
            pass
        info = _status_info(data)
        if resp.status_code in (401, 403):
            raise SonicWallAuthError(
                f"{what}: HTTP {resp.status_code} — {info or 'credentials rejected'}. Check the admin username/password and "
                "that 'RFC-2617 HTTP Basic Access authentication' is enabled under Device > Settings > Administration > "
                "SonicOS API")
        if resp.status_code == 404 or "not found" in info.lower() or "does not exist" in info.lower():
            if allow_404:
                return None
            raise SonicWallNotFound(f"{what}: {info or 'HTTP 404 not found'}")
        if resp.status_code >= 400 or (isinstance(data, dict) and (data.get("status") or {}).get("success") is False):
            raise SonicWallError(f"{what}: HTTP {resp.status_code} {info or resp.text[:300]}")
        return data

    async def authenticate(self) -> None:
        if self._authenticated:
            return
        lock = _session_lock()
        await lock.acquire()
        self._lock_held = True
        try:
            _shared_client().cookies.clear()
            data = await self._request("POST", "/auth", "login", json={"override": True})
            token = None
            if isinstance(data, dict):
                token = data.get("token") or data.get("bearer_token") or (data.get("status") or {}).get("token")
            if token:
                self._token = str(token)
            self._authenticated = True
            try:
                await self._request("POST", "/config-mode", "config mode")
            except SonicWallAuthError:
                raise
            except SonicWallError:
                pass  # builds without an explicit config mode
        except BaseException:
            self._authenticated = False
            self._release()
            raise

    def _release(self) -> None:
        if self._lock_held:
            self._lock_held = False
            _session_lock().release()

    async def close(self) -> None:
        try:
            if self._authenticated:
                await self._request("DELETE", "/auth", "logout")
        except SonicWallError:
            pass
        finally:
            self._authenticated = False
            self._token = None
            self._release()

    async def commit(self) -> None:
        await self._request("POST", "/config/pending", "commit")

    # reads ------------------------------------------------------------------------------------
    async def _get_group(self, group_name: str) -> dict[str, Any]:
        data = await self._request("GET", f"/address-groups/ipv4/name/{quote(group_name, safe='')}",
                                   f"look up group {group_name}", allow_404=True)
        group = _group_body(data)
        if not group:
            raise SonicWallNotFound(f"address group '{group_name}' does not exist on the SonicWall")
        return group

    async def _objects(self) -> dict[str, dict[str, Any]]:
        data = await self._request("GET", "/address-objects/ipv4", "list address objects", allow_404=True)
        out: dict[str, dict[str, Any]] = {}
        for row in (data or {}).get("address_objects") or [] if isinstance(data, dict) else []:
            obj = row.get("ipv4") if isinstance(row, dict) else None
            if isinstance(obj, dict) and obj.get("name"):
                out[str(obj["name"])] = obj
        return out

    async def list_groups(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/address-groups/ipv4", "list address groups", allow_404=True)
        objects = await self._objects()
        groups: list[dict[str, Any]] = []
        for row in (data or {}).get("address_groups") or [] if isinstance(data, dict) else []:
            g = row.get("ipv4") if isinstance(row, dict) else None
            if not isinstance(g, dict) or not g.get("name"):
                continue
            members = []
            for name in _member_names(g):
                obj = objects.get(name, {})
                members.append({"name": name, "address": _describe_object(obj), "sentinel": name.startswith(OBJECT_PREFIX)})
            nested = [str(x.get("name")) for x in (g.get("address_group") or {}).get("ipv4") or [] if isinstance(x, dict)]
            groups.append({"name": str(g["name"]), "uuid": g.get("uuid", ""), "members": members,
                           "member_count": len(members) + len(nested), "nested_groups": nested})
        groups.sort(key=lambda x: x["name"].lower())
        return groups

    async def group_members(self, group_name: str) -> list[str]:
        return _member_names(await self._get_group(check_name(group_name)))

    # writes -----------------------------------------------------------------------------------
    async def _write_members(self, group_name: str, group: dict[str, Any], names: list[str], what: str) -> None:
        body: dict[str, Any] = {"name": group_name, "address_object": {"ipv4": [{"name": n} for n in names]}}
        ipv6 = (group.get("address_object") or {}).get("ipv6")
        if ipv6:
            body["address_object"]["ipv6"] = ipv6
        if group.get("address_group"):
            body["address_group"] = group["address_group"]
        await self._request("PUT", f"/address-groups/ipv4/name/{quote(group_name, safe='')}", what,
                            json={"address_groups": [{"ipv4": body}]})

    async def create_address_group(self, group_name: str, description: str = "") -> str:
        group_name = check_name(group_name)
        try:
            await self._get_group(group_name)
            return f"address group {group_name} already exists"
        except SonicWallNotFound:
            pass
        # SonicOS address groups have no comment field; the description is kept in Sentinel's log only.
        await self._request("POST", "/address-groups/ipv4", f"create group {group_name}",
                            json={"address_groups": [{"ipv4": {"name": group_name}}]})
        await self.commit()
        log.info("SonicWall address group %s created%s", group_name, f" ({description})" if description else "")
        return f"address group {group_name} created and committed"

    async def delete_address_group(self, group_name: str) -> str:
        group_name = check_name(group_name)
        if self.protected_group and group_name.lower() == self.protected_group.lower():
            raise SonicWallError(f"{group_name} is the default ban group Sentinel writes to; pick another default "
                                 "group before deleting it")
        group = await self._get_group(group_name)
        await self._request("DELETE", f"/address-groups/ipv4/name/{quote(group_name, safe='')}", f"delete group {group_name}")
        removed = 0
        for name in _member_names(group):
            if not name.startswith(OBJECT_PREFIX):
                continue
            try:
                await self._request("DELETE", f"/address-objects/ipv4/name/{quote(name, safe='')}",
                                    f"delete address object {name}", allow_404=True)
                removed += 1
            except SonicWallError as exc:
                log.info("SonicWall kept %s (still referenced elsewhere): %s", name, exc)
        await self.commit()
        extra = f"; {removed} Sentinel address object(s) removed" if removed else ""
        return f"address group {group_name} deleted and committed{extra}"

    async def add_ip_to_group(self, group_name: str, ip_or_cidr: str) -> str:
        group_name = check_name(group_name)
        net = parse_target(ip_or_cidr)
        is_host = net.prefixlen == 32
        label = str(net.network_address) if is_host else str(net)
        name = object_name(label)
        group = await self._get_group(group_name)
        body: dict[str, Any] = {"name": name, "zone": self.zone}
        if is_host:
            body["host"] = {"ip": label}
        else:
            body["network"] = {"subnet": str(net.network_address), "mask": str(net.netmask)}
        try:
            await self._request("POST", "/address-objects/ipv4", f"create address object {name}",
                                json={"address_objects": [{"ipv4": body}]})
        except SonicWallError as exc:
            if "exist" not in str(exc).lower() and "duplicate" not in str(exc).lower():
                raise
        members = _member_names(group)
        if name not in members:
            await self._write_members(group_name, group, members + [name], f"add {name} to {group_name}")
        await self.commit()
        note = ""
        try:
            after = _member_names(await self._get_group(group_name))
        except SonicWallError as exc:
            after, note = [], f" (could not re-read the group to verify: {exc})"
        if after:
            lost = [m for m in members if m not in after]
            if name not in after:
                note = f" — WARNING: the committed group does not list {name}; check {group_name} on the SonicWall"
                log.error("SonicWall group %s does not list %s after commit", group_name, name)
            elif lost:
                note = f" — WARNING: {len(lost)} earlier member(s) missing from {group_name}: {', '.join(lost[:5])}"
                log.error("SonicWall group %s lost members while adding %s: %s", group_name, name, lost)
        count = f" ({len(after)} member(s))" if after else ""
        return f"address object {name} added to SonicWall group {group_name}{count} and committed{note}"

    async def remove_ip_from_group(self, group_name: str, ip_or_cidr: str) -> str:
        group_name = check_name(group_name)
        net = parse_target(ip_or_cidr)
        label = str(net.network_address) if net.prefixlen == 32 else str(net)
        name = object_name(label)
        group = await self._get_group(group_name)
        members = _member_names(group)
        if name in members:
            remaining = [m for m in members if m != name]
            try:
                await self._write_members(group_name, group, remaining, f"remove {name} from {group_name}")
            except SonicWallError as exc:
                if remaining:
                    raise
                log.info("SonicWall refused an empty group %s (%s); deleting the member instead", group_name, exc)
                await self._request("DELETE", f"/address-groups/ipv4/name/{quote(group_name, safe='')}",
                                    f"remove {name} from {group_name}",
                                    json={"address_groups": [{"ipv4": {"name": group_name,
                                                                       "address_object": {"ipv4": [{"name": name}]}}}]})
        try:
            await self._request("DELETE", f"/address-objects/ipv4/name/{quote(name, safe='')}",
                                f"delete address object {name}", allow_404=True)
        except SonicWallError as exc:
            # Still referenced by another group or rule: leave the object, the group membership is gone.
            log.warning("SonicWall kept address object %s: %s", name, exc)
        await self.commit()
        state = "removed from" if name in members else "was not in"
        return f"address object {name} {state} SonicWall group {group_name} (committed)"

    async def test(self, group_name: str = "") -> str:
        groups = await self.list_groups()
        msg = f"SonicOS API OK at {self.base_url} ({len(groups)} address group(s))"
        if group_name:
            match = next((g for g in groups if g["name"].lower() == group_name.lower()), None)
            msg += (f"; group {match['name']} has {match['member_count']} member(s)" if match
                    else f"; WARNING: group {group_name} does not exist yet (create it below or on the SonicWall)")
        return msg


async def authenticate(base_url: str, username: str, password: str, *, timeout: float = DEFAULT_TIMEOUT,
                       zone: str = "WAN", protected_group: str = "") -> SonicWallSession:
    """Log in and return an open session; call ``close()`` when done (or use ``async with SonicWallSession``)."""
    session = SonicWallSession(base_url, username, password, timeout=timeout, zone=zone, protected_group=protected_group)
    await session.authenticate()
    return session
