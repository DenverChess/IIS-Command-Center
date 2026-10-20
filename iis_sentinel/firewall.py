"""Where APPROVE BAN pushes the block: Windows Firewall on the attacked IIS server, or a perimeter firewall.

Perimeter providers block the address for the whole network (every server), so one approval covers the
attacker everywhere. Each one only ever adds / removes an address in a list the operator owns:

  pfSense    pfSense-pkg-RESTAPI v2: adds the IP to a Host alias, then applies the filter.
  OPNsense   core REST API (key + secret): alias_util add / delete on an existing Host alias.
  SonicWall  SonicOS 7 REST API: creates an address object, adds it to an address group, commits.
  Palo Alto  PAN-OS XML API User-ID: registers the IP with a tag that drives a Dynamic Address Group.
             No commit is needed, so bans take effect within seconds.

The block rule that references the alias / group / DAG is created once by the operator (see README); Sentinel
never edits rules. pfSense and Palo Alto calls are blocking (requests) and run in threads; SonicWall uses the async
httpx client in sonicwall_api.py. Every call has a hard timeout.
"""
from __future__ import annotations

import asyncio
import logging
import inspect
import re
from typing import Any
from xml.etree import ElementTree
from xml.sax.saxutils import quoteattr

import sonicwall_api
from database import ConfigStore

log = logging.getLogger("sentinel.firewall")

PROVIDERS = {
    "windows": "Windows Firewall (on server)",
    "pfsense": "pfSense / OPNsense",
    "sonicwall": "SonicWall",
    "paloalto": "Palo Alto Networks",
}


class FirewallError(Exception):
    pass


def _base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise FirewallError("management URL is not configured")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def _http(method: str, url: str, *, verify: bool, timeout: float, **kw: Any) -> Any:
    import requests

    if not verify:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        return requests.request(method, url, verify=verify, timeout=timeout, **kw)
    except requests.exceptions.SSLError as exc:
        raise FirewallError(f"TLS error talking to {url.split('/api')[0]} (untick 'verify certificate' for a self-signed "
                            f"management certificate): {str(exc)[:200]}") from exc
    except requests.exceptions.RequestException as exc:
        raise FirewallError(f"cannot reach {url.split('/api')[0]}: {type(exc).__name__}: {str(exc)[:200]}") from exc


def _json(resp: Any, what: str) -> Any:
    if resp.status_code in (401, 403):
        raise FirewallError(f"{what}: HTTP {resp.status_code} — credentials rejected or the account lacks API privileges")
    try:
        data = resp.json()
    except ValueError:
        data = None
    if resp.status_code >= 400:
        msg = ""
        if isinstance(data, dict):
            msg = str(data.get("message") or data.get("status") or data.get("errorMessage") or data)
        raise FirewallError(f"{what}: HTTP {resp.status_code} {msg[:300] or resp.text[:300]}")
    return data


# --------------------------------------------------------------------------------------
# pfSense (pfSense-pkg-RESTAPI v2) / OPNsense (core API)
# --------------------------------------------------------------------------------------
class PfSense:
    def __init__(self, c: dict[str, Any]) -> None:
        self.url = _base(c["pfsense_url"])
        self.platform = c["pfsense_platform"]
        self.alias = c["pfsense_alias"].strip()
        self.key = c["pfsense_api_key"]
        self.secret = c["pfsense_api_secret"]
        self.verify = c["pfsense_verify_ssl"]
        self.timeout = float(c["timeout"])
        if not self.alias:
            raise FirewallError("alias name is not configured")
        if not self.key or (self.platform == "opnsense" and not self.secret):
            raise FirewallError("API key" + (" and secret are" if self.platform == "opnsense" else " is") + " not configured")

    @property
    def label(self) -> str:
        return f"{'OPNsense' if self.platform == 'opnsense' else 'pfSense'} alias {self.alias}"

    def _req(self, method: str, path: str, what: str, **kw: Any) -> Any:
        if self.platform == "opnsense":
            kw["auth"] = (self.key, self.secret)
        else:
            kw.setdefault("headers", {})["X-API-Key"] = self.key
        return _json(_http(method, self.url + path, verify=self.verify, timeout=self.timeout, **kw), what)

    # OPNsense ---------------------------------------------------------------------------
    def _opn_check_alias(self) -> None:
        data = self._req("GET", f"/api/firewall/alias/getAliasUUID/{self.alias}", "alias lookup")
        if not (isinstance(data, dict) and data.get("uuid")):
            raise FirewallError(f"alias '{self.alias}' does not exist on the OPNsense box (Firewall > Aliases: create a "
                                "Host(s) alias with that name and a block rule that uses it)")

    def _opn_util(self, action: str, ip: str) -> str:
        self._opn_check_alias()
        data = self._req("POST", f"/api/firewall/alias_util/{action}/{self.alias}", f"alias {action}", json={"address": ip})
        status = str((data or {}).get("status", "")).lower() if isinstance(data, dict) else ""
        if status not in ("done", "ok", ""):
            raise FirewallError(f"OPNsense refused to {action} {ip}: {data}")
        return f"{ip} {'added to' if action == 'add' else 'removed from'} OPNsense alias {self.alias}"

    # pfSense ----------------------------------------------------------------------------
    def _pf_alias(self) -> dict[str, Any]:
        data = self._req("GET", "/api/v2/firewall/aliases", "alias lookup", params={"name": self.alias})
        rows = (data or {}).get("data") if isinstance(data, dict) else None
        for row in rows or []:
            if isinstance(row, dict) and row.get("name") == self.alias:
                return row
        raise FirewallError(f"alias '{self.alias}' does not exist on the pfSense box (Firewall > Aliases: create a Host(s) "
                            "alias with that name and a block rule that uses it; the REST API package must be installed)")

    def _pf_write(self, ip: str, add: bool) -> str:
        alias = self._pf_alias()
        addresses = [str(a) for a in alias.get("address") or []]
        details = [str(d) for d in alias.get("detail") or []]
        details += [""] * (len(addresses) - len(details))
        if add and ip not in addresses:
            addresses.append(ip)
            details.append("IIS Sentinel ban")
        elif not add and ip in addresses:
            i = addresses.index(ip)
            del addresses[i]
            del details[i]
        else:
            return f"{ip} {'already in' if add else 'not in'} pfSense alias {self.alias}"
        self._req("PATCH", "/api/v2/firewall/alias", "alias update",
                  json={"id": alias.get("id"), "address": addresses, "detail": details[:len(addresses)]})
        self._req("POST", "/api/v2/firewall/apply", "apply changes", json={})
        return f"{ip} {'added to' if add else 'removed from'} pfSense alias {self.alias} (filter reloaded)"

    # common -----------------------------------------------------------------------------
    def ban(self, ip: str) -> str:
        return self._opn_util("add", ip) if self.platform == "opnsense" else self._pf_write(ip, True)

    def unban(self, ip: str) -> str:
        return self._opn_util("delete", ip) if self.platform == "opnsense" else self._pf_write(ip, False)

    def test(self) -> str:
        if self.platform == "opnsense":
            self._opn_check_alias()
            data = self._req("GET", f"/api/firewall/alias_util/list/{self.alias}", "alias list")
            n = len((data or {}).get("rows") or []) if isinstance(data, dict) else 0
            return f"OPNsense API OK; alias {self.alias} exists with {n} address(es)"
        alias = self._pf_alias()
        return f"pfSense REST API OK; alias {self.alias} ({alias.get('type', '?')}) holds {len(alias.get('address') or [])} address(es)"


# --------------------------------------------------------------------------------------
# SonicWall (SonicOS 7 REST API, async client in sonicwall_api.py; TLS verification off, http or https)
# --------------------------------------------------------------------------------------
class SonicWall:
    def __init__(self, c: dict[str, Any]) -> None:
        self.url = (c.get("sonicwall_url") or "").strip()
        self.user = c.get("sonicwall_username") or ""
        self.password = c.get("sonicwall_password") or ""
        self.group = (c.get("sonicwall_group") or "").strip()
        self.zone = (c.get("sonicwall_zone") or "").strip() or "WAN"
        self.timeout = float(c.get("timeout") or 15)
        if not self.url:
            raise FirewallError("SonicWall API URL is not configured")
        if not (self.user and self.password):
            raise FirewallError("admin username and password are not configured")
        if not self.group:
            raise FirewallError("default address group is not configured")

    @property
    def label(self) -> str:
        return f"SonicWall group {self.group}"

    @staticmethod
    def obj_name(ip: str) -> str:
        return sonicwall_api.object_name(ip)

    def session(self) -> "sonicwall_api.SonicWallSession":
        try:
            return sonicwall_api.SonicWallSession(self.url, self.user, self.password, timeout=self.timeout,
                                                  zone=self.zone, protected_group=self.group)
        except sonicwall_api.SonicWallError as exc:
            raise FirewallError(str(exc)) from exc

    async def run(self, op: Any) -> Any:
        try:
            async with self.session() as api:
                return await op(api)
        except sonicwall_api.SonicWallError as exc:
            raise FirewallError(str(exc)) from exc

    async def ban(self, ip: str) -> str:
        return await self.run(lambda api: api.add_ip_to_group(self.group, ip))

    async def unban(self, ip: str) -> str:
        return await self.run(lambda api: api.remove_ip_from_group(self.group, ip))

    async def test(self) -> str:
        return await self.run(lambda api: api.test(self.group))


# --------------------------------------------------------------------------------------
# Palo Alto Networks (PAN-OS XML API, User-ID tag registration -> Dynamic Address Group)
# --------------------------------------------------------------------------------------
class PaloAlto:
    def __init__(self, c: dict[str, Any]) -> None:
        self.url = _base(c["paloalto_url"]) + "/api/"
        self.key = c["paloalto_api_key"]
        self.user = c["paloalto_username"]
        self.password = c["paloalto_password"]
        self.tag = c["paloalto_tag"].strip()
        self.vsys = c["paloalto_vsys"].strip()
        self.timeout_min = int(c["paloalto_timeout_minutes"])
        self.verify = c["paloalto_verify_ssl"]
        self.timeout = float(c["timeout"])
        if not self.tag or not re.match(r"^[A-Za-z0-9_.\-]{1,127}$", self.tag):
            raise FirewallError("tag must be 1-127 letters, digits, '.', '_' or '-'")
        if not self.key and not (self.user and self.password):
            raise FirewallError("API key (or username + password) is not configured")

    @property
    def label(self) -> str:
        return f"Palo Alto tag {self.tag}"

    def _post(self, data: dict[str, str], what: str) -> ElementTree.Element:
        headers = {"X-PAN-KEY": self.key} if data.get("type") != "keygen" else {}
        resp = _http("POST", self.url, verify=self.verify, timeout=self.timeout, data=data, headers=headers)
        if resp.status_code in (401, 403):
            raise FirewallError(f"{what}: HTTP {resp.status_code} — API key rejected or the admin role lacks XML API access")
        try:
            root = ElementTree.fromstring(resp.text)
        except ElementTree.ParseError as exc:
            raise FirewallError(f"{what}: unexpected reply (HTTP {resp.status_code}): {resp.text[:200]}") from exc
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())
            raise FirewallError(f"{what}: {msg[:400] or 'error'}")
        return root

    def _ensure_key(self) -> None:
        if self.key:
            return
        root = self._post({"type": "keygen", "user": self.user, "password": self.password}, "API key generation")
        key = root.findtext("./result/key")
        if not key:
            raise FirewallError("API key generation returned no key")
        self.key = key

    def _uid(self, ip: str, register: bool) -> None:
        self._ensure_key()
        timeout = f" timeout=\"{self.timeout_min * 60}\"" if register and self.timeout_min > 0 else ""
        persistent = ' persistent="1"' if register else ""
        verb = "register" if register else "unregister"
        cmd = (f"<uid-message><version>2.0</version><type>update</type><payload><{verb}>"
               f"<entry ip={quoteattr(ip)}{persistent}><tag><member{timeout}>{self.tag}</member></tag></entry>"
               f"</{verb}></payload></uid-message>")
        data = {"type": "user-id", "cmd": cmd}
        if self.vsys:
            data["vsys"] = self.vsys
        self._post(data, f"tag {verb}")

    def ban(self, ip: str) -> str:
        self._uid(ip, True)
        exp = f", expires in {self.timeout_min} min" if self.timeout_min > 0 else ""
        return f"{ip} tagged '{self.tag}' on the Palo Alto (Dynamic Address Group{exp})"

    def unban(self, ip: str) -> str:
        self._uid(ip, False)
        return f"tag '{self.tag}' removed from {ip} on the Palo Alto"

    def test(self) -> str:
        self._ensure_key()
        root = self._post({"type": "op", "cmd": "<show><system><info></info></system></show>"}, "system info")
        info = root.find("./result/system")
        get = (lambda k: info.findtext(k) or "?") if info is not None else (lambda k: "?")
        return f"PAN-OS XML API OK; {get('hostname')} ({get('model')}, PAN-OS {get('sw-version')}); bans tag '{self.tag}'"


_CLASSES = {"pfsense": PfSense, "sonicwall": SonicWall, "paloalto": PaloAlto}


class FirewallManager:
    def __init__(self, config: ConfigStore, remote: Any) -> None:
        self.config = config
        self.remote = remote

    def provider(self) -> str:
        p = self.config.value("firewall", "provider", "windows")
        return p if p in PROVIDERS else "windows"

    def _client(self, provider: str, overrides: dict[str, Any] | None = None) -> Any:
        cls = _CLASSES.get(provider)
        if cls is None:
            raise FirewallError(f"unknown firewall provider '{provider}'")
        c = {**self.config.get("firewall"), **(overrides or {})}
        return cls(c)

    def also_windows(self, provider: str | None = None) -> bool:
        return (provider or self.provider()) != "windows" and bool(self.config.value("firewall", "also_windows", False))

    def summary(self) -> dict[str, Any]:
        p = self.provider()
        out = {"provider": p, "label": PROVIDERS[p], "perimeter": p != "windows", "target": "", "error": None,
               "also_windows": self.also_windows(p)}
        if p == "windows":
            out["target"] = "Windows Firewall on the attacked IIS server"
        else:
            try:
                out["target"] = self._client(p).label + (" + Windows Firewall on the server" if out["also_windows"] else "")
            except FirewallError as exc:
                out["error"] = str(exc)
        return out

    def rule_name(self, provider: str, ip: str) -> str:
        if provider == "windows":
            return f"SENTINEL BAN: {ip}"
        try:
            return self._client(provider).label
        except FirewallError:
            return PROVIDERS.get(provider, provider)

    def _timeout(self) -> float:
        return float(self.config.value("firewall", "timeout", 15)) * 4 + 10

    async def _call(self, provider: str, method: str, ip: str | None = None,
                    overrides: dict[str, Any] | None = None) -> str:
        client = self._client(provider, overrides)
        fn = getattr(client, method)
        args = [ip] if ip else []
        timeout = self._timeout()
        try:
            if inspect.iscoroutinefunction(fn):
                return await asyncio.wait_for(fn(*args), timeout=timeout)
            return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise FirewallError(f"{PROVIDERS[provider]} did not answer within {timeout:.0f}s") from exc

    async def sonicwall(self, op: Any, overrides: dict[str, Any] | None = None) -> Any:
        """Run ``op(session)`` inside one authenticated SonicOS session (group management endpoints)."""
        client = self._client("sonicwall", overrides)
        try:
            return await asyncio.wait_for(client.run(op), timeout=self._timeout())
        except asyncio.TimeoutError as exc:
            raise FirewallError(f"SonicWall did not answer within {self._timeout():.0f}s") from exc

    async def ban(self, provider: str, server_id: int, ip: str) -> tuple[bool, str]:
        if provider == "windows":
            return await self.remote.ban(server_id, ip)
        return True, await self._call(provider, "ban", ip)

    async def unban(self, provider: str, server_id: int, ip: str) -> tuple[bool, str]:
        if provider == "windows":
            return await self.remote.unban(server_id, ip)
        return True, await self._call(provider, "unban", ip)

    async def test(self, provider: str | None = None, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        p = provider or self.provider()
        if p == "windows":
            return {"ok": True, "message": "Windows Firewall bans run netsh over each server's WinRM connection; use TEST "
                                           "under SERVERS to check a server."}
        try:
            return {"ok": True, "message": await self._call(p, "test", overrides=overrides)}
        except FirewallError as exc:
            return {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            log.exception("Firewall test failed")
            return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
