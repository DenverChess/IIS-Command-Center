"""Where APPROVE BAN pushes the block: Windows Firewall on the attacked IIS server, or a perimeter firewall.

Perimeter providers block the address for the whole network (every server), so one approval covers the
attacker everywhere. Each one only ever adds / removes an address in a list the operator owns:

  pfSense    pfSense-pkg-RESTAPI v2: adds the IP to a Host alias, then applies the filter.
  OPNsense   core REST API (key + secret): alias_util add / delete on an existing Host alias.
  SonicWall  SonicOS 7 REST API: creates an address object, adds it to an address group, commits.
  Palo Alto  PAN-OS XML API User-ID: registers the IP with a tag that drives a Dynamic Address Group.
             No commit is needed, so bans take effect within seconds.

The block rule that references the alias / group / DAG is created once by the operator (see README); Sentinel
never edits rules. Every call is blocking (requests), so the manager runs them in threads with a hard timeout.
"""
from __future__ import annotations

import asyncio
import logging
import re
import threading
from typing import Any
from xml.etree import ElementTree
from xml.sax.saxutils import quoteattr

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
# SonicWall (SonicOS 7 REST API)
# --------------------------------------------------------------------------------------
class SonicWall:
    _group_lock = threading.Lock()

    def __init__(self, c: dict[str, Any]) -> None:
        self.url = _base(c["sonicwall_url"]) + "/api/sonicos"
        self.user = c["sonicwall_username"]
        self.password = c["sonicwall_password"]
        self.group = c["sonicwall_group"].strip()
        self.zone = c["sonicwall_zone"].strip() or "WAN"
        self.verify = c["sonicwall_verify_ssl"]
        self.timeout = float(c["timeout"])
        if not (self.user and self.password):
            raise FirewallError("admin username and password are not configured")
        if not self.group:
            raise FirewallError("address group is not configured")

    @property
    def label(self) -> str:
        return f"SonicWall group {self.group}"

    @staticmethod
    def obj_name(ip: str) -> str:
        return f"SENTINEL_{ip.replace(':', '_')}"[:63]

    def _session(self) -> Any:
        import requests

        if not self.verify:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        s = requests.Session()
        s.verify = self.verify
        s.auth = (self.user, self.password)
        s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        return s

    def _call(self, s: Any, method: str, path: str, what: str, **kw: Any) -> Any:
        import requests

        try:
            resp = s.request(method, self.url + path, timeout=self.timeout, **kw)
        except requests.exceptions.RequestException as exc:
            raise FirewallError(f"cannot reach the SonicWall: {type(exc).__name__}: {str(exc)[:200]}") from exc
        data = None
        try:
            data = resp.json()
        except ValueError:
            pass
        if resp.status_code >= 400 or (isinstance(data, dict) and (data.get("status") or {}).get("success") is False):
            info = ""
            if isinstance(data, dict):
                infos = (data.get("status") or {}).get("info") or []
                info = "; ".join(str(i.get("message")) for i in infos if isinstance(i, dict)) or str(data)[:300]
            raise FirewallError(f"{what}: HTTP {resp.status_code} {info or resp.text[:300]}")
        return data

    def _run(self, fn: Any) -> str:
        s = self._session()
        self._call(s, "POST", "/auth", "login (enable 'RFC-2617 HTTP Basic Access authentication' for the SonicOS API)",
                   json={"override": True})
        try:
            try:
                self._call(s, "POST", "/config-mode", "config mode")
            except FirewallError:
                pass  # SonicOS 6.5 / auto-config-mode builds have no explicit config mode
            return fn(s)
        finally:
            try:
                self._call(s, "DELETE", "/auth", "logout")
            except FirewallError:
                pass

    def _check_group(self, s: Any) -> Any:
        try:
            return self._call(s, "GET", f"/address-groups/ipv4/name/{self.group}", "group lookup")
        except FirewallError as exc:
            raise FirewallError(f"address group '{self.group}' not found ({exc}). Create it under Object > Address "
                                "Groups and reference it in a deny access rule") from exc

    @staticmethod
    def _group(data: Any) -> dict[str, Any]:
        try:
            g = data["address_groups"][0]["ipv4"]
        except (KeyError, IndexError, TypeError):
            return {}
        return g if isinstance(g, dict) else {}

    @staticmethod
    def _members(group: dict[str, Any]) -> list[str]:
        items = (group.get("address_object") or {}).get("ipv4") or []
        return [str(m["name"]) for m in items if isinstance(m, dict) and m.get("name")]

    def _write_members(self, s: Any, group: dict[str, Any], names: list[str], what: str) -> None:
        # SonicOS PUT replaces the group's member list, so always send the complete list (including any
        # IPv6 objects or nested groups the operator put in it by hand).
        body: dict[str, Any] = {"name": self.group, "address_object": {"ipv4": [{"name": n} for n in names]}}
        ipv6 = (group.get("address_object") or {}).get("ipv6")
        if ipv6:
            body["address_object"]["ipv6"] = ipv6
        if group.get("address_group"):
            body["address_group"] = group["address_group"]
        self._call(s, "PUT", f"/address-groups/ipv4/name/{self.group}", what, json={"address_groups": [{"ipv4": body}]})

    def ban(self, ip: str) -> str:
        name = self.obj_name(ip)

        def op(s: Any) -> str:
            with SonicWall._group_lock:
                group = self._group(self._check_group(s))
                try:
                    self._call(s, "POST", "/address-objects/ipv4", "create address object",
                               json={"address_objects": [{"ipv4": {"name": name, "zone": self.zone, "host": {"ip": ip}}}]})
                except FirewallError as exc:
                    if "exist" not in str(exc).lower():
                        raise
                members = self._members(group)
                if name not in members:
                    self._write_members(s, group, members + [name], "add to group")
                after = self._members(self._group(self._check_group(s)))
                if name not in after:
                    raise FirewallError(f"{name} was created but the SonicWall did not keep it in group {self.group}")
                lost = [m for m in members if m not in after]
                if lost:
                    log.error("SonicWall group %s lost members while adding %s: %s", self.group, name, lost)
                self._call(s, "POST", "/config/pending", "commit")
                return f"address object {name} added to SonicWall group {self.group} ({len(after)} member(s)) and committed"

        return self._run(op)

    def unban(self, ip: str) -> str:
        name = self.obj_name(ip)

        def op(s: Any) -> str:
            with SonicWall._group_lock:
                group = self._group(self._check_group(s))
                members = self._members(group)
                if name in members:
                    remaining = [m for m in members if m != name]
                    try:
                        self._write_members(s, group, remaining, "remove from group")
                    except FirewallError as exc:
                        if remaining:
                            raise
                        # Some SonicOS builds refuse an empty member list; fall back to deleting the member.
                        log.info("SonicWall refused an empty group %s (%s); deleting the member instead", self.group, exc)
                        self._call(s, "DELETE", f"/address-groups/ipv4/name/{self.group}", "remove from group",
                                   json={"address_groups": [{"ipv4": {"name": self.group,
                                                                      "address_object": {"ipv4": [{"name": name}]}}}]})
                try:
                    self._call(s, "DELETE", f"/address-objects/ipv4/name/{name}", "delete address object")
                except FirewallError as exc:
                    if "not found" not in str(exc).lower() and "404" not in str(exc):
                        raise
                self._call(s, "POST", "/config/pending", "commit")
                return f"address object {name} removed from SonicWall group {self.group} and committed"

        return self._run(op)

    def test(self) -> str:
        def op(s: Any) -> str:
            data = self._check_group(s)
            members = []
            try:
                members = data["address_groups"][0]["ipv4"].get("address_object", {}).get("ipv4", [])
            except (KeyError, IndexError, TypeError):
                pass
            return f"SonicOS API OK; group {self.group} has {len(members)} member(s)"

        return self._run(op)


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

    def _client(self, provider: str) -> Any:
        cls = _CLASSES.get(provider)
        if cls is None:
            raise FirewallError(f"unknown firewall provider '{provider}'")
        return cls(self.config.get("firewall"))

    def summary(self) -> dict[str, Any]:
        p = self.provider()
        out = {"provider": p, "label": PROVIDERS[p], "perimeter": p != "windows", "target": "", "error": None}
        if p == "windows":
            out["target"] = "Windows Firewall on the attacked IIS server"
        else:
            try:
                out["target"] = self._client(p).label
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

    async def _call(self, provider: str, method: str, ip: str | None = None) -> str:
        client = self._client(provider)
        fn = getattr(client, method)
        timeout = float(self.config.value("firewall", "timeout", 15)) * 4 + 10
        try:
            return await asyncio.wait_for(asyncio.to_thread(fn, *([ip] if ip else [])), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise FirewallError(f"{PROVIDERS[provider]} did not answer within {timeout:.0f}s") from exc

    async def ban(self, provider: str, server_id: int, ip: str) -> tuple[bool, str]:
        if provider == "windows":
            return await self.remote.ban(server_id, ip)
        return True, await self._call(provider, "ban", ip)

    async def unban(self, provider: str, server_id: int, ip: str) -> tuple[bool, str]:
        if provider == "windows":
            return await self.remote.unban(server_id, ip)
        return True, await self._call(provider, "unban", ip)

    async def test(self, provider: str | None = None) -> dict[str, Any]:
        p = provider or self.provider()
        if p == "windows":
            return {"ok": True, "message": "Windows Firewall bans run netsh over each server's WinRM connection; use TEST "
                                           "under SERVERS to check a server."}
        try:
            return {"ok": True, "message": await self._call(p, "test")}
        except FirewallError as exc:
            return {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            log.exception("Firewall test failed")
            return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
