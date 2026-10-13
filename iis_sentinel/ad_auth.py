"""Active Directory authentication via ldap3 simple bind (LDAPS / StartTLS recommended)."""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
import ssl
from dataclasses import dataclass, field
from typing import Any

import local_admin
from database import DEMO_MODE, ConfigStore

log = logging.getLogger("sentinel.ad")

# AD "LDAP_MATCHING_RULE_IN_CHAIN": resolves nested group membership server-side.
_IN_CHAIN = "1.2.840.113556.1.4.1941"


@dataclass
class AuthResult:
    ok: bool
    username: str = ""
    display_name: str = ""
    source: str = "ad"
    error: str = ""
    groups: list[str] = field(default_factory=list)


class ADAuthenticator:
    def __init__(self, config: ConfigStore) -> None:
        self.config = config

    async def authenticate(self, username: str, password: str) -> AuthResult:
        username = (username or "").strip()
        if not username or not password:
            # An empty password would succeed as an LDAP *anonymous/unauthenticated* bind.
            return AuthResult(False, error="Username and password are required")
        if len(username) > 256 or len(password) > 512 or any(ord(c) < 32 for c in username):
            return AuthResult(False, error="Invalid credentials")

        local = await asyncio.to_thread(self._local_account, username, password)
        if local is not None:
            return local

        cfg = self.config.get("ad")
        if not cfg.get("servers"):
            return AuthResult(False, error="Active Directory is not configured")
        timeout = float(cfg.get("timeout") or 8)
        overall = timeout * (len(cfg["servers"]) * 2 + 2) + 5
        try:
            return await asyncio.wait_for(asyncio.to_thread(self._bind, cfg, username, password), timeout=overall)
        except asyncio.TimeoutError:
            log.error("AD authentication timed out after %.0fs", overall)
            return AuthResult(False, error="Directory unreachable (timeout)")
        except Exception as exc:  # noqa: BLE001
            log.exception("AD authentication error")
            return AuthResult(False, error=f"Directory error: {type(exc).__name__}")

    @staticmethod
    def _local_account(username: str, password: str) -> AuthResult | None:
        """Break-glass local login so the console stays reachable when AD is down or not yet configured."""
        local_user = os.environ.get("SENTINEL_LOCAL_ADMIN_USER", local_admin.DEFAULT_USER)
        local_pass = os.environ.get("SENTINEL_LOCAL_ADMIN_PASSWORD", "")
        stored = None if local_pass else local_admin.load()
        if stored:
            local_user = stored["user"]
        elif DEMO_MODE and not local_pass:
            local_user, local_pass = "demo", "demo"
        if not local_pass and not stored:
            return None
        if hmac.compare_digest(username.lower().encode(), local_user.lower().encode()):
            ok = local_admin.verify_password(password, stored["hash"]) if stored else hmac.compare_digest(
                password.encode(), local_pass.encode()
            )
            if ok:
                log.warning("Break-glass local login used by '%s'", username)
                return AuthResult(True, username=local_user, display_name="Local Administrator", source="local")
            return AuthResult(False, error="Invalid credentials")
        return None

    @staticmethod
    def _bind_name(cfg: dict[str, Any], username: str) -> str:
        if "@" in username or "\\" in username:
            return username
        if cfg.get("upn_suffix"):
            return f"{username}@{cfg['upn_suffix'].lstrip('@')}"
        if cfg.get("domain"):
            return f"{cfg['domain']}\\{username}"
        return username

    def _bind(self, cfg: dict[str, Any], username: str, password: str) -> AuthResult:
        from ldap3 import FIRST, NONE, SIMPLE, SUBTREE, Connection, Server, ServerPool, Tls
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars

        timeout = float(cfg.get("timeout") or 8)
        tls = Tls(validate=ssl.CERT_REQUIRED if cfg.get("verify_ssl", True) else ssl.CERT_NONE)
        servers = [
            Server(
                host,
                port=int(cfg.get("port") or (636 if cfg.get("use_ssl") else 389)),
                use_ssl=bool(cfg.get("use_ssl")),
                tls=tls,
                get_info=NONE,
                connect_timeout=timeout,
            )
            for host in cfg["servers"]
        ]
        pool = ServerPool(servers, FIRST, active=1, exhaust=True)
        bind_user = self._bind_name(cfg, username)
        conn = Connection(
            pool,
            user=bind_user,
            password=password,
            authentication=SIMPLE,
            receive_timeout=timeout,
            raise_exceptions=False,
            read_only=True,
            auto_referrals=False,
        )
        try:
            try:
                if not cfg.get("use_ssl") and cfg.get("start_tls"):
                    conn.open()
                    if not conn.start_tls():
                        return AuthResult(False, error="StartTLS negotiation failed")
                elif not cfg.get("use_ssl"):
                    log.warning("AD bind over plaintext LDAP; enable LDAPS or StartTLS")
                if not conn.bind():
                    desc = (conn.result or {}).get("description", "")
                    msg = (conn.result or {}).get("message", "")
                    log.info("AD bind rejected for %s: %s %s", bind_user, desc, msg)
                    if "data 775" in msg:
                        return AuthResult(False, error="Account locked out")
                    if "data 533" in msg or "data 532" in msg or "data 773" in msg:
                        return AuthResult(False, error="Account disabled or password expired")
                    return AuthResult(False, error="Invalid credentials")
            except LDAPException as exc:
                log.error("AD servers unreachable: %s", exc)
                return AuthResult(False, error="Directory unreachable")

            sam = bind_user.split("\\", 1)[-1].split("@", 1)[0]
            display = sam
            base_dn = cfg.get("base_dn") or ""
            if base_dn:
                user_filter = (
                    f"(&(objectCategory=person)(objectClass=user)"
                    f"(|(sAMAccountName={escape_filter_chars(sam)})(userPrincipalName={escape_filter_chars(bind_user)})))"
                )
                try:
                    if conn.search(base_dn, user_filter, SUBTREE, attributes=["displayName", "distinguishedName"], size_limit=1) and conn.entries:
                        entry = conn.entries[0]
                        names = entry.entry_attributes_as_dict.get("displayName") or []
                        display = str(names[0]) if names else sam
                        user_dn = str(entry.entry_dn)
                    else:
                        user_dn = ""
                except LDAPException as exc:
                    log.warning("AD user lookup failed: %s", exc)
                    user_dn = ""

                group = (cfg.get("required_group") or "").strip()
                if group:
                    group_dn = group if "=" in group else self._resolve_group(conn, base_dn, group)
                    if not group_dn or not user_dn:
                        return AuthResult(False, error="Not authorised (group membership could not be verified)")
                    member_filter = f"(&(distinguishedName={escape_filter_chars(user_dn)})(memberOf:{_IN_CHAIN}:={escape_filter_chars(group_dn)}))"
                    try:
                        if not (conn.search(base_dn, member_filter, SUBTREE, attributes=["cn"], size_limit=1) and conn.entries):
                            log.warning("User %s denied: not a member of %s", sam, group_dn)
                            return AuthResult(False, error="Not authorised for IIS Sentinel")
                    except LDAPException as exc:
                        log.warning("AD group check failed: %s", exc)
                        return AuthResult(False, error="Not authorised (group check failed)")
            elif cfg.get("required_group"):
                return AuthResult(False, error="Group restriction set but base DN not configured")

            log.info("AD login OK for %s", bind_user)
            return AuthResult(True, username=sam, display_name=display, source="ad")
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _resolve_group(conn: Any, base_dn: str, name: str) -> str:
        from ldap3 import SUBTREE
        from ldap3.utils.conv import escape_filter_chars

        flt = f"(&(objectClass=group)(|(cn={escape_filter_chars(name)})(sAMAccountName={escape_filter_chars(name)})))"
        try:
            if conn.search(base_dn, flt, SUBTREE, attributes=["distinguishedName"], size_limit=1) and conn.entries:
                return str(conn.entries[0].entry_dn)
        except Exception:  # noqa: BLE001
            log.exception("Failed to resolve AD group %s", name)
        return ""
