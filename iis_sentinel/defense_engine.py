"""CIDR range bans: one block rule per range on Windows Firewall (netsh over WinRM), the SonicWall ban group, or both.

Single-IP bans keep going through firewall.FirewallManager (APPROVE BAN from the WHOIS dialog, BAN ALL); this module
adds subnet escalation on top of the same transports. Every range passes three pre-flight checks before anything is
pushed: strict ipaddress parsing (never broader than an IPv4 /16 or IPv6 /32), the allowlist (overlap in either
direction, so a nested range is caught), and the monitored servers' own addresses.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from typing import Any

from sqlalchemy import and_, select, update

from database import BannedRange, ConfigStore, ServerRegistry, allowlist_overlaps, parse_network, run_db, utcnow
from firewall import FirewallError, FirewallManager
from remote_manager import RemoteManager, validate_ban_network

log = logging.getLogger("sentinel.defense")

TARGETS = ("windows", "sonicwall", "both")


class DefenseEngine:
    def __init__(self, config: ConfigStore, registry: ServerRegistry, remote: RemoteManager, firewall: FirewallManager) -> None:
        self.config = config
        self.registry = registry
        self.remote = remote
        self.firewall = firewall
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ helpers
    def default_target(self) -> str:
        provider = self.firewall.provider()
        if provider == "sonicwall":
            return "both" if self.config.value("firewall", "also_windows", False) else "sonicwall"
        return "windows"

    def sonicwall_status(self) -> dict[str, Any]:
        """Whether SonicWall range bans can run (configured, even if not the active APPROVE BAN provider)."""
        try:
            client = self.firewall._client("sonicwall")
        except FirewallError as exc:
            return {"ready": False, "error": str(exc), "group": ""}
        return {"ready": True, "error": None, "group": client.group}

    def protected_servers(self, net: Any) -> list[str]:
        """Monitored servers whose address falls inside `net` (banning them would cut Sentinel off)."""
        hits = []
        for srv in self.registry.all(enabled_only=False):
            try:
                addr = ipaddress.ip_address(str(srv.get("ip_address", "")).strip())
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                hits.append(srv["server_name"])
        return hits

    def _windows_servers(self, server_id: int | None) -> list[dict[str, Any]]:
        if server_id is not None:
            srv = self.registry.get(server_id)
            return [srv] if srv else []
        return list(self.registry.all())

    async def preflight(self, cidr: str) -> dict[str, Any]:
        try:
            net = parse_network(validate_ban_network(cidr))
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "allowlist": [], "protected": []}
        allow = await allowlist_overlaps(str(net))
        protected = self.protected_servers(net)
        error = None
        if allow:
            error = "CIDR overlaps with allowlist entry: " + ", ".join(
                f"{a['ip_or_cidr']}{' (' + a['description'] + ')' if a['description'] else ''}" for a in allow[:3])
        elif protected:
            error = f"{net} contains monitored server(s) {', '.join(protected[:5])}"
        return {"ok": error is None, "error": error, "cidr": str(net), "allowlist": allow, "protected": protected}

    # ------------------------------------------------------------------ ban / unban
    async def execute_range_ban(self, cidr: str, scope: str, firewall_target: str, server_id: int | None = None, *,
                                reason: str = "", threat_score: float = 0.0, source_ips: list[str] | None = None,
                                alert_id: int | None = None, user: str = "") -> dict[str, Any]:
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            return {"success": False, "error": f"'{cidr}' is not a valid CIDR"}
        if firewall_target not in TARGETS:
            return {"success": False, "error": f"firewall_target must be one of {', '.join(TARGETS)}"}
        pre = await self.preflight(str(net))
        if not pre["ok"]:
            return {"success": False, "error": pre["error"], "allowlist": pre.get("allowlist", []),
                    "protected": pre.get("protected", [])}
        cidr = pre["cidr"]
        scope = scope or f"/{net.prefixlen}"

        async with self._lock:
            existing = await run_db(lambda s: self._active(s, cidr))
            if existing is not None:
                return {"success": True, "already": True, "id": existing["id"], "cidr": cidr, "scope": existing["scope"],
                        "firewall_target": existing["firewall_target"], "results": [],
                        "message": f"{cidr} is already banned (range #{existing['id']})"}

            results: list[dict[str, Any]] = []
            applied: dict[str, Any] = {"windows": [], "sonicwall": ""}
            if firewall_target in ("windows", "both"):
                servers = self._windows_servers(server_id)
                if not servers:
                    results.append({"target": "windows", "ok": False, "server": None,
                                    "message": "no monitored server to push the Windows Firewall rule to"})

                async def win(srv: dict[str, Any]) -> None:
                    try:
                        ok, out = await self.remote.ban_range(srv["id"], cidr)
                    except Exception as exc:  # noqa: BLE001
                        ok, out = False, f"{type(exc).__name__}: {exc}"
                    results.append({"target": "windows", "ok": ok, "server": srv["server_name"], "message": str(out)[:400]})
                    if ok:
                        applied["windows"].append(srv["id"])

                await asyncio.gather(*(win(srv) for srv in servers))
            if firewall_target in ("sonicwall", "both"):
                sw = self.sonicwall_status()
                if not sw["ready"]:
                    results.append({"target": "sonicwall", "ok": False, "server": None,
                                    "message": f"SonicWall is not configured: {sw['error']}"})
                else:
                    group = sw["group"]
                    try:
                        out = await self.firewall.sonicwall(lambda api: api.add_ip_to_group(group, cidr))
                        results.append({"target": "sonicwall", "ok": True, "server": None, "message": out})
                        applied["sonicwall"] = group
                    except Exception as exc:  # noqa: BLE001
                        results.append({"target": "sonicwall", "ok": False, "server": None,
                                        "message": f"{exc}" if isinstance(exc, FirewallError) else f"{type(exc).__name__}: {exc}"})

            if not applied["windows"] and not applied["sonicwall"]:
                return {"success": False, "cidr": cidr, "scope": scope, "firewall_target": firewall_target, "results": results,
                        "error": "; ".join(r["message"] for r in results if not r["ok"])[:600] or "nothing was applied"}

            ips = list(dict.fromkeys(source_ips or []))
            row = BannedRange(
                cidr_notation=cidr, scope=scope, reason=reason[:2000], threat_score=float(threat_score or 0),
                banned_at=utcnow(), is_active=True, source_ip_count=len(ips), source_ips=json.dumps(ips[:500]),
                server_id=server_id, firewall_target=firewall_target, applied=json.dumps(applied), alert_id=alert_id,
                banned_by=user, output="\n".join(f"[{r['target']}{' ' + r['server'] if r['server'] else ''}] "
                                                  f"{'OK' if r['ok'] else 'FAILED'}: {r['message']}" for r in results)[:4000],
            )

            async def _op(s):  # type: ignore[no-untyped-def]
                s.add(row)
                await s.flush()
                return row.id

            range_id = await run_db(_op)
        failed = [r for r in results if not r["ok"]]
        log.warning("RANGE BAN %s (%s) by %s via %s: %d ok, %d failed", cidr, scope, user, firewall_target,
                    len(results) - len(failed), len(failed))
        return {"success": True, "id": range_id, "cidr": cidr, "scope": scope, "firewall_target": firewall_target,
                "results": results, "partial": bool(failed), "applied": applied}

    @staticmethod
    async def _active(s: Any, cidr: str) -> dict[str, Any] | None:
        row = (await s.execute(select(BannedRange).where(
            and_(BannedRange.cidr_notation == cidr, BannedRange.is_active.is_(True))))).scalars().first()
        return {"id": row.id, "scope": row.scope, "firewall_target": row.firewall_target} if row else None

    async def lift_range_ban(self, range_id: int, user: str = "") -> dict[str, Any]:
        async with self._lock:
            async def _get(s):  # type: ignore[no-untyped-def]
                return await s.get(BannedRange, range_id)

            row = await run_db(_get)
            if row is None or not row.is_active:
                return {"success": False, "error": "Active range ban not found", "not_found": True}
            try:
                applied = json.loads(row.applied or "{}")
            except ValueError:
                applied = {}
            results: list[dict[str, Any]] = []
            for sid in applied.get("windows") or []:
                srv = self.registry.get(sid)
                if srv is None:
                    results.append({"target": "windows", "ok": True, "server": f"#{sid}", "message": "server no longer monitored"})
                    continue
                try:
                    ok, out = await self.remote.unban_range(sid, row.cidr_notation)
                    ok = ok or "No rules match" in out
                except Exception as exc:  # noqa: BLE001
                    ok, out = False, f"{type(exc).__name__}: {exc}"
                results.append({"target": "windows", "ok": ok, "server": srv["server_name"], "message": str(out)[:400]})
            group = applied.get("sonicwall")
            if group:
                try:
                    out = await self.firewall.sonicwall(lambda api: api.remove_ip_from_group(group, row.cidr_notation))
                    results.append({"target": "sonicwall", "ok": True, "server": None, "message": out})
                except Exception as exc:  # noqa: BLE001
                    results.append({"target": "sonicwall", "ok": False, "server": None, "message": str(exc)[:400]})
            failed = [r for r in results if not r["ok"]]
            if failed:
                return {"success": False, "results": results,
                        "error": "; ".join(f"{r['target']}{' ' + r['server'] if r['server'] else ''}: {r['message']}"
                                           for r in failed)[:600]}

            async def _op(s):  # type: ignore[no-untyped-def]
                await s.execute(update(BannedRange).where(BannedRange.id == range_id)
                                .values(is_active=False, lifted_at=utcnow(), lifted_by=user))

            await run_db(_op)
        log.warning("Range ban %s (%s) lifted by %s", range_id, row.cidr_notation, user)
        return {"success": True, "id": range_id, "cidr": row.cidr_notation, "results": results,
                "server_id": row.server_id, "firewall_target": row.firewall_target}
