"""Windows Server / IIS health monitor.

Polls CPU, RAM and free space on the IIS log drive with psutil, IIS application pool runtime state through
WMI (root\\WebAdministration via pywin32) with an appcmd.exe fallback, and the W3SVC / WAS services.
Raises CRITICAL alerts when an app pool stops, W3SVC stops, or disk free space drops below the threshold,
and HIGH alerts when CPU exceeds the threshold.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil

from database import DATA_DIR, DEMO_MODE, IS_WINDOWS, LOCAL_SERVER_ID, ConfigStore, SystemMetric, iso, run_db, utcnow

if TYPE_CHECKING:
    from database import ServerRegistry
    from events import AlertManager, Hub
    from remote_manager import RemoteManager

log = logging.getLogger("sentinel.health")

POOL_STATES = {0: "Starting", 1: "Started", 2: "Stopping", 3: "Stopped", 4: "Unknown"}
_APPCMD_RE = re.compile(r'APPPOOL\s+"(?P<name>[^"]+)"\s+\((?P<attrs>[^)]*)\)')
_SERVICE_STATES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}


def _query_pools_wmi() -> dict[str, str]:
    import pythoncom  # type: ignore
    import win32com.client  # type: ignore

    pythoncom.CoInitialize()
    try:
        wmi = win32com.client.GetObject(
            r"winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\.\root\WebAdministration"
        )
        pools: dict[str, str] = {}
        for pool in wmi.InstancesOf("ApplicationPool"):
            name = str(pool.Name)
            try:
                out = pool.ExecMethod_("GetState")
                pools[name] = POOL_STATES.get(int(out.ReturnValue), "Unknown")
            except Exception:  # noqa: BLE001
                pools[name] = "Unknown"
        return pools
    finally:
        pythoncom.CoUninitialize()


def _query_pools_appcmd() -> dict[str, str]:
    appcmd = Path(os.environ.get("windir", r"C:\Windows")) / "System32" / "inetsrv" / "appcmd.exe"
    if not appcmd.exists():
        raise FileNotFoundError(str(appcmd))
    proc = subprocess.run(
        [str(appcmd), "list", "apppool"],
        capture_output=True,
        text=True,
        timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"appcmd exit code {proc.returncode}")
    pools: dict[str, str] = {}
    for m in _APPCMD_RE.finditer(proc.stdout):
        attrs = dict(a.split(":", 1) for a in m.group("attrs").split(",") if ":" in a)
        pools[m.group("name")] = attrs.get("state", "Unknown")
    return pools


def _service_state(name: str) -> str:
    try:
        import win32serviceutil  # type: ignore

        return _SERVICE_STATES.get(win32serviceutil.QueryServiceStatus(name)[1], "UNKNOWN")
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        if "1060" in str(exc):
            return "NOT_INSTALLED"
        log.debug("QueryServiceStatus(%s) failed: %s", name, exc)
    try:
        svc = psutil.win_service_get(name)  # type: ignore[attr-defined]
        return str(svc.status()).upper()
    except Exception:  # noqa: BLE001
        return "UNKNOWN"


class _ServerState:
    def __init__(self) -> None:
        self.pools: dict[str, str] = {}
        self.w3svc: str | None = None
        self.online: bool | None = None


class HealthMonitor:
    """Polls every monitored server concurrently: one task per server, each on its own interval and backoff."""

    RECONCILE_SECONDS = 5.0

    def __init__(self, config: ConfigStore, alerts: "AlertManager", hub: "Hub",
                 registry: "ServerRegistry", remote: "RemoteManager") -> None:
        self.config = config
        self.alerts = alerts
        self.hub = hub
        self.registry = registry
        self.remote = remote
        self.latest: dict[int, dict[str, Any]] = {}
        self._state: dict[int, _ServerState] = {}
        self._tasks: dict[int, tuple[tuple[Any, ...], asyncio.Task[None]]] = {}
        self._reconcile = asyncio.Event()
        self._pool_source = "none"
        self._pool_error: str | None = None
        self._demo_pools = {"DefaultAppPool": "Started", "IntranetPortal": "Started", "OrdersAPI": "Started", "ReportingSvc": "Started"}
        psutil.cpu_percent(interval=None)

    def reload(self) -> None:
        self._reconcile.set()

    def snapshot(self) -> list[dict[str, Any]]:
        out = []
        for server in self.registry.all(enabled_only=True):
            sid = server["id"]
            sample = self.latest.get(sid) or {
                "server_id": sid, "server_name": server["server_name"], "ip_address": server["ip_address"],
                "online": None, "error": None, "app_pools": [],
            }
            out.append(sample)
        return out

    # ------------------------------------------------------------------ local collection (worker thread)
    def _disk_path(self) -> str:
        for d in self.config.value("watchers", "log_dirs", []) or []:
            p = Path(d)
            while not p.exists() and p.parent != p:
                p = p.parent
            if p.exists():
                if IS_WINDOWS and p.anchor:
                    return p.anchor
                return str(p)
        return str(DATA_DIR)

    def _app_pools(self) -> dict[str, str]:
        if DEMO_MODE:
            for name in self._demo_pools:
                if self._demo_pools[name] == "Started" and random.random() < 0.01:
                    self._demo_pools[name] = "Stopped"
                elif self._demo_pools[name] == "Stopped" and random.random() < 0.3:
                    self._demo_pools[name] = "Started"
            self._pool_source = "demo"
            return dict(self._demo_pools)
        if not IS_WINDOWS:
            self._pool_source = "unavailable"
            self._pool_error = "Not running on Windows"
            return {}
        errors = []
        for source, fn in (("wmi", _query_pools_wmi), ("appcmd", _query_pools_appcmd)):
            try:
                pools = fn()
                self._pool_source = source
                self._pool_error = None
                return pools
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{source}: {type(exc).__name__}: {exc}")
        self._pool_source = "error"
        self._pool_error = "; ".join(errors)
        log.warning("Unable to query IIS app pools: %s", self._pool_error)
        return {}

    def _collect_local(self) -> dict[str, Any]:
        cpu = psutil.cpu_percent(interval=1.0)
        vm = psutil.virtual_memory()
        disk_path = self._disk_path()
        try:
            du = psutil.disk_usage(disk_path)
            disk_percent, free_percent, free_gb, total_gb = du.percent, 100.0 - du.percent, du.free / 1024**3, du.total / 1024**3
        except OSError as exc:
            log.warning("disk_usage(%s) failed: %s", disk_path, exc)
            disk_percent, free_percent, free_gb, total_gb = 0.0, 100.0, 0.0, 0.0
        pools = self._app_pools()
        if DEMO_MODE:
            w3svc = was = "RUNNING"
        elif IS_WINDOWS:
            w3svc, was = _service_state("W3SVC"), _service_state("WAS")
        else:
            w3svc = was = "N/A"
        boot = psutil.boot_time()
        return {
            "ts": iso(utcnow()),
            "cpu_percent": round(cpu, 1),
            "cpu_count": psutil.cpu_count() or 0,
            "ram_percent": round(vm.percent, 1),
            "ram_used_gb": round((vm.total - vm.available) / 1024**3, 2),
            "ram_total_gb": round(vm.total / 1024**3, 2),
            "disk_path": disk_path,
            "disk_percent": round(disk_percent, 1),
            "disk_free_percent": round(free_percent, 1),
            "disk_free_gb": round(free_gb, 2),
            "disk_total_gb": round(total_gb, 2),
            "app_pools": [{"name": k, "state": v, "running": v == "Started"} for k, v in sorted(pools.items())],
            "app_pool_source": self._pool_source,
            "app_pool_error": self._pool_error,
            "w3svc_state": w3svc,
            "was_state": was,
            "uptime_seconds": round(time.time() - boot),
            "hostname": socket.gethostname(),
        }

    def _filter_pools(self, sample: dict[str, Any]) -> None:
        wanted = [p.lower() for p in self.config.value("watchers", "app_pools", []) or []]
        pools = {p["name"]: p["state"] for p in sample.get("app_pools", [])}
        if wanted and pools:
            found = {k.lower(): k for k in pools}
            filtered = {found[w]: pools[found[w]] for w in wanted if w in found}
            for w in wanted:
                if w not in found:
                    filtered[w] = "Missing"
            pools = filtered
            sample["app_pools"] = [{"name": k, "state": v, "running": v == "Started"} for k, v in sorted(pools.items())]
        sample["pools_all_started"] = all(v == "Started" for v in pools.values()) if pools else True

    # ------------------------------------------------------------------ alerting
    async def _alert(self, server_id: int, severity: str, category: str, title: str, message: str, **kw: Any) -> None:
        if kw.get("dedup_key"):
            kw["dedup_key"] = f"{server_id}:{kw['dedup_key']}"
        await self.alerts.raise_alert(severity, category, title, message, server_id=server_id, **kw)

    async def _evaluate(self, server_id: int, s: dict[str, Any]) -> None:
        cfg = self.config.get("watchers")
        st = self._state.setdefault(server_id, _ServerState())
        explicit = bool(cfg.get("app_pools"))
        current = {p["name"]: p["state"] for p in s["app_pools"]}

        for name, state in current.items():
            prev = st.pools.get(name)
            down = state in ("Stopped", "Stopping", "Missing")
            if down and prev in (None, "Started", "Starting"):
                first_seen = prev is None
                await self._alert(
                    server_id, "CRITICAL" if (not first_seen or explicit) else "WARNING", "system",
                    f"IIS App Pool '{name}' is {state.upper()}",
                    f"Application pool '{name}' is {state}"
                    + (" (detected at startup)." if first_seen else f" (was {prev}). Sites in this pool are not serving requests."),
                    details={"app_pool": name, "state": state, "previous": prev, "source": s["app_pool_source"]},
                    dedup_key=f"pool:{name}:down", cooldown=60,
                )
            elif state == "Started" and prev in ("Stopped", "Stopping", "Missing"):
                await self._alert(server_id, "INFO", "recovery", f"IIS App Pool '{name}' recovered",
                                  f"Application pool '{name}' is running again (was {prev}).", details={"app_pool": name})
        if s["app_pool_source"] not in ("error", "unavailable") and not s.get("app_pool_error"):
            for name in set(st.pools) - set(current):
                await self._alert(server_id, "WARNING", "system", f"IIS App Pool '{name}' disappeared",
                                  f"Application pool '{name}' is no longer reported by IIS.", details={"app_pool": name},
                                  dedup_key=f"pool:{name}:gone", cooldown=3600)
            st.pools = current

        w3 = s["w3svc_state"]
        if w3 not in ("RUNNING", "N/A", "UNKNOWN", "NOT_INSTALLED") and st.w3svc in (None, "RUNNING"):
            await self._alert(server_id, "CRITICAL", "system", f"W3SVC (World Wide Web Publishing Service) is {w3}",
                              "The IIS web service is not running. All sites on this server are offline.",
                              details={"w3svc": w3, "was": s["was_state"]}, dedup_key="w3svc:down", cooldown=300)
        elif w3 == "RUNNING" and st.w3svc not in (None, "RUNNING", "N/A", "UNKNOWN"):
            await self._alert(server_id, "INFO", "recovery", "W3SVC is running again", "IIS web service recovered.")
        st.w3svc = w3

        if s["disk_free_percent"] < float(cfg["disk_free_critical"]) and s["disk_total_gb"] > 0:
            await self._alert(
                server_id, "CRITICAL", "system", f"Disk space critical on {s['disk_path']} ({s['disk_free_percent']:.1f}% free)",
                f"Only {s['disk_free_gb']:.2f} GB free of {s['disk_total_gb']:.1f} GB on the IIS log volume. "
                "IIS stops logging (and can stop serving) when the log volume fills up.",
                details={"disk_path": s["disk_path"], "free_gb": s["disk_free_gb"], "free_percent": s["disk_free_percent"]},
                dedup_key="disk:critical", cooldown=3600,
            )
        if s["cpu_percent"] > float(cfg["cpu_threshold"]):
            details: dict[str, Any] = {"cpu_percent": s["cpu_percent"]}
            if server_id == LOCAL_SERVER_ID:
                details["top_processes"] = self._top_processes()
            await self._alert(
                server_id, "HIGH", "system", f"CPU utilisation {s['cpu_percent']:.0f}% (threshold {cfg['cpu_threshold']}%)",
                "Sustained high CPU can indicate a runaway worker process (w3wp.exe) or a volumetric attack.",
                details=details, dedup_key="cpu:high", cooldown=900,
            )
        if s["ram_percent"] > float(cfg["ram_threshold"]):
            await self._alert(server_id, "WARNING", "system", f"Memory utilisation {s['ram_percent']:.0f}%",
                              f"{s['ram_used_gb']} GB of {s['ram_total_gb']} GB in use.",
                              details={"ram_percent": s["ram_percent"]}, dedup_key="ram:high", cooldown=1800)

    async def _connectivity(self, server: dict[str, Any], ok: bool, error: str | None) -> None:
        sid = server["id"]
        st = self._state.setdefault(sid, _ServerState())
        changed = self.registry.set_status(sid, "health", ok, error)
        if ok and st.online is False:
            log.info("[%s] WinRM health link restored", server["server_name"])
            await self._alert(sid, "INFO", "recovery", "Server reachable again", "Health telemetry restored.")
        elif not ok and changed:
            log.error("[%s] health poll failed: %s", server["server_name"], error)
            await self._alert(
                sid, "HIGH", "system", "Server unreachable",
                f"Sentinel cannot collect health from {server['server_name']} ({server['ip_address']}): {error}. "
                "Monitoring of the other servers continues.",
                details={"ip_address": server["ip_address"], "error": error}, dedup_key="unreachable", cooldown=1800,
            )
        st.online = ok

    @staticmethod
    def _top_processes(n: int = 5) -> list[str]:
        try:
            procs = sorted(
                psutil.process_iter(["name", "pid", "cpu_percent"]),
                key=lambda p: p.info.get("cpu_percent") or 0,
                reverse=True,
            )[:n]
            return [f"{p.info['name']} (pid {p.info['pid']}): {p.info.get('cpu_percent') or 0:.0f}%" for p in procs]
        except Exception:  # noqa: BLE001
            return []

    # ------------------------------------------------------------------ per-server loop
    async def poll_server(self, server: dict[str, Any]) -> dict[str, Any]:
        sid = server["id"]
        if server.get("local"):
            sample = await asyncio.wait_for(asyncio.to_thread(self._collect_local), timeout=60)
        else:
            sample = await self.remote.health(server)
        self._filter_pools(sample)
        sample.update({"server_id": sid, "server_name": server["server_name"], "ip_address": server["ip_address"],
                       "online": True, "error": None})
        self.latest[sid] = sample
        self.hub.broadcast({"type": "health", "server_id": sid, "server_name": server["server_name"], "data": sample})
        try:
            pools_json = json.dumps({p["name"]: p["state"] for p in sample["app_pools"]})

            async def _op(s):  # type: ignore[no-untyped-def]
                s.add(SystemMetric(
                    server_id=sid, ts=utcnow(), cpu_percent=sample["cpu_percent"], ram_percent=sample["ram_percent"],
                    disk_percent=sample["disk_percent"], disk_free_percent=sample["disk_free_percent"],
                    disk_free_gb=sample["disk_free_gb"], disk_path=str(sample["disk_path"])[:260], app_pools=pools_json,
                    pools_all_started=sample["pools_all_started"], w3svc_state=sample["w3svc_state"],
                    uptime_seconds=sample["uptime_seconds"],
                ))

            await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("[%s] failed to persist system metric", server["server_name"])
        await self._evaluate(sid, sample)
        return sample

    def _mark_offline(self, server: dict[str, Any], error: str) -> None:
        sid = server["id"]
        prev = self.latest.get(sid) or {}
        sample = {**prev, "server_id": sid, "server_name": server["server_name"], "ip_address": server["ip_address"],
                  "online": False, "error": error, "ts": iso(utcnow())}
        sample.setdefault("app_pools", [])
        self.latest[sid] = sample
        self.hub.broadcast({"type": "health", "server_id": sid, "server_name": server["server_name"], "data": sample})

    async def _server_loop(self, server_id: int) -> None:
        failures = 0
        while True:
            server = self.registry.get(server_id)
            if server is None:
                return
            started = time.monotonic()
            try:
                await self.poll_server(server)
                await self._connectivity(server, True, None)
                failures = 0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                failures += 1
                error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                self._mark_offline(server, error)
                await self._connectivity(server, False, error)
            interval = float(self.config.value("watchers", "health_interval", 60))
            if failures:
                interval = min(interval * (2 ** min(failures - 1, 3)), 600.0)
            await asyncio.sleep(max(1.0, interval - (time.monotonic() - started)))

    def _signature(self, server: dict[str, Any]) -> tuple[Any, ...]:
        return (server.get("ip_address"), server.get("winrm_username"), server.get("winrm_password"),
                server.get("winrm_transport"), server.get("winrm_port"), server.get("winrm_use_ssl"))

    def _reconcile_tasks(self) -> None:
        desired = {s["id"]: s for s in self.registry.all(enabled_only=True)}
        for sid in list(self._tasks):
            sig, task = self._tasks[sid]
            server = desired.get(sid)
            if server is None or sig != self._signature(server) or task.done():
                task.cancel()
                del self._tasks[sid]
                if server is None:
                    self.latest.pop(sid, None)
                    self._state.pop(sid, None)
                    self.hub.broadcast({"type": "health_removed", "server_id": sid})
        for sid, server in desired.items():
            if sid not in self._tasks:
                task = asyncio.create_task(self._server_loop(sid), name=f"health:{server['server_name']}")
                self._tasks[sid] = (self._signature(server), task)

    async def run(self) -> None:
        try:
            while True:
                self._reconcile_tasks()
                try:
                    await asyncio.wait_for(self._reconcile.wait(), timeout=self.RECONCILE_SECONDS)
                except asyncio.TimeoutError:
                    pass
                self._reconcile.clear()
        finally:
            for _sig, task in self._tasks.values():
                task.cancel()
            await asyncio.gather(*(t for _s, t in self._tasks.values()), return_exceptions=True)
            self._tasks.clear()
