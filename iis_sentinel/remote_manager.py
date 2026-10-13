"""Remote IIS server management: WinRM (pywinrm) health + firewall bans, and UNC log tailing.

The module-level functions are blocking and safe to call from worker threads:
    get_remote_health(server_ip, username, password, ...)  -> dict
    execute_remote_ban(server_ip, username, password, ip_to_ban, ...) -> (ok, output)
`RemoteManager` wraps them for asyncio with hard timeouts and per-server "busy" guards, so a server that
hangs (offline, SMB stall, WinRM timeout) can never pile up threads or stall monitoring of the others.
`RemoteManager.read_remote_logs(server_id)` tails a server's IIS logs over its UNC path.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import re
import subprocess
import time
from pathlib import Path, PureWindowsPath
from typing import Any

from database import IS_WINDOWS, LOCAL_SERVER_ID, ConfigStore, ServerRegistry, iso, utcnow
from log_tailer import DirectoryTailer

log = logging.getLogger("sentinel.remote")

BAN_RULE_PREFIX = "SENTINEL BAN: "

# Runs on the remote IIS server. Emits a single JSON object on stdout.
HEALTH_PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$logDir = $null
try {
    Import-Module WebAdministration -ErrorAction Stop
    $logDir = [Environment]::ExpandEnvironmentVariables((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
        -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name directory).Value)
} catch { }
$drive = if ($logDir -and $logDir -match '^[A-Za-z]:') { $logDir.Substring(0, 2) } else { $env:SystemDrive }
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'"
$pools = @()
$poolSource = 'none'
$poolError = $null
try {
    Import-Module IISAdministration -ErrorAction Stop
    $pools = @(Get-IISAppPool | ForEach-Object { [pscustomobject]@{ name = $_.Name; state = [string]$_.State } })
    $poolSource = 'IISAdministration'
} catch {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $pools = @(Get-ChildItem IIS:\AppPools | ForEach-Object { [pscustomobject]@{ name = $_.Name; state = [string]$_.State } })
        $poolSource = 'WebAdministration'
    } catch { $poolError = $_.Exception.Message }
}
function SvcState($n) { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; if ($s) { [string]$s.Status } else { 'NOT_INSTALLED' } }
[pscustomobject]@{
    hostname       = $env:COMPUTERNAME
    cpu_percent    = [double]$cpu
    cpu_count      = [int]$cs.NumberOfLogicalProcessors
    ram_total_kb   = [double]$os.TotalVisibleMemorySize
    ram_free_kb    = [double]$os.FreePhysicalMemory
    disk_path      = $drive
    disk_size      = [double]$disk.Size
    disk_free      = [double]$disk.FreeSpace
    pools          = $pools
    pool_source    = $poolSource
    pool_error     = $poolError
    w3svc          = SvcState 'W3SVC'
    was            = SvcState 'WAS'
    uptime_seconds = [double]((Get-Date) - $os.LastBootUpTime).TotalSeconds
} | ConvertTo-Json -Compress -Depth 4
"""


class RemoteError(RuntimeError):
    pass


def validate_ban_ip(ip: str) -> str:
    """Strictly parse the address; it is interpolated into a remote command line."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise ValueError(f"'{ip}' is not a valid IP address") from exc
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"refusing to ban {addr}: loopback/unspecified/multicast address")
    return str(addr)


def _endpoint(host: str, port: int, use_ssl: bool) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    return f"{'https' if use_ssl else 'http'}://{host}:{port}/wsman"


def _session(server_ip: str, username: str, password: str, *, transport: str = "ntlm", port: int | None = None,
             use_ssl: bool = False, verify_ssl: bool = True, timeout: int = 30) -> Any:
    try:
        import winrm
    except ImportError as exc:
        raise RemoteError("pywinrm is not installed") from exc
    return winrm.Session(
        _endpoint(server_ip, port or (5986 if use_ssl else 5985), use_ssl),
        auth=(username, password),
        transport=transport,
        server_cert_validation="validate" if verify_ssl else "ignore",
        operation_timeout_sec=max(5, timeout - 5),
        read_timeout_sec=timeout,
    )


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "cp437"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _gb(n: float) -> float:
    return round(n / 1024**3, 2)


def normalize_health(raw: dict[str, Any]) -> dict[str, Any]:
    pools = raw.get("pools") or []
    if isinstance(pools, dict):  # PowerShell 5.1 unrolls single-element arrays
        pools = [pools]
    total_kb = float(raw.get("ram_total_kb") or 0)
    free_kb = float(raw.get("ram_free_kb") or 0)
    size = float(raw.get("disk_size") or 0)
    free = float(raw.get("disk_free") or 0)
    disk_percent = round(100.0 * (size - free) / size, 1) if size else 0.0
    return {
        "hostname": raw.get("hostname") or "",
        "cpu_percent": round(float(raw.get("cpu_percent") or 0), 1),
        "cpu_count": int(raw.get("cpu_count") or 0),
        "ram_percent": round(100.0 * (total_kb - free_kb) / total_kb, 1) if total_kb else 0.0,
        "ram_used_gb": round((total_kb - free_kb) / 1024**2, 2),
        "ram_total_gb": round(total_kb / 1024**2, 2),
        "disk_path": str(raw.get("disk_path") or ""),
        "disk_percent": disk_percent,
        "disk_free_percent": round(100.0 - disk_percent, 1) if size else 100.0,
        "disk_free_gb": _gb(free),
        "disk_total_gb": _gb(size),
        "app_pools": [
            {"name": str(p.get("name")), "state": str(p.get("state") or "Unknown"), "running": str(p.get("state")) == "Started"}
            for p in pools if isinstance(p, dict) and p.get("name")
        ],
        "app_pool_source": f"winrm/{raw.get('pool_source') or 'none'}",
        "app_pool_error": raw.get("pool_error"),
        "w3svc_state": str(raw.get("w3svc") or "UNKNOWN").upper(),
        "was_state": str(raw.get("was") or "UNKNOWN").upper(),
        "uptime_seconds": round(float(raw.get("uptime_seconds") or 0)),
    }


def get_remote_health(server_ip: str, username: str, password: str, **opts: Any) -> dict[str, Any]:
    """Run the health PowerShell over WinRM; returns CPU/RAM/disk/app-pool/service state."""
    resp = _session(server_ip, username, password, **opts).run_ps(HEALTH_PS)
    out = _decode(resp.std_out).strip()
    if resp.status_code != 0:
        err = _decode(resp.std_err).strip() or out
        raise RemoteError(f"health script exited {resp.status_code}: {err[:500]}")
    line = next((ln for ln in reversed(out.splitlines()) if ln.strip().startswith("{")), "")
    if not line:
        raise RemoteError(f"health script returned no JSON: {out[:300]}")
    return normalize_health(json.loads(line))


def _netsh_args(action: str, ip: str) -> list[str]:
    name = f'name="{BAN_RULE_PREFIX}{ip}"'
    if action == "add":
        return ["advfirewall", "firewall", "add", "rule", name, "dir=in", "action=block", f"remoteip={ip}"]
    return ["advfirewall", "firewall", action, "rule", name]


def execute_remote_ban(server_ip: str, username: str, password: str, ip_to_ban: str, **opts: Any) -> tuple[bool, str]:
    """Add an inbound block rule `SENTINEL BAN: <ip>` on the remote server's Windows Firewall (idempotent)."""
    ip = validate_ban_ip(ip_to_ban)
    session = _session(server_ip, username, password, **opts)
    existing = session.run_cmd("netsh", _netsh_args("show", ip))
    if existing.status_code == 0 and ip.encode() in existing.std_out:
        return True, f"rule '{BAN_RULE_PREFIX}{ip}' already present"
    resp = session.run_cmd("netsh", _netsh_args("add", ip))
    output = (_decode(resp.std_out) + _decode(resp.std_err)).strip()
    return resp.status_code == 0, output or f"netsh exit code {resp.status_code}"


def execute_remote_unban(server_ip: str, username: str, password: str, ip_to_unban: str, **opts: Any) -> tuple[bool, str]:
    ip = validate_ban_ip(ip_to_unban)
    resp = _session(server_ip, username, password, **opts).run_cmd("netsh", _netsh_args("delete", ip))
    output = (_decode(resp.std_out) + _decode(resp.std_err)).strip()
    return resp.status_code == 0, output or f"netsh exit code {resp.status_code}"


def _local_netsh(action: str, ip: str) -> tuple[bool, str]:
    if not IS_WINDOWS:
        raise RemoteError("local firewall bans require Windows")
    proc = subprocess.run(["netsh", *_netsh_args(action, ip)], capture_output=True, text=True, timeout=30,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def _connect_unc(path: str, username: str, password: str) -> None:
    """Authenticate an SMB session to \\\\host\\share with the server's credentials (no password on any command line)."""
    if not IS_WINDOWS or not path.startswith("\\\\"):
        return
    parts = PureWindowsPath(path).parts
    share = parts[0].rstrip("\\") if parts else ""
    if not share or not username:
        return
    try:
        import win32netcon  # type: ignore
        import win32wnet  # type: ignore
    except ImportError:
        log.warning("pywin32 missing; relying on the service account's own access to %s", share)
        return
    try:
        win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, None, share, None, username, password, 0)
        log.info("SMB session established to %s as %s", share, username)
    except Exception as exc:  # noqa: BLE001
        # 1219: a session to this host already exists with other credentials; 85: already connected.
        if getattr(exc, "winerror", None) in (85, 1219) or "1219" in str(exc):
            return
        raise RemoteError(f"cannot authenticate to {share}: {exc}") from exc


def _friendly(exc: BaseException) -> RemoteError:
    """Turn transport-level exceptions (urllib3 / requests / pywinrm) into a one-line operator message."""
    name = type(exc).__name__
    text = str(exc)
    host = ""
    m = re.search(r"host='([^']+)', port=(\d+)", text)
    if m:
        host = f" {m.group(1)}:{m.group(2)}"
    if name in ("ConnectTimeout", "ConnectTimeoutError"):
        return RemoteError(f"WinRM{host} connect timeout (host down or TCP 5985/5986 firewalled)")
    if name == "ReadTimeout":
        return RemoteError(f"WinRM{host} read timeout (server too busy or script hung)")
    if name in ("ConnectionError", "NewConnectionError", "MaxRetryError"):
        if "refused" in text.lower():
            return RemoteError(f"WinRM{host} connection refused (WinRM service not listening; run 'winrm quickconfig')")
        if "name or service not known" in text.lower() or "getaddrinfo" in text.lower():
            return RemoteError(f"WinRM{host} DNS lookup failed")
        return RemoteError(f"WinRM{host} unreachable")
    if name == "SSLError":
        return RemoteError(f"WinRM{host} TLS error (certificate not trusted? set winrm_verify_ssl=false for self-signed)")
    if name == "InvalidCredentialsError":
        return RemoteError("WinRM authentication failed (check winrm_username / winrm_password)")
    if name in ("WinRMTransportError", "WinRMOperationTimeoutError", "WinRMError"):
        return RemoteError(f"WinRM error: {text[:300]}")
    if isinstance(exc, RemoteError):
        return exc
    return RemoteError(f"{name}: {text[:300]}")


class _Guard:
    """Tracks one in-flight worker per (server, op) so a hung call is never duplicated."""

    def __init__(self) -> None:
        self._inflight: dict[tuple[int, str], tuple[asyncio.Future[Any], float]] = {}

    async def run(self, key: tuple[int, str], limit: float, fn: Any, /, *args: Any, **kwargs: Any) -> Any:
        current = self._inflight.get(key)
        if current is not None and not current[0].done():
            raise RemoteError(f"previous {key[1]} call still running for {int(time.monotonic() - current[1])}s (server unresponsive)")
        fut = asyncio.ensure_future(asyncio.to_thread(fn, *args, **kwargs))
        self._inflight[key] = (fut, time.monotonic())
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=limit)
        except asyncio.TimeoutError as exc:
            raise RemoteError(f"{key[1]} timed out after {int(limit)}s") from exc
        except (asyncio.CancelledError, ValueError):
            raise
        except Exception as exc:  # noqa: BLE001
            raise _friendly(exc) from exc


class RemoteManager:
    def __init__(self, config: ConfigStore, registry: ServerRegistry) -> None:
        self.config = config
        self.registry = registry
        self._guard = _Guard()
        self._tailers: dict[int, tuple[tuple[Any, ...], DirectoryTailer]] = {}
        self._unc_ok: dict[int, float] = {}
        self._sim: dict[int, dict[str, Any]] = {}

    def _timeout(self) -> float:
        return float(self.config.value("watchers", "remote_timeout", 30))

    @staticmethod
    def _opts(server: dict[str, Any], timeout: float) -> dict[str, Any]:
        return {
            "transport": server.get("winrm_transport") or "ntlm",
            "port": server.get("winrm_port"),
            "use_ssl": bool(server.get("winrm_use_ssl")),
            "verify_ssl": bool(server.get("winrm_verify_ssl", True)),
            "timeout": int(timeout),
        }

    # ------------------------------------------------------------------ health
    async def health(self, server: dict[str, Any]) -> dict[str, Any]:
        if server.get("simulated"):
            return self._simulated_health(server)
        timeout = self._timeout()
        sample = await self._guard.run(
            (server["id"], "health"), timeout + 10, get_remote_health,
            server["ip_address"], server["winrm_username"], server["winrm_password"], **self._opts(server, timeout),
        )
        sample["ts"] = iso(utcnow())
        return sample

    def _simulated_health(self, server: dict[str, Any]) -> dict[str, Any]:
        sid = server["id"]
        st = self._sim.setdefault(sid, {
            "cpu": random.uniform(10, 40), "ram": random.uniform(40, 70), "disk": random.uniform(30, 80),
            "pools": {"DefaultAppPool": "Started", "OrdersAPI": "Started", f"{server['server_name']}-Portal": "Started"},
            "boot": time.time() - random.uniform(86400, 86400 * 40),
        })
        st["cpu"] = min(99.0, max(1.0, st["cpu"] + random.uniform(-8, 8) + (35 if random.random() < 0.02 else 0)))
        st["ram"] = min(97.0, max(20.0, st["ram"] + random.uniform(-2, 2)))
        for name, state in st["pools"].items():
            if state == "Started" and random.random() < 0.01:
                st["pools"][name] = "Stopped"
            elif state == "Stopped" and random.random() < 0.3:
                st["pools"][name] = "Started"
        total, used = 250.0, 250.0 * st["disk"] / 100
        return {
            "ts": iso(utcnow()), "hostname": server["server_name"], "cpu_percent": round(st["cpu"], 1), "cpu_count": 8,
            "ram_percent": round(st["ram"], 1), "ram_used_gb": round(32 * st["ram"] / 100, 2), "ram_total_gb": 32.0,
            "disk_path": "D:", "disk_percent": round(st["disk"], 1), "disk_free_percent": round(100 - st["disk"], 1),
            "disk_free_gb": round(total - used, 2), "disk_total_gb": total,
            "app_pools": [{"name": n, "state": s, "running": s == "Started"} for n, s in sorted(st["pools"].items())],
            "app_pool_source": "simulated", "app_pool_error": None, "w3svc_state": "RUNNING", "was_state": "RUNNING",
            "uptime_seconds": round(time.time() - st["boot"]),
        }

    # ------------------------------------------------------------------ logs
    def _tailer_for(self, server: dict[str, Any]) -> DirectoryTailer | None:
        path = (server.get("log_unc_path") or "").strip()
        if not path:
            return None
        cfg = self.config.get("watchers")
        sig = (path, cfg.get("file_pattern"), cfg.get("start_at_end"))
        current = self._tailers.get(server["id"])
        if current is None or current[0] != sig:
            tailer = DirectoryTailer(Path(path), cfg.get("file_pattern") or "*.log", bool(cfg.get("start_at_end", True)))
            self._tailers[server["id"]] = (sig, tailer)
            self._unc_ok.pop(server["id"], None)
            return tailer
        return current[1]

    def _poll_unc(self, server: dict[str, Any], tailer: DirectoryTailer) -> tuple[list[dict[str, Any]], bool]:
        sid = server["id"]
        if not server.get("simulated") and time.monotonic() - self._unc_ok.get(sid, 0) > 600:
            _connect_unc(server["log_unc_path"], server.get("winrm_username", ""), server.get("winrm_password", ""))
            self._unc_ok[sid] = time.monotonic()
        entries = tailer.poll()
        if tailer.status in ("missing", "access denied") or tailer.status.startswith("error"):
            self._unc_ok.pop(sid, None)
            raise RemoteError(f"log path {server['log_unc_path']}: {tailer.status}")
        return entries, tailer.has_more

    async def read_remote_logs(self, server_id: int) -> tuple[list[dict[str, Any]], bool]:
        """Read new W3C lines from the server's UNC log directory. Returns (entries, more_pending)."""
        server = self.registry.get(server_id)
        if server is None:
            raise RemoteError(f"server {server_id} is not registered")
        tailer = self._tailer_for(server)
        if tailer is None:
            return [], False
        return await self._guard.run((server_id, "logs"), self._timeout() + 30, self._poll_unc, server, tailer)

    def tailer_status(self, server_id: int) -> dict[str, Any] | None:
        current = self._tailers.get(server_id)
        return current[1].info() if current else None

    def forget(self, server_id: int) -> None:
        self._tailers.pop(server_id, None)
        self._unc_ok.pop(server_id, None)
        self._sim.pop(server_id, None)

    # ------------------------------------------------------------------ bans
    async def ban(self, server_id: int, ip: str) -> tuple[bool, str]:
        ip = validate_ban_ip(ip)
        server = self.registry.get(server_id)
        if server is None:
            raise RemoteError(f"server {server_id} is not registered")
        if server.get("simulated"):
            await asyncio.sleep(0.4)
            return True, f"[simulated] Ok. rule '{BAN_RULE_PREFIX}{ip}' added on {server['server_name']}"
        if server_id == LOCAL_SERVER_ID:
            return await self._guard.run((server_id, "ban"), 45, _local_netsh, "add", ip)
        timeout = self._timeout()
        return await self._guard.run(
            (server_id, "ban"), timeout + 15, execute_remote_ban,
            server["ip_address"], server["winrm_username"], server["winrm_password"], ip, **self._opts(server, timeout),
        )

    async def unban(self, server_id: int, ip: str) -> tuple[bool, str]:
        ip = validate_ban_ip(ip)
        server = self.registry.get(server_id)
        if server is None:
            raise RemoteError(f"server {server_id} is not registered")
        if server.get("simulated"):
            return True, f"[simulated] rule '{BAN_RULE_PREFIX}{ip}' deleted on {server['server_name']}"
        if server_id == LOCAL_SERVER_ID:
            return await self._guard.run((server_id, "unban"), 45, _local_netsh, "delete", ip)
        timeout = self._timeout()
        return await self._guard.run(
            (server_id, "unban"), timeout + 15, execute_remote_unban,
            server["ip_address"], server["winrm_username"], server["winrm_password"], ip, **self._opts(server, timeout),
        )

    async def test(self, server_id: int) -> dict[str, Any]:
        server = self.registry.get(server_id)
        if server is None:
            raise RemoteError(f"server {server_id} is not registered")
        result: dict[str, Any] = {"server_id": server_id, "server_name": server["server_name"]}
        try:
            sample = await self.health(server)
            result["winrm"] = {"ok": True, "hostname": sample.get("hostname"), "app_pools": len(sample.get("app_pools", []))}
        except Exception as exc:  # noqa: BLE001
            result["winrm"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if not server.get("log_unc_path"):
            result["logs"] = {"ok": False, "error": "no log_unc_path configured"}
            return result
        try:
            result["logs"] = await self._guard.run((server_id, "probe"), self._timeout() + 15, self._probe_unc, server)
        except Exception as exc:  # noqa: BLE001
            result["logs"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return result

    def _probe_unc(self, server: dict[str, Any]) -> dict[str, Any]:
        """Check the log share is reachable without consuming any lines from the live tailer."""
        path = Path(server["log_unc_path"])
        if not server.get("simulated"):
            _connect_unc(server["log_unc_path"], server.get("winrm_username", ""), server.get("winrm_password", ""))
        if not path.is_dir():
            return {"ok": False, "error": f"{path} is not reachable or not a directory"}
        pattern = self.config.value("watchers", "file_pattern", "u_ex*.log") or "*.log"
        files = sorted(path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        return {"ok": True, "files": len(files), "newest": files[0].name if files else None}
