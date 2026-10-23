"""Per-site / per-app-pool / per-server IIS resource metrics, pulled on demand over WinRM.

`RESOURCE_PS` runs on the IIS server and returns one JSON object with:
  * IIS configuration of the site (bindings, limits, applications) and its application pools
  * every counter of the IIS / ASP.NET / HTTP.sys performance counter sets, plus w3wp process counters
  * worker processes (memory, handles, threads, CPU) and the requests executing inside them right now
  * TCP connections on the site's ports, by state, by port and by remote client
`normalize_resources()` turns that into the structure the dashboard's RESOURCE MONITOR modal renders, and
`simulate_resources()` produces the same raw shape for the demo fleet.
"""
from __future__ import annotations

import base64
import random
import re
import subprocess
import time
from typing import Any

RESOURCE_KINDS = ("site", "pool", "server")

RESOURCE_PS = r"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$kind = '__KIND__'
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TARGET__'))
$sw = [Diagnostics.Stopwatch]::StartNew()
$notes = New-Object System.Collections.ArrayList
function Note($m) { [void]$notes.Add([string]$m) }
function U($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function Port($info) { $m = [regex]::Match([string]$info, ':(\d+):[^:]*$'); if ($m.Success) { [int]$m.Groups[1].Value } else { $null } }

$os = $null; $cs = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { Note ('CIM: ' + $_.Exception.Message) }

$sm = $null
try {
    [void][Reflection.Assembly]::LoadFrom("$env:windir\System32\inetsrv\Microsoft.Web.Administration.dll")
    $sm = New-Object Microsoft.Web.Administration.ServerManager
} catch { Note ('IIS configuration API unavailable: ' + $_.Exception.Message) }

$siteInfo = $null
$sitesOut = @()
$poolNames = @()
$siteIds = @()
$siteNames = @()
$ports = @()
if ($sm) {
    $allSites = @($sm.Sites)
    $chosen = @()
    if ($kind -eq 'site') {
        $chosen = @($allSites | Where-Object { [string]$_.Id -eq $target -or $_.Name -eq $target } | Select-Object -First 1)
        if (-not $chosen.Count) { Note "Site '$target' was not found on this server" }
    } elseif ($kind -eq 'pool') {
        $chosen = @($allSites | Where-Object { @($_.Applications | Where-Object { $_.ApplicationPoolName -eq $target }).Count })
        $poolNames += $target
    } else {
        $chosen = $allSites
        $poolNames += @($sm.ApplicationPools | ForEach-Object { $_.Name })
    }
    foreach ($s in $chosen) {
        $state = 'Unknown'; try { $state = [string]$s.State } catch { }
        $apps = @()
        foreach ($a in $s.Applications) {
            $vd = $a.VirtualDirectories | Where-Object { $_.Path -eq '/' } | Select-Object -First 1
            $pp = ''; if ($vd) { $pp = [Environment]::ExpandEnvironmentVariables([string]$vd.PhysicalPath) }
            $apps += [pscustomobject]@{ path = $a.Path; pool = $a.ApplicationPoolName; physical_path = $pp }
            if ($kind -eq 'site') { $poolNames += $a.ApplicationPoolName }
        }
        $binds = @()
        foreach ($b in $s.Bindings) {
            $p = Port $b.BindingInformation
            if ($p -and ($b.Protocol -eq 'http' -or $b.Protocol -eq 'https')) { $ports += $p }
            $binds += [pscustomobject]@{ protocol = $b.Protocol; info = $b.BindingInformation; host = $b.Host; port = $p
                                         sni = [bool]($b.SslFlags -band 1) }
        }
        $siteIds += [int]$s.Id
        $siteNames += $s.Name
        $logDir = ''; try { $logDir = [Environment]::ExpandEnvironmentVariables([string]$s.LogFile.Directory) } catch { }
        $o = [pscustomobject]@{
            id = [int]$s.Id; name = $s.Name; state = $state; auto_start = [bool]$s.ServerAutoStart
            bindings = $binds; applications = $apps
            max_connections = [double]$s.Limits.MaxConnections; max_bandwidth = [double]$s.Limits.MaxBandwidth
            connection_timeout_s = [double]$s.Limits.ConnectionTimeout.TotalSeconds
            log_dir = $logDir; log_enabled = [bool]$s.LogFile.Enabled
            log_folder = ('W3SVC{0}' -f $s.Id)
        }
        if ($kind -eq 'site') { $siteInfo = $o } else { $sitesOut += $o }
    }
}
$poolNames = @($poolNames | Where-Object { $_ } | Select-Object -Unique)
if (-not $ports.Count) { $ports = @(80, 443) }
$ports = @($ports | Select-Object -Unique)

$pools = @()
$wpList = @()
if ($sm) {
    foreach ($pn in $poolNames) {
        $p = $sm.ApplicationPools[$pn]
        if (-not $p) { Note "Application pool '$pn' was not found"; continue }
        $pstate = 'Unknown'; try { $pstate = [string]$p.State } catch { }
        $wps = @()
        try { foreach ($w in $p.WorkerProcesses) { $wps += [pscustomobject]@{ pid = [int]$w.ProcessId; state = [string]$w.State }; $wpList += $w } } catch { Note ("Worker processes of '$pn': " + $_.Exception.Message) }
        $rc = $p.Recycling.PeriodicRestart
        $sched = @(); try { $sched = @($rc.Schedule | ForEach-Object { $_.Time.ToString() }) } catch { }
        $pools += [pscustomobject]@{
            name = $p.Name; state = $pstate; runtime = [string]$p.ManagedRuntimeVersion; pipeline = [string]$p.ManagedPipelineMode
            enable32 = [bool]$p.Enable32BitAppOnWin64; auto_start = [bool]$p.AutoStart; start_mode = [string]$p.StartMode
            queue_length = [double]$p.QueueLength; identity = [string]$p.ProcessModel.IdentityType; user = [string]$p.ProcessModel.UserName
            idle_timeout_min = [double]$p.ProcessModel.IdleTimeout.TotalMinutes; max_processes = [double]$p.ProcessModel.MaxProcesses
            recycle_minutes = [double]$rc.Time.TotalMinutes; recycle_requests = [double]$rc.Requests
            recycle_memory_kb = [double]$rc.Memory; recycle_private_kb = [double]$rc.PrivateMemory; recycle_schedule = $sched
            cpu_limit = [double]$p.Cpu.Limit; cpu_action = [string]$p.Cpu.Action; rapid_fail = [bool]$p.Failure.RapidFailProtection
            rapid_fail_max = [double]$p.Failure.RapidFailProtectionMaxCrashes
            workers = $wps
        }
    }
}

$procs = @()
foreach ($w in $wpList) {
    try {
        $gp = Get-Process -Id $w.ProcessId -ErrorAction Stop
        $procs += [pscustomobject]@{
            pid = [int]$gp.Id; pool = $w.AppPoolName; working_set = [double]$gp.WorkingSet64; private_bytes = [double]$gp.PrivateMemorySize64
            virtual_bytes = [double]$gp.VirtualMemorySize64; peak_working_set = [double]$gp.PeakWorkingSet64
            handles = [int]$gp.HandleCount; threads = [int]$gp.Threads.Count; cpu_seconds = [double]$gp.TotalProcessorTime.TotalSeconds
            started = U $gp.StartTime
        }
    } catch { }
}

$reqs = @()
$reqError = $null
foreach ($w in $wpList) {
    try {
        foreach ($r in $w.GetRequests(0)) {
            if ($kind -eq 'site' -and $siteIds -notcontains [int]$r.SiteId) { continue }
            $reqs += [pscustomobject]@{ pid = [int]$w.ProcessId; pool = $w.AppPoolName; site_id = [int]$r.SiteId; verb = $r.Verb
                                        url = $r.Url; host = $r.HostName; client = $r.ClientIPAddr; elapsed_ms = [double]$r.TimeElapsed
                                        stage = [string]$r.PipelineState; module = $r.CurrentModule }
        }
    } catch { $reqError = $_.Exception.Message }
}
if ($reqError) { Note ('Requests in flight unavailable (install the IIS "Request Monitor" role service to see them): ' + $reqError) }
$reqs = @($reqs | Sort-Object elapsed_ms -Descending | Select-Object -First 200)

$wantSets = @('Web Service', 'Web Service Cache', 'APP_POOL_WAS', 'W3SVC_W3WP', 'HTTP Service Request Queues', 'HTTP Service Url Groups',
              'HTTP Service', 'ASP.NET Applications', 'ASP.NET', 'ASP.NET v4.0.30319', 'ASP.NET Apps v4.0.30319',
              'Processor', 'Memory', 'System', 'TCPv4', 'TCPv6', 'PhysicalDisk', 'Process', 'Network Interface')
$have = @{}
foreach ($set in @(Get-Counter -ListSet $wantSets -ErrorAction SilentlyContinue)) { $have[$set.CounterSetName] = $set }
$paths = @()
foreach ($n in @('Web Service', 'Web Service Cache', 'APP_POOL_WAS', 'W3SVC_W3WP', 'HTTP Service Request Queues', 'HTTP Service',
                 'ASP.NET Applications', 'ASP.NET', 'ASP.NET v4.0.30319', 'ASP.NET Apps v4.0.30319')) {
    if ($have.ContainsKey($n)) { $paths += @($have[$n].Paths) }
}
if ($kind -eq 'server' -and $have.ContainsKey('HTTP Service Url Groups')) { $paths += @($have['HTTP Service Url Groups'].Paths) }
$generic = @{
    'Processor' = @('\Processor(_Total)\% Processor Time', '\Processor(_Total)\% Privileged Time', '\Processor(_Total)\% Interrupt Time')
    'Memory' = @('\Memory\Available MBytes', '\Memory\% Committed Bytes In Use', '\Memory\Pages/sec', '\Memory\Committed Bytes', '\Memory\Pool Nonpaged Bytes')
    'System' = @('\System\Processor Queue Length', '\System\Context Switches/sec', '\System\Processes', '\System\Threads')
    'TCPv4' = @('\TCPv4\Connections Established', '\TCPv4\Connection Failures', '\TCPv4\Connections Reset', '\TCPv4\Segments Retransmitted/sec')
    'TCPv6' = @('\TCPv6\Connections Established')
    'PhysicalDisk' = @('\PhysicalDisk(_Total)\% Disk Time', '\PhysicalDisk(_Total)\Avg. Disk Queue Length', '\PhysicalDisk(_Total)\Avg. Disk sec/Read', '\PhysicalDisk(_Total)\Avg. Disk sec/Write')
    'Network Interface' = @('\Network Interface(*)\Bytes Total/sec', '\Network Interface(*)\Current Bandwidth', '\Network Interface(*)\Output Queue Length')
    'Process' = @('\Process(w3wp*)\% Processor Time', '\Process(w3wp*)\ID Process', '\Process(w3wp*)\IO Data Bytes/sec', '\Process(w3wp*)\Page Faults/sec')
}
foreach ($k in $generic.Keys) { if ($have.ContainsKey($k)) { $paths += $generic[$k] } }
$samples = New-Object System.Collections.ArrayList
if ($paths.Count) {
    try {
        $cs2 = (Get-Counter -Counter $paths -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples
        foreach ($c in $cs2) {
            $m = [regex]::Match($c.Path, '^\\\\[^\\]*\\([^\\(]+)(?:\((.*)\))?\\([^\\]+)$')
            if (-not $m.Success) { continue }
            [void]$samples.Add(@($m.Groups[1].Value, [string]$c.InstanceName, $m.Groups[3].Value, [double]$c.CookedValue))
        }
    } catch { Note ('Performance counters: ' + $_.Exception.Message) }
} else { Note 'No IIS performance counter sets were found on this server' }

$tcp = $null
try {
    $conns = @(Get-NetTCPConnection -LocalPort $ports -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Listen' })
    $est = @($conns | Where-Object { [string]$_.State -eq 'Established' })
    $tcp = [pscustomobject]@{
        source = 'Get-NetTCPConnection'; ports = $ports; total = $conns.Count; established = $est.Count
        unique_clients = @($est | Select-Object -ExpandProperty RemoteAddress -Unique).Count
        by_state = @($conns | Group-Object { [string]$_.State } | ForEach-Object { [pscustomobject]@{ state = $_.Name; count = $_.Count } })
        by_port = @($est | Group-Object LocalPort | ForEach-Object { [pscustomobject]@{ port = [int]$_.Name; count = $_.Count } })
        top_clients = @($est | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 25 |
                        ForEach-Object { [pscustomobject]@{ ip = $_.Name; count = $_.Count } })
    }
} catch {
    try {
        $rows = @()
        foreach ($ln in (netstat -ano -p tcp)) {
            $f = -split $ln
            if ($f.Count -lt 4 -or $f[0] -ne 'TCP') { continue }
            $lp = [int]($f[1] -replace '^.*:', '')
            if ($ports -notcontains $lp -or $f[3] -eq 'LISTENING') { continue }
            $rows += [pscustomobject]@{ port = $lp; ip = ($f[2] -replace ':\d+$', '').Trim('[', ']'); state = $f[3] }
        }
        $est = @($rows | Where-Object { $_.state -eq 'ESTABLISHED' })
        $tcp = [pscustomobject]@{
            source = 'netstat'; ports = $ports; total = $rows.Count; established = $est.Count
            unique_clients = @($est | Select-Object -ExpandProperty ip -Unique).Count
            by_state = @($rows | Group-Object state | ForEach-Object { [pscustomobject]@{ state = $_.Name; count = $_.Count } })
            by_port = @($est | Group-Object port | ForEach-Object { [pscustomobject]@{ port = [int]$_.Name; count = $_.Count } })
            top_clients = @($est | Group-Object ip | Sort-Object Count -Descending | Select-Object -First 25 |
                            ForEach-Object { [pscustomobject]@{ ip = $_.Name; count = $_.Count } })
        }
    } catch { Note ('TCP connections: ' + $_.Exception.Message) }
}

[pscustomobject]@{
    kind = $kind; target = $target; hostname = $env:COMPUTERNAME
    os = $(if ($os) { $os.Caption } else { '' }); cpu_count = $(if ($cs) { [int]$cs.NumberOfLogicalProcessors } else { 0 })
    ram_total_kb = $(if ($os) { [double]$os.TotalVisibleMemorySize } else { 0 }); ram_free_kb = $(if ($os) { [double]$os.FreePhysicalMemory } else { 0 })
    uptime_seconds = $(if ($os) { [double]((Get-Date) - $os.LastBootUpTime).TotalSeconds } else { 0 })
    site = $siteInfo; sites = $sitesOut; site_ids = $siteIds; site_names = $siteNames; pools = $pools
    processes = $procs; requests = $reqs; counters = $samples; tcp = $tcp
    notes = @($notes); duration_ms = [int]$sw.ElapsedMilliseconds
} | ConvertTo-Json -Compress -Depth 6
"""


def build_script(kind: str, target: str) -> str:
    if kind not in RESOURCE_KINDS:
        raise ValueError(f"kind must be one of {', '.join(RESOURCE_KINDS)}")
    encoded = base64.b64encode(target.encode("utf-8")).decode("ascii")
    return RESOURCE_PS.replace("__KIND__", kind).replace("__TARGET__", encoded)


def run_local(kind: str, target: str, timeout: float) -> str:
    proc = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"],
        input=build_script(kind, target), capture_output=True, text=True, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0 and "{" not in proc.stdout:
        raise RuntimeError(f"resource script exited {proc.returncode}: {(proc.stderr or proc.stdout)[:500]}")
    return proc.stdout


# ---------------------------------------------------------------------------- normalization

def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


SET_TITLES = {
    "web service": "Web Service (connections, requests, bytes)",
    "web service cache": "Web Service Cache (kernel / file / URI cache)",
    "app_pool_was": "Application Pool (WAS)",
    "w3svc_w3wp": "Worker Process (W3SVC_W3WP)",
    "http service request queues": "HTTP.sys Request Queue",
    "http service url groups": "HTTP.sys URL Groups",
    "http service": "HTTP.sys Service",
    "asp.net applications": "ASP.NET Application",
    "asp.net apps v4.0.30319": "ASP.NET v4 Application",
    "asp.net": "ASP.NET (global)",
    "asp.net v4.0.30319": "ASP.NET v4 (global)",
    "process": "w3wp Process",
    "processor": "Processor",
    "memory": "Memory",
    "system": "System",
    "tcpv4": "TCPv4",
    "tcpv6": "TCPv6",
    "physicaldisk": "Physical Disk",
    "network interface": "Network Interface",
}
SET_ORDER = list(SET_TITLES)

_KEEP_CASE = {"asp.net": "ASP.NET", "url": "URL", "uri": "URI", "cgi": "CGI", "isapi": "ISAPI", "io": "IO", "id": "ID",
              "ws": "WS", "http": "HTTP", "sec": "sec", "mbytes": "MBytes", "kbytes": "KBytes", "was": "WAS",
              "nonanonymous": "NonAnonymous", "wpi": "WPI", "tcpv4": "TCPv4", "tcpv6": "TCPv6"}
# HTTP.sys counters are CamelCase without spaces; Get-Counter returns them lower-cased.
_HTTPSYS = ["ArrivalRate", "CacheHitRate", "CurrentQueueSize", "MaxQueueItemAge", "RejectedRequests", "RejectionRate",
            "CurrentConnections", "MaxConnections", "ConnectionAttempts", "BytesSentRate", "BytesReceivedRate",
            "BytesTransferredRate", "GetRequestsRate", "HeadRequestsRate", "AllRequestsRate", "AllRequests",
            "SendErrors", "SendRate", "TotalUrisCached", "UriCacheHits", "UriCacheMisses", "UriCacheFlushes",
            "CurrentUrisCached", "BytesSent", "BytesReceived", "BytesTransferred", "GetRequests", "HeadRequests"]
_KEEP_CASE.update({n.lower(): n for n in _HTTPSYS})


def counter_label(name: str) -> str:
    def word(w: str) -> str:
        if "/" in w:
            return "/".join(word(p) for p in w.split("/"))
        return _KEEP_CASE.get(w.lower(), w[:1].upper() + w[1:])
    return " ".join(word(w) for w in name.split(" "))


def counter_unit(name: str) -> str:
    n = name.lower()
    if n.startswith("%") or n.endswith("%") or "ratio" in n:
        return "%"
    if n in ("request execution time", "request wait time"):
        return "ms"
    if "uptime" in n or "time since" in n or n == "maxqueueitemage" or n.startswith("avg. disk sec"):
        return "s"
    if "mbytes" in n:
        return "MB"
    if "bytes" in n or "memory usage" in n:
        return "B/s" if ("/sec" in n or "rate" in n) else "B"
    if n == "current bandwidth":
        return "bit/s"
    if "/sec" in n or "/ sec" in n or n.endswith("rate"):
        return "/s"
    return ""


POOL_STATES = {1: "Uninitialized", 2: "Initialized", 3: "Running", 4: "Disabling", 5: "Disabled", 6: "Shutdown pending",
               7: "Delete pending"}


def _inst_lower(i: Any) -> str:
    return str(i or "").lower()


def _relevant(kind: str, set_name: str, inst: str, site_names: set[str], site_ids: set[int], pools: set[str],
              pids: set[int], w3wp_instances: set[str]) -> bool:
    if kind == "server":
        return set_name != "process" or inst in w3wp_instances
    if set_name == "web service":
        return inst in site_names or inst == "_total"
    if set_name in ("app_pool_was", "http service request queues"):
        return inst in pools
    if set_name == "w3svc_w3wp":
        m = re.match(r"^(\d+)_(.+)$", inst)
        return bool(m) and (m.group(2) in pools or int(m.group(1)) in pids)
    if set_name in ("asp.net applications", "asp.net apps v4.0.30319"):
        return any(inst.startswith(f"_lm_w3svc_{i}_") for i in site_ids)
    if set_name == "process":
        return inst in w3wp_instances
    return True


def normalize_resources(raw: dict[str, Any], *, server_id: int, server_name: str, source: str) -> dict[str, Any]:
    kind = str(raw.get("kind") or "server")
    cpu_count = int(raw.get("cpu_count") or 0) or 1
    notes = [str(n) for n in _list(raw.get("notes")) if n]

    site = raw.get("site") if isinstance(raw.get("site"), dict) else None
    sites = [s for s in _list(raw.get("sites")) if isinstance(s, dict)]
    for s in ([site] if site else []) + sites:
        s["bindings"] = [b for b in _list(s.get("bindings")) if isinstance(b, dict)]
        s["applications"] = [a for a in _list(s.get("applications")) if isinstance(a, dict)]
        if (s.get("max_connections") or 0) >= 4294967295:
            s["max_connections"] = None
        if (s.get("max_bandwidth") or 0) >= 4294967295:
            s["max_bandwidth"] = None
    pools = [p for p in _list(raw.get("pools")) if isinstance(p, dict)]
    pool_names = {str(p.get("name") or "").lower() for p in pools}
    site_names = {str(n).lower() for n in _list(raw.get("site_names"))}
    site_ids = {int(i) for i in _list(raw.get("site_ids")) if str(i).lstrip("-").isdigit()}

    procs = {int(p["pid"]): p for p in _list(raw.get("processes")) if isinstance(p, dict) and p.get("pid") is not None}
    for p in pools:
        p["workers"] = [w for w in _list(p.get("workers")) if isinstance(w, dict)]
        p["recycle_schedule"] = [str(x) for x in _list(p.get("recycle_schedule"))]

    raw_samples = [c for c in _list(raw.get("counters")) if isinstance(c, list) and len(c) >= 4]
    # Map w3wp / w3wp#1 ... process instances to PIDs via the "id process" counter.
    inst_pid: dict[str, int] = {}
    for s_name, inst, ctr, val in (c[:4] for c in raw_samples):
        if str(s_name).lower() == "process" and str(ctr).lower() == "id process":
            inst_pid[_inst_lower(inst)] = int(val or 0)
    w3wp = {i for i, pid in inst_pid.items() if kind == "server" or pid in procs}
    pids = set(procs)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for s_name, inst, ctr, val in (c[:4] for c in raw_samples):
        set_name, inst_l = str(s_name).lower(), _inst_lower(inst)
        if not _relevant(kind, set_name, inst_l, site_names, site_ids, pool_names, pids, w3wp):
            continue
        try:
            v = float(val)
        except (TypeError, ValueError):
            continue
        row = {"name": counter_label(str(ctr)), "key": str(ctr).lower(), "value": round(v, 3), "unit": counter_unit(str(ctr))}
        if row["key"] == "current application pool state":
            row["text"] = POOL_STATES.get(int(v), str(int(v)))
        groups.setdefault((set_name, str(inst or "")), []).append(row)

    def val(set_name: str, inst: str, ctr: str) -> float | None:
        for (s, i), rows in groups.items():
            if s == set_name and i.lower() == inst.lower():
                return next((r["value"] for r in rows if r["key"] == ctr), None)
        return None

    def total(set_name: str, ctr: str, pred: Any = None) -> float | None:
        vals = [r["value"] for (s, i), rows in groups.items() if s == set_name and (pred is None or pred(i.lower()))
                for r in rows if r["key"] == ctr]
        return round(sum(vals), 3) if vals else None

    # Per-process enrichment: CPU % from the Process counter set, W3SVC_W3WP counters by PID.
    for inst, pid in inst_pid.items():
        if pid in procs:
            cpu = val("process", inst, "% processor time")
            if cpu is not None:
                procs[pid]["cpu_percent"] = round(cpu / cpu_count, 1)
            io = val("process", inst, "io data bytes/sec")
            if io is not None:
                procs[pid]["io_bytes_per_sec"] = io
    for (s, inst), rows in groups.items():
        m = re.match(r"^(\d+)_", inst)
        if s == "w3svc_w3wp" and m and int(m.group(1)) in procs:
            d = {r["key"]: r["value"] for r in rows}
            procs[int(m.group(1))].update({
                "active_requests": d.get("active requests"), "requests_per_sec": d.get("requests / sec"),
                "total_requests": d.get("total http requests served"), "active_threads": d.get("active threads count"),
            })
    for p in pools:
        for w in p["workers"]:
            w.update(procs.get(int(w.get("pid") or 0), {}))

    pool_match = (lambda i: i in pool_names) if kind != "server" else (lambda i: True)
    in_sites = (lambda i: i in site_names) if kind != "server" else (lambda i: i != "_total")
    w3 = (lambda i: bool(re.match(r"^\d+_", i)))
    if kind == "site":
        ws_inst = (site or {}).get("name") or ""
        current = val("web service", ws_inst, "current connections")
        peak = val("web service", ws_inst, "maximum connections")
        rps = val("web service", ws_inst, "total method requests/sec")
        bps = val("web service", ws_inst, "bytes total/sec")
        users = (val("web service", ws_inst, "current anonymous users") or 0) + (val("web service", ws_inst, "current nonanonymous users") or 0)
    else:
        current = total("web service", "current connections", in_sites)
        peak = total("web service", "maximum connections", in_sites)
        rps = total("web service", "total method requests/sec", in_sites)
        bps = total("web service", "bytes total/sec", in_sites)
        users = (total("web service", "current anonymous users", in_sites) or 0) + (total("web service", "current nonanonymous users", in_sites) or 0)
    worker_list = [procs[pid] for pid in procs]
    tcp = raw.get("tcp") if isinstance(raw.get("tcp"), dict) else None
    if tcp:
        for k in ("by_state", "by_port", "top_clients", "ports"):
            tcp[k] = _list(tcp.get(k))
    requests = [r for r in _list(raw.get("requests")) if isinstance(r, dict)]
    asp_queued = total("asp.net", "requests queued")
    if asp_queued is None:
        asp_queued = total("asp.net v4.0.30319", "requests queued")

    headline = {
        "current_connections": current,
        "peak_connections": peak,
        "current_users": users if current is not None else None,
        "active_requests": total("w3svc_w3wp", "active requests", w3),
        "requests_in_flight": None if any("Request Monitor" in n for n in notes) else len(requests),
        "http_queue": total("http service request queues", "currentqueuesize", pool_match),
        "http_rejected": total("http service request queues", "rejectedrequests", pool_match),
        "asp_queued": asp_queued,
        "requests_per_sec": rps,
        "bytes_per_sec": bps,
        "tcp_established": tcp.get("established") if tcp else None,
        "unique_clients": tcp.get("unique_clients") if tcp else None,
        "w3wp_cpu_percent": round(sum(p.get("cpu_percent") or 0 for p in worker_list), 1) if worker_list else None,
        "w3wp_private_bytes": sum(p.get("private_bytes") or 0 for p in worker_list) if worker_list else None,
        "w3wp_working_set": sum(p.get("working_set") or 0 for p in worker_list) if worker_list else None,
        "worker_processes": len(worker_list),
        "pool_recycles": total("app_pool_was", "total application pool recycles", pool_match),
        "worker_failures": total("app_pool_was", "total worker process failures", pool_match),
    }
    if kind != "server":
        headline["server_current_connections"] = val("web service", "_Total", "current connections")

    order = {s: n for n, s in enumerate(SET_ORDER)}
    counter_groups = [
        {"set": s, "instance": i, "title": SET_TITLES.get(s, counter_label(s)) + (f" :: {i}" if i else ""),
         "rows": sorted(rows, key=lambda r: r["name"].lower())}
        for (s, i), rows in sorted(groups.items(), key=lambda kv: (order.get(kv[0][0], 99), kv[0][1] != "_total", kv[0][1].lower()))
    ]
    total_kb = float(raw.get("ram_total_kb") or 0)
    free_kb = float(raw.get("ram_free_kb") or 0)
    return {
        "kind": kind,
        "target": str(raw.get("target") or ""),
        "server_id": server_id,
        "server_name": server_name,
        "hostname": str(raw.get("hostname") or ""),
        "source": source,
        "duration_ms": int(raw.get("duration_ms") or 0),
        "host": {
            "os": str(raw.get("os") or ""), "cpu_count": int(raw.get("cpu_count") or 0),
            "cpu_percent": val("processor", "_Total", "% processor time"),
            "ram_total_bytes": total_kb * 1024, "ram_used_bytes": (total_kb - free_kb) * 1024,
            "uptime_seconds": round(float(raw.get("uptime_seconds") or 0)),
        },
        "headline": headline,
        "site": site,
        "sites": sites,
        "pools": pools,
        "processes": worker_list,
        "requests": requests,
        "tcp": tcp,
        "counter_groups": counter_groups,
        "counter_count": sum(len(g["rows"]) for g in counter_groups),
        "notes": notes,
    }


# ---------------------------------------------------------------------------- demo fleet

_WS_COUNTERS = [
    "Anonymous Users/sec", "Bytes Received/sec", "Bytes Sent/sec", "Bytes Total/sec", "CGI Requests/sec",
    "Connection Attempts/sec", "Copy Requests/sec", "Current Anonymous Users", "Current Blocked Async I/O Requests",
    "Current CGI Requests", "Current Connections", "Current ISAPI Extension Requests", "Current NonAnonymous Users",
    "Delete Requests/sec", "Files Received/sec", "Files Sent/sec", "Files/sec", "Get Requests/sec", "Head Requests/sec",
    "ISAPI Extension Requests/sec", "Locked Errors/sec", "Maximum Anonymous Users", "Maximum Connections",
    "Maximum NonAnonymous Users", "Measured Async I/O Bandwidth Usage", "NonAnonymous Users/sec", "Not Found Errors/sec",
    "Options Requests/sec", "Other Request Methods/sec", "Post Requests/sec", "Put Requests/sec", "Service Uptime",
    "Total Allowed Async I/O Requests", "Total Anonymous Users", "Total Blocked Async I/O Requests", "Total Bytes Received",
    "Total Bytes Sent", "Total Bytes Transferred", "Total Connection Attempts (all instances)", "Total Files Received",
    "Total Files Sent", "Total Files Transferred", "Total Get Requests", "Total Head Requests", "Total Locked Errors",
    "Total Method Requests", "Total Method Requests/sec", "Total Not Found Errors", "Total Post Requests",
    "Total Rejected Async I/O Requests",
]
_POOL_COUNTERS = ["Current Application Pool State", "Current Application Pool Uptime", "Current Worker Processes",
                  "Maximum Worker Processes", "Recent Worker Process Failures", "Time Since Last Worker Process Failure",
                  "Total Application Pool Recycles", "Total Application Pool Uptime", "Total Worker Process Failures",
                  "Total Worker Process Ping Failures", "Total Worker Process Shutdown Failures",
                  "Total Worker Process Startup Failures", "Total Worker Processes Created"]
_W3WP_COUNTERS = ["Active Listener Channels", "Active Requests", "Active Threads Count", "Current File Cache Memory Usage",
                  "Current Files Cached", "Current URIs Cached", "File Cache Hits %", "Maximum Threads Count",
                  "Output Cache Current Items", "Output Cache Current Memory Usage", "Output Cache Hits %",
                  "Requests / Sec", "Total HTTP Requests Served", "Total Threads", "Uri Cache Hits %",
                  "WebSocket Active Requests"]
_QUEUE_COUNTERS = ["ArrivalRate", "CacheHitRate", "CurrentQueueSize", "MaxQueueItemAge", "RejectedRequests",
                   "RejectionRate"]
_ASP_APP_COUNTERS = ["Anonymous Requests", "Cache Total Entries", "Cache Total Hit Ratio", "Errors Total/Sec",
                     "Pipeline Instance Count", "Request Execution Time", "Request Wait Time", "Requests Executing",
                     "Requests In Application Queue", "Requests/Sec", "Requests Failed", "Requests Succeeded",
                     "Requests Timed Out", "Sessions Active", "Sessions Total"]
_SIM: dict[tuple[int, str], dict[str, Any]] = {}


def simulate_resources(server: dict[str, Any], health: dict[str, Any], kind: str, target: str) -> dict[str, Any]:
    """Raw resource payload for a demo server, shaped exactly like RESOURCE_PS output."""
    rnd = random.Random()
    name = server["server_name"]
    all_sites = health.get("sites") or []
    all_pools = [p["name"] for p in health.get("app_pools") or []]
    notes: list[str] = []

    def pool_for(site_id: int) -> str:
        return all_pools[(site_id + len(all_pools) - 1) % len(all_pools)] if all_pools else "DefaultAppPool"

    if kind == "site":
        chosen = [s for s in all_sites if str(s["id"]) == target or s["name"] == target][:1]
        if not chosen:
            notes.append(f"Site '{target}' was not found on this server")
    elif kind == "pool":
        chosen = [s for s in all_sites if pool_for(s["id"]) == target]
        if target not in all_pools:
            notes.append(f"Application pool '{target}' was not found")
    else:
        chosen = list(all_sites)

    pool_names = [target] if kind == "pool" else sorted({pool_for(s["id"]) for s in chosen}) if kind == "site" else all_pools
    st = _SIM.setdefault((server["id"], "boot"), {"boot": time.time() - rnd.uniform(3600, 86400 * 9),
                                                  "pids": {p: rnd.randint(2000, 19000) for p in all_pools}})
    uptime = time.time() - st["boot"]
    site_objs = []
    for s in chosen:
        host = s["name"].lower().replace(" ", "")
        site_objs.append({
            "id": s["id"], "name": s["name"], "state": s.get("state", "Started"), "auto_start": True,
            "bindings": [{"protocol": "https", "info": f"*:443:{host}.corp.local", "host": f"{host}.corp.local", "port": 443, "sni": True},
                         {"protocol": "http", "info": f"*:80:{host}.corp.local", "host": f"{host}.corp.local", "port": 80, "sni": False}],
            "applications": [{"path": "/", "pool": pool_for(s["id"]), "physical_path": f"D:\\inetpub\\{host}"},
                             {"path": "/api", "pool": pool_for(s["id"]), "physical_path": f"D:\\inetpub\\{host}\\api"}],
            "max_connections": 4294967295.0, "max_bandwidth": 4294967295.0, "connection_timeout_s": 120.0,
            "log_dir": "D:\\inetpub\\logs\\LogFiles", "log_enabled": True, "log_folder": f"W3SVC{s['id']}",
        })
    pools, procs, counters, reqs = [], [], [], []
    pool_state = {p["name"]: p["state"] for p in health.get("app_pools") or []}
    for pn in pool_names:
        pid = st["pids"].setdefault(pn, rnd.randint(2000, 19000))
        running = pool_state.get(pn, "Started") == "Started"
        pools.append({"name": pn, "state": pool_state.get(pn, "Started"), "runtime": "v4.0", "pipeline": "Integrated",
                      "enable32": False, "auto_start": True, "start_mode": "OnDemand", "queue_length": 1000.0,
                      "identity": "ApplicationPoolIdentity", "user": "", "idle_timeout_min": 20.0, "max_processes": 1.0,
                      "recycle_minutes": 1740.0, "recycle_requests": 0.0, "recycle_memory_kb": 0.0,
                      "recycle_private_kb": 0.0, "recycle_schedule": ["03:00:00"], "cpu_limit": 0.0,
                      "cpu_action": "NoAction", "rapid_fail": True, "rapid_fail_max": 5.0,
                      "workers": [{"pid": pid, "state": "Running"}] if running else []})
        if running:
            ws = rnd.uniform(180, 900) * 1024**2
            procs.append({"pid": pid, "pool": pn, "working_set": ws, "private_bytes": ws * rnd.uniform(1.05, 1.4),
                          "virtual_bytes": ws * 6, "peak_working_set": ws * 1.3, "handles": rnd.randint(900, 4200),
                          "threads": rnd.randint(30, 140), "cpu_seconds": rnd.uniform(200, 9000),
                          "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st["boot"] + 600))})
            inst = f"w3wp#{len(procs) - 1}" if len(procs) > 1 else "w3wp"
            counters += [["process", inst, "id process", pid], ["process", inst, "% processor time", rnd.uniform(1, 45)],
                         ["process", inst, "io data bytes/sec", rnd.uniform(1e4, 4e6)],
                         ["process", inst, "page faults/sec", rnd.uniform(5, 900)]]
            active = rnd.randint(0, 14)
            for c in _W3WP_COUNTERS:
                v = {"Active Requests": active, "Requests / Sec": rnd.uniform(2, 180), "Active Threads Count": rnd.randint(0, 12),
                     "Total HTTP Requests Served": rnd.randint(20000, 3_000_000)}.get(c, rnd.uniform(0, 100) if "%" in c else rnd.randint(0, 5000))
                counters.append(["w3svc_w3wp", f"{pid}_{pn}", c.lower(), v])
            for _ in range(min(active, 8)):
                site = rnd.choice(site_objs) if site_objs else None
                if kind == "site" and site is None:
                    break
                reqs.append({"pid": pid, "pool": pn, "site_id": site["id"] if site else 1, "verb": rnd.choice(["GET", "GET", "POST"]),
                             "url": rnd.choice(["/api/orders", "/login", "/reports/export?fmt=xlsx", "/", "/api/search?q=widgets"]),
                             "host": (site["bindings"][0]["host"] if site else "localhost"),
                             "client": f"10.{rnd.randint(0, 40)}.{rnd.randint(0, 255)}.{rnd.randint(2, 254)}",
                             "elapsed_ms": rnd.uniform(5, 9000), "stage": rnd.choice(["ExecuteRequestHandler", "AuthenticateRequest", "SendResponse"]),
                             "module": rnd.choice(["ManagedPipelineHandler", "WindowsAuthenticationModule", "StaticFileModule"])})
        for c in _POOL_COUNTERS:
            v = {"Current Application Pool State": 3 if running else 4, "Current Application Pool Uptime": uptime if running else 0,
                 "Total Application Pool Uptime": uptime, "Current Worker Processes": 1 if running else 0,
                 "Maximum Worker Processes": 1}.get(c, rnd.randint(0, 3))
            counters.append(["app_pool_was", pn, c.lower(), v])
        for c in _QUEUE_COUNTERS:
            v = {"CurrentQueueSize": rnd.choice([0, 0, 0, rnd.randint(1, 30)]), "MaxQueueItemAge": rnd.uniform(0, 2),
                 "ArrivalRate": rnd.uniform(2, 180)}.get(c, rnd.uniform(0, 3))
            counters.append(["http service request queues", pn, c.lower(), v])
    total_conn = 0
    for s in (site_objs if kind != "server" else [{"id": x["id"], "name": x["name"]} for x in all_sites]) + [{"id": 0, "name": "_Total"}]:
        is_total = s["name"] == "_Total"
        for c in _WS_COUNTERS:
            if c == "Current Connections":
                v = total_conn + rnd.randint(5, 60) if is_total else rnd.randint(3, 260)
                total_conn += 0 if is_total else v
            elif c == "Service Uptime":
                v = uptime
            elif c.endswith("/sec") or c.endswith("Usage"):
                v = rnd.uniform(0, 2e5 if "Bytes" in c else 120)
            elif c.startswith("Maximum"):
                v = rnd.randint(300, 1400)
            else:
                v = rnd.randint(0, 9_000_000 if "Total" in c else 40)
            counters.append(["web service", s["name"], c.lower(), v])
        if not is_total:
            for c in _ASP_APP_COUNTERS:
                counters.append(["asp.net applications", f"_LM_W3SVC_{s['id']}_ROOT", c.lower(),
                                 rnd.uniform(0, 100) if "Ratio" in c else rnd.randint(0, 500)])
    counters += [["asp.net", "", "requests queued", rnd.choice([0, 0, 2])], ["asp.net", "", "requests current", rnd.randint(0, 30)],
                 ["asp.net", "", "request wait time", rnd.randint(0, 40)], ["asp.net", "", "application restarts", rnd.randint(0, 4)],
                 ["processor", "_total", "% processor time", health.get("cpu_percent") or rnd.uniform(5, 50)],
                 ["processor", "_total", "% privileged time", rnd.uniform(1, 9)],
                 ["memory", "", "available mbytes", 32768 * (1 - (health.get("ram_percent") or 50) / 100)],
                 ["memory", "", "% committed bytes in use", health.get("ram_percent") or 50],
                 ["memory", "", "pages/sec", rnd.uniform(0, 200)], ["system", "", "processor queue length", rnd.randint(0, 6)],
                 ["system", "", "context switches/sec", rnd.uniform(2000, 40000)],
                 ["tcpv4", "", "connections established", rnd.randint(200, 2500)], ["tcpv4", "", "connections reset", rnd.randint(10, 9000)],
                 ["tcpv4", "", "segments retransmitted/sec", rnd.uniform(0, 12)],
                 ["physicaldisk", "_total", "% disk time", rnd.uniform(0, 60)], ["physicaldisk", "_total", "avg. disk queue length", rnd.uniform(0, 2)],
                 ["network interface", "Ethernet0", "bytes total/sec", rnd.uniform(1e5, 9e6)],
                 ["network interface", "Ethernet0", "current bandwidth", 10_000_000_000]]
    clients = [f"{rnd.choice([10, 172, 203, 198])}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(rnd.randint(8, 30))]
    tops = sorted(({"ip": ip, "count": rnd.randint(1, 40)} for ip in clients), key=lambda x: -x["count"])
    est = sum(t["count"] for t in tops)
    tcp = {"source": "simulated", "ports": [443, 80], "total": est + rnd.randint(10, 300), "established": est,
           "unique_clients": len(tops), "top_clients": tops[:25],
           "by_state": [{"state": "Established", "count": est}, {"state": "TimeWait", "count": rnd.randint(10, 250)},
                        {"state": "CloseWait", "count": rnd.randint(0, 6)}, {"state": "FinWait2", "count": rnd.randint(0, 12)}],
           "by_port": [{"port": 443, "count": int(est * 0.9)}, {"port": 80, "count": est - int(est * 0.9)}]}
    return {
        "kind": kind, "target": target, "hostname": name, "os": "Microsoft Windows Server 2022 Datacenter",
        "cpu_count": 8, "ram_total_kb": 32 * 1024**2, "ram_free_kb": 32 * 1024**2 * (1 - (health.get("ram_percent") or 50) / 100),
        "uptime_seconds": uptime, "site": site_objs[0] if kind == "site" and site_objs else None,
        "sites": site_objs if kind != "site" else [], "site_ids": [s["id"] for s in site_objs],
        "site_names": [s["name"] for s in site_objs], "pools": pools, "processes": procs,
        "requests": sorted(reqs, key=lambda r: -r["elapsed_ms"]), "counters": counters, "tcp": tcp,
        "notes": notes, "duration_ms": rnd.randint(1100, 1900),
    }
