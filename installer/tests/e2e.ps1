<#
.SYNOPSIS
  End-to-end test of the IIS Sentinel installer on a disposable Windows Server machine (used by CI).

.DESCRIPTION
  Turns this machine into a lab IIS 10 server, silently installs IIS Sentinel, and drives the real product:
  WinRM health collection, UNC log tailing over SMB, threat detection, an operator-approved firewall ban, a
  service restart, an in-place upgrade and a clean uninstall.

  DESTRUCTIVE: installs IIS, creates a local administrator, enables PS Remoting and shares the IIS log folder.
  Run it only on a throwaway VM / CI runner.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [string]$ArtifactDir = (Join-Path $PSScriptRoot "e2e-artifacts"),
    [int]$Port = 8443
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Installer = (Resolve-Path $Installer).Path
$AppDir = Join-Path $env:ProgramFiles "IIS Sentinel"
$DataDir = Join-Path $env:ProgramData "IIS Sentinel"
$Base = "http://127.0.0.1:$Port"
$AdminUser = "soc-admin"
$AdminPassword = "Br3akGlass-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$LabUser = "sentinel-lab"
$LabPassword = "Lab!" + [guid]::NewGuid().ToString("N").Substring(0, 16) + "aA1"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

$script:Failures = 0
function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  PASS  $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++; throw $msg }

function Wait-Until([scriptblock]$Condition, [int]$TimeoutSec, [string]$What, [int]$IntervalSec = 2) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = $null
    while ((Get-Date) -lt $deadline) {
        try { $r = & $Condition; if ($r) { return $r } } catch { $last = $_.Exception.Message }
        Start-Sleep -Seconds $IntervalSec
    }
    Fail "Timed out after ${TimeoutSec}s waiting for: $What $(if ($last) { "(last error: $last)" })"
}

function Invoke-Setup([string[]]$Arguments, [string]$LogName) {
    $log = Join-Path $ArtifactDir $LogName
    $p = Start-Process -FilePath $Installer -ArgumentList ($Arguments + @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG=`"$log`"")) -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "Setup exited with $($p.ExitCode); see $log" }
    Pass "setup exited 0 ($LogName)"
}

function Api([string]$Method, [string]$Path, $Body = $null) {
    $params = @{ Method = $Method; Uri = "$Base$Path"; WebSession = $script:Session; UseBasicParsing = $true; TimeoutSec = 90 }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 6); $params.ContentType = "application/json" }
    Invoke-RestMethod @params
}

function Connect-Console([string]$Password = $AdminPassword) {
    Wait-Until { (Invoke-RestMethod -UseBasicParsing -TimeoutSec 5 "$Base/healthz").status -eq "ok" } 90 "/healthz" | Out-Null
    $script:Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $me = Invoke-RestMethod -Method Post -Uri "$Base/login" -WebSession $script:Session -UseBasicParsing -ContentType "application/json" `
        -Body (@{ username = $AdminUser; password = $Password } | ConvertTo-Json)
    if (-not $me.ok -and -not $me.user) { Fail "login returned $($me | ConvertTo-Json -Compress)" }
    Api GET "/me" | Out-Null
    Pass "signed in as break-glass account '$AdminUser'"
}

function Send-Traffic([string]$Target, [int]$Count, [string]$Path = "/", [string]$UserAgent = "Mozilla/5.0 (E2E)") {
    for ($i = 0; $i -lt $Count; $i++) {
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -UserAgent $UserAgent -Uri "http://$Target$Path" | Out-Null } catch { }
    }
    & netsh http flush logbuffer | Out-Null
}

function Save-Diagnostics {
    foreach ($f in @("sentinel.log", "local_admin.json")) {
        $src = Join-Path $DataDir $f
        if (Test-Path $src) { Copy-Item $src $ArtifactDir -Force -ErrorAction SilentlyContinue }
    }
    $svcLogs = Join-Path $DataDir "service-logs"
    if (Test-Path $svcLogs) { Copy-Item $svcLogs (Join-Path $ArtifactDir "service-logs") -Recurse -Force -ErrorAction SilentlyContinue }
    $xml = Join-Path $AppDir "IISSentinelService.xml"
    if (Test-Path $xml) { Copy-Item $xml $ArtifactDir -Force -ErrorAction SilentlyContinue }
}

try {
    # ------------------------------------------------------------------------------------------ lab setup
    Step "Installing IIS 10 (Web-Server + management scripting)"
    $features = Install-WindowsFeature -Name Web-Server, Web-Scripting-Tools, Web-Mgmt-Console
    if (-not $features.Success) { Fail "Install-WindowsFeature failed" }
    Import-Module WebAdministration
    Pass "IIS installed; app pools: $((Get-ChildItem IIS:\AppPools).Name -join ', ')"

    $LanIp = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.AddressState -eq "Preferred" } |
        Select-Object -First 1).IPAddress
    if (-not $LanIp) { Fail "No routable IPv4 address found for attack traffic" }
    Pass "attacker traffic will originate from $LanIp"

    Send-Traffic "127.0.0.1" 3
    $LogDir = "C:\inetpub\logs\LogFiles\W3SVC1"
    Wait-Until { Get-ChildItem $LogDir -Filter "u_ex*.log" -ErrorAction SilentlyContinue } 60 "first IIS W3C log file" | Out-Null
    Pass "IIS is writing W3C logs to $LogDir"

    Step "Creating lab WinRM / SMB account and enabling remote management"
    $secure = ConvertTo-SecureString $LabPassword -AsPlainText -Force
    New-LocalUser -Name $LabUser -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Add-LocalGroupMember -Group Administrators -Member $LabUser
    # Remote UAC would otherwise strip admin rights from local accounts over the network (WinRM / SMB).
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy `
        -Value 1 -PropertyType DWord -Force | Out-Null
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Pass "WinRM listener: $((Get-ChildItem WSMan:\localhost\Listener | ForEach-Object { $_.Keys -join ',' }) -join '; ')"
    New-SmbShare -Name "IISLogs" -Path "C:\inetpub\logs\LogFiles" -ReadAccess $LabUser -FullAccess "Administrators" | Out-Null
    Pass "shared C:\inetpub\logs\LogFiles as \\127.0.0.1\IISLogs"

    # ------------------------------------------------------------------------------------------ install
    Step "Silent install"
    Invoke-Setup @("/ADMINUSER=$AdminUser", "/ADMINPASSWORD=$AdminPassword", "/PORT=$Port", "/REMOTEACCESS=1") "install.log"
    $svc = Get-Service IISSentinel -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") { Fail "IISSentinel service is not running" }
    $startType = (Get-CimInstance Win32_Service -Filter "Name='IISSentinel'")
    Pass "service running as $($startType.StartName), start mode $($startType.StartMode)"
    if (-not (& netsh advfirewall firewall show rule name="IIS Sentinel SOC" | Select-String "LocalPort:\s+$Port")) { Fail "console firewall rule missing" }
    Pass "firewall rule 'IIS Sentinel SOC' opens TCP $Port"
    foreach ($lnk in @("IIS Sentinel Console.url", "Reset Break-glass Password.lnk", "Data and Logs.lnk")) {
        if (-not (Test-Path (Join-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\IIS Sentinel" $lnk)) -and
            -not (Test-Path (Join-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\IIS Sentinel" ($lnk -replace '\.url$', '.lnk')))) {
            Fail "Start menu entry '$lnk' missing"
        }
    }
    Pass "Start menu shortcuts created"

    Step "Verifying secrets at rest"
    foreach ($f in @((Join-Path $DataDir "local_admin.json"), (Join-Path $AppDir "IISSentinelService.xml"))) {
        if (Select-String -Path $f -SimpleMatch $AdminPassword -Quiet) { Fail "plaintext password found in $f" }
    }
    if (-not (Select-String -Path (Join-Path $DataDir "local_admin.json") -Pattern 'pbkdf2_sha256\$310000\$' -Quiet)) { Fail "local_admin.json is not a PBKDF2 hash" }
    Pass "break-glass password stored only as a PBKDF2 hash"
    $acl = (Get-Acl $DataDir).Access | ForEach-Object { $_.IdentityReference.Value }
    $unexpected = $acl | Where-Object { $_ -notmatch "SYSTEM$|Administrators$" }
    if ($unexpected) { Fail "data directory grants access to: $($unexpected -join ', ')" }
    Pass "data directory ACL limited to SYSTEM + Administrators ($($acl -join ', '))"

    Connect-Console
    $bad = try { Invoke-RestMethod -Method Post -Uri "$Base/login" -UseBasicParsing -ContentType "application/json" `
        -Body (@{ username = $AdminUser; password = "wrong-password" } | ConvertTo-Json); "accepted" } catch { [int]$_.Exception.Response.StatusCode }
    if ($bad -ne 401) { Fail "wrong password returned $bad (expected 401)" }
    Pass "wrong password rejected with 401"
    foreach ($asset in @("/", "/static/js/app.js", "/static/css/style.css")) {
        $r = Invoke-WebRequest -UseBasicParsing "$Base$asset"
        if ($r.StatusCode -ne 200) { Fail "$asset returned $($r.StatusCode)" }
    }
    Pass "login page and static assets served"

    # ------------------------------------------------------------------------------------------ monitoring
    Step "Registering this machine as a monitored IIS server over WinRM + UNC"
    $server = (Api POST "/servers" @{
            server_name = "IIS-LAB"; ip_address = "127.0.0.1"; winrm_username = "$env:COMPUTERNAME\$LabUser"
            winrm_password = $LabPassword; log_unc_path = "\\127.0.0.1\IISLogs\W3SVC1"; winrm_transport = "ntlm"
        }).server
    $sid = $server.id
    Pass "server IIS-LAB registered with id $sid"
    $test = Wait-Until { $t = Api POST "/servers/$sid/test"; if ($t.winrm.ok -and $t.logs.ok) { $t } else { throw ($t | ConvertTo-Json -Compress) } } 120 "connection test" 5
    Pass "connection test: WinRM host $($test.winrm.hostname), $($test.winrm.app_pools) app pools; share has $($test.logs.files) log file(s)"

    $health = Wait-Until {
        $s = (Api GET "/system/health?server_id=$sid").servers | Select-Object -First 1
        if ($s.online -and $null -ne $s.cpu_percent -and ($s.app_pools | Where-Object { $_.name -eq "DefaultAppPool" })) { $s }
    } 240 "a WinRM health sample containing DefaultAppPool" 5
    Pass "health: CPU $($health.cpu_percent)% RAM $($health.ram_percent)% W3SVC $($health.w3svc_state); pools $(($health.app_pools | ForEach-Object { "$($_.name)=$($_.state)" }) -join ', ')"

    Wait-Until { (Api GET "/servers").logs | Where-Object { $_.server_id -eq $sid -and $_.status -eq "tailing" } } 120 "UNC log tailer to attach" 3 | Out-Null
    Pass "log tailer attached to \\127.0.0.1\IISLogs\W3SVC1"

    Step "Attacking IIS-LAB from $LanIp (SQL injection + scanner user-agent)"
    $alert = Wait-Until {
        Send-Traffic $LanIp 6 "/?id=1%27%20OR%20%271%27%3D%271" "sqlmap/1.7.2#stable (https://sqlmap.org)"
        Send-Traffic $LanIp 6 "/products?q=1%20UNION%20SELECT%20username,password%20FROM%20users--" "sqlmap/1.7.2#stable (https://sqlmap.org)"
        (Api GET "/alerts?status=pending&server_id=$sid").alerts | Where-Object { $_.source_ip -eq $LanIp } | Select-Object -First 1
    } 240 "a Pending actionable alert for $LanIp" 10
    Pass "alert #$($alert.id) [$($alert.severity)] '$($alert.title)' on $($alert.server_name)"
    $threat = (Api GET "/threats/ip/$LanIp")
    Pass "threat profile: $($threat | ConvertTo-Json -Compress -Depth 2 | ForEach-Object { $_.Substring(0, [math]::Min(200, $_.Length)) })"

    Step "Approving the ban (WinRM -> netsh on IIS-LAB)"
    $ban = Api POST "/defense/ban" @{ alert_id = $alert.id }
    if (-not $ban.ok) { Fail "ban failed: $($ban | ConvertTo-Json -Compress)" }
    $rule = "SENTINEL BAN: $LanIp"
    & netsh advfirewall firewall show rule name="$rule" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "firewall rule '$rule' not found after ban" }
    Pass "Windows Firewall rule '$rule' created; alerts $($ban.alert_ids -join ', ') marked Approved"
    $status = ((Api GET "/alerts?server_id=$sid&limit=500").alerts | Where-Object { $_.id -eq $alert.id }).status
    if ($status -ne "Approved") { Fail "alert status is '$status' (expected Approved)" }
    $again = try { Api POST "/defense/ban" @{ alert_id = $alert.id } | Out-Null; 200 } catch { [int]$_.Exception.Response.StatusCode }
    if ($again -ne 409) { Fail "re-approving returned $again (expected 409)" }
    Pass "duplicate approval refused with 409"

    $banRow = (Api GET "/defense/bans?server_id=$sid").bans | Where-Object { $_.ip_address -eq $LanIp } | Select-Object -First 1
    Api DELETE "/defense/bans/$($banRow.id)" | Out-Null
    & netsh advfirewall firewall show rule name="$rule" | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail "firewall rule '$rule' still present after lifting the ban" }
    Pass "ban lifted and firewall rule removed"

    Step "Unreachable server does not disturb monitoring"
    $dead = (Api POST "/servers" @{
            server_name = "IIS-DEAD"; ip_address = "10.255.255.14"; winrm_username = "x\y"; winrm_password = "nope"
            log_unc_path = "\\10.255.255.14\IISLogs\W3SVC1"
        }).server
    Start-Sleep -Seconds 45
    $hz = Invoke-RestMethod -UseBasicParsing "$Base/healthz"
    $deadTasks = $hz.tasks.PSObject.Properties | Where-Object { -not $_.Value } | ForEach-Object { $_.Name }
    if ($deadTasks) { Fail "background tasks died: $($deadTasks -join ', ')" }
    $live = (Api GET "/system/health?server_id=$sid").servers | Select-Object -First 1
    if (-not $live.online) { Fail "IIS-LAB went offline while IIS-DEAD was unreachable" }
    Api DELETE "/servers/$($dead.id)" | Out-Null
    Pass "IIS-DEAD failed in isolation; all background tasks alive; IIS-LAB still online"

    # ------------------------------------------------------------------------------------------ lifecycle
    Step "Service restart"
    Restart-Service IISSentinel -Force
    Connect-Console
    if (-not ((Api GET "/servers").servers | Where-Object { $_.server_name -eq "IIS-LAB" })) { Fail "IIS-LAB missing after restart" }
    Pass "configuration and DPAPI-protected credentials survived the restart"

    Step "In-place upgrade (silent, no password -> keeps the existing account)"
    Save-Diagnostics
    Invoke-Setup @() "upgrade.log"
    Connect-Console
    $after = (Api GET "/servers").servers | Where-Object { $_.server_name -eq "IIS-LAB" }
    if (-not $after) { Fail "IIS-LAB missing after upgrade" }
    $t2 = Api POST "/servers/$($after.id)/test"
    if (-not $t2.winrm.ok) { Fail "WinRM test failed after upgrade: $($t2 | ConvertTo-Json -Compress)" }
    Pass "upgrade kept settings, account, port $Port and remote-access choice"
    if (-not (& netsh advfirewall firewall show rule name="IIS Sentinel SOC" | Select-String "LocalPort:\s+$Port")) { Fail "console firewall rule lost on upgrade" }

    Step "Break-glass reset via sentinelctl"
    $NewPassword = "Rotated-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
    $env:SENTINEL_DATA_DIR = $DataDir
    $env:E2E_NEW_PW = $NewPassword
    & (Join-Path $AppDir "python\python.exe") (Join-Path $AppDir "app\sentinelctl.py") set-admin-password --from-env E2E_NEW_PW
    if ($LASTEXITCODE -ne 0) { Fail "sentinelctl set-admin-password exited $LASTEXITCODE" }
    Remove-Item Env:\SENTINEL_DATA_DIR, Env:\E2E_NEW_PW -ErrorAction SilentlyContinue
    Connect-Console $NewPassword
    Pass "rotated password accepted without restarting the service"
    Save-Diagnostics

    # ------------------------------------------------------------------------------------------ uninstall
    Step "Silent uninstall with /PURGEDATA"
    $uninst = Join-Path $AppDir "unins000.exe"
    $p = Start-Process -FilePath $uninst -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/PURGEDATA", "/LOG=`"$(Join-Path $ArtifactDir 'uninstall.log')`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "uninstaller exited $($p.ExitCode)" }
    Wait-Until { -not (Get-Service IISSentinel -ErrorAction SilentlyContinue) -and -not (Test-Path (Join-Path $AppDir "python")) } 90 "service + files removed" | Out-Null
    & netsh advfirewall firewall show rule name="IIS Sentinel SOC" | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail "console firewall rule left behind" }
    if (Test-Path $DataDir) { Fail "data directory left behind despite /PURGEDATA" }
    $listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Fail "something is still listening on $Port" }
    Pass "service, program files, firewall rule and data removed"

    Write-Host "`nALL END-TO-END CHECKS PASSED" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "`nE2E FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    Save-Diagnostics
    exit 1
}
