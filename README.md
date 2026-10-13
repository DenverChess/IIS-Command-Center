# IIS Sentinel

A centralized Security Operations Center for IIS 10 fleets: real-time W3C log defense, Windows Server health monitoring,
Z-score anomaly detection, operator-approved firewall bans and scheduled Exchange reporting — with a cyberpunk
command-center UI.

Sentinel runs on a Windows 10/11 admin workstation (or any Windows server) and monitors any number of remote IIS
servers at once: logs are tailed over their UNC share, health and bans go over WinRM. Every server gets its own
independent async tasks, so a server that goes offline is logged, alerted on and retried with backoff while the rest
of the fleet keeps streaming.

```
iis_sentinel/
  main.py            FastAPI app: REST API, /ws/dashboard WebSocket, task supervisor, processing pipeline
  remote_manager.py  WinRM health (PowerShell CIM + IISAdministration), UNC log tailing, netsh firewall bans
  log_tailer.py      one tail task per server; rolling W3C parser (rollover, truncation, #Fields aware)
  system_health.py   one health task per server; app pool / W3SVC / disk / CPU alerting, offline detection
  baseliner.py       24h statistical baseline (per server / per IP / population), Z-score anomalies
  threat_rules.py    SQLi / XSS / traversal / scanner signatures, 404 + 401/403 spikes, per-(server, IP) threat score
  database.py        async SQLAlchemy (SQLite WAL) models, server registry, DPAPI-protected config store
  events.py          WebSocket fan-out hub and alert pipeline (persist -> broadcast -> email)
  ad_auth.py         Active Directory simple bind (LDAPS / StartTLS, optional nested-group gate)
  mailer.py          exchangelib delivery with retries, timeouts, circuit breaker, rate limiting
  reporter.py        APScheduler weekly / monthly HTML reports with a per-server fleet breakdown
  static/            index.html (login), dashboard.html (SOC), css/style.css, js/app.js
```

## Quick start (admin workstation)

```powershell
cd iis_sentinel
py -3.11 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
$env:SENTINEL_LOCAL_ADMIN_PASSWORD = "<strong break-glass password>"   # first login before AD is configured
.venv\Scripts\python main.py
```

Browse to `http://localhost:8443/`, sign in as `sentinel-admin` with the break-glass password, open **CONFIG** and:

1. **SERVERS** — register each IIS server: name (`IIS-01`), IP, WinRM credentials and the UNC path of its log folder
   (e.g. `\\10.0.20.11\c$\inetpub\logs\LogFiles\W3SVC1`). Press **TEST** to verify WinRM and the share.
2. **AD**, **EXCHANGE**, **WATCHERS**, **REPORTS** — as before. After AD is configured operators sign in with AD credentials.

### Preparing each IIS server

* WinRM: `winrm quickconfig` (HTTP 5985) or an HTTPS listener on 5986. NTLM / Kerberos / CredSSP are supported;
  Basic is only accepted over HTTPS. Kerberos needs a domain-joined workstation and the server's DNS name; NTLM
  works by IP from anywhere. Kerberos / CredSSP need the optional extras: `pip install "pywinrm[kerberos,credssp]"`.
* The WinRM account needs to run `Get-CimInstance`, `Get-IISAppPool` (IISAdministration / WebAdministration) and
  `netsh advfirewall` — in practice local Administrators on the IIS server.
* The same account must be able to read the log share; Sentinel maps it with `WNetAddConnection2` (no password on a
  command line). Read-only access to the `W3SVC*` folder is enough.
* Enable **sc-bytes** and **cs-bytes** in IIS logging (IIS Manager → Logging → Select Fields) so bandwidth
  baselining works. Field order is read from each file's `#Fields:` directive.

WinRM passwords are stored DPAPI-encrypted on Windows (base64 elsewhere) and are never returned by the API.

Running Sentinel directly on an IIS box still works: put the local log folders in **WATCHERS → Local IIS log
directories** (or `SENTINEL_LOG_DIRS`) and the host appears as an extra server alongside the remote ones.

## Active defense (Manual Ban)

Attack signatures, spikes and **ACTIVE THREAT** escalations create *actionable* alerts with status `Pending`. They are
grouped per attacker per target server in the **PENDING THREATS** panel. **APPROVE BAN** calls `POST /defense/ban`
with the alert id; Sentinel looks up the alert's server and runs on it over WinRM:

```
netsh advfirewall firewall add rule name="SENTINEL BAN: <ip>" dir=in action=block remoteip=<ip>
```

The IP is strictly validated (loopback / unspecified / multicast are refused), the rule is only added if it does not
exist yet, a `banned_ips` row is recorded, the alert (plus any other pending alerts for that attacker on that server)
becomes `Approved` and the ban is broadcast to every console. Bans can be lifted from the **BANS** tab
(`DELETE /defense/bans/{id}` deletes the firewall rule). Alerts can also be dismissed without action.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SENTINEL_HOST` / `SENTINEL_PORT` | Bind address (default `0.0.0.0:8443`) |
| `SENTINEL_SSL_CERT` / `SENTINEL_SSL_KEY` | Serve HTTPS directly (then set `SENTINEL_COOKIE_SECURE=1`) |
| `SENTINEL_LOCAL_ADMIN_USER` / `SENTINEL_LOCAL_ADMIN_PASSWORD` | Break-glass login when AD is down / unconfigured (disabled if no password) |
| `SENTINEL_LOG_DIRS` | Optional local IIS log directories (`;` separated) when Sentinel runs on an IIS server |
| `SENTINEL_AD_SERVERS`, `SENTINEL_AD_DOMAIN`, `SENTINEL_AD_UPN_SUFFIX`, `SENTINEL_AD_BASE_DN`, `SENTINEL_AD_GROUP` | Initial AD settings |
| `SENTINEL_DATA_DIR` | Where the SQLite DB and rotating `sentinel.log` live (default `./data`) |
| `SENTINEL_SECRET_KEY` | Session signing key (default: random, stored DPAPI-protected in the DB) |
| `SENTINEL_DEMO=1` | Demo mode: simulated 4-server fleet, synthetic traffic + attacks, login `demo` / `demo` |

## Demo mode (any OS)

```bash
cd iis_sentinel
pip install -r requirements.txt
SENTINEL_DEMO=1 python main.py     # http://localhost:8443  (demo / demo)
```

Demo mode seeds four servers. `IIS-01`..`IIS-03` (127.0.0.11-13) are simulated: the generator writes real W3C files into
`data/demo_logs/<server>/W3SVC1`, so the tailer, parser, threat engine, baseliner, database and WebSocket are exercised
end to end, while health and bans are simulated instead of using WinRM. `IIS-04` (10.255.255.14) is a real,
unreachable address that shows how an offline server is reported while the others keep streaming.
`SENTINEL_DEMO_ROLLOVER_SECONDS=120` forces frequent log rollovers.

## Detection model

* **Signatures** (+10 each): SQL injection, XSS, path traversal/LFI; known scanner user-agents +5. Payloads are
  URL/HTML-entity decoded up to three times before matching.
* **Spikes** (+5): ≥ `spike_404_threshold` 404s, or ≥ `spike_auth_threshold` 401/403s, from one IP within the spike window.
* **Z-score** (+20): per-IP requests/min or bandwidth/min with Z > 3.0 against the IP's own 24h baseline (or the
  client-population baseline for unseen IPs). Per-server volume surges, traffic drops and latency outliers raise anomaly alerts.
* Scores are kept per **(server, source IP)** so a ban lands on the server actually under attack. Scores decay with a
  configurable half-life; above **50** the IP becomes an **ACTIVE THREAT** (HIGH alert, emailed, pending approval).
* Baselines are learned only from requests that did not match an attack signature, so attackers can't poison the model.
  Each server has its own live per-minute bucket, because each IIS box flushes its log buffer on its own schedule.

## API

| Method | Path | Description |
| --- | --- | --- |
| POST | `/login` | `{username, password}` → AD bind, sets an HttpOnly session cookie |
| POST | `/logout` | End session |
| GET | `/servers` | Monitored servers (passwords masked), connectivity status, latest health, log tailer status |
| POST | `/servers` | Register a server: `{server_name, ip_address, winrm_username, winrm_password, log_unc_path, winrm_transport?, winrm_port?, winrm_use_ssl?, winrm_verify_ssl?}` |
| PUT / DELETE | `/servers/{id}` | Update (blank password keeps the stored one) / remove a server |
| POST | `/servers/{id}/test` | Check WinRM and the log share without consuming log lines |
| POST | `/defense/ban` | `{alert_id}` (or `{server_id, ip}`) → firewall ban on the alert's server, alert → `Approved` |
| POST | `/defense/dismiss` | `{alert_id}` → `Dismissed` |
| GET | `/defense/bans`, DELETE `/defense/bans/{id}` | Active bans / lift a ban |
| GET / POST | `/config` | Read / update `ad`, `exchange`, `watchers`, `reports` sections (secrets masked) |
| POST | `/config/test/exchange` | Send a test mail |
| GET | `/threats/live` | Recent malicious requests + threat/anomaly alerts |
| GET | `/threats/active?server_id=` | Current threat matrix (scored server/IP pairs) |
| GET | `/threats/ip/{ip}?server_id=` | Threat state + recent requests for one IP |
| GET | `/system/health?server_id=` | Latest CPU / RAM / disk / app pool / W3SVC sample per server |
| GET | `/stats/baseline?server_id=` | Baseline model, pipeline and watcher status |
| GET | `/alerts?server_id=&status=&severity=`, POST `/alerts/{id}/ack` | Alert history / acknowledge |
| GET | `/reports`, POST `/reports/run`, GET `/reports/{id}/html` | Report history, run now, view HTML |
| WS | `/ws/dashboard` | Push stream: `hello`, `logs`, `health`, `servers`, `server_status`, `threats`, `alert`, `ban`, `alert_status`, `baseline`, `tick` |

Every log line, health sample, threat and alert pushed over the WebSocket carries `server_id` and `server_name`.

## Resilience

* Each server has its own log task and health task. Failures (WinRM timeouts, refused connections, bad credentials,
  unreachable shares) back off per server (logs up to 60 s, health up to 10 min), raise one HIGH "unreachable" / "log
  feed offline" alert and an INFO alert on recovery, and never block other servers.
* Remote calls run in worker threads with hard timeouts; a hung WinRM call is never duplicated (one in-flight call per
  server and operation), so a dead server cannot exhaust the thread pool.
* Every background task runs under a supervisor that logs crashes and restarts it with exponential backoff; per-server
  tasks are reconciled every 5 s (and immediately when servers are added, edited or removed).
* AD and Exchange calls run in worker threads with hard timeouts; failures return errors, never exceptions.
  Exchange has retries, a circuit breaker and an hourly alert-mail cap; reports are always recorded in the DB
  even when delivery fails.
* SQLite runs in WAL mode with busy timeouts and lock retries; log writes are batched and re-queued on failure.
  Databases created by the single-server version are migrated in place (new columns default to the local server).
* Log files are opened per read and never held open, so IIS log cleanup and rotation are never blocked.
