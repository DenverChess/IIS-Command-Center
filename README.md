# IIS Sentinel

Real-time IIS W3C log defense, Windows Server health monitoring, Z-score anomaly detection and scheduled
Exchange reporting — with a cyberpunk command-center UI.

```
iis_sentinel/
  main.py           FastAPI app: REST API, /ws/dashboard WebSocket, task supervisor, processing pipeline
  log_tailer.py     watchdog + polling tailer for rolling W3C logs (rollover, truncation, #Fields aware)
  system_health.py  psutil CPU/RAM/disk + IIS app pool state (WMI via pywin32, appcmd fallback), W3SVC/WAS
  baseliner.py      24h statistical baseline (global / per-IP / population), Z-score anomalies
  threat_rules.py   SQLi / XSS / traversal / scanner signatures, 404 + 401/403 spikes, decaying threat score
  database.py       async SQLAlchemy (SQLite WAL) models + DPAPI-protected config store
  events.py         WebSocket fan-out hub and alert pipeline (persist -> broadcast -> email)
  ad_auth.py        Active Directory simple bind (LDAPS / StartTLS, optional nested-group gate)
  mailer.py         exchangelib delivery with retries, timeouts, circuit breaker, rate limiting
  reporter.py       APScheduler weekly / monthly HTML reports (sends "All Quiet" reports too)
  static/           index.html (login), dashboard.html (command center), css/style.css, js/app.js
```

## Quick start (Windows Server)

```powershell
cd iis_sentinel
py -3.11 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
$env:SENTINEL_LOCAL_ADMIN_PASSWORD = "<strong break-glass password>"   # first login before AD is configured
$env:SENTINEL_LOG_DIRS = "C:\inetpub\logs\LogFiles\W3SVC1;C:\inetpub\logs\LogFiles\W3SVC2"
.venv\Scripts\python main.py
```

Browse to `http://<server>:8443/`, sign in as `sentinel-admin` with the break-glass password, open **CONFIG** and fill in
the AD, Exchange, Watchers and Reports tabs. After that, operators sign in with their AD credentials.

Run it as a service account that can read the IIS log folders and query WMI `root\WebAdministration`
(local Administrators, or grant WMI namespace rights). [NSSM](https://nssm.cc/) works well for running `python main.py`
as a Windows service.

### Recommended IIS logging fields

The defaults are parsed automatically; also enable **sc-bytes** and **cs-bytes** (IIS Manager → Logging → Select Fields)
so bandwidth baselining works. Field order is read from each file's `#Fields:` directive.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SENTINEL_HOST` / `SENTINEL_PORT` | Bind address (default `0.0.0.0:8443`) |
| `SENTINEL_SSL_CERT` / `SENTINEL_SSL_KEY` | Serve HTTPS directly (then set `SENTINEL_COOKIE_SECURE=1`) |
| `SENTINEL_LOCAL_ADMIN_USER` / `SENTINEL_LOCAL_ADMIN_PASSWORD` | Break-glass login when AD is down / unconfigured (disabled if no password) |
| `SENTINEL_LOG_DIRS` | Initial IIS log directories (`;` separated) — later editable in the UI |
| `SENTINEL_AD_SERVERS`, `SENTINEL_AD_DOMAIN`, `SENTINEL_AD_UPN_SUFFIX`, `SENTINEL_AD_BASE_DN`, `SENTINEL_AD_GROUP` | Initial AD settings |
| `SENTINEL_DATA_DIR` | Where the SQLite DB and rotating `sentinel.log` live (default `./data`) |
| `SENTINEL_SECRET_KEY` | Session signing key (default: random, stored DPAPI-protected in the DB) |
| `SENTINEL_DEMO=1` | Demo mode: synthetic W3C traffic + attacks + simulated app pools, login `demo` / `demo` |

## Demo mode (any OS)

```bash
cd iis_sentinel
pip install -r requirements.txt
SENTINEL_DEMO=1 python main.py     # http://localhost:8443  (demo / demo)
```

The generator writes real W3C files into `data/demo_logs/W3SVC1`, so the tailer, parser, threat engine, baseliner,
database and WebSocket are all exercised end to end. `SENTINEL_DEMO_ROLLOVER_SECONDS=120` forces frequent log
rollovers to exercise rollover handling.

## Detection model

* **Signatures** (+10 each): SQL injection, XSS, path traversal/LFI; known scanner user-agents +5. Payloads are
  URL/HTML-entity decoded up to three times before matching.
* **Spikes** (+5): ≥ `spike_404_threshold` 404s, or ≥ `spike_auth_threshold` 401/403s, from one IP within the spike window.
* **Z-score** (+20): per-IP requests/min or bandwidth/min with Z > 3.0 against the IP's own 24h baseline (or the
  client-population baseline for unseen IPs). Server-wide volume surges, traffic drops and latency outliers raise anomaly alerts.
* Scores decay with a configurable half-life; an IP above **50** becomes an **ACTIVE THREAT** (HIGH alert, emailed).
* Baselines are learned only from requests that did not match an attack signature, so attackers can't poison the model.

## API

| Method | Path | Description |
| --- | --- | --- |
| POST | `/login` | `{username, password}` → AD bind, sets an HttpOnly session cookie |
| POST | `/logout` | End session |
| GET / POST | `/config` | Read / update `ad`, `exchange`, `watchers`, `reports` sections (secrets masked) |
| POST | `/config/test/exchange` | Send a test mail |
| GET | `/threats/live` | Recent malicious requests + threat/anomaly alerts |
| GET | `/threats/active` | Current threat matrix (scored IPs) |
| GET | `/threats/ip/{ip}` | Threat state + recent requests for one IP |
| GET | `/system/health` | Latest CPU / RAM / disk / app pool / W3SVC sample |
| GET | `/stats/baseline` | Baseline model, pipeline and watcher status |
| GET | `/alerts`, POST `/alerts/{id}/ack` | Alert history / acknowledge |
| GET | `/reports`, POST `/reports/run`, GET `/reports/{id}/html` | Report history, run now, view HTML |
| WS | `/ws/dashboard` | Push stream: `hello`, `logs`, `health`, `threats`, `alert`, `baseline`, `tick` |

## Resilience

* Every background task runs under a supervisor that logs crashes and restarts it with exponential backoff.
* AD and Exchange calls run in worker threads with hard timeouts; failures return errors, never exceptions.
  Exchange has retries, a circuit breaker and an hourly alert-mail cap; reports are always recorded in the DB
  even when delivery fails.
* SQLite runs in WAL mode with busy timeouts and lock retries; log writes are batched and re-queued on failure.
* Log files are opened per read and never held open, so IIS log cleanup and rotation are never blocked.
