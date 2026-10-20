"""Catalog of every notification event Sentinel can raise, with the defaults used for the ALERTS config tab.

Each event has three independent switches the operator can flip per event:
    enabled  - record it in the alert stream at all (core events cannot be disabled)
    desktop  - pop a toast + browser/desktop notification on every open dashboard
    email    - send it through Exchange to the alert recipients
plus a severity override ("default" keeps the severity Sentinel computes at runtime).
"""
from __future__ import annotations

from typing import Any

SEVERITIES = ["INFO", "WARNING", "HIGH", "CRITICAL"]

GROUPS: list[tuple[str, str]] = [
    ("threats", "Threats & attacks"),
    ("http", "HTTP errors & traffic"),
    ("health", "Server & site health"),
    ("defense", "Active defense"),
    ("sentinel", "Sentinel & access"),
]

# id, group, label, description, default severity, enabled, desktop, email, core
_EVENTS: list[tuple[str, str, str, str, str, bool, bool, bool, bool]] = [
    # ---- threats
    ("active_threat", "threats", "Active threat (ban approval needed)",
     "An attacker's threat score crossed the threshold; it is queued for ban approval.", "HIGH", True, True, True, True),
    ("attack_sqli", "threats", "SQL injection attempt", "A request matched a SQL injection signature.", "WARNING", True, True, False, False),
    ("attack_xss", "threats", "Cross-site scripting attempt", "A request matched an XSS signature.", "WARNING", True, True, False, False),
    ("attack_traversal", "threats", "Path traversal / file inclusion", "A request tried to escape the web root (../, %2e%2e, etc).",
     "WARNING", True, True, False, False),
    ("attack_scanner", "threats", "Vulnerability scanner", "A known scanner user agent (sqlmap, nikto, zgrab...) was seen.",
     "WARNING", True, False, False, False),
    ("spike_404", "threats", "404 scan burst", "One IP produced a burst of 404s (content discovery / forced browsing).",
     "WARNING", True, False, False, False),
    ("dir_enum", "threats", "Directory enumeration (404 scan)",
     "One IP requested several different missing paths within a few minutes (forced browsing / directory brute force). "
     "Queued for ban approval with the probed URIs and WHOIS owner.", "WARNING", True, True, False, False),
    ("spike_auth", "threats", "Brute force (401/403 burst)", "One IP produced a burst of 401/403 responses (password spraying).",
     "WARNING", True, True, False, False),
    ("threat_cleared", "threats", "Threat cleared", "An attacker's score decayed back below the threshold.", "INFO", True, False, False, False),
    # ---- http
    ("http_5xx", "http", "HTTP server error (each)",
     "A site returned a server error (codes below, default 500-599). Repeats of the same URL are rolled up during the cooldown.",
     "WARNING", True, True, False, False),
    ("http_5xx_burst", "http", "Server error burst",
     "A site returned many server errors within the burst window (an outage or broken deploy).", "HIGH", True, True, True, False),
    ("http_status_watch", "http", "Watched status code",
     "A response used one of the extra status codes you chose to watch (e.g. 413, 429).", "WARNING", False, False, False, False),
    ("slow_response", "http", "Slow responses",
     "A site served several requests slower than the slow-response threshold within the window.", "WARNING", True, False, False, False),
    ("anomaly_ip", "http", "Abnormal client behaviour",
     "One client's request volume or bandwidth deviated far from its learned baseline.", "WARNING", True, False, False, False),
    ("anomaly_server", "http", "Traffic surge", "Server-wide request volume or bandwidth spiked far above the baseline.",
     "WARNING", True, True, False, False),
    ("traffic_drop", "http", "Traffic drop", "Server-wide traffic fell far below the baseline (possible outage).", "HIGH", True, True, True, False),
    ("latency_anomaly", "http", "Latency anomaly", "Response times deviated far above the learned baseline.", "WARNING", True, False, False, False),
    # ---- health
    ("server_unreachable", "health", "Server unreachable", "Sentinel cannot collect health from a server over WinRM.",
     "HIGH", True, True, True, False),
    ("server_recovered", "health", "Server reachable again", "Health telemetry from a server was restored.", "INFO", True, True, False, False),
    ("log_feed_offline", "health", "Log feed offline", "Sentinel cannot read a server's IIS logs (share offline, access denied).",
     "HIGH", True, True, True, False),
    ("log_feed_restored", "health", "Log feed restored", "Sentinel is reading a server's IIS logs again.", "INFO", True, False, False, False),
    ("site_discovered", "health", "New site log folder", "A new W3SVC site log folder appeared under a watched log root.",
     "INFO", True, False, False, False),
    ("site_stopped", "health", "IIS site stopped", "An IIS website stopped serving (state is no longer Started).", "HIGH", True, True, True, False),
    ("site_started", "health", "IIS site started", "A stopped IIS website is running again.", "INFO", True, False, False, False),
    ("app_pool_stopped", "health", "App pool stopped", "An IIS application pool stopped; its sites return 503.", "CRITICAL", True, True, True, False),
    ("app_pool_recovered", "health", "App pool recovered", "A stopped application pool is running again.", "INFO", True, False, False, False),
    ("app_pool_removed", "health", "App pool removed", "An application pool is no longer reported by IIS.", "WARNING", True, False, False, False),
    ("w3svc_down", "health", "W3SVC stopped", "The World Wide Web Publishing Service is not running: every site is down.",
     "CRITICAL", True, True, True, False),
    ("w3svc_recovered", "health", "W3SVC running again", "The IIS web service recovered.", "INFO", True, True, False, False),
    ("cpu_high", "health", "High CPU", "CPU utilisation exceeded the threshold.", "HIGH", True, False, False, False),
    ("ram_high", "health", "High memory", "Memory utilisation exceeded the threshold.", "WARNING", True, False, False, False),
    ("disk_low", "health", "Disk space critical", "Free space on the IIS log volume dropped below the threshold.", "CRITICAL", True, True, True, False),
    ("cert_expiring", "health", "TLS certificate expiring",
     "An HTTPS binding's certificate expires within the warning window (or already expired).", "WARNING", True, False, True, False),
    # ---- defense
    ("ban_executed", "defense", "Firewall ban executed", "An operator approved a ban and the firewall rule was created.", "INFO", True, False, False, False),
    ("ban_failed", "defense", "Firewall ban failed", "A ban was approved but the firewall rule could not be created.", "HIGH", True, True, True, False),
    ("ban_lifted", "defense", "Firewall ban lifted", "An operator removed a Sentinel firewall rule.", "INFO", True, False, False, False),
    ("range_ban_executed", "defense", "CIDR range banned",
     "An operator approved a subnet (CIDR) ban and it was applied to the Windows Firewall and/or SonicWall group.", "WARNING", True, False, False, False),
    ("range_ban_lifted", "defense", "CIDR range ban lifted", "An operator removed a Sentinel subnet (CIDR) ban.", "INFO", True, False, False, False),
    # ---- sentinel
    ("breakglass_login", "sentinel", "Break-glass login",
     "Someone signed in with the local emergency account (normally only used when AD is down).", "HIGH", True, True, True, False),
    ("login_lockout", "sentinel", "Login lockout", "Repeated failed sign-ins locked out a user or source IP.", "WARNING", True, True, False, False),
    ("login_failed", "sentinel", "Failed sign-in", "A dashboard sign-in attempt failed.", "INFO", False, False, False, False),
    ("login_success", "sentinel", "Successful sign-in", "An operator signed in to the dashboard.", "INFO", False, False, False, False),
    ("config_changed", "sentinel", "Configuration changed", "Someone changed Sentinel's configuration.", "INFO", True, False, False, False),
    ("server_config_changed", "sentinel", "Monitored servers changed", "A monitored server was added, edited or removed.",
     "INFO", True, False, False, False),
    ("report_failed", "sentinel", "Scheduled report failed", "A scheduled HTML report could not be generated or delivered.",
     "WARNING", True, True, False, False),
    ("sentinel_started", "sentinel", "Sentinel started", "The Sentinel service started (e.g. after a reboot or crash).", "INFO", True, False, False, False),
]

EVENTS: dict[str, dict[str, Any]] = {
    eid: {"id": eid, "group": group, "label": label, "description": desc, "severity": sev,
          "enabled": enabled, "desktop": desktop, "email": email, "core": core}
    for eid, group, label, desc, sev, enabled, desktop, email, core in _EVENTS
}

SIGNATURE_EVENTS = {"SQLI": "attack_sqli", "XSS": "attack_xss", "TRAVERSAL": "attack_traversal", "SCANNER": "attack_scanner"}

ANOMALY_EVENTS = {
    "rpm": "anomaly_ip", "bpm": "anomaly_ip", "time_taken": "latency_anomaly",
    "global_rpm": "anomaly_server", "global_bpm": "anomaly_server", "global_rpm_drop": "traffic_drop",
}


def default_event_settings(email_min_rank: int | None = None) -> dict[str, dict[str, Any]]:
    """Per-event defaults. `email_min_rank` (index into SEVERITIES) seeds email flags from the legacy
    exchange.alert_min_severity setting so upgrades keep mailing what they mailed before."""
    out: dict[str, dict[str, Any]] = {}
    for eid, ev in EVENTS.items():
        email = ev["email"]
        if email_min_rank is not None:
            email = ev["enabled"] and SEVERITIES.index(ev["severity"]) >= email_min_rank
        out[eid] = {"enabled": ev["enabled"], "desktop": ev["desktop"], "email": email, "severity": "default"}
    return out


def catalog() -> dict[str, Any]:
    return {"groups": [{"id": g, "label": label} for g, label in GROUPS], "events": list(EVENTS.values())}
