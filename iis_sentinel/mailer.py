"""Exchange (EWS) mail delivery for real-time alerts and scheduled HTML reports.

Every public coroutine here swallows Exchange failures and returns a status instead of raising:
an unreachable Exchange server must never take the monitoring pipeline down.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import threading
import time
from collections import deque
from typing import Any

from database import ConfigStore

log = logging.getLogger("sentinel.mailer")

SEVERITY_COLORS = {
    "CRITICAL": "#ff0033",
    "HIGH": "#ff5e00",
    "WARNING": "#ffae00",
    "INFO": "#00f3ff",
}


class MailerError(RuntimeError):
    pass


class Mailer:
    CIRCUIT_FAILURES = 3
    CIRCUIT_OPEN_SECONDS = 300

    def __init__(self, config: ConfigStore) -> None:
        self.config = config
        self._account: Any = None
        self._account_sig: tuple[Any, ...] | None = None
        self._thread_lock = threading.Lock()
        self._alert_times: deque[float] = deque()
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self.last_error: str | None = None
        self.last_success: float | None = None

    # ---------------------------------------------------------------- sync (worker thread)
    @staticmethod
    def _signature(cfg: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(cfg.get(k) for k in ("server", "autodiscover", "email", "username", "password", "auth_type", "verify_ssl", "timeout"))

    def _build_account(self, cfg: dict[str, Any]) -> Any:
        try:
            import requests.adapters
            from exchangelib import DELEGATE, Account, Configuration, Credentials
            from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
        except ImportError as exc:
            raise MailerError(f"exchangelib not installed: {exc}") from exc

        if not cfg.get("email"):
            raise MailerError("Exchange sender mailbox (email) is not configured")
        if not cfg.get("autodiscover") and not cfg.get("server"):
            raise MailerError("Exchange server is not configured")

        BaseProtocol.TIMEOUT = int(cfg.get("timeout") or 30)
        BaseProtocol.HTTP_ADAPTER_CLS = (
            requests.adapters.HTTPAdapter if cfg.get("verify_ssl", True) else NoVerifyHTTPAdapter
        )
        username = cfg.get("username") or cfg["email"]
        credentials = Credentials(username=username, password=cfg.get("password") or "")
        if cfg.get("autodiscover"):
            return Account(
                primary_smtp_address=cfg["email"],
                credentials=credentials,
                autodiscover=True,
                access_type=DELEGATE,
            )
        configuration = Configuration(
            server=cfg["server"],
            credentials=credentials,
            auth_type=cfg.get("auth_type") or "NTLM",
            max_connections=4,
        )
        return Account(
            primary_smtp_address=cfg["email"],
            config=configuration,
            autodiscover=False,
            access_type=DELEGATE,
        )

    def _send_sync(self, cfg: dict[str, Any], subject: str, html_body: str, recipients: list[str]) -> None:
        from exchangelib import HTMLBody, Mailbox, Message

        with self._thread_lock:
            sig = self._signature(cfg)
            if self._account is None or self._account_sig != sig:
                self._account = self._build_account(cfg)
                self._account_sig = sig
            account = self._account
        msg = Message(
            account=account,
            subject=subject,
            body=HTMLBody(html_body),
            to_recipients=[Mailbox(email_address=r) for r in recipients],
        )
        msg.send()

    # ---------------------------------------------------------------- async API
    async def send(
        self,
        subject: str,
        html_body: str,
        recipients: list[str] | None = None,
        retries: int = 3,
        bypass_circuit: bool = False,
    ) -> tuple[bool, str | None]:
        cfg = self.config.get("exchange")
        if not cfg.get("enabled"):
            return False, "Exchange delivery is disabled in config"
        to = [r for r in (recipients or cfg.get("alert_recipients") or []) if r]
        if not to:
            return False, "No recipients configured"
        now = time.monotonic()
        if not bypass_circuit and now < self._circuit_open_until:
            return False, f"Exchange circuit open for {int(self._circuit_open_until - now)}s after repeated failures"

        timeout = float(cfg.get("timeout") or 30) + 15
        delay = 2.0
        last_error = "unknown error"
        for attempt in range(1, retries + 1):
            try:
                await asyncio.wait_for(asyncio.to_thread(self._send_sync, cfg, subject, html_body, to), timeout=timeout)
                self._consecutive_failures = 0
                self._circuit_open_until = 0.0
                self.last_error = None
                self.last_success = time.time()
                log.info("Mail sent: '%s' -> %s", subject, ", ".join(to))
                return True, None
            except asyncio.TimeoutError:
                last_error = f"Exchange did not respond within {int(timeout)}s"
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
            self._account = None
            log.warning("Mail attempt %d/%d failed: %s", attempt, retries, last_error)
            if attempt < retries:
                await asyncio.sleep(delay)
                delay *= 2

        self._consecutive_failures += 1
        self.last_error = last_error
        if self._consecutive_failures >= self.CIRCUIT_FAILURES:
            self._circuit_open_until = time.monotonic() + self.CIRCUIT_OPEN_SECONDS
            log.error("Exchange unreachable %d times in a row; pausing alert mail for %ds",
                      self._consecutive_failures, self.CIRCUIT_OPEN_SECONDS)
        return False, last_error

    async def send_alert(self, record: dict[str, Any]) -> bool:
        cfg = self.config.get("exchange")
        limit = int(cfg.get("max_alerts_per_hour") or 20)
        now = time.monotonic()
        while self._alert_times and now - self._alert_times[0] > 3600:
            self._alert_times.popleft()
        if len(self._alert_times) >= limit and record.get("severity") != "CRITICAL":
            log.warning("Alert mail rate limit (%d/h) reached; not mailing '%s'", limit, record.get("title"))
            return False
        self._alert_times.append(now)
        server = f"[{record['server_name']}] " if record.get("server_name") else ""
        subject = f"[IIS Sentinel][{record.get('severity')}] {server}{record.get('title')}"
        ok, err = await self.send(subject, render_alert_html(record))
        if not ok:
            log.warning("Alert mail not delivered: %s", err)
        return ok

    async def send_test(self, recipients: list[str] | None = None) -> tuple[bool, str | None]:
        record = {
            "severity": "INFO",
            "category": "test",
            "title": "Exchange connectivity test",
            "message": "If you can read this, IIS Sentinel can deliver alerts through Exchange.",
            "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "source_ip": None,
            "details": {},
        }
        return await self.send("IIS Sentinel: Exchange test message", render_alert_html(record),
                               recipients=recipients, retries=1, bypass_circuit=True)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.config.value("exchange", "enabled", False)),
            "last_error": self.last_error,
            "last_success": self.last_success,
            "circuit_open": time.monotonic() < self._circuit_open_until,
        }


def render_alert_html(record: dict[str, Any]) -> str:
    esc = html.escape
    sev = str(record.get("severity", "INFO"))
    color = SEVERITY_COLORS.get(sev, "#00f3ff")
    details = record.get("details") or {}
    rows = "".join(
        f'<tr><td style="padding:6px 12px;color:#6c7a89;border-bottom:1px solid #15232b;">{esc(str(k))}</td>'
        f'<td style="padding:6px 12px;color:#d6f9ff;border-bottom:1px solid #15232b;word-break:break-all;">'
        f"{esc(v if isinstance(v, str) else json.dumps(v, default=str))}</td></tr>"
        for k, v in details.items()
    )
    source = (
        f'<p style="margin:0 0 8px 0;color:#9fb3c8;">Source IP: '
        f'<b style="color:{color};">{esc(str(record["source_ip"]))}</b></p>'
        if record.get("source_ip")
        else ""
    )
    return f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#050505;font-family:Consolas,'Courier New',monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050505;padding:24px 0;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="background:#0a0f12;border:1px solid {color};">
<tr><td style="padding:18px 24px;border-bottom:1px solid {color};">
<span style="color:#00f3ff;font-size:13px;letter-spacing:3px;">IIS SENTINEL // ALERT</span>
<span style="float:right;color:{color};font-size:13px;font-weight:bold;letter-spacing:2px;">{esc(sev)}</span>
</td></tr>
<tr><td style="padding:24px;">
<h2 style="margin:0 0 12px 0;color:{color};font-size:20px;">{esc(str(record.get("title", "")))}</h2>
<p style="margin:0 0 8px 0;color:#9fb3c8;">Server: <b style="color:#00f3ff;">{esc(str(record.get("server_name") or "-"))}</b> &nbsp;|&nbsp; Time: {esc(str(record.get("ts", "")))} &nbsp;|&nbsp; Category: {esc(str(record.get("category", "")))}</p>
{source}
<p style="margin:16px 0;color:#d6f9ff;line-height:1.5;">{esc(str(record.get("message", "")))}</p>
{f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:12px;font-size:12px;border:1px solid #15232b;">{rows}</table>' if rows else ''}
</td></tr>
<tr><td style="padding:12px 24px;border-top:1px solid #15232b;color:#3d4f5c;font-size:11px;">Automated message from IIS Sentinel.</td></tr>
</table></td></tr></table></body></html>"""
