"""Scheduled weekly / monthly HTML reports via APScheduler, delivered with mailer.py.

A report is always sent, even when nothing happened, so silence never hides a broken pipeline:
the subject then reads "IIS Sentinel: Weekly Summary (All Quiet)".
"""
from __future__ import annotations

import html
import json
import logging
import socket
from collections import Counter
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import case, desc, func, select

from database import (
    LOCAL_SERVER_ID,
    ActionableAlert,
    BannedIP,
    ConfigStore,
    LogEntry,
    MonitoredServer,
    ScheduledReport,
    SessionLocal,
    SystemMetric,
    purge_old_data,
    run_db,
    utcnow,
)

if TYPE_CHECKING:
    from mailer import Mailer

log = logging.getLogger("sentinel.reporter")

THREAT_CATEGORIES = ("threat", "attack")
REPORT_JOBS = {"weekly": "report_weekly", "monthly": "report_monthly"}


def _minus_one_month(dt: datetime) -> datetime:
    year, month = (dt.year - 1, 12) if dt.month == 1 else (dt.year, dt.month - 1)
    for day in (dt.day, 30, 29, 28):
        try:
            return dt.replace(year=year, month=month, day=day)
        except ValueError:
            continue
    return dt - timedelta(days=30)


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} PB"


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return f"{d}d {h}h {m}m"


class Reporter:
    def __init__(self, config: ConfigStore, mailer: "Mailer") -> None:
        self.config = config
        self.mailer = mailer
        self.on_failure: Callable[[str, str], Awaitable[None]] | None = None
        self.scheduler = AsyncIOScheduler(job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})

    # ------------------------------------------------------------------ scheduling
    def start(self) -> None:
        self.scheduler.start()
        self.scheduler.add_job(self._maintenance, CronTrigger(hour=3, minute=17), id="maintenance", replace_existing=True)
        self.reschedule()

    def shutdown(self) -> None:
        try:
            self.scheduler.shutdown(wait=False)
        except Exception:  # noqa: BLE001
            pass

    def reschedule(self) -> None:
        cfg = self.config.get("reports")
        for job_id in REPORT_JOBS.values():
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
        schedule = cfg.get("schedule", "weekly")
        hour, minute = int(cfg.get("hour", 7)), int(cfg.get("minute", 0))
        if schedule in ("weekly", "both"):
            self.scheduler.add_job(
                self._scheduled, CronTrigger(day_of_week=cfg.get("day_of_week", "mon"), hour=hour, minute=minute),
                args=["weekly"], id=REPORT_JOBS["weekly"], replace_existing=True,
            )
        if schedule in ("monthly", "both"):
            self.scheduler.add_job(
                self._scheduled, CronTrigger(day=int(cfg.get("day_of_month", 1)), hour=hour, minute=minute),
                args=["monthly"], id=REPORT_JOBS["monthly"], replace_existing=True,
            )
        log.info("Report schedule: %s -> %s", schedule, self.next_runs())

    def next_runs(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for kind, job_id in REPORT_JOBS.items():
            job = self.scheduler.get_job(job_id)
            nrt = getattr(job, "next_run_time", None) if job else None
            out[kind] = nrt.isoformat() if nrt else None
        return out

    async def _scheduled(self, kind: str) -> None:
        error = None
        try:
            result = await self.run_report(kind, send=True)
            if result.get("status") == "failed":
                error = result.get("error") or "delivery failed"
        except Exception as exc:  # noqa: BLE001
            log.exception("Scheduled %s report failed", kind)
            error = f"{type(exc).__name__}: {exc}"
        if error and self.on_failure is not None:
            try:
                await self.on_failure(kind, error)
            except Exception:  # noqa: BLE001
                log.exception("Report failure callback failed")

    async def _maintenance(self) -> None:
        try:
            removed = await purge_old_data(int(self.config.value("watchers", "retention_days", 45)))
            log.info("Retention purge removed %s", removed)
        except Exception:  # noqa: BLE001
            log.exception("Retention purge failed")

    # ------------------------------------------------------------------ data
    async def gather(self, start: datetime, end: datetime) -> dict[str, Any]:
        rng = (LogEntry.ts >= start) & (LogEntry.ts < end)
        async with SessionLocal() as s:
            totals = (
                await s.execute(
                    select(
                        func.count(),
                        func.count(func.distinct(LogEntry.c_ip)),
                        func.coalesce(func.sum(LogEntry.sc_bytes), 0),
                        func.coalesce(func.avg(LogEntry.time_taken), 0),
                        func.sum(case((LogEntry.sc_status < 300, 1), else_=0)),
                        func.sum(case(((LogEntry.sc_status >= 300) & (LogEntry.sc_status < 400), 1), else_=0)),
                        func.sum(case(((LogEntry.sc_status >= 400) & (LogEntry.sc_status < 500), 1), else_=0)),
                        func.sum(case((LogEntry.sc_status >= 500, 1), else_=0)),
                        func.sum(case((LogEntry.threat_tags != "", 1), else_=0)),
                    ).where(rng)
                )
            ).one()
            top_ips = (
                await s.execute(
                    select(LogEntry.c_ip, func.count().label("n"), func.sum(case((LogEntry.threat_tags != "", 1), else_=0)))
                    .where(rng).group_by(LogEntry.c_ip).order_by(desc("n")).limit(10)
                )
            ).all()
            top_uris = (
                await s.execute(
                    select(LogEntry.cs_uri_stem, func.count().label("n"), func.coalesce(func.avg(LogEntry.time_taken), 0))
                    .where(rng).group_by(LogEntry.cs_uri_stem).order_by(desc("n")).limit(10)
                )
            ).all()
            tag_rows = (
                await s.execute(
                    select(LogEntry.threat_tags, func.count()).where(rng & (LogEntry.threat_tags != "")).group_by(LogEntry.threat_tags)
                )
            ).all()
            threat_alerts = (
                await s.execute(
                    select(ActionableAlert)
                    .where((ActionableAlert.ts >= start) & (ActionableAlert.ts < end) & ActionableAlert.category.in_(THREAT_CATEGORIES))
                    .order_by(desc(ActionableAlert.ts)).limit(500)
                )
            ).scalars().all()
            sev_rows = (
                await s.execute(
                    select(ActionableAlert.severity, func.count()).where((ActionableAlert.ts >= start) & (ActionableAlert.ts < end)).group_by(ActionableAlert.severity)
                )
            ).all()
            system_alerts = (
                await s.execute(
                    select(ActionableAlert)
                    .where((ActionableAlert.ts >= start) & (ActionableAlert.ts < end) & (ActionableAlert.category == "system"))
                    .order_by(desc(ActionableAlert.ts)).limit(25)
                )
            ).scalars().all()
            health = (
                await s.execute(
                    select(
                        func.count(),
                        func.avg(SystemMetric.cpu_percent),
                        func.max(SystemMetric.cpu_percent),
                        func.avg(SystemMetric.ram_percent),
                        func.max(SystemMetric.ram_percent),
                        func.min(SystemMetric.disk_free_percent),
                        func.sum(case((SystemMetric.pools_all_started, 1), else_=0)),
                        func.min(SystemMetric.ts),
                        func.max(SystemMetric.ts),
                    ).where((SystemMetric.ts >= start) & (SystemMetric.ts < end))
                )
            ).one()
            pool_rows = (
                await s.execute(select(SystemMetric.server_id, SystemMetric.app_pools).where((SystemMetric.ts >= start) & (SystemMetric.ts < end)))
            ).all()
            latest = (await s.execute(select(SystemMetric).order_by(desc(SystemMetric.id)).limit(1))).scalar_one_or_none()
            names = {sid: name for sid, name in (await s.execute(select(MonitoredServer.id, MonitoredServer.server_name))).all()}
            srv_traffic = (
                await s.execute(
                    select(LogEntry.server_id, func.count(), func.sum(case((LogEntry.threat_tags != "", 1), else_=0)),
                           func.sum(case((LogEntry.sc_status >= 500, 1), else_=0)))
                    .where(rng).group_by(LogEntry.server_id)
                )
            ).all()
            srv_threats = dict((
                await s.execute(
                    select(ActionableAlert.server_id, func.count())
                    .where((ActionableAlert.ts >= start) & (ActionableAlert.ts < end) & ActionableAlert.category.in_(THREAT_CATEGORIES))
                    .group_by(ActionableAlert.server_id)
                )
            ).all())
            srv_health = {
                sid: (avg_cpu, max_cpu, n, up)
                for sid, avg_cpu, max_cpu, n, up in (
                    await s.execute(
                        select(SystemMetric.server_id, func.avg(SystemMetric.cpu_percent), func.max(SystemMetric.cpu_percent),
                               func.count(), func.sum(case((SystemMetric.pools_all_started, 1), else_=0)))
                        .where((SystemMetric.ts >= start) & (SystemMetric.ts < end)).group_by(SystemMetric.server_id)
                    )
                ).all()
            }
            srv_bans = dict((
                await s.execute(
                    select(BannedIP.server_id, func.count())
                    .where((BannedIP.banned_at >= start) & (BannedIP.banned_at < end)).group_by(BannedIP.server_id)
                )
            ).all())

        def name_of(sid: int | None) -> str:
            if sid in names:
                return names[sid]
            return socket.gethostname().upper() if sid == LOCAL_SERVER_ID else f"SRV-{sid}"

        fleet = []
        traffic = {sid: (n, m, e5) for sid, n, m, e5 in srv_traffic}
        for sid in sorted(set(traffic) | set(srv_threats) | set(srv_health) | set(srv_bans) | set(names), key=name_of):
            n, m, e5 = traffic.get(sid, (0, 0, 0))
            avg_cpu, max_cpu, samples_n, up = srv_health.get(sid, (None, None, 0, 0))
            fleet.append({
                "server": name_of(sid), "requests": int(n or 0), "malicious": int(m or 0), "errors_5xx": int(e5 or 0),
                "threats": int(srv_threats.get(sid, 0)), "bans": int(srv_bans.get(sid, 0)),
                "avg_cpu": float(avg_cpu) if avg_cpu is not None else None,
                "max_cpu": float(max_cpu) if max_cpu is not None else None,
                "pool_availability": (100.0 * int(up or 0) / samples_n) if samples_n else None,
            })

        tag_counts: Counter[str] = Counter()
        for tags, n in tag_rows:
            for t in str(tags).split(","):
                if t:
                    tag_counts[t] += int(n)

        pool_up: Counter[str] = Counter()
        pool_total: Counter[str] = Counter()
        for sid, raw in pool_rows:
            try:
                for name, state in json.loads(raw or "{}").items():
                    key = f"{name_of(sid)} / {name}"
                    pool_total[key] += 1
                    if state == "Started":
                        pool_up[key] += 1
            except json.JSONDecodeError:
                continue

        active = sorted(threat_alerts, key=lambda a: (a.category != "threat", -a.ts.timestamp()))
        threat_ips = Counter(a.source_ip for a in threat_alerts if a.source_ip)
        samples = int(health[0] or 0)
        return {
            "start": start,
            "end": end,
            "hostname": f"{len(fleet)} server(s): " + ", ".join(f["server"] for f in fleet) if fleet else socket.gethostname(),
            "fleet": fleet,
            "total_requests": int(totals[0] or 0),
            "unique_ips": int(totals[1] or 0),
            "bandwidth": int(totals[2] or 0),
            "avg_time_taken": float(totals[3] or 0),
            "status": {"2xx": int(totals[4] or 0), "3xx": int(totals[5] or 0), "4xx": int(totals[6] or 0), "5xx": int(totals[7] or 0)},
            "malicious_requests": int(totals[8] or 0),
            "attack_types": dict(tag_counts.most_common()),
            "top_ips": [{"ip": ip, "requests": int(n), "malicious": int(m or 0)} for ip, n, m in top_ips],
            "top_uris": [{"uri": u, "requests": int(n), "avg_ms": float(t or 0)} for u, n, t in top_uris],
            "threat_count": len(threat_alerts),
            "active_threats": [
                {"ts": a.ts, "ip": a.source_ip, "server": name_of(a.server_id), "title": a.title, "severity": a.severity}
                for a in active[:25]
            ],
            "threat_ips": threat_ips.most_common(10),
            "alerts_by_severity": {sev: int(n) for sev, n in sev_rows},
            "system_alerts": [{"ts": a.ts, "server": name_of(a.server_id), "title": a.title, "severity": a.severity} for a in system_alerts],
            "health": {
                "samples": samples,
                "avg_cpu": float(health[1] or 0),
                "max_cpu": float(health[2] or 0),
                "avg_ram": float(health[3] or 0),
                "max_ram": float(health[4] or 0),
                "min_disk_free": float(health[5]) if health[5] is not None else None,
                "pool_availability": (100.0 * int(health[6] or 0) / samples) if samples else None,
                "first_sample": health[7],
                "last_sample": health[8],
                "uptime_seconds": float(latest.uptime_seconds) if latest else None,
                "per_pool": {
                    name: round(100.0 * pool_up[name] / total, 2) for name, total in sorted(pool_total.items()) if total
                },
            },
        }

    # ------------------------------------------------------------------ rendering
    @staticmethod
    def subject_for(kind: str, data: dict[str, Any]) -> str:
        title = "Weekly" if kind == "weekly" else "Monthly"
        n = data["threat_count"]
        if n == 0:
            return f"IIS Sentinel: {title} Summary (All Quiet)"
        return f"IIS Sentinel: {title} Summary ({n} Threat{'s' if n != 1 else ''} Neutralized)"

    @staticmethod
    def render_html(kind: str, data: dict[str, Any]) -> str:
        esc = html.escape
        cyan, green, amber, red, muted, text = "#00f3ff", "#0aff00", "#ffae00", "#ff0033", "#6c7a89", "#d6f9ff"
        quiet = data["threat_count"] == 0
        accent = green if quiet else red
        title = "WEEKLY" if kind == "weekly" else "MONTHLY"
        period = f"{data['start']:%Y-%m-%d %H:%M} &rarr; {data['end']:%Y-%m-%d %H:%M} UTC"
        h = data["health"]
        td = "padding:8px 12px;border-bottom:1px solid #15232b;"
        th = f"padding:8px 12px;border-bottom:1px solid {cyan};color:{cyan};font-size:11px;letter-spacing:2px;text-align:left;"

        def kpi(label: str, value: str, color: str = cyan) -> str:
            return (
                f'<td width="25%" style="padding:14px;border:1px solid #15232b;background:#070b0d;">'
                f'<div style="color:{muted};font-size:10px;letter-spacing:2px;">{esc(label)}</div>'
                f'<div style="color:{color};font-size:20px;font-weight:bold;margin-top:6px;">{value}</div></td>'
            )

        def section(label: str) -> str:
            return (
                f'<tr><td style="padding:22px 24px 8px 24px;color:{cyan};font-size:12px;letter-spacing:3px;'
                f'border-bottom:1px solid #15232b;">// {esc(label)}</td></tr>'
            )

        def table(headers: list[str], rows: list[list[str]], empty: str) -> str:
            if not rows:
                return f'<tr><td style="padding:12px 24px;color:{muted};">{esc(empty)}</td></tr>'
            head = "".join(f'<th style="{th}">{esc(x)}</th>' for x in headers)
            body = "".join("<tr>" + "".join(f'<td style="{td}color:{text};word-break:break-all;">{c}</td>' for c in r) + "</tr>" for r in rows)
            return (
                f'<tr><td style="padding:8px 24px;"><table width="100%" cellpadding="0" cellspacing="0" '
                f'style="font-size:12px;border:1px solid #15232b;">{head and "<tr>" + head + "</tr>"}{body}</table></td></tr>'
            )

        status = data["status"]
        total = max(1, data["total_requests"])
        verdict = (
            f'<span style="color:{green};">ALL QUIET</span> &mdash; no threats were detected in this period.'
            if quiet
            else f'<span style="color:{red};">{data["threat_count"]} THREAT EVENT(S)</span> detected and flagged; '
            f'{data["malicious_requests"]:,} malicious requests identified.'
        )
        top_ips = [
            [esc(r["ip"]), f"{r['requests']:,}", f"{100 * r['requests'] / total:.1f}%",
             f'<span style="color:{red if r["malicious"] else muted};">{r["malicious"]:,}</span>']
            for r in data["top_ips"]
        ]
        top_uris = [[esc(r["uri"][:120]), f"{r['requests']:,}", f"{r['avg_ms']:.0f} ms"] for r in data["top_uris"]]
        threats = [
            [f"{a['ts']:%Y-%m-%d %H:%M}", esc(a.get("server", "")), f'<span style="color:{red};">{esc(a["ip"] or "-")}</span>', esc(a["title"])]
            for a in data["active_threats"]
        ]
        fleet = [
            [f'<span style="color:{cyan};">{esc(f["server"])}</span>', f"{f['requests']:,}",
             f'<span style="color:{red if f["malicious"] else muted};">{f["malicious"]:,}</span>',
             f'<span style="color:{red if f["threats"] else muted};">{f["threats"]:,}</span>',
             f'<span style="color:{green if f["bans"] else muted};">{f["bans"]:,}</span>',
             "n/a" if f["avg_cpu"] is None else f"{f['avg_cpu']:.0f}% / {f['max_cpu']:.0f}%",
             "n/a" if f["pool_availability"] is None else f"{f['pool_availability']:.1f}%"]
            for f in data.get("fleet", [])
        ]
        attack_types = [[esc(k), f"{v:,}"] for k, v in data["attack_types"].items()]
        threat_ips = [[esc(ip or "-"), f"{n:,}"] for ip, n in data["threat_ips"]]
        sys_alerts = [
            [f"{a['ts']:%Y-%m-%d %H:%M}", esc(a.get("server", "")), f'<span style="color:{red if a["severity"] == "CRITICAL" else amber};">{esc(a["severity"])}</span>', esc(a["title"])]
            for a in data["system_alerts"]
        ]
        pools = [
            [esc(name), f'<span style="color:{green if pct >= 99.9 else amber if pct >= 95 else red};">{pct:.2f}%</span>']
            for name, pct in h["per_pool"].items()
        ]

        def pct(v: float | None) -> str:
            return "n/a" if v is None else f"{v:.1f}%"

        health_rows = [
            ["Health samples", f"{h['samples']:,}"],
            ["CPU avg / peak", f"{h['avg_cpu']:.1f}% / {h['max_cpu']:.1f}%"],
            ["RAM avg / peak", f"{h['avg_ram']:.1f}% / {h['max_ram']:.1f}%"],
            ["Lowest disk free", pct(h["min_disk_free"])],
            ["All app pools running", pct(h["pool_availability"])],
            ["Current server uptime", _fmt_duration(h["uptime_seconds"]) if h["uptime_seconds"] else "n/a"],
        ]
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IIS Sentinel {title} Report</title></head>
<body style="margin:0;padding:0;background:#050505;font-family:Consolas,'Courier New',monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050505;padding:24px 0;"><tr><td align="center">
<table width="720" cellpadding="0" cellspacing="0" style="background:#0a0f12;border:1px solid {cyan};">
<tr><td style="padding:22px 24px;border-bottom:1px solid {cyan};">
<div style="color:{cyan};font-size:12px;letter-spacing:4px;">IIS SENTINEL // {title} INTELLIGENCE REPORT</div>
<div style="color:{muted};font-size:11px;margin-top:6px;">{esc(data['hostname'])} &nbsp;|&nbsp; {period}</div>
</td></tr>
<tr><td style="padding:20px 24px;border-bottom:1px solid #15232b;">
<div style="color:{accent};font-size:22px;font-weight:bold;letter-spacing:2px;">{'STATUS: ALL QUIET' if quiet else 'STATUS: HOSTILE ACTIVITY'}</div>
<div style="color:{text};font-size:13px;margin-top:8px;line-height:1.5;">{verdict}</div>
</td></tr>
<tr><td style="padding:16px 24px;"><table width="100%" cellpadding="0" cellspacing="6"><tr>
{kpi("TOTAL REQUESTS", f"{data['total_requests']:,}")}
{kpi("UNIQUE CLIENTS", f"{data['unique_ips']:,}")}
{kpi("BANDWIDTH OUT", _fmt_bytes(data['bandwidth']))}
{kpi("AVG RESPONSE", f"{data['avg_time_taken']:.0f} ms")}
</tr><tr>
{kpi("2XX / 3XX", f"{status['2xx']:,} / {status['3xx']:,}", green)}
{kpi("4XX ERRORS", f"{status['4xx']:,}", amber)}
{kpi("5XX ERRORS", f"{status['5xx']:,}", red if status['5xx'] else green)}
{kpi("THREATS", f"{data['threat_count']:,}", accent)}
</tr></table></td></tr>
{section("FLEET BREAKDOWN")}
{table(["SERVER", "REQUESTS", "MALICIOUS", "THREATS", "BANS", "CPU AVG / PEAK", "POOLS UP"], fleet, "No servers reported in this period.")}
{section("THREATS NEUTRALIZED")}
{table(["FIRST FLAGGED", "TARGET", "SOURCE IP", "EVENT"], threats, "No active threats were flagged in this period.")}
{table(["ATTACK SIGNATURE", "REQUESTS"], attack_types, "No attack signatures matched.")}
{table(["HOSTILE IP", "THREAT EVENTS"], threat_ips, "No hostile IPs.")}
{section("TOP 10 CLIENT IPS")}
{table(["IP ADDRESS", "REQUESTS", "SHARE", "MALICIOUS"], top_ips, "No traffic recorded.")}
{section("TOP 10 URIS")}
{table(["URI STEM", "REQUESTS", "AVG TIME"], top_uris, "No traffic recorded.")}
{section("SERVER HEALTH & UPTIME")}
{table([], health_rows, "")}
{table(["APP POOL", "AVAILABILITY"], pools, "No IIS application pool data collected.")}
{table(["TIME", "SERVER", "SEVERITY", "SYSTEM EVENT"], sys_alerts, "No system incidents.")}
<tr><td style="padding:18px 24px;border-top:1px solid #15232b;color:#3d4f5c;font-size:11px;">
Generated {utcnow():%Y-%m-%d %H:%M} UTC by IIS Sentinel. Alerts by severity: {esc(json.dumps(data['alerts_by_severity']))}
</td></tr></table></td></tr></table></body></html>"""

    # ------------------------------------------------------------------ orchestration
    async def run_report(self, kind: str, send: bool = True, recipients: list[str] | None = None) -> dict[str, Any]:
        if kind not in REPORT_JOBS:
            raise ValueError("kind must be 'weekly' or 'monthly'")
        end = utcnow()
        start = end - timedelta(days=7) if kind == "weekly" else _minus_one_month(end)
        data = await self.gather(start, end)
        subject = self.subject_for(kind, data)
        body = self.render_html(kind, data)
        status, error = "generated", ""
        if send:
            to = recipients or self.config.value("reports", "recipients", []) or self.config.value("exchange", "alert_recipients", [])
            ok, err = await self.mailer.send(subject, body, recipients=to, retries=3, bypass_circuit=True)
            status, error = ("sent", "") if ok else ("failed", err or "unknown error")
            if not ok:
                log.error("Report '%s' not delivered: %s", subject, error)

        async def _op(s):  # type: ignore[no-untyped-def]
            row = ScheduledReport(
                report_type=kind, period_start=start, period_end=end, generated_at=utcnow(), subject=subject,
                status=status, error=error, total_requests=data["total_requests"], threat_count=data["threat_count"], html=body,
            )
            s.add(row)
            await s.flush()
            return row.id

        report_id = None
        try:
            report_id = await run_db(_op)
        except Exception:  # noqa: BLE001
            log.exception("Failed to record report history")
        log.info("Report %s (%s): %s", kind, status, subject)
        return {
            "id": report_id,
            "kind": kind,
            "subject": subject,
            "status": status,
            "error": error,
            "total_requests": data["total_requests"],
            "threat_count": data["threat_count"],
        }
