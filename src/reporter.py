"""
reporter.py — Output and report generation for the Forensic Analysis Toolkit.

Supports two output modes:
  1. Console  → Richly formatted text printed to stdout (default mode)
  2. Markdown → A structured .md report saved to the reports/ directory

Forensic Phases Covered:
  Reporting → Present timeline, findings, and narrative in human-readable form
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.analyzer import (
    BruteForceIncident,
    IncidentTimeline,
    generate_summary_narrative,
)
from src.models import ForensicEvent


# ── Helpers ───────────────────────────────────────────────────────────────────

def _divider(char: str = "─", width: int = 72) -> str:
    return char * width


def _severity_icon(severity: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")


def _result_icon(result: str) -> str:
    return {"success": "✅", "failed": "❌", "suspicious": "⚠️", "unknown": "❓"}.get(result, "  ")


# ── Console Reporter ──────────────────────────────────────────────────────────

class ConsoleReporter:
    """Prints the full forensic report to stdout."""

    def __init__(self, width: int = 72):
        self.width = width

    def _header(self, title: str) -> None:
        print(_divider("═", self.width))
        print(f"  {title}")
        print(_divider("═", self.width))

    def _section(self, title: str) -> None:
        print()
        print(_divider("─", self.width))
        print(f"  {title}")
        print(_divider("─", self.width))

    def print_banner(self) -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._header(f"FORENSIC ANALYSIS REPORT  |  Generated: {now}")

    def print_timeline(self, timeline: IncidentTimeline) -> None:
        self._section(f"INCIDENT TIMELINE  [{timeline.label}]  ({len(timeline.events)} event(s))")
        if not timeline.events:
            print("  (no events match the current filter)")
            return
        for ev in timeline.events:
            icon = _result_icon(ev.result)
            ts   = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            user = f"  user={ev.user}" if ev.user else ""
            ip   = f"  ip={ev.ip_address}" if ev.ip_address else ""
            print(
                f"  {icon}  {ts}  [{ev.source}]  {ev.event_type.upper():<20}"
                f"{user:<22}{ip:<20}  {ev.details[:60]}"
            )
        if timeline.findings:
            print()
            for f in timeline.findings:
                print(f"  ℹ️  {f}")

    def print_bruteforce(self, incidents: list[BruteForceIncident]) -> None:
        self._section(f"BRUTE-FORCE ANALYSIS  ({len(incidents)} incident(s))")
        if not incidents:
            print("  ✅ No brute-force patterns detected.")
            return
        for inc in incidents:
            icon = _severity_icon(inc.severity)
            user = inc.user or "unknown"
            ip   = inc.ip_address or "unknown"
            print(f"\n  {icon} [{inc.severity}]  user={user}  ip={ip}")
            print(f"     Failed attempts : {inc.failed_count}")
            print(f"     Time window     : {inc.first_attempt:%H:%M:%S} → {inc.last_attempt:%H:%M:%S}")
            print(f"     Outcome         : {'⚠️  SUCCESSFUL LOGIN — potential compromise!' if inc.succeeded else '🔒 No successful login.'}")

    def print_file_correlations(self, correlations: list[dict]) -> None:
        self._section(
            f"SUSPICIOUS FILE ACCESS CORRELATIONS  ({len(correlations)} correlation(s))"
        )
        if not correlations:
            print("  ✅ No suspicious post-login file access detected.")
            return
        for corr in correlations:
            login = corr["login_event"]
            files = corr["file_events"]
            print(f"\n  ⚠️  user={login.user}  ip={login.ip_address}")
            print(f"     Login at {login.timestamp:%H:%M:%S}  [{login.result.upper()}]")
            print(f"     Followed by {len(files)} file access event(s):")
            for fe in files:
                print(f"       • {fe.timestamp:%H:%M:%S}  {fe.details[:60]}")

    def print_scan_alerts(self, alerts: list[ForensicEvent]) -> None:
        self._section(f"SCAN / ATTACK ALERTS  ({len(alerts)} event(s))")
        if not alerts:
            print("  ✅ No scanner/attack alerts detected.")
            return
        for alert in alerts:
            print(
                f"  ⚠️  {alert.timestamp:%H:%M:%S}  ip={alert.ip_address:<18}  "
                f"{alert.details[:60]}"
            )

    def print_narrative(self, narrative: str) -> None:
        self._section("EXECUTIVE SUMMARY")
        for line in narrative.splitlines():
            print(f"  {line}")

    def print_footer(self) -> None:
        print()
        print(_divider("═", self.width))
        print("  END OF REPORT")
        print(_divider("═", self.width))

    def render(
        self,
        all_events:        list[ForensicEvent],
        timeline:          IncidentTimeline,
        bf_incidents:      list[BruteForceIncident],
        file_correlations: list[dict],
        scan_alerts:       list[ForensicEvent],
    ) -> None:
        """Render the complete report to stdout."""
        narrative = generate_summary_narrative(
            all_events, bf_incidents, file_correlations, scan_alerts
        )
        self.print_banner()
        self.print_narrative(narrative)
        self.print_timeline(timeline)
        self.print_bruteforce(bf_incidents)
        self.print_file_correlations(file_correlations)
        self.print_scan_alerts(scan_alerts)
        self.print_footer()


# ── Markdown Reporter ─────────────────────────────────────────────────────────

class MarkdownReporter:
    """Saves the forensic report as a Markdown file in the reports/ directory."""

    def __init__(self, output_dir: str | Path = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _result_badge(self, result: str) -> str:
        badges = {
            "success":    "`✅ SUCCESS`",
            "failed":     "`❌ FAILED`",
            "suspicious": "`⚠️ SUSPICIOUS`",
            "unknown":    "`❓ UNKNOWN`",
        }
        return badges.get(result, f"`{result.upper()}`")

    def render(
        self,
        all_events:        list[ForensicEvent],
        timeline:          IncidentTimeline,
        bf_incidents:      list[BruteForceIncident],
        file_correlations: list[dict],
        scan_alerts:       list[ForensicEvent],
        filename:          Optional[str] = None,
    ) -> Path:
        """Write the full report to a Markdown file and return its path."""
        narrative = generate_summary_narrative(
            all_events, bf_incidents, file_correlations, scan_alerts
        )

        now = datetime.now()
        if filename is None:
            filename = f"forensic_report_{now:%Y%m%d_%H%M%S}.md"
        out_path = self.output_dir / filename

        lines: list[str] = []

        # ── Title ─────────────────────────────────────────────────────────────
        lines += [
            "# 🔍 Forensic Analysis Report",
            "",
            f"**Generated:** {now:%Y-%m-%d %H:%M:%S}  ",
            f"**Total Events Analyzed:** {len(all_events)}  ",
            "",
            "---",
            "",
        ]

        # ── Executive Summary ─────────────────────────────────────────────────
        lines += ["## Executive Summary", ""]
        lines += ["```", narrative, "```", ""]

        # ── Timeline ──────────────────────────────────────────────────────────
        lines += [
            f"## Incident Timeline — *{timeline.label}* ({len(timeline.events)} events)",
            "",
            "| Timestamp | Source | Type | User | IP | Result | Details |",
            "|-----------|--------|------|------|----|--------|---------|",
        ]
        for ev in timeline.events:
            ts      = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            user    = ev.user or "—"
            ip      = ev.ip_address or "—"
            details = ev.details[:70].replace("|", "\\|")
            lines.append(
                f"| {ts} | {ev.source} | {ev.event_type} | {user} | {ip} "
                f"| {self._result_badge(ev.result)} | {details} |"
            )
        lines.append("")

        # ── Brute-force ───────────────────────────────────────────────────────
        lines += [f"## Brute-Force Incidents ({len(bf_incidents)})", ""]
        if not bf_incidents:
            lines += ["> ✅ No brute-force patterns detected.", ""]
        else:
            for inc in bf_incidents:
                icon = _severity_icon(inc.severity)
                lines += [
                    f"### {icon} [{inc.severity}] user=`{inc.user or 'unknown'}`  "
                    f"ip=`{inc.ip_address or 'unknown'}`",
                    "",
                    f"- **Failed attempts:** {inc.failed_count}",
                    f"- **Window:** `{inc.first_attempt:%H:%M:%S}` → `{inc.last_attempt:%H:%M:%S}`",
                    f"- **Compromised:** {'⚠️ Yes — successful login detected' if inc.succeeded else 'No'}",
                    "",
                ]

        # ── File correlations ──────────────────────────────────────────────────
        lines += [f"## Suspicious File Access ({len(file_correlations)} correlation(s))", ""]
        if not file_correlations:
            lines += ["> ✅ No suspicious post-login file access detected.", ""]
        else:
            for corr in file_correlations:
                login = corr["login_event"]
                files = corr["file_events"]
                lines += [
                    f"### ⚠️ user=`{login.user}`  ip=`{login.ip_address}`",
                    "",
                    f"Login at `{login.timestamp:%H:%M:%S}` ({login.result}), "
                    f"followed by **{len(files)}** file access event(s):",
                    "",
                ]
                for fe in files:
                    lines.append(f"- `{fe.timestamp:%H:%M:%S}` — {fe.details[:80]}")
                lines.append("")

        # ── Scan alerts ────────────────────────────────────────────────────────
        lines += [f"## Scan / Attack Alerts ({len(scan_alerts)} event(s))", ""]
        if not scan_alerts:
            lines += ["> ✅ No scanner/attack alerts detected.", ""]
        else:
            lines += [
                "| Timestamp | IP | Details |",
                "|-----------|-----|---------|",
            ]
            for alert in scan_alerts:
                ts      = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                details = alert.details[:80].replace("|", "\\|")
                lines.append(f"| {ts} | {alert.ip_address or '—'} | {details} |")
            lines.append("")

        # ── Footer ─────────────────────────────────────────────────────────────
        lines += [
            "---",
            "",
            "*Report generated by the Forensic Analysis Toolkit.*  ",
            "*This output is for investigative reference only.*",
        ]

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
