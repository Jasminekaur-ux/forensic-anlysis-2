"""
analyzer.py — Forensic analysis and event correlation engine.

This module implements DFIR analysis routines that work exclusively on lists
of ForensicEvent objects, keeping it parser-agnostic.

Forensic Phases Covered:
  Analysis → Event correlation, pattern detection, timeline reconstruction

Key routines:
  find_bruteforce_patterns()   — Detect credential-stuffing / brute-force attacks
  find_suspicious_file_access() — Identify sensitive file access after wrong logins
  find_scan_alerts()           — Surface scanner/injection alert events
  build_incident_timeline()    — Produce a sorted, optionally-filtered timeline
  generate_summary_narrative() — Create a human-readable prose summary
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from src.models import ForensicEvent


# ─────────────────────────────────────────────────────────────────────────────
# Result containers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BruteForceIncident:
    """Represents a detected brute-force / credential-stuffing pattern."""
    user:         Optional[str]
    ip_address:   Optional[str]
    failed_count: int
    succeeded:    bool                      # Was there a successful login after?
    first_attempt: datetime
    last_attempt:  datetime
    events:        list[ForensicEvent] = field(default_factory=list, repr=False)

    @property
    def severity(self) -> str:
        if self.succeeded:
            return "CRITICAL"              # Actual compromise
        if self.failed_count >= 10:
            return "HIGH"
        if self.failed_count >= 5:
            return "MEDIUM"
        return "LOW"


@dataclass
class IncidentTimeline:
    """An ordered sequence of ForensicEvents representing a reconstructed timeline."""
    label:        str
    events:       list[ForensicEvent] = field(default_factory=list)
    findings:     list[str]           = field(default_factory=list)   # Human-readable notes


# ─────────────────────────────────────────────────────────────────────────────
# Core analysis functions
# ─────────────────────────────────────────────────────────────────────────────

def find_bruteforce_patterns(
    events: list[ForensicEvent],
    failed_threshold: int = 3,
    time_window_minutes: int = 15,
) -> list[BruteForceIncident]:
    """
    Identify credential-stuffing or brute-force login patterns.

    Strategy:
      1. Group login events by (user, ip) pair.
      2. Within each group, find consecutive failed-login bursts within
         *time_window_minutes* of each other.
      3. Flag any burst that meets or exceeds *failed_threshold*.
      4. Check whether a successful login follows the burst (indicating compromise).

    Args:
        events:               Normalized events from any parser.
        failed_threshold:     Minimum consecutive failures to flag as brute force.
        time_window_minutes:  Max gap (minutes) between failures to stay in a burst.

    Returns:
        List of BruteForceIncident objects, sorted by severity then timestamp.
    """
    # Only consider login events
    login_events = sorted(
        [e for e in events if e.event_type in {"login", "network_connection"}
         and e.result in {"failed", "success", "suspicious"}],
    )

    # Group by (user, ip) — None values treated as a wildcard key component
    groups: dict[tuple, list[ForensicEvent]] = defaultdict(list)
    for ev in login_events:
        key = (ev.user, ev.ip_address)
        groups[key].append(ev)

    incidents: list[BruteForceIncident] = []
    window = timedelta(minutes=time_window_minutes)

    for (user, ip), evs in groups.items():
        # Sliding-window burst detection
        burst: list[ForensicEvent] = []
        for ev in evs:
            if ev.result == "failed":
                if burst and (ev.timestamp - burst[-1].timestamp) > window:
                    # Gap too large → reset burst
                    burst = [ev]
                else:
                    burst.append(ev)
            elif ev.result in {"success", "suspicious"} and burst:
                # A success/suspicious event ends the burst — record incident
                if len(burst) >= failed_threshold:
                    succeeded = ev.result == "success"
                    incident  = BruteForceIncident(
                        user          = user,
                        ip_address    = ip,
                        failed_count  = len(burst),
                        succeeded     = succeeded,
                        first_attempt = burst[0].timestamp,
                        last_attempt  = ev.timestamp,
                        events        = burst + [ev],
                    )
                    incidents.append(incident)
                burst = []
            # Lone success with no preceding burst — skip

        # Burst at end of stream (no subsequent success)
        if len(burst) >= failed_threshold:
            incidents.append(BruteForceIncident(
                user          = user,
                ip_address    = ip,
                failed_count  = len(burst),
                succeeded     = False,
                first_attempt = burst[0].timestamp,
                last_attempt  = burst[-1].timestamp,
                events        = burst,
            ))

    # Sort: CRITICAL first, then by first attempt time
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    incidents.sort(key=lambda i: (severity_order[i.severity], i.first_attempt))
    return incidents


def find_suspicious_file_access(
    events: list[ForensicEvent],
    time_window_minutes: int = 30,
) -> list[dict]:
    """
    Detect sensitive file access that follows a suspicious/failed login,
    hinting at lateral movement or data exfiltration after compromise.

    Returns a list of correlation dicts with keys:
      - login_event: the suspicious/failed login
      - file_events: list of file_access events within the time window
    """
    suspicious_logins = [
        e for e in events
        if e.event_type == "login" and e.result in {"suspicious", "success"}
    ]
    file_events = [
        e for e in events
        if e.event_type == "file_access"
    ]

    correlations = []
    window = timedelta(minutes=time_window_minutes)

    for login_ev in suspicious_logins:
        # Look for file access events by the same user shortly after login
        related_files = [
            fe for fe in file_events
            if fe.user == login_ev.user
            and timedelta(0) < (fe.timestamp - login_ev.timestamp) <= window
        ]
        if related_files:
            correlations.append({
                "login_event": login_ev,
                "file_events": sorted(related_files),
            })

    return correlations


def find_scan_alerts(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """
    Return all events classified as 'alert' (scanner probes, injection attempts, etc.).
    These are typically already flagged by the parser but surfaced here for the report.
    """
    return sorted([e for e in events if e.event_type == "alert"])


def build_incident_timeline(
    events: list[ForensicEvent],
    filter_by_user: Optional[str] = None,
    filter_by_ip:   Optional[str] = None,
    only_suspicious: bool          = False,
) -> IncidentTimeline:
    """
    Build a chronologically sorted, optionally-filtered incident timeline.

    Args:
        events:          Full event list.
        filter_by_user:  If set, only include events matching this user.
        filter_by_ip:    If set, only include events matching this IP.
        only_suspicious: If True, include only failed/suspicious/alert events.

    Returns:
        IncidentTimeline with sorted events and human-readable findings.
    """
    filtered = list(events)

    if filter_by_user:
        filtered = [e for e in filtered if e.user == filter_by_user]
    if filter_by_ip:
        filtered = [e for e in filtered if e.ip_address == filter_by_ip]
    if only_suspicious:
        filtered = [e for e in filtered if e.result in {"failed", "suspicious"}
                    or e.event_type == "alert"]

    filtered.sort()   # dataclass ordering is by timestamp

    label_parts = []
    if filter_by_user: label_parts.append(f"user={filter_by_user}")
    if filter_by_ip:   label_parts.append(f"ip={filter_by_ip}")
    if only_suspicious: label_parts.append("suspicious-only")
    label = ", ".join(label_parts) if label_parts else "all events"

    timeline = IncidentTimeline(label=label, events=filtered)

    # Attach lightweight findings
    fail_count = sum(1 for e in filtered if e.result == "failed")
    susp_count = sum(1 for e in filtered if e.result == "suspicious")
    if fail_count:
        timeline.findings.append(f"{fail_count} failed event(s) in timeline.")
    if susp_count:
        timeline.findings.append(f"{susp_count} suspicious event(s) in timeline.")

    return timeline


def generate_summary_narrative(
    all_events: list[ForensicEvent],
    bf_incidents: list[BruteForceIncident],
    file_correlations: list[dict],
    scan_alerts: list[ForensicEvent],
) -> str:
    """
    Produce a concise prose summary of the forensic analysis findings.

    This mirrors the 'Reporting' phase of digital forensics, providing
    an analyst-facing narrative that highlights the most critical items.
    """
    lines: list[str] = []
    total = len(all_events)
    sources = sorted({e.source for e in all_events})

    lines.append(f"Total events analyzed: {total}  |  Sources: {', '.join(sources)}")
    lines.append("")

    # ── Brute-force findings ──────────────────────────────────────────────────
    if bf_incidents:
        lines.append(f"BRUTE-FORCE / CREDENTIAL STUFFING ({len(bf_incidents)} incident(s)):")
        for inc in bf_incidents:
            who  = f"user '{inc.user}'" if inc.user else "unknown user"
            src  = f"IP {inc.ip_address}" if inc.ip_address else "unknown IP"
            outcome = (
                "then achieved a SUCCESSFUL LOGIN — likely COMPROMISED"
                if inc.succeeded else "no successful login detected"
            )
            lines.append(
                f"  [{inc.severity}] {who} from {src}: "
                f"{inc.failed_count} failed login(s) between "
                f"{inc.first_attempt:%H:%M:%S} and {inc.last_attempt:%H:%M:%S}, "
                f"{outcome}."
            )
    else:
        lines.append("No brute-force patterns detected.")

    lines.append("")

    # ── File access after compromise ─────────────────────────────────────────
    if file_correlations:
        lines.append(f"SUSPICIOUS FILE ACCESS AFTER LOGIN ({len(file_correlations)} correlation(s)):")
        for corr in file_correlations:
            login = corr["login_event"]
            files = corr["file_events"]
            file_list = ", ".join(
                e.details.split("→")[0].strip().split()[-1]   # extract path part
                for e in files[:5]                             # cap at 5 for readability
            )
            lines.append(
                f"  User '{login.user}' (IP {login.ip_address}) logged in at "
                f"{login.timestamp:%H:%M:%S} then accessed: {file_list}"
            )
    else:
        lines.append("No correlated suspicious file access detected.")

    lines.append("")

    # ── Scanner / attack alerts ────────────────────────────────────────────────
    if scan_alerts:
        unique_ips = sorted({e.ip_address for e in scan_alerts if e.ip_address})
        lines.append(
            f"SCAN/ATTACK ALERTS: {len(scan_alerts)} alert event(s) from "
            f"{len(unique_ips)} IP(s): {', '.join(unique_ips)}"
        )
        for alert in scan_alerts[:5]:                         # show first 5
            lines.append(f"  {alert.timestamp:%H:%M:%S}  {alert.ip_address}  {alert.details}")
        if len(scan_alerts) > 5:
            lines.append(f"  ... and {len(scan_alerts) - 5} more alert(s).")
    else:
        lines.append("No scan/attack alerts detected.")

    return "\n".join(lines)
