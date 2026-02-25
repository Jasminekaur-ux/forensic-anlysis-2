"""
main.py — CLI entry point for the Forensic Analysis Toolkit.

Usage examples:
  # Analyze authentication CSV logs (console output)
  python main.py --source auth_csv --file data/auth_logs.csv

  # Analyze Apache access logs and save a Markdown report
  python main.py --source apache_access --file data/web_access.log --report

  # Filter timeline by user
  python main.py --source auth_csv --file data/auth_logs.csv --user alice

  # Filter timeline by IP address
  python main.py --source auth_csv --file data/auth_logs.csv --ip 192.168.1.101

  # Show only suspicious/failed events in the timeline
  python main.py --source auth_csv --file data/auth_logs.csv --suspicious-only

  # Run the full demo on both sample datasets
  python main.py --demo

Forensic Phases (mapped in this file):
  Identification → --source flag selects which log type to examine
  Collection     → parsers open files read-only and normalize events
  Analysis       → analyzer.py functions are called in run_analysis()
  Reporting      → ConsoleReporter or MarkdownReporter renders results
"""

import argparse
import sys
from pathlib import Path

# Ensure the project root is on the module search path when running directly
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import (
    build_incident_timeline,
    find_bruteforce_patterns,
    find_scan_alerts,
    find_suspicious_file_access,
)
from src.parsers import get_parser
from src.reporter import ConsoleReporter, MarkdownReporter


# ─────────────────────────────────────────────────────────────────────────────
# Core pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(
    source_type: str,
    file_path:   str,
    user_filter: str | None  = None,
    ip_filter:   str | None  = None,
    suspicious_only: bool    = False,
    save_report: bool        = False,
    report_dir:  str         = "reports",
) -> None:
    """
    Full forensic pipeline:
      1. Parse raw logs into normalized ForensicEvent objects.
      2. Run analysis routines.
      3. Render output (console + optionally a Markdown report).
    """

    print(f"\n  [*] Loading '{source_type}' data from: {file_path}")
    parser = get_parser(source_type)
    all_events = list(parser.parse(file_path))

    if not all_events:
        print("  [!] No events parsed. Check the file path and source type.")
        return

    print(f"  [*] Parsed {len(all_events)} events. Running analysis...\n")

    # ── Analysis ──────────────────────────────────────────────────────────────
    bf_incidents      = find_bruteforce_patterns(all_events)
    file_correlations = find_suspicious_file_access(all_events)
    scan_alerts       = find_scan_alerts(all_events)
    timeline          = build_incident_timeline(
        all_events,
        filter_by_user  = user_filter,
        filter_by_ip    = ip_filter,
        only_suspicious = suspicious_only,
    )

    # ── Console output ────────────────────────────────────────────────────────
    console = ConsoleReporter()
    console.render(all_events, timeline, bf_incidents, file_correlations, scan_alerts)

    # ── Optional Markdown report ───────────────────────────────────────────────
    if save_report:
        md_reporter = MarkdownReporter(output_dir=report_dir)
        out_path    = md_reporter.render(
            all_events, timeline, bf_incidents, file_correlations, scan_alerts
        )
        print(f"\n  [✓] Markdown report saved to: {out_path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Demo mode — runs both sample datasets automatically
# ─────────────────────────────────────────────────────────────────────────────

def run_demo() -> None:
    """
    Run the toolkit against both bundled sample datasets so you can see
    it working immediately without any extra arguments.
    """
    print("\n" + "═" * 72)
    print("  FORENSIC ANALYSIS TOOLKIT — DEMO MODE")
    print("═" * 72)

    datasets = [
        ("auth_csv",      "data/auth_logs.csv",   "Authentication CSV Logs"),
        ("apache_access", "data/web_access.log",  "Apache Access Logs"),
    ]

    for source, path, label in datasets:
        print(f"\n{'─'*72}")
        print(f"  DATASET: {label}  ({path})")
        print(f"{'─'*72}")
        run_analysis(
            source_type     = source,
            file_path       = path,
            suspicious_only = False,
            save_report     = True,
            report_dir      = "reports",
        )

    print("\n  [*] Demo complete. Check the reports/ directory for Markdown outputs.\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensic-toolkit",
        description=(
            "Forensic Analysis Toolkit — Parse, correlate, and report on "
            "cyber-incident logs.\n"
            "Run with --demo to analyze both bundled sample datasets immediately."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--demo",
        action="store_true",
        help="Run the full demo against both bundled sample datasets.",
    )
    p.add_argument(
        "--source",
        choices=["auth_csv", "apache_access"],
        help="Log source type to parse.",
    )
    p.add_argument(
        "--file",
        metavar="PATH",
        help="Path to the log file to analyze.",
    )
    p.add_argument(
        "--user",
        metavar="USERNAME",
        default=None,
        help="Filter timeline to events for a specific user.",
    )
    p.add_argument(
        "--ip",
        metavar="IP_ADDRESS",
        default=None,
        help="Filter timeline to events from a specific IP address.",
    )
    p.add_argument(
        "--suspicious-only",
        action="store_true",
        help="Show only failed/suspicious/alert events in the timeline.",
    )
    p.add_argument(
        "--report",
        action="store_true",
        help="Save a Markdown report to the reports/ directory.",
    )
    p.add_argument(
        "--report-dir",
        metavar="DIR",
        default="reports",
        help="Directory to save report files (default: reports/).",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.demo:
        run_demo()
        return

    if not args.source or not args.file:
        build_parser().print_help()
        print("\n  [!] Provide --source and --file, or use --demo to run the built-in demo.\n")
        sys.exit(1)

    run_analysis(
        source_type     = args.source,
        file_path       = args.file,
        user_filter     = args.user,
        ip_filter       = args.ip,
        suspicious_only = args.suspicious_only,
        save_report     = args.report,
        report_dir      = args.report_dir,
    )


if __name__ == "__main__":
    main()
