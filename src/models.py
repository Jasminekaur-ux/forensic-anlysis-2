"""
models.py — Core data model for the Forensic Analysis Toolkit.

Defines the normalized ForensicEvent dataclass that all parsers produce
and all analysis/reporting modules consume.  By funneling every raw log
source through this structure we keep the rest of the codebase source-agnostic.

Forensic Phases:
  Collection   → parsers convert raw data into ForensicEvent objects
  Analysis     → analyzer.py works exclusively with lists of ForensicEvent
  Reporting    → reporter.py renders ForensicEvent fields into output
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(order=True)
class ForensicEvent:
    """
    A single, normalized digital-forensics event.

    All timestamps are stored as timezone-naive UTC datetimes so that
    chronological sorting works with a simple list.sort() / sorted().
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    timestamp: datetime           # When the event occurred  (sort key)
    source: str                   # Origin system/app (e.g. "apache_access", "auth")
    event_type: str               # Semantic category: login | file_access | network | alert | other

    # ── Actor information ─────────────────────────────────────────────────────
    user: Optional[str] = field(default=None)   # Account / username
    ip_address: Optional[str] = field(default=None)  # Remote IPv4/IPv6

    # ── Outcome ───────────────────────────────────────────────────────────────
    result: str = "unknown"       # success | failed | suspicious | unknown

    # ── Free-text detail ─────────────────────────────────────────────────────
    details: str = ""             # Raw message or any extra context

    # ── Source-specific extras (preserved for traceability) ───────────────────
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    # ─────────────────────────────────────────────────────────────────────────
    def __str__(self) -> str:
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        user_part = f"user={self.user}" if self.user else ""
        ip_part   = f"ip={self.ip_address}" if self.ip_address else ""
        actor     = "  ".join(filter(None, [user_part, ip_part]))
        return (
            f"[{ts}] [{self.source}] [{self.event_type.upper()}] "
            f"[{self.result.upper()}]  {actor}  {self.details}"
        )
