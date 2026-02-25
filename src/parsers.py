"""
parsers.py — Log/event parsing and normalization layer.

Each parser class reads one type of raw data and yields ForensicEvent objects.

Forensic Phases Covered:
  Identification → Source type is identified by the class chosen (CSV auth, Apache log)
  Collection     → Files are opened read-only; no modification occurs to originals

Adding a new source:
  1. Create a new class that inherits from BaseParser.
  2. Implement the parse(path) method to yield ForensicEvent objects.
  3. Register the class in PARSER_REGISTRY at the bottom of this file.
"""

from __future__ import annotations

import csv
import re
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Generator

from src.models import ForensicEvent


# ── Base class ────────────────────────────────────────────────────────────────

class BaseParser(ABC):
    """Abstract base class for all forensic log parsers."""

    SOURCE_NAME: str = "unknown"  # Subclasses should override this

    @abstractmethod
    def parse(self, path: str | Path) -> Generator[ForensicEvent, None, None]:
        """
        Read the file at *path* and yield normalized ForensicEvent objects.
        Must not modify the original file (forensically sound read-only access).
        """
        ...


# ── CSV Authentication Log Parser ─────────────────────────────────────────────

class AuthCSVParser(BaseParser):
    """
    Parses CSV authentication logs with the following expected columns:
      timestamp, source, user, ip_address, event_type, result, details

    Timestamp format: YYYY-MM-DD HH:MM:SS
    """

    SOURCE_NAME = "auth_csv"

    # Map raw result strings to normalized values
    _RESULT_MAP = {
        "success": "success",
        "failed":  "failed",
        "suspicious": "suspicious",
        "locked":  "suspicious",   # account lockouts are suspicious
    }

    def parse(self, path: str | Path) -> Generator[ForensicEvent, None, None]:
        """Yield one ForensicEvent per CSV row, skipping malformed rows."""
        path = Path(path)
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row_num, row in enumerate(reader, start=2):  # row 1 = header
                try:
                    ts = datetime.strptime(
                        row["timestamp"].strip(), "%Y-%m-%d %H:%M:%S"
                    )
                    raw_result = row.get("result", "unknown").strip().lower()
                    # Normalize result — keep raw value if not in map
                    result = self._RESULT_MAP.get(raw_result, raw_result)

                    # Elevate lockout events to suspicious automatically
                    details = row.get("details", "").strip()
                    if "locked" in details.lower() or "lockout" in details.lower():
                        result = "suspicious"

                    yield ForensicEvent(
                        timestamp   = ts,
                        source      = row.get("source", self.SOURCE_NAME).strip(),
                        event_type  = row.get("event_type", "other").strip(),
                        user        = row.get("user", None) or None,
                        ip_address  = row.get("ip_address", None) or None,
                        result      = result,
                        details     = details,
                        raw         = dict(row),
                    )
                except (KeyError, ValueError) as exc:
                    # Skip bad rows but warn so analysts can investigate
                    print(f"  [PARSER WARNING] Skipping row {row_num} in {path.name}: {exc}")


# ── Apache / Combined Log Format Parser ──────────────────────────────────────

class ApacheAccessLogParser(BaseParser):
    """
    Parses Apache Combined Log Format lines:
      IP - USER [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD PATH PROTO" STATUS BYTES "REF" "UA"

    Classifies events as:
      - login      → POST to /login or /admin/login
      - file_access → GET for file-like paths (.pdf, .xlsx, .docx, etc.)
      - alert      → known attack patterns (SQL injection, scanner UA)
      - network    → everything else
    """

    SOURCE_NAME       = "apache_access"

    _LOG_RE = re.compile(
        r'(?P<ip>\S+)'                         # Client IP
        r' \S+ '                                # ident (ignored)
        r'(?P<user>\S+) '                       # auth user ('-' if none)
        r'\[(?P<ts>[^\]]+)\] '                  # [timestamp]
        r'"(?P<method>\S+) (?P<path>[^"]+) HTTP[^"]+" '  # "METHOD PATH HTTP/x"
        r'(?P<status>\d{3}) '                   # HTTP status
        r'(?P<bytes>\S+)'                       # Bytes transferred
        r'.*?"(?P<ua>[^"]*)"$'                  # Last quoted field = User-Agent
    )

    _TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

    # Attack pattern fingerprints (regex applied to path + UA)
    _ATTACK_PATTERNS = [
        re.compile(r"(?:union|select|insert|drop|'|--|or\s+1=1)", re.I),  # SQLi
        re.compile(r"(?:sqlmap|nikto|nessus|masscan|nmap)",        re.I),  # Scanner UAs
        re.compile(r"\.\./|%2e%2e",                                re.I),  # Path traversal
    ]

    # Extensions treated as sensitive file access
    _FILE_EXTS = {".pdf", ".xlsx", ".docx", ".csv", ".txt", ".tar", ".gz", ".zip", ".db"}

    def _classify(
        self, method: str, path: str, status: int, ua: str
    ) -> tuple[str, str]:
        """
        Return (event_type, result) for a single request.
        """
        combined = f"{path} {ua}"

        # Check for known attack signatures first
        if any(p.search(combined) for p in self._ATTACK_PATTERNS):
            return "alert", "suspicious"

        if method == "POST" and ("login" in path.lower() or "auth" in path.lower()):
            result = "success" if status < 400 else "failed"
            return "login", result

        # Sensitive file downloads
        suffix = Path(path.split("?")[0]).suffix.lower()
        if method == "GET" and suffix in self._FILE_EXTS:
            return "file_access", "success" if status < 400 else "failed"

        result = "success" if status < 400 else "failed"
        return "network_connection", result

    def parse(self, path: str | Path) -> Generator[ForensicEvent, None, None]:
        """Yield one ForensicEvent per log line, skipping unparseable lines."""
        path = Path(path)
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                m = self._LOG_RE.match(line)
                if not m:
                    print(f"  [PARSER WARNING] Skipping line {line_num} in {path.name}: no match")
                    continue

                try:
                    ts = datetime.strptime(m.group("ts"), self._TS_FMT)
                    # Convert to naive UTC for uniform comparison
                    ts = ts.replace(tzinfo=None)

                    ip   = m.group("ip")
                    user = m.group("user") if m.group("user") != "-" else None
                    status = int(m.group("status"))
                    path_str = m.group("path").strip()
                    ua   = m.group("ua")

                    event_type, result = self._classify(m.group("method"), path_str, status, ua)

                    yield ForensicEvent(
                        timestamp  = ts,
                        source     = self.SOURCE_NAME,
                        event_type = event_type,
                        user       = user,
                        ip_address = ip,
                        result     = result,
                        details    = f'{m.group("method")} {path_str} → HTTP {status}',
                        raw        = m.groupdict(),
                    )
                except (ValueError, AttributeError) as exc:
                    print(f"  [PARSER WARNING] Skipping line {line_num} in {path.name}: {exc}")


# ── Registry ──────────────────────────────────────────────────────────────────

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "auth_csv":     AuthCSVParser,
    "apache_access": ApacheAccessLogParser,
}


def get_parser(source_type: str) -> BaseParser:
    """
    Instantiate and return the parser for the given *source_type*.

    Args:
        source_type: Key from PARSER_REGISTRY (e.g. "auth_csv").

    Raises:
        ValueError: If *source_type* is not registered.
    """
    if source_type not in PARSER_REGISTRY:
        supported = ", ".join(PARSER_REGISTRY)
        raise ValueError(
            f"Unknown parser '{source_type}'. Supported: {supported}"
        )
    return PARSER_REGISTRY[source_type]()
