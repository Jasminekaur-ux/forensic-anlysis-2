# Forensic Analysis Toolkit

A small but realistic **Digital Forensics and Incident Response (DFIR)** toolkit
written in pure Python (stdlib only — no `pip install` needed).

It demonstrates how a professional would:
- Ingest and normalize raw log data
- Correlate events to detect attacks (brute-force, data exfiltration, scanners)
- Reconstruct an incident timeline
- Produce a human-readable summary and a Markdown report

---

## Forensic Phases

| Phase | Where it happens |
|-------|-----------------|
| **Identification** | `--source` flag / `PARSER_REGISTRY` in `parsers.py` |
| **Collection** | Each parser reads the target file read-only |
| **Analysis** | `analyzer.py` — correlation functions |
| **Reporting** | `reporter.py` — console + Markdown output |

---

## Project Structure

```
forensic analysis 2/
├── main.py              ← CLI entry point
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── models.py        ← ForensicEvent dataclass (shared data model)
│   ├── parsers.py       ← Log parsing + normalization layer
│   ├── analyzer.py      ← Analysis & correlation engine
│   └── reporter.py      ← Console & Markdown report generation
├── data/
│   ├── auth_logs.csv    ← Sample authentication events
│   └── web_access.log   ← Sample Apache access log
└── reports/             ← Generated Markdown reports (auto-created)
```

---

## Requirements

- **Python 3.8 or later** — no third-party packages needed.

Verify your Python version:
```bash
python --version
```

---

## Quick Start

### 1 — Run the built-in demo (easiest)

Analyzes **both** sample datasets and saves Markdown reports:

```bash
python main.py --demo
```

### 2 — Analyze authentication logs

```bash
python main.py --source auth_csv --file data/auth_logs.csv
```

### 3 — Analyze web server access logs

```bash
python main.py --source apache_access --file data/web_access.log
```

### 4 — Save a Markdown report

```bash
python main.py --source auth_csv --file data/auth_logs.csv --report
```

### 5 — Filter by user or IP

```bash
# Timeline for user 'alice' only
python main.py --source auth_csv --file data/auth_logs.csv --user alice

# Timeline from a specific IP
python main.py --source auth_csv --file data/auth_logs.csv --ip 203.0.113.55

# Show only suspicious/failed events
python main.py --source auth_csv --file data/auth_logs.csv --suspicious-only
```

---

## Sample Datasets

### `data/auth_logs.csv`
Simulates a real authentication log with:
- **Alice** — 5 failed logins from `192.168.1.101`, then a successful login, followed by access to `/etc/shadow` and an outbound connection to a suspicious IP (classic compromise pattern)
- **Root** — 7 rapid failures from an external IP `203.0.113.55`, ending in account lockout (brute-force blocked)
- **Bob, Charlie, Dave** — normal activity

### `data/web_access.log`
Apache Combined Log Format with:
- **Admin account** — 4 POST failures to `/admin/login` then success, followed by bulk data export (credential stuffing + exfiltration)
- **IP 198.51.100.22** — SQLi probe and scanner User-Agent (automated attack tool)
- **Alice** — bulk downloads of confidential files

---

## Adding a New Log Source

1. Create a class in `src/parsers.py` that inherits from `BaseParser`
2. Implement `parse(path)` to yield `ForensicEvent` objects
3. Add it to `PARSER_REGISTRY` at the bottom of `parsers.py`
4. Pass the new key to `--source`

---

## Example Output

```
════════════════════════════════════════════════════════════════════════
  FORENSIC ANALYSIS REPORT  |  Generated: 2024-03-15 10:00:00
════════════════════════════════════════════════════════════════════════

  EXECUTIVE SUMMARY
  ─────────────────────────────────────────────────────────────────────
  Total events analyzed: 27  |  Sources: auth

  BRUTE-FORCE / CREDENTIAL STUFFING (2 incident(s)):
    [CRITICAL] user 'alice' from IP 192.168.1.101: 5 failed login(s) ...
               then achieved a SUCCESSFUL LOGIN — likely COMPROMISED.
    [MEDIUM]   user 'root' from IP 203.0.113.55: 7 failed login(s) ...
               no successful login detected.
```

---

*This toolkit is designed for educational and demonstration purposes,
illustrating core DFIR workflows with realistic but entirely synthetic data.*
