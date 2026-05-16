# Security Log Analyzer

A defensive Python security tool that parses authentication logs, detects suspicious login behavior, assigns severity levels, and exports human-readable or machine-readable reports.

This project was built as a **Tier 4 security tooling project** focused on:

- log parsing and normalization
- detection rule design
- suspicious authentication pattern analysis
- configurable CLI behavior
- JSON report generation
- automated testing

---

## Features

- Parse CSV authentication logs
- Normalize raw rows into structured `LogEvent` objects
- Skip malformed rows safely without crashing
- Detect suspicious behaviors:
  - repeated failed logins
  - possible password spraying
  - successful login after multiple failures
  - off-hours successful logins
- Assign severity levels to findings
- Print readable terminal reports
- Export structured JSON reports
- Tune detection thresholds from the CLI
- Automated tests for parsing, detection rules, and reporting

---

## Detection Rules

| Rule ID    | Detection                                                                 | Severity |
| ---------- | ------------------------------------------------------------------------- | -------- |
| `AUTH-001` | Repeated failed login attempts from the same IP against the same username | High     |
| `AUTH-002` | Possible password spraying: one IP failing against multiple usernames     | Critical |
| `AUTH-003` | Successful login after multiple previous failures                         | Critical |
| `AUTH-004` | Successful login outside configured business hours                        | Medium   |

---

## How It Works

````text
CSV authentication logs
        ↓
Parser
        ↓
Normalized LogEvent objects
        ↓
Detection rules
        ↓
Finding objects
        ↓
Text report or JSON export

## Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd security-log-analyzer
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows PowerShell**

```powershell
.\venv\Scripts\Activate.ps1
```

**Windows CMD**

```cmd
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```
---

## Sample Log Format

The analyzer currently expects CSV input using this header:

```csv
timestamp,event_type,username,ip_address,status,user_agent
```

Example:

```csv
2026-02-01T09:00:00Z,login,john,10.0.0.5,failed,Chrome
2026-02-01T09:01:00Z,login,john,10.0.0.5,failed,Chrome
2026-02-01T09:05:00Z,login,john,10.0.0.5,success,Chrome
```

A sample file is included at:

```text
sample_logs/login_events.csv
```

---

## Basic Usage

Run the analyzer against the sample log file:

```bash
python -m analyzer.main sample_logs/login_events.csv
```

Example output:

```text
Scanning log file: sample_logs/login_events.csv
Parsed events: 11
Malformed rows skipped: 0
Findings detected: 4

Findings:
- [HIGH] AUTH-001: Repeated failed logins
  5 failed login attempts from 10.0.0.5 for user 'john'.
  Related events: 5

- [CRITICAL] AUTH-002: Possible password spraying
  IP 10.0.0.9 had failed login attempts against 4 different usernames.
  Related events: 4
```

---

## JSON Report Export

Export a structured report:

```bash
python -m analyzer.main sample_logs/login_events.csv \
  --format json \
  --output reports/report.json
```

Example terminal output:

```text
Wrote JSON report to: reports/report.json
```

Example JSON structure:

```json
{
  "summary": {
    "parsed_events": 11,
    "malformed_rows": 0,
    "findings_detected": 4
  },
  "findings": [
    {
      "rule_id": "AUTH-001",
      "title": "Repeated failed logins",
      "severity": "high",
      "description": "5 failed login attempts from 10.0.0.5 for user 'john'.",
      "related_events_count": 5,
      "related_events": []
    }
  ]
}
```

---

## CLI Options

```bash
python -m analyzer.main <file> [options]
```

### Available options

| Option | Description |
|---|---|
| `--format text\|json` | Report output format |
| `--output PATH` | File path for JSON report output |
| `--failed-threshold N` | Threshold for repeated failed logins |
| `--spray-threshold N` | Unique username threshold for password spraying |
| `--success-after-failure-threshold N` | Number of failures before a later success is suspicious |
| `--business-start HOUR` | Start of normal business hours |
| `--business-end HOUR` | End of normal business hours |

---

## Example Threshold Tuning

### Lower repeated-failure sensitivity

```bash
python -m analyzer.main sample_logs/login_events.csv \
  --failed-threshold 3
```

### Lower password-spraying sensitivity

```bash
python -m analyzer.main sample_logs/login_events.csv \
  --spray-threshold 2
```

### Change business hours

```bash
python -m analyzer.main sample_logs/login_events.csv \
  --business-start 9 \
  --business-end 17
```

---

## Reported Security Scenarios

### Repeated Failed Logins

Detects repeated failures from the same IP against the same account.

Example pattern:

```text
10.0.0.5 → john → failed
10.0.0.5 → john → failed
10.0.0.5 → john → failed
```

---

### Password Spraying

Detects one IP targeting multiple usernames with failed logins.

Example pattern:

```text
10.0.0.9 → alice → failed
10.0.0.9 → bob → failed
10.0.0.9 → charlie → failed
```

---

### Success After Failures

Detects when repeated failures are followed by a successful login for the same IP/user pair.

Example pattern:

```text
john → failed
john → failed
john → failed
john → success
```

---

### Off-Hours Login

Detects successful logins outside normal business hours.

Default configured business hours:

```text
08:00 through 17:59
```

---

## Testing

Run the full test suite:

```bash
pytest -v
```

The tests cover:

- timestamp parsing
- valid CSV parsing
- malformed row handling
- repeated failed login detection
- password spraying detection
- success-after-failures detection
- off-hours login detection
- JSON report building
- JSON report file output

---
````
