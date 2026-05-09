from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from analyzer.models import LogEvent

REQUIRED_FIELDS: tuple[str, ...] = (
    "timestamp",
    "event_type",
    "username",
    "ip_address",
    "status",
    "user_agent",
)


@dataclass(frozen=True)
class ParseResult:
    events: list[LogEvent]
    malformed_rows: int


def parse_timestamp(value: str) -> datetime:
    """
    Parse timestamps like:
    2026-02-01T09:00:00Z

    Python's datetime.fromisoformat understands +00:00 better than Z,
    so we convert trailing Z to +00:00.
    """

    clean_value = value.strip()

    if clean_value.endswith("Z"):
        clean_value = clean_value[:-1] + "+00:00"

    return datetime.fromisoformat(clean_value)


def row_to_event(row: dict[str, str]) -> LogEvent:
    """
    Convert a CSV row dictionary into a LogEvent.
    Raises ValueError if required fields are missing or invalid.
    """
    for field in REQUIRED_FIELDS:
        if not row.get(field):
            raise ValueError(f"Missing required field: {field}")

    return LogEvent(
        timestamp=parse_timestamp(row["timestamp"]),
        event_type=row["event_type"].strip().lower(),
        username=row["username"].strip(),
        ip_address=row["ip_address"].strip(),
        status=row["status"].strip().lower(),
        user_agent=row["user_agent"].strip(),
    )


def parse_csv_log(file_path: Path) -> ParseResult:
    """
    Parse a CSV login log file into normalized LogEvent objects.

    Malformed rows are skipped and counted instead of crashing the scan.
    """

    events: list[LogEvent] = []
    malformed_rows = 0

    with file_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            try:
                event = row_to_event(row)
            except (ValueError, KeyError):
                malformed_rows += 1
                continue

            events.append(event)

    return ParseResult(events=events, malformed_rows=malformed_rows)
