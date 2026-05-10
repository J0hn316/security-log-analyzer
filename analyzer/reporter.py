from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from analyzer.models import Finding, LogEvent
from analyzer.parser import ParseResult


def event_to_dict(event: LogEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "username": event.username,
        "ip_address": event.ip_address,
        "status": event.status,
        "user_agent": event.user_agent,
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "related_events_count": len(finding.related_events),
        "related_events": [event_to_dict(event) for event in finding.related_events],
    }


def build_report(parse_result: ParseResult, findings: list[Finding]) -> dict[str, Any]:
    return {
        "summary": {
            "parsed_events": len(parse_result.events),
            "malformed_rows": parse_result.malformed_rows,
            "findings_detected": len(findings),
        },
        "findings": [finding_to_dict(finding) for finding in findings],
    }


def print_text_report(
    parse_result: ParseResult, findings: list[Finding], *, file_path: Path
) -> None:
    print(f"Scanning log file: {file_path}")
    print(f"Parsed events: {len(parse_result.events)}")
    print(f"Malformed rows skipped: {parse_result.malformed_rows}")
    print(f"Findings detected: {len(findings)}")

    if not findings:
        print("\nNo suspicious activity detected.")
        return

    print("\nFindings:")

    for finding in findings:
        print(f"- [{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
        print(f"  {finding.description}")
        print(f"  Related events: {len(finding.related_events)}")


def write_json_report(
    parse_result: ParseResult,
    findings: list[Finding],
    *,
    output_path: Path,
) -> None:
    report = build_report(parse_result, findings)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
