from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from analyzer.models import Finding, LogEvent
from analyzer.parser import ParseResult
from analyzer.reporter import build_report, write_json_report


def make_event() -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 2, 1, 9, 0, tzinfo=UTC),
        event_type="login",
        username="john",
        ip_address="10.0.0.5",
        status="failed",
        user_agent="Chrome",
    )


def make_finding() -> Finding:
    event = make_event()

    return Finding(
        rule_id="AUTH-001",
        title="Repeated failed logins",
        severity="high",
        description="5 failed login attempts from 10.0.0.5 for user 'john'.",
        related_events=[event],
    )


def test_build_report_creates_expected_summary() -> None:
    parse_result = ParseResult(events=[make_event()], malformed_rows=2)
    findings = [make_finding()]

    report = build_report(parse_result, findings)

    assert report["summary"]["parsed_events"] == 1
    assert report["summary"]["malformed_rows"] == 2
    assert report["summary"]["findings_detected"] == 1

    assert len(report["findings"]) == 1
    assert report["findings"][0]["rule_id"] == "AUTH-001"


def test_write_json_report_creates_file(tmp_path: Path) -> None:
    parse_result = ParseResult(events=[make_event()], malformed_rows=0)
    findings = [make_finding()]
    output_path = tmp_path / "reports" / "report.json"

    write_json_report(
        parse_result,
        findings,
        output_path=output_path,
    )

    assert output_path.exists()

    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert data["summary"]["parsed_events"] == 1
    assert data["summary"]["findings_detected"] == 1
    assert data["findings"][0]["severity"] == "high"
