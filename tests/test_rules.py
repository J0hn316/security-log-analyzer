from __future__ import annotations

from datetime import UTC, datetime

from analyzer.models import LogEvent
from analyzer.rules import (
    detect_off_hours_logins,
    detect_password_spraying,
    detect_repeated_failed_logins,
    detect_success_after_failures,
    run_all_rules,
)


def make_event(
    timestamp: str,
    *,
    username: str,
    ip_address: str,
    status: str,
    user_agent: str = "Chrome",
) -> LogEvent:
    return LogEvent(
        timestamp=datetime.fromisoformat(timestamp).replace(tzinfo=UTC),
        event_type="login",
        username=username,
        ip_address=ip_address,
        status=status,
        user_agent=user_agent,
    )


def test_detect_repeated_failed_logins() -> None:
    events = [
        make_event(
            "2026-02-01T09:00:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:01:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:02:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:03:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:04:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
    ]

    findings = detect_repeated_failed_logins(events, threshold=5)

    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-001"
    assert findings[0].severity == "high"


def test_detect_password_spraying() -> None:
    events = [
        make_event(
            "2026-02-01T10:00:00",
            username="alice",
            ip_address="10.0.0.9",
            status="failed",
        ),
        make_event(
            "2026-02-01T10:01:00",
            username="bob",
            ip_address="10.0.0.9",
            status="failed",
        ),
        make_event(
            "2026-02-01T10:02:00",
            username="charlie",
            ip_address="10.0.0.9",
            status="failed",
        ),
        make_event(
            "2026-02-01T10:03:00",
            username="diana",
            ip_address="10.0.0.9",
            status="failed",
        ),
    ]

    findings = detect_password_spraying(events, threshold=4)

    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-002"
    assert findings[0].severity == "critical"


def test_detect_success_after_failures() -> None:
    events = [
        make_event(
            "2026-02-01T09:00:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:01:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:02:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:03:00",
            username="john",
            ip_address="10.0.0.5",
            status="success",
        ),
    ]

    findings = detect_success_after_failures(events, failure_threshold=3)

    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-003"
    assert findings[0].severity == "critical"
    assert len(findings[0].related_events) == 4


def test_detect_off_hours_logins() -> None:
    events = [
        make_event(
            "2026-02-01T23:30:00",
            username="admin",
            ip_address="10.0.0.20",
            status="success",
        ),
    ]

    findings = detect_off_hours_logins(events, business_start=8, business_end=18)

    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-004"
    assert findings[0].severity == "medium"


def test_run_all_rules_returns_multiple_findings() -> None:
    events = [
        make_event(
            "2026-02-01T09:00:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:01:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:02:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:03:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:04:00",
            username="john",
            ip_address="10.0.0.5",
            status="failed",
        ),
        make_event(
            "2026-02-01T09:05:00",
            username="john",
            ip_address="10.0.0.5",
            status="success",
        ),
    ]

    findings = run_all_rules(events)

    rule_ids = {finding.rule_id for finding in findings}

    assert "AUTH-001" in rule_ids
    assert "AUTH-003" in rule_ids
