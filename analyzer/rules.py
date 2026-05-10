from __future__ import annotations

from collections import defaultdict
from datetime import time

from analyzer.models import Finding, LogEvent


def detect_repeated_failed_logins(
    events: list[LogEvent],
    *,
    threshold: int = 5,
) -> list[Finding]:
    """
    Detect multiple failed login attempts from the same IP against the same username.
    """
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)

    for evt in events:
        if evt.event_type == "login" and evt.status == "failed":
            key = (evt.ip_address, evt.username)
            grouped[key].append(evt)

    findings: list[Finding] = []

    for (ip_address, username), related_events in grouped.items():
        if len(related_events) >= threshold:
            findings.append(
                Finding(
                    rule_id="AUTH-001",
                    title="Repeated failed logins",
                    severity="high",
                    description=(
                        f"{len(related_events)} failed login attempts "
                        f"from {ip_address} for user '{username}'."
                    ),
                    related_events=related_events,
                )
            )
    return findings


def detect_password_spraying(
    events: list[LogEvent],
    *,
    threshold: int = 4,
) -> list[Finding]:
    """
    Detect one IP attempting failed logins against many different usernames.
    """
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    events_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for evt in events:
        if evt.event_type == "login" and evt.status == "failed":
            users_by_ip[evt.ip_address].add(evt.username)
            events_by_ip[evt.ip_address].append(evt)

    findings: list[Finding] = []

    for ip_address, usernames in users_by_ip.items():
        if len(usernames) >= threshold:
            findings.append(
                Finding(
                    rule_id="AUTH-002",
                    title="Possible password spraying",
                    severity="critical",
                    description=(
                        f"IP {ip_address} had failed login attempts "
                        f"against {len(usernames)} different usernames."
                    ),
                    related_events=events_by_ip[ip_address],
                )
            )

    return findings


def detect_success_after_failures(
    events: list[LogEvent],
    *,
    failure_threshold: int = 3,
) -> list[Finding]:
    """
    Detect a successful login after several failures from the same IP/user pair.
    """
    sorted_events = sorted(events, key=lambda event: event.timestamp)

    failures_by_pair: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    findings: list[Finding] = []

    for event in sorted_events:
        if event.event_type != "login":
            continue

        key = (event.ip_address, event.username)

        if event.status == "failed":
            failures_by_pair[key].append(event)

        elif event.status == "success":
            previous_failures = failures_by_pair[key]

            if len(previous_failures) >= failure_threshold:
                related_events = previous_failures + [event]

                findings.append(
                    Finding(
                        rule_id="AUTH-003",
                        title="Successful login after multiple failures",
                        severity="critical",
                        description=(
                            f"Successful login for user '{event.username}' "
                            f"from {event.ip_address} after "
                            f"{len(previous_failures)} failed attempts."
                        ),
                        related_events=related_events,
                    )
                )

            # Reset after a successful login so we don't repeatedly report
            failures_by_pair[key] = []

    return findings


def detect_off_hours_logins(
    events: list[LogEvent],
    *,
    business_start: int = 8,
    business_end: int = 18,
) -> list[Finding]:
    """
    Detect successful logins outside normal business hours.
    Default business hours: 08:00 through 17:59.
    """
    findings: list[Finding] = []

    start = time(hour=business_start)
    end = time(hour=business_end)

    for event in events:
        if event.event_type != "login" or event.status != "success":
            continue

        event_time = event.timestamp.time()

        if event_time < start or event_time >= end:
            findings.append(
                Finding(
                    rule_id="AUTH-004",
                    title="Off-hours successful login",
                    severity="medium",
                    description=(
                        f"User '{event.username}' successfully logged in "
                        f"from {event.ip_address} at {event.timestamp.isoformat()}."
                    ),
                    related_events=[event],
                )
            )

    return findings


def run_all_rules(
    events: list[LogEvent],
    *,
    failed_threshold: int = 5,
    spray_threshold: int = 4,
    success_after_failure_threshold: int = 3,
    business_start: int = 8,
    business_end: int = 18,
) -> list[Finding]:
    """
    Run all detection rules and return combined findings.
    """
    findings: list[Finding] = []

    findings.extend(
        detect_repeated_failed_logins(
            events,
            threshold=failed_threshold,
        )
    )
    findings.extend(
        detect_password_spraying(
            events,
            threshold=spray_threshold,
        )
    )
    findings.extend(
        detect_success_after_failures(
            events,
            failure_threshold=success_after_failure_threshold,
        )
    )
    findings.extend(
        detect_off_hours_logins(
            events,
            business_start=business_start,
            business_end=business_end,
        )
    )

    return findings
