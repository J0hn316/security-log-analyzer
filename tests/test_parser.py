from __future__ import annotations

from pathlib import Path

from analyzer.parser import parse_csv_log, parse_timestamp


def test_parse_timestamp_converts_z_to_utc_offset() -> None:
    timestamp = parse_timestamp("2026-02-01T09:00:00Z")

    assert timestamp.isoformat() == "2026-02-01T09:00:00+00:00"


def test_parse_csv_log_parses_valid_rows(tmp_path: Path) -> None:
    log_file = tmp_path / "login_events.csv"

    log_file.write_text(
        "\n".join(
            [
                "timestamp,event_type,username,ip_address,status,user_agent",
                "2026-02-01T09:00:00Z,login,john,10.0.0.5,failed,Chrome",
                "2026-02-01T09:01:00Z,login,john,10.0.0.5,success,Chrome",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_csv_log(log_file)

    assert len(result.events) == 2
    assert result.malformed_rows == 0

    first_event = result.events[0]
    assert first_event.username == "john"
    assert first_event.ip_address == "10.0.0.5"
    assert first_event.status == "failed"


def test_parse_csv_log_skips_malformed_rows(tmp_path: Path) -> None:
    log_file = tmp_path / "bad_login_events.csv"

    log_file.write_text(
        "\n".join(
            [
                "timestamp,event_type,username,ip_address,status,user_agent",
                "2026-02-01T09:00:00Z,login,john,10.0.0.5,failed,Chrome",
                "not-a-valid-date,login,john,10.0.0.5,failed,Chrome",
                "2026-02-01T09:02:00Z,login,,10.0.0.5,failed,Chrome",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_csv_log(log_file)

    assert len(result.events) == 1
    assert result.malformed_rows == 2
