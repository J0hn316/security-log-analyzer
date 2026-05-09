from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analyzer.parser import parse_csv_log
from analyzer.rules import run_all_rules


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security Log Analyzer")

    arg_specs: list[tuple[tuple[str, ...], dict[str, Any]]] = [
        (
            ("file",),
            {
                "type": Path,
                "help": "Path to a CSV log file",
            },
        ),
    ]

    for flags, options in arg_specs:
        parser.add_argument(*flags, **options)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.file.exists():
        raise FileNotFoundError(f"Log file not found: {args.file}")

    result = parse_csv_log(args.file)
    findings = run_all_rules(result.events)

    print(f"Scanning log file: {args.file}")
    print(f"Parsed events: {len(result.events)}")
    print(f"Malformed rows skipped: {result.malformed_rows}")
    print(f"Findings detected: {len(findings)}")

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"- [{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
            print(f"  {finding.description}")
            print(f"  Related events: {len(finding.related_events)}")


if __name__ == "__main__":
    main()
