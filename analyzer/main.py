from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analyzer.rules import run_all_rules
from analyzer.parser import parse_csv_log
from analyzer.reporter import print_text_report, write_json_report


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
        (
            ("--format",),
            {
                "choices": ["text", "json"],
                "default": "text",
                "help": "Report output format",
            },
        ),
        (
            ("--output",),
            {
                "type": Path,
                "help": "Optional output path for JSON report",
            },
        ),
        (
            ("--failed-threshold",),
            {
                "type": int,
                "default": 5,
                "help": "Failed login count threshold for repeated-failure detection",
            },
        ),
        (
            ("--spray-threshold",),
            {
                "type": int,
                "default": 4,
                "help": "Unique username threshold for password spraying detection",
            },
        ),
        (
            ("--success-after-failure-threshold",),
            {
                "type": int,
                "default": 3,
                "help": "Failure count threshold before a successful login is suspicious",
            },
        ),
        (
            ("--business-start",),
            {
                "type": int,
                "default": 8,
                "help": "Business start hour using 24-hour time",
            },
        ),
        (
            ("--business-end",),
            {
                "type": int,
                "default": 18,
                "help": "Business end hour using 24-hour time",
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

    parse_result = parse_csv_log(args.file)

    findings = run_all_rules(
        parse_result.events,
        failed_threshold=args.failed_threshold,
        spray_threshold=args.spray_threshold,
        success_after_failure_threshold=args.success_after_failure_threshold,
        business_start=args.business_start,
        business_end=args.business_end,
    )

    if args.format == "json":
        if args.output is None:
            raise ValueError("--output is required when --format json")

        write_json_report(
            parse_result,
            findings,
            output_path=args.output,
        )

        print(f"Wrote JSON report to: {args.output}")
        return

    print_text_report(
        parse_result,
        findings,
        file_path=args.file,
    )


if __name__ == "__main__":
    main()
