from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security Log Analyzer")

    parser.add_argument(
        "file",
        type=Path,
        help="Path to a CSV log file",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.file.exists():
        raise FileNotFoundError(f"Log file not found: {args.file}")

    print(f"Scanning log file: {args.file}")
    print("Phase 1 setup complete.")


if __name__ == "__main__":
    main()
