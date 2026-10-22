#!/usr/bin/env python3
"""Require executed tests; ordinary lanes may explicitly allow reported skips."""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def require_executed(report: Path, *, allow_skips: bool = False) -> int:
    cases = list(ET.parse(report).getroot().iter("testcase"))
    if not cases:
        raise ValueError("required test report contains no test cases")
    failed = [
        case.get("name", "unnamed") for case in cases if any(case.find(tag) is not None for tag in ("error", "failure"))
    ]
    skipped = [case.get("name", "unnamed") for case in cases if case.find("skipped") is not None]
    if failed or (skipped and not allow_skips):
        raise ValueError(f"required proof skipped or failed: {', '.join(failed + skipped)}")
    executed = len(cases) - len(skipped)
    if not executed:
        raise ValueError("required test report has no executed test cases")
    return executed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-skips", action="store_true", help="permit reported optional skips while requiring an executed test"
    )
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        count = require_executed(args.report, allow_skips=args.allow_skips)
    except (OSError, ET.ParseError, ValueError) as exc:
        parser.exit(1, f"required qualification failed: {exc}\n")
    print(
        f"Required qualification: {count} executed, "
        f"{'optional skips allowed' if args.allow_skips else 'no skips'}, no failures"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
