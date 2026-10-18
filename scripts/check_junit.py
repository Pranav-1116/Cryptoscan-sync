#!/usr/bin/env python3
"""Fail a required qualification lane if it collected nothing or skipped proof."""
from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def require_executed(report: Path) -> int:
    cases = list(ET.parse(report).getroot().iter("testcase"))
    if not cases:
        raise ValueError("required test report contains no test cases")
    incomplete = [case.get("name", "unnamed") for case in cases
                  if any(case.find(tag) is not None for tag in ("skipped", "error", "failure"))]
    if incomplete:
        raise ValueError(f"required proof skipped or failed: {', '.join(incomplete)}")
    return len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        count = require_executed(args.report)
    except (OSError, ET.ParseError, ValueError) as exc:
        parser.exit(1, f"required qualification failed: {exc}\n")
    print(f"Required qualification: {count} executed, no skipped/failed cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
