"""Tiny version comparator for local CVE matching."""

from __future__ import annotations

import re


def parse_version(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in parts[:4]) or (0,)


def version_matches(installed: str | None, constraint: str) -> bool:
    if not constraint or constraint == "*":
        return True
    if not installed:
        return False
    constraint = constraint.strip()
    current = parse_version(installed)
    if constraint.startswith("<="):
        return current <= parse_version(constraint[2:])
    if constraint.startswith("<"):
        return current < parse_version(constraint[1:])
    if constraint.startswith(">="):
        return current >= parse_version(constraint[2:])
    if constraint.startswith(">"):
        return current > parse_version(constraint[1:])
    if constraint.startswith("=="):
        return current == parse_version(constraint[2:])
    return current == parse_version(constraint)
