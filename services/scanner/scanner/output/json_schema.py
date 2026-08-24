"""Lightweight scan-result schema checks (no extra JSON Schema dependency)."""

from __future__ import annotations

from typing import Any


REQUIRED_SCAN_FIELDS = {"scan_id", "scanner_id", "findings"}
REQUIRED_FINDING_FIELDS = {"source", "crypto", "metadata"}


def validate_scan_result(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED_SCAN_FIELDS - set(payload)
    if missing:
        errors.append(f"missing scan fields: {sorted(missing)}")
    findings = payload.get("findings")
    if findings is None:
        return errors
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] is not an object")
            continue
        absent = REQUIRED_FINDING_FIELDS - set(item)
        if absent:
            errors.append(f"findings[{index}] missing {sorted(absent)}")
    return errors


def is_valid_scan_result(payload: dict[str, Any]) -> bool:
    return not validate_scan_result(payload)
