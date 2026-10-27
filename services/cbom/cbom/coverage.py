"""Bank-scale CBOM coverage: unknown crypto until a system is scanned."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any

STALE_DAYS = 90
STATUSES = ("NO_TARGET", "NEVER_SCANNED", "CURRENT", "STALE", "FAILED")
SCANNABLE = frozenset({"NEVER_SCANNED", "STALE", "FAILED"})


def initial_status(scan_target: str | None) -> str:
    return "NEVER_SCANNED" if str(scan_target or "").strip() else "NO_TARGET"


def _as_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def effective_status(
    *,
    coverage_status: str | None,
    scan_target: str | None = None,
    last_scanned_at: Any = None,
    now: datetime | None = None,
    stale_days: int = STALE_DAYS,
) -> str:
    stored = str(coverage_status or "").upper().strip()
    target = str(scan_target or "").strip()
    scanned = _as_dt(last_scanned_at)
    if stored == "FAILED":
        return "FAILED"
    if stored == "STALE":
        return "STALE"
    if stored == "CURRENT" or scanned:
        when = now or datetime.now(timezone.utc)
        if scanned and when - scanned > timedelta(days=int(stale_days)):
            return "STALE"
        return "CURRENT"
    if stored == "NEVER_SCANNED" or (target and not scanned):
        return "NEVER_SCANNED" if target else "NO_TARGET"
    if stored == "NO_TARGET" or not target:
        return "NO_TARGET"
    return stored if stored in STATUSES else initial_status(target)


def rollup(counts: dict[str, int]) -> dict[str, Any]:
    normalized = {key: int(counts.get(key) or 0) for key in STATUSES}
    total = sum(normalized.values())
    with_cbom = normalized["CURRENT"] + normalized["STALE"]
    unknown = normalized["NEVER_SCANNED"] + normalized["NO_TARGET"]
    scannable = normalized["NEVER_SCANNED"] + normalized["STALE"] + normalized["FAILED"]
    pct = round(100.0 * with_cbom / total, 1) if total else 0.0
    return {
        "systems": total,
        "with_cbom": with_cbom,
        "unknown_crypto": unknown,
        "scannable": scannable,
        "coverage_pct": pct,
        "counts": normalized,
        "stale_after_days": STALE_DAYS,
        "message": (
            f"{unknown} of {total} systems have unknown cryptography until they are scanned."
            if total
            else "Register systems, then scan them. A CBOM cannot exist without a scan."
        ),
    }


def parse_system_import(payload: Any) -> list[dict[str, Any]]:
    if payload is None or payload == "":
        return []
    if isinstance(payload, list):
        return [_normalize_import_row(item) for item in payload if _normalize_import_row(item)]
    if isinstance(payload, dict):
        if isinstance(payload.get("systems"), list):
            return parse_system_import(payload["systems"])
        row = _normalize_import_row(payload)
        return [row] if row else []
    text = str(payload).strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            return parse_system_import(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV must include a header row with at least name")
    rows = [_normalize_import_row(item) for item in reader]
    return [item for item in rows if item]


def _normalize_import_row(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    lowered = {str(key).strip().lower().replace(" ", "_"): value for key, value in item.items()}
    name = str(lowered.get("name") or lowered.get("system") or lowered.get("system_name") or "").strip()
    if not name:
        return None
    scopes_raw = lowered.get("compliance_scopes") or lowered.get("scopes") or ""
    if isinstance(scopes_raw, str):
        scopes = [part.strip() for part in scopes_raw.replace(";", ",").split(",") if part.strip()]
    elif isinstance(scopes_raw, list):
        scopes = [str(part).strip() for part in scopes_raw if str(part).strip()]
    else:
        scopes = []
    target = str(
        lowered.get("scan_target")
        or lowered.get("target")
        or lowered.get("repo")
        or lowered.get("repo_url")
        or ""
    ).strip()
    return {
        "name": name,
        "scan_target": target or None,
        "scan_branch": str(lowered.get("scan_branch") or lowered.get("branch") or "").strip() or None,
        "owner": str(lowered.get("owner") or "").strip() or None,
        "environment": str(lowered.get("environment") or lowered.get("env") or "").strip() or None,
        "business_unit": str(lowered.get("business_unit") or lowered.get("unit") or lowered.get("bu") or "").strip()
        or None,
        "criticality": str(lowered.get("criticality") or lowered.get("tier") or "").strip() or None,
        "description": str(lowered.get("description") or "").strip() or None,
        "compliance_scopes": scopes,
        "coverage_status": initial_status(target or None),
    }
