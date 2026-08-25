"""Daily drift digest — MEDIUM/INFO plus still-open HIGH/CRITICAL."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


def build_digest(
    events: Iterable[Any],
    *,
    generated_at: datetime | None = None,
    window_hours: int = 24,
) -> dict[str, Any]:
    now = generated_at or datetime.now(timezone.utc)
    rows = [ _as_dict(item) for item in events ]
    by_severity = Counter(str(item.get("severity") or "INFO") for item in rows)
    by_status = Counter(str(item.get("resolution_status") or "OPEN") for item in rows)
    open_rows = [item for item in rows if str(item.get("resolution_status") or "OPEN") == "OPEN"]
    return {
        "generated_at": now.isoformat(),
        "window_hours": window_hours,
        "total": len(rows),
        "open": len(open_rows),
        "by_severity": {
            "CRITICAL": by_severity.get("CRITICAL", 0),
            "HIGH": by_severity.get("HIGH", 0),
            "MEDIUM": by_severity.get("MEDIUM", 0),
            "INFO": by_severity.get("INFO", 0),
        },
        "by_status": dict(by_status),
        "highlights": open_rows[:25],
        "subject": _subject(by_severity, len(open_rows)),
        "text": render_text(rows, by_severity, now, window_hours),
    }


def render_text(
    events: list[dict[str, Any]],
    by_severity: Counter,
    generated_at: datetime,
    window_hours: int,
) -> str:
    lines = [
        "CryptoScan daily drift digest",
        "============================",
        f"Generated: {generated_at.isoformat()}",
        f"Window: last {window_hours} hours",
        "",
        f"CRITICAL {by_severity.get('CRITICAL', 0)}  HIGH {by_severity.get('HIGH', 0)}  "
        f"MEDIUM {by_severity.get('MEDIUM', 0)}  INFO {by_severity.get('INFO', 0)}",
        "",
    ]
    if not events:
        lines.append("No drift events in this window.")
        return "\n".join(lines)
    lines.append("Open events:")
    for item in events:
        if str(item.get("resolution_status") or "OPEN") != "OPEN":
            continue
        details = item.get("drift_details") or {}
        lines.append(
            f"- [{item.get('severity')}] {item.get('drift_type')} "
            f"{details.get('algorithm') or details.get('reason') or item.get('current_scan_id')}"
        )
    return "\n".join(lines)


def window_start(now: datetime | None = None, hours: int = 24) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current - timedelta(hours=hours)


def _subject(by_severity: Counter, open_count: int) -> str:
    if by_severity.get("CRITICAL"):
        return f"[CRITICAL] {by_severity['CRITICAL']} critical crypto drift in the last day"
    if by_severity.get("HIGH"):
        return f"[HIGH] {by_severity['HIGH']} high-severity crypto drift in the last day"
    if open_count:
        return f"[CryptoScan] {open_count} open drift events in the last day"
    return "[CryptoScan] Daily drift digest — no open events"


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    details = getattr(item, "drift_details", None)
    return {
        "id": getattr(item, "id", None),
        "current_scan_id": getattr(item, "current_scan_id", None),
        "baseline_id": getattr(item, "baseline_id", None),
        "drift_type": getattr(item, "drift_type", None),
        "severity": getattr(item, "severity", None),
        "resolution_status": getattr(item, "resolution_status", None),
        "drift_details": details if isinstance(details, dict) else {},
        "detected_at": getattr(item, "detected_at", None).isoformat()
        if getattr(item, "detected_at", None) and hasattr(item.detected_at, "isoformat")
        else getattr(item, "detected_at", None),
    }
