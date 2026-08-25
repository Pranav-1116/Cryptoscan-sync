"""In-memory / DB-backed certificate inventory keyed by SHA-256 fingerprint."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


def merge_certificates(existing: list[dict[str, Any]], incoming: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_fp: dict[str, dict[str, Any]] = {}
    for row in existing:
        fp = row.get("fingerprint_sha256")
        if fp:
            by_fp[str(fp)] = dict(row)
    now = datetime.now(timezone.utc).isoformat()
    for cert in incoming:
        fp = cert.get("fingerprint_sha256")
        if not fp:
            continue
        current = by_fp.get(str(fp))
        if current is None:
            payload = dict(cert)
            payload["first_seen"] = now
            payload["last_seen"] = now
            payload["usages"] = list(cert.get("usages") or [])
            by_fp[str(fp)] = payload
            continue
        current["last_seen"] = now
        usages = list(current.get("usages") or [])
        for usage in cert.get("usages") or []:
            if usage not in usages:
                usages.append(usage)
        endpoint = cert.get("endpoint")
        if endpoint and endpoint not in usages:
            usages.append(endpoint)
        current["usages"] = usages
        for key in ("not_after", "days_until_expiry", "expiry_status", "subject", "issuer"):
            if cert.get(key) is not None:
                current[key] = cert[key]
    return list(by_fp.values())


def expiring(certs: Iterable[dict[str, Any]], *, days: int = 30) -> list[dict[str, Any]]:
    out = []
    for cert in certs:
        remaining = cert.get("days_until_expiry")
        if remaining is None:
            continue
        if 0 <= int(remaining) <= days:
            out.append(cert)
    return sorted(out, key=lambda row: int(row.get("days_until_expiry") or 0))
