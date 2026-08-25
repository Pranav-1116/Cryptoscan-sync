"""Normalize certificate usage strings into structured records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


def classify_location(location: str) -> str:
    raw = (location or "").lower()
    if raw.startswith("tls://") or ":" in raw and not raw.startswith("/") and not raw.endswith((".pem", ".crt", ".cer")):
        return "TLS_ENDPOINT"
    if raw.endswith((".pem", ".crt", ".cer")):
        return "PEM_FILE"
    if "secret" in raw or "tls.crt" in raw:
        return "K8S_SECRET"
    return "UNKNOWN"


def usage_records(certs: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for cert in certs:
        fp = cert.get("fingerprint_sha256")
        if not fp:
            continue
        locations = list(cert.get("usages") or [])
        if cert.get("endpoint") and cert["endpoint"] not in locations:
            locations.append(cert["endpoint"])
        if cert.get("file_path") and cert["file_path"] not in locations:
            locations.append(cert["file_path"])
        for location in locations:
            key = (str(fp), str(location))
            if not location or key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "fingerprint_sha256": str(fp),
                    "location": str(location),
                    "usage_type": classify_location(str(location)),
                    "last_seen": stamp,
                    "subject": cert.get("subject"),
                }
            )
    return out
