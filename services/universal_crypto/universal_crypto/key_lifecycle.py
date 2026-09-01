"""§26 Key lifecycle analysis.

Map Generate → Store → Use → Rotate → Backup → Revoke → Destroy, then
identify: never rotated, expired, orphaned, unknown owner, unknown storage,
long-lived, unsupported algorithm.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

STAGES = ["generated", "stored", "used", "rotated", "backed_up", "revoked", "destroyed"]

#: key types with expected rotation intervals (days)
_ROTATION_POLICY = {
    "signing": 365,
    "tls": 398,       # CA/B Forum 398-day max
    "encryption": 730,
    "authentication": 365,
    "jwt": 180,
    "unknown": 730,
}


class KeyLifecycleAnalyzer:
    """§26 lifecycle analysis over key metadata records (never secrets)."""

    def analyze(self, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        for record in records:
            key_id = str(record.get("key_id") or record.get("id") or "?")
            algorithm = str(record.get("algorithm") or "unknown")
            generated = _parse_dt(record.get("generated_at"))
            rotated = _parse_dt(record.get("rotated_at"))
            expires = _parse_dt(record.get("expires_at"))
            revoked = _parse_dt(record.get("revoked_at"))
            destroyed = _parse_dt(record.get("destroyed_at"))
            usage = str(record.get("usage") or "unknown")
            owner = str(record.get("owner") or "").strip()
            storage = str(record.get("storage") or "").strip()
            hw = bool(record.get("hardware_backed", False))

            lifecycle = []
            if generated:
                lifecycle.append("generated")
            if record.get("stored"):
                lifecycle.append("stored")
            if record.get("used"):
                lifecycle.append("used")
            if rotated:
                lifecycle.append("rotated")
            if record.get("backed_up"):
                lifecycle.append("backed_up")
            if revoked:
                lifecycle.append("revoked")
            if destroyed:
                lifecycle.append("destroyed")

            # — never rotated
            if generated and not rotated and not destroyed:
                age_days = (now - generated).days
                limit = _ROTATION_POLICY.get(usage, _ROTATION_POLICY["unknown"])
                if age_days > limit:
                    findings.append({"key_id": key_id, "type": "never_rotated",
                                     "detail": f"{age_days} days old (limit {limit})",
                                     "severity": "high"})
                elif age_days > 365:
                    findings.append({"key_id": key_id, "type": "long_lived",
                                     "detail": f"{age_days} days old",
                                     "severity": "medium"})
            # — expired
            if expires and expires < now and not revoked and not destroyed:
                findings.append({"key_id": key_id, "type": "expired",
                                 "detail": expires.isoformat(), "severity": "critical"})
            # — orphaned (revoked/destroyed but still referenced)
            if (revoked or destroyed) and record.get("still_referenced"):
                findings.append({"key_id": key_id, "type": "orphaned",
                                 "detail": "revoked/destroyed but still referenced",
                                 "severity": "high"})
            # — unknown owner / storage
            if not owner:
                findings.append({"key_id": key_id, "type": "unknown_owner",
                                 "detail": "", "severity": "low"})
            if not storage:
                findings.append({"key_id": key_id, "type": "unknown_storage",
                                 "detail": "", "severity": "medium"})
            # — unsupported algorithm
            if algorithm.upper() in ("MD5", "DES", "RC4", "SHA-1"):
                findings.append({"key_id": key_id, "type": "unsupported_algorithm",
                                 "detail": algorithm, "severity": "high"})
            # — no backup
            if generated and not record.get("backed_up") and not hw:
                findings.append({"key_id": key_id, "type": "no_backup",
                                 "detail": "software key without backup",
                                 "severity": "medium"})

        return {
            "records": len(list(records)),
            "stages": STAGES,
            "findings": findings,
        }


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None
