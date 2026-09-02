"""Credential / secrets-vault health logic (metadata only).

The platform never stores key material. A CredentialRef is a *locator* into
an external vault (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
HashiCorp Vault, on-prem KMS, or an out-of-band manual grant). These helpers
compute rotation/expiration health deterministically from metadata so the
scanner can fail-closed when a credential is stale or missing, and so access
is auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


def _parse(dt) -> datetime | None:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    try:
        v = datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass
class CredentialHealth:
    status: str
    healthy: bool
    days_until_expiry: int | None
    rotation_due: bool
    detail: str


def assess_credential(cred: dict, *, now: datetime | None = None) -> CredentialHealth:
    """Derive health from metadata. ``cred`` is a CredentialRef.to_dict()."""
    now = now or datetime.now(timezone.utc)
    status = cred.get("status", "pending")
    if status in {"revoked", "error"}:
        return CredentialHealth(status, False, None, False,
                                f"credential marked {status} — fail closed")

    expires = _parse(cred.get("expires_at"))
    days_exp = None
    if expires is not None:
        days_exp = round((expires - now).total_seconds() / 86400)
        if days_exp < 0:
            return CredentialHealth("expired", False, days_exp, False,
                                    "credential has expired — rotate before use")
        if days_exp <= 7:
            return CredentialHealth("active", cred.get("health_ok", False), days_exp,
                                    False, f"expires in {days_exp}d — urgent rotation")

    rotated = _parse(cred.get("last_rotated_at"))
    rotation_due = False
    policy_days = int(cred.get("rotation_policy_days", 90) or 90)
    if rotated is None:
        rotation_due = True
        detail = "never rotated — rotate before production use"
    else:
        age = (now - rotated).total_seconds() / 86400
        rotation_due = age >= policy_days
        detail = f"rotated {int(age)}d ago (policy {policy_days}d)"
        if rotation_due:
            detail += " — rotation due"

    healthy = bool(cred.get("health_ok", False)) and status == "active"
    # a credential that was never health-checked is not yet trusted
    if not cred.get("health_ok"):
        return CredentialHealth("pending", False, days_exp, rotation_due,
                                "not yet health-verified against vault")
    return CredentialHealth("active", healthy, days_exp, rotation_due, detail)
