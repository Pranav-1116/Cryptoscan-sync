"""Deterministic short-lived vault-lease policy for scanner credential access.

Scanners never receive or store key material. They receive a short-lived *lease*
that contains only a non-secret vault locator (``secret_ref``) plus the bounded
scope and TTL under which the customer's vault broker will honour a fetch. The
broker itself lives out-of-band (the customer grants access and runs it); this
service is the deterministic policy that decides whether a lease may be issued,
for how long, and with what scope. There is no secret in any object here and no
AI — it is pure time + scope + policy arithmetic.

Lease guarantees (all enforced, fail-closed):
* the credential must be ``active`` and not expired / past rotation grace;
* the requesting component must be in the credential's allowed components;
* the requested scope must be a subset of the credential's least-privilege scope;
* the TTL is capped (both a hard max and the credential's own max);
* an issued lease has a unique non-secret handle, an explicit expiry, and a
  one-time-use ``released`` path; leases are auditable but carry no secret bytes.
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

#: hard ceiling on any lease TTL regardless of caller request (seconds)
HARD_MAX_TTL_SECONDS = 900          # 15 minutes
DEFAULT_TTL_SECONDS = 300           # 5 minutes
ROTATION_GRACE_SECONDS = 3600       # credential usable up to 1h past rotation due

_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/\-]{2,255}$")
#: values that look like inline secret material — must never appear in a ref
_SECRET_VALUE_RE = re.compile(
    r"(?i)(begin .*private key|AKIA[0-9A-Z]{16}|-----BEGIN|password=|secret=|token=[A-Za-z0-9])"
)


class LeaseDenied(str, Enum):
    CREDENTIAL_NOT_ACTIVE = "CREDENTIAL_NOT_ACTIVE"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    ROTATION_OVERDUE = "ROTATION_OVERDUE"
    COMPONENT_NOT_ALLOWED = "COMPONENT_NOT_ALLOWED"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    TTL_TOO_LONG = "TTL_TOO_LONG"
    BAD_SECRET_REF = "BAD_SECRET_REF"
    SECRET_MATERIAL_IN_REF = "SECRET_MATERIAL_IN_REF"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    LEASE_ALREADY_RELEASED = "LEASE_ALREADY_RELEASED"
    LEASE_UNKNOWN = "LEASE_UNKNOWN"


@dataclass(frozen=True)
class CredentialInfo:
    """Policy view of a stored credential reference (never contains a secret)."""

    name: str
    secret_ref: str
    status: str = "active"                 # active | pending | revoked | expired
    allowed_components: frozenset[str] = frozenset()
    scope: frozenset[str] = frozenset()    # least-privilege action scopes
    max_ttl_seconds: int = DEFAULT_TTL_SECONDS
    expires_at: datetime | None = None
    last_rotated_at: datetime | None = None
    rotation_policy_days: int = 90

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "CredentialInfo":
        def _dt(k: str):
            v = d.get(k)
            if not v:
                return None
            if isinstance(v, datetime):
                dt = v
            else:
                dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        def _fs(k: str) -> frozenset[str]:
            v = d.get(k) or ()
            if isinstance(v, str):
                v = [x.strip() for x in v.replace(";", ",").split(",") if x.strip()]
            return frozenset(str(x) for x in v)

        return CredentialInfo(
            name=str(d.get("name") or ""),
            secret_ref=str(d.get("secret_ref") or ""),
            status=str(d.get("status") or "active").lower(),
            allowed_components=_fs("allowed_components") or _fs("components"),
            scope=_fs("least_privilege_scope") or _fs("scope"),
            max_ttl_seconds=int(d.get("max_ttl_seconds") or DEFAULT_TTL_SECONDS),
            expires_at=_dt("expires_at"),
            last_rotated_at=_dt("last_rotated_at"),
            rotation_policy_days=int(d.get("rotation_policy_days") or 90),
        )


@dataclass
class Lease:
    handle: str
    credential_name: str
    secret_ref: str
    component: str
    scope: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    released: bool = False
    ttl_seconds: int = 0

    def to_audit_dict(self) -> dict[str, Any]:
        """Safe-to-log view: never includes secret material (there is none)."""
        return {
            "handle": self.handle,
            "credential_name": self.credential_name,
            "secret_ref": self.secret_ref,
            "component": self.component,
            "scope": sorted(self.scope),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "released": self.released,
        }


@dataclass
class LeaseResult:
    allowed: bool
    reason: str | None = None
    lease: Lease | None = None
    rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "lease": self.lease.to_audit_dict() if self.lease else None,
            "rules": self.rules,
        }


def _deny(reason: LeaseDenied, rules: list[str]) -> LeaseResult:
    return LeaseResult(allowed=False, reason=reason.value, rules=rules)


def _validate_secret_ref(ref: str, rules: list[str]) -> LeaseResult | None:
    # check for inline key material first — a ref that smuggles a secret must be
    # refused regardless of whether it also happens to be malformed.
    if ref and _SECRET_VALUE_RE.search(ref):
        return _deny(LeaseDenied.SECRET_MATERIAL_IN_REF,
                     rules + ["fail_closed: secret_ref appears to contain inline key material; "
                              "store only a vault reference"])
    if not ref or not _REF_RE.match(ref):
        return _deny(LeaseDenied.BAD_SECRET_REF,
                     rules + ["secret_ref must be a non-secret vault locator (ARN/URI/name)"])
    return None


def issue_lease(
    credential: CredentialInfo,
    component: str,
    requested_scope: set[str] | frozenset[str] | list[str],
    *,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
    lease_handle: str | None = None,
) -> LeaseResult:
    """Issue a short-lived, scoped vault lease for a scanner component."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    comp = str(component or "").strip().lower()
    scope = frozenset(str(s).strip().lower() for s in requested_scope if str(s).strip())
    rules: list[str] = []

    # secret-ref sanity (defence in depth: never log/issue inline material)
    bad = _validate_secret_ref(credential.secret_ref, rules)
    if bad is not None:
        return bad

    if credential.status != "active":
        return _deny(LeaseDenied.CREDENTIAL_NOT_ACTIVE,
                     rules + [f"credential status is '{credential.status}', not 'active'"])

    if credential.expires_at is not None:
        exp = credential.expires_at if credential.expires_at.tzinfo else \
            credential.expires_at.replace(tzinfo=timezone.utc)
        if now > exp:
            return _deny(LeaseDenied.CREDENTIAL_EXPIRED,
                         rules + ["credential has passed its expiry date"])

    # rotation freshness (with a short grace window so rotation races don't break scans)
    if credential.last_rotated_at is not None:
        rotated = credential.last_rotated_at if credential.last_rotated_at.tzinfo else \
            credential.last_rotated_at.replace(tzinfo=timezone.utc)
        age = now - rotated
        policy = timedelta(days=credential.rotation_policy_days)
        if age > policy + timedelta(seconds=ROTATION_GRACE_SECONDS):
            return _deny(LeaseDenied.ROTATION_OVERDUE,
                         rules + [f"credential is past its {credential.rotation_policy_days}-day "
                                  "rotation policy (grace exceeded)"])

    if credential.allowed_components and comp not in credential.allowed_components:
        return _deny(LeaseDenied.COMPONENT_NOT_ALLOWED,
                     rules + [f"component '{comp}' is not in allowed_components "
                              f"{sorted(credential.allowed_components)}"])

    if credential.scope and not scope.issubset(credential.scope):
        excess = sorted(scope - credential.scope)
        return _deny(LeaseDenied.SCOPE_EXCEEDED,
                     rules + [f"requested scope exceeds least-privilege grant: {excess}"])

    # TTL: clamp to min(request, credential max, hard max); deny absurd asks
    eff_max = min(credential.max_ttl_seconds, HARD_MAX_TTL_SECONDS)
    asked = int(ttl_seconds or DEFAULT_TTL_SECONDS)
    if asked <= 0:
        asked = DEFAULT_TTL_SECONDS
    if asked > eff_max:
        # a request beyond the cap is a policy violation, not silently clamped,
        # so over-broad callers are visible — fail closed.
        return _deny(LeaseDenied.TTL_TOO_LONG,
                     rules + [f"requested TTL {asked}s exceeds effective cap {eff_max}s"])
    ttl = min(asked, eff_max)

    handle = lease_handle or "lease_" + hmac.new(
        os.urandom(32), f"{credential.name}:{comp}:{now.isoformat()}".encode(),
        "sha256").hexdigest()[:32]
    lease = Lease(
        handle=handle,
        credential_name=credential.name,
        secret_ref=credential.secret_ref,
        component=comp,
        scope=scope or credential.scope,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl),
        ttl_seconds=ttl,
    )
    rules.append(f"lease TTL clamped to {ttl}s (hard cap {HARD_MAX_TTL_SECONDS}s)")
    rules.append("reference-only: lease carries a vault locator, no secret bytes")
    return LeaseResult(allowed=True, lease=lease, rules=rules)


def validate_lease(lease: Lease, *, now: datetime | None = None) -> LeaseResult:
    """Check a lease is still valid for use (not expired, not released)."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if lease.released:
        return _deny(LeaseDenied.LEASE_ALREADY_RELEASED, ["lease was explicitly released"])
    exp = lease.expires_at if lease.expires_at.tzinfo else \
        lease.expires_at.replace(tzinfo=timezone.utc)
    if now > exp:
        return _deny(LeaseDenied.LEASE_EXPIRED,
                     [f"lease expired at {exp.isoformat()}"])
    return LeaseResult(allowed=True, lease=lease,
                       rules=["lease within TTL and not released"])


def release_lease(lease: Lease, *, now: datetime | None = None) -> LeaseResult:
    """Release a lease immediately (best practice: return after a scan)."""
    if lease.released:
        return _deny(LeaseDenied.LEASE_ALREADY_RELEASED, ["lease already released"])
    lease.released = True
    return LeaseResult(allowed=True, lease=lease, rules=["lease released; further use denied"])
