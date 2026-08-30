"""ZELNX Cloud Discovery Engine — cloud drift detection (spec §20).

Detects changes over time and classifies them:

    EXPECTED | APPROVED | UNEXPECTED | HIGH_RISK

Drift kinds: certificate changed, KMS key rotation disabled, TLS policy
changed, new public endpoint, new cloud account, key permission changed,
encryption disabled, new crypto algorithm detected.

Classification is evidence-driven: an approved-change register
(``approved_changes``) marks EXPECTED/APPROVED; anything else is
UNEXPECTED, and security-relevant kinds (rotation disabled, encryption
disabled, key permission changed, new public endpoint) escalate to
HIGH_RISK.  Drift events trigger alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EXPECTED = "EXPECTED"
APPROVED = "APPROVED"
UNEXPECTED = "UNEXPECTED"
HIGH_RISK = "HIGH_RISK"

CLASSIFICATIONS = (EXPECTED, APPROVED, UNEXPECTED, HIGH_RISK)

DRIFT_KINDS = (
    "CERTIFICATE_CHANGED",
    "KMS_KEY_ROTATION_DISABLED",
    "TLS_POLICY_CHANGED",
    "NEW_PUBLIC_ENDPOINT",
    "NEW_CLOUD_ACCOUNT",
    "KEY_PERMISSION_CHANGED",
    "ENCRYPTION_DISABLED",
    "NEW_CRYPTO_ALGORITHM",
)

HIGH_RISK_KINDS = {
    "KMS_KEY_ROTATION_DISABLED",
    "ENCRYPTION_DISABLED",
    "KEY_PERMISSION_CHANGED",
    "NEW_PUBLIC_ENDPOINT",
}


@dataclass
class DriftObservation:
    """One detected drift event."""

    drift_id: str
    kind: str
    resource: str
    provider: str = ""
    account: str = ""
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    classification: str = UNEXPECTED
    detected_at: str = ""
    alert: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "kind": self.kind,
            "resource": self.resource,
            "provider": self.provider,
            "account": self.account,
            "before": dict(self.before),
            "after": dict(self.after),
            "classification": self.classification,
            "detected_at": self.detected_at,
            "alert": self.alert,
        }


@dataclass
class DriftResult:
    """All drift found between two snapshots."""

    observations: list[DriftObservation] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [observation.to_dict() for observation in self.observations]

    def by_classification(self, classification: str) -> list[DriftObservation]:
        return [o for o in self.observations if o.classification == classification]

    def alerts(self) -> list[DriftObservation]:
        return [o for o in self.observations if o.alert]

    def summary(self) -> dict[str, Any]:
        return {
            "drift": len(self.observations),
            "by_classification": {
                cls: len(self.by_classification(cls)) for cls in CLASSIFICATIONS
            },
            "alerts": len(self.alerts()),
        }


def classify_drift(kind: str, *, approved: bool = False, expected: bool = False) -> str:
    """Classification rules (spec §20)."""
    if approved:
        return APPROVED
    if expected:
        return EXPECTED
    if kind in HIGH_RISK_KINDS:
        return HIGH_RISK
    return UNEXPECTED


def detect_drift(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    *,
    approved_changes: set[tuple[str, str]] | None = None,
    expected_changes: set[tuple[str, str]] | None = None,
    detected_at: str = "",
    seq: int = 0,
) -> DriftResult:
    """Diff two normalized snapshots (resource-id -> state) and classify.

    ``approved_changes`` / ``expected_changes`` are ``(kind, resource)``
    tuples the org has pre-approved.
    """
    approved = {tuple(item) for item in (approved_changes or [])}
    expected = {tuple(item) for item in (expected_changes or [])}
    result = DriftResult()
    ids = sorted(set(before) | set(after))
    for resource in ids:
        prev = before.get(resource) or {}
        curr = after.get(resource) or {}
        if prev == curr:
            continue
        kind = _drift_kind(prev, curr, resource)
        if kind is None:
            continue
        seq += 1
        classification = classify_drift(
            kind,
            approved=(kind, resource) in approved,
            expected=(kind, resource) in expected,
        )
        result.observations.append(DriftObservation(
            drift_id=f"drift-{seq}",
            kind=kind,
            resource=resource,
            provider=str(curr.get("provider") or prev.get("provider") or ""),
            account=str(curr.get("account") or prev.get("account") or ""),
            before={k: v for k, v in prev.items() if k not in ("provider", "account")},
            after={k: v for k, v in curr.items() if k not in ("provider", "account")},
            classification=classification,
            detected_at=detected_at,
            alert=classification in (UNEXPECTED, HIGH_RISK),
        ))
    return result


def _drift_kind(prev: dict[str, Any], curr: dict[str, Any], resource: str) -> str | None:
    if not prev and curr:
        # brand-new resource wins over per-field diffs
        return "NEW_CLOUD_ACCOUNT" if "account_id" in curr else "NEW_PUBLIC_ENDPOINT"
    if prev and not curr:
        return None
    prev_keys = set(prev)
    curr_keys = set(curr)
    if "encryption_enabled" in prev_keys or "encryption_enabled" in curr_keys:
        if prev.get("encryption_enabled") is True and curr.get("encryption_enabled") is False:
            return "ENCRYPTION_DISABLED"
    if "rotation_enabled" in prev_keys or "rotation_enabled" in curr_keys:
        if prev.get("rotation_enabled") is True and curr.get("rotation_enabled") is False:
            return "KMS_KEY_ROTATION_DISABLED"
    if "algorithm" in prev_keys or "algorithm" in curr_keys:
        if prev.get("algorithm") and prev.get("algorithm") != curr.get("algorithm"):
            return "NEW_CRYPTO_ALGORITHM"
    if "tls_version" in prev_keys or "tls_version" in curr_keys:
        if prev.get("tls_version") != curr.get("tls_version"):
            return "TLS_POLICY_CHANGED"
    if "permissions" in prev_keys or "permissions" in curr_keys:
        if prev.get("permissions") != curr.get("permissions"):
            return "KEY_PERMISSION_CHANGED"
    if "valid_to" in prev_keys or "valid_to" in curr_keys:
        if prev.get("valid_to") != curr.get("valid_to"):
            return "CERTIFICATE_CHANGED"
    if "serial" in prev_keys or "serial" in curr_keys:
        if prev.get("serial") != curr.get("serial"):
            return "CERTIFICATE_CHANGED"
    return None
