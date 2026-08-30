"""ZELNX Live Cloud Intelligence Engine — live cloud drift detection (§13).

Compares EXPECTED state vs CURRENT state continuously and classifies:

    NO_CHANGE | EXPECTED | APPROVED | UNEXPECTED | CRYPTO_DRIFT |
    CRITICAL_DRIFT | ACCESS_DRIFT

Examples: encryption disabled → CRITICAL_DRIFT; certificate algorithm
changed → CRYPTO_DRIFT; new key permission added → ACCESS_DRIFT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

NO_CHANGE = "NO_CHANGE"
EXPECTED = "EXPECTED"
APPROVED = "APPROVED"
UNEXPECTED = "UNEXPECTED"
CRYPTO_DRIFT = "CRYPTO_DRIFT"
CRITICAL_DRIFT = "CRITICAL_DRIFT"
ACCESS_DRIFT = "ACCESS_DRIFT"

CLASSIFICATIONS = (NO_CHANGE, EXPECTED, APPROVED, UNEXPECTED,
                   CRYPTO_DRIFT, CRITICAL_DRIFT, ACCESS_DRIFT)

CRITICAL_DRIFT_FIELDS = ("encryption_enabled", "rotation_enabled", "tls_version")
ACCESS_DRIFT_FIELDS = ("permissions", "policy", "grant", "bindings")


@dataclass
class LiveDrift:
    """One drift observation between expected and current state."""

    resource_id: str
    provider: str = ""
    expected: dict[str, Any] = field(default_factory=dict)
    current: dict[str, Any] = field(default_factory=dict)
    drift_classification: str = NO_CHANGE
    drift_kind: str = ""
    changed_fields: list[str] = field(default_factory=list)
    detected_at: str = ""
    alert: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "provider": self.provider,
            "expected": dict(self.expected),
            "current": dict(self.current),
            "drift_classification": self.drift_classification,
            "drift_kind": self.drift_kind,
            "changed_fields": list(self.changed_fields),
            "detected_at": self.detected_at,
            "alert": self.alert,
        }


def drift_kind_for_changes(changed_fields: list[str]) -> str:
    fields = {str(field).lower() for field in changed_fields}
    if fields & {"encryption_enabled"}:
        return "ENCRYPTION_DRIFT"
    if fields & {"rotation_enabled"}:
        return "ROTATION_DRIFT"
    if fields & {"tls_version"}:
        return "TLS_POLICY_DRIFT"
    if fields & set(ACCESS_DRIFT_FIELDS):
        return "ACCESS_DRIFT"
    if fields & {"algorithm", "signature_algorithm", "key_size", "curve",
                 "certificate_algorithm", "key_exchange"}:
        return "CRYPTO_ALGORITHM_DRIFT"
    return "STATE_DRIFT"


def classify_live_drift(
    expected: dict[str, Any],
    current: dict[str, Any],
    *,
    approved: bool = False,
    expected_change: bool = False,
) -> tuple[str, str, list[str]]:
    """Classify drift: (classification, drift_kind, changed_fields)."""
    changed = sorted(key for key in set(expected) | set(current)
                     if expected.get(key) != current.get(key))
    if not changed:
        return NO_CHANGE, "", []
    kind = drift_kind_for_changes(changed)
    if approved:
        return APPROVED, kind, changed
    if expected_change:
        return EXPECTED, kind, changed
    if kind == "ENCRYPTION_DRIFT":
        # encryption disabled is the highest-severity drift
        if expected.get("encryption_enabled") is True and current.get("encryption_enabled") is False:
            return CRITICAL_DRIFT, kind, changed
    if kind in ("ROTATION_DRIFT", "TLS_POLICY_DRIFT"):
        if expected.get("rotation_enabled") is True and current.get("rotation_enabled") is False:
            return CRITICAL_DRIFT, kind, changed
        if str(expected.get("tls_version") or "").lower() > \
                str(current.get("tls_version") or "").lower():
            return CRITICAL_DRIFT, kind, changed
    if kind == "ACCESS_DRIFT":
        return ACCESS_DRIFT, kind, changed
    if kind == "CRYPTO_ALGORITHM_DRIFT":
        return CRYPTO_DRIFT, kind, changed
    return UNEXPECTED, kind, changed


@dataclass
class LiveDriftResult:
    """All drift found in one comparison pass."""

    observations: list[LiveDrift] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [drift.to_dict() for drift in self.observations]

    def by_classification(self, classification: str) -> list[LiveDrift]:
        return [d for d in self.observations if d.drift_classification == classification]

    def alerts(self) -> list[LiveDrift]:
        return [d for d in self.observations if d.alert]

    def summary(self) -> dict[str, Any]:
        return {
            "drift": len(self.observations),
            "by_classification": {
                cls: len(self.by_classification(cls)) for cls in CLASSIFICATIONS
            },
            "alerts": len(self.alerts()),
        }


class LiveDriftDetector:
    """Compare expected state vs current state for every tracked asset."""

    def __init__(self, *, expected_state: dict[str, dict[str, Any]] | None = None,
                 approved_changes: set[tuple[str, str]] | None = None,
                 expected_changes: set[tuple[str, str]] | None = None,
                 clock: Any = None) -> None:
        self._expected = dict(expected_state or {})
        self._approved = {tuple(item) for item in (approved_changes or [])}
        self._expected_changes = {tuple(item) for item in (expected_changes or [])}
        self._clock = clock or (lambda: "")

    def set_expected(self, resource_id: str, state: dict[str, Any]) -> None:
        self._expected[resource_id] = dict(state)

    def check(self, current: dict[str, dict[str, Any]]) -> LiveDriftResult:
        result = LiveDriftResult()
        resource_ids = sorted(set(self._expected) | set(current))
        for resource_id in resource_ids:
            expected = dict(self._expected.get(resource_id) or {})
            observed = dict(current.get(resource_id) or {})
            if not expected:
                continue  # no expected baseline → nothing to compare (§13)
            changed = sorted(key for key in set(expected) | set(observed)
                             if expected.get(key) != observed.get(key))
            kind = drift_kind_for_changes(changed) if changed else ""
            classification, _, _ = classify_live_drift(
                expected, observed,
                approved=(kind, resource_id) in self._approved,
                expected_change=(kind, resource_id) in self._expected_changes,
            )
            if classification == NO_CHANGE:
                continue
            provider = str(observed.get("provider") or expected.get("provider") or "")
            result.observations.append(LiveDrift(
                resource_id=resource_id,
                provider=provider,
                expected=expected,
                current=observed,
                drift_classification=classification,
                drift_kind=kind,
                changed_fields=changed,
                detected_at=self._clock(),
                alert=classification in (UNEXPECTED, CRYPTO_DRIFT, CRITICAL_DRIFT,
                                         ACCESS_DRIFT),
            ))
        return result
