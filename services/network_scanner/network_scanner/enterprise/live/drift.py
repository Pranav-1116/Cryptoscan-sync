"""Drift Detection Engine.

Compare EXPECTED STATE vs CURRENT STATE and classify:

    NO_CHANGE · EXPECTED_CHANGE · APPROVED_CHANGE · UNEXPECTED_CHANGE ·
    CRITICAL_DRIFT

Example: previous RSA-3072 → current RSA-1024 ⇒ CRITICAL_CRYPTO_DRIFT
(because the key size dropped below the policy floor).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

DRIFT_CLASSES = ("NO_CHANGE", "EXPECTED_CHANGE", "APPROVED_CHANGE",
                 "UNEXPECTED_CHANGE", "CRITICAL_DRIFT")

# default policy floors for the most security-relevant crypto fields.
# ``expected`` values are accepted values; floors are minimum numeric sizes.
DEFAULT_CRYPTO_POLICY: dict[str, dict[str, Any]] = {
    "tls_version": {"floor": "TLSv1.2"},
    "public_key_size": {"floor": 2048},
    "key_size": {"floor": 2048},
    "signature_algorithm": {"allowed": {"SHA256", "SHA384", "SHA512", "ECDSA",
                                        "ED25519"}},
    "ike_version": {"allowed": {"IKEv2"}},
}

# crypto-critical fields: a policy violation here is CRITICAL, elsewhere
# it is UNEXPECTED_CHANGE.
CRITICAL_DRIFT_FIELDS = frozenset({
    "tls_version", "cipher_suites", "cipher", "public_key_size", "key_size",
    "public_key_algorithm", "signature_algorithm", "ike_encryption",
    "ike_version", "tunnel_encryption", "certificate_fingerprint",
})


def _tls_floor_ok(value: str, floor: str) -> bool:
    order = {"SSLV3": 0, "TLSV1.0": 1, "TLSV1.1": 2, "TLSV1.2": 3, "TLSV1.3": 4}
    a = order.get(str(value).upper(), 4)
    b = order.get(str(floor).upper(), 4)
    return a >= b


@dataclass
class DriftResult:
    asset_id: str
    field: str
    previous: Any = None
    current: Any = None
    classification: str = "UNEXPECTED_CHANGE"
    reason: str = ""
    severity: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "field": self.field,
                "previous": self.previous, "current": self.current,
                "classification": self.classification, "reason": self.reason,
                "severity": self.severity}


class DriftDetector:
    """Classifies field-level differences against expected policy + approvals.

    ``expected_policy`` maps field → {allowed: [...], floor: <number|tls-str>}.
    Approved change ids (e.g. change tickets) suppress unexpected/CRITICAL
    classification in favour of APPROVED_CHANGE.
    """

    def __init__(self, *,
                 policy: dict[str, dict[str, Any]] | None = None,
                 approved_ids: Iterable[str] | None = None,
                 field_resolver: Callable[[str], str] | None = None) -> None:
        merged = dict(DEFAULT_CRYPTO_POLICY)
        if policy:
            merged.update(policy)
        self._policy = merged
        self._approved = set(approved_ids or [])
        self._resolver = field_resolver or (lambda change_id: change_id)

    def approve(self, change_id: str) -> None:
        self._approved.add(change_id)

    def is_approved(self, change_id: str) -> bool:
        return self._resolver(change_id) in self._approved

    # ------------------------------------------------------------- detection

    def detect(self, previous: dict[str, Any], current: dict[str, Any], *,
               asset_id: str = "asset",
               change_id: str | None = None,
               approve: bool = False) -> list[DriftResult]:
        """Diff ``previous`` vs ``current`` and classify every changed field."""
        if approve and change_id:
            self.approve(change_id)
        approved = self.is_approved(change_id) if change_id else False
        results: list[DriftResult] = []
        for field_name in sorted(set(previous) | set(current)):
            old = previous.get(field_name)
            new = current.get(field_name)
            if old == new:
                continue
            classification, reason, severity = self._classify(
                field_name, old, new, approved=approved)
            results.append(DriftResult(asset_id=asset_id, field=field_name,
                                       previous=old, current=new,
                                       classification=classification,
                                       reason=reason, severity=severity))
        return results

    def _classify(self, field_name: str, old: Any, new: Any, *,
                  approved: bool) -> tuple[str, str, str]:
        if approved:
            return "APPROVED_CHANGE", "change authorized by approved change id", "INFO"
        rule = self._policy.get(field_name)
        if rule is None:
            return ("UNEXPECTED_CHANGE" if field_name in CRITICAL_DRIFT_FIELDS
                    else "EXPECTED_CHANGE",
                    f"no policy rule for '{field_name}'",
                    "MEDIUM" if field_name in CRITICAL_DRIFT_FIELDS else "LOW")

        ok, detail = self._satisfies(new, rule)
        if ok:
            # moving toward/into the compliant policy is expected
            return "EXPECTED_CHANGE", f"value '{new}' satisfies policy: {detail}", "INFO"
        if field_name in CRITICAL_DRIFT_FIELDS:
            return ("CRITICAL_DRIFT",
                    f"'{new}' violates crypto policy for '{field_name}': {detail}",
                    "CRITICAL")
        return ("UNEXPECTED_CHANGE",
                f"'{new}' violates policy for '{field_name}': {detail}",
                "MEDIUM")

    @staticmethod
    def _satisfies(value: Any, rule: dict[str, Any]) -> tuple[bool, str]:
        allowed = rule.get("allowed")
        if allowed is not None:
            norm = str(value).upper()
            ok = any(norm == str(a).upper() for a in allowed)
            return ok, f"allowed values: {sorted(allowed)}"
        floor = rule.get("floor")
        if floor is not None:
            if isinstance(floor, str):
                ok = isinstance(value, str) and _tls_floor_ok(value, floor)
                return ok, f"floor is {floor}"
            try:
                ok = float(value) >= float(floor)
            except (TypeError, ValueError):
                ok = False
            return ok, f"floor is {floor}"
        return True, "no constraint"


def classify_crypto_drift(previous: dict[str, Any], current: dict[str, Any]) -> str:
    """Convenience: overall CRITICAL_CRYPTO_DRIFT when any critical field drifts."""
    results = DriftDetector().detect(previous, current, asset_id="")
    if any(r.classification == "CRITICAL_DRIFT" for r in results):
        return "CRITICAL_CRYPTO_DRIFT"
    if any(r.classification in ("UNEXPECTED_CHANGE",) for r in results):
        return "CRYPTO_DRIFT"
    if any(r.classification == "APPROVED_CHANGE" for r in results):
        return "APPROVED_CRYPTO_CHANGE"
    if any(r.classification == "EXPECTED_CHANGE" for r in results):
        return "EXPECTED_CRYPTO_CHANGE"
    return "NO_CRYPTO_DRIFT"
