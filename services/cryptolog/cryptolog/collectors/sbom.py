"""SBOM and deployment observations -> crypto library deployment events."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)

_ACTIONS = {
    "INSTALLED": ("CRYPTO_LIBRARY_ADDED", "MEDIUM"),
    "UPGRADED": ("CRYPTO_LIBRARY_ADDED", "MEDIUM"),
    "DOWNGRADED": ("CRYPTO_LIBRARY_REGRESSION", "HIGH"),
    "REMOVED": ("CRYPTO_LIBRARY_REMOVED", "MEDIUM"),
}


def translate(ref: CollectorRef,
              observation: Mapping[str, Any]) -> Translation:
    ref_id = observation_ref(observation)
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    action = str(observation.get("action") or "").upper()
    if action not in _ACTIONS:
        return refused(ref_id, f"unknown deployment action {action!r}: expected "
                               f"{sorted(_ACTIONS)}")
    for field in ("tenant_id", "observed_at", "asset_id", "package_name"):
        if not str(observation.get(field) or "").strip():
            return refused(ref_id, f"deployment observation missing {field}")
    event_type, severity = _ACTIONS[action]
    event = base_event(
        ref,
        event_type=event_type,
        category="CRYPTO_LIBRARY",
        logging_kind="CHANGE",
        severity=str(observation.get("severity") or severity),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["cryptographic_context"] = {"evidence_level": "CONFIGURED"}
    event["attributes"] = {
        "package_name": str(observation["package_name"]),
        "package_version": str(observation.get("package_version") or ""),
        "deployment_ref": str(observation.get("deployment_ref") or ""),
        "action": action,
    }
    return Translation(events=[event])
