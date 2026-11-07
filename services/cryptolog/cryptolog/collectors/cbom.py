"""CBOM changes -> library and configuration events (CONFIGURED)."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)

_CHANGE_TYPES = {
    "ADDED": ("CRYPTO_LIBRARY_ADDED", "CRYPTO_LIBRARY", "MEDIUM"),
    "REMOVED": ("CRYPTO_LIBRARY_REMOVED", "CRYPTO_LIBRARY", "MEDIUM"),
    "CHANGED": ("CRYPTO_CONFIGURATION_CHANGED", "CONFIGURATION", "HIGH"),
    "REGRESSION": ("CRYPTO_LIBRARY_REGRESSION", "CRYPTO_LIBRARY", "HIGH"),
}


def translate(ref: CollectorRef,
              observation: Mapping[str, Any]) -> Translation:
    ref_id = observation_ref(observation)
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    change = str(observation.get("change") or "").upper()
    if change not in _CHANGE_TYPES:
        return refused(ref_id, f"unknown CBOM change kind {change!r}: expected "
                               f"{sorted(_CHANGE_TYPES)} — refused, never mapped by guess")
    for field in ("tenant_id", "observed_at", "asset_id", "component_name"):
        if not str(observation.get(field) or "").strip():
            return refused(ref_id, f"CBOM change missing {field}")
    event_type, category, severity = _CHANGE_TYPES[change]
    event = base_event(
        ref,
        event_type=event_type,
        category=category,
        logging_kind="CHANGE",
        severity=str(observation.get("severity") or severity),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["cryptographic_context"] = {
        "evidence_level": "CONFIGURED",
    }
    if observation.get("algorithm"):
        event["cryptographic_context"]["algorithm"] = str(observation["algorithm"])
    event["attributes"] = {
        "component_name": str(observation["component_name"]),
        "component_version": str(observation.get("component_version") or ""),
        "change_kind": change,
    }
    return Translation(events=[event])
