"""NBOM observations -> TLS negotiation events (NETWORK_NEGOTIATED)."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)


def translate(ref: CollectorRef,
              observation: Mapping[str, Any]) -> Translation:
    ref_id = observation_ref(observation)
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    required = ("tenant_id", "observed_at", "asset_id", "protocol", "protocol_version", "cipher_suite")
    missing = [f for f in required if not str(observation.get(f) or "").strip()]
    if missing:
        return refused(ref_id, f"NBOM observation missing {missing}: "
                               "an unrecorded parameter is refused, never inferred")
    event = base_event(
        ref,
        event_type="TLS_NEGOTIATION_OBSERVED",
        category="TLS",
        logging_kind="ACTIVITY",
        severity=str(observation.get("severity") or "INFO"),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["cryptographic_context"] = {
        "protocol": str(observation["protocol"]),
        "protocol_version": str(observation["protocol_version"]),
        "cipher_suite": str(observation["cipher_suite"]),
        "evidence_level": "NETWORK_NEGOTIATED",
    }
    if observation.get("certificate_id"):
        event["cryptographic_context"]["certificate_id"] = str(observation["certificate_id"])
    return Translation(events=[event])
