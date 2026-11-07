"""Runtime telemetry adapter — authorized surfaces only.

Emission requires a named authorization reference: an unauthorized
telemetry tap is refused, never quietly recorded. Counters and metadata
only; an observation carrying payloads is refused (section 10)."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)

_PAYLOAD_MARKERS = ("plaintext", "decrypted", "payload", "session_cookie",
                    "password", "token_value")


def translate(ref: CollectorRef,
              observation: Mapping[str, Any],
              *, authorization_ref: str | None) -> Translation:
    ref_id = observation_ref(observation)
    if not str(authorization_ref or "").strip():
        return refused(ref_id, "runtime telemetry requires a named authorization "
                               "reference: an unauthorized tap is refused, never "
                               "quietly recorded")
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    lowered = str(observation).lower()
    for marker in _PAYLOAD_MARKERS:
        if marker in lowered:
            return refused(ref_id, f"observation carries {marker!r}-like fields: "
                                   "runtime telemetry records counters and "
                                   "metadata, never payloads")
    for field in ("tenant_id", "observed_at", "asset_id", "operation"):
        if not str(observation.get(field) or "").strip():
            return refused(ref_id, f"runtime observation missing {field}")
    mode = str(observation.get("telemetry_mode") or "AGGREGATE")
    if mode not in ("AGGREGATE", "INVESTIGATION"):
        return refused(ref_id, f"telemetry mode {mode!r} is not one of "
                               "AGGREGATE, INVESTIGATION")
    if mode == "INVESTIGATION" and not str(observation.get("investigation_ref") or "").strip():
        return refused(ref_id, "INVESTIGATION telemetry names its investigation "
                               "reference: temporary detail without an approved "
                               "investigation is refused")
    event = base_event(
        ref,
        event_type="CRYPTO_OPERATION_OBSERVED",
        category="CRYPTO_OPERATION",
        logging_kind="ACTIVITY",
        severity=str(observation.get("severity") or "INFO"),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["telemetry_mode"] = mode
    event["cryptographic_context"] = {"evidence_level": "RUNTIME"}
    event["attributes"] = {
        "operation": str(observation["operation"]),
        "operation_count": int(observation.get("operation_count") or 1),
        "authorization_ref": str(authorization_ref),
    }
    return Translation(events=[event])
