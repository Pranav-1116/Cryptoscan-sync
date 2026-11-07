"""HSM/KMS metadata observations -> key metadata events.

Metadata only. The adapter refuses any observation carrying secret
material markers — CryptoLog collects counters, identifiers and approved
evidence, never key contents (section 10)."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)

#: substrings that mark a field as carrying key material
_SECRET_MARKERS = ("private_key", "secret_key", "key_material", "key_bytes",
                   "pkcs8", "plaintext", "pin", "passphrase")


def translate(ref: CollectorRef,
              observation: Mapping[str, Any]) -> Translation:
    ref_id = observation_ref(observation)
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    lowered = str(observation).lower()
    for marker in _SECRET_MARKERS:
        if marker in lowered:
            return refused(ref_id, f"observation carries {marker!r}-like fields: "
                                   "CryptoLog records metadata and identifiers, "
                                   "never secret material")
    for field in ("tenant_id", "observed_at", "asset_id", "key_id"):
        if not str(observation.get(field) or "").strip():
            return refused(ref_id, f"HSM metadata observation missing {field}")
    event = base_event(
        ref,
        event_type="HSM_KEY_METADATA_CHANGE",
        category="HSM_KMS",
        logging_kind="CHANGE",
        severity=str(observation.get("severity") or "HIGH"),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["cryptographic_context"] = {"evidence_level": "CONFIGURED"}
    if observation.get("provider"):
        event["cryptographic_context"]["provider"] = str(observation["provider"])
    event["attributes"] = {
        "key_id": str(observation["key_id"]),
        "metadata_change": dict(observation.get("metadata_change") or {}),
    }
    return Translation(events=[event])
