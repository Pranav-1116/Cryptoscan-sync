"""Certificate and PKI observations -> certificate lifecycle events."""

from __future__ import annotations

from typing import Any, Mapping

from cryptolog.collectors.base import (
    CollectorRef, Translation, base_event, observation_ref, refused,
    require_evidence,
)

_EVENT_KINDS = {
    "ISSUED": ("CERTIFICATE_ISSUED", "INFO"),
    "REPLACEMENT": ("CERTIFICATE_REPLACEMENT", "MEDIUM"),
    "EXPIRED": ("CERTIFICATE_EXPIRED", "HIGH"),
}


def translate(ref: CollectorRef,
              observation: Mapping[str, Any]) -> Translation:
    ref_id = observation_ref(observation)
    evidence_ids, problem = require_evidence(observation)
    if problem:
        return refused(ref_id, problem)
    kind = str(observation.get("event") or "").upper()
    if kind not in _EVENT_KINDS:
        return refused(ref_id, f"unknown certificate event {kind!r}: expected "
                               f"{sorted(_EVENT_KINDS)}")
    for field in ("tenant_id", "observed_at", "asset_id", "certificate_id"):
        if not str(observation.get(field) or "").strip():
            return refused(ref_id, f"certificate observation missing {field}")
    event_type, severity = _EVENT_KINDS[kind]
    event = base_event(
        ref,
        event_type=event_type,
        category="CERTIFICATE",
        logging_kind="CHANGE" if kind != "ISSUED" else "ACTIVITY",
        severity=str(observation.get("severity") or severity),
        asset_id=str(observation["asset_id"]),
        observed_at=str(observation["observed_at"]),
        evidence_ids=evidence_ids,
        tenant_id=str(observation["tenant_id"]),
        business_system_id=observation.get("business_system_id"),
    )
    event["cryptographic_context"] = {"evidence_level": "CONFIGURED"}
    attributes: dict[str, Any] = {
        "certificate_id": str(observation["certificate_id"]),
    }
    if observation.get("issuer"):
        attributes["issuer"] = str(observation["issuer"])
    if observation.get("not_after"):
        attributes["not_after"] = str(observation["not_after"])
    # A replacement carries its approved change reference when one exists;
    # its ABSENCE is left visible so CL-003 can name it — never papered over.
    if kind == "REPLACEMENT":
        approval = str(observation.get("approved_change_ref") or "")
        attributes["approved_change_ref"] = approval or None
    event["attributes"] = attributes
    return Translation(events=[event])
