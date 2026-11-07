"""CryptoLog event contract v1 tests (docs/cryptolog/01_PRODUCT_SPEC.md,
Phase 1 deliverable).

Each test proves one contract acceptance row: taxonomy integrity, privacy
refusals, evidence-backed relationships, capability never promoted to
usage, idempotent ingestion without silent overwrites, and corrections that
never rewrite the original."""

from __future__ import annotations

import pytest

from shared_models.cryptolog_events import (
    ACTIVITY, AGGREGATE_MODE, ALGORITHM, CATEGORIES, CAPABILITY, CHANGE,
    CONFLICT, DUPLICATE, EVENT_SCHEMA, EVENT_TYPES, GOVERNANCE,
    INVESTIGATION_MODE, INSERTED, NETWORK_NEGOTIATED, PQC_SUBTYPES, RUNTIME,
    TLS, canonical_event_bytes, event_hash, ingest, make_event,
    original_intact, supersede,
)

AS_OF = "2026-11-07T04:00:00Z"


def _ctx(**over):
    base = {"protocol": "TLS", "protocol_version": "TLS1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "evidence_level": NETWORK_NEGOTIATED}
    base.update(over)
    return base


def _src(**over):
    base = {"collector_id": "collector_nbom_01", "collector_version": "1.0.0",
            "source_type": "NETWORK_OBSERVATION"}
    base.update(over)
    return base


def _event(**over):
    base = dict(event_type="TLS_NEGOTIATION_OBSERVED", category=TLS,
                logging_kind=ACTIVITY, tenant_id="tenant_001",
                severity="INFO", asset_id="asset_gateway_001",
                source=_src(), cryptographic_context=_ctx(),
                observed_at=AS_OF, evidence_ids=["evidence_001"])
    base.update(over)
    return make_event(**base)


def test_taxonomy_twelve_categories_and_six_pqc_subtypes():
    assert len(CATEGORIES) == 12
    assert len(PQC_SUBTYPES) == 6
    for subtype in PQC_SUBTYPES:
        assert subtype in EVENT_TYPES, "every PQC subtype has its category"
    assert EVENT_SCHEMA == "cryptoscan.cryptolog-event/1"


def test_a_known_type_may_not_file_itself_under_another_category():
    with pytest.raises(ValueError) as exc:
        _event(category="SSH")
    assert "may not file itself under SSH" in str(exc.value)
    with pytest.raises(ValueError):
        _event(category="NOT_A_CATEGORY")
    with pytest.raises(ValueError):
        _event(event_type="", category=TLS)


def test_prohibited_values_are_never_logged():
    with pytest.raises(ValueError) as exc:
        _event(attributes={"nested": {"private_key": "-----BEGIN"}})
    assert "prohibited value" in str(exc.value)
    with pytest.raises(ValueError):
        _event(attributes={"password": "hunter2"})
    with pytest.raises(ValueError):
        _event(cryptographic_context=_ctx(session_cookie="sid=abc"))
    with pytest.raises(ValueError):
        _event(source=_src(access_token="tok"))


def test_an_event_without_evidence_is_a_rumor():
    with pytest.raises(ValueError) as exc:
        _event(evidence_ids=[])
    assert "rumor" in str(exc.value)


def test_every_relationship_carries_its_relationship_evidence():
    ok = _event(related_asset_ids=["asset_payments_001"],
                relationship_evidence_ids=["evidence_002"])
    assert ok["relationships"]["related_asset_ids"] == ["asset_payments_001"]
    with pytest.raises(ValueError) as exc:
        _event(related_asset_ids=["asset_payments_001"])
    assert "evidence behind it" in str(exc.value)


def test_pqc_capability_discovery_is_never_proof_of_pqc_usage():
    with pytest.raises(ValueError) as exc:
        _event(event_type="PQC_CAPABILITY_DISCOVERED", category=ALGORITHM,
               cryptographic_context=_ctx(evidence_level=NETWORK_NEGOTIATED))
    assert "not proof of PQC usage" in str(exc.value)
    with pytest.raises(ValueError):
        _event(event_type="PQC_CAPABILITY_DISCOVERED", category=ALGORITHM,
               cryptographic_context=_ctx(evidence_level=RUNTIME))
    ok = _event(event_type="PQC_CAPABILITY_DISCOVERED", category=ALGORITHM,
                cryptographic_context=_ctx(evidence_level=CAPABILITY))
    assert ok["cryptographic_context"]["evidence_level"] == CAPABILITY


def test_negotiation_and_operation_events_need_their_real_evidence_levels():
    with pytest.raises(ValueError) as exc:
        _event(cryptographic_context=_ctx(evidence_level="CONFIGURED"))
    assert NETWORK_NEGOTIATED in str(exc.value)
    with pytest.raises(ValueError):
        _event(event_type="PQC_OPERATION_OBSERVED", category="CRYPTO_OPERATION",
               cryptographic_context=_ctx(evidence_level=NETWORK_NEGOTIATED))
    ok = _event(event_type="PQC_OPERATION_OBSERVED",
                category="CRYPTO_OPERATION",
                cryptographic_context=_ctx(evidence_level=RUNTIME))
    assert ok["event_type"] == "PQC_OPERATION_OBSERVED"


def test_canonical_hash_is_deterministic_and_null_stable():
    first = _event()
    second = _event()
    assert event_hash(first) == event_hash(second)
    with_null = dict(first)
    with_null["business_system_id"] = None
    assert canonical_event_bytes(first) == canonical_event_bytes(with_null), \
        "absent and null are one state"
    changed = _event(severity="HIGH")
    assert event_hash(changed) != event_hash(first)


def test_ingestion_is_idempotent_and_never_a_silent_overwrite():
    first = _event(deduplication_key="nbom:gateway:tls:2026-11-07")
    assert ingest([], first)["outcome"] == INSERTED

    again = ingest([first], _event(deduplication_key="nbom:gateway:tls:2026-11-07"))
    assert again["outcome"] == DUPLICATE
    assert again["event"]["event_id"] == first["event_id"]

    conflicting = _event(deduplication_key="nbom:gateway:tls:2026-11-07",
                         severity="HIGH")
    clash = ingest([first], conflicting)
    assert clash["outcome"] == CONFLICT
    assert "never a silent overwrite" in clash["note"]

    # keyless identity falls back to the canonical hash
    plain = _event()
    assert ingest([plain], _event())["outcome"] == DUPLICATE


def test_a_correction_never_rewrites_the_original():
    original = _event()
    corrected = _event(severity="HIGH",
                       investigation_status="INVESTIGATION_REQUIRED")
    correction = supersede(original=original, corrected=corrected,
                           reason="severity understated after triage",
                           actor="analyst-7", evidence_ids=["ev-x"])
    assert correction["original_hash"] == event_hash(original)
    assert correction["original_preserved"] is True
    assert original_intact(original, correction)
    # the original keeps its own severity: nothing was overwritten
    assert original["severity"] == "INFO"
    with pytest.raises(ValueError):
        supersede(original=original, corrected=corrected, reason="",
                  actor="analyst-7", evidence_ids=["ev-x"])
    with pytest.raises(ValueError):
        supersede(original=original, corrected=corrected, reason="why",
                  actor="", evidence_ids=["ev-x"])
    with pytest.raises(ValueError):
        supersede(original=original, corrected=corrected, reason="why",
                  actor="analyst-7", evidence_ids=[])


def test_telemetry_modes_keep_their_promises():
    with pytest.raises(ValueError) as exc:
        _event(telemetry_mode=INVESTIGATION_MODE)
    assert "approval_ref" in str(exc.value)
    ok = _event(telemetry_mode=INVESTIGATION_MODE, approval_ref="case-42")
    assert ok["approval_ref"] == "case-42"
    with pytest.raises(ValueError) as exc:
        _event(telemetry_mode=AGGREGATE_MODE,
               attributes={"coverage": "COMPLETE"})
    assert "never claims complete event coverage" in str(exc.value)
    fine = _event(telemetry_mode=AGGREGATE_MODE,
                  attributes={"coverage": "SAMPLED", "window_seconds": 60})
    assert fine["telemetry_mode"] == AGGREGATE_MODE
