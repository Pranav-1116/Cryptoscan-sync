"""CryptoLog collector tests (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 4).

Adapters translate observations into canonical events; anything they
cannot translate is a named refusal — never an invented event, never a
silent drop. Secrets are never copied. A fixture is not support: the
qualification registry never upgrades itself.
"""

from __future__ import annotations

import pytest

from cryptolog.collectors import cbom, certificates, hsm_metadata, nbom, pipeline, runtime, sbom
from cryptolog.collectors.base import CollectorRef
from cryptolog.collectors.qualification import (
    QUALIFIED, REGISTERED, SUSPENDED, QualificationRegistry,
)
from shared_models.cryptolog_events import validate_event

REF = CollectorRef(collector_id="collector_nbom_01",
                   collector_version="1.0.0",
                   source_type="NETWORK_OBSERVATION")

AS_OF = "2026-11-07T04:00:00Z"


def _nbom_obs(**over):
    base = {
        "observation_id": "obs_001",
        "tenant_id": "tenant_001",
        "observed_at": AS_OF,
        "asset_id": "asset_gateway_001",
        "protocol": "TLS",
        "protocol_version": "TLS1.2",
        "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "evidence_ids": ["evidence_001"],
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# NBOM
# ---------------------------------------------------------------------------


def test_nbom_translation_preserves_provenance_and_passes_the_contract():
    result = nbom.translate(REF, _nbom_obs())
    assert result.accepted == 1 and result.refused == 0
    event = result.events[0]
    assert event["source"]["collector_id"] == "collector_nbom_01"
    assert event["cryptographic_context"]["evidence_level"] == "NETWORK_NEGOTIATED"
    assert event["evidence"]["evidence_ids"] == ["evidence_001"]
    validate_event(dict(event))


def test_an_observation_without_evidence_is_refused_never_fabricated():
    result = nbom.translate(REF, _nbom_obs(evidence_ids=[]))
    assert result.accepted == 0 and result.refused == 1
    assert "without evidence" in result.refusals[0].reason


def test_missing_parameters_are_named_refusals_never_inferred():
    result = nbom.translate(REF, _nbom_obs(cipher_suite=""))
    assert result.events == []
    assert "cipher_suite" in result.refusals[0].reason


# ---------------------------------------------------------------------------
# CBOM / certificates / SBOM
# ---------------------------------------------------------------------------


def test_cbom_change_kinds_map_to_their_event_types():
    for change, expected in [("ADDED", "CRYPTO_LIBRARY_ADDED"),
                             ("CHANGED", "CRYPTO_CONFIGURATION_CHANGED"),
                             ("REGRESSION", "CRYPTO_LIBRARY_REGRESSION")]:
        result = cbom.translate(REF, {
            "observation_id": "obs_cbom", "tenant_id": "tenant_001", "observed_at": AS_OF,
            "asset_id": "asset_001", "change": change,
            "component_name": "openssl", "component_version": "3.0.1",
            "evidence_ids": ["evidence_002"],
        })
        assert result.events[0]["event_type"] == expected
        assert result.events[0]["logging_kind"] == "CHANGE"


def test_an_unknown_change_kind_is_refused_not_mapped_by_guess():
    result = cbom.translate(REF, {
        "observation_id": "obs_x", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "a1",
        "change": "MUTATED", "component_name": "lib", "evidence_ids": ["e"],
    })
    assert result.events == []
    assert "refused, never mapped by guess" in result.refusals[0].reason


def test_a_replacement_leaves_the_absence_of_approval_visible():
    bare = certificates.translate(CollectorRef("c", "1.0.0", "CERTIFICATE_OBSERVATION"), {
        "observation_id": "obs_cert", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "a1",
        "event": "REPLACEMENT", "certificate_id": "cert_042",
        "evidence_ids": ["evidence_003"],
    }).events[0]
    assert bare["attributes"]["approved_change_ref"] is None, \
        "the absence of an approved change is recorded, never papered over"
    approved = certificates.translate(CollectorRef("c", "1.0.0", "CERTIFICATE_OBSERVATION"), {
        "observation_id": "obs_cert", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "a1",
        "event": "REPLACEMENT", "certificate_id": "cert_042",
        "approved_change_ref": "chg_9001", "evidence_ids": ["evidence_003"],
    }).events[0]
    assert approved["attributes"]["approved_change_ref"] == "chg_9001"


def test_deployment_actions_map_and_unknown_actions_refuse():
    result = sbom.translate(CollectorRef("c", "1.0.0", "SBOM_OBSERVATION"), {
        "observation_id": "obs_sbom", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "a1",
        "action": "DOWNGRADED", "package_name": "openssl", "package_version": "1.0.2",
        "evidence_ids": ["evidence_004"],
    })
    assert result.events[0]["event_type"] == "CRYPTO_LIBRARY_REGRESSION"
    assert result.events[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# HSM metadata / runtime
# ---------------------------------------------------------------------------


def test_hsm_metadata_refuses_secret_material():
    result = hsm_metadata.translate(CollectorRef("c", "1.0.0", "HSM_OBSERVATION"), {
        "observation_id": "obs_hsm", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "hsm-04",
        "key_id": "key_001", "metadata_change": {"state": "rotated"},
        "private_key": "-----BEGIN", "evidence_ids": ["evidence_005"],
    })
    assert result.events == []
    assert "never secret material" in result.refusals[0].reason


def test_runtime_telemetry_refuses_without_an_authorization():
    ref = CollectorRef("c", "1.0.0", "RUNTIME_OBSERVATION")
    observation = {"observation_id": "obs_rt", "tenant_id": "tenant_001",
                   "observed_at": AS_OF, "asset_id": "a1", "operation": "AES_GCM",
                   "operation_count": 1500, "evidence_ids": ["evidence_006"]}
    result = runtime.translate(ref, observation, authorization_ref=None)
    assert result.events == []
    assert "authorization" in result.refusals[0].reason
    ok = runtime.translate(ref, observation, authorization_ref="auth_ticket_77")
    assert ok.events[0]["telemetry_mode"] == "AGGREGATE"
    assert ok.events[0]["attributes"]["operation_count"] == 1500


def test_investigation_telemetry_names_its_investigation():
    ref = CollectorRef("c", "1.0.0", "RUNTIME_OBSERVATION")
    base = {"observation_id": "obs_rt", "tenant_id": "tenant_001", "observed_at": AS_OF, "asset_id": "a1",
            "operation": "AES_GCM", "evidence_ids": ["evidence_006"],
            "telemetry_mode": "INVESTIGATION"}
    result = runtime.translate(ref, base, authorization_ref="auth_1")
    assert result.events == []
    assert "investigation reference" in result.refusals[0].reason
    ok = runtime.translate(ref, {**base, "investigation_ref": "inv_009"},
                           authorization_ref="auth_1")
    assert ok.events[0]["telemetry_mode"] == "INVESTIGATION"


# ---------------------------------------------------------------------------
# Qualification — a fixture is not support
# ---------------------------------------------------------------------------


def test_registration_is_never_qualification():
    registry = QualificationRegistry()
    registry.register("nbom_adapter")
    assert registry.status_of("nbom_adapter") == REGISTERED


def test_qualification_demands_evidence_and_an_actor():
    registry = QualificationRegistry()
    with pytest.raises(ValueError):
        registry.qualify("nbom_adapter", evidence_ref="", qualified_by="bank", at=AS_OF)
    with pytest.raises(ValueError):
        registry.qualify("nbom_adapter", evidence_ref="qual_001", qualified_by="", at=AS_OF)
    record = registry.qualify("nbom_adapter", evidence_ref="qual_001",
                              qualified_by="bank-qa", at=AS_OF)
    assert record.status == QUALIFIED and record.evidence_ref == "qual_001"
    registry.suspend("nbom_adapter", reason="regression after upgrade")
    assert registry.status_of("nbom_adapter") == SUSPENDED
    assert len(registry.snapshot()) == 1


# ---------------------------------------------------------------------------
# Pipeline — accepted, skipped, rejected: every observation lands somewhere
# ---------------------------------------------------------------------------


def test_the_pipeline_reports_every_observation_with_reasons():
    from db.connection.session import Base
    from db.models.cryptolog import CryptoLogEvent
    from db.repositories.cryptolog_repository import CryptoLogRepository
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[CryptoLogEvent.__table__])
    repo = CryptoLogRepository(sessionmaker(bind=engine)())

    observations = [
        _nbom_obs(observation_id="obs_001"),
        _nbom_obs(observation_id="obs_002"),   # identical event -> DUPLICATE
        _nbom_obs(observation_id="obs_003", evidence_ids=[]),  # refused
    ]
    result = pipeline.run(nbom.translate, observations, ref=REF,
                          ingest=repo.insert_event)
    assert result["counts"] == {"accepted": 1, "skipped": 1, "rejected": 1,
                                "observations": 3}, \
        "every observation lands in exactly one bucket"
    assert "without evidence" in result["rejected"][0]["reason"]
    assert result["accepted"][0] == result["skipped"][0], \
        "a duplicate names the same stored event id — honest idempotent identity"
