"""Recorded bank-style telemetry is context inside a hypothetical Twin run."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all persisted tables
from api.dependencies import (get_current_user, get_db_session,
                              require_intelligence_writer)
from api.main import create_app
from db.connection.session import Base, configure_session
from db.models.hardware_live import HardwareAsset
from db.models.performance import PerformanceMetric as MetricRow
from db.models.system import System
from db.repositories.cryptolog_repository import CryptoLogRepository
from db.repositories.performance_repository import PerformanceRepository
from db.tenancy import tenant_scope
from shared_models.performance_metrics import PerformanceMetric

CHANGE = datetime.now(timezone.utc) - timedelta(hours=2)
TENANT = "bank-a"
ASSET = "app:sys-pay"
METRIC = "crypto.tls_handshake_ms"


@pytest.fixture()
def bank():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    db.add(System(id="sys-pay", tenant_id=TENANT, name="Payments API",
                  environment="test"))
    db.add(HardwareAsset(asset_id="host-pay", tenant_id=TENANT))
    db.commit()
    event = {
        "event_id": "change-pay-1", "event_type": "CRYPTO_CONFIGURATION_CHANGED",
        "category": "CONFIGURATION", "logging_kind": "CHANGE",
        "tenant_id": TENANT, "severity": "INFO", "asset_id": ASSET,
        "source": {"collector_id": "bank-config-exporter", "collector_version": "1.0",
                   "source_type": "CONFIGURATION_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS", "evidence_level": "CONFIGURED"},
        "observation": {"observed_at": CHANGE.isoformat()},
        "evidence": {"evidence_ids": ["unverified-event-ref"]},
    }
    assert CryptoLogRepository(db).insert_event(event)["outcome"] == "INSERTED"

    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[require_intelligence_writer] = lambda: "writer"
    try:
        yield TestClient(app), db
    finally:
        app.dependency_overrides.clear()
        db.close()
        engine.dispose()


def _params(**over):
    base = {"tenant_id": TENANT, "asset_ref": ASSET, "metric_name": METRIC,
            "source_id": "bank-exporter-1", "change_event_id": "change-pay-1",
            "before_start": (CHANGE - timedelta(minutes=30)).isoformat(),
            "before_end": (CHANGE - timedelta(minutes=1)).isoformat(),
            "after_start": (CHANGE + timedelta(minutes=1)).isoformat(),
            "after_end": (CHANGE + timedelta(minutes=30)).isoformat()}
    base.update(over)
    return base


def _measure(db, *, before=True, source="bank-exporter-1", unit="ms", count=5):
    for index in range(count):
        metric = PerformanceMetric(
            metric_id=f"{source}-{'before' if before else 'after'}-{index}",
            tenant_id=TENANT, asset_id=ASSET, metric_name=METRIC,
            metric_type="gauge", metric_value=20.0 if before else 30.0,
            unit="ms", source_id=source,
            observed_at=CHANGE + timedelta(minutes=(-20 if before else 10), seconds=index))
        PerformanceRepository(db).insert_metric(metric)
        if unit != "ms":
            db.query(MetricRow).filter_by(metric_id=metric.metric_id).update({"unit": unit})
            db.commit()


def test_bank_side_capture_is_bounded_persisted_and_never_claims_origin(bank):
    client, _ = bank
    start = CHANGE - timedelta(minutes=10)
    capture = {"tenant_id": TENANT, "asset_ref": "hw:host-pay",
               "source_id": "node-exporter-1", "source_type": "node_exporter",
               "authorization_ref": "bank-change/TEST-1",
               "observed_at": start.isoformat(),
               "payload": {"metrics": {"node_disk_read_bytes_total": [
                   {"value": 0, "labels": {"device": "sda"}}]}}}
    first = client.post("/api/v1/performance/captures/import", json=capture)
    assert first.status_code == 200, first.text
    assert first.json()["accepted"] == 1
    assert first.json()["provenance_state"] == "UNVERIFIED_CAPTURE_ORIGIN"
    repeated = client.post("/api/v1/performance/captures/import", json=capture)
    assert repeated.status_code == 200
    assert repeated.json()["duplicate"] == 1
    assert repeated.json()["receipt_id"] == first.json()["receipt_id"]

    later = {**capture, "observed_at": (start + timedelta(seconds=2)).isoformat(),
             "previous_observed_at": start.isoformat(),
             "previous": capture["payload"],
             "payload": {"metrics": {"node_disk_read_bytes_total": [
                 {"value": 1_000_000, "labels": {"device": "sda"}}]}}}
    measured = client.post("/api/v1/performance/captures/import", json=later)
    assert measured.status_code == 200, measured.text
    assert measured.json()["accepted"] == 1
    samples = client.get("/api/v1/performance/samples", params={
        "tenant_id": TENANT, "asset_id": "hw:host-pay",
        "metric_name": "disk.throughput_mbps"}).json()["samples"]
    assert len(samples) == 2
    assert samples[0]["metric_value"] is None and samples[0]["quality_status"] == "missing"
    assert samples[1]["metric_value"] == 0.5 and samples[1]["unit"] == "MB/s"
    assert all(str(s["evidence_id"]).startswith("unverified-capture:")
               for s in samples)
    receipt = client.get(f"/api/v1/performance/captures/{first.json()['receipt_id']}",
                         params={"tenant_id": TENANT})
    assert receipt.status_code == 200
    assert receipt.json()["signature"] is None
    assert receipt.json()["payload_sha256"] == first.json()["payload_sha256"]


def test_production_capture_requires_site_bound_signature(bank, monkeypatch, tmp_path):
    import base64
    import json
    from types import SimpleNamespace
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from api.routers import performance
    from shared_models.performance_capture import SCHEMA, payload_sha256

    client, _ = bank
    monkeypatch.setattr(performance, "get_settings",
                        lambda: SimpleNamespace(is_production=True))
    capture = {"tenant_id": TENANT, "asset_ref": "hw:host-pay",
               "source_id": "node-1", "source_type": "node_exporter",
               "authorization_ref": "bank-change/TEST-1",
               "observed_at": CHANGE.isoformat(),
               "payload": {"metrics": {"node_load1": [
                   {"value": 1.5, "labels": {}}]}}}
    assert client.post("/api/v1/performance/captures/import",
                       json=capture).status_code == 503  # no bank trust anchor
    key = Ed25519PrivateKey.generate()  # ephemeral test fixture, never deployed
    public = tmp_path / "bank-capture.pub"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE", str(public))
    assert client.post("/api/v1/performance/captures/import",
                       json=capture).status_code == 422  # unsigned
    signed = {"schema": SCHEMA, "algorithm": "Ed25519",
              "key_id": "fixture-key", "issuer": "fixture-bank-exporter",
              "tenant_id": TENANT, "asset_ref": "hw:host-pay",
              "source_id": "node-1", "source_type": "node_exporter",
              "observed_at": CHANGE.isoformat(), "previous_observed_at": None,
              "authorization_ref": "bank-change/TEST-1",
              "payload_sha256": payload_sha256(capture["payload"]),
              "previous_sha256": None}
    signature = key.sign(json.dumps(signed, sort_keys=True,
             separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    attestation = {"schema": SCHEMA, "algorithm": "Ed25519",
                   "key_id": "fixture-key", "issuer": "fixture-bank-exporter",
                   "signature": base64.b64encode(signature).decode()}
    accepted = client.post("/api/v1/performance/captures/import",
                           json={**capture, "attestation": attestation})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["provenance_state"] == "SIGNED_SOURCE_ASSERTION"
    assert accepted.json()["accepted"] == 1
    receipt = client.get(f"/api/v1/performance/captures/{accepted.json()['receipt_id']}",
                         params={"tenant_id": TENANT})
    assert receipt.status_code == 200
    assert receipt.json()["signature"] == attestation["signature"]
    assert receipt.json()["payload_sha256"] == accepted.json()["payload_sha256"]
    tampered = client.post("/api/v1/performance/captures/import", json={
        **capture, "payload": {"metrics": {"node_load1": [
            {"value": 99, "labels": {}}]}}, "attestation": attestation})
    assert tampered.status_code == 422


def test_signed_bank_style_series_becomes_simulation_context(bank, monkeypatch, tmp_path):
    import base64
    import json
    from types import SimpleNamespace
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from api.routers import performance
    from shared_models.performance_capture import SCHEMA, payload_sha256

    client, db = bank
    event = {"event_id": "change-host", "event_type": "CRYPTO_CONFIGURATION_CHANGED",
             "category": "CONFIGURATION", "logging_kind": "CHANGE",
             "tenant_id": TENANT, "severity": "INFO", "asset_id": "hw:host-pay",
             "source": {"collector_id": "bank-config", "collector_version": "1",
                        "source_type": "CONFIGURATION_OBSERVATION"},
             "cryptographic_context": {"protocol": "TLS", "evidence_level": "CONFIGURED"},
             "observation": {"observed_at": CHANGE.isoformat()},
             "evidence": {"evidence_ids": ["bank-change-ref"]}}
    assert CryptoLogRepository(db).insert_event(event)["outcome"] == "INSERTED"
    key = Ed25519PrivateKey.generate()  # test fixture only, not a bank signer
    public = tmp_path / "bank-trust.pem"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE", str(public))
    monkeypatch.setattr(performance, "get_settings",
                        lambda: SimpleNamespace(is_production=True))
    for before in (True, False):
        for index in range(5):
            captured = CHANGE + timedelta(minutes=-10 if before else 10,
                                         seconds=index)
            payload = {"metrics": {"node_load1": [
                {"value": 20 if before else 30, "labels": {}}]}}
            body = {"tenant_id": TENANT, "asset_ref": "hw:host-pay",
                    "source_id": "node-signed", "source_type": "node_exporter",
                    "authorization_ref": "bank-change/TEST-2",
                    "observed_at": captured.isoformat(), "payload": payload}
            signed = {"schema": SCHEMA, "algorithm": "Ed25519",
                      "key_id": "fixture-key", "issuer": "fixture-bank-exporter",
                      "tenant_id": TENANT, "asset_ref": "hw:host-pay",
                      "source_id": "node-signed", "source_type": "node_exporter",
                      "observed_at": captured.isoformat(), "previous_observed_at": None,
                      "authorization_ref": "bank-change/TEST-2",
                      "payload_sha256": payload_sha256(payload),
                      "previous_sha256": None}
            signature = key.sign(json.dumps(signed, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
            response = client.post("/api/v1/performance/captures/import", json={
                **body, "attestation": {"schema": SCHEMA, "algorithm": "Ed25519",
                    "key_id": "fixture-key", "issuer": "fixture-bank-exporter",
                    "signature": base64.b64encode(signature).decode()}})
            assert response.status_code == 200, response.text
            assert response.json()["accepted"] == 1
    review = client.get("/api/v1/performance/simulation-context", params=_params(
        asset_ref="hw:host-pay", metric_name="system.load", source_id="node-signed",
        change_event_id="change-host"))
    assert review.status_code == 200, review.text
    result = review.json()
    assert result["status"] == "MEASURED_COMPARISON"
    assert result["before"]["signed_capture_samples"] == 5
    assert result["after"]["signed_capture_samples"] == 5
    assert result["delta_percent"] == 50
    assert result["causation"] == "UNPROVEN"
    assert result["purpose"] == "SIMULATION_INPUT"
    assert "migration_plan" not in result
    from db.models.performance import PerformanceCaptureReceipt

    receipt = db.query(PerformanceCaptureReceipt).filter_by(
        tenant_id=TENANT, source_id="node-signed").first()
    assert receipt is not None
    receipt.signature = "tampered"
    db.commit()
    refused = client.get("/api/v1/performance/simulation-context", params=_params(
        asset_ref="hw:host-pay", metric_name="system.load", source_id="node-signed",
        change_event_id="change-host"))
    assert refused.status_code == 409
    assert "signature" in refused.json()["detail"]


def test_capture_refuses_foreign_assets_and_unbounded_samples(bank):
    client, _ = bank
    capture = {"tenant_id": TENANT, "asset_ref": "hw:host-pay",
               "source_id": "node-1", "source_type": "node_exporter",
               "authorization_ref": "bank-change/TEST-1",
               "observed_at": CHANGE.isoformat(),
               "payload": {"metrics": {"node_load1": [
                   {"value": 1, "labels": {}}]}}}
    with tenant_scope("bank-b"):
        assert client.post("/api/v1/performance/captures/import",
                           json=capture).status_code == 403
    assert client.post("/api/v1/performance/captures/import",
                       json={**capture, "asset_ref": "hw:forged"}).status_code == 404
    oversized = {**capture, "payload": {"metrics": {"node_load1": [
        {"value": 1, "labels": {}} for _ in range(1001)]}}}
    assert client.post("/api/v1/performance/captures/import",
                       json=oversized).status_code == 413
    assert client.post("/api/v1/performance/captures/import",
                       json={**capture, "previous": capture["payload"]}).status_code == 422


def test_unsigned_metrics_remain_provisional_simulation_context(bank):
    client, db = bank
    _measure(db)
    _measure(db, before=False)
    response = client.get("/api/v1/performance/simulation-context", params=_params())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "PROVISIONAL_UNATTESTED"
    assert body["before"]["valid"] == body["after"]["valid"] == 5
    assert body["before"]["signed_capture_samples"] == 0
    assert body["delta_p95"] == 10 and body["delta_percent"] == 50
    assert body["causation"] == "UNPROVEN"
    assert body["purpose"] == "SIMULATION_INPUT"
    assert "migration_plan" not in body
    assert body["benchmark"]["status"] == "NOT_SUPPLIED"
    assert body["change"]["evidence_refs_unverified"] == ["unverified-event-ref"]


def test_production_simulation_context_refuses_unsigned_direct_metrics(bank, monkeypatch):
    from types import SimpleNamespace
    from api.routers import performance

    client, db = bank
    _measure(db)
    _measure(db, before=False)
    monkeypatch.setattr(performance, "get_settings",
                        lambda: SimpleNamespace(is_production=True))
    denied = client.get("/api/v1/performance/simulation-context", params=_params())
    assert denied.status_code == 409
    assert "bank-signed capture" in denied.json()["detail"]


def test_thin_or_wrong_source_is_not_evaluable(bank):
    client, db = bank
    _measure(db, count=4)
    _measure(db, before=False, source="other-bank-collector")
    result = client.get("/api/v1/performance/simulation-context", params=_params())
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["status"] == "NOT_EVALUABLE"
    assert body["delta_p95"] is None
    assert body["before"]["valid"] == 4 and body["after"]["valid"] == 0


def test_foreign_or_forged_asset_and_unit_are_refused(bank):
    client, db = bank
    with tenant_scope("bank-b"):
        assert client.get("/api/v1/performance/simulation-context",
                          params=_params(tenant_id="bank-b")).status_code == 404
        assert client.get("/api/v1/performance/simulation-context",
                          params=_params()).status_code == 403
    _measure(db, unit="bytes")
    _measure(db, before=False)
    assert client.get("/api/v1/performance/simulation-context",
                      params=_params()).status_code == 409
    assert client.get("/api/v1/performance/simulation-context",
                      params=_params(asset_ref="app:not-registered")).status_code == 404


def test_controlled_benchmark_pair_is_separate_from_bank_telemetry(bank):
    from db.models.performance import PerformanceBenchmarkRun

    client, db = bank
    method = {"hardware": "synthetic-lab-node", "software": "provider-v1",
              "provider": "bank-approved-lab", "algorithm": "RSA-2048",
              "algorithm_parameters": {"key_size": 2048},
              "methodology": "controlled-sign-timing", "concurrency": 1,
              "sample_count": 5}
    for run_id, algorithm, mean in (("bench-before", "RSA-2048", 2.0),
                                    ("bench-after", "ML-DSA", 3.0)):
        db.add(PerformanceBenchmarkRun(
            tenant_id=TENANT, run_id=run_id,
            measurement_kind="controlled_benchmark", approved=1,
            method={**method, "algorithm": algorithm},
            results=[{"operation": "sign", "mean_ms": mean, "samples": 5}],
            executed_at=CHANGE))
    db.commit()
    params = _params(baseline_benchmark_run_id="bench-before",
                     candidate_benchmark_run_id="bench-after")
    response = client.get("/api/v1/performance/simulation-context", params=params)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "NOT_EVALUABLE"  # no bank telemetry supplied
    assert body["benchmark"]["status"] == "CONTROLLED_COMPARISON"
    assert body["benchmark"]["operations"][0]["delta_percent"] == 50
    assert body["purpose"] == "SIMULATION_INPUT"
    assert "migration_plan" not in body
    assert "never production traffic" in body["benchmark"]["note"]
    assert client.get("/api/v1/performance/simulation-context",
                      params=_params(baseline_benchmark_run_id="bench-before")).status_code == 422


def test_performance_attaches_to_twin_simulation_without_changing_live_state(bank):
    client, db = bank
    _measure(db)
    _measure(db, before=False)
    with tenant_scope(TENANT):
        discovery = client.post("/api/v1/estate/evidence/discover", json={
            "estate": "synthetic-payments", "assets": [{
                "ref": "pay", "type": "APPLICATION", "name": "Payments API",
                "identity": {"system_id": "sys-pay"}}],
            "evidence": [{"source": "static-fixture", "evidence_type": "STATIC_OBSERVED",
                          "target": "pay", "layer": "APPLICATION",
                          "facts": {"algorithm": "RSA", "purpose": "sign"}}]})
        assert discovery.status_code == 200, discovery.text
        before = client.get("/api/v1/estate/evidence/summary").json()
        simulated = client.post("/api/v1/estate/evidence/simulation/run", json={
            "kind": "REPLACE_ALGORITHM", "from": "RSA", "to": "ML-DSA",
            "persist": False, "performance_context": _params()})
        assert simulated.status_code == 200, simulated.text
        body = simulated.json()
        assert body["status"] == "SIMULATED"
        perf = body["performance_context"]
        assert perf["purpose"] == "SIMULATION_INPUT"
        assert perf["status"] == "PROVISIONAL_UNATTESTED"
        assert perf["link"]["state"] == "AFFECTED_EXACT_IDENTITY"
        assert perf["delta_p95"] == 10
        assert perf["causation"] == "UNPROVEN"
        assert "migration_plan" not in perf
        assert body["live_state_modified"] is False
        after = client.get("/api/v1/estate/evidence/summary").json()
        assert before == after


def test_performance_without_exact_twin_identity_is_not_attributed(bank):
    client, db = bank
    _measure(db)
    _measure(db, before=False)
    with tenant_scope(TENANT):
        discovery = client.post("/api/v1/estate/evidence/discover", json={
            "estate": "synthetic-payments", "assets": [{
                "ref": "pay", "type": "APPLICATION", "name": "Payments API",
                "identity": {"name": "Payments API"}}],
            "evidence": [{"source": "static-fixture", "evidence_type": "STATIC_OBSERVED",
                          "target": "pay", "layer": "APPLICATION",
                          "facts": {"algorithm": "RSA"}}]})
        assert discovery.status_code == 200, discovery.text
        response = client.post("/api/v1/estate/evidence/simulation/run", json={
            "kind": "REPLACE_ALGORITHM", "from": "RSA", "to": "ML-DSA",
            "persist": False, "performance_context": _params()})
    assert response.status_code == 200, response.text
    assert response.json()["performance_context"]["link"]["state"] == "NOT_ESTABLISHED"


def test_windows_must_straddle_recorded_change(bank):
    client, _ = bank
    invalid = client.get("/api/v1/performance/simulation-context",
                         params=_params(before_end=(CHANGE + timedelta(minutes=2)).isoformat()))
    assert invalid.status_code == 422
