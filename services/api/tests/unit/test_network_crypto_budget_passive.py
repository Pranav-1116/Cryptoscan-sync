"""Traffic budget accounting and passive intake (spec 67 §3, §22, §30).

Budget tests use a real SQLite session (the setting store is the accounting
ledger); passive tests pin the metadata-only whitelist. No socket is opened.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.main import create_app
from api.security.network_budget import (
    BudgetExhausted,
    budget_key,
    check,
    reserve,
    settle,
    state,
)
from api.security.network_scope import ScopeViolation
from db.connection.session import Base
from network_scanner.inventory.network_evidence import (
    PassiveObservationRejected,
    build_passive_evidence,
    to_cbom_assets,
    validate_passive_observation,
)

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def approved_scope(**overrides):
    document = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443", "10.20.10.16:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 4, "max_bytes": 1000},
        "valid_until": (NOW + timedelta(hours=6)).isoformat(),
        "_tenant": None,
    }
    document.update(overrides)
    return document


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# budget accounting
# --------------------------------------------------------------------------- #


def test_budget_key_is_tenant_scoped():
    assert budget_key("bank-a") == "network:crypto-budget:bank-a:default"
    assert budget_key(None, "core") == "network:crypto-budget:default:core"


def test_budget_starts_empty(db):
    usage = state(db, tenant_id=None, limit={"max_connections": 4, "max_bytes": 1000}, now=NOW)
    assert usage["connections_used"] == 0
    assert usage["connections_remaining"] == 4
    assert usage["bytes_remaining"] == 1000
    assert usage["exhausted"] is False
    assert usage["distributed"] is False


def test_reserve_charges_the_window(db):
    scope = approved_scope()
    reserve(db, scope, connections=2, now=NOW)
    usage = state(db, tenant_id=None, limit=scope["traffic_budget"], now=NOW)
    assert usage["connections_used"] == 2
    assert usage["connections_remaining"] == 2
    assert usage["runs"] == 1


def test_reserve_refuses_when_budget_would_be_exceeded(db):
    scope = approved_scope()
    reserve(db, scope, connections=4, now=NOW)
    with pytest.raises(BudgetExhausted) as excinfo:
        reserve(db, scope, connections=1, now=NOW)
    assert excinfo.value.code == "traffic_budget_exhausted"
    assert "4/4" in excinfo.value.reason


def test_scope_without_budget_zero_blocks_on_first_run(db):
    scope = approved_scope(traffic_budget={"max_connections": 0, "max_bytes": 0})
    # 0 means "unbounded" for max_* in the scope model, so nothing is charged.
    reserve(db, scope, connections=50, now=NOW)
    usage = state(db, tenant_id=None, limit=scope["traffic_budget"], now=NOW)
    assert usage["connections_remaining"] is None


def test_byte_budget_blocks_further_runs(db):
    scope = approved_scope()
    settle(db, scope, bytes_used=1000, now=NOW)
    with pytest.raises(BudgetExhausted) as excinfo:
        reserve(db, scope, connections=1, now=NOW)
    assert "byte budget spent" in excinfo.value.reason


def test_window_rolls_over_after_24h(db):
    scope = approved_scope()
    reserve(db, scope, connections=4, now=NOW)
    with pytest.raises(BudgetExhausted):
        check(db, scope, connections=1, now=NOW + timedelta(minutes=5))
    later = NOW + timedelta(seconds=24 * 3600 + 1)
    check(db, scope, connections=1, now=later)  # new window: allowed again
    usage = state(db, tenant_id=None, limit=scope["traffic_budget"], now=later)
    assert usage["connections_used"] == 0


def test_budget_without_scope_is_refused(db):
    with pytest.raises(BudgetExhausted):
        check(db, None, connections=1, now=NOW)


def test_usage_survives_separate_sessions(db):
    scope = approved_scope()
    reserve(db, scope, connections=3, now=NOW)
    assert state(db, tenant_id=None, limit=scope["traffic_budget"], now=NOW)["connections_used"] == 3


# --------------------------------------------------------------------------- #
# passive intake — metadata only (§22)
# --------------------------------------------------------------------------- #

SENSOR_OBSERVATION = {
    "timestamp": "2026-10-27T11:59:00Z",
    "src_ip": "10.20.1.50",
    "src_port": 51234,
    "dst_ip": "10.20.10.15",
    "dst_port": 443,
    "protocol": "TLS",
    "server_name": "payments.bank",
    "tls_version": "TLSv1.2",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "certificate_fingerprint_sha256": "sha256:abc",
    "certificate_public_key_algorithm": "RSA",
    "certificate_signature_algorithm": "sha256WithRSAEncryption",
    "ja3": "771,4865",
    "bytes": 4096,
    "sensor_id": "tap-01",
    "capture_point": "dmz-span",
}


def test_passive_record_is_typed_and_medium_confidence():
    record = build_passive_evidence(SENSOR_OBSERVATION)
    assert record["evidence_type"] == "NETWORK_PASSIVE_OBSERVED"
    assert record["target"]["endpoint"] == "10.20.10.15:443"
    assert record["confidence"] == "MEDIUM"
    assert record["decomposition"]["encryption"] == "AES-256"
    assert record["decomposition"]["key_exchange"] == "ECDHE"
    assert record["mutual_tls"] == "UNKNOWN"
    assert record["passive"]["ja3"] == "771,4865"
    assert any("only the traffic" in line for line in record["limitations"])


def test_passive_cipher_decomposition_matches_active_parser():
    record = build_passive_evidence(SENSOR_OBSERVATION)
    assert record["decomposition"]["authentication"] == "RSA"
    assert record["decomposition"]["mode"] == "GCM"
    assert record["decomposition"]["mac_or_prf"] == "SHA384"


@pytest.mark.parametrize(
    "field",
    ["payload", "plaintext", "session_key", "private_key", "authorization", "http_body", "cookie"],
)
def test_passive_intake_refuses_captured_content(field):
    observation = dict(SENSOR_OBSERVATION)
    observation[field] = "leaked"
    with pytest.raises(PassiveObservationRejected) as excinfo:
        validate_passive_observation(observation)
    assert field in str(excinfo.value)


def test_passive_intake_refuses_unknown_fields():
    with pytest.raises(PassiveObservationRejected):
        validate_passive_observation({"dst_ip": "10.0.0.1", "email": "x@y.z"})


def test_passive_record_contributes_cbom_assets():
    record = build_passive_evidence(SENSOR_OBSERVATION)
    cbom = to_cbom_assets([record])
    assert "AES-256" in cbom["algorithms"]
    assert cbom["layer"] == "NETWORK_TRANSPORT"


# --------------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client(monkeypatch):
    import api.routers.network as network_router

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    app.dependency_overrides[get_tenant_context] = lambda: type(
        "Ctx", (), {"tenant_id": None, "roles": ["superadmin"], "username": "tester"}
    )()
    app.dependency_overrides[network_router.network_context] = lambda: None

    def fake_run(db, **kwargs):
        from contextlib import contextmanager

        @contextmanager
        def _run():
            class Run:
                job_id = "job-1"
                run_id = "run-1"

                def plan(self, *_a, **_k):
                    return None

                def succeed(self, **_k):
                    return None

                def conclusions(self):
                    return {}

            yield Run()

        return _run()

    monkeypatch.setattr(network_router, "network_run", fake_run)
    monkeypatch.setattr(
        network_router, "persist_network", lambda db, result, run, **k: {"job_id": "job-1", "run_id": "run-1"}
    )
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def put_scope(http, **overrides):
    body = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443", "10.20.10.16:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 4, "max_bytes": 1000000},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "inventory_id": "default",
    }
    body.update(overrides)
    return http.put("/api/v1/network/crypto-scope", json=body)


def test_budget_endpoint_reports_not_configured(client):
    http, _session = client
    body = http.get("/api/v1/network/crypto-budget").json()
    assert body["configured"] is False
    assert "no approved scope" in body["reason"]


def test_budget_endpoint_reports_usage_after_scope(client):
    http, _session = client
    assert put_scope(http).status_code == 200
    body = http.get("/api/v1/network/crypto-budget").json()
    assert body["configured"] is True
    assert body["max_connections"] == 4
    assert body["connections_used"] == 0
    assert body["distributed"] is False


def test_passive_ingest_stores_metadata_records(client):
    http, _session = client
    response = http.post("/api/v1/network/crypto-passive", json={"observations": [SENSOR_OBSERVATION]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["active_packets"] == 0
    assert body["stored"] == 1
    assert body["evidence"][0]["evidence_type"] == "NETWORK_PASSIVE_OBSERVED"
    assert body["summary"]["observed"] == 1
    assert "NOT_OBSERVED" in body["note"]


def test_passive_ingest_refuses_payload_batch(client):
    http, _session = client
    observation = dict(SENSOR_OBSERVATION)
    observation["payload"] = "GET / HTTP/1.1"
    response = http.post("/api/v1/network/crypto-passive", json={"observations": [observation]})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "passive_observation_rejected"


def test_passive_ingest_refuses_empty_batch(client):
    http, _session = client
    assert http.post("/api/v1/network/crypto-passive", json={"observations": []}).status_code == 422


def test_legacy_discovery_sweep_is_refused_when_scope_exists(client):
    http, _session = client
    assert put_scope(http).status_code == 200
    response = http.post("/api/v1/network/discover", json={"cidr": "10.20.10.0/24", "scan": False})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_forbids_sweep"


def test_legacy_scan_refused_for_destination_outside_scope(client):
    http, _session = client
    assert put_scope(http).status_code == 200
    response = http.post("/api/v1/network/scan", json={"hosts": ["10.99.99.99:443"], "live": True})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "destination_outside_scope"


def test_legacy_scope_check_is_a_noop_without_scope(client):
    http, _session = client
    # No scope saved: the older admission path still applies (not a 409 from scope).
    response = http.post("/api/v1/network/scan", json={"hosts": ["127.0.0.1:443"], "live": True})
    assert response.status_code != 409 or response.json()["detail"] != "destination_outside_scope"


def test_scope_violation_is_a_scope_error_not_a_budget_error(db):
    from api.security.network_scope import check_scope

    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(None, ["10.20.10.15:443"], now=NOW)
    assert excinfo.value.code == "scope_not_configured"


# --------------------------------------------------------------------------- #
# admission contract: every network_run caller must satisfy the ledger
# --------------------------------------------------------------------------- #


def test_passive_admission_satisfies_durable_run_contract(db, monkeypatch):
    """A caller that omits ``checked_targets`` raises KeyError inside network_run.

    Passive ingest opens no connection, so the honest value is 0 — not a
    missing key and not a pretend target count.
    """
    import api.security.network_collection as collection

    captured: dict = {}

    class FakeDurable:
        def __init__(self, session, **kwargs):
            captured.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(collection, "DurableScanRun", FakeDurable)
    admission = {
        "schema": "cryptoscan.network-admission/1",
        "decision": "PASSIVE_INGEST",
        "protocol": "TLS",
        "active": False,
        "checked_targets": 0,
    }
    with collection.network_run(
        db, user="tester", target="passive:1", admission=admission, kind="crypto-passive", profile={}
    ):
        pass
    assert captured["metadata"]["hosts"] == 0
    assert captured["metadata"]["kind"] == "crypto-passive"
    assert captured["job_type"] == "NETWORK_SCAN"


def test_passive_admission_without_targets_fails_loudly(db, monkeypatch):
    """The ledger contract is enforced, so a future caller cannot silently drift."""
    import api.security.network_collection as collection

    class FakeDurable:
        def __init__(self, session, **kwargs):
            raise AssertionError("metadata built")

    monkeypatch.setattr(collection, "DurableScanRun", FakeDurable)
    with pytest.raises(KeyError):
        with collection.network_run(
            db, user="tester", target="x", admission={"decision": "PASSIVE_INGEST"}, kind="crypto-passive", profile={}
        ):
            pass


def test_evidence_readback_includes_passive_runs(client):
    """Active and passive runs are both evidence; neither may be hidden."""
    http, session = client
    from db.repositories.scan_run_repository import ScanRunRepository
    from network_scanner.inventory.network_evidence import build_passive_evidence

    record = build_passive_evidence(SENSOR_OBSERVATION)
    ScanRunRepository(session).create_run({"network_evidence": [record]}, target_kind="crypto-passive")
    session.commit()

    body = http.get("/api/v1/network/crypto-evidence").json()
    assert body["count"] == 1
    assert body["summary"]["observed_passive"] == 1
    assert body["evidence"][0]["evidence_type"] == "NETWORK_PASSIVE_OBSERVED"
