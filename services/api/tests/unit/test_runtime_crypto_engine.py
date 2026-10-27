"""Runtime crypto scan engine (spec 92).

The properties under test are the honesty properties, not the happy path:

* no scope → nothing is accepted, and an unapproved host/window is refused;
* a forbidden field (plaintext, key material, customer data) rejects the batch;
* an unreported parameter is ``UNKNOWN`` and is never inferred;
* attribution levels are reported and never promoted (Level 4 ≠ Level 1);
* Level 6 (custom crypto) is a blind spot, not a clean result.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from runtime.engine.adapters import adapter_catalog, get_adapter
from runtime.engine.assets import build_runtime_cbom, summarize_runtime_events
from runtime.engine.events import (
    CryptoObservationRejected,
    build_runtime_event,
    normalize_operation,
)
from runtime.engine.levels import level_for_evidence, level_table
from runtime.engine.policy import evaluate_runtime, runtime_pqc_readiness
from runtime.engine.scope import (
    RuntimeScopeViolation,
    check_runtime_scope,
    normalize_runtime_scope,
    scope_window_state,
)


def _scope(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    scope = {
        "name": "payments-runtime",
        "hosts": ["payments-prod-01"],
        "applications": ["payments-api"],
        "processes": ["payments-api"],
        "runtime_methods": ["CRYPTO_API_TRACE", "PROCESS_TELEMETRY"],
        "data_restrictions": ["NO_PLAINTEXT", "NO_PRIVATE_KEYS", "NO_CUSTOMER_DATA"],
        "collection_window": {"from": (now - timedelta(hours=1)).isoformat(), "to": (now + timedelta(hours=1)).isoformat()},
    }
    scope.update(overrides)
    return scope


def _observation(**overrides) -> dict:
    observation = {
        "source": "OPENSSL_TRACE",
        "runtime_method": "CRYPTO_API_TRACE",
        "host": "payments-prod-01",
        "application": "payments-api",
        "process": "payments-api",
        "pid": 1842,
        "executable": "/opt/payments/payment-api",
        "executable_digest": "sha256:abc123",
        "container_digest": "sha256:def456",
        "pod": "payments-api-7d9f",
        "crypto_provider": "OpenSSL",
        "algorithm": "AES",
        "key_size": 256,
        "mode": "GCM",
        "operation": "ENCRYPT",
        "nonce_length": 96,
        "tag_length": 128,
    }
    observation.update(overrides)
    return observation


# --------------------------------------------------------------------------- #
# §3 — scope and authorization
# --------------------------------------------------------------------------- #


def test_scope_without_hosts_is_refused():
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        normalize_runtime_scope({"name": "all", "hosts": []})
    assert excinfo.value.code == "runtime_scope_incomplete"
    assert "blanket instrumentation" in excinfo.value.reason


def test_scope_rejects_unapproved_method_and_restriction():
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        normalize_runtime_scope(_scope(runtime_methods=["KERNEL_HOOK"]))
    assert excinfo.value.code == "runtime_method_not_approved"

    with pytest.raises(RuntimeScopeViolation) as excinfo:
        normalize_runtime_scope(_scope(data_restrictions=["NO_LOGGING"]))
    assert excinfo.value.code == "runtime_restriction_unknown"


def test_scope_window_controls_collection():
    now = datetime.now(timezone.utc)
    scope = normalize_runtime_scope(_scope())
    assert scope_window_state(scope)["open"] is True

    expired = normalize_runtime_scope(
        _scope(
            collection_window={
                "from": (now - timedelta(hours=4)).isoformat(),
                "to": (now - timedelta(hours=3)).isoformat(),
            }
        )
    )
    assert scope_window_state(expired)["state"] == "EXPIRED"
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(), expired)
    assert excinfo.value.code == "runtime_window_closed"


def test_observation_outside_scope_is_refused():
    scope = normalize_runtime_scope(_scope())
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(host="fraud-prod-09"), scope)
    assert excinfo.value.code == "runtime_host_not_approved"

    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(application="fraud-service"), scope)
    assert excinfo.value.code == "runtime_application_not_approved"

    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(runtime_method="NETWORK_SESSION"), scope)
    assert excinfo.value.code == "runtime_method_not_approved"


def test_no_scope_means_no_instrumentation():
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(), None)
    assert excinfo.value.code == "runtime_scope_missing"


def test_data_restriction_rejects_plaintext_and_customer_fields():
    scope = normalize_runtime_scope(_scope())
    with pytest.raises(RuntimeScopeViolation) as excinfo:
        check_runtime_scope(_observation(plaintext="4111 1111 1111 1111"), scope)
    assert excinfo.value.code == "runtime_data_restriction_violated"
    assert excinfo.value.detail["field"] == "plaintext"


# --------------------------------------------------------------------------- #
# §7–§13 — the event
# --------------------------------------------------------------------------- #


def test_event_keeps_only_what_the_adapter_reported():
    event = build_runtime_event(_observation())
    assert event["schema"] == "cryptoscan.runtime-crypto-event/1"
    assert event["attribution_level"] == 1
    assert event["evidence_type"] == "RUNTIME_OBSERVED"
    assert event["operation"] == "ENCRYPT"
    assert event["parameters"]["nonce_length"] == 96
    assert event["parameters"]["tag_length"] == 128
    assert "key_size" in event["observed_fields"]
    # not reported by the OpenSSL shim → UNKNOWN, never defaulted
    assert event["decomposition"]["padding"] is None
    assert "padding" in event["unobserved_fields"]


def test_missing_key_size_is_unknown_not_inferred():
    observation = _observation()
    observation.pop("key_size")
    event = build_runtime_event(observation)
    assert event["key_size"] == "UNKNOWN"
    assert any("NOT inferred" in line for line in event["limitations"])


def test_event_rejects_content_and_key_material():
    with pytest.raises(CryptoObservationRejected):
        build_runtime_event(_observation(plaintext="secret"))
    with pytest.raises(CryptoObservationRejected):
        build_runtime_event(_observation(attributes={"key_bytes": "0011"}))
    with pytest.raises(CryptoObservationRejected):
        build_runtime_event({"source": "OPENSSL_TRACE", "host": "h", "private_key": "-----BEGIN"})


def test_operation_taxonomy_folds_adapter_spellings():
    assert normalize_operation("EVP_Encrypt") == "ENCRYPT"
    assert normalize_operation("digest") == "HASH"
    assert normalize_operation("hmac") == "MAC"
    assert normalize_operation("derive") == "KEY_AGREEMENT"
    assert normalize_operation("wrap") == "KEY_WRAP"
    # an unknown spelling does not become ENCRYPT by default
    assert normalize_operation("encryptish") == "UNKNOWN"


def test_identity_chain_is_carried_through_the_event():
    identity = build_runtime_event(_observation())["identity"]
    assert identity["pod"] == "payments-api-7d9f"
    assert identity["container_digest"] == "sha256:def456"
    assert identity["executable_digest"] == "sha256:abc123"
    assert identity["pid"] == 1842


# --------------------------------------------------------------------------- #
# §6 — the level hierarchy
# --------------------------------------------------------------------------- #


def test_levels_map_sources_and_never_promote():
    assert level_for_evidence("OPENSSL_TRACE") == 1
    assert level_for_evidence("HSM_AUDIT") == 3
    assert level_for_evidence("TLS_TAP") == 4
    assert level_for_evidence("BINARY_TRACE") == 5
    assert level_for_evidence("SOMETHING_NEW") == 6
    assert len(level_table()) == 6


def test_unknown_adapter_is_level_six_with_a_named_limit():
    event = build_runtime_event(_observation(source="CUSTOM_CRYPTO_HOOK"))
    assert event["attribution_level"] == 6
    assert event["evidence_type"] == "UNKNOWN"
    assert any("no approved observation covers this code path" in line for line in event["limitations"])


def test_network_observation_is_labelled_level_four_not_application_crypto():
    event = build_runtime_event(
        _observation(source="TLS_TAP", algorithm="TLS_AES_256_GCM_SHA384", operation="TLS_HANDSHAKE")
    )
    assert event["attribution_level"] == 4
    assert event["evidence_type"] == "NETWORK_OBSERVED"
    assert any("transport crypto only" in line for line in event["limitations"])


def test_adapter_catalogue_declares_blind_spots():
    catalog = adapter_catalog()
    assert catalog["adapter_count"] >= 8
    assert all(adapter["cannot_report"] for adapter in catalog["adapters"])
    jvm = get_adapter("jvm-jce")
    assert jvm is not None and jvm.source == "JVM_JCE"
    assert any("native code" in note for note in jvm.cannot_report)


# --------------------------------------------------------------------------- #
# §11 / §31 — risk and PQC
# --------------------------------------------------------------------------- #


def test_runtime_policy_flags_weak_algorithms_and_ecb():
    weak = build_runtime_event(_observation(algorithm="DES", key_size=56, mode="CBC", operation="ENCRYPT"))
    ecb = build_runtime_event(_observation(algorithm="AES", key_size=256, mode="ECB", operation="ENCRYPT"))
    report = evaluate_runtime([weak, ecb])
    rules = {finding["rule_id"] for finding in report["failed"]}
    assert "RT-ALGORITHM-FORBIDDEN" in rules
    assert "RT-MODE-ECB" in rules
    assert report["verdict"] == "FAIL"
    assert all(finding["layer"] == "RUNTIME" for finding in report["findings"])


def test_runtime_policy_marks_missing_key_size_unknown():
    observation = _observation(algorithm="RSA", operation="SIGN", mode=None)
    observation.pop("key_size")
    report = evaluate_runtime([build_runtime_event(observation)])
    key_size = [finding for finding in report["findings"] if finding["rule_id"] == "RT-KEY-SIZE"]
    assert key_size and key_size[0]["status"] == "UNKNOWN"


def test_runtime_policy_never_scores_a_blind_spot_as_clean():
    blind = build_runtime_event(_observation(source="CUSTOM_CRYPTO_HOOK", algorithm=None))
    report = evaluate_runtime([blind])
    assert report["verdict"] == "NOT_ASSESSABLE"
    assert report["coverage_gaps"]
    assert report["failed"] == []


def test_runtime_pqc_readiness_classifies_public_key_operations():
    sign = build_runtime_event(_observation(algorithm="RSA", key_size=3072, operation="SIGN", mode=None))
    pq = build_runtime_event(_observation(algorithm="MLKEM768", operation="KEY_GENERATION", mode=None, source="GO_CRYPTO"))
    report = runtime_pqc_readiness([sign, pq])
    assert report["summary"]["quantum_vulnerable"] == 1
    assert report["summary"]["post_quantum_or_hybrid"] == 1
    assert report["verdict"] == "PARTIAL"


# --------------------------------------------------------------------------- #
# §31 — assets / CBOM
# --------------------------------------------------------------------------- #


def test_cbom_groups_events_by_artifact_and_keeps_levels():
    events = [
        build_runtime_event(_observation()),
        build_runtime_event(_observation(observation_count=3)),
        build_runtime_event(_observation(algorithm="SHA-256", operation="HASH", mode=None, key_size=None)),
    ]
    cbom = build_runtime_cbom(events, estate="payments")
    assert cbom["asset_count"] == 2
    assert cbom["algorithms"]["AES"] == 4  # 1 + 3 observations
    assert cbom["attribution_levels"]["CRYPTO_API_OBSERVED"] == 3
    aes = next(asset for asset in cbom["assets"] if asset["algorithm"] == "AES")
    assert aes["applications"] == ["payments-api"]
    assert aes["images"] == ["sha256:def456"]
    assert aes["operations"] == {"ENCRYPT": 4}
    assert aes["parameter_metadata"]["nonce_length"] == 96


def test_summary_counts_blind_spots():
    events = [
        build_runtime_event(_observation()),
        build_runtime_event(_observation(source="CUSTOM_CRYPTO_HOOK", algorithm=None)),
    ]
    summary = summarize_runtime_events(events)
    assert summary["events"] == 2
    assert summary["level6_events"] == 1
    assert summary["unknown_algorithm_events"] == 1
    assert "blind spots" in summary["note"]


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "runtime-auditor"
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def test_ingest_without_scope_is_refused(client):
    http, _session = client
    response = http.post("/api/v1/runtime/crypto-events", json={"observations": [_observation()]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "runtime_scope_missing"


def test_scope_then_ingest_then_read_back(client):
    http, _session = client
    saved = http.put("/api/v1/runtime/crypto-scope", json=_scope())
    assert saved.status_code == 200, saved.text
    assert saved.json()["permitted"] is True

    ingest = http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": [_observation(), _observation(observation_count=2)]},
    )
    assert ingest.status_code == 200, ingest.text
    body = ingest.json()
    assert body["stored"] == 2
    assert body["summary"]["attribution_levels"] == {"CRYPTO_API_OBSERVED": 2}

    listed = http.get("/api/v1/runtime/crypto-events")
    assert listed.status_code == 200
    assert len(listed.json()["events"]) == 2

    cbom = http.get("/api/v1/runtime/crypto-cbom")
    assert cbom.status_code == 200
    assert cbom.json()["cbom"]["asset_count"] == 1


def test_ingest_refuses_out_of_scope_and_content(client):
    http, _session = client
    http.put("/api/v1/runtime/crypto-scope", json=_scope())

    out_of_scope = http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": [_observation(host="fraud-prod-09")]},
    )
    assert out_of_scope.status_code == 403
    assert out_of_scope.json()["detail"]["error"] == "runtime_host_not_approved"

    content = http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": [_observation(plaintext="4111")]},
    )
    assert content.status_code in {403, 422}
    assert "restriction" in content.text or "content" in content.text


def test_unknown_observation_field_is_refused(client):
    http, _session = client
    http.put("/api/v1/runtime/crypto-scope", json=_scope())
    response = http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": [{**_observation(), "session_capture": "…"}]},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "runtime_event_field_unknown"


def test_scope_and_adapter_endpoints(client):
    http, _session = client
    empty = http.get("/api/v1/runtime/crypto-scope")
    assert empty.status_code == 200
    assert empty.json()["configured"] is False
    assert empty.json()["permitted"] is False

    invalid = http.put("/api/v1/runtime/crypto-scope", json={"name": "x", "hosts": []})
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["error"] == "runtime_scope_incomplete"

    adapters = http.get("/api/v1/runtime/crypto-adapters")
    assert adapters.status_code == 200
    assert len(adapters.json()["levels"]) == 6
    assert adapters.json()["event_fields"]


def test_risk_endpoint_scores_stored_events(client):
    http, _session = client
    http.put("/api/v1/runtime/crypto-scope", json=_scope())
    http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": [_observation(algorithm="RC4", key_size=128, mode=None, operation="ENCRYPT")]},
    )
    response = http.post("/api/v1/runtime/crypto-risk", json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.runtime-risk/1"
    assert body["verdict"] == "FAIL"
    assert body["sources"]["origin"] == "stored_events"
    assert body["pqc"]["verdict"] in {"SYMMETRIC_ONLY", "CLASSICAL_ONLY", "NOT_OBSERVED"}


# --------------------------------------------------------------------------- #
# Evidence integrity chain (spec 92 §11, §16)
# --------------------------------------------------------------------------- #


def _ingest(http, observations=None):
    saved = http.put("/api/v1/runtime/crypto-scope", json=_scope())
    assert saved.status_code == 200, saved.text
    response = http.post(
        "/api/v1/runtime/crypto-events",
        json={"observations": observations or [_observation()]},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_ingest_chains_events_and_verification_is_intact(client):
    http, _session = client
    body = _ingest(http, [_observation(), _observation(observation_count=3)])

    receipt = body["evidence_chain"]
    assert receipt["namespace"] == "runtime"
    assert receipt["appended"] == 2
    assert receipt["head"] != "0" * 64

    verify = http.get("/api/v1/runtime/crypto-events/verify").json()
    assert verify["namespace"] == "runtime"
    assert verify["verified"] is True
    assert verify["entries"] == 2
    assert verify["chain"]["seq"] >= 2
    assert verify["distributed"] is False
    assert verify["anchoring"] == "local-database-only"

    listed = http.get("/api/v1/runtime/crypto-events").json()
    assert all("integrity" in event for event in listed["events"])
    assert listed["integrity"]["verified"] is True


def test_a_modified_event_breaks_the_chain(client):
    http, session = client
    body = _ingest(http)

    from db.repositories.scan_run_repository import ScanRunRepository

    row = ScanRunRepository(session).get_run(body["run_id"], owner=None)
    assert row is not None
    events = list((row.result or {}).get("runtime_events") or [])
    events[0] = {**events[0], "algorithm": "DES"}  # a quiet rewrite of stored evidence
    row.result = {**(row.result or {}), "runtime_events": events}
    session.commit()

    verify = http.get("/api/v1/runtime/crypto-events/verify").json()
    assert verify["verified"] is False
    assert [item["event_id"] for item in verify["tampered_records"]] == [events[0]["event_id"]]
    assert verify["tampered_records"][0]["problem"] == "RECORD_HASH_MISMATCH"
    assert verify["reason"] == "chain does not verify: RECORD_HASH_MISMATCH"


def test_runtime_chain_never_mixes_with_the_network_chain(client, monkeypatch):
    http, session = client
    _ingest(http)

    from api.security.network_evidence_chain import append as append_network

    append_network(
        session,
        [{"evidence_id": "ev-network-1", "evidence_type": "NETWORK_ACTIVE_OBSERVED", "protocol": "TLS"}],
        run_id="run-network",
        tenant_id=None,
    )
    session.commit()

    runtime = http.get("/api/v1/runtime/crypto-events/verify").json()
    assert runtime["verified"] is True
    assert runtime["entries"] == 1  # the network record did not enter the runtime chain

    from api.security.network_evidence_chain import read_chain as read_network
    from api.security.runtime_evidence_chain import read_chain as read_runtime

    assert read_runtime(session, tenant_id=None)["head"] != read_network(session, tenant_id=None)["head"]


# --------------------------------------------------------------------------- #
# Drift and runtime <-> network correlation (spec 92 §12-§13)
# --------------------------------------------------------------------------- #


def test_drift_reports_new_removed_and_changed_without_claiming_stop(client):
    http, _session = client
    previous = [
        {"event_id": "a", "algorithm": "AES", "key_size": 256, "mode": "GCM", "operation": "ENCRYPT",
         "identity": {"application": "payments-api", "process": "java", "host": "h1"}, "attribution_level": 1},
        {"event_id": "b", "algorithm": "RSA", "key_size": 2048, "operation": "SIGN",
         "identity": {"application": "payments-api", "process": "java", "host": "h1"}, "attribution_level": 1},
    ]
    current = [
        {"event_id": "a", "algorithm": "AES", "key_size": 256, "mode": "GCM", "operation": "ENCRYPT",
         "identity": {"application": "payments-api", "process": "java", "host": "h1"}, "attribution_level": 1},
        {"event_id": "c", "algorithm": "ECDSA", "key_size": 256, "operation": "SIGN",
         "identity": {"application": "payments-api", "process": "java", "host": "h1"}, "attribution_level": 1},
    ]
    report = http.post(
        "/api/v1/runtime/crypto-drift",
        json={"previous_events": previous, "current_events": current},
    ).json()

    assert report["verdict"] == "DRIFT"
    assert report["summary"]["new"] == 1
    assert report["summary"]["removed"] == 1
    assert report["model"] == "cryptoscan.runtime-crypto-drift/1"
    removed = report["removed"][0]
    assert "not observed in the newer window" in str(removed)


def test_drift_needs_two_windows_and_says_so(client):
    http, _session = client
    response = http.post("/api/v1/runtime/crypto-drift", json={})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "runtime_drift_needs_two_windows"


def test_runtime_network_correlation_compares_only_transport_fields(client):
    http, _session = client
    runtime_events = [
        {
            "event_id": "rt-1",
            "algorithm": "AES",
            "key_size": 256,
            "operation": "ENCRYPT",
            "transport": {"tls_version": "TLSv1.2", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
            "identity": {"host": "payments-prod-01", "application": "payments-api"},
        }
    ]
    network_records = [
        {
            "evidence_id": "ev-1",
            "evidence_type": "NETWORK_ACTIVE_OBSERVED",
            "protocol": "TLS",
            "target": {"endpoint": "10.20.10.15:443", "host": "payments-prod-01", "port": 443},
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "decomposition": {"key_exchange": "ECDHE"},
        }
    ]
    report = http.post(
        "/api/v1/runtime/network-correlation",
        json={"runtime_events": runtime_events, "network_evidence": network_records},
    ).json()

    assert report["model"] == "cryptoscan.runtime-network-correlation/1"
    assert report["sources"]["runtime"] == "request"
    subject = report["subjects"][0]
    comparisons = subject["comparisons"]
    results = {item["field"]: item["result"] for item in comparisons if "field" in item}
    assert results["tls_version"] == "MATCH"
    assert results["cipher_suite"] == "MATCH"
    # application algorithm is never compared against transport crypto
    assert all(item.get("field") in {"tls_version", "cipher_suite"} for item in comparisons)
    assert report["refused_comparisons"]
