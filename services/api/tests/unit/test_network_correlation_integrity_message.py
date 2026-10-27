"""Correlation, hop attribution, message-layer evidence, IPsec ESP and hashing.

Spec 67 §13 (IPsec), §15–§17 (LB/gateway/mesh), §19 (Kafka/MQ), §24 (evidence
integrity) and §26–§27 (cross-layer correlation).

No live device is touched: IKE responders and scanners are stubs, and every
"observed" record below is a synthetic packet or a fixture — nothing here
qualifies a real bank endpoint.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.main import create_app
from db.connection.session import Base
from network_scanner.inventory.crypto_attribution import attribute_path, infer_role, normalize_hops
from network_scanner.inventory.message_layer import (
    MessageLayerRejected,
    build_message_evidence,
    summarize,
    to_cbom_assets,
)
from network_scanner.inventory.network_evidence import (
    build_ipsec_evidence,
    to_cbom_assets as to_network_cbom,
)
from network_scanner.probing.ipsec_probe import (
    classify_esp,
    probe_ike,
    summarize_proposals,
)
from api.security.network_correlation import correlate, network_facts_from_evidence
from api.security.network_evidence_chain import (
    GENESIS,
    append,
    attach_integrity,
    ensure_evidence_ids,
    read_chain,
    record_hash,
    verify,
)


# --------------------------------------------------------------------------- #
# §13 — IPsec happy path, refusals and ESP honesty
# --------------------------------------------------------------------------- #

_ENCR, _PRF, _INTEG, _DH, _ESN = 1, 2, 3, 4, 5


def _transform(ttype: int, tid: int, key_length: int = 0) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_length) if key_length else b""
    body = bytes([ttype, 0]) + struct.pack("!H", tid) + attrs
    return struct.pack("!H", len(body) + 2) + body


def _proposal(protocol_id: int, transforms: list[bytes]) -> bytes:
    """One proposal substructure (no SA-payload header)."""
    body = bytes([1, protocol_id, 0, len(transforms)]) + b"".join(transforms)
    # the proposal length field includes itself (RFC 7296 §3.3)
    return struct.pack("!H", len(body) + 2) + body


def _sa_payload(*proposals: bytes) -> bytes:
    """SA payload body: four reserved bytes then the proposals (RFC 7296)."""
    return b"\x00\x00\x00\x00" + b"".join(proposals)


def _notify_body(notify_type: int, data: bytes = b"") -> bytes:
    """NOTIFY body: protocol_id, SPI size, notify type, (SPI), data — no reserved field."""
    return bytes([0, 0]) + struct.pack("!H", notify_type) + data


def _ike_response(*payloads: tuple[int, bytes], exchange: int = 34) -> bytes:
    """Assemble an IKEv2 message from ``(payload_type, body)`` pairs.

    Each payload's first byte carries the *next* payload's type, exactly as the
    parser walks it.
    """
    chain = b""
    next_type = 0
    for payload_type, body in reversed(payloads):
        chain = bytes([next_type, 0]) + struct.pack("!H", len(body) + 4) + body + chain
        next_type = payload_type
    header = struct.pack(
        "!8s8sBBBBII", b"\x11" * 8, b"\x22" * 8, next_type, 0x20, exchange, 0x20, 0, len(chain) + 28
    )
    return header + chain


_SA = 33
_NOTIFY = 41


def _strong_ike_payload() -> bytes:
    return _sa_payload(_proposal(1, [_transform(_ENCR, 5, 16), _transform(_PRF, 5), _transform(_DH, 14)]))


class _IkeResponder:
    """Minimal IKEv2 responder: replies to one SA_INIT with a fixed packet."""

    def __init__(self, payload: bytes):
        self.payload = payload
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        self.sock.settimeout(5.0)
        while not self._stop.is_set():
            try:
                _data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.sock.sendto(self.payload, addr)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def test_ikev2_happy_path_parses_the_ike_suite_end_to_end():
    responder = _IkeResponder(_ike_response((_SA, _strong_ike_payload())))
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
    finally:
        responder.close()
    assert probe["status"] == "OK"
    assert probe["header"]["version"] == "IKEv2"
    assert probe["ike"]["encryption"] == "AES-CBC-256"
    assert probe["ike"]["prf"] == "HMAC-SHA2-256"
    assert probe["ike"]["dh_group"] == "MODP-2048"
    # ESP is negotiated in IKE_AUTH, which we never perform
    assert probe["esp"]["status"] == "NOT_OBSERVED"
    assert probe["esp"]["encryption"] is None


def test_esp_suite_is_reported_when_the_responder_volunteers_it():
    payload = _sa_payload(
        _proposal(1, [_transform(_ENCR, 5, 16), _transform(_PRF, 5), _transform(_DH, 14)]),
        _proposal(3, [_transform(_ENCR, 2), _transform(_INTEG, 2), _transform(_DH, 2)]),
    )
    responder = _IkeResponder(_ike_response((_SA, payload)))
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
    finally:
        responder.close()
    assert probe["esp"]["status"] == "DECLARED_IN_SA_INIT"
    assert probe["esp"]["encryption"] == "3DES"
    assert probe["esp"]["pfs"] == "OFFERED"
    assert "WEAK_ESP_ENCRYPTION:3DES" in probe["issues"]
    assert "WEAK_ESP_INTEGRITY:HMAC-SHA1" in probe["issues"]
    assert "WEAK_ESP_DH_GROUP:MODP-1024" in probe["issues"]


def test_esp_without_dh_offers_no_pfs():
    proposals = [{"protocol": "ESP", "transforms": [{"type": _ENCR, "id": 5, "name": "AES-CBC-256"}]}]
    assert "ESP_NO_PFS" in classify_esp(proposals)


def test_no_proposal_chosen_is_a_refusal_not_an_absence_of_crypto():
    responder = _IkeResponder(_ike_response((_NOTIFY, _notify_body(14))))
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
    finally:
        responder.close()
    assert probe["status"] == "NO_PROPOSAL_CHOSEN"
    assert "IKE_PROPOSAL_REFUSED" in probe["issues"]
    assert probe["notifies"][0]["name"] == "NO_PROPOSAL_CHOSEN"


def test_invalid_ke_payload_reports_the_requested_group():
    responder = _IkeResponder(_ike_response((_NOTIFY, _notify_body(17, struct.pack("!H", 19)))))
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
    finally:
        responder.close()
    assert probe["status"] == "INVALID_KE"
    assert probe["notifies"][0]["suggested_dh_group"] == "ECP-256"


def test_summarize_proposals_marks_gcm_integrity_as_implied_aead():
    proposals = [{"protocol": "IKE", "transforms": [{"type": _ENCR, "id": 14, "name": "AES-GCM-16-256"},
                                                   {"type": _PRF, "id": 5, "name": "HMAC-SHA2-256"},
                                                   {"type": _DH, "id": 19, "name": "ECP-256"}]}]
    summary = summarize_proposals(proposals)
    assert summary["ike"]["integrity"] == "AEAD"


def test_ipsec_evidence_keeps_esp_unobserved_and_never_claims_authentication():
    probe = {
        "endpoint": "10.20.10.9:500",
        "status": "OK",
        "ike": {"encryption": "AES-GCM-16-256", "prf": "HMAC-SHA2-256", "integrity": "AEAD", "dh_group": "ECP-256", "esn": True},
        "esp": {"status": "NOT_OBSERVED", "pfs": "UNKNOWN"},
        "issues": [],
        "notifies": [],
        "header": {"version": "IKEv2"},
        "ke": {"dh_group": "ECP-256", "public_key_bytes": 64},
    }
    record = build_ipsec_evidence(probe)
    assert record["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert record["protocol"] == "IPsec"
    assert record["ike"]["authentication"] == "UNKNOWN"
    assert record["esp"]["status"] == "NOT_OBSERVED"
    assert record["mutual_tls"] == "NOT_APPLICABLE"
    assert any("IKE_AUTH was not attempted" in line for line in record["limitations"])
    assert record["decomposition"]["key_exchange"] == "ECP-256"

    cbom = to_network_cbom([record])
    assert cbom["roles"] == {"ike-key-exchange": 1, "ike-encryption": 1, "ike-integrity": 1}
    assert "esp-encryption" not in cbom["roles"]  # never invented


def test_refused_ike_is_unknown_not_weak():
    probe = {"endpoint": "10.20.10.9:500", "status": "NO_PROPOSAL_CHOSEN", "ike": None, "issues": ["IKE_PROPOSAL_REFUSED"]}
    record = build_ipsec_evidence(probe)
    assert record["evidence_type"] == "UNKNOWN"
    assert record["evidence_id"].startswith("ev-")
    assert any("not proof that the gateway has no crypto" in line for line in record["limitations"])


def test_ipsec_api_persists_evidence_and_chains_it(client, monkeypatch):
    http, _session = client
    import network_scanner.probing.ipsec_probe as probe_module

    assert save_scope(http, protocols=["IPsec"], allowed_operations=["IKE_PROBE"]).status_code == 200
    monkeypatch.setattr(
        probe_module,
        "probe_ike",
        lambda host, **kwargs: {
            "endpoint": f"{host}:500",
            "status": "OK",
            "port": 500,
            "transport": "UDP",
            "header": {"version": "IKEv2"},
            "ike": {"encryption": "AES-CBC-256", "prf": "HMAC-SHA2-256", "integrity": None, "dh_group": "MODP-2048", "esn": True},
            "esp": {"status": "NOT_OBSERVED", "pfs": "UNKNOWN"},
            "ke": {"dh_group": "MODP-2048"},
            "notifies": [],
            "proposals": [{"protocol": "IKE", "proposal": 1, "transforms": []}],
            "issues": [],
        },
    )
    response = http.post("/api/v1/network/ipsec-observe", json={"endpoints": ["10.20.10.15:500"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["observed"] == 1
    assert body["evidence"][0]["protocol"] == "IPsec"
    assert body["evidence"][0]["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert body["evidence_chain"]["appended"] == 1
    assert body["esp_observed"] is False

    listing = http.get("/api/v1/network/crypto-evidence").json()
    assert "ipsec-observe" in [run["target_kind"] for run in listing["runs"]]
    cbom = http.get("/api/v1/network/crypto-cbom").json()
    assert "ike-encryption" in cbom["roles"]


# --------------------------------------------------------------------------- #
# §19 — Kafka / MQ: transport crypto vs message crypto
# --------------------------------------------------------------------------- #


def test_sasl_is_authentication_and_never_a_bulk_cipher():
    record = build_message_evidence(
        {
            "endpoint": "kafka-01.bank:9093",
            "protocol": "KAFKA",
            "listener_security": "SASL_SSL",
            "sasl_mechanism": "SCRAM-SHA-512",
            "client_authentication": "mTLS",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        }
    )
    assert record["sasl"]["encrypts_messages"] is False
    assert record["sasl"]["authenticates"] == "CLIENT_TO_BROKER"
    cbom = to_cbom_assets([record])
    roles = {asset["role"] for asset in cbom["assets"]}
    assert "message-client-authentication" in roles
    assert "message-transport-encryption" in roles
    assert cbom["layers"]["MESSAGE_TRANSPORT"] == 2


def test_payload_encryption_is_declared_never_observed():
    record = build_message_evidence(
        {
            "endpoint": "kafka-02.bank:9093",
            "listener_security": "SSL",
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "payload_encryption": "AES-256-GCM",
            "payload_encryption_source": "BANK_DECLARATION",
        }
    )
    assert record["payload_encryption"]["status"] == "DECLARED"
    assert record["payload_encryption"]["observed"] is False
    assert "MESSAGE_PAYLOAD_ENCRYPTION_UNVERIFIED" in record["policy_issues"]
    payload_assets = [a for a in to_cbom_assets([record])["assets"] if a["layer"] == "MESSAGE_PAYLOAD"]
    assert [asset["observation_mode"] for asset in payload_assets] == ["DECLARED"]


def test_plaintext_listener_is_flagged_and_still_configured_evidence():
    record = build_message_evidence(
        {"endpoint": "kafka-03.bank:9092", "listener_security": "SASL_PLAINTEXT", "sasl_mechanism": "PLAIN"}
    )
    assert record["evidence_type"] == "NETWORK_CONFIGURED"
    assert "MESSAGE_SASL_OVER_PLAINTEXT" in record["policy_issues"]
    assert "MESSAGE_SASL_PLAIN_WITHOUT_TLS" in record["policy_issues"]


def test_observed_listener_requires_negotiated_parameters():
    with pytest.raises(MessageLayerRejected):
        build_message_evidence({"endpoint": "k:9093", "observed": True, "listener_security": "SSL"})


def test_sasl_mechanism_on_a_plain_listener_is_refused():
    with pytest.raises(MessageLayerRejected):
        build_message_evidence({"endpoint": "k:9093", "listener_security": "SSL", "sasl_mechanism": "SCRAM-SHA-256"})


def test_credentials_and_payload_fields_are_refused():
    for bad in ({"sasl_password": "x"}, {"payload": "..."}, {"jaas_config": "..."}):
        with pytest.raises(MessageLayerRejected):
            build_message_evidence({"endpoint": "k:9093", "listener_security": "SSL", **bad})


def test_message_summary_separates_transport_and_payload():
    records = [
        build_message_evidence({"endpoint": "k1:9093", "listener_security": "SASL_SSL", "tls_version": "TLSv1.3"}),
        build_message_evidence({"endpoint": "k2:9092", "listener_security": "PLAINTEXT"}),
    ]
    summary = summarize(records)
    assert summary["transport_encrypted"] == 1
    assert summary["transport_plaintext"] == 1
    assert summary["payload_encryption_states"] == {"UNKNOWN": 2}
    assert "not message encryption" in summary["boundary"]


def test_message_layer_api_ingest_and_readback(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/message-layer-observe",
        json={
            "brokers": [
                {
                    "endpoint": "kafka-01.bank:9093",
                    "protocol": "KAFKA",
                    "listener_security": "SASL_SSL",
                    "sasl_mechanism": "SCRAM-SHA-512",
                    "client_authentication": "mTLS",
                    "tls_version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "payload_encryption": "AES-256-GCM",
                    "payload_encryption_source": "BANK_DECLARATION",
                }
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["stored"] == 1
    assert body["active_packets"] == 0
    assert body["cbom"]["layers"]["MESSAGE_PAYLOAD"] == 1
    assert body["evidence_chain"]["appended"] == 1

    listing = http.get("/api/v1/network/message-layer-evidence").json()
    assert listing["count"] == 1
    assert listing["summary"]["transport_encrypted"] == 1
    # message-layer evidence must not leak into the transport-only projection
    transport_cbom = http.get("/api/v1/network/crypto-cbom").json()
    assert transport_cbom["asset_count"] == 0


def test_message_layer_api_refuses_credentials(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/message-layer-observe",
        json={"brokers": [{"endpoint": "k:9093", "listener_security": "SSL", "sasl_password": "hunter2"}]},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "message_layer_rejected"


# --------------------------------------------------------------------------- #
# §15–§17 — LB / gateway / mesh attribution
# --------------------------------------------------------------------------- #


def _observed(endpoint: str, fingerprint: str, *, tls: str = "TLSv1.3") -> dict:
    return {
        "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "evidence_id": f"ev-{endpoint}",
        "target": {"endpoint": endpoint, "host": endpoint.rsplit(":", 1)[0]},
        "tls_version": tls,
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "decomposition": {"key_exchange": "X25519"},
        "mutual_tls": "NOT_REQUIRED",
        "certificate": {"fingerprint_sha256": fingerprint},
        "certificate_chain": {},
        "confidence": "HIGH",
        "observed_at": "2026-10-27T00:00:00+00:00",
    }


_CHAIN_HOPS = [
    {"from": "internet-client", "to": "lb.bank:443"},
    {"from": "lb.bank:443", "to": "payments.svc:8443"},
]


def test_termination_is_proven_only_by_different_observed_certificates():
    path = attribute_path(
        [_observed("lb.bank:443", "aa"), _observed("payments.svc:8443", "bb")],
        _CHAIN_HOPS,
    )
    point = path["attribution"]["termination_points"][0]
    assert point["role"] == "LOAD_BALANCER"
    assert point["verdict"] == "TERMINATES_AND_REORIGINATES"
    assert point["certificate_comparison"] == "DIFFERENT_FINGERPRINT"


def test_same_certificate_on_both_legs_is_pass_through():
    path = attribute_path(
        [_observed("lb.bank:443", "aa"), _observed("payments.svc:8443", "aa")],
        _CHAIN_HOPS,
    )
    assert path["attribution"]["termination_points"][0]["verdict"] == "PASS_THROUGH"


def test_missing_internal_observation_leaves_termination_undetermined():
    path = attribute_path([_observed("lb.bank:443", "aa")], _CHAIN_HOPS)
    point = path["attribution"]["termination_points"][0]
    assert point["verdict"] == "UNDETERMINED"
    assert "no internal leg evidence" in point["reason"]


def test_sidecar_crypto_is_labelled_as_not_the_application_crypto():
    hops = [
        {"from": "internet", "to": "api-gateway:443"},
        {"from": "api-gateway:443", "to": "payments.app:8443"},
        {"from": "payments.app:8443", "to": "istio-sidecar:15006", "to_role": "SERVICE_MESH_SIDECAR"},
    ]
    path = attribute_path([_observed("api-gateway:443", "aa")], hops)
    sidecar = path["attribution"]["sidecars"][0]
    assert sidecar["role"] == "SERVICE_MESH_SIDECAR"
    assert "out of network reach" in sidecar["note"]
    assert path["attribution"]["segment_kinds"]["MESH_SIDECAR_PATH"] == 1


def test_inferred_roles_are_labelled_as_inferred():
    normalized = normalize_hops([{"from": "lb.bank:443", "to": "payments.svc:8443"}])
    assert normalized[0]["from_role"] == "LOAD_BALANCER"
    assert normalized[0]["from_role_source"] == "INFERRED_FROM_LABEL"
    declared = normalize_hops([{"from": "edge:443", "to": "svc:8443", "from_role": "WAF"}])
    assert declared[0]["from_role_source"] == "DECLARED"
    assert infer_role("mystery-host") == ("UNKNOWN", "UNDECLARED")


def test_crypto_path_api_keeps_unknown_hops_and_adds_attribution(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/crypto-path",
        json={"hops": [{"from": "lb.bank:443", "to": "payments.svc:8443", "from_role": "LOAD_BALANCER"}]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["edges"][0]["evidence_type"] == "UNKNOWN"
    assert body["complete"] is False
    assert body["attribution"]["roles"]["lb.bank:443"] == "LOAD_BALANCER"
    assert body["attribution"]["segments"][0]["crypto"]["evidence_type"] == "UNKNOWN"
    assert body["attribution"]["termination_points"][0]["verdict"] == "UNDETERMINED"


# --------------------------------------------------------------------------- #
# §26–§27 — cross-layer correlation
# --------------------------------------------------------------------------- #

_SERVICES = [{"name": "payments-api", "hosts": ["payments.bank"], "endpoints": ["payments.bank:443"]}]


def test_matching_fingerprint_across_layers_is_a_match():
    report = correlate(
        services=_SERVICES,
        static=[{"service": "payments-api", "kind": "certificate_fingerprint", "role": "tls-server-certificate", "value": "sha256:AA:BB"}],
        network=[{"endpoint": "payments.bank:443", "kind": "certificate_fingerprint", "role": "tls-server-certificate", "value": "aabb"}],
    )
    comparison = report["services"][0]["comparisons"][0]
    assert comparison["result"] == "MATCH"
    assert report["summary"]["mismatches"] == 0


def test_declared_tls_version_mismatch_is_a_review_item_not_a_verdict():
    report = correlate(
        services=_SERVICES,
        static=[{"service": "payments-api", "kind": "tls_version", "role": "network-transport", "value": "TLS1.2"}],
        network=[{"endpoint": "payments.bank:443", "kind": "tls_version", "role": "network-transport", "value": "TLSv1.3"}],
    )
    comparison = report["services"][0]["comparisons"][0]
    assert comparison["result"] == "MISMATCH"
    hint = report["services"][0]["risk_hints"][0]
    assert hint["requires_analyst_confirmation"] is True
    assert hint["automatic_verdict"] is False


def test_transport_and_application_algorithms_are_not_comparable():
    report = correlate(
        services=_SERVICES,
        static=[{"service": "payments-api", "kind": "cipher_suite", "role": "application", "value": "AES-256-GCM"}],
        network=[{"endpoint": "payments.bank:443", "kind": "cipher_suite", "role": "network-transport", "value": "TLS_AES_256_GCM_SHA384"}],
    )
    comparison = report["services"][0]["comparisons"][0]
    assert comparison["result"] == "NOT_COMPARABLE"
    assert "different layers" in comparison["reason"]
    assert report["services"][0]["risk_hints"] == []


def test_missing_network_layer_is_not_observed_not_clean():
    report = correlate(
        services=_SERVICES,
        static=[{"service": "payments-api", "kind": "tls_version", "role": "network-transport", "value": "TLS1.3"}],
    )
    service = report["services"][0]
    assert service["layers_missing"] == ["RUNTIME", "NETWORK"]
    assert service["coverage"]["complete"] is False
    assert report["summary"]["services_without_network_evidence"] == 1


def test_unmatched_facts_are_reported_not_guessed():
    report = correlate(
        services=_SERVICES,
        static=[{"service": "unknown-service", "kind": "tls_version", "role": "network-transport", "value": "TLS1.2"}],
    )
    assert report["unattributed_facts"][0]["service"] == "unknown-service"
    assert report["summary"]["unattributed_facts"] == 1


def test_network_facts_are_derived_from_observed_evidence_only():
    facts = network_facts_from_evidence(
        [
            _observed("payments.bank:443", "aa"),
            {"evidence_type": "UNKNOWN", "target": {"endpoint": "other:443"}, "tls_version": None, "certificate": {}},
        ]
    )
    assert {fact["kind"] for fact in facts} == {"certificate_fingerprint", "tls_version", "cipher_suite", "mutual_tls"}
    assert all(fact["endpoint"] == "payments.bank:443" for fact in facts)


def test_correlate_api_uses_stored_evidence(client, monkeypatch):
    http, _session = client
    from network_scanner.core.scanner import NetworkTlsScanner

    assert save_scope(http).status_code == 200
    monkeypatch.setattr(
        NetworkTlsScanner,
        "scan_hosts",
        lambda self, hosts, **kwargs: {
            "scan_id": "scan-1",
            "run_id": "run-1",
            "findings": [
                {
                    "finding_id": "f-1",
                    "endpoint": "10.20.10.15:443",
                    "ip_address": "10.20.10.15",
                    "status": "OK",
                    "crypto": {
                        "tls_version": "TLSv1.2",
                        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "key_exchange_algorithm": "ECDHE",
                        "authentication_algorithm": "RSA",
                        "encryption_algorithm": "AES-256",
                        "encryption_mode": "GCM",
                    },
                    "certificates": [{"fingerprint_sha256": "sha256:zz", "public_key_algorithm": "RSA"}],
                    "chain_validation": {},
                    "policy_issues": [],
                    "metadata": {"confidence": "HIGH"},
                }
            ],
            "certificates": [],
            "probe_telemetry": {"status": "OK", "probed": 1, "ok": 1},
        },
    )
    assert http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]}).status_code == 200

    response = http.post(
        "/api/v1/network/crypto-correlate",
        json={
            "services": [{"name": "payments-api", "hosts": ["10.20.10.15"], "endpoints": ["10.20.10.15:443"]}],
            "static": [
                {
                    "service": "payments-api",
                    "kind": "tls_version",
                    "role": "network-transport",
                    "value": "TLS1.3",
                    "source": "nginx.conf",
                }
            ],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sources"]["network_facts_from_stored_evidence"] >= 1
    service = body["services"][0]
    assert service["layers"]["NETWORK"]["present"] is True
    assert [c["result"] for c in service["comparisons"]] == ["MISMATCH"]
    assert body["summary"]["mismatches"] == 1


# --------------------------------------------------------------------------- #
# §24 — evidence hash chain
# --------------------------------------------------------------------------- #


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        yield db
    finally:
        db.close()


def _record(endpoint: str, tls: str = "TLSv1.3") -> dict:
    return _observed(endpoint, "aa", tls=tls)


def test_chain_appends_and_verifies(session):
    records = ensure_evidence_ids([_record("a:443"), _record("b:443")])
    receipt = append(session, records, run_id="run-1", tenant_id=None)
    assert receipt["appended"] == 2
    assert receipt["seq"] == 2
    assert receipt["distributed"] is False
    assert receipt["anchoring"] == "local-database-only"

    chain = read_chain(session, tenant_id=None)
    assert chain["entries"][0]["prev_hash"] == GENESIS
    assert chain["entries"][1]["prev_hash"] == chain["entries"][0]["record_hash"]
    assert chain["head"] == record_hash(records[1])

    report = verify(chain, records=records)
    assert report["verified"] is True
    assert report["checked_records"] == 2


def test_appending_the_same_run_twice_is_idempotent(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)
    assert len(chain["entries"]) == 1
    assert verify(chain, records=records)["verified"] is True


def test_modified_record_breaks_verification(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)

    tampered = {**records[0], "tls_version": "TLSv1.0"}
    report = verify(chain, records=[tampered])
    assert report["verified"] is False
    assert report["tampered_records"][0]["problem"] == "RECORD_HASH_MISMATCH"
    assert "RECORD_HASH_MISMATCH" in report["reason"]


def test_rewritten_link_is_detected(session):
    records = ensure_evidence_ids([_record("a:443"), _record("b:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)
    chain["entries"][1]["prev_hash"] = "f" * 64
    report = verify(chain, records=records)
    assert report["verified"] is False
    assert any(item["problem"] == "BROKEN_LINK" for item in report["problems"])


def test_swapped_head_is_detected(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)
    chain["head"] = "0" * 64
    report = verify(chain, records=records)
    assert report["verified"] is False
    assert any(item["problem"] == "HEAD_MISMATCH" for item in report["problems"])


def test_missing_and_unloaded_records_are_reported_as_gaps(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)

    unloaded = verify(chain)
    assert unloaded["verified"] is True  # nothing to contradict — but the gap is disclosed
    assert unloaded["unverifiable_entries"][0]["reason"] == "record not loaded in this window"

    missing = verify(chain, records_by_run={"run-1": []})
    assert missing["verified"] is False
    assert missing["missing_records"][0]["run_id"] == "run-1"


def test_unchained_records_are_listed(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)
    extra = ensure_evidence_ids([_record("c:443")])
    report = verify(chain, records=[*records, *extra])
    assert report["unchained_records"] == [extra[0]["evidence_id"]]


def test_integrity_is_attached_without_changing_the_hash(session):
    records = ensure_evidence_ids([_record("a:443")])
    append(session, records, run_id="run-1", tenant_id=None)
    chain = read_chain(session, tenant_id=None)
    [chained] = attach_integrity(records, chain)
    assert chained["integrity"]["chained"] is True
    assert chained["integrity"]["seq"] == 1
    # read-time integrity metadata must not invalidate the record hash
    assert record_hash(chained) == chained["integrity"]["record_hash"]


def test_integrity_endpoint_verifies_a_real_ingest(client):
    http, _session = client
    ingest = http.post(
        "/api/v1/network/crypto-passive",
        json={
            "observations": [
                {"dst_ip": "10.20.10.15", "dst_port": 443, "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                {"dst_ip": "10.20.10.16", "dst_port": 443, "tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    assert ingest.json()["evidence_chain"]["appended"] == 2

    report = http.get("/api/v1/network/crypto-evidence/integrity").json()
    assert report["verified"] is True
    assert report["entries"] == 2
    assert report["checked_records"] == 2
    assert report["chain"]["head_hash"] == report["head_hash"]

    chained = http.get("/api/v1/network/crypto-evidence/chained").json()
    assert chained["count"] == 2
    assert all(item["integrity"]["chained"] for item in chained["evidence"])
    assert chained["integrity"]["verified"] is True


# --------------------------------------------------------------------------- #
# fixtures
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
    app.dependency_overrides[network_router.require_auditor] = lambda: "tester"
    # no live preflight/metering in a unit test; the ledger shape is preserved
    monkeypatch.setattr(
        network_router,
        "admit_network",
        lambda targets, **kwargs: {
            "schema": "cryptoscan.network-admission/1",
            "decision": "PERMITTED",
            "targets": list(targets),
            "checked_targets": len(list(targets)),
        },
    )
    monkeypatch.setattr(network_router, "meter_network", lambda *args, **kwargs: None)
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def save_scope(http, **overrides):
    from datetime import datetime, timedelta, timezone

    body = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443", "10.20.10.15:500"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 20, "max_bytes": 1000000},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "inventory_id": "default",
    }
    body.update(overrides)
    return http.put("/api/v1/network/crypto-scope", json=body)
