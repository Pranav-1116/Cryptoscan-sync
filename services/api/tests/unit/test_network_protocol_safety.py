"""Port ≠ protocol, SSH offer evidence, database transport crypto, STOP switch.

Spec 67 §5 (service/protocol detection), §12 (SSH), §18 (database transport vs
TDE), §30 (emergency stop) and the §24 evidence contract they all feed.

No live device is contacted: probes are injected, and the API tests stub the
detector and the scanners.
"""

from __future__ import annotations

import socket
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.main import create_app
from api.security.network_safety import (
    NetworkStopped,
    engage,
    release,
    require_running,
    state as safety_state,
)
from db.connection.session import Base
from network_scanner.discovery.protocol_detector import (
    detect_protocol,
    detection_summary,
)
from network_scanner.inventory.protocol_evidence import (
    DATABASE_OUT_OF_REACH,
    build_database_evidence,
    build_protocol_evidence,
    build_ssh_evidence,
    to_protocol_cbom_assets,
)


# --------------------------------------------------------------------------- #
# §5 — protocol detection is a response, not a port number
# --------------------------------------------------------------------------- #


def _detect(port: int, *, tls=None, banner=None, postgres=None, mysql=None):
    return detect_protocol(
        "10.20.10.15",
        port,
        timeout=0.1,
        tls_probe=lambda *_: tls,
        banner_probe=lambda *_: ({"banner": banner} if banner else None),
        postgres_probe=lambda *_: postgres,
        mysql_probe=lambda *_: mysql,
    )


def test_tls_on_an_unusual_port_is_detected_and_flagged_as_a_mismatch():
    detection = _detect(
        9999,
        tls={"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "alpn": "h2", "sni_sent": True, "has_certificate": True},
    )
    assert detection["detected"] == "TLS"
    assert detection["detection_method"] == "TLS_HANDSHAKE"
    assert detection["confidence"] == "HIGH"
    assert detection["port_matches_protocol"] is False  # 9999 is not HTTPS
    assert detection["tls"]["tls_version"] == "TLSv1.3"


def test_tls_on_443_matches_the_port_guess():
    detection = _detect(443, tls={"tls_version": "TLSv1.2", "cipher_suite": "X", "alpn": None, "sni_sent": True, "has_certificate": True})
    assert detection["port_matches_protocol"] is True


def test_ssh_banner_is_identified():
    detection = _detect(22, banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    assert detection["detected"] == "SSH"
    assert detection["detection_method"] == "BANNER"
    assert detection["port_matches_protocol"] is True
    assert "banner" in detection["details"]


def test_ssh_on_a_web_port_is_a_mismatch_not_an_assumption():
    detection = _detect(8443, banner=b"SSH-2.0-OpenSSH_8.9\r\n")
    assert detection["detected"] == "SSH"
    assert detection["port_matches_protocol"] is False  # 8443 is registered as HTTPS


def test_smtp_and_ftp_share_a_greeting_and_are_disambiguated_by_the_banner():
    smtp = _detect(25, banner=b"220 mail.bank ESMTP Postfix\r\n")
    ftp = _detect(21, banner=b"220 (vsFTPd 3.0.5)\r\n")
    assert smtp["detected"] == "SMTP"
    assert ftp["detected"] == "FTP"


def test_http_is_identified_from_the_response_to_a_request():
    detection = _detect(8080, banner=b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n")
    assert detection["detected"] == "HTTP"
    assert detection["tls_capable"] is False


def test_postgresql_ssl_request_answer_is_the_servers_own_statement():
    supported = _detect(5432, postgres={"ssl_supported": True, "answer": "S"})
    refused = _detect(5432, postgres={"ssl_supported": False, "answer": "N"})
    assert supported["detected"] == "POSTGRESQL"
    assert supported["detection_method"] == "SSL_REQUEST"
    assert supported["tls_capable"] is True
    assert refused["details"]["postgres"]["ssl_supported"] is False


def test_mysql_handshake_packet_is_identified():
    detection = _detect(
        3306,
        banner=b"\x4a\x00\x00\x00\x0a" + b"8.0.35\x00" + b"\x01\x00\x00\x00" + b"\x21\x02\x00",
    )
    assert detection["detected"] == "MYSQL"
    assert detection["detection_method"] == "HANDSHAKE_PACKET"


def test_unidentified_service_is_unknown_not_clean():
    detection = _detect(5001)
    assert detection["detected"] == "UNKNOWN"
    assert detection["detection_method"] == "NO_RESPONSE"
    assert detection["attempts"][0]["probe"] == "TLS_CLIENT_HELLO"
    assert any("UNKNOWN is the result" in line for line in detection["limitations"])


def test_detection_summary_keeps_port_protocol_mismatches_visible():
    summary = detection_summary(
        [
            _detect(9999, tls={"tls_version": "TLSv1.3", "cipher_suite": "X", "alpn": None, "sni_sent": True, "has_certificate": True}),
            _detect(2222, banner=b"SSH-2.0-x\r\n"),
            _detect(5001),
        ]
    )
    assert summary["by_protocol"] == {"TLS": 1, "SSH": 1, "UNKNOWN": 1}
    assert summary["unknown"] == 1
    # only the TLS-on-9999 endpoint is a mismatch; SSH on 2222 is registered
    assert {item["detected"] for item in summary["port_protocol_mismatches"]} == {"TLS"}


def test_detection_against_a_local_tls_listener(tmp_path):
    """One real socket: the detector must identify a genuine TLS handshake."""
    pytest.importorskip("cryptography")
    from network_scanner.probing.mock_bank_tls import MockBankTLS

    with MockBankTLS() as server:
        detection = detect_protocol("127.0.0.1", server.port, timeout=3.0)
    assert detection["detected"] == "TLS"
    assert detection["tls"]["tls_version"] in {"TLSv1.2", "TLSv1.3"}
    assert detection["tls"]["has_certificate"] is True


def test_detection_against_a_local_ssh_banner_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(0.2)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        # the detector tries TLS first, so the listener must greet every attempt
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        detection = detect_protocol("127.0.0.1", port, timeout=1.5)
    finally:
        stop.set()
        server.close()
    assert detection["detected"] == "SSH"
    assert detection["details"]["banner"].startswith("SSH-2.0")


# --------------------------------------------------------------------------- #
# §12 — SSH: an offer is not a negotiation
# --------------------------------------------------------------------------- #

_SSH_KEX = {
    "status": "OK",
    "server_banner": "SSH-2.0-OpenSSH_8.9",
    "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha1"],
    "host_key_algorithms": ["ssh-ed25519", "ssh-rsa"],
    "ciphers": ["chacha20-poly1305@openssh.com", "aes128-cbc"],
    "macs": ["hmac-sha2-256", "hmac-sha1"],
    "compression": ["none"],
    "weak": {"weak_ciphers": ["aes128-cbc"], "weak_macs": ["hmac-sha1"], "weak_kex": []},
    "legacy": {"legacy_macs": [], "legacy_host_keys": ["ssh-rsa"], "legacy_kex": []},
    "policy_issues": ["SSH_WEAK_CIPHER_OFFERED"],
}

_SSH_KEYS = {
    "status": "OK",
    "keys": [
        {"key_type": "ssh-ed25519", "bits": 256, "fingerprint_sha256": "SHA256:abc", "verdict": {"status": "OK"}},
        {"key_type": "ssh-rsa", "bits": 2048, "fingerprint_sha256": "SHA256:def", "verdict": {"status": "WEAK"}},
    ],
    "policy_issues": ["SSH_WEAK_HOST_KEY"],
}


def test_ssh_evidence_records_offers_and_refuses_to_claim_negotiation():
    record = build_ssh_evidence(endpoint="10.20.10.30:22", kex=_SSH_KEX, host_keys=_SSH_KEYS)
    assert record["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert record["protocol"] == "SSH"
    assert record["ssh"]["negotiated"] is None
    assert record["ssh"]["negotiation_status"] == "NOT_NEGOTIATED"
    assert record["ssh"]["algorithms_offered"]["kex"][0] == "curve25519-sha256"
    assert record["ssh"]["version"] == "2.0"
    assert {key["key_type"] for key in record["ssh"]["host_keys"]} == {"ssh-ed25519", "ssh-rsa"}
    assert record["policy_issues"] == ["SSH_WEAK_CIPHER_OFFERED", "SSH_WEAK_HOST_KEY"]
    assert any("NOT_OBSERVED" in line for line in record["limitations"])
    assert record["mutual_tls"] == "NOT_APPLICABLE"


def test_ssh_evidence_without_a_response_is_unknown():
    record = build_ssh_evidence(endpoint="10.20.10.31:22", kex={"status": "SSH_UNREACHABLE"})
    assert record["evidence_type"] == "UNKNOWN"
    assert record["ssh"]["negotiation_status"] == "NOT_OBSERVED"
    assert any("not proof of weak crypto" in line for line in record["limitations"])


def test_ssh_cbom_assets_are_labelled_as_offers():
    record = build_ssh_evidence(endpoint="10.20.10.30:22", kex=_SSH_KEX, host_keys=_SSH_KEYS)
    cbom = to_protocol_cbom_assets([record])
    assert cbom["roles"] == {
        "ssh-key-exchange": 1,
        "ssh-host-key": 1,
        "ssh-cipher": 1,
        "ssh-mac": 1,
    }
    assert all("offered, not negotiated" == asset["context"]["note"] for asset in cbom["assets"])
    assert cbom["protocols"] == {"SSH": 4}


# --------------------------------------------------------------------------- #
# §18 — database transport TLS vs TDE
# --------------------------------------------------------------------------- #


def test_database_tls_refusal_is_recorded_and_tde_stays_out_of_reach():
    record = build_database_evidence(
        endpoint="10.20.10.40:5432",
        engine="POSTGRESQL",
        detection={"details": {"postgres": {"ssl_supported": False, "answer": "N"}}},
    )
    assert record["evidence_type"] == "UNKNOWN"
    assert record["observation_status"] == "TLS_REFUSED"
    assert record["policy_issues"] == ["DB_TRANSPORT_TLS_NOT_OFFERED"]
    assert record["database"]["tde"] == "NOT_OBSERVED"
    assert record["database"]["column_encryption"] == "NOT_OBSERVED"
    assert record["database"]["transport"]["ssl_supported"] is False
    assert set(DATABASE_OUT_OF_REACH).issubset(set(record["limitations"]))


def test_database_transport_tls_with_a_handshake_produces_real_parameters():
    record = build_database_evidence(
        endpoint="10.20.10.40:5432",
        engine="POSTGRESQL",
        detection={"details": {"postgres": {"ssl_supported": True, "answer": "S"}}},
        tls={"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "has_certificate": True},
    )
    assert record["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert record["observation_status"] == "TLS_HANDSHAKE"
    assert record["tls_version"] == "TLSv1.3"
    assert record["decomposition"]["encryption"] == "AES-256"
    assert record["decomposition"]["key_exchange"]  # TLS 1.3 key agreement
    assert record["database"]["transport"]["tls_negotiated"] is True
    assert record["database"]["tde"] == "NOT_OBSERVED"  # never promoted from transport


def test_database_cbom_assets_are_transport_only():
    record = build_database_evidence(
        endpoint="10.20.10.40:5432",
        engine="POSTGRESQL",
        tls={"tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "has_certificate": True},
    )
    cbom = to_protocol_cbom_assets([record])
    roles = set(cbom["roles"])
    assert "db-transport-encryption" in roles
    assert "db-transport-key-exchange" in roles
    assert not any("tde" in role for role in roles)
    assert cbom["not_observed"] == []


def test_protocol_evidence_keeps_the_endpoint_and_its_gap():
    detection = _detect(5001)
    detection["endpoint"] = "10.20.10.15:5001"
    record = build_protocol_evidence(detection)
    assert record["evidence_type"] == "UNKNOWN"
    assert record["target"]["endpoint"] == "10.20.10.15:5001"
    assert record["detection"]["attempts"][0]["probe"] == "TLS_CLIENT_HELLO"
    assert any("UNKNOWN is the result" in line for line in record["limitations"])


# --------------------------------------------------------------------------- #
# §30 — emergency stop
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


def test_stop_blocks_active_observation_and_release_restores_it(session):
    assert safety_state(session, tenant_id=None)["engaged"] is False
    require_running(session, tenant_id=None)  # no exception while running

    engaged = engage(session, reason="IDS alert from SOC-1182", by="soc", tenant_id=None)
    assert engaged["engaged"] is True
    assert engaged["active_observation_permitted"] is False
    # passive ingest stays available during an incident
    assert engaged["passive_ingest_permitted"] is True
    assert engaged["config_import_permitted"] is True

    with pytest.raises(NetworkStopped) as excinfo:
        require_running(session, tenant_id=None)
    assert excinfo.value.code == "network_observation_stopped"
    assert "IDS alert" in excinfo.value.reason

    released = release(session, by="soc", note="alert triaged, IDS confirmed healthy", tenant_id=None)
    assert released["engaged"] is False
    assert released["released_by"] == "soc"
    require_running(session, tenant_id=None)


# --------------------------------------------------------------------------- #
# API
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
    body = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443", "10.20.10.30:22", "10.20.10.40:5432"],
        "protocols": ["TLS", "SSH"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ", "SSH_BANNER"],
        "traffic_budget": {"max_connections": 30, "max_bytes": 1000000},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "inventory_id": "default",
    }
    body.update(overrides)
    return http.put("/api/v1/network/crypto-scope", json=body)


def test_stop_endpoint_blocks_observation_and_import_still_works(client, monkeypatch):
    http, _session = client
    from network_scanner.core.scanner import NetworkTlsScanner

    assert save_scope(http).status_code == 200
    monkeypatch.setattr(
        NetworkTlsScanner,
        "scan_hosts",
        lambda self, hosts, **kwargs: {
            "scan_id": "scan-1",
            "run_id": "run-1",
            "findings": [],
            "certificates": [],
            "probe_telemetry": {"status": "OK", "probed": 1, "ok": 0},
        },
    )
    stop = http.post("/api/v1/network/crypto-stop", json={"engage": True, "reason": "IDS alert"})
    assert stop.status_code == 200
    assert stop.json()["engaged"] is True

    refused = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert refused.status_code == 409
    assert refused.json()["detail"]["error"] == "network_observation_stopped"
    assert refused.json()["detail"]["reason"] == "IDS alert"

    # passive ingest opens no socket, so it keeps working while stopped
    passive = http.post(
        "/api/v1/network/crypto-passive",
        json={"observations": [{"dst_ip": "10.20.10.15", "dst_port": 443, "tls_version": "TLSv1.3"}]},
    )
    assert passive.status_code == 200

    assert http.post("/api/v1/network/crypto-stop", json={"engage": False, "note": "triaged"}).json()["engaged"] is False
    resumed = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert resumed.status_code == 200, resumed.text


def test_crypto_probe_detects_then_observes_each_protocol(client, monkeypatch):
    http, _session = client
    import network_scanner.discovery.protocol_detector as detector
    from network_scanner.core.scanner import NetworkTlsScanner

    assert save_scope(http).status_code == 200

    detections = {
        443: {
            "schema": "cryptoscan.protocol-detection/1",
            "host": "10.20.10.15",
            "port": 443,
            "detected": "TLS",
            "detection_method": "TLS_HANDSHAKE",
            "confidence": "HIGH",
            "service_guess": {"name": "HTTPS", "source": "PORT_REGISTRY"},
            "port_matches_protocol": True,
            "tls": {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "has_certificate": True},
            "tls_capable": True,
            "attempts": [{"probe": "TLS_CLIENT_HELLO", "result": "HANDSHAKE_COMPLETED"}],
            "details": {},
            "limitations": [],
        },
        22: {
            "schema": "cryptoscan.protocol-detection/1",
            "host": "10.20.10.30",
            "port": 22,
            "detected": "SSH",
            "detection_method": "BANNER",
            "confidence": "HIGH",
            "service_guess": {"name": "SSH", "source": "PORT_REGISTRY"},
            "port_matches_protocol": True,
            "tls": None,
            "tls_capable": False,
            "attempts": [{"probe": "BANNER", "result": "SSH"}],
            "details": {"banner": "SSH-2.0-OpenSSH_8.9"},
            "limitations": [],
        },
        5432: {
            "schema": "cryptoscan.protocol-detection/1",
            "host": "10.20.10.40",
            "port": 5432,
            "detected": "POSTGRESQL",
            "detection_method": "SSL_REQUEST",
            "confidence": "HIGH",
            "service_guess": {"name": "POSTGRES", "source": "PORT_REGISTRY"},
            "port_matches_protocol": True,
            "tls": None,
            "tls_capable": True,
            "attempts": [{"probe": "POSTGRES_SSL_REQUEST", "result": "SUPPORTED"}],
            "details": {"postgres": {"ssl_supported": True, "answer": "S"}},
            "limitations": [],
        },
    }
    monkeypatch.setattr(
        detector,
        "detect_protocol",
        lambda host, port, **kwargs: detections[port],
    )
    monkeypatch.setattr(
        detector,
        "postgres_tls_handshake",
        lambda host, port, **kwargs: {
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "has_certificate": True,
        },
    )
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
                        "tls_version": "TLSv1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "key_exchange_algorithm": "X25519",
                        "authentication_algorithm": "ECDSA",
                        "encryption_algorithm": "AES-256",
                        "encryption_mode": "GCM",
                    },
                    "certificates": [{"fingerprint_sha256": "sha256:aa", "public_key_algorithm": "ECDSA"}],
                    "chain_validation": {},
                    "policy_issues": [],
                    "metadata": {"confidence": "HIGH"},
                }
            ],
            "certificates": [],
            "probe_telemetry": {"status": "OK", "probed": 1, "ok": 1},
        },
    )
    import network_scanner.probing.ssh_kex as ssh_kex
    import network_scanner.probing.ssh_keyscan as ssh_keyscan

    monkeypatch.setattr(ssh_kex, "probe_ssh_kex_offer", lambda host, port, **kwargs: _SSH_KEX)
    monkeypatch.setattr(ssh_keyscan, "scan_ssh_host_keys", lambda host, port, **kwargs: _SSH_KEYS)

    response = http.post("/api/v1/network/crypto-probe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 200, response.text
    body = response.json()
    # the scope binds the run: detection only probes approved destinations
    assert body["detection_summary"]["by_protocol"] == {"TLS": 1}
    assert body["cbom"]["roles"].get("tls-bulk-encryption") or body["cbom"]["roles"]
    assert body["evidence_chain"]["appended"] >= 1

    # a second run against the SSH + database destinations
    assert save_scope(
        http,
        destinations=["10.20.10.30:22", "10.20.10.40:5432"],
    ).status_code == 200
    response = http.post("/api/v1/network/crypto-probe", json={"endpoints": ["10.20.10.30:22", "10.20.10.40:5432"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detection_summary"]["by_protocol"] == {"SSH": 1, "POSTGRESQL": 1}
    protocols = {record["protocol"] for record in body["evidence"]}
    assert {"SSH", "POSTGRESQL"} <= protocols
    ssh_record = next(record for record in body["evidence"] if record["protocol"] == "SSH")
    assert ssh_record["ssh"]["negotiation_status"] == "NOT_NEGOTIATED"
    db_record = next(record for record in body["evidence"] if record["protocol"] == "POSTGRESQL")
    assert db_record["database"]["transport"]["tls_negotiated"] is True
    assert db_record["database"]["tde"] == "NOT_OBSERVED"
    assert "ssh-cipher" in body["cbom"]["roles"]
    assert "db-transport-encryption" in body["cbom"]["roles"]


def test_crypto_probe_refuses_an_endpoint_outside_the_scope(client):
    http, _session = client
    assert save_scope(http).status_code == 200
    response = http.post("/api/v1/network/crypto-probe", json={"endpoints": ["10.99.99.99:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "destination_outside_scope"


def test_crypto_probe_without_a_scope_is_refused(client):
    http, _session = client
    response = http.post("/api/v1/network/crypto-probe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_not_configured"


def test_crypto_probe_does_not_escalate_operations_across_protocols(client, monkeypatch):
    """A TLS-only approval must not authorise reading an SSH banner."""
    http, _session = client
    import network_scanner.discovery.protocol_detector as detector

    assert save_scope(
        http,
        destinations=["10.20.10.30:22"],
        protocols=["TLS"],
        allowed_operations=["CONNECT", "TLS_HANDSHAKE"],
    ).status_code == 200
    monkeypatch.setattr(
        detector,
        "detect_protocol",
        lambda host, port, **kwargs: {
            "schema": "cryptoscan.protocol-detection/1",
            "host": host,
            "port": port,
            "detected": "SSH",
            "detection_method": "BANNER",
            "confidence": "HIGH",
            "service_guess": {"name": "SSH", "source": "PORT_REGISTRY"},
            "port_matches_protocol": True,
            "tls": None,
            "tls_capable": False,
            "attempts": [{"probe": "BANNER", "result": "SSH"}],
            "details": {"banner": "SSH-2.0-x"},
            "limitations": [],
        },
    )
    response = http.post("/api/v1/network/crypto-probe", json={"endpoints": ["10.20.10.30:22"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scope_refusals"][0]["protocol"] == "SSH"
    assert body["scope_refusals"][0]["error"] == "protocol_not_allowed"
    ssh_record = next(record for record in body["evidence"] if record["protocol"] == "SSH")
    assert ssh_record["evidence_type"] == "UNKNOWN"  # no KEXINIT was read


def test_safety_endpoint_reports_state(client):
    http, _session = client
    body = http.get("/api/v1/network/crypto-safety").json()
    assert body["engaged"] is False
    assert body["active_observation_permitted"] is True
    assert body["distributed"] is False


# --------------------------------------------------------------------------- #
# §20 — Kubernetes declares topology; only evidence is observed
# --------------------------------------------------------------------------- #


_K8S_MANIFESTS = [
    {
        "kind": "Ingress",
        "metadata": {"name": "payments", "namespace": "production"},
        "spec": {
            "tls": [{"hosts": ["payments.bank"], "secretName": "payments-tls"}],
            "rules": [
                {"host": "payments.bank", "http": {"paths": [{"path": "/", "backend": {"service": {"name": "payments-api"}}}]}}
            ],
        },
    },
    {
        "kind": "Service",
        "metadata": {"name": "payments-api", "namespace": "production"},
        "spec": {"clusterIP": "10.20.30.10", "ports": [{"port": 8443}], "selector": {"app": "payments"}},
    },
    {
        "kind": "Pod",
        "metadata": {"name": "payments-1", "namespace": "production", "labels": {"app": "payments"}},
        "spec": {
            "containers": [
                {"name": "payments", "image": "registry.bank/payments@sha256:abc"},
                {"name": "istio-proxy", "image": "proxyv2@sha256:def"},
            ]
        },
    },
]


def test_kubernetes_correlation_keeps_declared_and_observed_apart():
    from api.security.network_kubernetes import correlate as correlate_kubernetes

    evidence = [
        {
            "evidence_type": "NETWORK_ACTIVE_OBSERVED",
            "evidence_id": "ev-1",
            "target": {"endpoint": "payments.bank:443", "host": "payments.bank"},
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "mutual_tls": "NOT_REQUIRED",
        }
    ]
    report = correlate_kubernetes(_K8S_MANIFESTS, evidence)
    assert report["summary"]["ingresses"] == 1
    assert report["summary"]["declared_endpoints"] == 2
    assert report["summary"]["observed_endpoints"] == 1

    ingress = next(item for item in report["endpoints"] if item["kind"] == "INGRESS_TLS")
    assert ingress["tls_version"] == "TLSv1.3"
    assert ingress["declared"]["secret_name"] == "payments-tls"
    assert ingress["declared"]["source"] == "KUBERNETES_INGRESS_SPEC"

    service = next(item for item in report["endpoints"] if item["kind"] == "SERVICE_PORT")
    assert service["evidence_type"] == "UNKNOWN"
    assert "NOT_OBSERVED" in service["note"]


def test_kubernetes_correlation_labels_sidecars_and_selector_links():
    from api.security.network_kubernetes import correlate as correlate_kubernetes

    report = correlate_kubernetes(_K8S_MANIFESTS, [])
    assert report["sidecars"] == [{"pod": "production/payments-1", "containers": ["istio-proxy"]}]
    assert report["links"][0]["kind"] == "SELECTOR_MATCH"
    assert report["pods"][0]["image_digest_pinned"] is True
    assert any("sidecar proxy's TLS" in line for line in report["limitations"])


def test_kubernetes_correlation_never_invents_observed_tls():
    from api.security.network_kubernetes import correlate as correlate_kubernetes

    report = correlate_kubernetes(_K8S_MANIFESTS, [])
    assert all(item["evidence_type"] == "UNKNOWN" for item in report["endpoints"])
    assert report["summary"]["observed_endpoints"] == 0


def test_kubernetes_endpoint_reports_sources(client):
    http, _session = client
    response = http.post("/api/v1/network/kubernetes-correlate", json={"manifests": _K8S_MANIFESTS})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.kubernetes-correlation/1"
    assert body["sources"]["manifests_supplied"] == 3
    assert body["summary"]["sidecar_pods"] == 1


# --------------------------------------------------------------------------- #
# §28–§31 — policy, risk, PQC readiness, NBOM/TechBOM
# --------------------------------------------------------------------------- #


def _weak_tls_record() -> dict:
    return {
        "schema": "cryptoscan.network-evidence/1",
        "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "evidence_id": "ev-weak",
        "protocol": "TLS",
        "target": {"endpoint": "payments.bank:443", "host": "payments.bank", "port": 443},
        "tls_version": "TLSv1.2",
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "decomposition": {
            "key_exchange": "RSA",
            "authentication": "RSA",
            "encryption": "AES-128-CBC",
            "mac_or_prf": "SHA1",
            "key_size_bits": 2048,
        },
        "certificate": {
            "subject": "CN=payments.bank",
            "issuer": "CN=Bank Issuing CA",
            "public_key_algorithm": "RSA",
            "public_key_bits": 1024,
            "signature_algorithm": "sha1WithRSAEncryption",
            "not_after": "2026-11-01T00:00:00Z",
        },
        "certificate_chain": {"length": 1, "structural_status": "INCOMPLETE", "trust_status": "UNTRUSTED"},
        "mutual_tls": "NOT_REQUIRED",
        "observed_at": "2026-10-27T00:00:00Z",
    }


def test_policy_fails_weak_tls_and_never_calls_it_compliant():
    from network_scanner.inventory.network_policy import evaluate

    report = evaluate([_weak_tls_record()])
    assert report["verdict"] == "FAIL"
    rules = {finding["rule_id"] for finding in report["failed"]}
    assert {"NET-TLS-FORWARD-SECRECY", "NET-CERT-KEY-SIZE", "NET-CERT-SIGNATURE", "NET-CERT-EXPIRY"} <= rules
    assert all(finding["layer"] == "NETWORK_TRANSPORT" for finding in report["findings"])
    assert report["policy"]["min_tls_version"] == "TLSv1.2"


def test_policy_treats_unobserved_evidence_as_a_gap_not_a_pass():
    from network_scanner.inventory.network_policy import evaluate

    record = {
        "evidence_type": "NETWORK_CONFIGURED",
        "evidence_id": "ev-config",
        "protocol": "TLS",
        "target": {"endpoint": "gw.bank:8443", "host": "gw.bank", "port": 8443},
        "tls_version": "TLSv1.3",
    }
    report = evaluate([record])
    assert report["verdict"] == "NOT_ASSESSABLE"
    assert report["failed"] == []
    assert report["coverage_gaps"]
    assert "UNKNOWN" in report["coverage_gaps"][0]["message"]
    assert report["coverage_gaps"][0]["status"] == "UNKNOWN"


def test_policy_passes_modern_tls_but_still_reports_unknowns():
    from network_scanner.inventory.network_policy import evaluate

    record = _weak_tls_record()
    record.update(
        {
            "evidence_id": "ev-strong",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "decomposition": {
                "key_exchange": "X25519",
                "authentication": "ECDSA",
                "encryption": "AES-256-GCM",
                "mac_or_prf": "SHA384",
                "key_size_bits": 253,
            },
            "certificate": {
                "subject": "CN=payments.bank",
                "issuer": "CN=Bank Issuing CA",
                "public_key_algorithm": "ECDSA",
                "public_key_bits": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "not_after": "2027-10-01T00:00:00Z",
            },
            "certificate_chain": {"length": 3, "structural_status": "COMPLETE", "trust_status": "TRUSTED"},
            "mutual_tls": "CLIENT_CERT_REQUESTED",
        }
    )
    report = evaluate([record], {"require_mtls_endpoints": ["payments.bank:443"]})
    assert report["verdict"] == "PASS"
    assert report["failed"] == []
    assert all(finding["status"] in {"PASS", "UNKNOWN"} for finding in report["findings"])


def test_policy_flags_ssh_and_database_weaknesses():
    from network_scanner.inventory.network_policy import evaluate

    ssh = {
        "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "evidence_id": "ev-ssh",
        "protocol": "SSH",
        "target": {"endpoint": "10.0.0.5:22", "host": "10.0.0.5", "port": 22},
        "ssh": {
            "algorithms_offered": {
                "kex": ["diffie-hellman-group14-sha1", "curve25519-sha256"],
                "host_key": ["ssh-rsa", "ssh-ed25519"],
                "cipher": ["aes128-cbc", "aes256-gcm@openssh.com"],
                "mac": ["hmac-sha1", "hmac-sha2-256"],
            },
            "host_keys": [{"key_type": "ssh-rsa", "bits": 1024}],
        },
    }
    db = {
        "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "evidence_id": "ev-db",
        "protocol": "PostgreSQL",
        "target": {"endpoint": "10.0.0.9:5432", "host": "10.0.0.9", "port": 5432},
        "database": {"engine": "POSTGRESQL", "transport": {"tls_negotiated": False, "ssl_supported": False}},
    }
    report = evaluate([ssh, db])
    rules = {finding["rule_id"] for finding in report["failed"]}
    assert {"NET-SSH-KEX", "NET-SSH-HOST-KEY", "NET-SSH-CIPHER", "NET-SSH-MAC", "NET-SSH-HOST-KEY-SIZE"} <= rules
    assert "NET-DB-TLS" in rules
    storage = [f for f in report["findings"] if f["rule_id"] == "NET-DB-STORAGE"]
    assert storage and storage[0]["status"] == "UNKNOWN"


def test_pqc_readiness_never_claims_readiness_without_observation():
    from network_scanner.inventory.network_policy import pqc_readiness

    report = pqc_readiness(
        [
            {"evidence_type": "UNKNOWN", "protocol": "TLS", "target": {"endpoint": "a.bank:443"}},
            {
                "evidence_type": "NETWORK_ACTIVE_OBSERVED",
                "protocol": "TLS",
                "target": {"endpoint": "b.bank:443"},
                "decomposition": {"key_exchange": "X25519"},
                "certificate": {"signature_algorithm": "ecdsa-with-SHA256"},
            },
        ]
    )
    assert report["verdict"] == "CLASSICAL_ONLY"
    assert report["summary"]["not_observed"] == 1
    assert report["endpoints"][0]["readiness"] == "NOT_OBSERVED"
    assert report["endpoints"][1]["harvest_now_decrypt_later_exposed"] is True


def test_pqc_readiness_detects_hybrid_key_exchange():
    from network_scanner.inventory.network_policy import pqc_readiness

    report = pqc_readiness(
        [
            {
                "evidence_type": "NETWORK_ACTIVE_OBSERVED",
                "protocol": "TLS",
                "target": {"endpoint": "pq.bank:443"},
                "decomposition": {"key_exchange": "X25519MLKEM768"},
            }
        ]
    )
    assert report["verdict"] == "HYBRID_KEX_PRESENT"
    assert report["summary"]["hybrid_kex"] == 1


def test_nbom_inventories_unobserved_endpoints_without_verdicts():
    from network_scanner.inventory.network_policy import to_nbom, to_techbom

    nbom = to_nbom(
        [
            _weak_tls_record(),
            {"evidence_type": "UNKNOWN", "protocol": "TLS", "target": {"endpoint": "dead.bank:443", "host": "dead.bank", "port": 443}},
        ],
        estate="payments",
    )
    assert nbom["bomFormat"] == "CycloneDX"
    assert any(
        component.get("properties")
        and any(prop.get("name") == "cryptoscan:host" and prop.get("value") == "dead.bank"
                for prop in component["properties"])
        for component in nbom["components"]
    )
    assert any(
        prop["name"] == "cryptoscan:unobserved_endpoints" and prop["value"] == "1"
        for prop in nbom["metadata"]["properties"]
    )
    techbom = to_techbom([_weak_tls_record()])
    assert techbom["protocols"][0]["protocol"] == "TLS"
    assert techbom["bom_type"] == "TECHBOM"


def test_risk_endpoint_scores_stored_evidence(client):
    http, session = client
    from db.models.network_scan_run import NetworkScanRun

    run = NetworkScanRun(result={"network_evidence": [_weak_tls_record()]}, target_kind="crypto-observe")
    session.add(run)
    session.commit()

    response = http.post("/api/v1/network/crypto-risk", json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.network-risk/1"
    assert body["verdict"] == "FAIL"
    assert body["sources"]["origin"] == "stored_evidence"
    assert body["pqc"]["verdict"] == "CLASSICAL_ONLY"

    bom = http.post("/api/v1/network/crypto-nbom", json={})
    assert bom.status_code == 200, bom.text
    assert bom.json()["nbom"]["bomFormat"] == "CycloneDX"
