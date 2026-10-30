"""Live TLS handshake → NBOM, end to end (§4.4, round 53).

The bank-sandbox portals need keys and network this environment does not
have; what they would give the CBOM tool is a TLS endpoint with a known
handshake. These tests build that locally: a mock-bank TLS server
(``MockBankTLS``) with a fresh self-signed certificate and pinned
protocol/ciphers, then run the REAL probe → mapping → CycloneDX NBOM
path against it and assert the captured crypto metadata — negotiated
version, cipher suite, key algorithm/size, self-signed status, the
dependency graph and the honest-findings rules.

``probe_to_endpoint`` parity with the API's stored-probe path is pinned
too: the offline script, ``GET /cbom/nbom`` and the cross-BOM query must
share one contract, not three near-copies.
"""

from __future__ import annotations

import socket
import ssl

import pytest

from cbom.nbom import build_nbom, probe_to_endpoint
from network_scanner.probing.active_prober import probe_endpoint
from network_scanner.probing.mock_bank_tls import MockBankTLS


def test_mock_bank_pins_are_real():
    """The harness does what it claims: a TLS 1.3 client cannot talk to a
    TLS 1.2-pinned mock, so test outcomes below are deterministic."""
    with MockBankTLS(min_tls_version="1.2", max_tls_version="1.2",
                     ciphers="ECDHE-RSA-AES128-GCM-SHA256") as bank:
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        host, port = bank.endpoint.rsplit(":", 1)
        with pytest.raises(ssl.SSLError):
            with socket.create_connection((host, int(port)), timeout=5) as raw:
                with client.wrap_socket(raw):
                    pass


def test_live_handshake_to_cyclonedx_nbom_tls12():
    """The full execution pattern: handshake against a pinned mock bank →
    negotiated crypto captured → CycloneDX 1.5 NBOM with dependencies."""
    with MockBankTLS(min_tls_version="1.2", max_tls_version="1.2",
                     ciphers="ECDHE-RSA-AES128-GCM-SHA256",
                     common_name="mock-bank-emirates.local") as bank:
        finding = probe_endpoint(bank.endpoint, timeout=10.0)

    assert finding["status"] == "OK", finding.get("error")
    crypto = finding["crypto"]  # the raw prober nests negotiated facts here
    assert crypto["tls_version"] == "TLSv1.2"
    assert crypto["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
    leaf = finding["certificates"][0]
    assert leaf["public_key_algorithm"] == "RSA"
    assert leaf["public_key_size"] == 2048
    assert leaf["is_self_signed"] is True

    endpoint = probe_to_endpoint(finding)
    assert endpoint["host"] == "127.0.0.1"
    assert endpoint["observed"] is True
    # round-53 contract fix: the nested facts MUST survive the mapping —
    # a real stored scan used to lose the negotiated protocol here
    assert endpoint["tls_version"] == "TLSv1.2"
    assert endpoint["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert endpoint["certificate"]["is_self_signed"] is True

    nbom = build_nbom([endpoint], estate="mock-bank-test")
    assert nbom["specVersion"] == "1.5"
    by_ref = {c["bom-ref"]: c for c in nbom["components"]}
    endpoints = [c for r, c in by_ref.items() if r.startswith("endpoint:")]
    suites = [c for r, c in by_ref.items() if r.startswith("suite:")]
    certs = [c for r, c in by_ref.items() if r.startswith("certificate:")]
    assert endpoints and suites and certs, "endpoint + negotiated suite + leaf are all components"

    deps = {d["ref"]: d["dependsOn"] for d in nbom["dependencies"]}
    ep_ref = endpoints[0]["bom-ref"]
    assert ep_ref in deps
    # the endpoint depends on the suite it negotiated and the leaf it served
    assert suites[0]["bom-ref"] in deps[ep_ref]
    assert any(c["bom-ref"] in deps[ep_ref] for c in certs)
    assert suites[0]["type"] == "cryptographic-asset"  # a first-class crypto asset


def test_live_handshake_captures_tls13():
    """A TLS 1.3-only mock bank: the negotiated version and one of the five
    RFC 8446 suites must be captured and inventoried."""
    with MockBankTLS(min_tls_version="1.3", max_tls_version="1.3",
                     common_name="mock-bank-qnb.local") as bank:
        finding = probe_endpoint(bank.endpoint, timeout=10.0)

    assert finding["status"] == "OK", finding.get("error")
    assert finding["crypto"]["tls_version"] == "TLSv1.3"
    assert finding["crypto"]["cipher_suite"], "TLS 1.3 negotiates a suite — it must be captured"

    endpoint = probe_to_endpoint(finding)
    nbom = build_nbom([endpoint], estate="mock-bank-test-tls13")
    suites = [c for c in nbom["components"]
              if c.get("bom-ref", "").startswith("suite:")]
    assert suites, "the negotiated TLS 1.3 suite must be a BOM component"


def test_probe_to_endpoint_matches_the_api_contract():
    """Parity: the same probe maps to the same endpoint dict the API's
    stored-probe path builds (host/port/protocol/observed/certificate)."""
    finding = {
        "endpoint": "bank.example.com:443",
        "status": "OK",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "alpn": "h2",
        "certificates": [{
            "subject": "CN=bank.example.com",
            "issuer": "CN=Test Issuer CA",
            "serial_number": "01",
            "fingerprint_sha256": "c" * 64,
            "public_key_algorithm": "ECDSA",
            "public_key_size": 256,
            "not_after": "2030-01-01T00:00:00+00:00",
            "is_self_signed": False,
        }],
    }
    endpoint = probe_to_endpoint(finding)
    assert endpoint == {
        "host": "bank.example.com",
        "port": 443,
        "protocol": "tls",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "observed": True,
        "service": "h2",
        "certificate": {
            "subject": "CN=bank.example.com",
            "issuer": "CN=Test Issuer CA",
            "serial_number": "01",
            "fingerprint_sha256": "c" * 64,
            "public_key_algorithm": "ECDSA",
            "public_key_size": 256,
            "not_after": "2030-01-01T00:00:00+00:00",
            "is_self_signed": False,
            "expiry_status": None,
        },
    }
    unreachable = probe_to_endpoint({"endpoint": "dark.example.com:443", "status": "CONNECT_ERROR"})
    assert unreachable["observed"] is False  # unknown, never healthy
    assert probe_to_endpoint({}) == {}


def test_refused_endpoint_never_becomes_a_healthy_component():
    """A closed port is inventoried with observed=false and contributes no
    verdict — the honesty rule, through the whole path."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here now

    finding = probe_endpoint(f"127.0.0.1:{port}", timeout=5.0)
    assert finding["status"] != "OK"

    nbom = build_nbom([probe_to_endpoint(finding)], estate="refused-test")
    endpoint_component = next(c for c in nbom["components"]
                              if c.get("bom-ref", "").startswith("endpoint:"))
    observed = next((p.get("value") for p in endpoint_component.get("properties", [])
                     if p.get("name") == "cryptoscan:observed"), None)
    assert observed in ("False", "false", False)


def test_failed_handshake_is_unknown_not_plaintext():
    """Round 53 fix, pinned: a probe whose handshake FAILED (TLS_ERROR,
    STARTTLS_REFUSED, MTLS_REQUIRED) must render the endpoint as
    observed=false with NO verdict — a failed handshake never proves the
    traffic is plaintext."""
    from cbom.nbom import OBSERVED_OK_STATUSES

    for status in ("TLS_ERROR", "STARTTLS_REFUSED", "MTLS_REQUIRED"):
        endpoint = probe_to_endpoint({
            "endpoint": "blocked.example.com:443",
            "status": status,
            "error": "handshake closed by middlebox",
        })
        assert endpoint["observed"] is False, status
        nbom = build_nbom([endpoint], estate="failed-handshake-test")
        component = next(c for c in nbom["components"]
                         if c["bom-ref"].startswith("endpoint:"))
        findings = component.get("cryptoscan:findings") or []
        assert findings == [], f"{status} must not fabricate a verdict: {findings}"
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["cryptoscan:observed"] == "False"

    # a negotiated handshake is the only observed status
    assert probe_to_endpoint({"endpoint": "ok.example.com:443", "status": "OK"})["observed"] is True
    assert OBSERVED_OK_STATUSES == {"OK", "TLS_OK"}


