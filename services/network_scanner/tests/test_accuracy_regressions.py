"""Deterministic regressions for network/TLS scan accuracy."""

from __future__ import annotations

import socket
import ssl

from network_scanner.certificates.cert_parser import hostname_matches, parse_pem
from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.core.scanner import NetworkTlsScanner, normalize_endpoint
from network_scanner.probing.active_prober import probe_endpoint


CERTS = __import__("pathlib").Path(__file__).resolve().parents[3] / "demo" / "certs"


def _load(name: str) -> dict:
    parsed = parse_pem((CERTS / name).read_text(encoding="utf-8"))
    assert parsed
    return parsed[0]


def test_hostname_matching_honors_san_and_limits_wildcards():
    # A CN must not override an explicitly present, non-matching SAN.
    assert not hostname_matches(
        "wrong.example.com",
        {"subject": "CN=wrong.example.com", "san": ["DNS:right.example.com"]},
    )
    assert hostname_matches("one.example.com", {"san": ["DNS:*.example.com"]})
    assert not hostname_matches("two.one.example.com", {"san": ["DNS:*.example.com"]})
    assert not hostname_matches("192.0.2.10", {"san": ["DNS:*.example.com"]})
    assert hostname_matches("192.0.2.10", {"san": ["IP Address:192.0.2.10"]})


def test_leaf_only_non_self_signed_chain_is_explicitly_incomplete():
    leaf = _load("valid_leaf.pem")
    result = validate_chain([leaf], hostname="api.payment.example.com")
    assert result["is_valid"] is False
    assert result["structural_status"] == "INVALID"
    assert "CHAIN_INCOMPLETE" in result["errors"]
    assert result["trust_status"] == "NOT_VERIFIED"
    assert result["trust_verification"]["status"] == "NOT_PERFORMED"


def test_endpoint_normalization_is_deterministic():
    assert normalize_endpoint(" Example.COM.:443 ") == "example.com:443"
    assert normalize_endpoint("[2001:DB8::1]:8443") == "[2001:db8::1]:8443"
    assert normalize_endpoint("example.com") == "example.com:443"


def test_revocation_combines_conclusive_ocsp_and_crl_results(monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    monkeypatch.setattr(
        scanner_mod,
        "check_ocsp",
        lambda cert, live: {"method": "OCSP", "status": "UNKNOWN", "urls": ["http://ocsp.test"]},
    )
    monkeypatch.setattr(
        scanner_mod,
        "check_crl",
        lambda cert, live: {"method": "CRL", "status": "REVOKED", "urls": ["http://crl.test"]},
    )
    cert = {"subject": "CN=leaf", "serial_number": "01"}
    NetworkTlsScanner(live=False)._attach_revocation([cert])
    assert cert["revocation_status"] == "REVOKED"
    assert cert["revocation_method"] == "CRL"
    assert cert["revocation"]["ocsp"]["status"] == "UNKNOWN"


def test_scan_hosts_deduplicates_equivalent_endpoints(monkeypatch):
    calls = []

    def fake_probe(endpoint, **kwargs):
        calls.append(endpoint)
        return {"endpoint": endpoint, "status": "OK", "policy_issues": [], "metadata": {}}

    import network_scanner.core.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "probe_endpoint", fake_probe)
    result = NetworkTlsScanner(live=True).scan_hosts(
        ["EXAMPLE.com:443", "example.com:443", "example.com.", "[2001:DB8::1]:443"]
    )
    assert calls == ["example.com:443", "[2001:db8::1]:443"]
    assert [row["endpoint"] for row in result["findings"]] == calls


def test_probe_uses_explicit_sni_for_certificate_identity(tmp_path):
    # Reuse the same deterministic local certificate-generation approach as
    # the deep-probe tests, but make the certificate identity localhost while
    # the transport endpoint is an IP literal.
    import subprocess
    import threading

    key = tmp_path / "sni.key"
    cert = tmp_path / "sni.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        try:
            conn, _ = listener.accept()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            with context.wrap_socket(conn, server_side=True):
                pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        finding = probe_endpoint(f"127.0.0.1:{port}", sni="localhost", check_http=False)
    finally:
        thread.join(timeout=3)
        listener.close()

    assert finding["status"] == "OK"
    assert "HOSTNAME_MISMATCH" not in finding["chain_validation"]["errors"]
    assert finding["metadata"]["endpoint_hostname"] == "127.0.0.1"
    assert finding["metadata"]["certificate_hostname"] == "localhost"


def test_probe_falls_back_to_another_resolved_address(monkeypatch, tmp_path):
    # The first candidate is a controlled closed local port; the second is a
    # local TLS server. This never depends on public DNS or infrastructure.
    import subprocess
    import threading
    import network_scanner.probing.active_prober as prober

    key = tmp_path / "fallback.key"
    cert = tmp_path / "fallback.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    good_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    bad_port = closed.getsockname()[1]
    closed.close()

    def serve():
        try:
            conn, _ = listener.accept()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            with context.wrap_socket(conn, server_side=True):
                pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    candidates = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", bad_port)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", good_port)),
    ]
    monkeypatch.setattr(prober, "_resolve_addresses", lambda host, port: candidates)
    try:
        finding = probe_endpoint("localhost:443", check_http=False, timeout=2.0)
    finally:
        thread.join(timeout=3)
        listener.close()

    assert finding["status"] == "OK"
    assert finding["selected_address"] == "127.0.0.1"
    assert finding["resolved_addresses"] == ["127.0.0.1", "127.0.0.1"]
    assert [attempt["status"] for attempt in finding["connection_attempts"]] == ["FAILED", "CONNECTED"]
