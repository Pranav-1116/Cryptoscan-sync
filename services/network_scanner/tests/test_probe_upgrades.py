"""STARTTLS negotiation, HTTP header checks, policy verdicts, concurrency."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
import time

from network_scanner.core.scanner import NetworkTlsScanner, certificate_verdict, probe_telemetry
from network_scanner.probing.active_prober import _resolve_starttls, probe_endpoint
from network_scanner.probing.cipher_suite_parser import headline_issue, policy_issues, registry_verdict
from network_scanner.probing.http_headers import check_http_headers
from network_scanner.probing.starttls import negotiate_starttls, protocol_for_port


# --------------------------------------------------------------------------- #
# STARTTLS negotiators (socketpair-driven, no server needed)
# --------------------------------------------------------------------------- #


def _pair():
    return socket.socketpair()


def _serve(client_side, script: list[bytes]) -> None:
    """Fake plaintext server: read one line, reply with the next script entry."""

    def run():
        try:
            client_side.settimeout(2.0)
            for expected_prefix, reply in script:
                if expected_prefix:
                    data = b""
                    while not data.endswith(b"\n") and b"\n" not in data:
                        chunk = client_side.recv(256)
                        if not chunk:
                            break
                        data += chunk
                client_side.sendall(reply)
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()


def test_smtp_starttls_negotiation():
    a, b = _pair()
    _serve(b, [(None, b"220 mail.example.com ESMTP ready\r\n"),
               (b"EHLO", b"250-mail.example.com\r\n250 STARTTLS\r\n"),
               (b"STARTTLS", b"220 2.0.0 Ready to start TLS\r\n")])
    result = negotiate_starttls(a, "smtp", timeout=2.0)
    assert result["ok"] is True
    a.close(); b.close()


def test_smtp_starttls_refused():
    a, b = _pair()
    _serve(b, [(None, b"220 mail ESMTP\r\n"),
               (b"EHLO", b"250 OK\r\n"),
               (b"STARTTLS", b"454 TLS not available\r\n")])
    result = negotiate_starttls(a, "smtp", timeout=2.0)
    assert result["ok"] is False
    assert "refused" in result["detail"].lower()
    a.close(); b.close()


def test_imap_and_pop3_starttls():
    a, b = _pair()
    _serve(b, [(None, b"* OK IMAP4rev1 ready\r\n"), (b"a001", b"a001 OK Begin TLS negotiation now\r\n")])
    assert negotiate_starttls(a, "imap", timeout=2.0)["ok"] is True
    a.close(); b.close()

    a, b = _pair()
    _serve(b, [(None, b"+OK POP3 server ready\r\n"), (b"STLS", b"+OK Begin TLS\r\n")])
    assert negotiate_starttls(a, "pop3", timeout=2.0)["ok"] is True
    a.close(); b.close()


def test_postgresql_sslrequest():
    a, b = _pair()

    def run():
        b.settimeout(2.0)
        request = b.recv(16)
        assert len(request) == 8  # length(4) + code(4)
        b.sendall(b"S")

    threading.Thread(target=run, daemon=True).start()
    assert negotiate_starttls(a, "postgresql", timeout=2.0)["ok"] is True
    a.close(); b.close()


def test_starttls_resolution_modes():
    assert _resolve_starttls(None, 443) is None
    assert _resolve_starttls(False, 25) is None
    assert _resolve_starttls("off", 25) is None
    assert _resolve_starttls(True, 25) == "smtp"       # auto by port
    assert _resolve_starttls("auto", 587) == "smtp"
    assert _resolve_starttls("auto", 443) == "none"    # plain TLS port
    assert _resolve_starttls("ldap", 443) == "ldap"    # explicit wins
    assert protocol_for_port(143) == "imap"
    assert protocol_for_port(443) is None


# --------------------------------------------------------------------------- #
# HTTP headers / HSTS
# --------------------------------------------------------------------------- #


def _http_pair(response: bytes):
    a, b = socket.socketpair()

    def run():
        try:
            b.settimeout(2.0)
            b.recv(4096)  # the HEAD request
            b.sendall(response)
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return a, b


def test_hsts_parsed_from_head_response():
    a, _b = _http_pair(
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
        b"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\r\n"
    )
    facts = check_http_headers(_FakeTls(a), "example.com", timeout=2.0)
    assert facts is not None
    assert facts["http_status"] == 200
    assert facts["hsts"]["present"] is True
    assert facts["hsts"]["max_age"] == 31536000
    assert facts["hsts"]["include_subdomains"] is True
    assert facts["hsts"]["preload"] is True


def test_no_hsts_reports_absence():
    a, _b = _http_pair(b"HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n")
    facts = check_http_headers(_FakeTls(a), "example.com", timeout=2.0)
    assert facts["hsts"]["present"] is False
    assert facts["redirects_to_https"] is True
    assert "NO_HSTS" in policy_issues({"tls_version": "TLSv1.3", "status": "ALLOWED"}, hsts=facts)


def test_non_http_socket_returns_none():
    a, _b = _http_pair(b"\x16\x03\x01\x00\xa9 binary tls bytes not http")
    assert check_http_headers(_FakeTls(a), "example.com", timeout=2.0) is None


class _FakeTls:
    """Duck-typed stand-in for the TLS socket (only send/recv/settimeout)."""

    def __init__(self, sock):
        self._sock = sock

    def settimeout(self, value):
        self._sock.settimeout(value)

    def sendall(self, data):
        self._sock.sendall(data)

    def recv(self, size):
        return self._sock.recv(size)


# --------------------------------------------------------------------------- #
# policy verdicts
# --------------------------------------------------------------------------- #


def test_registry_verdicts_for_suites():
    modern = registry_verdict("TLS_AES_256_GCM_SHA384")
    assert modern["status"] == "ALLOWED"
    assert modern["key_size"] == 256
    legacy = registry_verdict("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
    assert legacy["status"] in {"DISALLOWED", "DEPRECATED"}


def test_policy_issues_ordering():
    issues = policy_issues({
        "tls_version": "TLSv1.0",
        "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        "encryption_algorithm": "RC4",
        "encryption_mode": "CBC",
        "status": "DISALLOWED",
    })
    assert issues[0] == "DISALLOWED_CIPHER"      # most severe first
    assert "WEAK_TLS_VERSION" in issues
    assert headline_issue(issues) == "DISALLOWED_CIPHER"
    clean = policy_issues({
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "encryption_algorithm": "AES-256",
        "encryption_mode": "GCM",
        "status": "ALLOWED",
    }, hsts={"hsts": {"present": True}})
    assert clean == []


# --------------------------------------------------------------------------- #
# concurrency + telemetry
# --------------------------------------------------------------------------- #


def test_probe_all_runs_concurrently_and_keeps_order(monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    def slow_probe(endpoint, *, timeout=5.0, sni=None, starttls=None, check_http=True, **kwargs):
        time.sleep(0.25)
        return {"endpoint": endpoint, "status": "OK", "policy_issues": [], "metadata": {}}

    monkeypatch.setattr(scanner_mod, "probe_endpoint", slow_probe)
    scanner = NetworkTlsScanner(live=True, timeout=5.0, workers=4)
    endpoints = [f"10.0.0.{i}:443" for i in range(1, 9)]
    started = time.monotonic()
    results = scanner._probe_all(endpoints)
    elapsed = time.monotonic() - started
    assert [row["endpoint"] for row in results] == endpoints  # order preserved
    # serial would be 8 * 0.25s = 2.0s; pooled (4 workers) ~0.5s. Bound 1.6s
    # is >3x the pooled time yet well under serial, so the assertion still
    # proves concurrency while tolerating a fully loaded CI runner (the
    # previous 0.5s/2.5s variant flaked twice under the full test lane).
    assert elapsed < 1.6


def test_scan_hosts_telemetry_verdicts(monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    def fake_probe(endpoint, *, timeout=5.0, sni=None, starttls=None, check_http=True, **kwargs):
        if endpoint.startswith("weak"):
            return {"endpoint": endpoint, "status": "OK", "policy_issues": ["WEAK_TLS_VERSION", "DISALLOWED_CIPHER"], "metadata": {}}
        if endpoint.startswith("dead"):
            return {"endpoint": endpoint, "status": "TIMEOUT", "policy_issues": [], "metadata": {}}
        return {"endpoint": endpoint, "status": "OK", "policy_issues": [], "metadata": {}}

    monkeypatch.setattr(scanner_mod, "probe_endpoint", fake_probe)
    scanner = NetworkTlsScanner(live=True)
    result = scanner.scan_hosts(["good:443", "weak:443", "dead:443"], workers=3)
    telemetry = result["probe_telemetry"]
    assert telemetry["probed"] == 3
    assert telemetry["ok"] == 2
    assert telemetry["weak_tls_versions"] == 1
    assert telemetry["weak_cipher_suites"] == 1
    assert telemetry["status"] == "PARTIAL"
    assert telemetry["statuses"] == {"OK": 2, "TIMEOUT": 1}


def test_probe_telemetry_all_failed():
    rows = [
        {"endpoint": "a", "status": "TIMEOUT"},
        {"endpoint": "b", "status": "DNS_FAILED"},
    ]
    assert probe_telemetry(rows)["status"] == "FAILED"
    assert probe_telemetry([])["status"] == "SKIPPED"


def test_one_endpoint_error_never_sinks_the_scan(monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    def boom(endpoint, **kwargs):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(scanner_mod, "probe_endpoint", boom)
    scanner = NetworkTlsScanner(live=True, workers=2)
    result = scanner.scan_hosts(["a:443", "b:443"])
    assert result["probe_telemetry"]["status"] == "FAILED"
    assert all(row["status"] == "PROBE_ERROR" for row in result["probes"])


# --------------------------------------------------------------------------- #
# certificate verdicts
# --------------------------------------------------------------------------- #


def test_certificate_verdict_flags_weak_keys_and_signatures():
    weak_key = certificate_verdict({"public_key_algorithm": "RSA", "public_key_size": 1024})
    assert weak_key["compliance_issue"] == "WEAK_CERTIFICATE_KEY"

    sha1_sig = certificate_verdict({"public_key_algorithm": "RSA", "public_key_size": 2048, "signature_algorithm": "sha1WithRSAEncryption"})
    assert sha1_sig["compliance_issue"] == "WEAK_SIGNATURE_ALGORITHM"

    strong = certificate_verdict({"public_key_algorithm": "RSA", "public_key_size": 2048, "signature_algorithm": "sha256WithRSAEncryption"})
    assert strong["compliance_issue"] is None
    assert strong["status"] == "ALLOWED"


# --------------------------------------------------------------------------- #
# end-to-end: STARTTLS probe against a live scripted SMTP+TLS server
# --------------------------------------------------------------------------- #


def _make_cert(tmp_path):
    key = tmp_path / "probe.key"
    crt = tmp_path / "probe.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(crt), str(key)


def test_probe_endpoint_starttls_end_to_end(tmp_path):
    cert, key = _make_cert(tmp_path)
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)
    server.settimeout(5)

    def smtp_tls_server():
        try:
            conn, _ = server.accept()
            conn.settimeout(5)
            conn.sendall(b"220 mail.internal ESMTP ready\r\n")
            conn.recv(1024)                      # EHLO
            conn.sendall(b"250-mail.internal\r\n250 STARTTLS\r\n")
            conn.recv(1024)                      # STARTTLS
            conn.sendall(b"220 2.0.0 Ready\r\n")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1024)                   # tolerate client bytes
        except Exception:
            pass
        finally:
            try:
                server.close()
            except OSError:
                pass

    threading.Thread(target=smtp_tls_server, daemon=True).start()
    finding = probe_endpoint(f"127.0.0.1:{port}", starttls="smtp", timeout=5.0, check_http=False)
    assert finding["status"] == "OK"
    assert finding["metadata"]["starttls"] == "smtp"
    assert finding["crypto"]["tls_version"]
    assert finding["crypto"]["cipher_suite"]
    assert finding["policy_issues"] is not None
    assert finding["chain_validation"]["errors"]  # self-signed -> SELF_SIGNED
