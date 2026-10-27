"""Renegotiation (RFC 5746) + sent-chain order probes and their telemetry."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading

from network_scanner.certificates.cert_parser import pem_to_der
from network_scanner.certificates.chain_order import (
    analyze_chain_sent,
    fetch_sent_chain,
    probe_chain_sent,
)
from network_scanner.core.scanner import NetworkTlsScanner, probe_telemetry
from network_scanner.probing.active_prober import probe_endpoint
from network_scanner.probing.renegotiation import (
    parse_renegotiation_output,
    probe_renegotiation,
)


def _make_cert(tmp_path, name="reneg"):
    key = tmp_path / f"{name}.key"
    crt = tmp_path / f"{name}.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(crt), str(key)


class Tls12Server:
    """Reusable TLS 1.2 server (renegotiation is a TLS<=1.2 mechanism)."""

    def __init__(self, cert, key):
        self.cert, self.key = cert, key
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.sock.settimeout(10)
        self.done = threading.Event()
        threading.Thread(target=self._serve_forever, daemon=True).start()

    def _serve_forever(self):
        while not self.done.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert, self.key)
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(3)
                try:
                    tls.recv(4096)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self.done.set()
        try:
            self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# renegotiation transcript parser (pure)
# --------------------------------------------------------------------------- #

def test_parse_secure_renegotiation_supported():
    parsed = parse_renegotiation_output(
        "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
        "Secure Renegotiation IS supported\n",
        "",
    )
    assert parsed["secure_renegotiation"] == "SUPPORTED"


def test_parse_secure_renegotiation_not_supported():
    parsed = parse_renegotiation_output(
        "Secure Renegotiation IS NOT supported\n", ""
    )
    assert parsed["secure_renegotiation"] == "NOT_SUPPORTED"


def test_parse_client_renegotiation_refused():
    parsed = parse_renegotiation_output(
        "Secure Renegotiation IS supported\n",
        "RENEGOTIATING\n"
        "error:ssl3_read_bytes:no renegotiation:../ssl/record/rec_layer_s3.c:1617:",
    )
    assert parsed["client_renegotiation"] == "REFUSED"
    assert parsed["client_detail"]


def test_parse_client_renegotiation_accepted():
    parsed = parse_renegotiation_output(
        "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\nSecure Renegotiation IS supported\n",
        "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
        "RENEGOTIATING\n"
        "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n",
    )
    assert parsed["client_renegotiation"] == "ACCEPTED"


def test_parse_unknown_when_start_without_completion():
    parsed = parse_renegotiation_output("Secure Renegotiation IS supported\n", "RENEGOTIATING\n")
    assert parsed["client_renegotiation"] == "UNKNOWN"


def test_parse_silent_handshake_is_unknown_not_guesswork():
    parsed = parse_renegotiation_output("depth=0 CN = localhost\nverify return:1\n", "")
    assert parsed["secure_renegotiation"] == "UNKNOWN"
    assert parsed["secure_detail"]


# --------------------------------------------------------------------------- #
# renegotiation probe (live, honest outcomes)
# --------------------------------------------------------------------------- #

def test_probe_renegotiation_against_tls12_server(tmp_path):
    cert, key = _make_cert(tmp_path, "live")
    server = Tls12Server(cert, key)
    try:
        result = probe_renegotiation("127.0.0.1", server.port, sni="localhost", timeout=6.0)
        # OpenSSL 3 server sends renegotiation_info: RFC 5746 supported
        assert result["secure_renegotiation"] == "SUPPORTED"
        # client-initiated renegotiation: honest outcome, never a guess
        assert result["client_renegotiation"] in {"ACCEPTED", "REFUSED", "UNKNOWN"}
        assert result["method"] == "openssl-sclient"
    finally:
        server.close()


def test_probe_renegotiation_unreachable_port_is_untestable():
    result = probe_renegotiation("127.0.0.1", 1, timeout=2.0)
    assert result["secure_renegotiation"] == "UNKNOWN"
    assert result["secure_detail"]


def test_probe_renegotiation_without_openssl(monkeypatch):
    import network_scanner.probing.renegotiation as mod

    monkeypatch.setattr(mod, "_openssl_binary", lambda: None)
    result = mod.probe_renegotiation("127.0.0.1", 443)
    assert result["client_renegotiation"] == "LOCAL_UNSUPPORTED"
    assert result["method"] == "openssl-sclient-unavailable"


# --------------------------------------------------------------------------- #
# sent-chain analysis (pure)
# --------------------------------------------------------------------------- #

def _cert(subject, issuer, fp, *, self_signed=False, size=2048, sig="sha256WithRSAEncryption"):
    return {
        "subject": subject,
        "issuer": issuer,
        "fingerprint_sha256": fp,
        "is_self_signed": self_signed,
        "public_key_algorithm": "RSA",
        "public_key_size": size,
        "signature_algorithm": sig,
    }


LEAF = _cert("CN=leaf", "CN=inter", "aa")
INTER = _cert("CN=inter", "CN=root", "bb")
ROOT = _cert("CN=root", "CN=root", "cc", self_signed=True)


def test_chain_sent_well_formed():
    # a proper server chain: leaf + intermediate, root NOT shipped
    analysis = analyze_chain_sent([LEAF, INTER])
    assert analysis["sent_length"] == 2
    assert analysis["issues"] == []
    assert analysis["order_ok"] is True


def test_chain_sent_full_chain_with_root_disclosed():
    analysis = analyze_chain_sent([LEAF, INTER, ROOT])
    assert analysis["sent_length"] == 3
    # shipping the self-signed root is the only complaint
    assert analysis["issues"] == ["ROOT_CERT_SENT"]
    assert analysis["order_ok"] is True


def test_chain_sent_reordered():
    analysis = analyze_chain_sent([LEAF, ROOT, INTER])
    assert "CHAIN_ORDER_BROKEN" in analysis["issues"]
    assert analysis["order_ok"] is False


def test_chain_sent_link_broken():
    analysis = analyze_chain_sent([LEAF, _cert("CN=other", "CN=root", "dd")])
    assert "CHAIN_LINK_BROKEN" in analysis["issues"]


def test_chain_sent_incomplete_single_leaf():
    analysis = analyze_chain_sent([_cert("CN=leaf", "CN=inter", "ee")])
    assert "CHAIN_INCOMPLETE" in analysis["issues"]


def test_chain_sent_self_signed_leaf_is_not_incomplete():
    analysis = analyze_chain_sent([_cert("CN=solo", "CN=solo", "ff", self_signed=True)])
    assert "CHAIN_INCOMPLETE" not in analysis["issues"]


def test_chain_sent_root_disclosed():
    analysis = analyze_chain_sent([LEAF, INTER, ROOT])
    # a full chain including the self-signed root
    assert "ROOT_CERT_SENT" in analyze_chain_sent([LEAF, ROOT])["issues"]


def test_chain_sent_duplicate():
    analysis = analyze_chain_sent([LEAF, INTER, ROOT, INTER])
    assert "DUPLICATE_CERT_IN_CHAIN" in analysis["issues"]


def test_chain_sent_weak_intermediate():
    weak = _cert("CN=inter", "CN=root", "gg", sig="sha1WithRSAEncryption")
    analysis = analyze_chain_sent([LEAF, weak, ROOT])
    assert "CHAIN_WEAK_INTERMEDIATE" in analysis["issues"]


def test_chain_sent_empty():
    analysis = analyze_chain_sent([])
    assert analysis["issues"] == ["CHAIN_UNAVAILABLE"]
    assert analysis["sent_length"] == 0


def test_chain_sent_weak_key_registry():
    weak_key = _cert("CN=inter", "CN=root", "hh", size=1024)
    analysis = analyze_chain_sent([LEAF, weak_key, ROOT])
    assert "CHAIN_WEAK_INTERMEDIATE" in analysis["issues"]


# --------------------------------------------------------------------------- #
# sent-chain fetch (live) + pem_to_der
# --------------------------------------------------------------------------- #

def test_pem_to_der_roundtrip():
    der = pem_to_der(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    )
    assert der == b"\x00\x00\x00"


def test_pem_to_der_garbage():
    assert pem_to_der("not a pem") is None
    assert pem_to_der(None) is None


def test_fetch_sent_chain_live(tmp_path):
    cert, key = _make_cert(tmp_path, "chain")
    server = Tls12Server(cert, key)
    try:
        certs = fetch_sent_chain("127.0.0.1", server.port, sni="localhost", timeout=6.0)
        assert len(certs) == 1
        assert certs[0].get("subject")
        analysis = probe_chain_sent("127.0.0.1", server.port, sni="localhost", timeout=6.0)
        assert analysis["sent_length"] == 1
        assert analysis["leaf_self_signed"] is True
        assert analysis["issues"] == []
        assert analysis["certificates"]
    finally:
        server.close()


def test_probe_chain_sent_without_openssl(monkeypatch):
    import network_scanner.certificates.chain_order as mod

    monkeypatch.setattr(mod, "_openssl_binary", lambda: None)
    result = mod.probe_chain_sent("127.0.0.1", 443)
    assert result["detail"]
    assert result["issues"] == []


# --------------------------------------------------------------------------- #
# probe_endpoint integration + telemetry
# --------------------------------------------------------------------------- #

def test_probe_endpoint_renegotiation_and_chain_flags(tmp_path):
    cert, key = _make_cert(tmp_path, "flags")
    server = Tls12Server(cert, key)
    try:
        finding = probe_endpoint(
            f"127.0.0.1:{server.port}",
            timeout=8.0,
            check_http=False,
            check_renegotiation=True,
            check_chain_sent=True,
        )
        assert finding["status"] == "OK"
        assert finding["renegotiation"]["secure_renegotiation"] == "SUPPORTED"
        assert finding["chain_sent"]["sent_length"] == 1
        # OpenSSL 3 server: RFC 5746 negotiated, nothing weak to report
        assert "INSECURE_RENEGOTIATION_ENABLED" not in finding["policy_issues"]
    finally:
        server.close()


def test_telemetry_counts_renegotiation_and_chain_issues():
    rows = [
        {"status": "OK", "policy_issues": ["INSECURE_RENEGOTIATION_ENABLED"]},
        {"status": "OK", "policy_issues": ["CLIENT_RENEGOTIATION_ACCEPTED"]},
        {"status": "OK", "policy_issues": ["CHAIN_ORDER_BROKEN", "CBC_ACCEPTED"]},
    ]
    telemetry = probe_telemetry(rows)
    assert telemetry["insecure_renegotiation"] == 1
    assert telemetry["client_renegotiation_accepted"] == 1
    assert telemetry["chain_order_issues"] == 1
    assert telemetry["status"] == "PARTIAL"


def test_scanner_passes_deep_flags(tmp_path):
    cert, key = _make_cert(tmp_path, "scan")
    server = Tls12Server(cert, key)
    try:
        result = NetworkTlsScanner(live=True, timeout=8.0).scan_hosts(
            [f"127.0.0.1:{server.port}"],
            check_renegotiation=True,
            check_chain_sent=True,
        )
        finding = result["findings"][0]
        assert finding["status"] == "OK"
        assert "renegotiation" in finding
        assert "chain_sent" in finding
        assert "insecure_renegotiation" in result["probe_telemetry"]
    finally:
        server.close()
