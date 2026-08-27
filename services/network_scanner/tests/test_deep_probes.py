"""Deep probes: version floor, weak-cipher acceptance, mTLS, ALPN, subnet sweep."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading

from network_scanner.discovery.subnet_discoverer import discover_subnet
from network_scanner.probing.active_prober import probe_endpoint
from network_scanner.probing.cipher_probe import probe_weak_ciphers
from network_scanner.probing.version_floor import probe_version_floor


def _make_cert(tmp_path, name="deep"):
    key = tmp_path / f"{name}.key"
    crt = tmp_path / f"{name}.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(crt), str(key)


class TlsServer:
    """Scripted one-shot TLS server with configurable versions/ciphers/auth."""

    def __init__(self, cert, key, *, max_version=None, ciphers=None, require_client_cert=False, alpn=None):
        self.cert, self.key = cert, key
        self.max_version = max_version
        self.ciphers = ciphers
        self.require_client_cert = require_client_cert
        self.alpn = alpn
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
            if self.max_version is not None:
                ctx.maximum_version = self.max_version
                ctx.minimum_version = self.max_version
            if self.ciphers:
                ctx.set_ciphers(self.ciphers)
            if self.alpn:
                ctx.set_alpn_protocols(self.alpn)
            if self.require_client_cert:
                ctx.verify_mode = ssl.CERT_REQUIRED
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(1.0)
                try:
                    tls.recv(1024)
                except (ssl.SSLError, OSError, TimeoutError):
                    pass
        except ssl.SSLError:
            pass
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.done.set()
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# version floor
# --------------------------------------------------------------------------- #


def test_version_floor_against_tls12_only_server(tmp_path):
    cert, key = _make_cert(tmp_path)
    server = TlsServer(cert, key, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        floor = probe_version_floor("127.0.0.1", server.port, timeout=4.0)
        assert floor["versions"]["TLSv1.2"] == "ACCEPTED"
        assert floor["versions"]["TLSv1.3"] == "REFUSED"
        for weak in ("TLSv1.0", "TLSv1.1"):
            # honest outcomes only: never ACCEPTED-by-accident, never silence
            assert floor["versions"][weak] in {"REFUSED", "LOCAL_UNSUPPORTED"}
            if floor["versions"][weak] == "ACCEPTED":
                assert weak in floor["weak_accepted"]
        assert "TLSv1.2" in floor["accepted"]
        assert floor["weakest_accepted"] in {"TLSv1.0", "TLSv1.1", "TLSv1.2", None}
    finally:
        server.close()


def test_version_floor_unreachable_host():
    floor = probe_version_floor("127.0.0.1", 1, timeout=1.0)  # nothing listens on port 1
    assert floor["accepted"] == []
    assert floor["weakest_accepted"] is None
    # the sweep stops at the first unreachable attempt; whatever was tested is honest
    for verdict in floor["versions"].values():
        assert verdict in {"REFUSED", "LOCAL_UNSUPPORTED", "UNREACHABLE", "TIMEOUT"}


# --------------------------------------------------------------------------- #
# weak cipher acceptance
# --------------------------------------------------------------------------- #


def test_weak_cipher_probe_modern_server(tmp_path):
    cert, key = _make_cert(tmp_path, "modern")
    server = TlsServer(cert, key, ciphers="ECDHE-RSA-AES256-GCM-SHA384")
    try:
        result = probe_weak_ciphers("127.0.0.1", server.port, timeout=4.0)
        assert result["disallowed_accepted"] == []
        # RC4/3DES: locally unavailable (default OpenSSL 3) or refused — never accepted
        for cipher in ("RC4-SHA", "DES-CBC3-SHA"):
            assert cipher in result["local_unsupported"] or cipher in result["refused"]
        assert "AES128-SHA" in result["refused"]  # AEAD-only server refuses CBC
        assert result["cbc_accepted"] == []
    finally:
        server.close()


def test_weak_cipher_probe_cbc_server_reports_it(tmp_path):
    cert, key = _make_cert(tmp_path, "cbc")
    server = TlsServer(cert, key, ciphers="AES128-SHA:AES256-GCM-SHA256")
    try:
        result = probe_weak_ciphers("127.0.0.1", server.port, timeout=4.0)
        assert "AES128-SHA" in result["cbc_accepted"]
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# mTLS + ALPN via probe_endpoint
# --------------------------------------------------------------------------- #


def test_mtls_classification():
    from network_scanner.probing.active_prober import _classify_ssl_error

    # stacks that surface the explicit alert are classified MTLS_REQUIRED
    assert _classify_ssl_error(ssl.SSLError("sslv3 alert certificate required")) == "MTLS_REQUIRED"
    assert _classify_ssl_error(ssl.SSLError("PEER_DID_NOT_RETURN_A_CERTIFICATE")) == "MTLS_REQUIRED"
    # generic handshake failure stays a mismatch, never silently OK
    assert _classify_ssl_error(ssl.SSLError("sslv3 alert handshake failure")) == "HANDSHAKE_FAILURE"


def test_probe_against_mtls_server_is_never_ok(tmp_path):
    """A server demanding client certs must not scan as a healthy endpoint."""
    cert, key = _make_cert(tmp_path, "mtls")
    # TLS 1.2 + CERT_REQUIRED: this OpenSSL sends a generic handshake_failure
    # alert to the client, so the probe reports the mismatch honestly
    server = TlsServer(cert, key, require_client_cert=True, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        finding = probe_endpoint(f"127.0.0.1:{server.port}", timeout=5.0, check_http=False)
        assert finding["status"] in {"MTLS_REQUIRED", "TLS_ERROR"}
        assert finding["status"] != "OK"
        assert finding["error_type"] in {"MTLS_REQUIRED", "HANDSHAKE_FAILURE"}
    finally:
        server.close()


def test_probe_negotiates_alpn(tmp_path):
    cert, key = _make_cert(tmp_path, "alpn")
    server = TlsServer(cert, key, alpn=["h2", "http/1.1"])
    try:
        finding = probe_endpoint(f"127.0.0.1:{server.port}", timeout=5.0, check_http=False)
        assert finding["status"] == "OK"
        assert finding["crypto"]["alpn"] == "h2"
    finally:
        server.close()


def test_probe_endpoint_deep_scan_flags(tmp_path):
    cert, key = _make_cert(tmp_path, "deep")
    server = TlsServer(cert, key, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        finding = probe_endpoint(
            f"127.0.0.1:{server.port}",
            timeout=5.0,
            check_http=False,
            scan_versions=True,
            scan_ciphers=True,
        )
        assert finding["status"] == "OK"
        assert "TLSv1.2" in finding["version_floor"]["accepted"]
        assert "weak_cipher_probe" in finding
        assert finding["policy_issues"] is not None
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# subnet discovery
# --------------------------------------------------------------------------- #


def _listener():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    return sock, sock.getsockname()[1]


def test_discover_subnet_finds_open_ports():
    a, port_a = _listener()
    b, port_b = _listener()
    try:
        result = discover_subnet("127.0.0.1/32", [port_a, port_b, 59999], timeout=1.0)
        assert result["open_count"] == 2
        assert set(result["endpoints"]) == {f"127.0.0.1:{port_a}", f"127.0.0.1:{port_b}"}
        assert result["truncated"] is False
    finally:
        a.close()
        b.close()


def test_discover_subnet_guards_and_errors():
    result = discover_subnet("not-a-cidr")
    assert result["error"] and result["endpoints"] == []
    v6 = discover_subnet("::1/128")
    assert "IPv4" in v6["error"]
    # huge range is truncated, never runaway
    big = discover_subnet("10.0.0.0/16", [443], timeout=0.05, max_targets=64)
    assert big["truncated"] is True
    assert big["candidates"] <= 64
