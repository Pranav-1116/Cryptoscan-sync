"""Live revocation: real OCSP queries + CRL fetch/parse, all on localhost."""

from __future__ import annotations

import http.server
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from network_scanner.certificates.revocation_cache import cache_get, cache_put
from network_scanner.certificates.revocation_live import (
    check_crl_live,
    check_ocsp_live,
    check_revocation_live,
    crl_is_stale,
    normalize_serial,
    parse_crl_text,
    parse_ocsp_output,
)

CA_CONF = """
[ ca ]
default_ca = CA_default
[ CA_default ]
database = {root}/index.txt
new_certs_dir = {root}/newcerts
serial = {root}/serial
crlnumber = {root}/crlnumber
default_md = sha256
default_days = 5
policy = policy_any
copy_extensions = copy
unique_subject = no
[ policy_any ]
commonName = supplied
"""


def _run(*argv, check=True):
    proc = subprocess.run(argv, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise AssertionError(f"{' '.join(argv)} failed: {proc.stderr[-300:]}")
    return proc


class MiniPki:
    """Local CA + leaves with OCSP/CRL URLs pointing at 127.0.0.1:<http_port>."""

    def __init__(self, tmp_path: Path, http_port: int):
        self.root = tmp_path
        self.ca_pem = tmp_path / "ca.pem"
        self.ca_key = tmp_path / "ca.key"
        _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.ca_key), "-out", str(self.ca_pem),
             "-days", "5", "-subj", "/CN=Test Revocation CA")
        (tmp_path / "index.txt").write_text("")
        (tmp_path / "index.txt.attr").write_text("unique_subject = no\n")
        (tmp_path / "newcerts").mkdir()
        (tmp_path / "serial").write_text("1000")
        (tmp_path / "crlnumber").write_text("1000")
        (tmp_path / "ca.cnf").write_text(CA_CONF.format(root=tmp_path))
        self.http_port = http_port

    def issue(self, name: str) -> dict[str, str]:
        ext = self.root / f"{name}.ext"
        ext.write_text(
            f"authorityInfoAccess = OCSP;URI:http://127.0.0.1:{self.http_port}/ocsp\n"
            f"crlDistributionPoints = URI:http://127.0.0.1:{self.http_port}/{name}.crl.pem\n"
        )
        _run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.root / f"{name}.key"),
             "-out", str(self.root / f"{name}.csr"), "-subj", f"/CN={name}")
        cert = self.root / f"{name}.pem"
        _run("openssl", "ca", "-config", str(self.root / "ca.cnf"), "-batch", "-notext",
             "-in", str(self.root / f"{name}.csr"), "-out", str(cert),
             "-cert", str(self.ca_pem), "-keyfile", str(self.ca_key), "-extfile", str(ext))
        serial = _run("openssl", "x509", "-in", str(cert), "-noout", "-serial").stdout.strip().split("=")[1]
        return {"name": name, "pem": cert.read_text(), "serial": serial}

    def revoke(self, name: str):
        _run("openssl", "ca", "-config", str(self.root / "ca.cnf"), "-batch",
             "-revoke", str(self.root / f"{name}.pem"),
             "-cert", str(self.ca_pem), "-keyfile", str(self.ca_key))

    def crl(self, name: str = "crl") -> dict[str, str]:
        pem = self.root / f"{name}.crl.pem"
        der = self.root / f"{name}.crl.der"
        _run("openssl", "ca", "-config", str(self.root / "ca.cnf"), "-batch", "-gencrl",
             "-out", str(pem), "-cert", str(self.ca_pem), "-keyfile", str(self.ca_key), "-crldays", "3")
        _run("openssl", "crl", "-in", str(pem), "-outform", "DER", "-out", str(der))
        return {"pem": str(pem), "der": str(der)}

    def ocsp_urls(self, name: str) -> list[str]:
        return [f"http://127.0.0.1:{self.http_port}/ocsp"]


class FileServer:
    """Tiny HTTP server serving one file with a request counter."""

    def __init__(self, path: str, content: bytes):
        self.requests = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 — http.server API
                outer.requests += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *_args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        # serve at the requested path
        self._path = path
        self.server.timeout = 0.05
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                self.server.handle_request()
            except OSError:
                return
            except Exception:  # noqa: BLE001 — client disconnects must not noise tests
                continue

    def close(self):
        self.server.server_close()


class OcspResponder:
    def __init__(self, pki: MiniPki, port: int):
        self.proc = subprocess.Popen(
            ["openssl", "ocsp", "-port", str(port), "-index", str(pki.root / "index.txt"),
             "-CA", str(pki.ca_pem), "-rkey", str(pki.ca_key), "-rsigner", str(pki.ca_pem),
             "-nmin", "5"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture()
def pki(tmp_path):
    http_port = _free_port()
    built = MiniPki(tmp_path, http_port)
    try:
        yield built
    finally:
        pass


# --------------------------------------------------------------------------- #
# pure parsers
# --------------------------------------------------------------------------- #

def test_normalize_serial_forms():
    assert normalize_serial("0x1A:2B") == "1a2b"
    assert normalize_serial("1a:2b:30") == "1a2b30"
    assert normalize_serial("001a2b") == "1a2b"
    assert normalize_serial(None) == ""
    assert normalize_serial("1000") == "1000"


def test_parse_ocsp_output_revoked():
    parsed = parse_ocsp_output(
        "leaf.pem: revoked\n\tThis Update: Aug 27 14:30:06 2026 GMT\n\tRevocation Time: Aug 27 14:29:53 2026 GMT\n",
        "c:64:Verify error: self-signed certificate",
    )
    assert parsed["status"] == "REVOKED"
    assert parsed["revocation_time"] == "Aug 27 14:29:53 2026 GMT"
    assert parsed["response_verified"] is False  # honest: signer unverified


def test_parse_ocsp_output_good_and_verified():
    parsed = parse_ocsp_output("leaf.pem: good\n\tThis Update: x\n", "Response verify OK")
    assert parsed["status"] == "GOOD"
    assert parsed["response_verified"] is True


def test_parse_ocsp_output_unreachable():
    parsed = parse_ocsp_output("", "Error querying OCSP responder\nconnect timeout")
    assert parsed["status"] == "UNKNOWN"
    assert parsed["reason"] == "responder_unreachable"


def test_parse_crl_text_and_staleness():
    text = (
        "Revoked Certificates:\n"
        "    Serial Number: 1000\n"
        "        Revocation Date: Aug 27 14:29:53 2026 GMT\n"
        "Next Update: Aug 30 14:29:53 2026 GMT\n"
    )
    parsed = parse_crl_text(text)
    assert parsed["revoked_serials"] == ["1000"]
    assert crl_is_stale(parsed["next_update_raw"]) is False
    assert crl_is_stale("Jan  1 00:00:00 2020 GMT") is True
    assert crl_is_stale(None) is None


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #

def test_cache_roundtrip_and_ttl(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_TTL", "3600")
    assert cache_get("http://x/crl") is None
    cache_put("http://x/crl", b"crl-bytes")
    hit = cache_get("http://x/crl")
    assert hit is not None and hit["data"] == b"crl-bytes"
    # TTL 0 disables both read and write
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_TTL", "0")
    assert cache_get("http://x/crl") is None


# --------------------------------------------------------------------------- #
# live CRL (PEM, DER, cache, stale, unreachable)
# --------------------------------------------------------------------------- #

def test_crl_live_flow(pki, monkeypatch, tmp_path):
    """revoked leaf -> REVOKED via PEM CRL; good leaf -> GOOD via same CRL."""
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c2"))
    revoked = pki.issue("revoked")
    good = pki.issue("good")
    pki.revoke("revoked")
    crl = pki.crl("flow")
    server = FileServer("/flow.crl.pem", Path(crl["pem"]).read_bytes())
    try:
        # point both leaves at the running server
        monkeypatch.setattr(
            "network_scanner.certificates.revocation_live.extract_crl_urls",
            lambda cert: [f"http://127.0.0.1:{server.port}/flow.crl.pem"],
        )
        result_revoked = check_crl_live({"pem": revoked["pem"], "serial_number": revoked["serial"]})
        assert result_revoked["status"] == "REVOKED"
        assert result_revoked["reason"] == "serial_on_crl"
        assert result_revoked["cache"] == "miss"

        result_good = check_crl_live({"pem": good["pem"], "serial_number": good["serial"]})
        assert result_good["status"] == "GOOD"
        assert result_good["cache"] == "hit"  # same URL -> cached CRL
        assert server.requests == 1
    finally:
        server.close()


def test_crl_live_der_supported(pki, monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c3"))
    leaf = pki.issue("derleaf")
    pki.revoke("derleaf")
    crl = pki.crl("der")
    server = FileServer("/der.crl.der", Path(crl["der"]).read_bytes())
    try:
        monkeypatch.setattr(
            "network_scanner.certificates.revocation_live.extract_crl_urls",
            lambda cert: [f"http://127.0.0.1:{server.port}/der.crl.der"],
        )
        result = check_crl_live({"pem": leaf["pem"], "serial_number": leaf["serial"]})
        assert result["status"] == "REVOKED"
    finally:
        server.close()


def test_crl_live_stale_is_fail_closed(pki, monkeypatch, tmp_path):
    """A CRL whose next-update has passed proves nothing: UNKNOWN, never GOOD."""
    import network_scanner.certificates.revocation_live as rl

    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c4"))
    leaf = pki.issue("staleleaf")
    crl = pki.crl("stale")
    server = FileServer("/stale.crl.pem", Path(crl["pem"]).read_bytes())
    try:
        monkeypatch.setattr(
            "network_scanner.certificates.revocation_live.extract_crl_urls",
            lambda cert: [f"http://127.0.0.1:{server.port}/stale.crl.pem"],
        )
        real_parse = rl.parse_crl_text
        # openssl cannot mint a past-dated CRL; fake ONLY the date, keep the
        # real serial parsing and the real staleness branch under test
        monkeypatch.setattr(
            rl, "parse_crl_text",
            lambda text: {**real_parse(text), "next_update_raw": "Jan  1 00:00:00 2020 GMT"},
        )
        result = check_crl_live({"pem": leaf["pem"], "serial_number": leaf["serial"]})
        assert result["status"] == "UNKNOWN"
        assert result["reason"] == "crl_stale"
    finally:
        server.close()


def test_crl_live_unreachable_is_unknown(pki, monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c5"))
    leaf = pki.issue("offline")
    monkeypatch.setattr(
        "network_scanner.certificates.revocation_live.extract_crl_urls",
        lambda cert: [f"http://127.0.0.1:{_free_port()}/nothing.crl"],
    )
    result = check_crl_live({"pem": leaf["pem"], "serial_number": leaf["serial"]}, timeout=2.0)
    assert result["status"] == "UNKNOWN"
    assert result["reason"].startswith("crl_unreachable")


# --------------------------------------------------------------------------- #
# live OCSP (local responder)
# --------------------------------------------------------------------------- #

def test_ocsp_live_revoked_against_responder(pki, monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c6"))
    leaf = pki.issue("ocrevoke")
    pki.revoke("ocrevoke")
    port = _free_port()
    responder = OcspResponder(pki, port)
    try:
        leaf_dict = {
            "pem": leaf["pem"],
            "serial_number": leaf["serial"],
            "issuer": "CN=Test Revocation CA",
            "ocsp_url": f"http://127.0.0.1:{port}/ocsp",
        }
        issuer = [{"subject": "CN=Test Revocation CA", "pem": Path(pki.ca_pem).read_text()}]
        result = check_ocsp_live(leaf_dict, [leaf_dict] + issuer)
        assert result["status"] == "REVOKED"
        assert result["revocation_time"]
        assert result["response_verified"] is False  # self-signed responder signer
    finally:
        responder.stop()


def test_ocsp_dead_responder_is_unknown(pki, monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c7"))
    leaf = pki.issue("ocdead")
    leaf_dict = {
        "pem": leaf["pem"],
        "serial_number": leaf["serial"],
        "issuer": "CN=Test Revocation CA",
        "ocsp_url": f"http://127.0.0.1:{_free_port()}/ocsp",
    }
    issuer = [{"subject": "CN=Test Revocation CA", "pem": Path(pki.ca_pem).read_text()}]
    result = check_ocsp_live(leaf_dict, [leaf_dict] + issuer, timeout=2.0)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "responder_unreachable"


def test_ocsp_without_issuer_is_honest(pki, tmp_path):
    leaf = pki.issue("noissuer")
    result = check_ocsp_live(
        {"pem": leaf["pem"], "serial_number": leaf["serial"],
         "issuer": "CN=Test Revocation CA", "ocsp_url": "http://127.0.0.1:1/ocsp"},
        [{"pem": leaf["pem"]}],  # no issuer in chain
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "issuer_unavailable"


# --------------------------------------------------------------------------- #
# combined + probe integration
# --------------------------------------------------------------------------- #

def test_check_revocation_live_prefers_ocsp_then_crl(pki, monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c8"))
    leaf = pki.issue("combo")
    pki.revoke("combo")
    crl = pki.crl("combo")
    server = FileServer("/combo.crl.pem", Path(crl["pem"]).read_bytes())
    try:
        leaf_dict = {
            "pem": leaf["pem"],
            "serial_number": leaf["serial"],
            "issuer": "CN=Test Revocation CA",
            "ocsp_url": f"http://127.0.0.1:{_free_port()}/ocsp",  # dead -> fallback
            "crl_url": f"http://127.0.0.1:{server.port}/combo.crl.pem",
        }
        issuer = [{"subject": "CN=Test Revocation CA", "pem": Path(pki.ca_pem).read_text()}]
        result = check_revocation_live(leaf_dict, [leaf_dict] + issuer, timeout=3.0)
        assert result["method"] == "CRL"
        assert result["status"] == "REVOKED"
        assert result["ocsp"]["status"] == "UNKNOWN"  # honest fallback trail
    finally:
        server.close()


def test_probe_endpoint_live_revocation_flags_revoked(pki, monkeypatch, tmp_path):
    """End-to-end: TLS server presents a revoked leaf -> CERT_REVOKED policy issue."""
    monkeypatch.setenv("CRYPTOSCAN_REVOCATION_CACHE_DIR", str(tmp_path / "c9"))
    leaf = pki.issue("served")
    pki.revoke("served")
    crl = pki.crl("served")
    server_http = FileServer("/served.crl.pem", Path(crl["pem"]).read_bytes())
    tls_sock = socket.socket()
    tls_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tls_sock.bind(("127.0.0.1", 0))
    tls_port = tls_sock.getsockname()[1]
    tls_sock.listen(4)
    tls_sock.settimeout(15)
    leaf_path = pki.root / "served.pem"
    key_path = pki.root / "served.key"

    def serve_tls():
        try:
            while True:
                conn, _ = tls_sock.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except OSError:
            return

    def handle(conn):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(leaf_path), str(key_path))
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(4)
                tls.recv(1024)
        except Exception:
            pass

    threading.Thread(target=serve_tls, daemon=True).start()
    try:
        # the served leaf's CRL DP points at pki.http_port; reroute to the live server
        original_extract = __import__(
            "network_scanner.certificates.crl_checker", fromlist=["extract_crl_urls"]
        ).extract_crl_urls

        def fake_extract(cert):
            urls = original_extract(cert)
            if urls:
                return [f"http://127.0.0.1:{server_http.port}/served.crl.pem"]
            return urls

        monkeypatch.setattr(
            "network_scanner.certificates.revocation_live.extract_crl_urls", fake_extract
        )
        monkeypatch.setattr(
            "network_scanner.certificates.revocation_live.extract_ocsp_urls",
            lambda cert: [f"http://127.0.0.1:{_free_port()}/ocsp"],  # dead -> CRL fallback
        )
        from network_scanner.probing.active_prober import probe_endpoint

        finding = probe_endpoint(
            f"127.0.0.1:{tls_port}",
            timeout=10.0,
            check_http=False,
            live_revocation=True,
        )
        assert finding["status"] == "OK"
        assert finding["revocation_status"]["status"] == "REVOKED"
        assert "CERT_REVOKED" in finding["policy_issues"]
        assert finding["compliance_issue"] == "CERT_REVOKED"
    finally:
        server_http.close()
        tls_sock.close()
