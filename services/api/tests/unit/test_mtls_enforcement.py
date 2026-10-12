"""mTLS context enforcement (advanced/82, round 38) — real handshakes."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from api.security.mtls import MtlsError, build_mtls_context, client_context


def _make_cert(key, *, days=90, cn="api.cryproscan.internal",
               issuer=None, signer_key=None, ca=False):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
        .sign(signer_key or key, hashes.SHA256())
    )
    return builder


@pytest.fixture(scope="module")
def mtls_material(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("mtls")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _make_cert(ca_key, cn="site-ca.cryproscan.internal", ca=True)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _make_cert(server_key, cn="localhost",
                             issuer=ca_cert.subject, signer_key=ca_key)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = _make_cert(client_key, cn="soc-console",
                             issuer=ca_cert.subject, signer_key=ca_key)
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_cert = _make_cert(rogue_key, cn="rogue-client", ca=False)

    def _write(name, cert, key=None):
        cert_path = tmp / f"{name}.crt"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = None
        if key is not None:
            key_path = tmp / f"{name}.key"
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        return str(cert_path), (str(key_path) if key_path else None)

    return {
        "ca": _write("ca", ca_cert),
        "server": _write("server", server_cert, server_key),
        "client": _write("client", client_cert, client_key),
        "rogue": _write("rogue", rogue_cert, rogue_key),
        "bundle": str(tmp / "bundle.pem"),
    }


@pytest.fixture()
def mtls_server(mtls_material):
    """A real TLS server enforcing client certs; yields (host, port)."""
    ca_path, _ = mtls_material["ca"]
    cert_path, key_path = mtls_material["server"]
    context = build_mtls_context(cert_path, key_path, mtls_material["bundle"],
                                 min_version="1.2")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(10)

    def _serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"hello-mtls")
            except ssl.SSLError:
                continue  # rejected handshake — exactly the policy working
            except OSError:
                continue

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield listener.getsockname()
    listener.close()


def _bundle(mtls_material):
    import shutil
    ca_path, _ = mtls_material["ca"]
    path = mtls_material["bundle"]
    shutil.copyfile(ca_path, path)
    return path


def test_context_policy_is_cert_required_by_construction(mtls_material):
    _bundle(mtls_material)
    cert_path, key_path = mtls_material["server"]
    context = build_mtls_context(cert_path, key_path, mtls_material["bundle"])
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_context_refuses_incomplete_or_broken_material(mtls_material):
    cert_path, key_path = mtls_material["server"]
    with pytest.raises(MtlsError, match="TLS_CA_BUNDLE is required"):
        build_mtls_context(cert_path, key_path, "")
    with pytest.raises(MtlsError, match="does not exist"):
        build_mtls_context(cert_path, key_path, "/nope/bundle.pem")
    with pytest.raises(MtlsError, match="unsupported TLS_MIN_VERSION"):
        build_mtls_context(cert_path, key_path, mtls_material["bundle"],
                           min_version="1.0")


def test_handshake_rejects_clients_without_a_certificate(mtls_material, mtls_server):
    _bundle(mtls_material)
    host, port = mtls_server
    ctx = client_context()  # no client cert, no verification (test client)
    with socket.create_connection((host, port), timeout=5) as sock:
        # Under TLS 1.3 the server's rejection may surface at the first
        # read instead of the handshake — either way, NO application
        # byte may ever reach a certificate-less client.
        try:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                first = tls.recv(64)
        except ssl.SSLError:
            return  # rejected at handshake — the strictest outcome
        assert first == b""  # connection torn down, no app data


def test_handshake_accepts_site_ca_client_and_rejects_rogue_ca(mtls_material,
                                                               mtls_server):
    _bundle(mtls_material)
    host, port = mtls_server
    ca_path, _ = mtls_material["ca"]
    client_cert, client_key = mtls_material["client"]
    rogue_cert, rogue_key = mtls_material["rogue"]

    good = client_context(client_cert, client_key, ca_path)
    good.check_hostname = False  # server CN is localhost; CA is what matters
    with socket.create_connection((host, port), timeout=5) as sock:
        with good.wrap_socket(sock, server_hostname="localhost") as tls:
            assert tls.recv(64) == b"hello-mtls"

    bad = client_context(rogue_cert, rogue_key, ca_path)
    bad.check_hostname = False
    with socket.create_connection((host, port), timeout=5) as sock:
        # rejection may surface at first read (TLS 1.3 timing); either
        # way no application byte reaches a rogue-CA client
        try:
            with bad.wrap_socket(sock, server_hostname="localhost") as tls:
                first = tls.recv(64)
        except ssl.SSLError:
            return
        assert first == b""
