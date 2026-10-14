"""Local mock-bank TLS harness — a deterministic, zero-auth test target (§4.4).

The bank-sandbox portals (Plaid, Open Bank Project, QNB, Emirates NBD,
Neotek, …) need registrations, keys and network access this environment
does not have. What a CBOM tool actually needs from them is a **TLS
endpoint with a known handshake**: a certificate, a pinned protocol
version and a pinned cipher list. That can be served locally with no
keys, no registration and no network — deterministically, which the real
portals are not.

:class:`MockBankTLS` runs a threaded TLS listener on an ephemeral port
with a freshly generated self-signed certificate and whatever protocol /
cipher pins the test asks for, and answers each connection with a minimal
HTTP response (so ALPN and the prober's HTTP-header check exercise too).
Use it to test the whole live-handshake path — ``probe_endpoint`` →
``cbom.nbom.probe_to_endpoint`` → ``build_nbom`` — with outcomes you can
assert, not hope for.

This is a TEST/DEMO harness, not a scanner and not a real bank: its
certificate asserts nothing and it must never be pointed at as evidence
of external coverage.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Sequence

__all__ = ["MockBankTLS"]

_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b'Content-Length: 47\r\n'
    b"Connection: close\r\n"
    b"\r\n"
    b'{"bank": "mock", "accounts": [], "currency": "AED"}'
)


class MockBankTLS:
    """A self-signed TLS listener with pinned protocol/ciphers, on loopback.

    * ``max_tls_version`` / ``min_tls_version`` — ``"1.2"``, ``"1.3"`` …
    * ``ciphers`` — an OpenSSL cipher-list string pinned via
      ``SSLContext.set_ciphers`` (e.g. ``"ECDHE-RSA-AES128-GCM-SHA256"``);
      TLS 1.3 suites cannot be pinned this way (they are policy) — pin
      ``max_tls_version="1.2"`` when you need an exact negotiated suite.
    * ``key_size`` — RSA key size of the generated self-signed leaf.
    """

    def __init__(
        self,
        *,
        min_tls_version: str = "1.2",
        max_tls_version: str = "1.3",
        ciphers: str | None = None,
        key_size: int = 2048,
        common_name: str = "mock-bank.local",
        alpn: Sequence[str] = ("http/1.1",),
    ) -> None:
        self._min = getattr(ssl.TLSVersion, f"TLSv{min_tls_version.replace('.', '_')}")
        self._max = getattr(ssl.TLSVersion, f"TLSv{max_tls_version.replace('.', '_')}")
        self._ciphers = ciphers
        self._key_size = key_size
        self._cn = common_name
        self._alpn = list(alpn)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self.port: int | None = None

    # -- lifecycle ------------------------------------------------------

    @property
    def endpoint(self) -> str:
        if self.port is None:
            raise RuntimeError("MockBankTLS not started")
        return f"127.0.0.1:{self.port}"

    def start(self, *, timeout: float = 10.0) -> str:
        """Bind, listen and serve on a thread. Returns host:port."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = self._min
        ctx.maximum_version = self._max
        if self._ciphers:
            ctx.set_ciphers(self._ciphers)
        if self._alpn:
            ctx.set_alpn_protocols(self._alpn)
        ctx.load_cert_chain(self._cert_file(), self._key_file())

        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, args=(ctx,), daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):  # pragma: no cover - slow hosts
            raise RuntimeError("MockBankTLS failed to start serving")
        return self.endpoint

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "MockBankTLS":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    # -- internals ------------------------------------------------------

    def _serve(self, ctx: ssl.SSLContext) -> None:
        self._started.set()
        while not self._stop.is_set():
            try:
                assert self._sock is not None
                conn, _ = self._sock.accept()
            except OSError:
                break  # listener closed — shutdown
            try:
                conn.settimeout(5)
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    try:
                        tls.read(1024)  # drain the client's request line
                    except (OSError, ssl.SSLError):
                        pass
                    try:
                        tls.write(_RESPONSE)
                    except (OSError, ssl.SSLError):
                        pass
            except (OSError, ssl.SSLError):
                try:
                    conn.close()
                except OSError:
                    pass

    def _cert_file(self) -> str:
        import tempfile, os

        cert, key = _self_signed_pair(cn=self._cn, key_size=self._key_size)
        self._tmpdir = tempfile.mkdtemp(prefix="mock-bank-tls-")
        cert_path = os.path.join(self._tmpdir, "cert.pem")
        key_path = os.path.join(self._tmpdir, "key.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert)
        with open(key_path, "wb") as fh:
            fh.write(key)
        return cert_path  # noqa: RET504 — key file read via _key_file()

    def _key_file(self) -> str:
        import os

        return os.path.join(self._tmpdir, "key.pem")


def _self_signed_pair(*, cn: str, key_size: int, days: int = 825) -> tuple[bytes, bytes]:
    """A fresh self-signed RSA leaf + key in PEM form."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem
