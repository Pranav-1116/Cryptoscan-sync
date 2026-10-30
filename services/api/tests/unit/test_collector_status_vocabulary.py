"""A collector's outcome uses the engine's vocabulary, and a refusal carries its report.

Two failures from a real run, both fixed here:

* the network collector emitted its own word ``NO_TARGET`` for "named targets, no
  result", and the estate engine rejected the whole payload with
  ``unknown collector status 'NO_TARGET'`` — a 422 for a *correct* observation
  about a plane nobody could reach;
* that 422 carried only the engine's complaint, so the twenty per-target errors
  that explained it were discarded. A refusal has to carry the report that
  caused it.
"""
from __future__ import annotations

import socket

import pytest

from shared_models.estate_graph import collector_outcome

from api import host_collect


def test_the_engine_accepts_the_coverage_word_for_a_missed_target():
    """``NO_TARGET`` is the coverage vocabulary's word; it means FAILED here."""
    outcome = collector_outcome("NETWORK", "NO_TARGET", expected=20, collected=0)
    assert outcome["status"] == "FAILED"
    assert outcome["impact"]  # a failed plane is unknown, never empty


def test_an_unknown_word_is_still_refused():
    with pytest.raises(ValueError):
        collector_outcome("NETWORK", "MOSTLY_FINE")


def _closed_port() -> int:
    """A port nothing is listening on, so the handshake really fails."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_no_target_negotiating_is_a_failed_plane_not_an_empty_one():
    port = _closed_port()
    package = host_collect.collect_network([f"127.0.0.1:{port}"], timeout=1.0)

    assert package["collector"]["status"] == "FAILED"
    assert package["collector"]["expected"] == 1
    assert package["collector"]["collected"] == 0
    assert "unknown, not empty" in package["collector"]["impact"]
    # and the target itself is a coverage row, not a silent omission
    assert package["coverage"][0]["status"] == "NOT_OBSERVED"
    assert package["coverage"][0]["target"] == f"127.0.0.1:{port}"


def _loopback_tls_service():
    """A real TLS listener on loopback, carrying a certificate generated here.

    The partial-plane case needs one target that negotiates and one that does
    not. Nothing synthetic is needed for that: generate a throw-away EC
    certificate, serve it on 127.0.0.1, and point the collector at it.
    """
    import datetime
    import ssl
    import tempfile
    import threading
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    work = Path(tempfile.mkdtemp(prefix="collect-status-"))
    cert_path, key_path = work / "cert.pem", work / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.2)
    port = int(listener.getsockname()[1])
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(1.0)
                    try:
                        tls.recv(1)
                    except (ssl.SSLError, OSError):
                        pass
            except (ssl.SSLError, OSError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()

    def shutdown() -> None:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass

    return port, shutdown


def test_a_partly_reachable_plane_is_partial():
    """One target that negotiates and one that does not is PARTIAL, not COMPLETE."""
    pytest.importorskip("cryptography")
    port, shutdown = _loopback_tls_service()
    try:
        package = host_collect.collect_network(
            [f"127.0.0.1:{port}", f"127.0.0.1:{_closed_port()}"], timeout=2.0
        )
    finally:
        shutdown()

    assert package["collector"]["collected"] == 1, package["collector"]
    assert package["collector"]["status"] == "PARTIAL"
