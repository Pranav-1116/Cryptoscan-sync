"""Real hybrid TLS over owned loopback. No customer/HSM/native qualification."""

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import socket
import threading
import pytest
from services.inventory.tests.test_tls_session import target, server as classical_server
from inventory.collection import ApprovedTlsSessionCollector
from shared_models.host_collection import HostInput, HostSnapshot
from shared_models.tls_hybrid import KIND, TlsHybridFact
from shared_models.tls_key_share import parse_hello


@contextmanager
def hybrid_server():
    pytest.importorskip("OpenSSL", minversion="26.4.0", reason="Optional actual-hybrid validation provider")
    from OpenSSL import SSL
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .sign(key, hashes.SHA256())
    )
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_certificate(cert)
    ctx.use_privatekey(key)
    ctx.set_options(SSL.OP_NO_TICKET)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(0.1)
    stop = threading.Event()
    done = threading.Event()
    state = {
        "port": listener.getsockname()[1],
        "pin": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "connections": 0,
        "completed": False,
        "done": done,
    }

    def run():
        while not stop.is_set():
            try:
                tcp, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            state["connections"] += 1
            with tcp:
                tcp.settimeout(2)
                tls = SSL.Connection(ctx, None)
                tls.set_accept_state()
                try:
                    for _ in range(512):
                        complete = False
                        need = False
                        try:
                            tls.do_handshake()
                            complete = True
                        except SSL.WantReadError:
                            need = True
                        except SSL.WantWriteError:
                            pass
                        while True:
                            try:
                                data = tls.bio_read(16384)
                            except SSL.WantReadError:
                                break
                            tcp.sendall(data)
                        if complete:
                            state["completed"] = True
                            done.set()
                            break
                        if need:
                            data = tcp.recv(16384)
                            if not data:
                                break
                            tls.bio_write(data)
                except (OSError, SSL.Error):
                    pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        listener.close()
        thread.join(4)
        assert not thread.is_alive()


def hybrid_target(state):
    t = target(state)
    i = t.manifest.inputs[0]
    t.manifest.inputs[0] = HostInput(
        input_id=i.input_id,
        kind=KIND,
        path=i.path.replace("tls-session://", "tls-hybrid://").replace("/peer/", "/group/X25519MLKEM768/peer/"),
    )
    return t


def test_actual_x25519_mlkem768_tcp_handshake_both_peers_finish():
    with hybrid_server() as state:
        t = hybrid_target(state)
        with pytest.raises(ValueError):
            ApprovedTlsSessionCollector(include_key_share=True).collect(t)
        assert state["connections"] == 0
        s = ApprovedTlsSessionCollector(include_hybrid=True).collect(t)
        r = s.receipts[0]
        assert r.status == "PARSED", r
        f = r.facts[0]
        assert isinstance(f, TlsHybridFact)
        from shared_models.host_runtime import domains

        assert domains(f) == ["CBOM", "NBOM", "TechBOM"]
        assert f.hybrid_session_completed and f.selected_group_id == 4588 and f.key_exchange_group == "X25519MLKEM768"
        assert parse_hello(bytes.fromhex(f.server_hello_hex))[1] == 4588
        assert state["done"].wait(2) and state["completed"] and state["connections"] == 1
        assert f.pqc_implementation_verified is False and f.pqc_readiness_verified is False
        assert f.runtime_use == f.operation_use == "UNKNOWN" and f.application_identity_verified is False
        assert f.openssl_version.startswith("OpenSSL ")
        HostSnapshot.model_validate(s.model_dump(mode="json"))


def test_classical_fallback_is_gap_not_hybrid_success(tmp_path):
    pytest.importorskip("OpenSSL", minversion="26.4.0")
    with classical_server(tmp_path) as state:
        r = ApprovedTlsSessionCollector(include_hybrid=True).collect(hybrid_target(state)).receipts[0]
        assert r.status == "UNAVAILABLE" and r.reason == "TLS_REQUIRED_GROUP_NOT_SELECTED" and not r.facts
        assert state["connections"] == 1


@pytest.mark.parametrize("prefix", ["tls-session://", "tls-key-share://"])
def test_new_profile_cannot_use_old_approved_resource(prefix):
    with pytest.raises(ValueError):
        HostInput(
            input_id="bad",
            kind=KIND,
            path=prefix + "127.0.0.1:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        )


def test_optional_provider_missing_fails_before_socket(monkeypatch):
    import builtins

    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "OpenSSL":
            raise ImportError("not installed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)

    def forbidden(*a):
        raise AssertionError("No TCP without provider")

    monkeypatch.setattr(socket, "socket", forbidden)
    r = (
        ApprovedTlsSessionCollector(include_hybrid=True)
        .collect(hybrid_target({"port": 443, "pin": "a" * 64}))
        .receipts[0]
    )
    assert r.status == "UNSUPPORTED" and not r.facts
