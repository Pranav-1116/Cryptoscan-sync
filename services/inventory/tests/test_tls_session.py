"""Owned loopback TLS tests only. No bank/public endpoint or qualification claim."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import pytest
from inventory.collection import ApprovedTlsSessionCollector, OfflineLinuxCollector, OfflineContainerCollector
from inventory.host import collect
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot, digest
from shared_models.host_runtime import domains
from shared_models.tls_session import OPERATION, selected_bytes, tls_resource


@contextmanager
def server(tmp_path, version="TLSv1.3", stall=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
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
        .not_valid_after(now + timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    cp, kp = tmp_path / "public.pem", tmp_path / "fixture-key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = getattr(ssl.TLSVersion, version.replace(".", "_"))
    context.load_cert_chain(cp, kp)
    state = {"connections": 0, "sni": [], "application": []}
    context.set_servername_callback(lambda obj, hostname, ctx: state["sni"].append(hostname))
    stop = threading.Event()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.1)
    state["port"] = listener.getsockname()[1]
    state["pin"] = hashlib.sha256(der).hexdigest()

    def run():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            state["connections"] += 1
            with conn:
                conn.settimeout(3)
                try:
                    if stall:
                        stop.wait(3)
                    else:
                        with context.wrap_socket(conn, server_side=True) as tls:
                            state["application"].append(tls.recv(1))
                except (ssl.SSLError, OSError):
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


def target(state, version="TLSv1.3"):
    now = datetime.now(timezone.utc)
    address = f"127.0.0.1:{state['port']}"
    uri = f"tls-session://{address}/sni/fixture.example/version/{version}/peer/sha256/{state['pin']}"
    manifest = HostManifest(
        approval_reference="fixture/approved-active-tls",
        host_id="fixture-tls-scope",
        environment="test",
        platform="linux",
        expires_at=now + timedelta(minutes=5),
        inputs=[HostInput(input_id="session", kind="NETWORK_TLS_SESSION", path=uri)],
    )
    return TargetSpec(
        target_key="fixture-tls",
        system_id="system-a",
        owner="Synthetic owner",
        environment="test",
        collection_method="network",
        address=address,
        allowed_operations=[OPERATION],
        not_before=now - timedelta(seconds=1),
        manifest=manifest,
    )


@pytest.mark.parametrize("version", ["TLSv1.2", "TLSv1.3"])
def test_owned_single_tls_session_no_dns_retry_or_application_data(tmp_path, monkeypatch, version):
    def forbidden(*args, **kwargs):
        raise AssertionError("DNS/discovery forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with server(tmp_path, version) as state:
        t = target(state, version)
        s = ApprovedTlsSessionCollector().collect(t)
        r = s.receipts[0]
        assert r.status == "PARSED", r
        f = r.facts[0]
        assert f.reviewed_target_sha256 == digest(t) and f.authorized_operation == OPERATION
        assert state["connections"] == 1 and state["sni"] == ["fixture.example"]
        assert f.tls_version == version and f.certificate.fingerprint_sha256 == state["pin"]
        assert f.certificate.algorithm == "RSA" and f.certificate.key_size == 2048
        assert f.algorithm == f.runtime_use == f.key_exchange_group == f.server_signature_scheme == "UNKNOWN"
        assert f.peer_fingerprint_matched and f.negotiated_session_observed
        assert not f.hostname_validated and not f.certificate_chain_validated and not f.all_tls_versions_tested
        assert r.byte_count == f.wire_bytes_sent + f.wire_bytes_received + f.peer_der_bytes + len(selected_bytes(f))
        assert hashlib.sha256(selected_bytes(f)).hexdigest() == r.content_sha256 == f.interface_sha256
        assert domains(f) == ["CBOM", "NBOM", "TechBOM"]
        HostSnapshot.model_validate(s.model_dump(mode="json"))
    assert not any(state["application"])


@pytest.mark.parametrize(
    "patch",
    [
        {"collection_method": "offline_host"},
        {"allowed_operations": ["READ_APPROVED_METADATA"]},
        {"credential_ref": "vault://fixture/forbidden"},
        {"environment": "other"},
        {"address": "fixture.example:443"},
        {"exclusions": ["session"]},
        {"not_before": datetime.now(timezone.utc) + timedelta(days=1)},
    ],
)
def test_preflight_scope_refuses_without_any_socket(monkeypatch, patch):
    t = target({"port": 443, "pin": "a" * 64}).model_copy(update=patch)

    def forbidden(*args):
        raise AssertionError("Socket allocated outside scope")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ValueError):
        ApprovedTlsSessionCollector().collect(t)


@pytest.mark.parametrize(
    "path",
    [
        "tls-session://fixture.example:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.01:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:0443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:65536/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://0.0.0.0:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://224.0.0.1:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:443/sni/*.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:443/sni/fixture.example./version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:443/sni/FIXTURE.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:443/sni/127.0.0.1/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://[fe80::1]:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64,
        "tls-session://127.0.0.1:443/sni/fixture.example/version/TLSv1.0/peer/sha256/" + "a" * 64,
    ],
)
def test_noncanonical_resources_reject_without_probe(path):
    with pytest.raises(ValueError):
        HostInput(input_id="bad", kind="NETWORK_TLS_SESSION", path=path)


def test_canonical_ipv6_is_exact_not_expanded():
    assert tls_resource("tls-session://[::1]:443/sni/fixture.example/version/TLSv1.3/peer/sha256/" + "a" * 64)[:2] == (
        "::1",
        443,
    )


def test_bare_host_and_other_wrappers_cannot_probe(monkeypatch):
    t = target({"port": 443, "pin": "a" * 64})

    def forbidden(*args):
        raise AssertionError("Active bypass")

    monkeypatch.setattr(socket, "socket", forbidden)
    r = collect(t.manifest).receipts[0]
    assert r.status == "DENIED" and r.reason == "ACTIVE_PROBE_NOT_AUTHORIZED" and not r.facts
    with pytest.raises(ValueError):
        OfflineLinuxCollector().collect(t.model_copy(update={"collection_method": "offline_host"}))
    with pytest.raises(ValueError):
        OfflineContainerCollector().collect(t.model_copy(update={"collection_method": "container"}))


@pytest.mark.parametrize("mode", ["pin", "version", "budget", "expired"])
def test_gaps_not_no_tls_and_never_retry(tmp_path, mode):
    with server(tmp_path) as state:
        t = target(state)
        if mode == "pin":
            t.manifest.inputs[0] = t.manifest.inputs[0].model_copy(
                update={"path": t.manifest.inputs[0].path[:-64] + "f" * 64}
            )
        if mode == "version":
            t.manifest.inputs[0] = t.manifest.inputs[0].model_copy(
                update={"path": t.manifest.inputs[0].path.replace("TLSv1.3", "TLSv1.2")}
            )
        if mode == "budget":
            t = t.model_copy(update={"manifest": t.manifest.model_copy(update={"max_file_bytes": 100})})
        if mode == "expired":
            t = t.model_copy(
                update={
                    "manifest": t.manifest.model_copy(
                        update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}
                    )
                }
            )
        if mode == "expired":
            with pytest.raises(ValueError):
                ApprovedTlsSessionCollector().collect(t)
            assert state["connections"] == 0
            return
        r = ApprovedTlsSessionCollector().collect(t).receipts[0]
        assert r.status != "PARSED" and not r.facts and r.content_sha256 is None
        if mode == "pin":
            assert r.reason == "TLS_PEER_PIN_MISMATCH"
        if mode == "budget":
            assert r.status == "BUDGET_EXCEEDED" and state["connections"] == 0
        assert state["connections"] <= 1


def test_timeout_is_a_gap_and_socket_closed(tmp_path):
    with server(tmp_path, stall=True) as state:
        r = ApprovedTlsSessionCollector().collect(target(state)).receipts[0]
        assert r.status == "UNAVAILABLE" and r.reason == "TLS_TIMEOUT" and not r.facts
        assert state["connections"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostname_validated", True),
        ("runtime_use", "OBSERVED"),
        ("all_tls_versions_tested", True),
        ("key_exchange_group", "X25519"),
        ("application_identity_verified", True),
        ("certificate_chain_validated", True),
        ("wire_bytes_sent", 0),
        ("identity_key", "unscoped"),
    ],
)
def test_promoted_changed_or_unbound_facts_refuse(tmp_path, field, value):
    with server(tmp_path) as state:
        s = ApprovedTlsSessionCollector().collect(target(state)).model_dump(mode="json")
    s["receipts"][0]["facts"][0][field] = value
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(s)


def test_cli_requires_review_hash_acknowledgement_and_reserves_output(tmp_path):
    with server(tmp_path) as state:
        t = target(state)
        file = tmp_path / "target.json"
        file.write_text(t.model_dump_json())
        out = tmp_path / "snapshot.json"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parents[3] / "scripts/collect_tls_session.py"),
            "--target",
            str(file),
            "--approved-target-sha256",
            digest(t),
            "--output",
            str(out),
        ]
        assert subprocess.run(cmd, capture_output=True).returncode != 0 and state["connections"] == 0
        assert subprocess.run([*cmd, "--acknowledge-active-tls"], capture_output=True).returncode == 0
        assert state["connections"] == 1
        original = out.read_bytes()
        assert subprocess.run([*cmd, "--acknowledge-active-tls"], capture_output=True).returncode == 64
        assert state["connections"] == 1 and out.read_bytes() == original
        HostSnapshot.model_validate_json(original)


def test_wire_budget_and_partial_send_cleanup(monkeypatch):
    from inventory.tls_session import probe_session
    from inventory.host import Refused
    import inventory.tls_session as module

    class Incoming:
        def write(self, data):
            pass

    class Outgoing:
        pending = 4

        def read(self, n):
            self.pending = 0
            return b"abcd"

    class Engine:
        def do_handshake(self):
            raise ssl.SSLWantReadError()

    class Tcp:
        calls = 0
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.closed = True

        def settimeout(self, t):
            pass

        def connect(self, *a):
            pass

        def send(self, data):
            return min(2, len(data))

        def recv(self, n):
            self.calls += 1
            return b"x" * n

    tcp = Tcp()
    monkeypatch.setattr(module, "client_session", lambda *a: (Engine(), Incoming(), Outgoing()))
    monkeypatch.setattr(socket, "socket", lambda *a: tcp)
    t = target({"port": 443, "pin": "a" * 64})
    counts = []
    with pytest.raises(Refused) as error:
        probe_session(
            t.manifest.inputs[0], 8192, counts.append, t.manifest.expires_at, reviewed_target_sha256=digest(t)
        )
    assert error.value.status == "BUDGET_EXCEEDED" and sum(counts) == 8192 and tcp.closed and tcp.calls == 1


def test_changed_receipt_byte_count_refuses(tmp_path):
    with server(tmp_path) as state:
        value = ApprovedTlsSessionCollector().collect(target(state)).model_dump(mode="json")
    value["receipts"][0]["byte_count"] += 1
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(value)


def test_tls13_cipher_bits_cannot_be_resealed_to_impossible_suite(tmp_path):
    from shared_models.tls_session import seal_session

    with server(tmp_path) as state:
        f = ApprovedTlsSessionCollector().collect(target(state)).receipts[0].facts[0]
    values = {k: getattr(f, k) for k in type(f).model_fields if k != "interface_sha256"}
    values["cipher_suite"] = "ECDHE-RSA-AES128-GCM-SHA256"
    with pytest.raises(ValueError):
        seal_session(**values)


def test_peer_pin_scope_cannot_be_resealed_to_another_certificate(tmp_path):
    from shared_models.tls_session import seal_session

    with server(tmp_path) as state:
        snapshot = ApprovedTlsSessionCollector().collect(target(state))
    f = snapshot.receipts[0].facts[0]
    values = {k: getattr(f, k) for k in type(f).model_fields if k != "interface_sha256"}
    values["certificate"] = f.certificate.model_copy(update={"fingerprint_sha256": "f" * 64})
    forged = seal_session(**values)
    receipt = snapshot.receipts[0].model_copy(update={"facts": [forged], "content_sha256": forged.interface_sha256})
    bad = snapshot.model_copy(update={"receipts": [receipt]})
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(bad.model_dump(mode="json"))


def test_legacy_adapter_exposes_fresh_constrained_engine_without_connect(monkeypatch):
    from network_scanner.probing.tls_handshaker import approved_session_engine

    def forbidden(*args):
        raise AssertionError("Engine setup cannot connect")

    monkeypatch.setattr(socket, "socket", forbidden)
    first, _, _ = approved_session_engine("fixture.example", "TLSv1.3")
    second, _, _ = approved_session_engine("fixture.example", "TLSv1.3")
    assert first.context is not second.context
    assert first.context.minimum_version == first.context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert first.context.verify_mode == ssl.CERT_NONE and not first.context.check_hostname
    assert first.context.keylog_filename is None and first.context.options & ssl.OP_NO_TICKET


def test_deadline_stops_io_and_closes_connection(monkeypatch):
    from inventory.tls_session import probe_session
    from inventory.host import Refused
    import inventory.tls_session as module

    class Tcp:
        closed = False
        connected = 0

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.closed = True

        def settimeout(self, t):
            assert 0 < t <= 2

        def connect(self, *a):
            self.connected += 1

    tcp = Tcp()
    clock = iter([100.0, 100.0, 100.0, 109.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(socket, "socket", lambda *a: tcp)
    t = target({"port": 443, "pin": "a" * 64})
    with pytest.raises(Refused) as error:
        probe_session(
            t.manifest.inputs[0], 8192, lambda n: None, t.manifest.expires_at, reviewed_target_sha256=digest(t)
        )
    assert error.value.reason == "TLS_TIMEOUT" and tcp.closed and tcp.connected == 1


def test_expiry_before_socket_allocation(monkeypatch):
    from inventory.tls_session import probe_session
    from inventory.host import Refused

    t = target({"port": 443, "pin": "a" * 64})

    def forbidden(*a):
        raise AssertionError("Expired approval must not allocate socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(Refused) as error:
        probe_session(
            t.manifest.inputs[0],
            8192,
            lambda n: None,
            datetime.now(timezone.utc) - timedelta(seconds=1),
            reviewed_target_sha256=digest(t),
        )
    assert error.value.reason == "EXPIRED"


def test_missing_peer_certificate_is_handshake_gap_not_byte_limit(monkeypatch):
    from inventory.tls_session import probe_session
    from inventory.host import Refused
    import inventory.tls_session as module

    class Engine:
        def do_handshake(self):
            pass

        def getpeercert(self, **kwargs):
            return None

    class Empty:
        pending = 0

    class Tcp:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.closed = True

        def settimeout(self, t):
            pass

        def connect(self, *a):
            pass

    tcp = Tcp()
    monkeypatch.setattr(module, "client_session", lambda *a: (Engine(), Empty(), Empty()))
    monkeypatch.setattr(socket, "socket", lambda *a: tcp)
    t = target({"port": 443, "pin": "a" * 64})
    with pytest.raises(Refused) as error:
        probe_session(
            t.manifest.inputs[0], 8192, lambda n: None, t.manifest.expires_at, reviewed_target_sha256=digest(t)
        )
    assert error.value.status == "UNAVAILABLE" and error.value.reason == "TLS_HANDSHAKE_FAILED" and tcp.closed


@pytest.mark.parametrize("mode", ["hash", "existing", "symlink"])
def test_cli_preflight_refuses_before_active_execution(tmp_path, monkeypatch, mode):
    import collect_tls_session as cli

    t = target({"port": 443, "pin": "a" * 64})
    file = tmp_path / "target.json"
    file.write_text(t.model_dump_json())
    out = tmp_path / "snapshot.json"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"unchanged")
    if mode == "existing":
        out.write_bytes(b"original")
    if mode == "symlink":
        out.symlink_to(sentinel)
    calls = []

    def forbidden(*a):
        calls.append("probe")
        raise AssertionError("No active work before preflight")

    monkeypatch.setattr(ApprovedTlsSessionCollector, "collect", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_tls_session",
            "--target",
            str(file),
            "--output",
            str(out),
            "--approved-target-sha256",
            "0" * 64 if mode == "hash" else digest(t),
            "--acknowledge-active-tls",
        ],
    )
    assert cli.main() == 64 and calls == [] and sentinel.read_bytes() == b"unchanged"
    if mode == "existing":
        assert out.read_bytes() == b"original"


def test_selected_budget_is_charged_before_sealing_profile_limit(tmp_path):
    from inventory.host import Refused
    from shared_models.tls_session import seal_session, WIRE_LIMIT

    with server(tmp_path) as state:
        f = ApprovedTlsSessionCollector().collect(target(state)).receipts[0].facts[0]
    values = {k: getattr(f, k) for k in type(f).model_fields if k != "interface_sha256"}
    values["wire_bytes_received"] = WIRE_LIMIT - f.wire_bytes_sent - f.peer_der_bytes - 100
    charged = []

    def charge(data):
        charged.append(min(100, len(data)))
        if len(data) > 100:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")

    with pytest.raises(Refused) as error:
        seal_session(on_selected=charge, **values)
    assert error.value.status == "BUDGET_EXCEEDED" and charged == [100]
