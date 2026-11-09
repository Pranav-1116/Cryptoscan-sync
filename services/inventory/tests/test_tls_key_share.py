"""Real classical TLS only on owned loopback. Hybrid vectors are parser fixtures."""

import hashlib
import subprocess
import sys
from pathlib import Path
import pytest
from services.inventory.tests.test_tls_session import server, target
from inventory.collection import ApprovedTlsSessionCollector, OfflineLinuxCollector
from inventory.host import collect
from shared_models.host_collection import HostInput, HostSnapshot, digest
from shared_models.tls_key_share import (
    KIND,
    HRR_RANDOM,
    GROUPS,
    SUITES,
    ServerHelloReader,
    TlsKeyShareFact,
    parse_hello,
    group_classification,
)
from shared_models.tls_session import seal_session, selected_bytes


def key_target(state):
    t = target(state)
    i = t.manifest.inputs[0]
    t.manifest.inputs[0] = HostInput(
        input_id=i.input_id, kind=KIND, path=i.path.replace("tls-session://", "tls-key-share://")
    )
    return t


def hello(group=29, *, retry=False, cipher=0x1302, extra=b"", share_length=None):
    length = share_length if share_length is not None else {23: 65, 24: 97, 25: 133, 29: 32, 30: 56}.get(group, 1120)
    share = group.to_bytes(2, "big") if retry else group.to_bytes(2, "big") + length.to_bytes(2, "big") + b"x" * length
    extensions = b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33" + len(share).to_bytes(2, "big") + share + extra
    body = (
        b"\x03\x03"
        + (HRR_RANDOM if retry else b"x" * 32)
        + b"\x00"
        + cipher.to_bytes(2, "big")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return b"\x02" + len(body).to_bytes(3, "big") + body


def record(data, kind=22):
    return bytes([kind]) + b"\x03\x03" + len(data).to_bytes(2, "big") + data


def test_owned_tls13_actual_final_server_hello_and_legacy_profile_unchanged(tmp_path, monkeypatch):
    import socket

    def forbidden(*a):
        raise AssertionError("No DNS")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with server(tmp_path) as state:
        t = key_target(state)
        with pytest.raises(ValueError):
            ApprovedTlsSessionCollector().collect(t)
        assert state["connections"] == 0
        s = ApprovedTlsSessionCollector(include_key_share=True).collect(t)
        r = s.receipts[0]
        assert r.status == "PARSED", r
        f = r.facts[0]
        assert isinstance(f, TlsKeyShareFact)
        retry, group, cipher = parse_hello(bytes.fromhex(f.server_hello_hex))
        assert not retry and GROUPS.get(group, "UNKNOWN") == f.key_exchange_group and SUITES[cipher] == f.cipher_suite
        assert f.group_classification == group_classification(group)
        # A hybrid ServerHello is an observed selection, not an assurance
        # that a PQC implementation or end-to-end use was verified.
        assert f.certificate.algorithm == "RSA" and f.key_exchange_group != "RSA"
        assert f.runtime_use == f.operation_use == f.pqc_assessment == f.server_signature_scheme == "UNKNOWN"
        assert not f.pqc_implementation_verified and not f.pqc_readiness_verified and not f.all_groups_tested
        assert r.byte_count == f.wire_bytes_sent + f.wire_bytes_received + f.peer_der_bytes + len(
            bytes.fromhex(f.server_hello_hex)
        ) + len(selected_bytes(f))
        assert state["connections"] == 1
        HostSnapshot.model_validate(s.model_dump(mode="json"))


@pytest.mark.parametrize("split", range(1, 16))
def test_fragmented_records_and_tcp_chunks(split):
    data = hello()
    wire = record(data[:split]) + record(data[split:])
    reader = ServerHelloReader()
    for i in range(0, len(wire), split):
        reader.feed(wire[i : i + split])
    assert reader.final == data and not reader.retries
    reader.feed(b"encrypted/app bytes are ignored after final public hello")


def test_retry_is_not_selected_until_final_and_allows_compat_ccs():
    reader = ServerHelloReader()
    reader.feed(record(hello(retry=True)))
    assert reader.final is None and reader.retries == 1
    reader.feed(record(b"\x01", 20) + record(hello()))
    assert reader.final == hello()


@pytest.mark.parametrize(
    "data",
    [
        record(hello(retry=True)) + record(hello(retry=True)),
        record(hello(retry=True)) + record(hello(group=23)),
        record(hello()[:-1]),
        b"\x16\x03\x03\xff\xff",
        record(hello(extra=b"\x00\x2b\x00\x02\x03\x04")),
        record(hello(extra=b"\x00\x29\x00\x02\x00\x01")),
        record(hello(share_length=31)),
        record(hello(cipher=0x1304)),
        record(b"\x01\x00\xff\xff"),
        record(b"\x00", 23),
    ],
)
def test_malformed_public_hellos_never_become_positive(data):
    reader = ServerHelloReader()
    try:
        reader.feed(data)
    except ValueError:
        pass
    assert reader.final is None


@pytest.mark.parametrize("group", [0x11EB, 0x11EC, 0x11ED])
def test_hybrid_parser_vectors_not_actual_pqc_execution(group):
    retry, actual, cipher = parse_hello(hello(group))
    assert not retry and actual == group and group_classification(group) == "REGISTERED_HYBRID_GROUP_SELECTED"
    assert group_classification(65000) == "UNRECOGNIZED_GROUP"


def test_retry_never_validates_as_final_fact(tmp_path):
    with server(tmp_path) as state:
        f = ApprovedTlsSessionCollector(include_key_share=True).collect(key_target(state)).receipts[0].facts[0]
    values = {k: getattr(f, k) for k in type(f).model_fields if k != "interface_sha256"}
    data = hello(retry=True)
    values.update(server_hello_hex=data.hex(), server_hello_sha256=hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError):
        seal_session(fact_model=TlsKeyShareFact, **values)


@pytest.mark.parametrize(
    "patch",
    [
        {"selected_group_id": 23},
        {"key_exchange_group": "RSA"},
        {"group_classification": "opposite_observed"},
        {"pqc_assessment": "READY"},
        {"pqc_readiness_verified": True},
        {"all_groups_tested": True},
        {"runtime_use": "OBSERVED"},
        {"server_hello_sha256": "a" * 64},
        {"application_identity_verified": True},
    ],
)
def test_resealed_false_group_or_promoted_use_refuses(tmp_path, patch):
    with server(tmp_path) as state:
        f = ApprovedTlsSessionCollector(include_key_share=True).collect(key_target(state)).receipts[0].facts[0]
    values = {k: getattr(f, k) for k in type(f).model_fields if k != "interface_sha256"}
    if patch.get("group_classification") == "opposite_observed":
        patch = {"group_classification": (
            "REGISTERED_CLASSICAL_GROUP_SELECTED"
            if f.group_classification == "REGISTERED_HYBRID_GROUP_SELECTED"
            else "REGISTERED_HYBRID_GROUP_SELECTED")}
    values.update(patch)
    with pytest.raises(ValueError):
        seal_session(fact_model=TlsKeyShareFact, **values)


def test_bare_and_offline_wrapper_cannot_activate_key_share(monkeypatch):
    import socket

    t = key_target({"port": 443, "pin": "a" * 64})

    def forbidden(*a):
        raise AssertionError("No implicit probe")

    monkeypatch.setattr(socket, "socket", forbidden)
    assert collect(t.manifest).receipts[0].reason == "ACTIVE_PROBE_NOT_AUTHORIZED"
    with pytest.raises(ValueError):
        OfflineLinuxCollector().collect(t.model_copy(update={"collection_method": "offline_host"}))


def test_cli_requires_optin_and_target_changed_hash(tmp_path):
    with server(tmp_path) as state:
        t = key_target(state)
        path = tmp_path / "target.json"
        path.write_text(t.model_dump_json())
        out = tmp_path / "snapshot.json"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parents[3] / "scripts/collect_tls_session.py"),
            "--target",
            str(path),
            "--output",
            str(out),
            "--approved-target-sha256",
            digest(t),
            "--acknowledge-active-tls",
        ]
        assert subprocess.run(cmd, capture_output=True).returncode == 64 and state["connections"] == 0
        assert subprocess.run([*cmd, "--include-key-share"], capture_output=True).returncode == 0
        assert state["connections"] == 1
        HostSnapshot.model_validate_json(out.read_bytes())


def test_zero_record_flood_and_retry_cipher_change_refuse():
    with pytest.raises(ValueError):
        ServerHelloReader().feed(record(b"") * 129)
    reader = ServerHelloReader()
    reader.feed(record(hello(retry=True)))
    with pytest.raises(ValueError):
        reader.feed(record(hello(cipher=0x1301)))


def test_tls12_cannot_claim_tls13_key_share_resource():
    with pytest.raises(ValueError):
        HostInput(
            input_id="bad",
            kind=KIND,
            path="tls-key-share://127.0.0.1:443/sni/fixture.example/version/TLSv1.2/peer/sha256/" + "a" * 64,
        )
