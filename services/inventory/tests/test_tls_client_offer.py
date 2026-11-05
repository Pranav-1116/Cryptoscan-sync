"""The client-offer probe, over owned loopback: real sockets, no customer estate.

Where the session probe dials out and records what a *server* selected, this collector
binds one approved endpoint and records what *clients* offer — the runtime acceptance
the protocol floor could not see. These tests pin the boundaries that make that evidence
honest: the probe completes no handshake (the client receives a refusal alert, never a
ServerHello), a quiet window is a failed read rather than an empty estate, and garbage
on the wire is refused rather than half-parsed.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import socket
import threading
import time

import pytest

from inventory.collection import ApprovedTlsClientOfferCollector
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostInput, HostManifest, digest
from shared_models.tls_client_offer import KIND, OPERATION
from inventory import tls_client_offer as probe_module


def hello(*, legacy=0x0301, suites=(0x002F, 0x0035), sni="payments.bank.example", versions=None):
    """A well-formed ClientHello on the wire — TLS 1.0-era unless versions are given."""
    body = legacy.to_bytes(2, "big") + b"\x22" * 32 + b"\x00"
    body += (2 * len(suites)).to_bytes(2, "big") + b"".join(s.to_bytes(2, "big") for s in suites)
    body += b"\x01\x00"
    exts = b""
    if versions is not None:
        payload = bytes([2 * len(versions)]) + b"".join(v.to_bytes(2, "big") for v in versions)
        exts += (43).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if sni is not None:
        name = sni.encode()
        inner = b"\x00" + len(name).to_bytes(2, "big") + name
        payload = len(inner).to_bytes(2, "big") + inner
        exts += (0).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if exts:
        body += len(exts).to_bytes(2, "big") + exts
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    # on the wire a handshake travels inside a TLS record; the probe reads the record
    # framing first and parses one handshake message out of it
    return b"\x16\x03\x01" + len(message).to_bytes(2, "big") + message


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def target(port, *, operation=OPERATION, kind=KIND, path=None):
    now = datetime.now(timezone.utc)
    address = f"127.0.0.1:{port}"
    manifest = HostManifest(
        approval_reference="fixture/approved-client-offer",
        host_id="fixture-offer-scope",
        environment="test",
        platform="linux",
        expires_at=now + timedelta(minutes=5),
        inputs=[HostInput(input_id="offers", kind=kind, path=path or f"tls-client-offer://{address}")],
    )
    return TargetSpec(
        target_key="fixture-offer",
        system_id="system-a",
        owner="Synthetic owner",
        environment="test",
        collection_method="network",
        address=address,
        allowed_operations=[operation],
        not_before=now - timedelta(seconds=1),
        manifest=manifest,
    )


def connect_and_send(port, payload, *, wait=3.0, expect_alert=True):
    """Connect to the probe from another thread; return what the probe sent back."""
    deadline = time.monotonic() + wait
    reply = b""
    while True:
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise AssertionError("the probe never bound its approved endpoint")
            time.sleep(0.02)
    try:
        client.sendall(payload)
        if expect_alert:
            client.settimeout(3.0)
            try:
                reply = client.recv(64)
            except socket.timeout:
                reply = b""
    finally:
        client.close()
    return reply


@pytest.fixture(autouse=True)
def short_window(monkeypatch):
    monkeypatch.setattr(probe_module, "WINDOW_SECONDS", 2.0)


def test_a_connecting_client_is_recorded_at_the_wire_never_at_its_config():
    port = free_port()
    t = target(port)
    received = {}
    thread = threading.Thread(target=lambda: received.update(reply=connect_and_send(port, hello())))
    thread.start()
    snapshot = ApprovedTlsClientOfferCollector().collect(t)
    thread.join()

    receipt = snapshot.receipts[0]
    assert receipt.status == "PARSED", receipt
    assert len(receipt.facts) == 1
    fact = receipt.facts[0]
    # the offer is what arrived on the wire: a TLS 1.0-era clienthello with no
    # supported_versions extension offers its legacy_version
    assert fact.offered_versions == ["TLSv1.0"]
    assert fact.versions_field == "legacy_version"
    # two RSA-era suites this build has no name for are echoed as codepoints
    assert fact.offered_cipher_suites == ["0x002F", "0x0035"]
    assert fact.sni == "payments.bank.example"
    assert fact.local_basis == "OBSERVED"
    assert fact.handshake_completed is False and fact.application_data_sent is False
    assert fact.reviewed_target_sha256 == digest(t) and fact.authorized_operation == OPERATION
    assert fact.bind_address == "127.0.0.1" and fact.bind_port == port
    assert fact.client_address == "127.0.0.1"
    # the receipt commits to the bounded observation record as collected
    assert len(receipt.content_sha256) == 64
    assert receipt.byte_count >= fact.wire_bytes_received


def test_the_probe_completes_no_handshake():
    port = free_port()
    t = target(port)
    received = {}
    thread = threading.Thread(target=lambda: received.update(reply=connect_and_send(port, hello())))
    thread.start()
    ApprovedTlsClientOfferCollector().collect(t)
    thread.join()

    # the client gets the same refusal alert every time and never a ServerHello
    assert received["reply"] == probe_module.ALERT_HANDSHAKE_FAILURE
    assert received["reply"][:1] == b"\x15"  # alert record, not handshake record 0x16


def test_a_quiet_window_is_a_failed_read_not_an_empty_estate():
    port = free_port()
    snapshot = ApprovedTlsClientOfferCollector().collect(target(port))

    receipt = snapshot.receipts[0]
    assert receipt.status == "UNAVAILABLE"
    assert receipt.reason == "TLS_TIMEOUT"
    # a failed read prints no facts and no zeros: no client was observed, which is not
    # "no client is below the floor"
    assert receipt.facts == [] and receipt.content_sha256 is None


def test_garbage_on_the_wire_is_refused_not_half_parsed():
    port = free_port()
    t = target(port)
    thread = threading.Thread(target=lambda: connect_and_send(port, b"\x16\x03\x01\x00\x04ABCD"))
    thread.start()
    snapshot = ApprovedTlsClientOfferCollector().collect(t)
    thread.join()

    receipt = snapshot.receipts[0]
    assert receipt.status == "INVALID"
    assert receipt.reason == "INVALID_FORMAT"
    assert receipt.facts == []


def test_two_clients_two_offers_never_one_merged_fact():
    port = free_port()
    t = target(port)
    threads = [
        threading.Thread(target=connect_and_send, args=(port, hello()), kwargs={"expect_alert": True}),
        threading.Thread(target=connect_and_send, args=(port, hello(sni="other.bank.example"))),
    ]
    for thread in threads:
        thread.start()
        time.sleep(0.15)  # distinct client ports
    snapshot = ApprovedTlsClientOfferCollector().collect(t)
    for thread in threads:
        thread.join()

    facts = snapshot.receipts[0].facts
    assert len(facts) == 2
    assert {fact.sni for fact in facts} == {"payments.bank.example", "other.bank.example"}
    assert len({fact.client_port for fact in facts}) == 2


def test_the_observation_endpoint_must_be_the_approved_one():
    port = free_port()
    with pytest.raises(ValueError, match="Exact single-endpoint"):
        ApprovedTlsClientOfferCollector().validate_scope(target(port, operation="READ_APPROVED_METADATA"))
    session_path = f"tls-session://127.0.0.1:{port}/sni/fixture.example/version/TLSv1.2/peer/sha256/{'a' * 64}"
    with pytest.raises(ValueError, match="Exact single-endpoint"):
        ApprovedTlsClientOfferCollector().validate_scope(target(port, kind="NETWORK_TLS_SESSION",
                                                                path=session_path))
    # a manifest whose path points somewhere else than the target address is refused
    t = target(port, path=f"tls-client-offer://127.0.0.1:{free_port()}")
    with pytest.raises(ValueError, match="must bind the approved numeric observation endpoint"):
        ApprovedTlsClientOfferCollector().validate_scope(t)


def test_health_states_what_this_collector_is():
    health = ApprovedTlsClientOfferCollector().health()

    assert health["inbound_observation"] is True
    assert health["handshake_completed"] is False
    assert health["production_execution_qualified"] is False
