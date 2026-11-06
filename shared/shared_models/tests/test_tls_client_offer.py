"""The client side of a handshake, observed and sealed — never completed.

The protocol floor's leading blind spot was runtime client acceptance. These tests pin
the two rules that keep this evidence honest: an offer is never a negotiation (the
probe sends no ServerHello, so nothing may claim use), and a value the parser cannot
name is echoed verbatim rather than renamed into something plausible.
"""

import pytest

from shared_models.tls_client_offer import (
    KIND,
    client_offer_resource,
    endpoint,
    is_grease,
    parse_client_hello,
    seal_offer,
    validate_offer,
)


def hello(
    *,
    legacy=0x0303,
    suites=(0x1301, 0x00FF),
    versions=None,
    groups=None,
    sigalgs=None,
    sni=None,
    alpn=None,
    grease_suite=None,
):
    """A minimal well-formed ClientHello on the wire, with knobs for each test."""
    body = legacy.to_bytes(2, "big") + b"\x11" * 32 + b"\x00"
    all_suites = list(suites) + ([grease_suite] if grease_suite else [])
    body += (2 * len(all_suites)).to_bytes(2, "big") + b"".join(s.to_bytes(2, "big") for s in all_suites)
    body += b"\x01\x00"
    exts = b""
    if versions is not None:
        payload = bytes([2 * len(versions)]) + b"".join(v.to_bytes(2, "big") for v in versions)
        exts += (43).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if groups is not None:
        payload = (2 * len(groups)).to_bytes(2, "big") + b"".join(g.to_bytes(2, "big") for g in groups)
        exts += (10).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if sigalgs is not None:
        payload = (2 * len(sigalgs)).to_bytes(2, "big") + b"".join(s.to_bytes(2, "big") for s in sigalgs)
        exts += (13).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if sni is not None:
        name = sni.encode()
        inner = b"\x00" + len(name).to_bytes(2, "big") + name
        payload = len(inner).to_bytes(2, "big") + inner
        exts += (0).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if alpn is not None:
        inner = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        payload = len(inner).to_bytes(2, "big") + inner
        exts += (16).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if exts:
        body += len(exts).to_bytes(2, "big") + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body


def fact(**over):
    value = {
        "reviewed_target_sha256": "a" * 64,
        "bind_address": "10.0.0.9",
        "bind_port": 8443,
        "client_address": "10.0.0.5",
        "client_port": 51234,
        "sni": "payments.bank.example",
        "offered_versions": ["TLSv1.3", "TLSv1.2"],
        "offered_cipher_suites": ["TLS_AES_128_GCM_SHA256"],
        "offered_groups": ["x25519"],
        "offered_signature_algorithms": ["0x0403"],
        "alpn": ["h2"],
        "grease_values_seen": 0,
        "versions_field": "supported_versions",
        "wire_bytes_received": 128,
    }
    value.update(over)
    value.setdefault(
        "identity_key",
        "tls-client-endpoint:"
        + endpoint(value["bind_address"], value["bind_port"])
        + ":client:" + endpoint(value["client_address"], value["client_port"]),
    )
    return seal_offer(**value)


# -- the wire parser --------------------------------------------------------- #


def test_a_supported_versions_clienthello_offers_the_extension_not_the_decoy():
    parsed = parse_client_hello(hello(versions=[0x0304, 0x0303]))

    assert parsed["offered_versions"] == ["TLSv1.3", "TLSv1.2"]
    assert parsed["versions_field"] == "supported_versions"
    # legacy_version 0303 is the TLS 1.3 decoy and must not appear as its own offer
    assert parsed["legacy_version"] == "TLSv1.2"


def test_a_clienthello_without_the_extension_offers_its_legacy_version():
    parsed = parse_client_hello(hello(legacy=0x0301, versions=None))

    assert parsed["offered_versions"] == ["TLSv1.0"]
    assert parsed["versions_field"] == "legacy_version"


def test_grease_values_are_dropped_with_a_count_never_named():
    parsed = parse_client_hello(
        hello(versions=[0x7A7A, 0x0303], suites=(0x1301,), grease_suite=0x0A0A)
    )

    assert parsed["offered_versions"] == ["TLSv1.2"]
    assert "0x7A7A" not in parsed["offered_versions"]
    assert parsed["offered_cipher_suites"] == ["TLS_AES_128_GCM_SHA256"]
    assert parsed["grease_values_seen"] == 2


def test_a_value_this_build_cannot_name_is_echoed_as_its_codepoint():
    parsed = parse_client_hello(
        hello(versions=[0x1234, 0x0303], suites=(0x2F2F, 0x00FF), groups=[0x1234, 29], sigalgs=[0x0403])
    )

    assert parsed["offered_versions"] == ["0x1234", "TLSv1.2"]
    assert parsed["offered_cipher_suites"] == ["0x2F2F", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"]
    assert parsed["offered_groups"] == ["0x1234", "x25519"]
    assert parsed["offered_signature_algorithms"] == ["0x0403"]


def test_sni_and_alpn_are_read_only_when_present():
    parsed = parse_client_hello(hello(sni="payments.bank.example", alpn=["h2", "http/1.1"]))

    assert parsed["sni"] == "payments.bank.example"
    assert parsed["alpn"] == ["h2", "http/1.1"]
    assert parse_client_hello(hello())["sni"] is None


def test_a_malformed_hello_is_refused_not_partially_parsed():
    good = hello()
    cases = [
        good[:40],                                   # truncated body
        b"\x02" + good[1:],                          # a ServerHello is not a ClientHello
        good[:38] + b"\x21" + good[39:],             # session id longer than 32
        (good[:1] + len(good).to_bytes(3, "big") + good[4:]),  # length mismatch
        hello(suites=()),                            # no cipher suite is no offer
    ]
    for raw in cases:
        with pytest.raises(ValueError):
            parse_client_hello(raw)


# -- the sealed fact --------------------------------------------------------- #


def test_an_offer_is_never_a_negotiation():
    offer = fact()

    assert offer.kind == KIND
    assert offer.handshake_completed is False
    assert offer.application_data_sent is False
    assert offer.local_basis == "OBSERVED"
    assert offer.capabilities_observed is False
    # the sealed False cannot be undone at construction
    with pytest.raises(Exception):
        fact(handshake_completed=True)


def test_the_fact_commits_to_its_selected_bytes():
    offer = fact()

    assert offer.interface_sha256 != "0" * 64
    with pytest.raises(Exception):
        fact(identity_key="tls-client-endpoint:wrong")


def test_an_offered_value_must_be_a_known_name_or_an_echoed_codepoint():
    with pytest.raises(Exception):
        fact(offered_versions=["the server will pick something"])


def test_validate_offer_keeps_facts_inside_the_approved_endpoint():
    item = type("Item", (), {"path": "tls-client-offer://10.0.0.9:8443"})()

    validate_offer(item, [fact()])                       # exact endpoint: fine
    validate_offer(item, [])                             # bound, no client: fine, and NOT_OBSERVED
    with pytest.raises(ValueError):
        validate_offer(item, [fact(bind_port=9999)])     # observed elsewhere
    with pytest.raises(ValueError):
        validate_offer(item, [fact(), fact()])                   # the same connection twice
    validate_offer(item, [fact(), fact(client_port=51235)])      # two connections, two facts


def test_the_bind_endpoint_must_be_a_numeric_approved_socket():
    assert client_offer_resource("tls-client-offer://10.0.0.9:8443") == ("10.0.0.9", 8443)
    for bad in (
        "tls-client-offer://bank.example:8443",
        "tls-client-offer://10.0.0.9",
        "tls-client-offer://0.0.0.0:8443",
        "tls-client-offer://224.0.0.1:8443",
        "tls-session://10.0.0.9:8443/sni/x/version/TLSv1.2/peer/sha256/" + "a" * 64,
    ):
        with pytest.raises(ValueError):
            client_offer_resource(bad)


def test_grease_detection_follows_rfc_8701():
    assert is_grease(0x0A0A) and is_grease(0x7A7A) and is_grease(0xFAFA)
    assert not is_grease(0x0303) and not is_grease(0x1234) and not is_grease(0x1301)
