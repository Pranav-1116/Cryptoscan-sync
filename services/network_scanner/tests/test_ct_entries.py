"""CT log entry ingestion (audit 63, round 34).

Every assertion is against a real, cryptography-parsed certificate packed
into an RFC 6962 leaf — not a mock.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("cryptography")

from network_scanner.certificates.ct_entries import (
    CtEntryError,
    ct_entry_to_payload,
    ingest_ct_entries,
    parse_leaf_input,
)
from network_scanner.certificates.cert_parser import fingerprint_der
from network_scanner.certificates.lifecycle import issue_self_signed


def _leaf_for(der: bytes, *, version: int = 0, entry_type: int = 0,
              extensions: bytes = b"") -> bytes:
    """Build an RFC 6962 MerkleTreeLeaf (x509 entry) around a DER cert."""
    return (
        bytes([version])
        + entry_type.to_bytes(2, "big")
        + len(der).to_bytes(3, "big")
        + der
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


@pytest.fixture(scope="module")
def issued():
    result = issue_self_signed(
        subject={"CN": "ct-ingest-test"},
        san=["ct.example"],
        key_size=2048,
        validity_days=30,
    )
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
    return result, cert


def test_parse_leaf_round_trip(issued):
    from cryptography.hazmat.primitives.serialization import Encoding

    _, cert = issued
    der = cert.public_bytes(Encoding.DER)
    leaf = _leaf_for(der)
    parsed = parse_leaf_input(leaf)
    assert parsed["entry_type"] == 0 and parsed["version"] == 0
    assert parsed["der"] == der


def test_parse_leaf_rejects_malformed_and_precert(issued):
    from cryptography.hazmat.primitives.serialization import Encoding

    _, cert = issued
    der = cert.public_bytes(Encoding.DER)
    with pytest.raises(CtEntryError) as e:
        parse_leaf_input(b"\x00\x00")  # shorter than version+type
    assert e.value.reason == "malformed_leaf"
    with pytest.raises(CtEntryError) as e:
        parse_leaf_input(_leaf_for(der)[:8])  # truncated after header
    assert e.value.reason == "malformed_leaf"
    with pytest.raises(CtEntryError) as e:
        parse_leaf_input(b"\x00\x00\x01" + b"\x00" * 40)  # precert entry
    assert e.value.reason == "unsupported_precert"
    with pytest.raises(CtEntryError) as e:
        parse_leaf_input(b"\x00\x00\x09" + b"\x00" * 10)  # unknown entry type
    assert e.value.reason == "malformed_leaf"


def test_ct_entry_to_payload_carries_identity_and_provenance(issued):
    result, cert = issued
    from cryptography.hazmat.primitives.serialization import Encoding

    der = cert.public_bytes(Encoding.DER)
    leaf_b64 = base64.b64encode(_leaf_for(der)).decode()
    payload = ct_entry_to_payload(
        {"leaf_input": leaf_b64, "index": 1234}, log_url="https://ct.example/log")
    assert payload["fingerprint_sha256"] == fingerprint_der(der)
    assert payload["fingerprint_sha256"] == result.fingerprint_sha256
    assert "ct-ingest-test" in (payload["subject"] or "")
    assert payload["san"] == ["dnsname:ct.example"]
    assert payload["is_self_signed"] is True
    assert payload["public_key_algorithm"] and payload["public_key_size"] == 2048
    assert payload["extra"]["ct"] == {
        "log": "https://ct.example/log", "index": 1234,
        "entry_type": "x509_entry", "source": "certificate-transparency",
    }
    assert payload["not_before"] and payload["not_after"]


def test_ct_entry_rejects_non_certificate_and_bad_b64():
    # structurally valid x509 leaf whose DER payload is not a certificate
    junk = b"definitely not a DER certificate " * 3
    leaf = b"\x00\x00\x00" + len(junk).to_bytes(3, "big") + junk + b"\x00\x00"
    with pytest.raises(CtEntryError) as e:
        ct_entry_to_payload({"leaf_input": base64.b64encode(leaf).decode()})
    assert e.value.reason == "not_a_certificate"
    with pytest.raises(CtEntryError) as e:
        ct_entry_to_payload({"leaf_input": "!!!not-base64!!!"})
    assert e.value.reason == "malformed_leaf"
    with pytest.raises(CtEntryError) as e:
        ct_entry_to_payload({"leaf_input": ""})
    assert e.value.reason == "malformed_leaf"


def test_ingest_batch_separates_payloads_from_skips(issued):
    result, cert = issued
    from cryptography.hazmat.primitives.serialization import Encoding

    der = cert.public_bytes(Encoding.DER)
    good = base64.b64encode(_leaf_for(der)).decode()
    batch = ingest_ct_entries(
        [
            {"leaf_input": good, "index": 1},
            {"leaf_input": "!!!bad!!!", "index": 2},
            {"leaf_input": base64.b64encode(b"\x00\x00\x01" + b"\x00" * 40).decode(), "index": 3},
        ],
        log_url="https://ct.example/log",
    )
    assert len(batch["payloads"]) == 1
    assert batch["payloads"][0]["fingerprint_sha256"] == result.fingerprint_sha256
    reasons = [s["reason"] for s in batch["skipped"]]
    assert reasons == ["malformed_leaf", "unsupported_precert"]
    assert [s["index"] for s in batch["skipped"]] == [2, 3]
