"""Runtime usage: what a session negotiated, and what this module refuses to hold."""

from __future__ import annotations

from datetime import date

import pytest

from vendor_intel.runtime_usage import (
    IncompleteSession,
    PayloadRefused,
    decode_cipher_suite,
    decode_group,
    ingest_sessions,
    to_claims,
)


def _session(index: int, *, suite: str = "TLS_AES_256_GCM_SHA384",
             group: str | None = None, peer: str = "10.0.0.5:443") -> dict:
    record = {"session_id": f"S-{index}", "started_at": "2026-10-01", "peer": peer,
              "cipher_suite": suite}
    if group:
        record["group"] = group
    return record


def test_a_tls13_suite_decodes_into_its_primitives():
    decoded = decode_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert decoded["known"] is True
    roles = {(item["algorithm"], item["role"]) for item in decoded["primitives"]}
    assert roles == {("AES-256-GCM", "aead"), ("SHA-384", "hash")}


def test_the_iana_spelling_is_read_and_says_more_than_the_openssl_one():
    """A TLS 1.2 IANA name also names the key exchange; the short form does not."""
    iana = decode_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA")
    openssl = decode_cipher_suite("AES128-SHA")
    assert iana["known"] is True and openssl["known"] is True
    iana_algorithms = {item["algorithm"] for item in iana["primitives"]}
    assert {"AES-128-CBC", "RSA"} <= iana_algorithms
    assert {item["algorithm"] for item in openssl["primitives"]} == {"AES-128"}


def test_a_hybrid_group_is_post_quantum_in_the_wild():
    decoded = decode_group("x25519mlkem768")
    algorithms = {item["algorithm"] for item in decoded["primitives"]}
    assert algorithms == {"X25519", "ML-KEM-768"}
    assert decoded["hybrid"] is True
    assert any(item["pqc"] for item in decoded["primitives"])


def test_an_unknown_suite_is_named_not_guessed():
    decoded = decode_cipher_suite("TLS_FOO_SHA256")
    assert decoded["known"] is False
    assert decoded["primitives"] == []
    assert "hash" in decoded["reason"]
    assert decode_cipher_suite("")["known"] is False


def test_payload_and_key_material_are_refused_by_name():
    with pytest.raises(PayloadRefused) as raised:
        ingest_sessions([_session(1) | {"payload": "deadbeef"}], asset_id="HSM-001")
    assert "payload" in str(raised.value)
    with pytest.raises(PayloadRefused):
        ingest_sessions([_session(1) | {"premaster_secret": "00"}], asset_id="HSM-001")


def test_a_session_without_a_time_cannot_be_cited():
    with pytest.raises(IncompleteSession):
        ingest_sessions([{"session_id": "S-1", "cipher_suite": "TLS_AES_256_GCM_SHA384"}],
                        asset_id="HSM-001")


def test_many_sessions_outrank_one():
    one = ingest_sessions([_session(1)], asset_id="HSM-001")
    many = ingest_sessions([_session(index) for index in range(12)], asset_id="HSM-001")
    assert one["primitives"][0]["confidence"] == "LOW"
    assert many["primitives"][0]["confidence"] == "HIGH"
    assert many["sessions"] == 12


def test_the_claims_carry_one_citation_per_session_and_are_not_a_declaration():
    summary = ingest_sessions([_session(index) for index in range(3)], asset_id="HSM-001")
    claims = to_claims(summary)
    aes = next(claim for claim in claims if claim.algorithm == "AES-256-GCM")
    assert len(aes.evidence) == 3
    assert aes.verification_status.value == "RUNTIME_OBSERVED_ONLY"
    assert aes.vendor_declared is False
    assert aes.runtime_observed is True


def test_an_undecoded_suite_is_reported_and_produces_no_claim():
    summary = ingest_sessions([_session(1), _session(2, suite="TLS_MYSTERY_SHA256")],
                              asset_id="HSM-001")
    assert summary["undecoded"][0]["value"] == "TLS_MYSTERY_SHA256"
    assert summary["undecoded"][0]["kind"] == "cipher_suite"
    assert all(claim.algorithm != "MYSTERY" for claim in to_claims(summary))
    assert "not guessed" in summary["statement"]


def test_an_empty_transcript_is_not_an_all_clear():
    summary = ingest_sessions([], asset_id="HSM-001")
    assert summary["sessions"] == 0
    assert "not evidence of absence" in summary["statement"]


def test_extra_fields_are_reported_rather_than_silently_used():
    summary = ingest_sessions([_session(1) | {"hostname": "hsm-001.corp"}], asset_id="HSM-001")
    assert summary["ignored_fields"] == ["hostname"]


def test_the_period_is_the_observed_window_not_the_run_date():
    summary = ingest_sessions([_session(1), _session(2) | {"started_at": "2026-09-01"}],
                              asset_id="HSM-001")
    assert summary["period"] == {"first": "2026-09-01", "last": "2026-10-01"}
    assert to_claims(summary)[0].observed_at == date(2026, 10, 1)


def test_usage_belongs_to_an_asset():
    with pytest.raises(ValueError):
        ingest_sessions([_session(1)], asset_id="  ")
