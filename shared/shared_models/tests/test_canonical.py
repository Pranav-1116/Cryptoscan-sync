"""Tests for shared_models.canonical — deterministic JSON + crypto encodings."""

from __future__ import annotations

import hashlib
import hmac as hmac_module

from shared_models.canonical import (
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    canonical_json,
    constant_time_eq,
    exclude_fields,
    hmac_sha256,
    sha256_hex,
)


def test_canonical_json_is_key_order_independent():
    a = {"b": 1, "a": {"d": 2, "c": [3, {"z": 4, "y": 5}]}}
    b = {"a": {"c": [3, {"y": 5, "z": 4}], "d": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_has_no_whitespace_and_keeps_unicode():
    out = canonical_json({"key": "valüe", "n": 1})
    assert out == '{"key":"valüe","n":1}'  # ensure_ascii=False, no spaces


def test_canonical_bytes_is_utf8():
    assert canonical_bytes({"k": "é"}) == '{"k":"é"}'.encode("utf-8")


def test_canonical_form_stable_across_calls_and_processes():
    payload = {"scan_id": "s", "findings": [{"id": i} for i in range(5)]}
    assert canonical_json(payload) == canonical_json(payload)


def test_exclude_fields_recursive():
    data = {
        "finding_id": "strip-me",
        "keep": 1,
        "nested": {"finding_id": "also", "created_at": "x", "deep": [{"finding_id": "y", "k": 2}]},
    }
    out = exclude_fields(data, {"finding_id", "created_at"})
    assert out == {"keep": 1, "nested": {"deep": [{"k": 2}]}}


def test_sha256_hex_known_vector():
    # SHA-256 of "{}" — fixed anchor vector.
    assert sha256_hex({}) == hashlib.sha256(b"{}").hexdigest()
    assert sha256_hex({}) == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_sha256_hex_matches_plain_hashlib_on_canonical_bytes():
    data = {"a": [1, 2, {"b": None}], "c": True}
    assert sha256_hex(data) == hashlib.sha256(canonical_bytes(data)).hexdigest()


# RFC 7515 base64url semantics: URL-safe alphabet, no padding
def test_b64url_rfc7515_alphabet_and_padding():
    assert b64url_encode(b"") == ""
    assert b64url_encode(b"{}") == "e30"
    assert b64url_encode(b"\xfb\x10\x23\x1f") == "-xAjHw"  # 0xfb -> '/' -> '_'
    assert b64url_encode(b"\xff\xff\xfe") == "___-"  # 0xff -> '+'/'/' -> '_' 
    assert b64url_encode(b"?") == "Pw"  # 2-byte group -> no '=' padding
    assert "=" not in b64url_encode(b"abcde")


def test_b64url_round_trip():
    for blob in (b"", b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
        assert b64url_decode(b64url_encode(blob)) == blob


def test_b64url_decode_accepts_padded_input():
    assert b64url_decode("e30=") == b"{}"


def test_hmac_sha256_matches_stdlib():
    mac = hmac_sha256("secret", b"payload")
    assert mac == hmac_module.new(b"secret", b"payload", hashlib.sha256).digest()


def test_constant_time_eq_behaviour():
    assert constant_time_eq("abc", "abc") is True
    assert constant_time_eq("abc", "abd") is False
    assert constant_time_eq(b"abc", b"abc") is True
    assert constant_time_eq("abc", b"abc") is True  # both encode to same bytes
    assert constant_time_eq("", "") is True


def test_cross_module_contracts():
    """The exact strings other services rely on for interoperable hashes."""
    # Matches the CBOM JWS canonicalization (RFC 7515 HS256 payload form).
    assert canonical_json({"alg": "HS256", "typ": "JWT"}) == '{"alg":"HS256","typ":"JWT"}'
    assert b64url_encode(b'{"alg":"HS256","typ":"JWT"}') == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
