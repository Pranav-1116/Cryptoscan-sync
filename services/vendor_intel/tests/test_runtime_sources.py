"""Reading the logs a bank already has, without believing anything unstated."""

from __future__ import annotations

import pytest

from vendor_intel.runtime_sources import (
    EmptySource,
    SourceError,
    detect_format,
    load_sessions,
    records_for_ingest,
)
from vendor_intel.runtime_usage import ingest_sessions, to_claims

ZEEK = "\n".join([
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve",
    "1780000000.1\tC1\t10.0.0.9\t51000\t10.0.0.5\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tx25519mlkem768",
    "1780000100.5\tC2\t10.0.0.9\t51001\t10.0.0.5\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tx25519",
    "1780000200.5\tC3\t10.0.0.9\t51002\t10.0.0.5\t443\tTLSv12\t-\t-",
    "",
])

CSV = "\n".join([
    "session_id,started_at,peer,cipher_suite,group,hostname",
    "A1,2026-10-01,10.0.0.5:443,AES256,x25519,hsm-001.corp",
    "A2,2026-10-01,10.0.0.5:443,,,",
    "",
])

NGINX = "\n".join([
    '10.0.0.9 - - [04/Oct/2026:10:11:12 +0000] "POST /v1/authorize HTTP/1.1" 200 512 "-" '
    '"curl/8" "TLSv1.3" "TLS_AES_256_GCM_SHA384" "x25519mlkem768"',
    '10.0.0.9 - - [04/Oct/2026:10:12:12 +0000] "GET /health HTTP/1.1" 200 12 "-" "curl/8"',
    "",
])


def test_a_zeek_log_becomes_sessions_that_decode_to_post_quantum_use():
    loaded = load_sessions(ZEEK)
    assert loaded["format"] == "zeek_ssl_log"
    assert (loaded["rows_read"], loaded["rows_used"], loaded["rows_skipped"]) == (3, 2, 1)
    summary = ingest_sessions(records_for_ingest(loaded), asset_id="HSM-001")
    assert "ML-KEM-768" in summary["pqc_primitives"]


def test_a_row_without_a_cipher_is_counted_not_dropped():
    loaded = load_sessions(ZEEK)
    # Lines 1-2 are the #separator and #fields header; the third row is the bad one.
    assert loaded["skipped"][0]["line"] == 5
    assert "no cipher" in loaded["skipped"][0]["reason"]


def test_an_absent_zeek_value_stays_absent():
    loaded = load_sessions(ZEEK)
    assert loaded["records"][0]["sni"] is None
    assert all(record.get("group") != "-" for record in loaded["records"])


def test_a_csv_is_mapped_through_the_alias_table_and_unknown_columns_are_named():
    loaded = load_sessions(CSV)
    assert loaded["format"] == "csv"
    assert loaded["unknown_columns"] == ["hostname"]
    assert loaded["records"][0]["cipher_suite"] == "AES256"
    assert loaded["rows_skipped"] == 1


def test_an_access_log_yields_protocol_cipher_and_curve():
    loaded = load_sessions(NGINX)
    assert loaded["format"] == "nginx_access"
    session = loaded["records"][0]
    assert session["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert session["tls_version"] == "TLS1.3"
    assert session["group"] == "x25519mlkem768"
    assert session["started_at"] == "2026-10-04"
    assert session["session_id"].startswith("ngx-")


def test_a_virtual_host_that_logs_no_cipher_is_reported_as_such():
    loaded = load_sessions(NGINX)
    assert loaded["rows_used"] == 1 and loaded["rows_skipped"] == 1
    assert "$ssl_cipher" in loaded["skipped"][0]["reason"]


def test_a_column_that_looks_like_key_material_refuses_the_file():
    with pytest.raises(SourceError) as raised:
        load_sessions("session_id,started_at,cipher_suite,premaster_secret\n")
    assert "premaster_secret" in str(raised.value)


def test_an_empty_file_is_not_an_absence_of_traffic():
    with pytest.raises(SourceError):
        load_sessions("   \n")


def test_a_file_with_rows_and_no_usable_session_raises_unless_soft():
    text = "\n".join([
        '10.0.0.9 - - [04/Oct/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"',
    ])
    with pytest.raises(EmptySource):
        load_sessions(text)
    soft = load_sessions(text, strict=False)
    assert soft["rows_used"] == 0 and soft["rows_skipped"] == 1


def test_an_unrecognised_shape_is_named_rather_than_guessed():
    with pytest.raises(SourceError) as raised:
        load_sessions("this is a paragraph about TLS 1.3\n")
    assert "not in a shape" in str(raised.value)
    assert detect_format("this is a paragraph") is None


def test_the_format_can_be_forced_and_a_csv_without_a_cipher_column_is_refused():
    assert load_sessions(ZEEK, format="zeek_ssl_log")["rows_used"] == 2
    with pytest.raises(SourceError):
        load_sessions("a,b\n1,2\n", format="csv")
    with pytest.raises(SourceError):
        load_sessions("session_id,cipher_suite\nA1,\n", format="csv")


def test_the_claims_from_a_log_are_runtime_observed_and_cite_sessions():
    loaded = load_sessions(ZEEK)
    claims = to_claims(ingest_sessions(records_for_ingest(loaded), asset_id="HSM-001"))
    aes = next(claim for claim in claims if claim.algorithm == "AES-256-GCM")
    assert len(aes.evidence) == 2
    assert aes.verification_status.value == "RUNTIME_OBSERVED_ONLY"
