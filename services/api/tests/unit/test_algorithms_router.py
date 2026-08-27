"""Algorithm registry API tests."""

from __future__ import annotations

from api.routers.algorithms import list_algorithms, parse, parse_many


def test_catalog_lists_algorithms_with_key_sizes():
    res = list_algorithms()
    assert res["total_count"] > 50
    des = next(e for e in res["algorithms"] if e["algorithm"] == "DES")
    assert des["key_size"] == 56
    assert des["status"] == "DISALLOWED"
    aes = next(e for e in res["algorithms"] if e["algorithm"] == "AES")
    assert aes["allowed_key_sizes"] == [128, 192, 256]
    assert "block-cipher" in res["families"]
    assert res["counts_by_status"]["DISALLOWED"] >= 5


def test_catalog_filters_by_status_family_and_search():
    disallowed = list_algorithms(status="disallowed")["algorithms"]
    assert disallowed and all(e["status"] == "DISALLOWED" for e in disallowed)
    hashes = list_algorithms(family="hash")["algorithms"]
    assert hashes and all(e["family"] == "hash" for e in hashes)
    assert any(e["algorithm"].startswith("ML-KEM") for e in list_algorithms(q="kem")["algorithms"])


def test_parse_endpoint_full_contract():
    out = parse(name="AES-256")
    assert out["algorithm"] == "AES"
    assert out["key_size"] == 256
    assert out["status"] == "ALLOWED"
    assert out["parameter_kind"] == "key_bits"

    suite = parse(name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert suite["family"] == "tls-suite"
    assert suite["key_size"] == 128
    assert {"key_exchange", "bulk_cipher", "mac"} <= {c["role"] for c in suite["components"]}

    unknown = parse(name="scratchpad-9000")
    assert unknown["status"] == "UNKNOWN"
    assert unknown["recognized"] is False


def test_parse_many_counts_recognized():
    res = parse_many(names="DES, AES-256, scratchpad-9000")
    assert res["total_count"] == 3
    assert res["recognized"] == 2
    by_raw = {r["raw"]: r for r in res["results"]}
    assert by_raw["DES"]["key_size"] == 56
    assert by_raw["AES-256"]["key_size"] == 256
