"""The crypto asset identity spine (§4.2, round 57) — canonical contract.

One deterministic string identity for one crypto asset, derivable from
any observation shape. The contract pins: stability, line-exclusion,
shape-equivalence, the no-locator rule, and versioning.
"""

from __future__ import annotations

from shared_models.asset_identity import (
    IDENTITY_VERSION,
    crypto_asset_key,
    crypto_asset_key_from_row,
)


def test_key_is_deterministic_and_versioned():
    a = crypto_asset_key("RSA", "ENCRYPTION", "src/Keys.java", 2048, None)
    b = crypto_asset_key("RSA", "ENCRYPTION", "src/Keys.java", 2048, None)
    assert a == b
    assert a.startswith(f"{IDENTITY_VERSION}:")
    assert len(a) == len(IDENTITY_VERSION) + 1 + 64  # tag + ':' + sha256 hex


def test_every_identity_field_discriminates():
    base = crypto_asset_key("RSA", "ENCRYPTION", "src/Keys.java", 2048, None)
    assert crypto_asset_key("ECDSA", "ENCRYPTION", "src/Keys.java", 2048, None) != base
    assert crypto_asset_key("RSA", "SIGNING", "src/Keys.java", 2048, None) != base
    assert crypto_asset_key("RSA", "ENCRYPTION", "src/Other.java", 2048, None) != base
    assert crypto_asset_key("RSA", "ENCRYPTION", "src/Keys.java", 3072, None) != base
    assert crypto_asset_key("RSA", "ENCRYPTION", "src/Keys.java", 2048, "GCM") != base


def test_line_number_is_not_identity():
    """The fact kernel's declared rule: the same algorithm/purpose/
    parameters in the same file is ONE fact observed at several lines —
    a line shift between scans must not fork the identity."""
    at_line_10 = crypto_asset_key_from_row(
        {"algorithm": "AES", "purpose": "ENCRYPTION", "file_path": "src/A.java",
         "key_size": 256, "mode": "GCM", "line_number": 10})
    at_line_412 = crypto_asset_key_from_row(
        {"algorithm": "AES", "purpose": "ENCRYPTION", "file_path": "src/A.java",
         "key_size": 256, "mode": "GCM", "line_number": 412})
    assert at_line_10 == at_line_412


def test_every_observation_shape_derives_the_same_key():
    """Evidence row, crypto_assets row and fact row are the SAME crypto
    fact — the spine must not care which shape it sees."""
    evidence_row = {
        "id": "ev-1", "algorithm": "AES", "purpose": "ENCRYPTION",
        "file_path": "src/A.java", "key_size": 256, "mode": "GCM",
        "line_number": 3, "content_hash": "x" * 64,
    }
    asset_row = {
        "id": "asset-1", "algorithm": "AES", "purpose": "ENCRYPTION",
        "file_path": "src/A.java", "key_size": 256, "mode": "GCM",
        "line_number": 0, "lifecycle_state": "DISCOVERED",
    }
    fact_row = {
        "algorithm": "AES", "purpose": "ENCRYPTION",
        "file_path": "src/A.java", "key_size": 256, "mode": "GCM",
    }
    keys = {crypto_asset_key_from_row(row) for row in (evidence_row, asset_row, fact_row)}
    assert len(keys) == 1


def test_none_and_missing_fields_normalize_not_fork():
    """None and absent are the same thing ("" normalization) — SQL NULL
    distinctness must never fork identity."""
    explicit_none = crypto_asset_key_from_row(
        {"algorithm": "RSA", "purpose": None, "file_path": "src/A.java",
         "key_size": None, "mode": None})
    absent = crypto_asset_key_from_row(
        {"algorithm": "RSA", "file_path": "src/A.java"})
    assert explicit_none == absent


def test_no_locator_means_no_identity_claim():
    """Identity is what + why + WHERE + parameters. Without a locator the
    key would join unrelated rows — returning "" (no claim) is the only
    honest answer."""
    assert crypto_asset_key_from_row({"algorithm": "RSA", "key_size": 2048}) == ""
    assert crypto_asset_key_from_row({"algorithm": "RSA", "file_path": "src/A.java"}) != ""


def test_cloud_resource_ref_is_a_locator():
    """Cloud-collected keys: the stable resource ref lives in file_path —
    the spine covers the cloud write path without a second namespace."""
    first_collection = crypto_asset_key_from_row(
        {"algorithm": "AES", "purpose": "ENCRYPTION",
         "file_path": "aws-kms://eu-central-1/abcd-1234", "key_size": 256, "mode": None})
    recollection = crypto_asset_key_from_row(
        {"algorithm": "AES", "purpose": "ENCRYPTION",
         "file_path": "aws-kms://eu-central-1/abcd-1234", "key_size": 256, "mode": None,
         "extra": {"last_seen_at": "2026-10-14T00:00:00Z"}})
    assert first_collection == recollection
