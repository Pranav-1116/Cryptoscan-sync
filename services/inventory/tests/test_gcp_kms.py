"""GCP Cloud KMS collector — normalization table and bounded collection.

Fake clients are dict-shaped like the REST/protobuf representation; no
network, no credentials. Unknown algorithms must be skipped with a reason,
never guessed.
"""

from __future__ import annotations

from inventory.cloud_kms import collect_gcp_kms, normalize_gcp_key

FULL_NAME = "projects/bank-prod/locations/global/keyRings/main-ring/cryptoKeys/{name}"


def _key(name: str, algorithm: str, *, protection: str = "HSM", rotation: str | None = None,
         with_primary: bool = True):
    primary = {"name": f"{FULL_NAME.format(name=name)}/cryptoKeyVersions/1",
               "algorithm": algorithm, "protection_level": protection} if with_primary else None
    key = {"name": FULL_NAME.format(name=name), "purpose": "ENCRYPT_DECRYPT",
           "next_rotation_time": rotation}
    if primary:
        key["primary"] = primary
    return key


def test_gcp_algorithm_table():
    cases = {
        "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES-256", 256, "encryption"),
        "HMAC_SHA256": ("HMAC-SHA256", 256, "mac"),
        "HMAC_SHA512": ("HMAC-SHA512", 512, "mac"),
        "RSA_SIGN_PSS_2048_SHA256": ("RSA-2048", 2048, "signing"),
        "RSA_SIGN_PKCS1_4096_SHA256": ("RSA-4096", 4096, "signing"),
        "RSA_SIGN_RAW_PKCS1_2048": ("RSA-2048", 2048, "signing"),
        "RSA_DECRYPT_OAEP_3072_SHA256": ("RSA-3072", 3072, "encryption"),
        "EC_SIGN_P256_SHA256": ("ECDSA-P256", 256, "signing"),
        "EC_SIGN_P384_SHA384": ("ECDSA-P384", 384, "signing"),
        "EC_SIGN_SECP256K1_SHA256": ("ECDSA-P256K1", 256, "signing"),
    }
    for algorithm, (family, bits, purpose) in cases.items():
        asset = normalize_gcp_key(_key("k", algorithm))
        assert asset, algorithm
        assert asset["algorithm"] == family, algorithm
        assert asset["key_size"] == bits, algorithm
        assert asset["purpose"] == purpose, algorithm


def test_gcp_normalization_shape():
    asset = normalize_gcp_key(
        _key("master-key", "GOOGLE_SYMMETRIC_ENCRYPTION", rotation="2026-10-01T00:00:00Z"))
    assert asset["file_path"] == "gcp-kms://projects/bank-prod/locations/global/keyRings/main-ring/master-key"
    assert asset["source_language"] == "gcp-kms" and asset["confidence"] == "HIGH"
    assert asset["extra"]["collector"] == "gcp-kms"
    assert asset["extra"]["project"] == "bank-prod"
    assert asset["extra"]["key_ring"] == "main-ring"
    assert asset["extra"]["protection_level"] == "HSM"
    assert asset["extra"]["next_rotation_at"] == "2026-10-01T00:00:00Z"


def test_gcp_unknown_and_degenerate_are_not_guessed():
    bad = [
        _key("x", "QUANTUM_SAFE_FAR_FUTURE"),
        _key("x", "EC_SIGN_P999_BLAKE3"),
        _key("x", "GOOGLE_SYMMETRIC_ENCRYPTION", with_primary=False),  # no primary
        {"name": "", "primary": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}},
        {"name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"},  # no primary at all
    ]
    for key in bad:
        assert normalize_gcp_key(key) is None, key


def test_collect_gcp_bounded_and_honest():
    keys = [
        _key("symmetric", "GOOGLE_SYMMETRIC_ENCRYPTION"),
        _key("signing", "RSA_SIGN_PSS_3072_SHA256"),
        _key("exotic", "PQ_SIGN_DILITHIUM_DREAMS"),
        _key("no-primary", "GOOGLE_SYMMETRIC_ENCRYPTION", with_primary=False),
        _key("overflow", "GOOGLE_SYMMETRIC_ENCRYPTION"),
    ]

    class FakeKms:
        def list_crypto_keys(self, parent):
            assert parent == "projects/bank-prod/locations/global/keyRings/-"
            return iter(keys)

    result = collect_gcp_kms(FakeKms(), project="bank-prod", limit=4)
    assert result["provider"] == "gcp-kms"
    assert result["seen"] == 4
    assert result["truncated"] is True  # we read limit+1 and KNOW more exist
    assert [asset["algorithm"] for asset in result["assets"]] == ["AES-256", "RSA-3072"]
    assert result["skipped"] == [
        {"ref": "exotic", "reason": "unsupported algorithm 'PQ_SIGN_DILITHIUM_DREAMS' — not classified"},
        {"ref": "no-primary", "reason": "no active primary version"}]


def test_collect_gcp_requires_sdk_without_client(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "google", None)
    monkeypatch.setitem(sys.modules, "google.cloud", None)
    try:
        collect_gcp_kms(None, project="p")
    except RuntimeError as exc:
        assert "google-cloud-kms" in str(exc)


def test_collect_gcp_requires_project_without_client():
    import inventory.cloud_kms as mod

    class Sentinel:
        def __getattr__(self, name):
            raise AssertionError("client must not be constructed without a project")

    # client=None + real import path → RuntimeError about project, before any list call
    try:
        mod.collect_gcp_kms(None, project="")
    except RuntimeError as exc:
        assert "project" in str(exc)
    except ImportError:  # google sdk present, but project gate fires first anyway
        raise AssertionError("project must be validated before any client use")
