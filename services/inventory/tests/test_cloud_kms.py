"""Cloud KMS connectors — normalization tables and bounded collection.

Provider clients are fakes shaped exactly like the real APIs (boto3 dicts,
Azure SDK attribute objects); no network, no credentials.
"""

from __future__ import annotations

import base64
from datetime import datetime
from types import SimpleNamespace

from inventory.cloud_kms import (
    collect_aws_kms,
    collect_azure_keyvault,
    normalize_aws_key,
    normalize_azure_key,
)


# ------------------------------------------------------------------- AWS KMS


def _aws_desc(**overrides):
    base = {
        "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "Enabled": True,
        "Origin": "AWS_KMS",
        "AWSAccountId": "111122223333",
    }
    base.update(overrides)
    return base


def test_aws_spec_table():
    _usage = {"ENCRYPT_DECRYPT": "encryption", "SIGN_VERIFY": "signing",
              "GENERATE_VERIFY_MAC": "mac", "KEY_AGREEMENT": "key_agreement"}
    cases = {
        # spec: (family, bits, usage_to_set, expected_purpose)
        "SYMMETRIC_DEFAULT": ("AES-256", 256, "ENCRYPT_DECRYPT", "encryption"),
        "RSA_2048": ("RSA-2048", 2048, "SIGN_VERIFY", "signing"),
        "RSA_4096": ("RSA-4096", 4096, "", None),
        "ECC_NIST_P256": ("ECDSA-P256", 256, "SIGN_VERIFY", "signing"),
        "ECC_NIST_P384": ("ECDSA-P384", 384, "", None),
        "ECC_NIST_P521": ("ECDSA-P521", 521, "", None),
        "ECC_SECG_P256K1": ("ECDSA-P256K1", 256, "", None),
        "HMAC_256": ("HMAC-SHA256", 256, "GENERATE_VERIFY_MAC", "mac"),
        "HMAC_512": ("HMAC-SHA512", 512, "", "mac"),  # spec default applies
    }
    for spec, (family, bits, usage, expected) in cases.items():
        desc = _aws_desc(KeySpec=spec, KeyUsage=usage)
        asset = normalize_aws_key(desc, region="us-east-1")
        assert asset, spec
        assert asset["algorithm"] == family and asset["key_size"] == bits
        assert asset["purpose"] == expected, spec


def test_aws_normalization_shape_and_untagged_usage():
    asset = normalize_aws_key(_aws_desc(), region="eu-central-1")
    assert asset["file_path"] == "aws-kms://eu-central-1/1234abcd-12ab-34cd-56ef-1234567890ab"
    assert asset["source_language"] == "aws-kms" and asset["confidence"] == "HIGH"
    assert asset["extra"]["collector"] == "aws-kms"
    assert asset["extra"]["aws_account"] == "111122223333"
    assert asset["extra"]["origin"] == "AWS_KMS"
    # legacy field name honored
    legacy = normalize_aws_key(_aws_desc(KeySpec="", CustomerMasterKeySpec="RSA_3072"))
    assert legacy["algorithm"] == "RSA-3072"


def test_aws_unknown_spec_is_not_guessed():
    assert normalize_aws_key(_aws_desc(KeySpec="SM2_KEY AGREE")) is None
    assert normalize_aws_key(_aws_desc(KeyId="")) is None


def test_collect_aws_bounded_and_honest_about_denials():
    denied_key = "denied-key-id"

    class FakeKms:
        def list_keys(self):
            return {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"},
                             {"KeyId": denied_key}, {"KeyId": "k4"}],
                    "Truncated": True}

        def get_key_description(self, KeyId):
            if KeyId == denied_key:
                raise RuntimeError("AccessDeniedException")
            if KeyId == "k4":
                return _aws_desc(KeyId="k4", KeySpec="QUANTUM_SAFE_FUTURE")
            return _aws_desc(KeyId=KeyId, KeySpec="RSA_3072" if KeyId == "k2" else "SYMMETRIC_DEFAULT")

    result = collect_aws_kms(FakeKms(), region="us-east-1", limit=3)
    assert result["provider"] == "aws-kms"
    assert result["seen"] == 3  # bounded to limit
    assert result["truncated"] is True
    assert [asset["algorithm"] for asset in result["assets"]] == ["AES-256", "RSA-3072"]
    assert result["skipped"] == [
        {"ref": denied_key, "reason": "describe failed: AccessDeniedException"}]


def test_collect_aws_requires_boto3_when_no_client(monkeypatch):
    import sys

    # None in sys.modules makes `import boto3` raise ImportError even when the
    # real package is installed — forces the honest install-hint path.
    monkeypatch.setitem(sys.modules, "boto3", None)
    try:
        collect_aws_kms(None)
    except RuntimeError as exc:
        assert "pip install boto3" in str(exc)
    else:  # pragma: no cover — unreachable: None in sys.modules always fails
        raise AssertionError("collection without boto3 must fail with a RuntimeError")


# -------------------------------------------------------------- Azure KeyVault


def test_azure_kty_matrix():
    cases = [
        ({"kty": "RSA", "key_size": 3072}, "RSA-3072"),
        ({"kty": "RSA-HSM", "key_size": 4096}, "RSA-4096"),
        ({"kty": "EC", "crv": "P-256"}, "ECDSA-P256"),
        ({"kty": "EC-HSM", "crv": "P-521"}, "ECDSA-P521"),
        ({"kty": "EC", "crv": "P-256K"}, "ECDSA-P256K1"),
        ({"kty": "oct", "key_size": 256}, "AES-256"),
        ({"kty": "oct-HSM", "key_size": 128}, "AES-128"),
    ]
    for key, expected in cases:
        bundle = {"key": {**key, "kid": f"https://kv.vault.azure.net/keys/master/{expected}"},
                  "properties": {"enabled": True, "operations": ["sign", "verify"]}}
        asset = normalize_azure_key(bundle, vault_url="https://kv.vault.azure.net")
        assert asset, key
        assert asset["algorithm"] == expected
        assert asset["purpose"] == "signing"
        assert asset["file_path"].startswith("azure-kv://kv.vault.azure.net/keys/") or \
            asset["file_path"] == f"azure-kv://kv.vault.azure.net/{expected}"
        assert asset["extra"]["collector"] == "azure-keyvault"


def test_azure_rsa_size_from_modulus_when_key_size_absent():
    modulus = base64.urlsafe_b64encode(b"\x01" + b"\xff" * 255).decode().rstrip("=")  # 2048 bits
    bundle = {"key": {"kid": "https://kv.vault.azure.net/keys/rsa-key", "kty": "RSA", "n": modulus},
              "properties": {"enabled": True, "operations": ["encrypt", "decrypt"]}}
    asset = normalize_azure_key(bundle, vault_url="https://kv.vault.azure.net")
    assert asset["algorithm"] == "RSA-2048" and asset["key_size"] == 2048
    assert asset["purpose"] == "encryption"


def test_azure_unsupported_is_not_guessed():
    bad = [
        {"key": {"kid": "https://v/keys/x", "kty": "RSA", "key_size": 1024}, "properties": {}},
        {"key": {"kid": "https://v/keys/x", "kty": "EC", "crv": "P-999"}, "properties": {}},
        {"key": {"kid": "https://v/keys/x", "kty": "oct", "key_size": 100}, "properties": {}},
        {"key": {"kid": "https://v/keys/x", "kty": "OKP"}, "properties": {}},
        {"key": {"kty": "RSA", "key_size": 2048}, "properties": {}},  # no kid → no name
        {"properties": {}},  # no key at all
    ]
    for bundle in bad:
        assert normalize_azure_key(bundle, vault_url="https://v") is None, bundle


def test_azure_timestamps_surface_iso():
    bundle = {"key": {"kid": "https://v/keys/k", "kty": "EC", "crv": "P-256"},
              "properties": {"enabled": False, "operations": [],
                             "created_on": datetime(2026, 1, 2, 3, 4, 5),
                             "expires_on": datetime(2027, 1, 2)}}
    asset = normalize_azure_key(bundle, vault_url="https://v")
    assert asset["extra"]["created_at"] == "2026-01-02T03:04:05"
    assert asset["extra"]["expires_at"] == "2027-01-02T00:00:00"
    assert asset["extra"]["enabled"] is False


def test_collect_azure_via_sdk_shaped_fakes():
    def props(name, enabled=True):
        return SimpleNamespace(name=name, enabled=enabled, operations=["sign"],
                               expires_on=None, created_on=datetime(2026, 5, 1),
                               not_before=None)

    class FakeKeyClient:
        def __init__(self):
            self.fetched = []

        def list_properties_of_keys(self):
            return [props("signing-key"), props("broken-key"), props("weird-key")]

        def get_key(self, name):
            self.fetched.append(name)
            if name == "broken-key":
                raise RuntimeError("Key is disabled / denied")
            kty = "EC" if name != "weird-key" else "OKP"
            return SimpleNamespace(
                key=SimpleNamespace(kid=f"https://kv.vault.azure.net/keys/{name}",
                                    kty=kty, crv="P-384", key_size=None, n=None),
                properties=props(name))

    fake = FakeKeyClient()
    result = collect_azure_keyvault(fake, vault_url="https://kv.vault.azure.net")
    assert result["provider"] == "azure-keyvault"
    assert result["seen"] == 3 and result["truncated"] is False
    assert len(result["assets"]) == 1
    assert result["assets"][0]["algorithm"] == "ECDSA-P384"
    assert result["assets"][0]["extra"]["created_at"] == "2026-05-01T00:00:00"
    assert result["skipped"] == [
        {"ref": "broken-key", "reason": "get_key failed: Key is disabled / denied"},
        {"ref": "weird-key", "reason": "unsupported key type 'OKP' — not classified"}]


def test_collect_azure_respects_limit():
    def props(name):
        return SimpleNamespace(name=name, enabled=True, operations=["sign"],
                               expires_on=None, created_on=None, not_before=None)

    class FakeKeyClient:
        def list_properties_of_keys(self):
            return [props(f"k{i}") for i in range(5)]

        def get_key(self, name):
            return SimpleNamespace(
                key=SimpleNamespace(kid=f"https://v/keys/{name}", kty="EC",
                                    crv="P-256", key_size=None, n=None),
                properties=props(name))

    result = collect_azure_keyvault(FakeKeyClient(), vault_url="https://v", limit=2)
    assert result["seen"] == 2 and result["truncated"] is True
    assert len(result["assets"]) == 2
