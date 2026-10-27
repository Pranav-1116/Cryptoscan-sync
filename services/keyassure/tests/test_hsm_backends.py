"""Concrete HSM backend adapters: provider response -> residence verdict.

No SDK and no network: each adapter takes an injected client/session, so what
is exercised here is the part that actually decides a bank's answer -- how a
provider's native attributes are normalised, and whether ``check_key`` then
calls the key hardware-backed or not.
"""

from __future__ import annotations

import pytest

from keyassure.hsm_backends import (
    AwsKmsBackend,
    AzureKeyVaultBackend,
    BackendUnavailable,
    GcpKmsBackend,
    Pkcs11Backend,
)
from keyassure.hsm_connectivity import check_key


# --------------------------------------------------------------- AWS fakes


class _FakeKmsClient:
    def __init__(self, metadata: dict, signature: bytes | None = b"sig"):
        self._metadata = metadata
        self._signature = signature
        self.signed: list[dict] = []

    def describe_key(self, KeyId: str):  # noqa: N803 - boto3 casing
        return {"KeyMetadata": self._metadata}

    def sign(self, **kwargs):
        self.signed.append(kwargs)
        return {"Signature": self._signature}


class _FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, name, region_name=None):
        assert name == "kms"
        return self._client


def _aws(metadata, signature=b"sig"):
    client = _FakeKmsClient(metadata, signature)
    return AwsKmsBackend(session=_FakeSession(client)), client


def test_aws_cloudhsm_origin_is_hardware_backed():
    backend, _ = _aws({
        "KeyState": "Enabled", "Origin": "AWS_CLOUDHSM", "KeySpec": "RSA_2048",
        "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
        "CustomKeyStoreId": "cks-123",
    })
    result = check_key("arn:aws:kms:eu-west-1:1:key/abc", provider="aws_kms", backend=backend)
    assert result["key_residence"] == "HSM"
    assert result["hardware_backed"] is True
    assert result["sign_challenge"] == "OK"


def test_aws_default_managed_key_is_not_hardware_backed():
    """A plain AWS_KMS origin is multi-tenant, not a dedicated HSM."""
    backend, _ = _aws({
        "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "RSA_2048",
        "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
    })
    result = check_key("arn:aws:kms:eu-west-1:1:key/abc", provider="aws_kms", backend=backend)
    assert result["key_residence"] == "SOFTWARE"
    assert result["hardware_backed"] is False
    assert any(i["code"] == "NOT_HARDWARE_BACKED" for i in result["issues"])


def test_aws_sign_challenge_uses_the_keys_own_algorithm():
    backend, client = _aws({
        "KeyState": "Enabled", "Origin": "AWS_CLOUDHSM", "KeySpec": "ECC_NIST_P256",
        "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ECDSA_SHA_256"],
    })
    check_key("k", provider="aws_kms", backend=backend)
    assert client.signed and client.signed[0]["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert client.signed[0]["MessageType"] == "RAW"


def test_aws_encrypt_only_key_reports_sign_challenge_failure():
    """No signing algorithms means the probe cannot run — that is a FAIL, not a pass."""
    backend, _ = _aws({
        "KeyState": "Enabled", "Origin": "AWS_CLOUDHSM", "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT", "SigningAlgorithms": [],
    })
    result = check_key("k", provider="aws_kms", backend=backend)
    assert result["sign_challenge"] == "FAIL"


def test_connectivity_failure_is_reported_not_raised():
    class _Broken:
        def describe(self, key_ref):
            raise OSError("endpoint unreachable")

        def sign_challenge(self, key_ref, nonce):  # pragma: no cover - never reached
            raise AssertionError

    result = check_key("k", provider="aws_kms", backend=_Broken())
    assert result["connectivity"] == "FAIL"
    assert result["hardware_backed"] is False


# ------------------------------------------------------------- Azure fakes


class _FakeAzureKey:
    def __init__(self, kty: str, exportable: bool = False):
        self.key = type("K", (), {"kty": kty, "key_ops": ["sign", "verify"]})()
        self.properties = type("P", (), {"enabled": True, "exportable": exportable})()


class _FakeAzureClient:
    def __init__(self, key):
        self._key = key

    def get_key(self, name):
        return self._key


def test_azure_managed_hsm_key_type_is_hardware():
    backend = AzureKeyVaultBackend(
        "https://v.managedhsm.azure.net", client=_FakeAzureClient(_FakeAzureKey("RSA-HSM"))
    )
    desc = backend.describe("signing-key")
    assert desc["metadata"]["protection_level"] == "HARDWARE"


def test_azure_software_key_type_is_software():
    backend = AzureKeyVaultBackend(
        "https://v.vault.azure.net", client=_FakeAzureClient(_FakeAzureKey("RSA"))
    )
    desc = backend.describe("signing-key")
    assert desc["metadata"]["protection_level"] == "SOFTWARE"
    assert desc["exportable"] is False


def test_azure_exportable_flag_is_passed_through():
    backend = AzureKeyVaultBackend(
        "https://v.vault.azure.net", client=_FakeAzureClient(_FakeAzureKey("RSA", exportable=True))
    )
    assert backend.describe("k")["exportable"] is True


# --------------------------------------------------------------- GCP fakes


class _FakeGcpClient:
    def __init__(self, protection_level: str):
        self._level = protection_level

    def get_crypto_key_version(self, name):
        return type("V", (), {
            "state": "ENABLED",
            "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
            "protection_level": self._level,
        })()

    def asymmetric_sign(self, request):
        return type("R", (), {"signature": b"sig"})()


@pytest.mark.parametrize(
    "level,expected",
    [("ProtectionLevel.HSM", "HSM"), ("ProtectionLevel.SOFTWARE", "SOFTWARE")],
)
def test_gcp_protection_level_maps_to_residence(level, expected):
    backend = GcpKmsBackend(client=_FakeGcpClient(level))
    result = check_key("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                       provider="gcp_kms", backend=backend)
    assert result["key_residence"] == expected


# ------------------------------------------------------------ PKCS#11 fakes


class _FakePkcs11Session:
    """Mimics PyKCS11's attribute-vector API for one private key object."""

    def __init__(self, attrs: dict, signature=b"sig"):
        self._attrs = attrs
        self._signature = signature

    def findObjects(self, template):  # noqa: N802 - PyKCS11 casing
        wants_label = any(t[0] == 3 for t in template)  # CKA_LABEL == 0x03
        return ["handle"] if wants_label else []

    def getAttributeValue(self, obj, wanted):  # noqa: N802
        return [self._attrs.get(w) for w in wanted]

    def sign(self, obj, data, mechanism):
        return list(self._signature)


def test_pkcs11_backend_without_library_fails_closed():
    """No Cryptoki library configured must be an explicit error, never a silent pass."""
    backend = Pkcs11Backend(lib_path="")
    with pytest.raises((BackendUnavailable, Exception)):
        backend.describe("signing-key")


def test_pkcs11_non_extractable_sensitive_token_key_is_hardware(monkeypatch):
    pkcs11 = pytest.importorskip("PyKCS11", reason="PyKCS11 not installed")
    attrs = {
        pkcs11.CKA_EXTRACTABLE: False,
        pkcs11.CKA_SENSITIVE: True,
        pkcs11.CKA_TOKEN: True,
        pkcs11.CKA_KEY_TYPE: 0x00000000,
        pkcs11.CKA_MODULUS_BITS: 2048,
        pkcs11.CKA_SIGN: True,
    }
    backend = Pkcs11Backend(session=_FakePkcs11Session(attrs))
    desc = backend.describe("signing-key")
    assert desc["metadata"]["protection_level"] == "HARDWARE"
    assert desc["extractable"] is False


def test_pkcs11_extractable_key_is_software(monkeypatch):
    pkcs11 = pytest.importorskip("PyKCS11", reason="PyKCS11 not installed")
    attrs = {
        pkcs11.CKA_EXTRACTABLE: True,
        pkcs11.CKA_SENSITIVE: False,
        pkcs11.CKA_TOKEN: True,
        pkcs11.CKA_KEY_TYPE: 0x00000000,
        pkcs11.CKA_MODULUS_BITS: 2048,
        pkcs11.CKA_SIGN: True,
    }
    backend = Pkcs11Backend(session=_FakePkcs11Session(attrs))
    desc = backend.describe("signing-key")
    assert desc["metadata"]["protection_level"] == "SOFTWARE"
    assert desc["extractable"] is True


# ------------------------------------------------------- no key material out


def test_adapters_never_return_private_material():
    """Even if a provider leaks material, check_key must flag it and scrub it."""

    class _Leaky:
        def describe(self, key_ref):
            return {"metadata": {"origin": "AWS_CLOUDHSM"}, "private_key": "-----BEGIN PRIVATE KEY-----"}

        def sign_challenge(self, key_ref, nonce):
            return {"signature": b"sig"}

    result = check_key("k", provider="aws_kms", backend=_Leaky())
    assert "private_key" not in str(result["attributes"])
