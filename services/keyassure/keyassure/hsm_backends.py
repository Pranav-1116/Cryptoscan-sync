"""Concrete ``Backend`` adapters for :mod:`keyassure.hsm_connectivity`.

``hsm_connectivity`` classifies provider-reported residence, not hardware
attestation. These adapters perform SDK calls when explicitly selected; a
successful response must not be confused with customer-application execution.

Each adapter:

* imports its SDK lazily, inside the call, so this module is importable with
  none of them installed (the same idiom as ``cloud_scanner.aws.live``);
* normalises provider-native fields onto the small dict shape
  ``_extract_attributes`` reads (``origin`` / ``protection_level`` /
  ``key_spec`` / ``exportable`` / ``extractable`` / ``key_usage`` / ``state``);
* returns **no key material**, ever. ``check_key`` scrubs its input as a second
  line of defence, but these adapters never put material in the dict to begin
  with: they read attributes and signatures, never private components.

The sign challenge is the load-bearing probe: a hardware key signs inside the
boundary, but a nonempty SDK response is not signature verification or hardware proof.
Approved public-key verification is separate; application/hardware origin remains unknown.

    from keyassure.hsm_backends import AwsKmsBackend
    from keyassure.hsm_connectivity import check_key

    check_key("arn:aws:kms:...", provider="aws_kms", backend=AwsKmsBackend())
"""

from __future__ import annotations

import os
from typing import Any


class BackendUnavailable(RuntimeError):
    """The adapter's SDK (or native PKCS#11 library) is not installed."""


def _require(module: str, package: str):
    try:
        return __import__(module, fromlist=["*"])
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise BackendUnavailable(f"{package} is required for this backend: pip install {package}") from exc


# --------------------------------------------------------------------- AWS KMS


class AwsKmsBackend:
    """AWS KMS / CloudHSM-backed custom key stores.

    AWS does not report a ``protection_level``; hardware backing is expressed
    through ``Origin`` (``AWS_CLOUDHSM``) and the presence of a
    ``CustomKeyStoreId``. Both are passed through untouched so the caller's
    residence rules -- which already know a plain ``AWS_KMS`` origin is *not*
    dedicated-HSM backed -- can apply.
    """

    def __init__(self, *, region: str | None = None, session: Any = None, client: Any = None) -> None:
        self._session = session
        self._injected_client = client
        self._region = region

    def _client(self):
        if self._injected_client is not None:
            return self._injected_client
        if self._session is not None:
            return self._session.client("kms", region_name=self._region)
        boto3 = _require("boto3", "boto3")
        return boto3.Session().client("kms", region_name=self._region)

    def describe(self, key_ref: str) -> dict[str, Any]:
        meta = self._client().describe_key(KeyId=key_ref).get("KeyMetadata", {}) or {}
        return {
            "metadata": {
                "state": meta.get("KeyState"),
                "algorithm": (meta.get("SigningAlgorithms") or [None])[0],
                "key_spec": meta.get("KeySpec") or meta.get("CustomerMasterKeySpec"),
                "origin": meta.get("Origin"),
                "key_usage": [meta["KeyUsage"]] if meta.get("KeyUsage") else [],
                # Surfaced so _provider_claims_hsm() sees CUSTOM_KEY_STORE.
                "custom_key_store_id": meta.get("CustomKeyStoreId"),
                "multi_region": meta.get("MultiRegion"),
            },
            # A KMS CMK's private material is never exportable by design.
            "exportable": False,
        }

    def sign_challenge(self, key_ref: str, nonce: bytes, *, algorithm: str | None = None) -> dict[str, Any]:
        client = self._client()
        meta = client.describe_key(KeyId=key_ref).get("KeyMetadata", {}) or {}
        algorithms = meta.get("SigningAlgorithms") or []
        if not algorithms:
            raise ValueError(f"key {key_ref} has no signing algorithms (KeyUsage={meta.get('KeyUsage')})")
        if algorithm is not None and algorithm not in algorithms:
            raise ValueError("Approved signing algorithm is not offered by this key")
        chosen = algorithm or algorithms[0]
        resp = client.sign(
            KeyId=key_ref,
            Message=nonce,
            MessageType="RAW",
            SigningAlgorithm=chosen,
        )
        if resp.get("SigningAlgorithm", chosen) != chosen:
            raise ValueError("Provider changed approved signing algorithm")
        return {"signature": resp.get("Signature"), "algorithm": chosen}


# ------------------------------------------------------------- Azure Key Vault


class AzureKeyVaultBackend:
    """Azure Key Vault and Managed HSM.

    Azure encodes hardware backing in the key type: ``RSA-HSM`` / ``EC-HSM``
    are HSM-protected, plain ``RSA`` / ``EC`` are software. That is mapped onto
    ``protection_level`` so the shared residence rules apply unchanged.
    """

    def __init__(self, vault_url: str, *, credential: Any = None, client: Any = None) -> None:
        self.vault_url = vault_url
        self._credential = credential
        self._client = client

    def _key_client(self):
        if self._client is not None:
            return self._client
        keys = _require("azure.keyvault.keys", "azure-keyvault-keys")
        cred = self._credential
        if cred is None:
            identity = _require("azure.identity", "azure-identity")
            cred = identity.DefaultAzureCredential()
        return keys.KeyClient(vault_url=self.vault_url, credential=cred)

    def describe(self, key_ref: str) -> dict[str, Any]:
        key = self._key_client().get_key(key_ref)
        props = getattr(key, "properties", None)
        kty = str(getattr(getattr(key, "key", None), "kty", "") or "")
        hsm = kty.upper().endswith("-HSM")
        return {
            "metadata": {
                "state": "Enabled" if getattr(props, "enabled", None) else "Disabled",
                "key_spec": kty,
                "algorithm": kty,
                # Managed HSM and -HSM key types are hardware; everything else is not.
                "protection_level": "HARDWARE" if hsm else "SOFTWARE",
                "origin": "MANAGED_HSM" if hsm else "SOFTWARE",
                "key_usage": [str(o) for o in (getattr(getattr(key, "key", None), "key_ops", None) or [])],
                "vault": self.vault_url,
            },
            "exportable": bool(getattr(props, "exportable", False) or False),
        }

    def sign_challenge(self, key_ref: str, nonce: bytes) -> dict[str, Any]:
        import hashlib

        crypto_mod = _require("azure.keyvault.keys.crypto", "azure-keyvault-keys")
        key = self._key_client().get_key(key_ref)
        cred = self._credential
        if cred is None:
            identity = _require("azure.identity", "azure-identity")
            cred = identity.DefaultAzureCredential()
        client = crypto_mod.CryptographyClient(key, credential=cred)
        kty = str(getattr(getattr(key, "key", None), "kty", "") or "").upper()
        alg = crypto_mod.SignatureAlgorithm.es256 if kty.startswith("EC") else crypto_mod.SignatureAlgorithm.rs256
        # Key Vault signs a pre-computed digest, not the raw message.
        digest = hashlib.sha256(nonce).digest()
        result = client.sign(alg, digest)
        return {"signature": getattr(result, "signature", None), "algorithm": str(alg)}


# ----------------------------------------------------------------- Google KMS


class GcpKmsBackend:
    """Google Cloud KMS.

    GCP reports ``protection_level`` directly (``SOFTWARE`` / ``HSM`` /
    ``EXTERNAL``), which maps onto the shared rules with no interpretation.
    """

    def __init__(self, *, client: Any = None) -> None:
        self._client = client

    def _kms(self):
        if self._client is not None:
            return self._client
        kms = _require("google.cloud.kms", "google-cloud-kms")
        return kms.KeyManagementServiceClient()

    def describe(self, key_ref: str) -> dict[str, Any]:
        version = self._kms().get_crypto_key_version(name=key_ref)
        return {
            "metadata": {
                "state": str(getattr(version, "state", "")),
                "algorithm": str(getattr(version, "algorithm", "")),
                "key_spec": str(getattr(version, "algorithm", "")),
                "protection_level": str(getattr(version, "protection_level", "")).rsplit(".", 1)[-1].upper(),
                "origin": str(getattr(version, "protection_level", "")).rsplit(".", 1)[-1].upper(),
            },
            # CryptoKeyVersion material is non-extractable by construction.
            "extractable": False,
        }

    def sign_challenge(self, key_ref: str, nonce: bytes) -> dict[str, Any]:
        import hashlib

        resp = self._kms().asymmetric_sign(
            request={"name": key_ref, "digest": {"sha256": hashlib.sha256(nonce).digest()}}
        )
        return {"signature": getattr(resp, "signature", None), "algorithm": "SHA256"}


# ------------------------------------------------------------------- PKCS#11


class Pkcs11Backend:
    """A PKCS#11 token: Thales Luna, Utimaco, nCipher, CloudHSM's client, SoftHSM.

    Hardware backing is read from the object's own attributes rather than
    inferred: a key that is ``CKA_SENSITIVE`` and not ``CKA_EXTRACTABLE`` on a
    ``CKA_TOKEN`` object cannot leave the token. Those three attributes are the
    actual PKCS#11 definition of "the material stays in the HSM", so they are
    what the adapter reports.

    Needs the vendor's native Cryptoki library plus ``PyKCS11``; both are
    site-specific, so the library path is explicit (or ``PKCS11_LIB``) and the
    import is lazy.
    """

    def __init__(
        self, *, lib_path: str | None = None, slot: int | None = None, pin: str | None = None, session: Any = None
    ) -> None:
        self.lib_path = lib_path or os.environ.get("PKCS11_LIB", "")
        self.slot = slot
        # Read from the environment so a PIN need not be passed through call sites.
        self._pin = pin if pin is not None else os.environ.get("PKCS11_PIN")
        self._session = session

    def _open(self):
        if self._session is not None:
            return self._session
        pkcs11 = _require("PyKCS11", "PyKCS11")
        if not self.lib_path:
            raise BackendUnavailable("set lib_path or PKCS11_LIB to the vendor Cryptoki library")
        lib = pkcs11.PyKCS11Lib()
        lib.load(self.lib_path)
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            raise BackendUnavailable("no PKCS#11 slot with a token present")
        slot = self.slot if self.slot is not None else slots[0]
        session = lib.openSession(slot, pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)
        if self._pin:
            session.login(self._pin)
        return session

    def _find(self, session, key_ref: str):
        pkcs11 = _require("PyKCS11", "PyKCS11")
        # key_ref is a CKA_LABEL; fall back to CKA_ID for tokens keyed by id.
        for template in (
            [(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY), (pkcs11.CKA_LABEL, key_ref)],
            [(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY), (pkcs11.CKA_ID, tuple(key_ref.encode()))],
        ):
            found = session.findObjects(template)
            if found:
                return found[0]
        raise ValueError(f"no PKCS#11 private key with label or id {key_ref!r}")

    def describe(self, key_ref: str) -> dict[str, Any]:
        pkcs11 = _require("PyKCS11", "PyKCS11")
        session = self._open()
        obj = self._find(session, key_ref)
        wanted = [
            pkcs11.CKA_EXTRACTABLE,
            pkcs11.CKA_SENSITIVE,
            pkcs11.CKA_TOKEN,
            pkcs11.CKA_KEY_TYPE,
            pkcs11.CKA_MODULUS_BITS,
            pkcs11.CKA_SIGN,
        ]
        values = dict(zip(wanted, session.getAttributeValue(obj, wanted)))
        extractable = bool(values.get(pkcs11.CKA_EXTRACTABLE))
        sensitive = bool(values.get(pkcs11.CKA_SENSITIVE))
        on_token = bool(values.get(pkcs11.CKA_TOKEN))
        in_hardware = on_token and sensitive and not extractable
        key_type = values.get(pkcs11.CKA_KEY_TYPE)
        return {
            "metadata": {
                "state": "Enabled",
                "key_spec": _PKCS11_KEY_TYPES.get(key_type, str(key_type)),
                "algorithm": _PKCS11_KEY_TYPES.get(key_type, str(key_type)),
                "protection_level": "HARDWARE" if in_hardware else "SOFTWARE",
                "origin": "PKCS11_TOKEN",
                "key_usage": ["SIGN"] if values.get(pkcs11.CKA_SIGN) else [],
                "key_size": values.get(pkcs11.CKA_MODULUS_BITS),
                "token_object": on_token,
                "sensitive": sensitive,
            },
            "extractable": extractable,
            "exportable": extractable,
        }

    def sign_challenge(self, key_ref: str, nonce: bytes) -> dict[str, Any]:
        pkcs11 = _require("PyKCS11", "PyKCS11")
        session = self._open()
        obj = self._find(session, key_ref)
        key_type = session.getAttributeValue(obj, [pkcs11.CKA_KEY_TYPE])[0]
        mech = pkcs11.CKM_ECDSA_SHA256 if _PKCS11_KEY_TYPES.get(key_type) == "EC" else pkcs11.CKM_SHA256_RSA_PKCS
        signature = session.sign(obj, nonce, pkcs11.Mechanism(mech, None))
        return {"signature": bytes(signature), "algorithm": _PKCS11_KEY_TYPES.get(key_type, "")}


# CKK_* numeric key types -> readable names (values are fixed by the standard).
_PKCS11_KEY_TYPES = {0x00000000: "RSA", 0x00000001: "DSA", 0x00000002: "DH", 0x00000003: "EC", 0x0000001F: "AES"}


BACKENDS = {
    "aws_kms": AwsKmsBackend,
    "azure_keyvault": AzureKeyVaultBackend,
    "azure_managed_hsm": AzureKeyVaultBackend,
    "gcp_kms": GcpKmsBackend,
    "pkcs11": Pkcs11Backend,
    "luna": Pkcs11Backend,
}
