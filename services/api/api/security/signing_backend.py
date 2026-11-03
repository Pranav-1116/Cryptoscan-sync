"""Where a report signature's private key actually lives.

The report signer used to take a PEM path and nothing else. That is fine for a
laptop and wrong for a bank: the key that signs regulatory evidence should live
in an HSM or a KMS, never in a file next to the process, and a deployment that
says "use the HSM" must fail loudly when the HSM is unreachable rather than
quietly fall back to something weaker.

This module is that seam. ``REPORT_SIGNING_KEY`` selects the backend by scheme:

======================  ==================================================
reference               backend
======================  ==================================================
``/etc/cryptoscan/…``   PEM file on disk (the pre-existing behaviour)
``-----BEGIN…``         inline PEM (secrets-manager substitution)
``aws-kms://<key-id>``  AWS KMS asymmetric CMK, RSASSA_PKCS1_V1_5_SHA_256
``vault://transit/<k>`` HashiCorp Vault Transit key
``pkcs11://<lib>?…``    PKCS#11 device (SoftHSM, YubiHSM, Luna, …)
======================  ==================================================

Every non-file backend is optional: the SDK or module it needs is imported at
construction time, and an absent module or an unreachable device raises
:class:`SignerRefused` with the reason. Nothing here degrades a signature to an
HMAC — a deployment that cannot sign says so.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlparse

#: RSASSA-PKCS1-v1_5 with SHA-256 — the algorithm the report path has always
#: produced, and the one every KMS/HMAC-free backend below is asked for.
ALG = "RS256"


class SignerRefused(RuntimeError):
    """The configured backend cannot be used. Never downgraded, always raised."""


class Signer(Protocol):
    """Minimal signing surface the report path needs."""

    alg: str

    def key_id(self) -> str | None: ...

    def sign(self, data: bytes) -> bytes: ...

    def describe(self) -> dict[str, Any]: ...


@dataclass
class FileSigner:
    """PEM private key from a file path or inline PEM text."""

    reference: str
    key_name: str | None = None
    alg: str = field(default=ALG, init=False)

    def key_id(self) -> str | None:
        return self.key_name

    def sign(self, data: bytes) -> bytes:
        from reporting.signing import SigningError, _b64url_decode, sign_bytes

        try:
            signed = sign_bytes(data, self.reference)
        except SigningError as exc:
            raise SignerRefused(str(exc)) from exc
        return _b64url_decode(signed["value"])

    def describe(self) -> dict[str, Any]:
        return {"backend": "file", "alg": self.alg, "key_id": self.key_id()}


@dataclass
class AwsKmsSigner:
    """An asymmetric CMK in AWS KMS.

    The private key never leaves KMS; ``kms.Sign`` returns the signature. The
    key policy — not this process — decides who may use it, which is the point.
    """

    key_id_ref: str
    region: str | None = None
    alg: str = field(default=ALG, init=False)
    _client: Any = field(default=None, repr=False)

    def _kms(self):
        if self._client is None:
            try:
                import boto3  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise SignerRefused(
                    "aws-kms:// signing needs the 'boto3' package (pip install boto3)"
                ) from exc
            try:
                self._client = boto3.client("kms", region_name=self.region)
            except Exception as exc:  # noqa: BLE001 - credentials/endpoint problems
                raise SignerRefused(f"aws-kms:// client could not be created: {exc}") from exc
        return self._client

    def key_id(self) -> str | None:
        return self.key_id_ref

    def sign(self, data: bytes) -> bytes:
        client = self._kms()
        try:
            response = client.sign(
                KeyId=self.key_id_ref,
                Message=data,
                MessageType="RAW",
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
            )
        except Exception as exc:  # noqa: BLE001 - any KMS refusal is a refusal to sign
            raise SignerRefused(f"aws-kms:// sign failed: {exc}") from exc
        signature = response.get("Signature") if isinstance(response, dict) else None
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise SignerRefused("aws-kms:// returned no signature")
        return bytes(signature)

    def describe(self) -> dict[str, Any]:
        return {"backend": "aws-kms", "alg": self.alg, "key_id": self.key_id()}


@dataclass
class VaultTransitSigner:
    """HashiCorp Vault Transit — the key lives in Vault, signing happens there.

    Reuses the same ``VAULT_ADDR`` / ``VAULT_TOKEN`` / ``VAULT_TIMEOUT_SECONDS``
    settings the secret resolver already reads, so an install that stores its
    other credentials in Vault does not need a second set of coordinates.
    """

    mount: str
    key: str
    address: str
    token: str
    timeout: float = 5.0
    alg: str = field(default=ALG, init=False)

    def key_id(self) -> str | None:
        return self.key

    def sign(self, data: bytes) -> bytes:
        if not self.address or not self.token:
            raise SignerRefused(
                "vault:// transit signing needs VAULT_ADDR and VAULT_TOKEN configured"
            )
        import urllib.error
        import urllib.request

        body = json.dumps(
            {
                "input": base64.b64encode(data).decode("ascii"),
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.address.rstrip('/')}/v1/{self.mount}/sign/{self.key}",
            data=body,
            method="POST",
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - configured endpoint
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SignerRefused(f"vault transit sign failed: {exc}") from exc
        signature = ((payload or {}).get("data") or {}).get("signature") or ""
        # "vault:v1:<base64>" — the version prefix is Vault's, the bytes are ours.
        parts = str(signature).split(":")
        if len(parts) < 3 or parts[0] != "vault":
            raise SignerRefused("vault transit returned no usable signature")
        try:
            return base64.b64decode(parts[-1])
        except ValueError as exc:
            raise SignerRefused("vault transit returned a malformed signature") from exc

    def describe(self) -> dict[str, Any]:
        return {"backend": "vault-transit", "alg": self.alg, "key_id": self.key_id()}


@dataclass
class Pkcs11Signer:
    """A private key on a PKCS#11 device.

    The reference carries everything but the PIN:

        pkcs11:///usr/lib/softhsm/libsofthsm2.so?token=cryptoscan&label=report-signing&pin=env:HSM_PIN

    ``pin=env:NAME`` (or ``file:path``) keeps the PIN out of the process
    environment listing and out of the settings dump — the same indirection the
    secret resolver uses. A literal PIN is accepted but warned about by the
    audit script, not silently blessed.
    """

    library: str
    token_label: str
    key_label: str
    pin: str
    alg: str = field(default=ALG, init=False)

    def key_id(self) -> str | None:
        return self.key_label

    def sign(self, data: bytes) -> bytes:
        try:
            import pkcs11  # type: ignore[import-not-found]
            from pkcs11 import KeyType, Mechanism, ObjectClass
            from pkcs11.util.rsa import encode_rsa_public_key  # noqa: F401
        except ImportError as exc:
            raise SignerRefused(
                "pkcs11:// signing needs the 'python-pkcs11' package and the "
                "vendor's PKCS#11 library"
            ) from exc
        try:
            lib = pkcs11.lib(self.library)
            token = lib.get_token(token_label=self.token_label)
            with token.open(user_pin=self.pin) as session:
                key = session.get_key(
                    object_class=ObjectClass.PRIVATE_KEY,
                    key_type=KeyType.RSA,
                    label=self.key_label,
                )
                return bytes(key.sign(data, mechanism=Mechanism.RSA_PKCS))
        except SignerRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - device/driver errors are refusals
            raise SignerRefused(f"pkcs11:// sign failed: {exc}") from exc

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "pkcs11",
            "alg": self.alg,
            "key_id": self.key_id(),
            "token": self.token_label,
            "pin_from": "reference" if not self.pin else ("env/file" if self.pin == "" else "resolved"),
        }


def _resolve_pin(value: str) -> str:
    """``env:NAME`` / ``file:path`` / literal PIN."""
    if value.startswith("env:"):
        import os

        name = value[4:]
        resolved = os.environ.get(name, "")
        if not resolved:
            raise SignerRefused(f"PKCS#11 pin references empty environment variable {name}")
        return resolved
    if value.startswith("file:"):
        from pathlib import Path

        path = Path(value[5:])
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SignerRefused(f"PKCS#11 pin file unreadable: {exc}") from exc
    return value


def scheme_of(reference: str) -> str:
    """The backend a signing reference selects (``file`` when there is no scheme)."""
    text = (reference or "").strip()
    if text.startswith("aws-kms://"):
        return "aws-kms"
    if text.startswith("vault://transit/"):
        return "vault-transit"
    if text.startswith("pkcs11://"):
        return "pkcs11"
    return "file"


def build_signer(reference: str, *, key_name: str | None = None, settings: Any = None) -> Signer | None:
    """Construct the signer a reference names. ``None`` means "no signing configured"."""
    text = (reference or "").strip()
    if not text:
        return None
    scheme = scheme_of(text)
    if scheme == "file":
        return FileSigner(reference=text, key_name=key_name)
    if scheme == "aws-kms":
        parsed = urlparse(text)
        key_id_ref = unquote(parsed.netloc + parsed.path).lstrip("/")
        if not key_id_ref:
            raise SignerRefused("aws-kms:// reference needs a key id or ARN")
        region = parse_qs(parsed.query).get("region", [None])[0]
        return AwsKmsSigner(key_id_ref=key_id_ref, region=region)
    if scheme == "vault-transit":
        parsed = urlparse(text)
        # vault://transit/<mount>/<key>
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            raise SignerRefused("vault://transit/ reference needs mount and key name")
        address = str(getattr(settings, "VAULT_ADDR", "") or "")
        token = str(getattr(settings, "VAULT_TOKEN", "") or "")
        timeout = float(getattr(settings, "VAULT_TIMEOUT_SECONDS", 5.0) or 5.0)
        return VaultTransitSigner(
            mount=parts[0], key="/".join(parts[1:]), address=address, token=token, timeout=timeout
        )
    if scheme == "pkcs11":
        parsed = urlparse(text)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        library = unquote(parsed.path)
        if not library:
            raise SignerRefused("pkcs11:// reference needs the PKCS#11 library path")
        for required in ("token", "label"):
            if not query.get(required):
                raise SignerRefused(f"pkcs11:// reference needs ?{required}=")
        pin_ref = query.get("pin", "env:CRYPTOSCAN_HSM_PIN")
        return Pkcs11Signer(
            library=library,
            token_label=query["token"],
            key_label=query["label"],
            pin=_resolve_pin(pin_ref),
        )
    raise SignerRefused(f"unknown signing backend: {scheme}")


def report_signer_from_settings(settings: Any) -> Signer | None:
    """The report signer this deployment configured, or ``None``."""
    reference = str(getattr(settings, "REPORT_SIGNING_KEY", "") or "").strip()
    key_name = str(getattr(settings, "REPORT_SIGNING_KEY_ID", "") or "").strip() or None
    return build_signer(reference, key_name=key_name, settings=settings)


def signer_status(settings: Any) -> dict[str, Any]:
    """What a deployment would sign with — and whether it can, right now.

    Reported by ``/ops/signing`` so an operator finds out a KMS token expired
    from a dashboard, not from a bank rejecting an unsigned report.
    """
    reference = str(getattr(settings, "REPORT_SIGNING_KEY", "") or "").strip()
    if not reference:
        return {"configured": False, "backend": None, "note": "reports carry no signature"}
    scheme = scheme_of(reference)
    status: dict[str, Any] = {"configured": True, "backend": scheme, "alg": ALG}
    try:
        signer = report_signer_from_settings(settings)
        assert signer is not None
        # A real round-trip: construct, sign a fixed probe, report what happened.
        probe = signer.sign(b"cryptoscan signing self-test")
        status.update(
            {
                "usable": bool(probe),
                "key_id": signer.key_id(),
                "probe_bytes": len(probe),
                "detail": signer.describe(),
            }
        )
    except SignerRefused as exc:
        status.update({"usable": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - status must never raise at an operator
        status.update({"usable": False, "error": f"{type(exc).__name__}: {exc}"})
    return status
