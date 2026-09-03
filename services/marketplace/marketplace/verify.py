"""Deterministic plugin verification: content pinning + Ed25519 signatures.

Fail-closed trust model:

* The plugin payload hash MUST equal ``manifest.content_sha256``.
* Executable plugins MUST carry a valid Ed25519 signature over the signing
  digest, produced by a key whose *public* half is in the operator's pinned
  trust set. Data-only plugins may be unsigned.
* An unsupported platform version is rejected.

Signature scheme (Ed25519, deterministic, no AI):

    signing_digest = sha256( sha256(content_hex) || canonical_manifest_cbor-ish )

We sign over ``content_sha256 || canonical manifest JSON`` (sorted keys,
compact separators). Verification uses the ``cryptography`` library if
present; a plugin that requires verification but whose signature library is
unavailable fails closed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field

from marketplace.manifest import (
    MAX_CONTENT_BYTES,
    PluginManifest,
)


def _semver_tuple(v: str) -> tuple[int, int, int]:
    core = v.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    return tuple(int(p) for p in (parts + ["0", "0", "0"])[:3])  # type: ignore[return-value]


def platform_supports(manifest: PluginManifest, platform_version: str) -> bool:
    return _semver_tuple(platform_version) >= _semver_tuple(manifest.min_platform)


def content_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_manifest(manifest: PluginManifest) -> bytes:
    return json.dumps(
        manifest.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def signing_payload(manifest: PluginManifest) -> bytes:
    """The exact byte string that must be signed / verified."""
    return manifest.content_sha256.encode("ascii") + b"." + canonical_manifest(manifest)


def signing_digest(manifest: PluginManifest) -> bytes:
    return hashlib.sha256(signing_payload(manifest)).digest()


@dataclass
class VerificationResult:
    ok: bool
    trusted: bool = False
    reason: str = ""
    errors: list[str] = field(default_factory=list)
    signer_key_id: str | None = None

    def fail(self, msg: str) -> VerificationResult:
        self.ok = False
        self.errors.append(msg)
        if not self.reason:
            self.reason = msg
        return self


def _b64e(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"), validate=True)


def _verify_ed25519(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return False  # fail closed when the crypto backend is unavailable
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64))
        pub.verify(_b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_plugin(ed25519_private_key, manifest: PluginManifest) -> str:
    """Produce a base64 Ed25519 signature over the signing payload (helper)."""
    sig = ed25519_private_key.sign(signing_payload(manifest))
    return _b64e(sig)


def verify_plugin(
    manifest: PluginManifest,
    content: bytes,
    *,
    trusted_keys: Iterable[str] = (),
    signature: str | None = None,
    signer_key_id: str | None = None,
    platform_version: str = "999.0.0",
) -> VerificationResult:
    """Verify a plugin bundle. Returns a structured result (never raises for
    content problems — callers quarantine on ``not result.ok``)."""
    result = VerificationResult(ok=True)
    trust = {k.strip() for k in trusted_keys if k and k.strip()}

    # 1. size guard
    if len(content) > MAX_CONTENT_BYTES:
        return VerificationResult(ok=False).fail(
            f"plugin content exceeds {MAX_CONTENT_BYTES} bytes (got {len(content)})"
        )

    # 2. content pinning
    actual = content_digest(content)
    if actual != manifest.content_sha256:
        return VerificationResult(ok=False).fail(
            "content_sha256 mismatch — payload was tampered or corrupted"
        )

    # 3. platform gate
    if not platform_supports(manifest, platform_version):
        return VerificationResult(ok=False).fail(
            f"plugin requires platform >= {manifest.min_platform} "
            f"(running {platform_version})"
        )

    # 4. signature / trust (required for executable plugins)
    if manifest.is_executable:
        if not signature:
            return result.fail("executable plugin is not signed")
        if not signer_key_id:
            return result.fail("signed plugin is missing signer_key_id")
        if signer_key_id not in {e.split(":", 1)[0].strip() for e in trust if ":" in e}:
            return result.fail(
                f"signer {signer_key_id} is not in the pinned trust set"
            )
        # resolve key by id from the iterable (id:base64pub format)
        pub_key = _lookup_pubkey(trusted_keys, signer_key_id)
        if pub_key is None:
            return result.fail(f"no pinned public key for signer {signer_key_id}")
        if not _verify_ed25519(pub_key, signing_payload(manifest), signature):
            return result.fail("Ed25519 signature verification failed")
        result.trusted = True
        result.signer_key_id = signer_key_id

    return result


def _lookup_pubkey(trusted_keys: Iterable[str], key_id: str) -> str | None:
    for entry in trusted_keys:
        entry = entry.strip()
        if ":" in entry:
            kid, pub = entry.split(":", 1)
            if kid.strip() == key_id:
                return pub.strip()
    return None


def verify_manifest_dict(data: dict) -> PluginManifest:
    """Parse + structurally validate a raw manifest dict (raises ManifestError)."""
    return PluginManifest.from_dict(data)
