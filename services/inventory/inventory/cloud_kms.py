"""Cloud KMS inventory connectors — AWS KMS and Azure Key Vault → crypto assets.

Read-only metadata collection: ListKeys + GetKeyDescription (AWS),
list_properties_of_keys + get_key (Azure). These provider APIs never return
key material and none is stored — only algorithm, size, usage, state and
origin, tagged with the collector that found them and folded into the same
crypto-asset inventory (and therefore the CBOM / migration roadmap).

Honesty rules:
- Unknown key specs are skipped WITH their reason, never guessed into a family.
- A key the caller may not describe is recorded as skipped, not silently absent.
- Collection is bounded per pass (MAX_KEYS_PER_PASS) and reports truncation.

The cloud SDKs are lazy imports: the API boots (and the pure normalizers test)
without boto3/Azure installed; an actual collection attempt without them
raises a RuntimeError with the exact install hint.
"""

from __future__ import annotations

import base64
from datetime import date, datetime
from typing import Any

MAX_KEYS_PER_PASS = 100

# KeySpec → (family, key_size, default_purpose). KMS symmetric keys are
# AES-256 (AWS documents this); RSA/ECC specs carry their bits in the name.
_AWS_SPECS: dict[str, tuple[str, int, str | None]] = {
    "SYMMETRIC_DEFAULT": ("AES-256", 256, "encryption"),
    "HMAC_224": ("HMAC-SHA224", 224, "mac"),
    "HMAC_256": ("HMAC-SHA256", 256, "mac"),
    "HMAC_384": ("HMAC-SHA384", 384, "mac"),
    "HMAC_512": ("HMAC-SHA512", 512, "mac"),
    "RSA_2048": ("RSA-2048", 2048, None),
    "RSA_3072": ("RSA-3072", 3072, None),
    "RSA_4096": ("RSA-4096", 4096, None),
    "ECC_NIST_P256": ("ECDSA-P256", 256, None),
    "ECC_NIST_P384": ("ECDSA-P384", 384, None),
    "ECC_NIST_P521": ("ECDSA-P521", 521, None),
    "ECC_SECG_P256K1": ("ECDSA-P256K1", 256, None),
}

_AWS_USAGE = {
    "ENCRYPT_DECRYPT": "encryption",
    "SIGN_VERIFY": "signing",
    "GENERATE_VERIFY_MAC": "mac",
    "KEY_AGREEMENT": "key_agreement",
}

# Azure KeyVault kty → family, via curve/size.
_AZURE_CURVES = {
    "P-256": ("ECDSA-P256", 256),
    "P-384": ("ECDSA-P384", 384),
    "P-521": ("ECDSA-P521", 521),
    "P-256K": ("ECDSA-P256K1", 256),
    "SECP256K1": ("ECDSA-P256K1", 256),
}


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read a field from either an SDK object (attributes) or a dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _iso(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


# ------------------------------------------------------------------- AWS KMS


def normalize_aws_key(description: dict[str, Any], *, region: str = "",
                      account: str = "") -> dict[str, Any] | None:
    """AWS GetKeyDescription dict → crypto-asset dict, or None if the key spec
    is not one we classify (the caller records the skip honestly)."""
    key_id = str(description.get("KeyId") or "").strip()
    spec = str(description.get("KeySpec")
               or description.get("CustomerMasterKeySpec") or "").strip()
    if not key_id or spec not in _AWS_SPECS:
        return None
    family, bits, default_purpose = _AWS_SPECS[spec]
    usage = str(description.get("KeyUsage") or "").strip()
    purpose = _AWS_USAGE.get(usage) or default_purpose
    where = region.strip() or "unknown"
    return {
        "algorithm": family,
        "key_size": bits,
        "purpose": purpose,
        "file_path": f"aws-kms://{where}/{key_id}",
        "source_language": "aws-kms",
        "confidence": "HIGH",
        "extra": {
            "collector": "aws-kms",
            "cloud": "aws",
            "key_id": key_id,
            "region": where,
            "aws_account": str(account or description.get("AWSAccountId") or ""),
            "enabled": bool(description.get("Enabled", True)),
            "origin": str(description.get("Origin") or ""),
            "key_spec": spec,
        },
    }


def collect_aws_kms(client: Any = None, *, region: str = "",
                    limit: int = MAX_KEYS_PER_PASS) -> dict[str, Any]:
    """List + describe KMS keys (bounded) → {provider, assets, skipped, seen, truncated}.

    `client` is any object exposing list_keys() / get_key_description(KeyId=…)
    — real boto3 is constructed lazily when omitted.
    """
    if client is None:
        try:
            import boto3  # noqa: F401 — presence check before construction
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for AWS KMS collection (pip install boto3)") from exc
        import boto3

        client = boto3.client("kms", region_name=region or None)

    listing = client.list_keys()
    entries = list(listing.get("Keys") or [])[: max(1, limit)]
    assets: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for entry in entries:
        key_id = str(entry.get("KeyId") or "")
        try:
            description = dict(client.get_key_description(KeyId=key_id))
        except Exception as exc:  # provider refused / transient — honest skip
            skipped.append({"ref": key_id, "reason": f"describe failed: {exc}"[:160]})
            continue
        asset = normalize_aws_key(description, region=region)
        if asset is None:
            spec = str(description.get("KeySpec")
                       or description.get("CustomerMasterKeySpec") or "unknown")
            skipped.append({"ref": key_id,
                            "reason": f"unsupported KeySpec '{spec}' — not classified"})
            continue
        assets.append(asset)
    return {
        "provider": "aws-kms",
        "assets": assets,
        "skipped": skipped,
        "seen": len(entries),
        "truncated": bool(listing.get("Truncated")) or len(list(listing.get("Keys") or [])) > len(entries),
    }


# -------------------------------------------------------------- Azure Key Vault


def _azure_family(kty: str, crv: str, key_size: Any) -> tuple[str, int] | None:
    if kty.startswith("RSA"):
        size = int(key_size) if key_size else 0
        if size in (2048, 3072, 4096):
            return (f"RSA-{size}", size)
        return None
    if kty.startswith("EC"):
        family = _AZURE_CURVES.get(crv)
        return family
    if kty.startswith("oct"):  # oct / oct-HSM — symmetric AES keys
        size = int(key_size) if key_size else 0
        if 128 <= size <= 512 and size % 64 == 0:
            return (f"AES-{size}", size)
        return None
    return None


def normalize_azure_key(bundle: Any, *, vault_url: str = "") -> dict[str, Any] | None:
    """Azure KeyVault key bundle (SDK object or dict) → asset dict, or None.

    Accepts {"key": {...}, "properties": {...}} shaped payloads; the RSA size
    comes from key_size when present, else from the modulus length (matching
    what the real JsonWebKey carries).
    """
    key = _attr(bundle, "key", None)
    properties = _attr(bundle, "properties", None)
    if key is None:
        return None
    kid = str(_attr(key, "kid", "") or "")
    kty = str(_attr(key, "kty", "") or "")
    crv = str(_attr(key, "crv", "") or "")
    key_size = _attr(key, "key_size", None)
    modulus = _attr(key, "n", None)
    if key_size is None and modulus:
        try:
            pad = "=" * (-len(str(modulus)) % 4)
            key_size = len(base64.urlsafe_b64decode(str(modulus) + pad)) * 8
        except Exception:
            key_size = None
    family = _azure_family(kty, crv, key_size)
    if family is None:
        return None
    algorithm, bits = family

    name = kid.rsplit("/", 1)[-1] if kid else ""
    if not name:
        return None
    vault_host = vault_url.strip().rstrip("/").split("//")[-1] if vault_url.strip() else "unknown"
    ops = list(_attr(properties, "operations", []) or [])
    purpose = ("signing" if "sign" in ops else
               "encryption" if "encrypt" in ops or "unwrapKey" in ops else None)
    extra: dict[str, Any] = {
        "collector": "azure-keyvault",
        "cloud": "azure",
        "key_name": name,
        "key_kid": kid,
        "vault": vault_host,
        "enabled": bool(_attr(properties, "enabled", True)),
        "kty": kty,
    }
    for source, field in (("expires_on", "expires_at"), ("created_on", "created_at"),
                          ("not_before", "not_before")):
        stamp = _iso(_attr(properties, source, None))
        if stamp:
            extra[field] = stamp
    return {
        "algorithm": algorithm,
        "key_size": bits,
        "purpose": purpose,
        "file_path": f"azure-kv://{vault_host}/{name}",
        "source_language": "azure-keyvault",
        "confidence": "HIGH",
        "extra": extra,
    }


def collect_azure_keyvault(client: Any = None, *, vault_url: str = "",
                           limit: int = MAX_KEYS_PER_PASS) -> dict[str, Any]:
    """List + fetch KeyVault keys (bounded) → {provider, assets, skipped, seen, truncated}.

    `client` is any object exposing list_properties_of_keys() / get_key(name)
    — the real KeyClient (azure-identity + azure-keyvault-keys) is constructed
    lazily when omitted.
    """
    if client is None:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
        except ImportError as exc:
            raise RuntimeError(
                "azure-identity and azure-keyvault-keys are required for KeyVault "
                "collection (pip install azure-identity azure-keyvault-keys)") from exc
        import os

        vault = vault_url.strip() or os.environ.get("AZURE_KEY_VAULT_URL", "")
        if not vault:
            raise RuntimeError("no vault configured — pass vault_url or set AZURE_KEY_VAULT_URL")
        client = KeyClient(vault_url=vault, credential=DefaultAzureCredential())

    assets: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen = 0
    truncated = False
    for props in client.list_properties_of_keys():
        if seen >= max(1, limit):
            truncated = True
            break
        seen += 1
        name = str(_attr(props, "name", "") or "")
        try:
            bundle = client.get_key(name)
        except Exception as exc:
            skipped.append({"ref": name, "reason": f"get_key failed: {exc}"[:160]})
            continue
        normalized = {
            "key": {
                "kid": _attr(bundle, "kid", None) or _attr(_attr(bundle, "key", None), "kid"),
                "kty": _attr(_attr(bundle, "key", None), "kty"),
                "crv": _attr(_attr(bundle, "key", None), "crv"),
                "key_size": _attr(_attr(bundle, "key", None), "key_size"),
                "n": _attr(_attr(bundle, "key", None), "n"),
            },
            "properties": {
                "enabled": _attr(props, "enabled", True),
                "operations": list(_attr(props, "operations", []) or []),
                "expires_on": _attr(props, "expires_on", None),
                "created_on": _attr(props, "created_on", None),
                "not_before": _attr(props, "not_before", None),
            },
        }
        asset = normalize_azure_key(normalized, vault_url=vault_url)
        if asset is None:
            kty = str(normalized["key"].get("kty") or "unknown")
            skipped.append({"ref": name,
                            "reason": f"unsupported key type '{kty}' — not classified"})
            continue
        assets.append(asset)
    return {"provider": "azure-keyvault", "assets": assets, "skipped": skipped,
            "seen": seen, "truncated": truncated}
