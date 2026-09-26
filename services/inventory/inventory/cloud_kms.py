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
from datetime import date, datetime, timezone
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


# --------------------------------------------------------------------- GCP KMS

# Cloud KMS CryptoKeyVersionAlgorithm → (family, bits, purpose).
# Symmetric encryption keys are AES-256 (GCP documents this); HMAC variants
# carry their digest; RSA/EC naming embeds curve and size.
_GCP_RSA = {
    "SIGN_PSS": "signing",
    "SIGN_PKCS1": "signing",
    "SIGN_RAW_PKCS1": "signing",
    "DECRYPT_OAEP": "encryption",
}


def _gcp_family(algorithm: str) -> tuple[str, int, str | None] | None:
    if algorithm == "GOOGLE_SYMMETRIC_ENCRYPTION":
        return ("AES-256", 256, "encryption")
    if algorithm.startswith("HMAC_SHA"):
        bits = algorithm.removeprefix("HMAC_SHA")
        if bits in {"224", "256", "384", "512"}:
            return (f"HMAC-SHA{bits}", int(bits), "mac")
        return None
    if algorithm.startswith("EC_SIGN_"):
        curves = {"P256_SHA256": ("ECDSA-P256", 256),
                  "P384_SHA384": ("ECDSA-P384", 384),
                  "SECP256K1_SHA256": ("ECDSA-P256K1", 256)}
        curve = curves.get(algorithm.removeprefix("EC_SIGN_"))
        if curve:
            return (curve[0], curve[1], "signing")
        return None
    # RSA_(SIGN_PSS|SIGN_PKCS1|SIGN_RAW_PKCS1|DECRYPT_OAEP)_<bits>(_SHAxxx)?
    parts = algorithm.split("_")
    if len(parts) >= 4 and parts[0] == "RSA":
        bits = next((p for p in parts if p.isdigit()), "")
        kind = "_".join(parts[1:parts.index(bits)])
        purpose = _GCP_RSA.get(kind)
        if purpose and bits in {"2048", "3072", "4096"}:
            return (f"RSA-{bits}", int(bits), purpose)
    return None


def normalize_gcp_key(kms_key: Any, *, project: str = "", location: str = "") -> dict[str, Any] | None:
    """GCP CryptoKey (SDK proto or dict) → asset dict, or None when the
    primary version's algorithm is not one we classify."""
    name = str(_attr(kms_key, "name", "") or "")
    primary = _attr(kms_key, "primary", None)
    algorithm = str(_attr(primary, "algorithm", "") or "") if primary else ""
    if not name or not algorithm:
        return None
    family = _gcp_family(algorithm)
    if family is None:
        return None
    algo, bits, purpose = family
    # name …/projects/P/locations/L/keyRings/R/cryptoKeys/K
    segments = name.strip("/").split("/")
    try:
        ring = segments[segments.index("keyRings") + 1]
        key_name = segments[segments.index("cryptoKeys") + 1]
        proj = project or segments[segments.index("projects") + 1]
        loc = location or segments[segments.index("locations") + 1]
    except (ValueError, IndexError):
        return None
    extra: dict[str, Any] = {
        "collector": "gcp-kms",
        "cloud": "gcp",
        "project": proj,
        "location": loc,
        "key_ring": ring,
        "key_name": key_name,
        "gcp_algorithm": algorithm,
        "protection_level": str(_attr(primary, "protection_level", "") or ""),
    }
    rotation = _iso(_attr(kms_key, "next_rotation_time", None))
    if rotation:
        extra["next_rotation_at"] = rotation
    return {
        "algorithm": algo,
        "key_size": bits,
        "purpose": purpose,
        "file_path": f"gcp-kms://projects/{proj}/locations/{loc}/keyRings/{ring}/{key_name}",
        "source_language": "gcp-kms",
        "confidence": "HIGH",
        "extra": extra,
    }


def collect_gcp_kms(client: Any = None, *, project: str = "", location: str = "global",
                    limit: int = MAX_KEYS_PER_PASS) -> dict[str, Any]:
    """List CryptoKeys (bounded) → {provider, assets, skipped, seen, truncated}.

    `client` is any object exposing list_crypto_keys(parent=…) — the real
    KeyManagementServiceClient (google-cloud-kms) is constructed lazily.
    """
    if client is None:
        if not project:
            raise RuntimeError("no project configured — pass project for GCP collection")
        try:
            from google.cloud import kms  # noqa: F401 — presence check
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-kms is required for GCP KMS collection "
                "(pip install google-cloud-kms)") from exc
        from google.cloud import kms as _kms

        client = _kms.KeyManagementServiceClient()
        parent = f"projects/{project}/locations/{location}/keyRings/-"
    else:
        parent = f"projects/{project or '-'}/locations/{location}/keyRings/-"

    # read limit+1 to know, honestly, whether more keys exist
    keys = list(client.list_crypto_keys(parent=parent))[: max(1, limit) + 1]
    truncated = len(keys) > limit
    keys = keys[:limit]
    assets: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for key in keys:
        normalized = normalize_gcp_key(key, project=project, location=location)
        if normalized is None:
            primary = _attr(key, "primary", None)
            algorithm = str(_attr(primary, "algorithm", "") or "") if primary else ""
            ref = str(_attr(key, "name", "") or "unknown").rsplit("/", 1)[-1]
            reason = ("no active primary version" if not primary
                      else f"unsupported algorithm '{algorithm}' — not classified")
            skipped.append({"ref": ref, "reason": reason})
            continue
        assets.append(normalized)
    return {"provider": "gcp-kms", "assets": assets, "skipped": skipped,
            "seen": len(keys), "truncated": truncated}


# --------------------------------------------------------------------- AWS ACM

_ACM_KEY_ALGOS = {
    "RSA_2048": ("RSA-2048", 2048),
    "RSA_3072": ("RSA-3072", 3072),
    "RSA_4096": ("RSA-4096", 4096),
    "EC_prime256v1": ("ECDSA-P256", 256),
    "EC_secp384r1": ("ECDSA-P384", 384),
    "EC_secp521r1": ("ECDSA-P521", 521),
}


def normalize_acm_certificate(detail: dict[str, Any], *, pem: str,
                              region: str = "") -> dict[str, Any] | None:
    """ACM describe_certificate + PEM → Certificate-repository payload.

    The SHA-256 fingerprint is computed from the REAL certificate DER — an
    identifier would be mislabeled, so certs without a retrievable PEM
    (pending validation) are skipped by the caller instead.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    arn = str(detail.get("CertificateArn") or "").strip()
    algorithm = str(detail.get("KeyAlgorithm") or "").strip()
    if not arn or algorithm not in _ACM_KEY_ALGOS:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception:
        return None
    family, bits = _ACM_KEY_ALGOS[algorithm]
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc).astimezone()).days
    try:
        sans = [str(g.value) for g in
                cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        sans = []
    return {
        "fingerprint_sha256": fingerprint,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "public_key_algorithm": family,
        "public_key_size": bits,
        "expiry_status": "expired" if days_left < 0 else "valid",
        "days_until_expiry": days_left,
        "is_self_signed": cert.subject == cert.issuer,
        "san": sans,
        "usages": ["tls"],
        "extra": {
            "collector": "aws-acm",
            "cloud": "aws",
            "arn": arn,
            "region": region,
            "acm_type": str(detail.get("Type") or ""),
            "acm_status": str(detail.get("Status") or ""),
            "signature_algorithm": str(detail.get("SignatureAlgorithm") or ""),
            "renewal_eligibility": str(detail.get("RenewalEligibility") or ""),
        },
    }


def collect_aws_acm(client: Any = None, *, region: str = "",
                    limit: int = MAX_KEYS_PER_PASS) -> dict[str, Any]:
    """Inventory ACM certificates into the shared certificate table.

    Three read-only calls per certificate (list → describe → PEM); the PEM is
    parsed locally so the fingerprint is the true SHA-256 of the DER.
    Certificates without a retrievable PEM (pending validation) are skipped
    WITH their reason.
    """
    if client is None:
        try:
            import boto3  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS ACM collection (pip install boto3)") from exc
        import boto3

        client = boto3.client("acm", region_name=region or None)

    listing = client.list_certificates()
    summaries = list(listing.get("CertificateSummaryList") or [])[: max(1, limit)]
    certificates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for summary in summaries:
        arn = str(summary.get("CertificateArn") or "")
        domain = str(summary.get("DomainName") or arn)
        try:
            detail = dict(client.describe_certificate(CertificateArn=arn).get("Certificate") or {})
            fetched = client.get_certificate(CertificateArn=arn)
            pem = str(fetched.get("Certificate") or "")
        except Exception as exc:
            skipped.append({"ref": domain, "reason": f"describe/pem failed: {exc}"[:160]})
            continue
        if not pem:
            skipped.append({"ref": domain,
                            "reason": f"no PEM issued yet (status {detail.get('Status') or 'unknown'})"})
            continue
        payload = normalize_acm_certificate(detail, pem=pem, region=region)
        if payload is None:
            skipped.append({"ref": domain,
                            "reason": f"unsupported KeyAlgorithm '{detail.get('KeyAlgorithm')}' "
                                      "or unparseable PEM — not classified"})
            continue
        certificates.append(payload)
    return {"provider": "aws-acm", "certificates": certificates, "skipped": skipped,
            "seen": len(summaries),
            "truncated": bool(listing.get("NextToken")) or len(list(listing.get("CertificateSummaryList") or [])) > limit}
