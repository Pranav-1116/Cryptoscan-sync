"""Map AWS API fields onto CryptoScan algorithm / purpose values."""

from __future__ import annotations

from typing import Any


def map_kms_key_spec(spec: str | None) -> tuple[str, int | None]:
    raw = (spec or "SYMMETRIC_DEFAULT").upper()
    if "SYMMETRIC" in raw:
        return "AES-256", 256
    if raw.startswith("RSA_"):
        bits = int(raw.split("_")[1]) if raw.split("_")[1].isdigit() else None
        return "RSA", bits
    if "ECC_NIST_P256" in raw or raw.endswith("P256"):
        return "ECDSA", 256
    if "ECC_NIST_P384" in raw or raw.endswith("P384"):
        return "ECDSA", 384
    if "ECC_NIST_P521" in raw or raw.endswith("P521"):
        return "ECDSA", 521
    if "ECC_SECG_P256K1" in raw:
        return "ECDSA", 256
    return raw, None


def map_s3_sse(algorithm: str | None) -> tuple[str, str | None]:
    raw = (algorithm or "").upper()
    if raw in {"AES256", "AES-256"}:
        return "AES-256", None
    if raw in {"AWS:KMS", "AWS:KMS:DSSE"}:
        return "AES-256", "KMS"
    return algorithm or "NONE", None


def map_acm_key(algorithm: str | None) -> tuple[str, int | None]:
    raw = (algorithm or "").upper().replace("-", "_")
    if raw.startswith("RSA_"):
        bits = int(raw.split("_")[1]) if raw.split("_")[1].isdigit() else None
        return "RSA", bits
    if "EC" in raw and "256" in raw:
        return "ECDSA", 256
    if "EC" in raw and "384" in raw:
        return "ECDSA", 384
    return algorithm or "UNKNOWN", None


def weak_tls_protocols(protocols: list[str] | None) -> bool:
    tokens = {(item or "").upper().replace(" ", "") for item in (protocols or [])}
    return bool(tokens & {"TLSV1", "TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2", "TLS-1-0", "TLS-1-1"})


def min_tls_from_protocols(protocols: list[str] | None) -> str:
    tokens = [(item or "").upper() for item in (protocols or [])]
    if any("1.0" in t or t.endswith("V1") for t in tokens):
        return "TLS1.0"
    if any("1.1" in t for t in tokens):
        return "TLS1.1"
    if any("1.3" in t for t in tokens) and not any("1.2" in t for t in tokens):
        return "TLS1.3"
    if any("1.2" in t for t in tokens):
        return "TLS1.2"
    return "TLS"


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
