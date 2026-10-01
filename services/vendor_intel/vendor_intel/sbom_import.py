"""Import CycloneDX cryptographic-asset components from a vendor SBOM/CBOM."""

from __future__ import annotations

import re
from typing import Any


def import_vendor_cbom(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    components = sbom.get("components") or []
    out: list[dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        ctype = str(component.get("type") or "").lower()
        props = component.get("cryptoProperties") or {}
        algo_props = props.get("algorithmProperties") or {}
        if ctype not in {"cryptographic-asset", "crypto-asset"} and not props:
            continue
        primitive = str(algo_props.get("primitive") or "")
        param = algo_props.get("parameterSetIdentifier")
        mode = algo_props.get("mode")
        name = str(component.get("name") or "vendor-crypto")
        algorithm = _algorithm(name, primitive, param, mode)
        key_mgmt = None
        for prop in component.get("properties") or []:
            if str(prop.get("name") or "").lower() in {"key-management", "kms"}:
                key_mgmt = prop.get("value")
        out.append(
            {
                "crypto_use_case": name,
                "algorithm": algorithm,
                "algorithm_raw": name if algorithm is None else None,
                "key_size": int(param) if str(param).isdigit() else None,
                "mode": str(mode).upper() if mode else None,
                "key_management": key_mgmt,
                "pqc_ready": _is_pqc(algorithm),
                "discovery_method": "SBOM",
                # A structured CBOM record is strong evidence of a crypto
                # asset, but an unrecognized component name is not proof of a
                # particular algorithm.
                "confidence": "HIGH" if algorithm else "MEDIUM",
                "source_document": sbom.get("serialNumber") or sbom.get("bomFormat"),
            }
        )
    return out


def _is_pqc(algorithm: str | None) -> bool:
    if not algorithm:
        return False
    try:
        from shared_models.quantum_classify import quantum_verdict

        return quantum_verdict(algorithm)["verdict"] == "PQC_RESISTANT"
    except Exception:
        return algorithm.upper().startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "FALCON"))


def _algorithm(name: str, primitive: str, param: Any, mode: Any) -> str | None:
    """Extract a canonical algorithm only from complete known tokens."""
    source = " ".join((str(name), str(primitive), str(param or ""), str(mode or "")))
    candidates = (
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-KEM",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-DSA",
        "KYBER512", "KYBER768", "KYBER1024", "KYBER",
        "DILITHIUM2", "DILITHIUM3", "DILITHIUM5", "DILITHIUM",
        "FALCON", "SPHINCS", "AES-256", "AES-128", "AES256", "AES128", "AES",
        "CHACHA20", "RSA-4096", "RSA-2048", "RSA-1024", "RSA", "ECDSA", "ED25519",
        "SHA-512", "SHA-384", "SHA-256", "SHA512", "SHA384", "SHA256",
        "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3",
    )
    for token in candidates:
        pattern = re.compile(
            r"(?<![A-Za-z0-9-])" + re.escape(token) + r"(?![A-Za-z0-9-])",
            re.IGNORECASE,
        )
        if pattern.search(source):
            canonical_token = token.upper()
            if canonical_token.startswith("DILITHIUM"):
                canonical_token = "DILITHIUM"
            elif canonical_token.startswith("KYBER"):
                canonical_token = "KYBER"
            elif canonical_token.startswith("ML-KEM"):
                canonical_token = "ML-KEM"
            elif canonical_token.startswith("ML-DSA"):
                canonical_token = "ML-DSA"
            aes_alias = re.fullmatch(r"AES(128|256)", canonical_token)
            if aes_alias:
                canonical_token = f"AES-{aes_alias.group(1)}"
            sha_alias = re.fullmatch(r"SHA(1|256|384|512)", canonical_token)
            if sha_alias:
                canonical_token = f"SHA-{sha_alias.group(1)}"
            try:
                from shared_models.algorithm_registry import parse_algorithm
                parsed = parse_algorithm(canonical_token)
                if parsed.recognized:
                    return parsed.canonical
            except (ImportError, AttributeError, TypeError, ValueError):
                pass
            return canonical_token
    primitive_name = str(primitive).lower()
    if primitive_name in {"ae", "block-cipher", "enc"}:
        bits = str(param) if str(param).isdigit() else None
        if bits in {"128", "192", "256"}:
            suffix = str(mode).upper() if mode else ""
            return f"AES-{bits}" + (f"-{suffix}" if suffix else "")
    return None
