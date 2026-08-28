"""Import CycloneDX cryptographic-asset components from a vendor SBOM/CBOM."""

from __future__ import annotations

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
                "key_size": int(param) if str(param).isdigit() else None,
                "mode": str(mode).upper() if mode else None,
                "key_management": key_mgmt,
                "pqc_ready": _is_pqc(algorithm),
                "discovery_method": "SBOM",
                "confidence": "HIGH",
                "source_document": sbom.get("serialNumber") or sbom.get("bomFormat"),
            }
        )
    return out


def _is_pqc(algorithm: str) -> bool:
    try:
        from shared_models.quantum_classify import quantum_verdict

        return quantum_verdict(algorithm)["verdict"] == "PQC_RESISTANT"
    except Exception:
        return algorithm.upper().startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "FALCON"))


def _algorithm(name: str, primitive: str, param: Any, mode: Any) -> str:
    upper = name.upper()
    for token in ("TLS 1.3", "TLS1.3", "TLS 1.2", "TLS1.2", "TLS 1.0", "AES-256", "AES-128", "ML-KEM", "RSA"):
        if token.replace(" ", "") in upper.replace(" ", ""):
            return token.replace(" ", "") if "TLS" in token else token
    if primitive in {"ae", "block-cipher", "enc"}:
        bits = param or "256"
        suffix = f"-{str(mode).upper()}" if mode else ""
        return f"AES-{bits}{suffix}"
    return name
