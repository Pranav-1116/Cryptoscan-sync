"""HSM / KMS / PKCS#11 connectivity and key-residence verification.

Deterministically verify that a key referenced by the platform actually lives
in a hardware-backed store (AWS KMS, Azure Key Vault / Managed HSM, Google
Cloud KMS, Thales/Utimaco Luna/PKCS#11 HSM) rather than in software, and report
the key's attributes.

Network/SDK access is injected as a ``backend`` callable so the logic is fully
testable offline and never imports a cloud SDK at module load. The canonical
deterministic test is a **non-exportable sign challenge**: a hardware-backed
key can sign inside the HSM but its private material cannot be exported. We
model three probes:

- connectivity   : endpoint reachable / authenticated
- key_residence  : the provider reports HSM-origin / non-exportable attributes
- sign_challenge : provider signs a fixed nonce with the key (material never
                   leaves the boundary) — proves the key is usable in-hardware

Key material is never returned (fail-closed scrub).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

SUPPORTED_PROVIDERS = ("aws_kms", "azure_keyvault", "azure_managed_hsm",
                       "gcp_kms", "pkcs11", "luna")

# Attribute values that prove hardware backing / non-exportability.
_HSM_ORIGIN = ("AWS_CLOUDHSM", "HSM", "HSM_PROTECTED", "HARDWARE",
               "TRANSIT_PROTECTED", "HSM_BACKED")
_NON_EXPORTABLE = ("EXTERNAL", "HSM", "true")


class HsmCheckError(ValueError):
    pass


@dataclass
class KeyAttributes:
    key_id: str
    provider: str
    state: str | None = None
    key_usage: list[str] = field(default_factory=list)
    algorithm: str | None = None
    key_spec: str | None = None
    origin: str | None = None          # AWS_KMS / AWS_CLOUDHSM / EXTERNAL
    protection_level: str | None = None  # HARDWARE / SOFTWARE
    exportable: bool | None = None
    extractable: bool | None = None
    raw_present: bool = False           # must stay False


class Backend(Protocol):
    """Minimal provider adapter contract. Implementations wrap SDKs; tests use
    a fake. All methods return plain dicts; never key bytes."""

    def describe(self, key_ref: str) -> dict[str, Any]: ...
    def sign_challenge(self, key_ref: str, nonce: bytes) -> dict[str, Any]: ...


_FORBIDDEN_SEGMENTS = frozenset({
    "privatekey", "private_key", "privkey", "plaintext", "key_material",
    "keymaterial", "pem", "privatekeymaterial", "secret_material",
    "privateexponent", "private_exponent",
})


def _is_material_key(k: str) -> bool:
    norm = k.lower().replace("-", "_")
    segments = set(norm.split("_"))
    if norm in _FORBIDDEN_SEGMENTS:
        return True
    # exact whole-field matches; do not match bare "material"/"secret" to
    # avoid eating legitimate fields like key_spec/origin.
    if "private" in segments or "plaintext" in segments:
        return True
    if "material" in segments and ("key" in segments or "private" in segments):
        return True
    return False


def _scrub(blob: Any) -> Any:
    """Recursively remove anything that looks like private key material."""
    if isinstance(blob, dict):
        return {k: _scrub(v) for k, v in blob.items() if not _is_material_key(str(k))}
    if isinstance(blob, list):
        return [_scrub(v) for v in blob]
    return blob


def check_key(key_ref: str, *, provider: str, backend: Backend) -> dict[str, Any]:
    """Run connectivity + residence + sign-challenge for one key reference."""
    provider = provider.lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HsmCheckError(f"unsupported provider {provider!r}; supported: {SUPPORTED_PROVIDERS}")

    result: dict[str, Any] = {
        "key_ref": key_ref, "provider": provider,
        "connectivity": "UNKNOWN", "key_residence": "UNKNOWN",
        "sign_challenge": "UNKNOWN", "hardware_backed": False,
        "attributes": None, "issues": [],
    }

    # 1) describe / connectivity
    try:
        desc = backend.describe(key_ref)
        result["connectivity"] = "OK"
    except Exception as exc:  # SDK/network failure
        result["connectivity"] = "FAIL"
        result["issues"].append({"severity": "HIGH", "code": "CONNECTIVITY",
                                 "detail": f"{type(exc).__name__}: {str(exc)[:160]}"})
        return _finalize(result)

    attrs = _extract_attributes(key_ref, provider, _scrub(desc or {}))
    result["attributes"] = attrs
    result["raw_key_material_present"] = attrs.raw_present  # must be False

    # 2) residence determination
    origin = (attrs.origin or "").upper()
    protection = (attrs.protection_level or "").upper()
    claims_hsm = _provider_claims_hsm(desc)
    if attrs.raw_present:
        result["key_residence"] = "SOFTWARE"
        result["issues"].append({"severity": "CRITICAL", "code": "KEY_MATERIAL_EXPOSED",
                                 "detail": "provider response contained private key material"})
    elif protection == "HARDWARE" or "CLOUDHSM" in origin or "HSM" in origin \
            or (origin == "EXTERNAL" and claims_hsm) or (provider in ("pkcs11", "luna") and protection != "SOFTWARE"):
        # Explicit hardware protection level, CloudHSM/HSM origin, an EXTERNAL
        # key in an HSM-backed custom key store, or a PKCS#11/Luna token key.
        result["key_residence"] = "HSM"
    elif protection == "SOFTWARE":
        result["key_residence"] = "SOFTWARE"
        result["issues"].append({"severity": "MEDIUM", "code": "NOT_HARDWARE_BACKED",
                                 "detail": "provider reports SOFTWARE protection level"})
    elif provider == "aws_kms" and origin == "AWS_KMS":
        # Default AWS-managed KMS keys are not dedicated-HSM backed.
        result["key_residence"] = "SOFTWARE"
        result["issues"].append({"severity": "MEDIUM", "code": "NOT_HARDWARE_BACKED",
                                 "detail": "AWS_KMS origin without CloudHSM/custom key store is not dedicated-HSM backed"})
    elif attrs.exportable is True or attrs.extractable is True:
        result["key_residence"] = "SOFTWARE"
        result["issues"].append({"severity": "HIGH", "code": "EXPORTABLE_KEY",
                                 "detail": "key is marked exportable/extractable — not hardware-protected"})
    else:
        result["key_residence"] = "UNDETERMINED"

    if attrs.exportable is True or attrs.extractable is True:
        result["issues"].append({"severity": "HIGH", "code": "EXPORTABLE_KEY",
                                 "detail": "key export/extract flag is set"})

    # 3) non-exportable sign challenge — proves in-hardware usability
    nonce = b"cryptoscan-hsm-challenge-0123456789abcdef"
    try:
        sign = backend.sign_challenge(key_ref, nonce)
        sig = (sign or {}).get("signature") or (sign or {}).get("Signature")
        if sig:
            result["sign_challenge"] = "OK"
        else:
            result["sign_challenge"] = "FAIL"
            result["issues"].append({"severity": "HIGH", "code": "SIGN_CHALLENGE",
                                     "detail": "provider returned no signature"})
    except Exception as exc:
        result["sign_challenge"] = "FAIL"
        result["issues"].append({"severity": "HIGH", "code": "SIGN_CHALLENGE",
                                 "detail": f"{type(exc).__name__}: {str(exc)[:160]}"})

    result["hardware_backed"] = result["key_residence"] == "HSM" and result["connectivity"] == "OK"
    return _finalize(result)


def _provider_claims_hsm(desc: dict) -> bool:
    text = str(desc).upper()
    return any(h in text for h in ("CUSTOM_KEY_STORE", "CLOUDHSM", "HSM"))


def _extract_attributes(key_ref: str, provider: str, d: dict) -> KeyAttributes:
    attrs = KeyAttributes(key_id=key_ref, provider=provider)
    meta = d.get("metadata") if isinstance(d.get("metadata"), dict) else d
    attrs.state = meta.get("state") or meta.get("enabled") or d.get("state")
    attrs.algorithm = meta.get("algorithm") or d.get("algorithm") or meta.get("alg")
    attrs.key_spec = meta.get("key_spec") or d.get("key_spec") or meta.get("spec")
    attrs.origin = meta.get("origin") or d.get("origin")
    attrs.protection_level = (meta.get("protection_level")
                              or d.get("protection_level") or d.get("protectionLevel"))
    if "exportable" in meta:
        attrs.exportable = bool(meta["exportable"])
    elif "exportable" in d:
        attrs.exportable = bool(d["exportable"])
    if "extractable" in meta or "extractable" in d:
        attrs.extractable = bool(meta.get("extractable", d.get("extractable")))
    usage = meta.get("key_usage") or d.get("key_usage") or meta.get("operations")
    if isinstance(usage, list):
        attrs.key_usage = [str(u) for u in usage]
    # raw material detection post-scrub (should always be False)
    attrs.raw_present = _contains_material(d)
    return attrs


def _contains_material(d: dict) -> bool:
    import re

    text = str(d)
    # a PEM private key block or a long base64 blob in a key-like field
    if "BEGIN" in text and "PRIVATE KEY" in text:
        return True
    return bool(re.search(r"'(private_key|material|plaintext)'\s*:\s*'.{40,}", text))


def _finalize(result: dict) -> dict:
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    worst = "INFO"
    for i in result["issues"]:
        if sev_order.get(i["severity"], 0) > sev_order.get(worst, 0):
            worst = i["severity"]
    result["worst_severity"] = worst
    result["attrib_dict"] = None  # placeholder removed below
    if isinstance(result["attributes"], KeyAttributes):
        result["attributes"] = {
            "key_id": result["attributes"].key_id,
            "provider": result["attributes"].provider,
            "state": str(result["attributes"].state),
            "algorithm": result["attributes"].algorithm,
            "key_spec": result["attributes"].key_spec,
            "origin": result["attributes"].origin,
            "protection_level": result["attributes"].protection_level,
            "exportable": result["attributes"].exportable,
            "extractable": result["attributes"].extractable,
            "key_usage": result["attributes"].key_usage,
            "raw_key_material_present": result["attributes"].raw_present,
        }
    result.pop("attrib_dict", None)
    return result


def check_many(checks: list[dict], *, backend_factory: Callable[[str], Backend]) -> dict:
    """Run check_key over many {key_ref, provider} specs and summarize."""
    results = []
    for spec in checks:
        backend = backend_factory(spec["provider"])
        results.append(check_key(spec["key_ref"], provider=spec["provider"], backend=backend))
    return {
        "total": len(results),
        "hardware_backed": sum(1 for r in results if r["hardware_backed"]),
        "software_keys": sum(1 for r in results if r["key_residence"] == "SOFTWARE"),
        "sign_ok": sum(1 for r in results if r["sign_challenge"] == "OK"),
        "connectivity_failures": sum(1 for r in results if r["connectivity"] == "FAIL"),
        "results": results,
    }
