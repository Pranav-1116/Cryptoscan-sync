"""Algorithm weakness policy for drift — one bridge to the shared registry.

Replaces four drift-local weak-algorithm sets (detector, gate, severity
calculator x2) with a single registry-backed verdict. The registry knows
key-size policy (RSA min 2048), mode weakening (AES-…-ECB), versioned
names (RSA-1024), and legacy spellings (DESede / TripleDES -> 3DES).

Weak means: DISALLOWED, DEPRECATED, or RESTRICTED classical (pre-standard
PQC names like Kyber are RESTRICTED but not weak), ECB mode on a cipher,
or an explicit key size outside the registry's allowed/minimum sizes.
The registry remains the source of truth; this module only adapts it.
"""

from __future__ import annotations

from typing import Any, Mapping

try:  # shared_models is on the platform PYTHONPATH; degrade honestly if absent
    from shared_models.algorithm_registry import (
        DEPRECATED,
        DISALLOWED,
        RESTRICTED,
        UNKNOWN,
        parse_algorithm,
    )

    _REGISTRY = True
except Exception:  # pragma: no cover — only hit in standalone embedding
    _REGISTRY = False
    parse_algorithm = None  # type: ignore[assignment]
    DISALLOWED, DEPRECATED, RESTRICTED, UNKNOWN = "DISALLOWED", "DEPRECATED", "RESTRICTED", "UNKNOWN"

#: legacy spellings the old drift sets treated as weak; the registry covers
#: the rest. Kept so no previously-flagged name silently stops flagging.
LEGACY_WEAK_NAMES = {"DESEDE", "DES-EDE3", "TRIPLEDES", "ECB"}

_CIPHER_FAMILIES = {"block-cipher", "stream-cipher", "aead"}

# key-size weakness scores like "deprecated": an RSA key below the registry
# minimum is practically broken, and the legacy severity path's dedicated
# key-size factor is unreachable before its change-type early returns.
_KIND_SCORE = {"disallowed": 4, "ecb-mode": 4, "deprecated": 3, "key-size": 3, "restricted": 2, "legacy-name": 4}


def algorithm_weakness(
    algorithm: str | None,
    key_size: int | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Registry-backed weakness verdict for one algorithm sighting."""
    raw = str(algorithm or "")
    if _REGISTRY:
        info = parse_algorithm(raw)
        canonical = info.canonical if info.recognized else raw.upper() or "UNKNOWN"
        family = info.family if info.recognized else "unknown"
        status = info.status if info.recognized else UNKNOWN
    else:  # pragma: no cover — standalone fallback keeps legacy behavior
        canonical, family, status = raw.upper() or "UNKNOWN", "unknown", UNKNOWN
        info = None

    weak_kind: str | None = None
    reason: str | None = None
    if status == DISALLOWED:
        weak_kind, reason = "disallowed", f"{canonical} is disallowed by the algorithm registry"
    elif status == DEPRECATED:
        weak_kind, reason = "deprecated", f"{canonical} is deprecated by the algorithm registry"
    elif status == RESTRICTED and not family.endswith("-pqc"):
        weak_kind, reason = "restricted", f"{canonical} is restricted (not for new use); pre-standard PQC names are exempt"
    if weak_kind is None and mode and str(mode).upper() == "ECB" and family in _CIPHER_FAMILIES:
        weak_kind, reason = "ecb-mode", f"{canonical} in ECB mode leaks structure; use an AEAD mode"
    if weak_kind is None and info is not None and key_size is not None:
        allowed = info.allowed_key_sizes or ()
        minimum = info.min_key_size
        if allowed and int(key_size) not in allowed:
            weak_kind = "key-size"
            reason = f"{canonical} key size {key_size} is outside the registry's allowed sizes {list(allowed)}"
        elif minimum and int(key_size) < minimum:
            weak_kind = "key-size"
            reason = f"{canonical} key size {key_size} is below the registry minimum {minimum}"
    unrecognized = (not _REGISTRY) or (info is not None and not info.recognized)
    if weak_kind is None and unrecognized and raw.upper() in LEGACY_WEAK_NAMES:
        weak_kind, reason = "legacy-name", f"{raw.upper()} is a legacy weak spelling"
    return {
        "algorithm": canonical,
        "raw": raw,
        "family": family,
        "status": status if _REGISTRY else UNKNOWN,
        "weak": weak_kind is not None,
        "weak_kind": weak_kind,
        "reason": reason,
        "weakness_score": _KIND_SCORE.get(weak_kind or "", 0),
        "is_hash": family == "hash",
        "recognized": bool(_REGISTRY and info is not None and info.recognized),
    }


def is_weak(algorithm: str | None, key_size: int | None = None, mode: str | None = None) -> bool:
    return algorithm_weakness(algorithm, key_size=key_size, mode=mode)["weak"]


def weakness_score(algorithm: str | None, key_size: int | None = None, mode: str | None = None) -> int:
    return algorithm_weakness(algorithm, key_size=key_size, mode=mode)["weakness_score"]


def is_hash(algorithm: str | None) -> bool:
    if _REGISTRY:
        return parse_algorithm(str(algorithm or "")).family == "hash"
    return str(algorithm or "").upper() in {"MD5", "SHA-1", "SHA1", "SHA-256", "SHA-512"}


def finding_is_weak(finding: Mapping[str, Any]) -> bool:
    """Convenience for finding/record dicts with separate mode/key_size fields."""
    return is_weak(
        finding.get("algorithm"),
        key_size=finding.get("key_size"),
        mode=finding.get("mode"),
    )
