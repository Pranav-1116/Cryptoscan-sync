"""Registry bridge for normalization — one source for names, families, statuses.

Before this module the service kept six private exact-name knowledge bases
(PatternMatcher aliases + families, FamilyEnricher sets, NISTEnricher sets,
IANA mappings) that diverged from each other and from the shared algorithm
registry. Everything the registry knows is asked here; the legacy tables
remain only as honest fallbacks when the registry is unavailable.

Every helper returns None (never a guess) when the registry does not
recognize the input.
"""

from __future__ import annotations

from typing import Any, Optional

try:  # heavy import kept guarded so the service stays import-light
    from shared_models.algorithm_registry import parse_algorithm
except Exception:  # pragma: no cover - registry missing in exotic deployments
    parse_algorithm = None

# Registry family -> NormalizedCrypto.algorithm_family (model-allowed set).
# The old FamilyEnricher emitted 'pqc', which the model validator rejects.
_FAMILY_MAP = {
    "block-cipher": "symmetric",
    "stream-cipher": "symmetric",
    "aead": "symmetric",
    "pke": "asymmetric",
    "hash": "hash",
    "mac": "mac",
    "kdf": "kdf",
    "signature": "signature",
    "kem-pqc": "key-agreement",
    "signature-pqc": "signature",
}

# Families where a number embedded in the raw name can only be a key size
# (in hash names like SHA-256 the digits are the digest size, not a key).
_KEYED_FAMILIES = {"block-cipher", "stream-cipher", "aead", "pke"}


def _info(raw: str) -> Optional[Any]:
    if parse_algorithm is None or not raw:
        return None
    try:
        info = parse_algorithm(str(raw))
    except Exception:
        return None
    return info if getattr(info, "recognized", False) else None


def canonical_name(raw: str) -> Optional[str]:
    """Registry-canonical name (AES_128_CBC -> AES), or None if unrecognized."""
    info = _info(raw)
    return str(info.canonical) if info else None


def model_family(raw: str) -> Optional[str]:
    """Algorithm family in the NormalizedCrypto vocabulary, or None."""
    info = _info(raw)
    if info is None:
        return None
    return _FAMILY_MAP.get(str(info.family))


def name_key_size(raw: str) -> Optional[int]:
    """Key size embedded in the algorithm name (RSA-2048 -> 2048), or None."""
    info = _info(raw)
    if info is None or str(info.family) not in _KEYED_FAMILIES:
        return None
    key_size = getattr(info, "key_size", None)
    try:
        return int(key_size) if key_size is not None else None
    except (TypeError, ValueError):
        return None


def fixed_key_size(raw: str) -> Optional[int]:
    """The only possible key size, when structurally determined (DES -> 56).

    AES (128/192/256) and 3DES (112/168) have several options, so they are
    not fixed; a scanner-reported size for them is real evidence.
    """
    info = _info(raw)
    if info is None or str(info.family) not in _KEYED_FAMILIES:
        return None
    allowed = set(getattr(info, "allowed_key_sizes", None) or ())
    key_size = getattr(info, "key_size", None)
    if key_size is None:
        return None
    return int(key_size) if len(allowed) <= 1 else None


def nist_designation(raw: str, key_size: Optional[int] = None) -> Optional[str]:
    """Map the registry status onto the NIST SP 800-131A vocabulary.

    DISALLOWED -> DISALLOWED, DEPRECATED -> DEPRECATED,
    RESTRICTED -> ACCEPTABLE (allowed in constrained contexts),
    ALLOWED -> APPROVED unless the key size is below the registry minimum,
    in which case the use is DISALLOWED regardless of the algorithm.
    Returns None when unrecognized — the caller's legacy tables decide.
    """
    info = _info(raw)
    if info is None:
        return None
    status = str(info.status)
    if status == "DISALLOWED":
        return "DISALLOWED"
    if status == "DEPRECATED":
        return "DEPRECATED"
    if status == "RESTRICTED":
        return "ACCEPTABLE"
    if status == "ALLOWED":
        minimum = getattr(info, "min_key_size", None)
        if key_size and minimum and int(key_size) < int(minimum):
            return "DISALLOWED"
        return "APPROVED"
    return None


def registry_family(raw: str) -> Optional[str]:
    """Raw registry family string (exposed for diagnostics), or None."""
    info = _info(raw)
    return str(info.family) if info else None


def resolve_key_size(
    rule_size: Optional[int],
    raw: str,
    context_size: Optional[int],
) -> Optional[int]:
    """Decide between a rule's key size and a scanner-reported one.

    Precedence on conflict:
      1. the size is written into the raw string itself (AES-256-GCM) —
         the string wins;
      2. the algorithm has a single structurally possible size (DES 56) —
         the rule wins;
      3. otherwise the rule value was a default guess for an undersized
         pattern ("AES/GCM/NoPadding" -> 256) and the scanner's measured
         size wins.
    """
    if context_size is None:
        return rule_size
    if rule_size is None:
        return context_size
    if int(rule_size) == int(context_size):
        return rule_size
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    if digits and str(rule_size) in digits:
        return rule_size  # grounded in the raw string
    if fixed_key_size(raw) is not None:
        return rule_size  # structurally the only option
    return context_size  # scanner-measured beats rule default
