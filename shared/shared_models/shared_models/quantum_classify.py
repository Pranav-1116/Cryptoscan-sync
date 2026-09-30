"""Quantum verdicts for any algorithm name — the single shared classifier.

Built on the algorithm registry (which already parses code names, JOSE
names, SSH names, curves and full TLS suites), so every service reports
the same verdict for the same string. Services keep their own scoring;
this module only classifies.

Verdict taxonomy:

* ``SHOR_VULNERABLE``  — asymmetric: broken by a CRQC (RSA/ECC/DH/...)
* ``PQC_RESISTANT``    — ML-KEM / ML-DSA / SLH-DSA families
* ``GROVER_MARGINAL``  — symmetric/hash with a parameter below the
  comfortable post-quantum floor (cipher key < 256 bits, digest < 384)
* ``QUANTUM_RESISTANT``— symmetric/AEAD/MAC at adequate strength
* ``UNKNOWN``          — unrecognized names or unmodeled families (kdf);
  absence of a verdict is never silently treated as safe
"""

from __future__ import annotations

from typing import Any, Iterable

from shared_models.algorithm_registry import parse_algorithm

SHOR_VULNERABLE = "SHOR_VULNERABLE"
GROVER_MARGINAL = "GROVER_MARGINAL"
QUANTUM_RESISTANT = "QUANTUM_RESISTANT"
PQC_RESISTANT = "PQC_RESISTANT"
UNKNOWN = "UNKNOWN"

#: comfortable post-quantum parameter floors (Grover halves security)
CIPHER_KEY_FLOOR_BITS = 256
HASH_DIGEST_FLOOR_BITS = 384

_CIPHER_FAMILIES = {"block-cipher", "stream-cipher", "aead"}

#: Families Grover acts on, whether or not the registry bothered to say so.
_GROVER_FAMILIES = _CIPHER_FAMILIES | {"hash"}


def _grover_applies(info) -> bool:
    """True when Grover is the relevant quantum attack on this primitive.

    The registry only stamps ``quantum_impact`` on algorithms it still allows,
    so every DEPRECATED/DISALLOWED symmetric primitive carries ``None`` —
    3DES, DES, RC4, SHA-1, MD5, IDEA, SEED, CAST5. Trusting that field alone
    sent all of them to UNKNOWN, which is wrong twice over: they are recognized,
    modelled families with known parameters, and they are exactly the legacy
    crypto a migration programme exists to find. Being classically broken does
    not remove the quantum dimension — it compounds it.

    So the family decides, and the registry field is only a fast path.
    """
    return info.quantum_impact == "grover" or info.family in _GROVER_FAMILIES


def quantum_verdict(raw: str | None) -> dict[str, Any]:
    """Classify one algorithm name. Never guesses: unrecognized -> UNKNOWN."""
    info = parse_algorithm(raw or "")
    verdict = UNKNOWN
    reason = "unrecognized algorithm name"
    if info.recognized and info.family != "unknown":
        if info.quantum_impact == "shor":
            verdict = SHOR_VULNERABLE
            reason = "asymmetric primitive broken by Shor's algorithm"
        elif info.family.endswith("-pqc"):
            verdict = PQC_RESISTANT
            reason = "post-quantum family (FIPS 203/204/205)"
        elif _grover_applies(info):
            size = info.key_size
            if info.family in _CIPHER_FAMILIES:
                if size is None:
                    verdict = UNKNOWN
                    reason = "key size unknown — resistance cannot be asserted"
                elif size < CIPHER_KEY_FLOOR_BITS:
                    verdict = GROVER_MARGINAL
                    reason = f"{size}-bit key halved to ~{size // 2} bits under Grover"
                else:
                    verdict = QUANTUM_RESISTANT
                    reason = "symmetric at adequate post-quantum strength"
            elif info.family == "hash":
                if size is None:
                    verdict = UNKNOWN
                    reason = "digest size unknown — resistance cannot be asserted"
                elif size < HASH_DIGEST_FLOOR_BITS:
                    verdict = GROVER_MARGINAL
                    reason = f"{size}-bit digest below the {HASH_DIGEST_FLOOR_BITS}-bit post-quantum floor"
                else:
                    verdict = QUANTUM_RESISTANT
                    reason = "hash at adequate post-quantum strength"
            else:
                verdict = QUANTUM_RESISTANT
                reason = "Grover impact only; no parameter concern modeled"
        elif info.family == "mac":
            verdict = QUANTUM_RESISTANT
            reason = "symmetric PRF construction"
        else:
            verdict = UNKNOWN
            reason = f"family '{info.family}' has no quantum model yet"
    return {
        "raw": info.raw,
        "algorithm": info.canonical,
        "family": info.family,
        "status": info.status,
        "key_size": info.key_size,
        "parameter_kind": info.parameter_kind,
        "verdict": verdict,
        "quantum_vulnerable": verdict == SHOR_VULNERABLE,
        "reason": reason,
        "recognized": info.recognized,
    }


def is_shor_vulnerable(raw: str | None) -> bool:
    """Convenience predicate for hot-spot counting."""
    return quantum_verdict(raw)["verdict"] == SHOR_VULNERABLE


def summarize_verdicts(names: Iterable[str | None]) -> dict[str, Any]:
    """Aggregate verdicts over a list of algorithm names (order-free)."""
    counts: dict[str, int] = {}
    vulnerable_algorithms: set[str] = set()
    unknown_algorithms: set[str] = set()
    total = 0
    for name in names:
        total += 1
        row = quantum_verdict(name)
        verdict = row["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict == SHOR_VULNERABLE:
            vulnerable_algorithms.add(row["algorithm"])
        elif verdict == UNKNOWN:
            unknown_algorithms.add(str(name))
    return {
        "total": total,
        "counts": dict(sorted(counts.items())),
        "shor_vulnerable_algorithms": sorted(vulnerable_algorithms),
        "unknown_names": sorted(unknown_algorithms),
    }
