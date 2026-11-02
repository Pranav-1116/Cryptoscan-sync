"""Algorithm identity: one name per primitive, or an honest *different* answer.

The VBOM reconciles values that vendors, SBOMs, CBOMs and runtimes write down
by hand, and they do not spell them the same way: ``AES256``, ``AES-256``,
``aes_256`` and ``AES 256`` are one algorithm, while ``AES-256`` and
``AES-256-GCM`` are not — the second names a mode as well, so a source that
says the first is saying *less*, not something else.

This module answers three questions and refuses a fourth:

* :func:`algorithm_identity` — what is this string, structurally?
* :func:`compare_algorithms` — do two strings name the same thing, and if not,
  is the difference a parameter, a mode, or a different algorithm altogether?
* :func:`same_algorithm` — the boolean, for callers that only need the boolean.
* It will not answer "is this string *correct*". A name that matches nothing it
  knows comes back with ``recognised=False`` and a canonical form built from its
  shape, so the reconciler can still compare ``FOO256`` with ``FOO-256`` while a
  report says plainly that nobody in this codebase knows what FOO is.

Everything here is a pure function of a string; no repository or network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

SCHEMA = "cryptoscan.algorithm-identity/1"

#: Relations :func:`compare_algorithms` can return. Three of them are *not* a
#: contradiction, and the caller is expected to keep the distinction.
RELATIONS: tuple[str, ...] = (
    "SAME_IDENTITY",       # one algorithm, spelled two ways
    "LESS_SPECIFIC",       # one source says less: AES-256 against AES-256-GCM
    "DIFFERENT_PARAMETER",  # same family, different size: AES-128 against AES-256
    "DIFFERENT_MODE",      # same primitive, two modes: AES-256-GCM against CBC
    "DIFFERENT_ALGORITHM",  # different family
    "UNKNOWN_IDENTITY",    # at least one side is not a name at all
)


@dataclass(frozen=True)
class AlgorithmIdentity:
    """A parsed algorithm name, plus where it came from."""

    canonical: str
    family: str
    key_size: int | None = None
    mode: str | None = None
    parameter_set: str | None = None
    recognised: bool = True
    raw: str = ""

    @property
    def pqc(self) -> bool:
        return self.family in PQC_FAMILIES

    @property
    def normalised(self) -> bool:
        """True when the caller's spelling differed from the canonical form.

        ``AES256``, ``aes_256`` and ``AES 256`` are all normalised; ``AES-256``
        is not. The flag is what lets a report say *these two sources agree after
        normalisation* instead of quietly rewriting one of them.
        """
        return bool(self.raw) and self.raw.strip() != self.canonical

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "canonical": self.canonical,
            "family": self.family,
            "key_size": self.key_size,
            "mode": self.mode,
            "parameter_set": self.parameter_set,
            "recognised": self.recognised,
            "pqc": self.pqc,
            "normalised": self.normalised,
        }


PQC_FAMILIES = frozenset({
    "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "SPHINCS+", "HQC", "BIKE", "CLASSIC-MCELIECE",
})
CLASSICAL_ASYMMETRIC = frozenset({
    "RSA", "ECDSA", "ECDH", "EDDSA", "DH", "DSA", "ELGAMAL", "X25519", "X448",
})
SYMMETRIC = frozenset({"AES", "3DES", "DES", "CHACHA20", "CAMELLIA", "ARIA", "SM4", "RC4"})
HASH_FAMILIES = frozenset({"SHA-1", "SHA-2", "SHA-3", "SHAKE", "MD5", "BLAKE2", "SM3"})

#: Well-known spellings that carry information a shape parser would lose.
#: Keys are compacted (upper case, nothing but ``A-Z0-9``).
_EXPLICIT: dict[str, tuple[str, str, int | None, str | None, str | None]] = {
    # compact form: (canonical, family, key_size, mode, parameter_set)
    "AES": ("AES", "AES", None, None, None),
    "AES128": ("AES-128", "AES", 128, None, None),
    "AES192": ("AES-192", "AES", 192, None, None),
    "AES256": ("AES-256", "AES", 256, None, None),
    "AES128GCM": ("AES-128-GCM", "AES", 128, "GCM", None),
    "AES256GCM": ("AES-256-GCM", "AES", 256, "GCM", None),
    "AES128CBC": ("AES-128-CBC", "AES", 128, "CBC", None),
    "AES256CBC": ("AES-256-CBC", "AES", 256, "CBC", None),
    "AES256CTR": ("AES-256-CTR", "AES", 256, "CTR", None),
    "AES256CCM": ("AES-256-CCM", "AES", 256, "CCM", None),
    "AES256KW": ("AES-256-KW", "AES", 256, "KW", None),
    "RIJNDAEL": ("AES", "AES", None, None, None),
    "3DES": ("3DES", "3DES", 168, None, None),
    "TDEA": ("3DES", "3DES", 168, None, None),
    "TRIPLEDES": ("3DES", "3DES", 168, None, None),
    "DES": ("DES", "DES", 56, None, None),
    "RC4": ("RC4", "RC4", 128, None, None),
    "CHACHA20": ("ChaCha20", "CHACHA20", 256, None, None),
    "CHACHA20POLY1305": ("ChaCha20-Poly1305", "CHACHA20", 256, "POLY1305", None),
    "RSA": ("RSA", "RSA", None, None, None),
    "RSA1024": ("RSA-1024", "RSA", 1024, None, None),
    "RSA2048": ("RSA-2048", "RSA", 2048, None, None),
    "RSA3072": ("RSA-3072", "RSA", 3072, None, None),
    "RSA4096": ("RSA-4096", "RSA", 4096, None, None),
    "RSAPSS": ("RSA-PSS", "RSA", None, "PSS", None),
    "RSASSAPSS": ("RSA-PSS", "RSA", None, "PSS", None),
    "RSAOAEP": ("RSA-OAEP", "RSA", None, "OAEP", None),
    "RSAKEYTRANSPORT": ("RSA", "RSA", None, "KEY_TRANSPORT", None),
    "RSASIGNATURE": ("RSA", "RSA", None, "SIGNATURE", None),
    "ECDSA": ("ECDSA", "ECDSA", None, None, None),
    "ECDSA256": ("ECDSA-P-256", "ECDSA", 256, None, "P-256"),
    "ECDSAP256": ("ECDSA-P-256", "ECDSA", 256, None, "P-256"),
    "ECDSAP384": ("ECDSA-P-384", "ECDSA", 384, None, "P-384"),
    "ECDSASHA256": ("ECDSA-SHA-256", "ECDSA", None, "SHA-256", None),
    "ECDH": ("ECDH", "ECDH", None, None, None),
    "ECDHP256": ("ECDH-P-256", "ECDH", 256, None, "P-256"),
    "ECDHES": ("ECDHE", "ECDH", None, "EPHEMERAL", None),
    "ECDHE": ("ECDHE", "ECDH", None, "EPHEMERAL", None),
    "DHE": ("DHE", "DH", None, "EPHEMERAL", None),
    "DH": ("DH", "DH", None, None, None),
    "DSA": ("DSA", "DSA", None, None, None),
    "X25519": ("X25519", "X25519", 255, None, "curve25519"),
    "X448": ("X448", "X448", 448, None, "curve448"),
    "ED25519": ("EdDSA-Ed25519", "EDDSA", 255, None, "Ed25519"),
    "EDDSA25519": ("EdDSA-Ed25519", "EDDSA", 255, None, "Ed25519"),
    "ED448": ("EdDSA-Ed448", "EDDSA", 448, None, "Ed448"),
    "EDDSA": ("EdDSA", "EDDSA", None, None, None),
    "SECP256R1": ("ECDSA-P-256", "ECDSA", 256, None, "P-256"),
    "PRIME256V1": ("ECDSA-P-256", "ECDSA", 256, None, "P-256"),
    "SECP384R1": ("ECDSA-P-384", "ECDSA", 384, None, "P-384"),
    "SECP521R1": ("ECDSA-P-521", "ECDSA", 521, None, "P-521"),
    "MLDSA": ("ML-DSA", "ML-DSA", None, None, None),
    "MLDSA44": ("ML-DSA-44", "ML-DSA", None, None, "44"),
    "MLDSA65": ("ML-DSA-65", "ML-DSA", None, None, "65"),
    "MLDSA87": ("ML-DSA-87", "ML-DSA", None, None, "87"),
    "DILITHIUM2": ("ML-DSA-44", "ML-DSA", None, None, "44"),
    "DILITHIUM3": ("ML-DSA-65", "ML-DSA", None, None, "65"),
    "DILITHIUM5": ("ML-DSA-87", "ML-DSA", None, None, "87"),
    "MLKEM": ("ML-KEM", "ML-KEM", None, None, None),
    "MLKEM512": ("ML-KEM-512", "ML-KEM", None, None, "512"),
    "MLKEM768": ("ML-KEM-768", "ML-KEM", None, None, "768"),
    "MLKEM1024": ("ML-KEM-1024", "ML-KEM", None, None, "1024"),
    "KYBER512": ("ML-KEM-512", "ML-KEM", None, None, "512"),
    "KYBER768": ("ML-KEM-768", "ML-KEM", None, None, "768"),
    "KYBER1024": ("ML-KEM-1024", "ML-KEM", None, None, "1024"),
    "SLHDSA": ("SLH-DSA", "SLH-DSA", None, None, None),
    "SPHINCSSHA2128S": ("SLH-DSA-SHA2-128s", "SLH-DSA", 128, None, "128s"),
    "SLHDSASHA2128S": ("SLH-DSA-SHA2-128s", "SLH-DSA", 128, None, "128s"),
    "FALCON512": ("Falcon-512", "FALCON", None, None, "512"),
    "FALCON1024": ("Falcon-1024", "FALCON", None, None, "1024"),
    "SHA1": ("SHA-1", "SHA-1", None, None, None),
    "SHA256": ("SHA-256", "SHA-2", 256, None, None),
    "SHA384": ("SHA-384", "SHA-2", 384, None, None),
    "SHA512": ("SHA-512", "SHA-2", 512, None, None),
    "SHA3256": ("SHA3-256", "SHA-3", 256, None, None),
    "SHA3384": ("SHA3-384", "SHA-3", 384, None, None),
    "SHA3512": ("SHA3-512", "SHA-3", 512, None, None),
    "SHAKE128": ("SHAKE128", "SHAKE", 128, None, None),
    "MD5": ("MD5", "MD5", 128, None, None),
    "BLAKE2": ("BLAKE2", "BLAKE2", None, None, None),
    "HMACSHA256": ("HMAC-SHA-256", "SHA-2", 256, "HMAC", None),
    "HMACSHA384": ("HMAC-SHA-384", "SHA-2", 384, "HMAC", None),
}

#: ``SHA2-256`` and ``SHA-2-256`` compact to ``SHA2256``, which is the same
#: algorithm as ``SHA-256``. Kept separate because it is a spelling rule, not a
#: family of its own.
_SHA2_ALIASES = {"SHA2256": "SHA256", "SHA2384": "SHA384", "SHA2512": "SHA512"}
_SECP_ALIASES = {"P256": "SECP256R1", "P384": "SECP384R1", "P521": "SECP521R1"}

_MODES = ("GCM", "CBC", "CTR", "CCM", "POLY1305", "KW", "OAEP", "PSS", "OFB", "CFB", "XTS")


def _compact(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


def _shape(compact: str, raw: str) -> AlgorithmIdentity:
    """A name nobody here knows, described by its shape and marked as such."""
    match = re.fullmatch(r"([A-Z][A-Z0-9]*?)(\d{3,4})(GCM|CBC|CTR|CCM|POLY1305|KW|XTS)?", compact)
    if match:
        family = match.group(1)
        canonical = f"{family}-{match.group(2)}"
        if match.group(3):
            canonical += f"-{match.group(3)}"
        return AlgorithmIdentity(canonical=canonical, family=family,
                                 key_size=int(match.group(2)), mode=match.group(3),
                                 recognised=False, raw=raw)
    return AlgorithmIdentity(canonical=compact or raw.strip(), family=compact or "",
                             recognised=False, raw=raw)


def algorithm_identity(name: Any) -> AlgorithmIdentity:
    """Parse one algorithm name into its identity.

    ``AES256``, ``aes_256``, ``AES-256`` and ``AES 256`` all return
    ``canonical="AES-256"``; ``AES-256-GCM`` returns the same family and size
    with ``mode="GCM"``, which is what lets the reconciler call the pair
    *less specific* instead of *equal*.
    """
    raw = str(name if name is not None else "").strip()
    if not raw:
        raise ValueError("an algorithm with no name cannot be reconciled")
    compact = _compact(raw)
    if not compact:
        raise ValueError(f"{raw!r} contains no algorithm name")
    compact = _SHA2_ALIASES.get(compact, _SECP_ALIASES.get(compact, compact))
    if compact in _EXPLICIT:
        canonical, family, size, mode, params = _EXPLICIT[compact]
        return AlgorithmIdentity(canonical=canonical, family=family, key_size=size,
                                 mode=mode, parameter_set=params, raw=raw)
    # ``AES-256`` style names whose compact form missed the table.
    match = re.fullmatch(r"([A-Z][A-Z0-9]*?)(?:-)?(\d{3,4})?-?(" + "|".join(_MODES) + r")?", compact)
    if match and match.group(2) and match.group(1) in {"AES", "CAMELLIA", "ARIA", "SM4"}:
        size = int(match.group(2))
        mode = match.group(3)
        canonical = f"{match.group(1)}-{size}" + (f"-{mode}" if mode else "")
        return AlgorithmIdentity(canonical=canonical, family=match.group(1), key_size=size,
                                 mode=mode, raw=raw)
    return _shape(compact, raw)


def compare_algorithms(left: Any, right: Any) -> dict[str, Any]:
    """How two spellings relate, in the vocabulary a reviewer can act on.

    ``SAME_IDENTITY`` and ``LESS_SPECIFIC`` mean no source is wrong;
    ``DIFFERENT_PARAMETER``, ``DIFFERENT_MODE`` and ``DIFFERENT_ALGORITHM`` mean
    at least one source is — and the difference is named so the reader knows
    which.
    """
    try:
        a = algorithm_identity(left)
        b = algorithm_identity(right)
    except ValueError as exc:
        return {"relation": "UNKNOWN_IDENTITY", "reason": str(exc),
                "left": None, "right": None, "normalised": False}
    if a.canonical == b.canonical:
        relation = "SAME_IDENTITY"
        reason = (f"both name {a.canonical}"
                  + (" (spelled differently)" if _compact(a.raw) != _compact(b.raw) else ""))
    elif a.family != b.family:
        relation = "DIFFERENT_ALGORITHM"
        reason = f"{a.canonical} and {b.canonical} are different algorithm families"
    elif a.key_size is not None and b.key_size is not None and a.key_size != b.key_size:
        relation = "DIFFERENT_PARAMETER"
        reason = f"same family, {a.key_size} against {b.key_size} bits"
    elif (a.mode is None) != (b.mode is None) and (
            a.parameter_set is None or a.parameter_set == b.parameter_set):
        relation = "LESS_SPECIFIC"
        reason = (f"{a.canonical if a.mode is None else b.canonical} does not state the mode "
                  f"the other side names")
    elif a.mode != b.mode:
        relation = "DIFFERENT_MODE"
        reason = f"same primitive, mode {a.mode} against {b.mode}"
    elif a.parameter_set != b.parameter_set:
        relation = "DIFFERENT_PARAMETER"
        reason = f"different parameter sets: {a.parameter_set} against {b.parameter_set}"
    else:
        relation = "UNKNOWN_IDENTITY"
        reason = "the two names agree on family but not on any attribute this model knows"
    return {"relation": relation, "reason": reason, "left": a.to_dict(),
            "right": b.to_dict(),
            "normalised": relation == "SAME_IDENTITY" and (a.normalised or b.normalised)}


def same_algorithm(left: Any, right: Any) -> bool:
    """Same identity — not merely the same family. ``AES-128`` is not ``AES-256``."""
    return compare_algorithms(left, right)["relation"] == "SAME_IDENTITY"


def normalise_algorithm(name: Any) -> str:
    """The canonical spelling, or ``""`` when the name cannot be parsed."""
    try:
        return algorithm_identity(name).canonical
    except ValueError:
        return ""


def normalise_all(names: Iterable[Any]) -> list[str]:
    """Canonical forms of many names, keeping order and dropping duplicates."""
    seen: list[str] = []
    for name in names:
        canonical = normalise_algorithm(name)
        if canonical and canonical not in seen:
            seen.append(canonical)
    return seen


def identity_summary(names: Sequence[Any]) -> dict[str, Any]:
    """A small report: what was recognised, what was not, and what is PQC."""
    rows = [algorithm_identity(name) for name in names if str(name or "").strip()]
    unrecognised = sorted({row.raw for row in rows if not row.recognised})
    return {
        "schema": SCHEMA,
        "count": len(rows),
        "canonical": normalise_all(names),
        "families": sorted({row.family for row in rows}),
        "pqc": sorted({row.canonical for row in rows if row.pqc}),
        "unrecognised": unrecognised,
        "statement": (
            "every name parsed into a known family" if not unrecognised else
            f"{len(unrecognised)} name(s) are not in the alias table "
            f"({', '.join(unrecognised)}); they compare by shape only and must not "
            "be asserted to be a known primitive"
        ),
    }
