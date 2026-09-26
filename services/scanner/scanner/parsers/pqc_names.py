"""FIPS 203/204/205 and pre-standard PQC algorithm spellings → canonical names.

Shared by every language parser so ``Kyber768`` (liboqs), ``ML-KEM-768`` (OpenSSL 3.5 / JDK 24 / .NET 10),
``MLKem768`` (.NET), ``ml_kem_768`` (pqcrypto), ``SPHINCS+-SHA2-128s-simple`` (liboqs) and ``Dilithium3``
all land on ML-KEM / ML-DSA / SLH-DSA. Works as an ``algo_map`` for the rule engine: lookups are prefix-aware
so parameter-set suffixes never need enumerating.
"""

from __future__ import annotations

_PREFIXES: tuple[tuple[str, str], ...] = (
    ("mlkem", "ML-KEM"), ("ml-kem", "ML-KEM"), ("ml_kem", "ML-KEM"), ("kyber", "ML-KEM"), ("crystals-kyber", "ML-KEM"),
    ("mldsa", "ML-DSA"), ("ml-dsa", "ML-DSA"), ("ml_dsa", "ML-DSA"), ("dilithium", "ML-DSA"), ("crystals-dilithium", "ML-DSA"),
    ("slhdsa", "SLH-DSA"), ("slh-dsa", "SLH-DSA"), ("slh_dsa", "SLH-DSA"), ("sphincs", "SLH-DSA"),
    ("falcon", "FALCON"), ("fn-dsa", "FALCON"), ("fndsa", "FALCON"),
    ("hqc", "HQC"), ("frodokem", "FrodoKEM"), ("frodo", "FrodoKEM"), ("bike", "BIKE"), ("ntru", "NTRU"), ("classic-mceliece", "McEliece"), ("mceliece", "McEliece"),
    ("xmss", "XMSS"), ("lms", "LMS"),
)


def pqc_name(token: str | None) -> str | None:
    """Canonical PQC family for one spelling, or None when the token is not a PQC algorithm name."""
    if not token:
        return None
    low = token.strip().strip("\"'").lower()
    low = low.replace("oqs_kem_alg_", "").replace("oqs_sig_alg_", "")
    for prefix, canon in _PREFIXES:
        if low.startswith(prefix):
            rest = low[len(prefix):]
            # the next character must be a parameter set / separator, never more letters ("kyberos", "lmsfile")
            if not rest or not rest[0].isalpha() or rest.startswith(("sha", "shake", "aes")):
                return canon
    return None


class PqcTable(dict):
    """``algo_map`` for ``rule_engine.resolve_token`` — prefix-aware membership and lookup."""

    def __contains__(self, key: object) -> bool:  # type: ignore[override]
        return isinstance(key, str) and pqc_name(key) is not None

    def __getitem__(self, key: str) -> str:  # type: ignore[override]
        name = pqc_name(key)
        if name is None:
            raise KeyError(key)
        return name

    def get(self, key, default=None):  # type: ignore[override]
        return pqc_name(key) if isinstance(key, str) and pqc_name(key) else default


PQC_NAMES = PqcTable()
