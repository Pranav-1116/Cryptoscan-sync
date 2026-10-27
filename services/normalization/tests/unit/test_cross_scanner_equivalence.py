"""Cross-scanner alias equivalence (§4.3, round 55).

Every scanner spells the same primitive differently — the network prober
extracts ``AES-128`` from a TLS suite, source scanning sees Java's
``AES/GCM/NoPadding``, the binary scanner reads OpenSSL constant names,
IaC says ``AES_256``. The normalization engine is the one place those
spellings must CONVERGE: same primitive in, same canonical fact out
(family, mode, key size, standard name). These tests pin that convergence
behaviorally — feeding real scanner-emitted spellings through the real
engine — and pin the documented key-size precedence contract:

1. a size written into the string itself wins (``AES-256-GCM``);
2. a structurally fixed size wins (DES is always 56);
3. otherwise the rule default is a GUESS for an undersized pattern
   (``AES/GCM/NoPadding`` -> 256) and a scanner-measured size wins.

Divergence is failure: if a new spelling of a known primitive stops
converging, this test names it instead of letting two spellings become
two different "algorithms" in the estate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from normalization.core.engine import NormalizationEngine

RULES_DIR = Path(__file__).resolve().parents[3] / "normalization" / "rule_definitions"


@pytest.fixture(scope="module")
def engine() -> NormalizationEngine:
    return NormalizationEngine(str(RULES_DIR))


def _identity(normalized) -> tuple:
    d = normalized.model_dump()
    return (d.get("algorithm"), d.get("mode"), d.get("key_size"), d.get("standard_name"))


#: same primitive, the spellings real scanners emit for it
EQUIVALENCE_SETS: dict[str, dict[str, dict]] = {
    "AES-128-GCM": {
        "network-suite-extracted": {"raw": "AES-128-GCM"},
        "iana-tls-name": {"raw": "aes128gcm"},
        "underscore-form": {"raw": "AES_128_GCM"},
        "hyphen-form": {"raw": "AES-128-GCM"},
    },
    "AES-256-GCM": {
        "java-transformation-sized": {"raw": "AES/GCM/NoPadding", "context": {"key_size": 256}},
        "hyphen-form": {"raw": "AES-256-GCM"},
        "underscore-form": {"raw": "AES_256_GCM"},
    },
    "RSA-2048": {
        "sized-name": {"raw": "RSA-2048"},
        "glued-form": {"raw": "RSA2048"},
        "family-plus_context": {"raw": "RSA", "context": {"key_size": 2048}},
    },
    "SHA-256": {
        "openssl-style": {"raw": "SHA256"},
        "dashed-form": {"raw": "SHA-256"},
        "glued-form": {"raw": "sha256"},
    },
    "P-256": {
        "secp-form": {"raw": "secp256r1"},
        "prime-form": {"raw": "prime256v1"},
        "nist-form": {"raw": "P-256"},
    },
}


@pytest.mark.parametrize("primitive", sorted(EQUIVALENCE_SETS))
def test_scanner_spellings_of_one_primitive_converge(engine: NormalizationEngine, primitive: str):
    spellings = EQUIVALENCE_SETS[primitive]
    identities = {}
    for label, spec in spellings.items():
        context = spec.get("context") or {}
        normalized = engine.normalize(spec["raw"], context=context)
        identities[label] = _identity(normalized)
    distinct = set(identities.values())
    assert len(distinct) == 1, (
        f"{primitive}: scanner spellings diverged into {len(distinct)} canonical facts: "
        f"{ {label: ident for label, ident in identities.items()} }"
    )
    # and the converged identity actually names the primitive
    algorithm, mode, key_size, standard_name = distinct.pop()
    assert standard_name and primitive.split("-")[0].upper() in str(algorithm).upper()


def test_key_size_precedence_contract(engine: NormalizationEngine):
    """The documented precedence: string > structurally-fixed > rule-default
    guess; a scanner-measured size beats the guess."""
    # 1. size in the string wins over a conflicting scanner context
    assert engine.normalize("AES-256-GCM", context={"key_size": 128}).key_size == 256
    # 2. an undersized pattern without context gets the documented default guess
    assert engine.normalize("AES/GCM/NoPadding").key_size == 256
    # 3. the guess yields to a scanner-measured size
    assert engine.normalize("AES/GCM/NoPadding", context={"key_size": 128}).key_size == 128


def test_unknown_spellings_are_not_silently_canonicalized(engine: NormalizationEngine):
    """A spelling the registry does not know must stay unknown — inventing
    a family for garbage is how false inventory rows are born."""
    normalized = engine.normalize("DEFINITELY_NOT_AN_ALGORITHM_42")
    assert normalized.algorithm in {"UNKNOWN", "DEFINITELY_NOT_AN_ALGORITHM_42"} or normalized.algorithm_family == "unknown"
