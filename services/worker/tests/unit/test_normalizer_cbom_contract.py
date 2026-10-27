"""Cross-service contract: every algorithm name the scanners emit must normalise into a CBOM-grade record.

Companion to ``test_policy_normalizer_contract.py``. The scanner benchmark proves names are *found*; this proves
what happens to them afterwards — `quantum_vulnerable`, `pqc_replacement`, `nist_designation` and the normalised
`algorithm` are what the CBOM export, the agility report and the migration waves are built from.

First run (2026-09-26): DH, DSA, ECDH(E), Ed25519, X25519 and every ``RSA-SHAxxx`` signature combo reached the CBOM
as **not quantum vulnerable** (only the ten hand-written YAML rules set the flag; the shared registry's
``quantum_impact`` was never consulted), and re-normalising the service's own ``SHA2`` output gave ``UNKNOWN``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import sys
import tempfile
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "services" / "scanner" / "tests"))

from accuracy.corpus import CASES, canonical_families  # noqa: E402
from normalization.core.engine import NormalizationEngine  # noqa: E402

NORMALIZATION_RULES = ROOT / "services" / "normalization" / "rule_definitions"

# families that Shor's algorithm breaks — must be flagged and must carry a FIPS 203/204 replacement
QUANTUM_BROKEN = {"RSA", "DSA", "DH", "ECDH", "ECDSA", "ECIES", "ED25519", "X25519"}
PQC = {"MLKEM", "MLDSA", "SLHDSA"}
# classically broken primitives — never anything but DISALLOWED
BROKEN = {"MD2", "MD4", "MD5", "DES", "RC4", "RC2"}
# protocol / posture markers the scanners emit that are not algorithms; UNKNOWN is the right answer for them
MARKERS = {"TLS", "SSH", "X509", "JWT", "PGP", "DPAPI", "CSPRNG", "PRNG", "SHA1PRNG", "PLAINTEXT", "TRUST-ALL", "SSH-HOSTKEY-NONE",
           "TLS-CERT-NONE", "TLS-CIPHERS", "TLS-CLEARTEXT", "TLS-DISABLED", "TLS-POLICY", "TLS-UNVERIFIED", "WEBCRYPTO"}


def _scanner_names() -> dict[str, int]:
    """Every distinct crypto.algorithm the scanners emit over the accuracy corpus (784 files)."""

    logging.disable(logging.CRITICAL)
    from scanner.registry.language_scanners import scan_file

    names: Counter[str] = Counter()
    with tempfile.TemporaryDirectory(prefix="cryptoscan-contract-") as tmp:
        root = Path(tmp)
        for lang, fname, code, _expected, _category in CASES:
            path = root / lang / fname
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code, encoding="utf-8")
            try:
                for f in scan_file(path, root):
                    if f.crypto.algorithm:
                        names[f.crypto.algorithm] += 1
            except Exception as _handler_exc:  # a crash is the benchmark's business, not this test's
                logger.debug(
                    "expected_exception_boundary",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue
    logging.disable(logging.NOTSET)
    return dict(names)


NAMES = _scanner_names()
LABELLED = sorted(n for n in NAMES if canonical_families(n) and n not in MARKERS)


@pytest.fixture(scope="module")
def normalizer() -> NormalizationEngine:
    return NormalizationEngine(str(NORMALIZATION_RULES))


def test_corpus_yields_a_real_vocabulary():
    assert len(NAMES) >= 60 and len(LABELLED) >= 45, (len(NAMES), len(LABELLED))


@pytest.mark.parametrize("name", LABELLED)
def test_every_labelled_scanner_name_is_recognised(normalizer, name):
    result = normalizer.normalize(name)
    assert result.algorithm and result.algorithm != "UNKNOWN", (name, result.model_dump())


@pytest.mark.parametrize("name", [n for n in LABELLED if canonical_families(n) & QUANTUM_BROKEN])
def test_quantum_broken_families_are_flagged_with_a_replacement(normalizer, name):
    result = normalizer.normalize(name)
    assert result.quantum_vulnerable is True, (name, result.model_dump())
    assert result.pqc_replacement and result.pqc_replacement.startswith(("ML-KEM", "ML-DSA", "SLH-DSA")), (name, result.pqc_replacement)


@pytest.mark.parametrize("name", [n for n in LABELLED if canonical_families(n) & PQC])
def test_pqc_algorithms_are_not_flagged(normalizer, name):
    result = normalizer.normalize(name)
    assert result.quantum_vulnerable is False, (name, result.model_dump())


@pytest.mark.parametrize("name", [n for n in LABELLED if canonical_families(n) & BROKEN and not (canonical_families(n) - BROKEN - {"HMAC"})])
def test_broken_primitives_are_disallowed(normalizer, name):
    result = normalizer.normalize(name)
    assert result.nist_designation == "DISALLOWED", (name, result.nist_designation)


@pytest.mark.parametrize("name", LABELLED)
def test_normalisation_is_idempotent(normalizer, name):
    """stage_normalize overwrites EvidenceRecord.algorithm with the normalised name; a re-run must not lose it."""
    first = normalizer.normalize(name)
    if first.algorithm == "UNKNOWN":
        pytest.skip("covered by test_every_labelled_scanner_name_is_recognised")
    second = normalizer.normalize(first.algorithm)
    assert second.algorithm == first.algorithm, (name, first.algorithm, second.algorithm)
    assert second.quantum_vulnerable == first.quantum_vulnerable, (name, first.algorithm)


@pytest.mark.parametrize("raw,expected", [("TLSv1", "DISALLOWED"), ("SSLv2", "DISALLOWED"), ("SSLv3", "DISALLOWED"), ("TLS1.1", "DISALLOWED"), ("TLS1.3", "APPROVED")])
def test_protocol_versions_carry_their_designation(normalizer, raw, expected):
    assert normalizer.normalize(raw).nist_designation == expected
