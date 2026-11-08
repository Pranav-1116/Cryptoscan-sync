"""Binary Intelligence Engine tests (docs/binary-intelligence/
01_PRODUCT_SPEC.md).

Acceptance rows proven here: content decides identity (§1); bounded
parsers fail safe (§14); a function reference is capability/reference,
never proof of runtime use (§5); unknown stays unknown (§5); a string is
only an indicator (§4); 'no cryptography found' is never 'absent' (§7);
confidence and coverage stay separate (§7); private-key contents are
never findings (§6); migration readiness is never invented (§9).
"""

from __future__ import annotations

import pytest

from binary_intelligence.certificates import inspect_certificates
from binary_intelligence.crypto_fingerprints import FINGERPRINT_DB_VERSION
from binary_intelligence.detection import (
    StaticExtraction, build_coverage, detect_crypto, not_detected_finding,
)
from binary_intelligence.elf import parse_elf
from binary_intelligence.evidence import EvidenceClass, UsageStatus
from binary_intelligence.formats import BinaryFormat, identify_format
from binary_intelligence.identity import artifact_identity
from binary_intelligence.pe import parse_pe
from binary_intelligence.pqc import assess_pqc

from tests.fixtures import (
    GROUND_TRUTH, elf_crypto_sample, elf_plain_sample, jar_like_sample,
    pe_crypto_sample,
)


def _identity(data: bytes, name: str = "payments-engine"):
    return artifact_identity(tenant_id="tenant_001", data=data,
                             original_filename=name, source_type="upload",
                             uploaded_by="auditor")


# --- §1: a file extension is only a hint ----------------------------

def test_format_comes_from_content_not_the_extension():
    elf_named_exe = elf_crypto_sample()
    fmt, reason = identify_format(elf_named_exe)
    assert fmt is BinaryFormat.ELF
    ident = _identity(elf_named_exe, name="payments-engine.exe")
    assert ident.detected_format is BinaryFormat.ELF, \
        "a .exe name does not make an ELF into a PE"
    pe_named_so = pe_crypto_sample()
    assert _identity(pe_named_so, name="libsomething.so").detected_format \
        is BinaryFormat.PE
    assert identify_format(jar_like_sample())[0] is BinaryFormat.ZIP_ARCHIVE
    unknown, reason = identify_format(b"not a binary at all")
    assert unknown is BinaryFormat.UNKNOWN
    assert "never guessed" in reason or "content" in reason


# --- §1: immutable SHA-256 identity --------------------------------

def test_artifact_identity_is_immutable_and_bounded():
    sample = elf_crypto_sample()
    first = _identity(sample)
    second = _identity(sample)
    assert first.sha256 == second.sha256
    assert first.artifact_id == second.artifact_id
    different = _identity(sample + b"\x00")
    assert different.sha256 != first.sha256, \
        "a changed artifact is a NEW artifact version, never an overwrite"
    with pytest.raises(ValueError, match="above the"):
        artifact_identity(tenant_id="t", data=b"x" * 100,
                          original_filename="big", source_type="upload",
                          uploaded_by="u", max_bytes=50)
    with pytest.raises(ValueError, match="empty"):
        artifact_identity(tenant_id="t", data=b"",
                          original_filename="none", source_type="upload",
                          uploaded_by="u")


# --- §4 Stage 2: structural parsing, ground truth -------------------

def test_elf_ground_truth_metadata():
    truth = GROUND_TRUTH["elf_crypto"]
    report = parse_elf(elf_crypto_sample())
    assert report.valid and report.architecture == truth["architecture"]
    assert report.bitness == 64 and report.endianness == "little"
    assert report.elf_type == "shared_object"
    assert report.dynamic_dependencies == truth["expected_dependencies"]
    for symbol in ("EVP_aes_256_gcm", "RSA_generate_key_ex", "EVP_sha256"):
        assert symbol in report.imported_symbols
    assert report.stripped is True
    assert "stripped" in " ".join(report.limitations) or report.stripped
    assert report.compiler and "GCC" in report.compiler


def test_pe_ground_truth_metadata():
    truth = GROUND_TRUTH["pe_crypto"]
    report = parse_pe(pe_crypto_sample())
    assert report.valid and report.pe32_plus
    assert report.architecture == truth["architecture"]
    assert report.imported_dlls == truth["expected_dependencies"]
    assert "EVP_aes_256_gcm" in report.imported_functions
    assert "BCryptSignHash" in report.imported_functions


def test_malformed_binaries_fail_safe_never_crash():
    for sample in (b"\x7fELF\x02\x01\x01" + b"\xff" * 20,
                   b"MZ" + b"\x00" * 0x3A + (0x10).to_bytes(4, "little") + b"JUNK",
                   b"\x7fELF", b"MZ"):
        if sample[:2] == b"MZ":
            report = parse_pe(sample)
        else:
            report = parse_elf(sample)
        assert report.valid is False
        assert report.reason, "a refusal always carries its reason"


# --- §5: capability versus usage -----------------------------------

def test_an_imported_function_is_referenced_not_proven_in_use():
    ident = _identity(elf_crypto_sample())
    extraction = StaticExtraction(
        imports=["EVP_aes_256_gcm"], dependencies=["libcrypto.so.3"])
    findings = detect_crypto(ident, extraction)
    aes = next(f for f in findings if f.algorithm == "AES")
    assert aes.usage_status == UsageStatus.STATICALLY_REFERENCED
    assert aes.runtime_confirmed is False
    assert "not proof" in " ".join(aes.limitations)
    lib = next(f for f in findings if f.finding_type == "cryptographic_library")
    assert lib.usage_status == UsageStatus.CAPABILITY_ONLY
    assert any("provides" in limitation.lower() or "PROVIDES" in limitation
               for limitation in lib.limitations)


def test_variant_and_key_size_stay_unknown_without_evidence():
    ident = _identity(elf_crypto_sample())
    findings = detect_crypto(ident, StaticExtraction(imports=["RSA_generate_key_ex"]))
    rsa = next(f for f in findings if f.algorithm == "RSA")
    assert rsa.variant == "", "variant is unknown, never guessed"
    assert rsa.key_size_bits is None, "key size is unknown, never guessed"
    assert rsa.operation == "key_generation"


def test_two_independent_indicators_raise_the_class_never_the_claim():
    ident = _identity(elf_crypto_sample())
    findings = detect_crypto(ident, StaticExtraction(
        imports=["EVP_aes_256_gcm", "EVP_aes_256_gcm"]))
    aes = next(f for f in findings if f.algorithm == "AES")
    assert aes.evidence_class == EvidenceClass.STRONGLY_SUPPORTED
    assert len(aes.evidence) == 2
    assert aes.usage_status == UsageStatus.STATICALLY_SUPPORTED
    assert aes.variant == "AES-256-GCM" and aes.key_size_bits == 256, \
        "the indicator itself names the variant and size — evidence-"
    "supported detail, not a guess"


def test_a_string_is_an_indicator_with_alternatives_named():
    ident = _identity(elf_plain_sample())
    findings = detect_crypto(ident, StaticExtraction(
        strings=["supports TLSv1.3 connections"]))
    tls = next(f for f in findings if f.algorithm == "TLS")
    assert tls.evidence_class == EvidenceClass.INDICATED
    assert tls.usage_status == UsageStatus.UNRESOLVED
    joined = " ".join(tls.limitations)
    assert "debug string" in joined and "not proof" in joined


# --- §7: no finding is never absence; coverage ≠ confidence --------

def test_no_cryptography_found_is_never_cryptography_absent():
    ident = _identity(elf_plain_sample())
    finding = not_detected_finding(ident)
    assert finding.evidence_class == EvidenceClass.NOT_DETECTED
    joined = " ".join(finding.limitations)
    assert "never 'absent'" in joined or "never" in joined
    assert "stripped" in joined and "coverage" in joined


def test_coverage_is_separate_from_confidence():
    ident = _identity(elf_crypto_sample())
    extraction = StaticExtraction(imports=["EVP_sha256"], stripped=True,
                                  sections=[{"executable": True}] * 3)
    coverage = build_coverage(ident, extraction,
                              unresolved_dependencies=["libvendorx.so"])
    as_dict = coverage.as_dict()
    assert as_dict["symbols_stripped"] is True
    assert as_dict["unresolved_dependencies"] == ["libvendorx.so"]
    assert "not finding confidence" in as_dict["note"]
    assert as_dict["coverage_fraction"] <= 1.0


# --- §6: private-key boundary --------------------------------------

def test_private_key_presence_is_recorded_but_never_contents():
    blob = (b"header" +
            b"-----BEGIN PRIVATE KEY-----\nSUPER-SECRET-KEY-MATERIAL\n"
            b"-----END PRIVATE KEY-----\n" +
            b"-----BEGIN CERTIFICATE-----\nnotbase64!\n-----END CERTIFICATE-----")
    certs, private_events = inspect_certificates(blob)
    assert len(private_events) == 1
    event = private_events[0].as_dict()
    assert "SUPER-SECRET" not in str(event), \
        "private-key contents are never a finding (§6)"
    assert "never exported" in event["note"]
    assert private_events[0].classification == "PRIVATE KEY"


# --- §9: PQC intelligence ------------------------------------------

def test_pqc_assessment_states_proven_and_unproven():
    ident = _identity(elf_crypto_sample())
    findings = detect_crypto(ident, StaticExtraction(
        imports=["RSA_generate_key_ex", "EVP_PKEY_derive"],
        dependencies=["libcrypto.so.3"], strings=["ML-KEM"]))
    assessment = assess_pqc(findings, libraries=["OpenSSL"],
                            stripped=True, proprietary_suspected=True)
    body = assessment.as_dict()
    assert body["quantum_vulnerable_algorithm_indicators"] == "Detected"
    assert body["pqc_implementation_indicators"] == "Detected", \
        "the ML-KEM string is an indicator — but presence is not usage"
    assert body["migration_readiness"] == "Not established"
    assert body["source_availability"] == "Unavailable"
    joined = " ".join(body["migration_blockers"])
    assert "stripped" in joined and "proprietary" in joined
    assert "presence is not usage" in body["note"]


def test_pqc_absence_in_scope_is_not_readiness():
    ident = _identity(elf_plain_sample())
    assessment = assess_pqc([], libraries=[])
    body = assessment.as_dict()
    assert body["quantum_vulnerable_algorithm_indicators"] == "Not detected"
    assert body["migration_readiness"] == "Not established"
    assert any("unproven" in blocker for blocker in body["migration_blockers"])


# --- §7: the fingerprint version rides on every finding ------------

def test_every_finding_carries_scanner_and_signature_versions():
    ident = _identity(elf_crypto_sample())
    findings = detect_crypto(ident, StaticExtraction(imports=["EVP_sha256"]))
    for finding in findings:
        assert finding.signature_database_version == FINGERPRINT_DB_VERSION
        assert finding.scanner_version.startswith("cryptoscan-binary")
        assert finding.artifact_sha256 == ident.sha256
