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


# --- Java/JAR (MVP scope) and §14 archive limits --------------------

def _minimal_class(*, string_const: str = "AES/GCM/NoPadding",
                   class_ref: str = "javax/crypto/Cipher") -> bytes:
    import struct as _s
    utf8_a = string_const.encode()
    utf8_b = class_ref.encode()
    pool = (_s.pack(">BH", 1, len(utf8_a)) + utf8_a +
            _s.pack(">BH", 1, len(utf8_b)) + utf8_b +
            _s.pack(">BH", 7, 1) +
            _s.pack(">BH", 7, 2) +
            _s.pack(">BHH", 12, 1, 1) +
            _s.pack(">BHH", 10, 4, 5))
    out = (b"\xca\xfe\xba\xbe" + _s.pack(">HH", 0, 52) +
           _s.pack(">H", 7) + pool +
           _s.pack(">HHH", 0x21, 3, 3) +
           _s.pack(">HHHH", 0, 0, 0, 0))
    return out


def _jar(entries: dict) -> bytes:
    import io as _io
    import zipfile as _zf
    buffer = _io.BytesIO()
    with _zf.ZipFile(buffer, "w") as archive:
        for name, blob in entries.items():
            archive.writestr(name, blob)
    return buffer.getvalue()


def test_java_class_parses_constant_pool_and_jca_transformation_strings():
    from binary_intelligence.java import parse_class, parse_jar
    report = parse_class(_minimal_class())
    assert report.parse_status == "parsed"
    assert "AES/GCM/NoPadding" in report.string_constants
    assert any("javax/crypto/Cipher" in ref for ref in report.method_refs)

    jar = parse_jar(_jar({
        "META-INF/MANIFEST.MF":
            "Manifest-Version: 1.0\nImplementation-Version: 2.1\n",
        "com/bank/Payments.class": _minimal_class(),
        "lib/inner.jar": b"PK\x03\x04inner",
    }))
    assert jar.valid and len(jar.classes) == 1
    assert jar.manifest.get("Implementation-Version") == "2.1"
    assert jar.embedded_archives == ["lib/inner.jar"], \
        "a nested archive is inventoried, not unpacked (§14)"
    assert any("bounded" in limitation or "depth" in limitation
               for limitation in jar.limitations)


def test_jar_extraction_is_bounded_against_archive_bombs():
    from binary_intelligence.java import parse_jar
    bomb = parse_jar(_jar({"a.class": b"x" * 10, "b.bin": b"y"}))
    # entry-count limit
    many = _jar({f"f{i}.txt": b"x" for i in range(5000)})
    refused = parse_jar(many)
    assert refused.valid is False and "bounded limit" in refused.reason
    # traversal names are refused, never extracted
    traversal = parse_jar(_jar({"../evil.class": _minimal_class(),
                                "ok/META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}))
    assert any("traversal" in limitation
               for limitation in traversal.limitations)
    assert all(".." not in c.class_name for c in traversal.classes)
    assert bomb.valid is True    # a small jar is fine


def test_jca_transformation_strings_are_indicators_never_proof():
    ident = _identity(elf_plain_sample(), name="app.jar")
    from binary_intelligence.detection import detect_crypto, StaticExtraction
    findings = detect_crypto(ident, StaticExtraction(
        strings=["javax.crypto.Cipher transformation AES/GCM/NoPadding"]))
    aes = next(f for f in findings if f.algorithm == "AES")
    assert aes.variant == "AES-GCM"
    assert aes.evidence_class == EvidenceClass.INDICATED
    assert aes.usage_status == UsageStatus.UNRESOLVED, \
        "a transformation string is an indicator, never proof of use"
    assert aes.key_size_bits is None, "GCM string names no key size here"


# --- §5/§8: provides vs uses in the BOM -----------------------------

def test_bom_provides_and_uses_follow_evidence_not_co_occurrence():
    from binary_intelligence.bom import build_bom
    ident = _identity(elf_crypto_sample())
    strong = detect_crypto(ident, StaticExtraction(
        imports=["EVP_aes_256_gcm", "EVP_aes_256_gcm"],
        dependencies=["libcrypto.so.3"]))
    bom = build_bom(
        artifact_id=ident.artifact_id, artifact_sha256=ident.sha256,
        subject="payments-engine", findings=strong,
        dependencies=["libcrypto.so.3"])
    edges = {(r.relationship_type, r.source, r.target)
             for r in bom.relationships}
    assert ("dependsOn", "payments-engine", "libcrypto.so.3") in edges
    assert ("provides", "OpenSSL", "AES-256-GCM") in edges
    uses = [r for r in bom.relationships if r.relationship_type == "uses"]
    assert len(uses) == 1 and uses[0].target == "AES-256-GCM"
    assert any("runtime use is still unconfirmed" in limitation
               for limitation in uses[0].limitations)

    weak = detect_crypto(ident, StaticExtraction(imports=["RSA_new"]))
    weak_bom = build_bom(
        artifact_id=ident.artifact_id, artifact_sha256=ident.sha256,
        subject="payments-engine", findings=weak, dependencies=[])
    assert not any(r.relationship_type == "uses"
                   for r in weak_bom.relationships), \
        "co-occurrence or a single reference never creates a `uses` edge (§5)"
    assert any(r.relationship_type == "indicates"
               for r in weak_bom.relationships)
    for asset in bom.cbom_assets:
        assert "evidence_class" in asset and "usage_status" in asset
    assert "never from names or co-occurrence" in " ".join(bom.limitations)


# --- §16: version comparison ----------------------------------------

def test_comparison_reports_indicator_drift_never_behavior_drift():
    from binary_intelligence.comparison import compare_findings
    ident = _identity(elf_crypto_sample())
    old = detect_crypto(ident, StaticExtraction(imports=["EVP_aes_256_gcm"]))
    new = detect_crypto(ident, StaticExtraction(imports=["EVP_sha256"]))
    report = compare_findings(
        base_artifact_id="bin-old", base_sha256="a" * 64,
        base_findings=[f.as_dict() for f in old],
        against_artifact_id="bin-new", against_sha256="b" * 64,
        against_findings=[f.as_dict() for f in new])
    body = report.as_dict()
    assert body["summary"]["added"] >= 1 and body["summary"]["removed"] >= 1
    removed = next(d for d in body["deltas"] if d["change"] == "removed")
    assert "stripped" in removed["caveat"] or "not proven" in removed["caveat"], \
        "a missing indicator never proves removal"
    added = next(d for d in body["deltas"] if d["change"] == "added")
    assert "not proof of new runtime behavior" in added["caveat"]
    assert "never drift of runtime behavior" in body["note"]
