"""Cryptographic detection engine (§4 Stage 4/5, §5, §7).

Capability versus usage is built into every finding: an imported
function is statically referenced — not proof of runtime use; a string
indicator is only an indicator (a debug string, an unused option, a help
message, a capability — or an operation); variant and key size stay
UNKNOWN unless the evidence names them. 'No cryptography found' is
reported as 'not detected within the analyzed scope' — never as absence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from binary_intelligence.crypto_fingerprints import (
    BY_SYMBOL, FINGERPRINT_DB_VERSION, LIBRARY_FINGERPRINTS,
    library_from_dependency,
)
from binary_intelligence.evidence import (
    CoverageReport, CryptoFinding, EvidenceClass, EvidenceItem, UsageStatus,
)
from binary_intelligence.identity import ArtifactIdentity

SCANNER_NAME = "cryptoscan-binary-intelligence"

#: string indicators are never proof (§4 Stage 3). The classification of
#: a string-only match is INDICATED at best, with the alternatives named.
_STRING_LIMITATION = (
    "a string indicator is not proof of use — it may be a debug string, "
    "an unused configuration option, a help message, a library "
    "capability or an operation; further evidence is required (§4)")

#: symbol tables seen; used for coverage
@dataclass
class StaticExtraction:
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    version_strings: List[str] = field(default_factory=list)
    sections: List[dict] = field(default_factory=list)
    stripped: bool = False
    compiler: Optional[str] = None


def _norm_symbol(raw: str) -> str:
    """Normalize a symbol to a catalogue key. C symbols may carry ABI
    decorations; JCA-style names carry dots — both are matched
    exactly after stripping only well-known decorations."""
    name = raw
    # Java internal class names: javax/crypto/Cipher -> javax.crypto.Cipher
    name = name.replace("/", ".")
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1].replace("/", ".")
    if name.startswith("_"):
        name = name[1:]
    # ELF versioned symbols: name@@GLIBC_2.2.5
    if "@@" in name:
        name = name.split("@@", 1)[0]
    elif "@" in name:
        name = name.split("@", 1)[0]
    return name


def detect_crypto(identity: ArtifactIdentity, extraction: StaticExtraction,
                  *, subject: Optional[str] = None) -> List[CryptoFinding]:
    """Run cryptographic detection over the static extraction. Every
    finding carries its evidence, class and usage status; nothing is
    concluded beyond what the evidence supports."""
    subject = subject or identity.original_filename
    findings: Dict[str, CryptoFinding] = {}
    counter = [0]

    def new_id() -> str:
        counter[0] += 1
        return f"bfind-{identity.artifact_id[4:]}-{counter[0]:03d}"

    def base(**kwargs) -> CryptoFinding:
        return CryptoFinding(
            finding_id=new_id(),
            artifact_id=identity.artifact_id,
            artifact_sha256=identity.sha256,
            subject=subject,
            scanner_version=SCANNER_NAME,
            signature_database_version=FINGERPRINT_DB_VERSION,
            **kwargs)

    all_symbols = extraction.imports + extraction.symbols
    # 1. function indicators (imports first: a reference from the
    #    dynamic symbol table is stronger than a bare symbol string)
    for source, bucket, location in (
            ("import", extraction.imports, "dynamic import table"),
            ("symbol", extraction.symbols, "symbol table")):
        for raw in bucket:
            name = _norm_symbol(raw)
            indicator = BY_SYMBOL.get(name)
            if indicator is None:
                # JCA-style getInstance("...") callers use dotted names
                indicator = BY_SYMBOL.get(raw)
            class_level = False
            if indicator is None:
                # a class-level reference (javax.crypto.Cipher) matches
                # the catalogue entry that begins with it
                matches = [ind for sym, ind in BY_SYMBOL.items()
                           if sym.startswith(name + ".")]
                if matches:
                    indicator = matches[0]
                    class_level = True
            if indicator is None:
                continue
            key = (indicator.algorithm_family, indicator.operation,
                   indicator.algorithm_variant)
            evidence = EvidenceItem(
                evidence_type="function_reference",
                location=f"{location}: {raw}",
                description=("Recognized cryptographic class reference"
                             if class_level else
                             "Recognized cryptographic function reference"),
                excerpt=raw[:120])
            class_limitation = [] if not class_level else [
                "a class-level reference establishes the interface is "
                "available to the code — which method is invoked, and "
                "with what parameters, is unproven"]
            existing = findings.get(key)
            if existing is not None:
                existing.evidence.append(evidence)
                if (existing.evidence_class == EvidenceClass.INDICATED
                        and len(existing.evidence) >= 2):
                    existing.evidence_class = EvidenceClass.STRONGLY_SUPPORTED
                    existing.usage_status = UsageStatus.STATICALLY_SUPPORTED
                continue
            findings[key] = base(
                finding_type="cryptographic_algorithm",
                algorithm=indicator.algorithm_family,
                variant=indicator.algorithm_variant,
                operation=indicator.operation,
                mode_or_padding=indicator.mode_or_padding,
                key_size_bits=indicator.key_size_bits,
                library=indicator.library,
                detection_method=f"function_{source}_analysis",
                evidence=[evidence],
                evidence_class=EvidenceClass.INDICATED,
                usage_status=(UsageStatus.STATICALLY_REFERENCED
                              if bucket == extraction.imports
                              else UsageStatus.CAPABILITY_ONLY),
                runtime_confirmed=False,
                quantum_vulnerable=indicator.quantum_vulnerable,
                pqc_family=indicator.pqc_family,
                limitations=[
                    "a function reference is an indicator of capability "
                    "or reference — it is not proof that the algorithm "
                    "runs at runtime (§5)",
                ] + class_limitation
                  + ([_STRING_LIMITATION]
                     if bucket == extraction.symbols else []))

    # 2. dependencies -> library findings (provides, not uses)
    for dep in extraction.dependencies:
        library = library_from_dependency(dep)
        if library is None:
            continue
        findings[("LIBRARY", dep, "")] = base(
            finding_type="cryptographic_library",
            library=library,
            detection_method="dependency_analysis",
            evidence=[EvidenceItem(
                evidence_type="dependency",
                location=f"dynamic dependencies: {dep}",
                description="Executable depends on this library",
                excerpt=dep[:120])],
            evidence_class=ObservationForDependency(extraction, dep),
            usage_status=UsageStatus.CAPABILITY_ONLY,
            limitations=[
                "a dependency PROVIDES cryptographic capability to the "
                "artifact; 'uses' requires call-path or runtime evidence "
                "(§5)",
            ])

    # 3. version strings from the library fingerprint catalogue —
    #    attach to an existing library finding or create one
    for fp in LIBRARY_FINGERPRINTS:
        if fp.kind != "version_string":
            continue
        for text in extraction.version_strings:
            if fp.indicator.lower() not in text.lower():
                continue
            existing = next(
                (f for f in findings.values()
                 if f.finding_type == "cryptographic_library"
                 and f.library == fp.library), None)
            item = EvidenceItem(
                evidence_type="string_indicator",
                location="string extraction",
                description=f"{fp.library} version string",
                excerpt=text[:120])
            if existing is not None:
                existing.evidence.append(item)
                if existing.evidence_class == EvidenceClass.OBSERVED:
                    existing.evidence_class = EvidenceClass.STRONGLY_SUPPORTED
            else:
                findings[("LIB", fp.library, "ver")] = base(
                    finding_type="cryptographic_library",
                    library=fp.library,
                    detection_method="version_string_analysis",
                    evidence=[item],
                    evidence_class=EvidenceClass.INDICATED,
                    usage_status=UsageStatus.CAPABILITY_ONLY,
                    limitations=[
                        "a version string identifies the library — it "
                        "provides capability; 'uses' requires call-path "
                        "or runtime evidence (§5)",
                    ])
            break

    # 4. string indicators for algorithm names — INDICATED at best, with
    #    the alternative explanations named (§4 Stage 3)
    _ALGO_STRINGS = {
        "AES-256-GCM": ("AES", "AES-256-GCM", "encryption", "GCM", 256),
        "AES-128-GCM": ("AES", "AES-128-GCM", "encryption", "GCM", 128),
        "AES-256-CBC": ("AES", "AES-256-CBC", "encryption", "CBC", 256),
        "ChaCha20-Poly1305": ("ChaCha20", "ChaCha20-Poly1305", "encryption",
                              "Poly1305", None),
        "TLSv1.2": ("TLS", "TLS 1.2", "protocol", "", None),
        "TLSv1.3": ("TLS", "TLS 1.3", "protocol", "", None),
        "ML-KEM": ("ML-KEM", "", "key_exchange", "", None),
        "ML-DSA": ("ML-DSA", "", "digital_signature", "", None),
        "SLH-DSA": ("SLH-DSA", "", "digital_signature", "", None),
        "RSA-2048": ("RSA", "RSA-2048", "digital_signature", "", 2048),
        "RSA-4096": ("RSA", "RSA-4096", "digital_signature", "", 4096),
        # JCA transformation strings (Java) — still only indicators
        "AES/GCM/NoPadding": ("AES", "AES-GCM", "encryption", "GCM", None),
        "AES/CBC/PKCS5Padding": ("AES", "AES-CBC", "encryption", "CBC", None),
        "AES/CTR/NoPadding": ("AES", "AES-CTR", "encryption", "CTR", None),
        "RSA/ECB/PKCS1Padding": ("RSA", "", "encryption", "PKCS1", None),
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding": (
            "RSA", "", "encryption", "OAEP-SHA-256", None),
        "SHA256withRSA": ("RSA", "", "digital_signature", "PKCS1-SHA-256",
                          None),
        "SHA512withECDSA": ("ECDSA", "", "digital_signature", "", None),
        "HmacSHA256": ("HMAC", "HMAC-SHA-256", "mac", "", None),
        "PBKDF2WithHmacSHA256": ("PBKDF2", "", "key_derivation", "", None),
    }
    for text in extraction.strings:
        for needle, (family, variant, operation, mode, bits) in _ALGO_STRINGS.items():
            if needle not in text:
                continue
            key = (family, "string", variant)
            pqc = family in ("ML-KEM", "ML-DSA", "SLH-DSA")
            evidence = EvidenceItem(
                evidence_type="string_indicator",
                location="string extraction",
                description="Algorithm name found in strings",
                excerpt=text[:120])
            existing = findings.get(key)
            if existing is not None:
                existing.evidence.append(evidence)
                continue
            findings[key] = base(
                finding_type="cryptographic_algorithm",
                algorithm=family, variant=variant, operation=operation,
                mode_or_padding=mode, key_size_bits=bits,
                detection_method="string_indicator",
                evidence=[evidence],
                evidence_class=EvidenceClass.INDICATED,
                usage_status=UsageStatus.UNRESOLVED,
                quantum_vulnerable=family in ("RSA",),
                pqc_family=pqc,
                limitations=[_STRING_LIMITATION,
                             "usage is unresolved — the string alone "
                             "cannot distinguish capability from use"])
            break   # one string finding per string, strongest needle first

    return list(findings.values())


def ObservationForDependency(extraction: StaticExtraction, dep: str) -> EvidenceClass:
    """A dependency observed in the dynamic table is OBSERVED evidence
    of the dependency itself (not of any algorithm's use)."""
    return EvidenceClass.OBSERVED


def not_detected_finding(identity: ArtifactIdentity, *,
                         subject: Optional[str] = None,
                         scope: str = "static analysis scope") -> CryptoFinding:
    """When nothing is detected: report 'not detected within the
    declared analysis scope' — NEVER 'cryptography absent' (§7)."""
    return CryptoFinding(
        finding_id=f"bfind-{identity.artifact_id[4:]}-000",
        artifact_id=identity.artifact_id,
        artifact_sha256=identity.sha256,
        subject=subject or identity.original_filename,
        finding_type="analysis_result",
        detection_method="static_analysis",
        evidence_class=EvidenceClass.NOT_DETECTED,
        usage_status=UsageStatus.UNRESOLVED,
        scanner_version=SCANNER_NAME,
        signature_database_version=FINGERPRINT_DB_VERSION,
        limitations=[
            f"no cryptography was detected within the declared {scope} — "
            "this is 'not detected', never 'absent': symbols may be "
            "stripped, code may be packed, and coverage is partial (§7)",
        ])


def build_coverage(identity: ArtifactIdentity,
                   extraction: StaticExtraction,
                   *, bytes_inspected: Optional[int] = None,
                   unresolved_dependencies: Optional[List[str]] = None,
                   extraction_failures: Optional[List[str]] = None,
                   packed_suspected: bool = False) -> CoverageReport:
    executable = sum(1 for s in extraction.sections if s.get("executable"))
    return CoverageReport(
        total_bytes=identity.file_size,
        bytes_inspected=(bytes_inspected if bytes_inspected is not None
                         else identity.file_size),
        sections_total=len(extraction.sections),
        sections_inspected=len(extraction.sections),
        executable_sections=executable,
        symbols_found=len(extraction.symbols) + len(extraction.imports),
        symbols_stripped=extraction.stripped,
        unresolved_dependencies=unresolved_dependencies or [],
        extraction_failures=extraction_failures or [],
        packed_or_encrypted_suspected=packed_suspected,
    )
