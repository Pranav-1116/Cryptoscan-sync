"""Scan orchestration (§3, §12): one job through the stages —
identity -> format -> structure -> extraction -> detection ->
evidence -> coverage -> PQC. Static analysis only: the artifact is
NEVER executed (§14). Three profiles; deep is never the default.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from binary_intelligence.bom import build_bom
from binary_intelligence.certificates import inspect_certificates
from binary_intelligence.crypto_fingerprints import FINGERPRINT_DB_VERSION
from binary_intelligence.detection import (
    SCANNER_NAME, StaticExtraction, build_coverage, detect_crypto,
    not_detected_finding,
)
from binary_intelligence.archive import parse_archive
from binary_intelligence.dotnet import parse_dotnet
from binary_intelligence.elf import parse_elf
from binary_intelligence.macho import parse_macho
from binary_intelligence.wasm import parse_wasm
from binary_intelligence.java import parse_class, parse_jar
from binary_intelligence.evidence import CoverageReport, CryptoFinding
from binary_intelligence.formats import BinaryFormat
from binary_intelligence.identity import ArtifactIdentity, artifact_identity
from binary_intelligence.pe import parse_pe
from binary_intelligence.pqc import assess_pqc

PROFILES = ("quick", "standard", "deep")


@dataclass
class ScanResult:
    scan_id: str
    identity: ArtifactIdentity
    profile: str
    status: str
    structural_report: Dict[str, Any]
    extraction: StaticExtraction
    findings: List[CryptoFinding]
    certificates: List[Dict[str, Any]]
    private_key_events: List[Dict[str, Any]]
    coverage: CoverageReport
    pqc_assessment: Dict[str, Any]
    bom: Optional[Any] = None
    timings: Dict[str, float] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "artifact": self.identity.as_dict(),
            "scan_profile": self.profile,
            "status": self.status,
            "scanner_version": SCANNER_NAME,
            "signature_database_version": FINGERPRINT_DB_VERSION,
            "structural_report": self.structural_report,
            "findings": [f.as_dict() for f in self.findings],
            "certificates": self.certificates,
            "private_key_events": self.private_key_events,
            "coverage": self.coverage.as_dict(),
            "pqc_assessment": self.pqc_assessment,
            "bom": self.bom.as_dict() if self.bom is not None else None,
            "timings": self.timings,
            "notes": self.notes,
        }


def _bounded_strings(data: bytes, *, min_len: int = 6,
                     max_count: int = 4000) -> List[str]:
    """Bounded string extraction (§14): no unbounded scans, no
    megabyte 'strings' dumps."""
    out: List[str] = []
    current = bytearray()
    for byte in data[:8 * 1024 * 1024]:          # bounded read window
        if 32 <= byte < 127:
            current.append(byte)
            if len(current) > 256:              # bounded string length
                del current[:]
        else:
            if len(current) >= min_len:
                out.append(current.decode("ascii"))
                if len(out) >= max_count:
                    return out
            del current[:]
    return out


def run_scan(*, tenant_id: str, data: bytes, original_filename: str,
             source_type: str, uploaded_by: str,
             source_location: Optional[str] = None,
             profile: str = "standard") -> ScanResult:
    """Execute the static analysis pipeline. The artifact is never
    executed; a profile above 'standard' runs the same stages and marks
    deep analysis as NOT completed — deep reverse-engineering tools are
    an external adapter (§10), never silently pretended."""
    if profile not in PROFILES:
        raise ValueError(
            f"unknown scan profile {profile!r} — profiles are "
            f"{PROFILES}; a deep scan is never the default (§12)")
    import time as _time
    timings: Dict[str, float] = {}
    _stage_start = _time.perf_counter()

    def _mark(stage: str) -> None:
        nonlocal _stage_start
        now = _time.perf_counter()
        timings[stage] = round(now - _stage_start, 6)
        _stage_start = now

    identity = artifact_identity(
        tenant_id=tenant_id, data=data,
        original_filename=original_filename, source_type=source_type,
        uploaded_by=uploaded_by, source_location=source_location)
    _mark("file_intake_and_hash_seconds")
    scan_id = f"bscan-{uuid.uuid4().hex[:12]}"
    notes: List[str] = [
        "static analysis only — the artifact was never executed (§14)",
    ]

    # Stage 2: structural parsing by format
    structural: Dict[str, Any] = {"format": identity.detected_format.value,
                                  "format_reason": identity.format_reason}
    extraction = StaticExtraction()
    failures: List[str] = []
    if identity.detected_format is BinaryFormat.ELF:
        report = parse_elf(data)
        structural["elf"] = report.as_dict()
        if report.valid:
            extraction.imports = list(report.imported_symbols)
            extraction.exports = list(report.exported_symbols)
            extraction.dependencies = list(report.dynamic_dependencies)
            extraction.sections = list(report.sections)
            extraction.stripped = report.stripped
            extraction.compiler = report.compiler
            if report.compiler:
                extraction.version_strings.append(report.compiler)
        else:
            failures.append(f"ELF parsing refused: {report.reason}")
    elif identity.detected_format is BinaryFormat.PE:
        report = parse_pe(data)
        structural["pe"] = report.as_dict()
        if report.valid:
            extraction.imports = list(report.imported_functions)
            extraction.exports = list(report.exported_functions)
            extraction.dependencies = list(report.imported_dlls)
            extraction.sections = list(report.sections)
            extraction.stripped = not bool(report.exported_functions)
        else:
            failures.append(f"PE parsing refused: {report.reason}")
        # a .NET assembly is a PE with a CLR header (Phase 4)
        dotnet = parse_dotnet(data)
        if dotnet.valid:
            structural["dotnet"] = dotnet.as_dict()
            extraction.symbols.extend(dotnet.type_names)
            if dotnet.runtime_version:
                extraction.version_strings.append(dotnet.runtime_version)
            if dotnet.assembly_name:
                extraction.dependencies.append(dotnet.assembly_name)
    elif identity.detected_format in (BinaryFormat.MACHO,
                                     BinaryFormat.MACHO_FAT):
        report = parse_macho(data)
        structural["macho"] = report.as_dict()
        if report.valid:
            extraction.symbols = list(report.symbols)
            extraction.dependencies = list(report.libraries)
            extraction.sections = [{"executable": True,
                                    "name": seg.get("name", "?")}
                                   for seg in report.segments]
            extraction.version_strings.append(
                f"Mach-O {report.architecture} {report.filetype}")
            if any("libcrypto" in lib or "libSystem" in lib
                   for lib in report.libraries):
                pass    # dependency detection handles the mapping
        else:
            failures.append(f"Mach-O parsing refused: {report.reason}")
    elif identity.detected_format is BinaryFormat.STATIC_ARCHIVE:
        report = parse_archive(data)
        structural["archive"] = report.as_dict()
        if report.valid:
            extraction.imports = list(report.imported_symbols)
            extraction.dependencies = list(report.dependencies)
        else:
            failures.append(f"archive refused: {report.reason}")
    elif identity.detected_format is BinaryFormat.WASM:
        report = parse_wasm(data)
        structural["wasm"] = report.as_dict()
        if report.valid:
            extraction.symbols = list(report.imports)
            extraction.exports = list(report.exports)
        else:
            failures.append(f"WASM refused: {report.reason}")
    elif identity.detected_format in (BinaryFormat.JAVA_CLASS,
                                     BinaryFormat.ZIP_ARCHIVE):
        if identity.detected_format is BinaryFormat.JAVA_CLASS:
            class_report = parse_class(data)
            structural["java_class"] = class_report.as_dict()
            extraction.strings = list(class_report.string_constants)
            extraction.symbols = (list(class_report.method_refs)
                                  + list(class_report.field_refs))
            extraction.version_strings.extend(class_report.class_refs[:200])
            if class_report.parse_status not in ("parsed", "partial"):
                failures.append(
                    f"class parsing refused: {class_report.parse_status}")
        else:
            jar_report = parse_jar(data)
            structural["jar"] = jar_report.as_dict()
            for class_report in jar_report.classes:
                extraction.strings.extend(class_report.string_constants)
                extraction.symbols.extend(class_report.method_refs)
                extraction.version_strings.extend(
                    class_report.class_refs[:50])
            for key, value in jar_report.manifest.items():
                if key in ("Implementation-Version", "Specification-Version",
                           "Main-Class", "Implementation-Title"):
                    extraction.version_strings.append(f"{key}: {value}")
            extraction.dependencies.extend(jar_report.embedded_archives)
            if not jar_report.valid:
                failures.append(f"jar refused: {jar_report.reason}")
                notes.append(jar_report.reason)
    else:
        notes.append(
            f"format {identity.detected_format.value} has no structural "
            "parser in this version — string and certificate analysis "
            "only; coverage names the gap, never hides it")
        failures.append(
            f"no structural parser for {identity.detected_format.value}")

    _mark("format_identification_and_structure_seconds")
    # Stage 3: bounded strings
    extraction.strings = _bounded_strings(data)
    for text in extraction.strings:
        if any(tag in text for tag in ("OpenSSL ", "BoringSSL", "LibreSSL",
                                      "mbedTLS", "wolfSSL", "libsodium",
                                      "Bouncy-Castle", "go.buildid")):
            extraction.version_strings.append(text)

    _mark("symbol_string_extraction_seconds")
    # Stage 5: detection
    findings = detect_crypto(identity, extraction)
    _mark("cryptographic_detection_seconds")
    if not findings:
        findings = [not_detected_finding(identity)]

    # Stage 6: certificates and private-key boundary
    certs, private_events = inspect_certificates(data)
    _mark("certificate_analysis_seconds")

    # coverage (§7) — separate from confidence
    coverage = build_coverage(
        identity, extraction,
        bytes_inspected=len(data) if identity.detected_format in
        (BinaryFormat.ELF, BinaryFormat.PE) else min(len(data), 8 * 1024 * 1024),
        extraction_failures=failures,
        packed_suspected=identity.detected_format not in
        (BinaryFormat.ELF, BinaryFormat.PE, BinaryFormat.JAVA_CLASS))

    libraries = sorted({f.library for f in findings
                        if f.finding_type == "cryptographic_library"
                        and f.library})
    pqc = assess_pqc(
        findings, libraries=libraries, stripped=extraction.stripped,
        proprietary_suspected=source_type in ("vendor", "firmware"),
        static_linking_suspected=bool(
            extraction.stripped and not extraction.dependencies))

    # SBOM/CBOM integration (§8) — feeds the existing BOM ecosystem
    bom = build_bom(
        artifact_id=identity.artifact_id,
        artifact_sha256=identity.sha256,
        subject=identity.original_filename,
        findings=findings,
        dependencies=[d for d in extraction.dependencies
                      if not d.endswith(".jar")],
        embedded_archives=[d for d in extraction.dependencies
                           if d.endswith(".jar")])

    if profile == "deep":
        notes.append(
            "deep analysis requested — advanced function analysis and "
            "reverse-engineering adapters are external capabilities "
            "(§10/§17 Phase 5); this run completed standard static "
            "analysis and reports deep analysis as NOT completed")

    _mark("coverage_pqc_bom_seconds")
    timings["total_seconds"] = round(sum(timings.values()), 6)
    return ScanResult(
        scan_id=scan_id, identity=identity, profile=profile,
        status="completed",
        structural_report=structural, extraction=extraction,
        findings=findings,
        certificates=[c.as_dict() for c in certs],
        private_key_events=[p.as_dict() for p in private_events],
        coverage=coverage,
        pqc_assessment=pqc.as_dict(),
        bom=bom,
        timings=timings,
        notes=notes)
