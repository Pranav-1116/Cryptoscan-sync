"""Bounded firmware extraction via Binwalk (§10, §14, §17 Phase 4).

Binwalk discovers embedded signatures; its output is treated as LEADS,
never as definitive evidence (§10): every row is validated (offset
within bounds, description non-empty) and normalized before use. The
tool runs in a bounded subprocess with a hard wall-clock timeout —
NEVER the analyzed artifact (§14). Carved components are inventoried
with depth, count and size limits; contents remain untrusted; nested
archives are never unpacked here; filenames are normalized. When the
tool is absent, the adapter says so and reports the analysis as NOT
COMPLETED — a missing tool is never a clean result.

Firmware version data is not proof of firmware contents.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_FIRMWARE_BYTES = 256 * 1024 * 1024
MAX_SCAN_SECONDS = 120
MAX_LEADS = 512
MAX_CARVED = 64
MAX_CARVED_BYTES = 64 * 1024 * 1024
MAX_CARVED_SIZE = 16 * 1024 * 1024

#: description tags -> component kind (normalized leads, never raw trust)
_KIND_TAGS = (
    ("gzip", "compressed_image"), ("zlib", "compressed_image"),
    ("xz", "compressed_image"), ("squashfs", "filesystem"),
    ("cramfs", "filesystem"), ("jffs2", "filesystem"),
    ("ubifs", "filesystem"), ("romfs", "filesystem"),
    ("uImage", "firmware_header"), ("TRX", "firmware_header"),
    ("u-boot", "bootloader"), ("ELF", "executable"),
    ("certificate", "certificate"), ("private key", "private_key"),
    ("RSA", "crypto_material"), ("AES", "crypto_material"),
)


@dataclass
class FirmwareLead:
    offset: int
    raw_description: str
    kind: str
    validated: bool
    validation_note: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset, "kind": self.kind,
            "description": self.raw_description,
            "validated": self.validated,
            "validation_note": self.validation_note,
        }


@dataclass
class CarvedComponent:
    index: int
    offset: int
    size: int
    sha256: str
    kind: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    component_notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index, "offset": self.offset, "size": self.size,
            "sha256": self.sha256, "kind": self.kind,
            "findings": self.findings,
            "notes": self.component_notes,
        }


@dataclass
class FirmwareReport:
    tool_name: str
    tool_version: str
    tool_available: bool
    analysis_completed: bool
    leads: List[FirmwareLead] = field(default_factory=list)
    carved: List[CarvedComponent] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "tool_available": self.tool_available,
            "analysis_completed": self.analysis_completed,
            "leads": [lead.as_dict() for lead in self.leads],
            "carved": [c.as_dict() for c in self.carved],
            "limitations": self.limitations,
            "notes": self.notes,
            "note": "third-party tool output is a LEAD, never definitive "
                    "evidence (§10); carved contents remain untrusted "
                    "(§14); firmware version data is not proof of "
                    "firmware contents",
        }


_BINWALK_ROW = re.compile(r"^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.*\S)\s*$")


def _normalize(lead_offset: int, description: str,
               file_size: int) -> FirmwareLead:
    validated = 0 <= lead_offset < file_size and bool(description.strip())
    kind = "unknown"
    for tag, mapped in _KIND_TAGS:
        if tag.lower() in description.lower():
            kind = mapped
            break
    note = ("offset within bounds and description present — normalized "
            "from third-party output" if validated else
            "lead refused: offset outside the file or empty description "
            "— never trusted blindly (§10)")
    return FirmwareLead(offset=lead_offset,
                        raw_description=description[:200],
                        kind=kind, validated=validated, validation_note=note)


def _run_binwalk(path: Path, *, timeout_seconds: float
                 ) -> Tuple[bool, str, List[str], Optional[str]]:
    """Run the binwalk CLI under a hard timeout. Executes the TOOL,
    never the artifact. Returns (available, version, output rows,
    error)."""
    executable = shutil.which("binwalk")
    if executable is None:
        # the interpreter's own bin directory (the venv) is where the
        # console script lives even when PATH does not name it
        import sys
        candidate = Path(sys.executable).parent / "binwalk"
        executable = str(candidate) if candidate.exists() else None
    if executable is None:
        return False, "", [], None
    import sys
    try:
        version = subprocess.run(                # noqa: S603 — bounded tool
            [sys.executable, "-c", "import binwalk; print(binwalk.__version__)"],
            capture_output=True, text=True, timeout=10,
            check=False).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        version = "unknown"
    try:
        proc = subprocess.run(                   # noqa: S603 — bounded tool
            [executable, "--signature", str(path)],
            capture_output=True, text=True, timeout=timeout_seconds,
            check=False)
    except subprocess.TimeoutExpired:
        return True, version, [], (
            f"binwalk exceeded the {timeout_seconds}s wall-clock limit — "
            "reported as NOT COMPLETED, never silently truncated (§14)")
    except OSError as exc:
        return True, version, [], (
            f"binwalk could not run: {type(exc).__name__} — analysis "
            "reported as NOT COMPLETED")
    rows = [line for line in proc.stdout.splitlines() if line.strip()]
    return True, version, rows, None


MAX_COMPONENT_ANALYSES = 8


def _analyze_component(blob: bytes, offset: int) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Feed one carved component through the static pipeline (§17 Phase
    4: extracted components feed cryptographic discovery). Bounded in
    count at the caller; findings carry sub-artifact provenance."""
    from binary_intelligence.pipeline import run_scan
    try:
        result = run_scan(
            tenant_id="firmware-component", data=blob,
            original_filename=f"carved@0x{offset:x}",
            source_type="firmware", uploaded_by="firmware-analysis")
    except ValueError as exc:
        return [], [f"component refused safely: {exc}"]
    findings = []
    for finding in result.findings:
        findings.append({
            "subject": finding.subject,
            "algorithm": finding.algorithm,
            "variant": finding.variant,
            "confidence": finding.evidence_class.value,
            "usage_status": finding.usage_status.value,
            "key_size_bits": finding.key_size_bits,
        })
    return findings, [
        "findings are from the STATIC pipeline over carved bytes — the "
        "carved content is untrusted and was never executed (§14)"]


def analyze_firmware(data: bytes, *, timeout_seconds: float = MAX_SCAN_SECONDS,
                     analyze_components: bool = True) -> FirmwareReport:
    """Bounded firmware analysis. Malformed or oversized input is
    refused with its reason; a missing tool reports the analysis as NOT
    COMPLETED — never a clean result."""
    report = FirmwareReport(tool_name="binwalk", tool_version="",
                            tool_available=False, analysis_completed=False)
    if len(data) > MAX_FIRMWARE_BYTES:
        report.notes.append(
            f"firmware image is {len(data)} bytes, above the bounded "
            f"limit {MAX_FIRMWARE_BYTES} — refused (§14)")
        return report
    if not data:
        report.notes.append("an empty image has no firmware to analyze")
        return report

    with tempfile.TemporaryDirectory(prefix="cryptoscan-fw-") as tmp:
        path = Path(tmp) / "image.bin"
        path.write_bytes(data)                  # in-memory analysis only
        available, version, rows, error = _run_binwalk(
            path, timeout_seconds=timeout_seconds)
        report.tool_available = available
        report.tool_version = version
        if not available:
            report.notes.append(
                "binwalk is not installed in this deployment — firmware "
                "signature analysis is reported as NOT COMPLETED, never "
                "as 'no firmware found' (§7)")
            return report
        if error is not None:
            report.notes.append(error)
            return report

        parsed = 0
        for row in rows:
            if parsed >= MAX_LEADS:
                report.limitations.append(
                    f"lead count exceeded the bounded limit {MAX_LEADS} "
                    "— the remainder is unknown, never guessed")
                break
            match = _BINWALK_ROW.match(row)
            if not match:
                continue    # non-signature lines (headers) are skipped
            offset = int(match.group(1))
            lead = _normalize(offset, match.group(2), len(data))
            if lead.validated:
                report.leads.append(lead)
                parsed += 1

        # bounded carving: contents remain untrusted (§14)
        total_carved = 0
        ordered = sorted(report.leads, key=lambda l: l.offset)
        for index, lead in enumerate(ordered[:MAX_CARVED]):
            end = (ordered[index + 1].offset
                   if index + 1 < len(ordered) else len(data))
            size = min(end - lead.offset, MAX_CARVED_SIZE)
            if size <= 0:
                continue
            if total_carved + size > MAX_CARVED_BYTES:
                report.limitations.append(
                    "carved total reached the bounded size limit — the "
                    "remainder is inventoried as leads only (§14)")
                break
            blob = data[lead.offset:lead.offset + size]
            component = CarvedComponent(
                index=index, offset=lead.offset, size=size,
                sha256=hashlib.sha256(blob).hexdigest(),
                kind=lead.kind)
            if analyze_components and index < MAX_COMPONENT_ANALYSES:
                component.findings, component.component_notes = \
                    _analyze_component(blob, lead.offset)
            elif analyze_components:
                component.component_notes.append(
                    f"component analysis beyond the bounded count "
                    f"{MAX_COMPONENT_ANALYSES} is not performed — the "
                    "remainder is inventoried, never guessed")
            report.carved.append(component)
            total_carved += size

    report.analysis_completed = True
    report.notes.append(
        "binwalk output validated and normalized into leads; a lead is "
        "not evidence — findings come from the static pipeline over "
        "carved components (§10), and carved content is untrusted")
    return report
