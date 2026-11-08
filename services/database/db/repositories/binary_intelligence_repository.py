"""Binary Intelligence repository (docs/binary-intelligence/
01_PRODUCT_SPEC.md §11/§12).

Wires the full static pipeline: identity -> format -> structure ->
extraction -> detection -> evidence -> coverage -> PQC -> persistence.
Every artifact is immutable; every scan run links to the artifact
digest; findings and evidence are stored separately.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.binary_intelligence import (
    BinaryAnalysisCoverage, BinaryArtifact, BinaryCryptoFinding,
    BinaryEvidence, BinaryScanRun,
)
from db.repositories.performance_repository import _aware


class BinaryIntelligenceRepository:

    def __init__(self, db: Session) -> None:
        self.db = db

    # --- artifacts ---------------------------------------------------

    def register_artifact(self, identity) -> Dict[str, Any]:
        """Register the artifact identity. Idempotent per digest: the
        same digest is the same artifact; a different digest is a
        different artifact row — existing rows are never overwritten."""
        row = self.db.scalars(
            select(BinaryArtifact).where(
                BinaryArtifact.tenant_id == identity.tenant_id,
                BinaryArtifact.sha256 == identity.sha256)).first()
        if row is not None:
            return {"artifact_id": row.artifact_id, "outcome": "existing"}
        row = BinaryArtifact(
            tenant_id=identity.tenant_id,
            artifact_id=identity.artifact_id,
            sha256=identity.sha256,
            file_size=identity.file_size,
            detected_format=identity.detected_format.value,
            format_reason=identity.format_reason,
            original_filename=identity.original_filename,
            source_type=identity.source_type,
            source_location=identity.source_location,
            uploaded_by=identity.uploaded_by)
        self.db.add(row)
        self.db.commit()
        return {"artifact_id": row.artifact_id, "outcome": "registered"}

    def get_artifact(self, tenant_id: str, artifact_id: str
                     ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(BinaryArtifact).where(
                BinaryArtifact.tenant_id == tenant_id,
                BinaryArtifact.artifact_id == artifact_id)).first()
        if row is None:
            return None
        return {
            "artifact_id": row.artifact_id, "sha256": row.sha256,
            "file_size": row.file_size,
            "detected_format": row.detected_format,
            "format_reason": row.format_reason,
            "original_filename": row.original_filename,
            "source_type": row.source_type,
            "source_location": row.source_location,
            "uploaded_by": row.uploaded_by,
            "received_at": _aware(row.created_at),
        }

    def find_by_sha256(self, tenant_id: str, sha256: str
                       ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(BinaryArtifact).where(
                BinaryArtifact.tenant_id == tenant_id,
                BinaryArtifact.sha256 == sha256)).first()
        return None if row is None else self.get_artifact(
            tenant_id, row.artifact_id)

    # --- scan runs ----------------------------------------------------

    def record_scan(self, *, tenant_id: str, scan_id: str, artifact_id: str,
                    artifact_sha256: str, scan_profile: str,
                    scanner_version: str, signature_database_version: str,
                    status: str, structural_report: Dict[str, Any],
                    pqc_assessment: Dict[str, Any],
                    scanned_at: datetime) -> Dict[str, Any]:
        row = BinaryScanRun(
            tenant_id=tenant_id, scan_id=scan_id, artifact_id=artifact_id,
            artifact_sha256=artifact_sha256, scan_profile=scan_profile,
            scanner_version=scanner_version,
            signature_database_version=signature_database_version,
            status=status, structural_report=structural_report,
            pqc_assessment=pqc_assessment, scanned_at=scanned_at)
        self.db.add(row)
        self.db.commit()
        return {"scan_id": scan_id, "status": status}

    def get_scan(self, tenant_id: str, scan_id: str
                 ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(BinaryScanRun).where(
                BinaryScanRun.tenant_id == tenant_id,
                BinaryScanRun.scan_id == scan_id)).first()
        if row is None:
            return None
        return {
            "scan_id": row.scan_id, "artifact_id": row.artifact_id,
            "artifact_sha256": row.artifact_sha256,
            "scan_profile": row.scan_profile,
            "scanner_version": row.scanner_version,
            "signature_database_version": row.signature_database_version,
            "status": row.status,
            "structural_report": row.structural_report,
            "pqc_assessment": row.pqc_assessment,
            "scanned_at": _aware(row.scanned_at),
        }

    def list_scans_for_artifact(self, tenant_id: str, artifact_id: str
                                ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(BinaryScanRun).where(
                BinaryScanRun.tenant_id == tenant_id,
                BinaryScanRun.artifact_id == artifact_id).order_by(
                BinaryScanRun.scanned_at))
        return [self.get_scan(tenant_id, row.scan_id) for row in rows]

    # --- findings + evidence -------------------------------------------

    def record_findings(self, *, tenant_id: str, run_id: str,
                        findings: List[Any]) -> Dict[str, Any]:
        stored = 0
        for finding in findings:
            self.db.add(BinaryCryptoFinding(
                tenant_id=tenant_id, run_id=run_id,
                finding_id=finding.finding_id,
                subject=finding.subject,
                finding_type=finding.finding_type,
                algorithm=finding.algorithm, variant=finding.variant,
                operation=finding.operation,
                mode_or_padding=finding.mode_or_padding,
                key_size_bits=finding.key_size_bits,
                library=finding.library,
                detection_method=finding.detection_method,
                evidence_class=finding.evidence_class.value,
                usage_status=finding.usage_status.value,
                runtime_confirmed=finding.runtime_confirmed,
                quantum_vulnerable=finding.quantum_vulnerable,
                pqc_family=finding.pqc_family,
                limitations=list(finding.limitations),
                observed_at=finding.observed_at))
            for item in finding.evidence:
                self.db.add(BinaryEvidence(
                    tenant_id=tenant_id, finding_id=finding.finding_id,
                    evidence_type=item.evidence_type,
                    location=item.location,
                    description=item.description,
                    excerpt=item.excerpt))
            stored += 1
        self.db.commit()
        return {"findings_stored": stored}

    def list_findings(self, tenant_id: str, *, run_id: Optional[str] = None,
                      artifact_id: Optional[str] = None
                      ) -> List[Dict[str, Any]]:
        stmt = select(BinaryCryptoFinding).where(
            BinaryCryptoFinding.tenant_id == tenant_id)
        if run_id is not None:
            stmt = stmt.where(BinaryCryptoFinding.run_id == run_id)
        if artifact_id is not None:
            scan_ids = [row["scan_id"] for row in
                        self.list_scans_for_artifact(tenant_id, artifact_id)]
            stmt = stmt.where(BinaryCryptoFinding.run_id.in_(scan_ids))
        rows = self.db.scalars(
            stmt.order_by(BinaryCryptoFinding.observed_at))
        out = []
        for row in rows:
            item = {
                "finding_id": row.finding_id, "run_id": row.run_id,
                "subject": row.subject, "finding_type": row.finding_type,
                "algorithm": row.algorithm, "variant": row.variant,
                "operation": row.operation,
                "mode_or_padding": row.mode_or_padding,
                "key_size_bits": row.key_size_bits,  # unknown stays None
                "library": row.library,
                "detection_method": row.detection_method,
                "evidence_class": row.evidence_class,
                "usage_status": row.usage_status,
                "runtime_confirmed": row.runtime_confirmed,
                "quantum_vulnerable": row.quantum_vulnerable,
                "pqc_family": row.pqc_family,
                "limitations": row.limitations or [],
                "observed_at": _aware(row.observed_at),
            }
            out.append(item)
        return out

    def list_evidence(self, tenant_id: str, *, finding_id: str
                      ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(BinaryEvidence).where(
                BinaryEvidence.tenant_id == tenant_id,
                BinaryEvidence.finding_id == finding_id))
        return [{
            "finding_id": row.finding_id,
            "evidence_type": row.evidence_type,
            "location": row.location,
            "description": row.description,
            "excerpt": row.excerpt,
        } for row in rows]

    def record_coverage(self, *, tenant_id: str, run_id: str,
                        coverage: Any) -> Dict[str, Any]:
        self.db.add(BinaryAnalysisCoverage(
            tenant_id=tenant_id, run_id=run_id,
            total_bytes=coverage.total_bytes,
            bytes_inspected=coverage.bytes_inspected,
            sections_total=coverage.sections_total,
            sections_inspected=coverage.sections_inspected,
            executable_sections=coverage.executable_sections,
            symbols_found=coverage.symbols_found,
            symbols_stripped=coverage.symbols_stripped,
            unresolved_dependencies=list(coverage.unresolved_dependencies),
            unsupported_regions=list(coverage.unsupported_regions),
            extraction_failures=list(coverage.extraction_failures),
            deep_analysis_completed=coverage.deep_analysis_completed,
            packed_or_encrypted_suspected=coverage.packed_or_encrypted_suspected,
            analysis_timeouts=coverage.analysis_timeouts))
        self.db.commit()
        return {"run_id": run_id}

    def get_coverage(self, tenant_id: str, run_id: str
                     ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(BinaryAnalysisCoverage).where(
                BinaryAnalysisCoverage.tenant_id == tenant_id,
                BinaryAnalysisCoverage.run_id == run_id)).first()
        if row is None:
            return None
        return {
            "run_id": row.run_id, "total_bytes": row.total_bytes,
            "bytes_inspected": row.bytes_inspected,
            "sections_total": row.sections_total,
            "sections_inspected": row.sections_inspected,
            "executable_sections": row.executable_sections,
            "symbols_found": row.symbols_found,
            "symbols_stripped": row.symbols_stripped,
            "unresolved_dependencies": row.unresolved_dependencies or [],
            "unsupported_regions": row.unsupported_regions or [],
            "extraction_failures": row.extraction_failures or [],
            "deep_analysis_completed": row.deep_analysis_completed,
            "packed_or_encrypted_suspected": row.packed_or_encrypted_suspected,
            "analysis_timeouts": row.analysis_timeouts,
            "note": (
                "analysis coverage is not finding confidence — no "
                "finding is never proof of absence (§7)"),
        }
