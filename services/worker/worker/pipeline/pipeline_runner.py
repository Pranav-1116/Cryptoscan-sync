"""8-stage scan pipeline (sync)."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from worker.config.settings import get_settings
from worker.workspace.repo_cloner import RepoCloner
from worker.workspace.workspace_manager import WorkspaceManager

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class PipelineContext:
    job_id: str
    target_repo: str
    target_branch: str
    triggered_by: str
    workspace_dir: str
    target_commit: str | None = None
    scan_id: str | None = None
    repo_path: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    scan_meta: dict[str, Any] = field(default_factory=dict)
    evidence_records: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    drift_events: list[dict[str, Any]] = field(default_factory=list)
    current_stage: str = ""

    def update(self, **kwargs) -> "PipelineContext":
        for key, value in kwargs.items():
            setattr(self, key, value)
        return self


class PipelineRunner:
    def __init__(self):
        self.workspaces = WorkspaceManager(settings.workspace_dir)
        self.cloner = RepoCloner()

    def run(
        self,
        job=None,
        workspace=None,
        db=None,
        job_id: str | None = None,
        target_repo: str | None = None,
        target_branch: str | None = None,
        triggered_by: str | None = None,
        target_commit: str | None = None,
        workspace_dir: str | None = None,
        **kwargs,
    ):
        if job is not None:
            job_id = job_id or getattr(job, "job_id", None) or getattr(job, "id", None)
            target_repo = target_repo or getattr(job, "target_repo", None)
            target_branch = target_branch or getattr(job, "target_branch", None) or "main"
            triggered_by = triggered_by or getattr(job, "triggered_by", None) or "system"
            target_commit = target_commit or getattr(job, "target_commit", None)

        if not job_id:
            job_id = str(uuid.uuid4())
        if not target_repo:
            raise ValueError("target_repo is required")

        from db.connection.session import SessionLocal

        owns_session = db is None
        session = db if db is not None else SessionLocal()
        workspace_path = Path(workspace_dir or workspace or self.workspaces.create(job_id))
        workspace_path.mkdir(parents=True, exist_ok=True)

        ctx = PipelineContext(
            job_id=str(job_id),
            target_repo=str(target_repo),
            target_branch=target_branch or "main",
            target_commit=target_commit,
            triggered_by=triggered_by or "system",
            workspace_dir=str(workspace_path),
            scan_id=str(uuid.uuid4()),
        )
        stage = "init"
        try:
            self._set_job_status(session, job_id, "RUNNING")
            stage = "clone"
            self._clone(ctx)
            stage = "scan"
            self._scan(ctx)
            stage = "evidence"
            self._evidence(ctx)
            stage = "load"
            self._load(ctx, session)
            stage = "normalize"
            self._normalize(ctx, session)
            stage = "policy"
            self._policy(ctx, session)
            stage = "drift"
            self._drift(ctx, session)
            stage = "alert"
            self._alert(ctx)
            if owns_session:
                session.commit()
            else:
                session.flush()
            self._set_job_status(session, job_id, "COMPLETED", scan_id=ctx.scan_id)
            if owns_session:
                session.commit()
            return ctx.scan_id
        except Exception as exc:
            logger.exception("pipeline_failed", extra={"job_id": job_id, "stage": stage})
            if owns_session:
                session.rollback()
            try:
                self._set_job_status(session, job_id, "FAILED", error_message=str(exc))
                if owns_session:
                    session.commit()
            except Exception:
                if owns_session:
                    session.rollback()
            raise RuntimeError(f"Pipeline failed at stage {stage}: {exc}") from exc
        finally:
            if owns_session:
                session.close()
            if settings.CLEANUP_WORKSPACE and workspace is None and workspace_dir is None:
                self.workspaces.cleanup(workspace_path)

    def _set_job_status(self, session, job_id: str, status: str, **kwargs) -> None:
        try:
            from db.repositories.job_repository import JobRepository

            JobRepository(session).update_status(job_id, status, **kwargs)
        except Exception:
            logger.debug("job_status_update_skipped", extra={"job_id": job_id, "status": status})

    def _clone(self, ctx: PipelineContext) -> None:
        dest = Path(ctx.workspace_dir) / "repo"
        commit = self.cloner.clone(
            repo_url=ctx.target_repo,
            branch=ctx.target_branch,
            target_path=str(dest),
            commit=ctx.target_commit,
        )
        ctx.repo_path = str(dest if dest.exists() else commit)
        if dest.exists():
            ctx.target_commit = str(commit)
        logger.info("stage_clone_done", extra={"path": ctx.repo_path, "commit": ctx.target_commit})

    def _scan(self, ctx: PipelineContext) -> None:
        from scanner.core.scanner import Scanner

        scanner = Scanner(exclude_test_dirs=True)
        scan_result = scanner.scan(
            root_path=ctx.repo_path,
            scan_id=ctx.scan_id,
            target_type="GIT_REPOSITORY"
            if "://" in ctx.target_repo and not ctx.target_repo.startswith(("local://", "file://"))
            else "LOCAL_DIRECTORY",
            target_location=ctx.target_repo,
            target_commit=ctx.target_commit,
            target_branch=ctx.target_branch,
        )
        findings = []
        for finding in scan_result.findings:
            if hasattr(finding, "model_dump"):
                findings.append(finding.model_dump(mode="json"))
            elif isinstance(finding, dict):
                findings.append(finding)
            else:
                findings.append({"raw": str(finding)})
        ctx.findings = findings
        stats = scan_result.statistics.model_dump(mode="json") if hasattr(scan_result, "statistics") else {}
        ctx.scan_meta = {
            "scan_id": getattr(scan_result, "scan_id", ctx.scan_id),
            "scan_start": getattr(scan_result, "scan_start", datetime.now(timezone.utc).isoformat()),
            "scan_end": getattr(scan_result, "scan_end", None),
            "scanner_id": getattr(scan_result, "scanner_id", "static-java-scanner-v0.1"),
            "scanner_version": getattr(scan_result, "scanner_version", "0.1.0"),
            "target_type": getattr(getattr(scan_result, "scan_target", None), "type", "LOCAL_DIRECTORY"),
            "target_location": ctx.target_repo,
            "target_commit": ctx.target_commit,
            "target_branch": ctx.target_branch,
            "operator": ctx.triggered_by,
            "statistics": stats,
        }
        logger.info("stage_scan_done", extra={"findings": len(ctx.findings)})

    def _evidence(self, ctx: PipelineContext) -> None:
        from evidence.core.pipeline import EvidencePipeline

        pipeline = EvidencePipeline(scan_session_id=ctx.scan_id)
        records, manifest = pipeline.process(findings=ctx.findings, scan_id=ctx.scan_id)
        ctx.evidence_records = [r.model_dump(mode="json") for r in records]
        ctx.manifest = manifest.model_dump(mode="json")
        logger.info("stage_evidence_done", extra={"records": len(ctx.evidence_records)})

    def _load(self, ctx: PipelineContext, session) -> None:
        from db.loader.evidence_loader import EvidenceLoader
        from db.loader.pre_load_verifier import verify_records

        ok, err = verify_records(ctx.evidence_records)
        if not ok:
            raise RuntimeError(f"pre-load verification failed: {err}")
        loader = EvidenceLoader(session)
        scan = loader.load(
            scan_meta=ctx.scan_meta,
            evidence_records=ctx.evidence_records,
            manifest=ctx.manifest,
            scan_id=ctx.scan_id,
        )
        ctx.scan_id = scan.id
        session.flush()
        logger.info("stage_load_done", extra={"scan_id": scan.id})

    def _normalize(self, ctx: PipelineContext, session) -> None:
        from sqlalchemy import select

        from db.models.evidence_record import EvidenceRecord
        from normalization.core.engine import NormalizationEngine

        rules_dir = settings.NORMALIZATION_RULES_DIR or str(
            Path(__file__).resolve().parents[3] / "normalization" / "rule_definitions"
        )
        engine = NormalizationEngine(rules_dir)
        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
        for row in rows:
            normalized = engine.normalize(
                row.algorithm or "UNKNOWN",
                context={
                    "mode": row.mode,
                    "key_size": row.key_size,
                    "padding": row.padding,
                    "purpose": row.purpose,
                },
            )
            row.normalized_crypto = normalized.model_dump(mode="json")
            if normalized.algorithm and normalized.algorithm != "UNKNOWN":
                row.algorithm = normalized.algorithm
            if normalized.mode:
                row.mode = normalized.mode
            if normalized.key_size:
                row.key_size = normalized.key_size
        session.flush()
        logger.info("stage_normalize_done", extra={"count": len(rows)})

    def _policy(self, ctx: PipelineContext, session) -> None:
        from sqlalchemy import select

        from db.models.evidence_record import EvidenceRecord
        from policy.core.engine import PolicyEngine

        rules_dir = settings.POLICY_RULES_DIR or str(
            Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"
        )
        engine = PolicyEngine(rules_dir)
        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
        for row in rows:
            payload = {
                "id": row.id,
                "evidence_id": row.id,
                "algorithm": row.algorithm,
                "key_size": row.key_size,
                "mode": row.mode,
                "purpose": row.purpose,
                "is_hardcoded_key": row.is_hardcoded_key,
                "normalized_crypto": row.normalized_crypto or {},
                "finding_data": row.finding_data or {},
            }
            evaluation = engine.evaluate(payload)
            row.policy_evaluation = evaluation.model_dump(mode="json")
            row.compliance_status = evaluation.overall_status
        session.flush()
        logger.info("stage_policy_done", extra={"count": len(rows)})

    def _drift(self, ctx: PipelineContext, session) -> None:
        from sqlalchemy import select

        from db.models.drift_event import DriftEvent
        from db.models.evidence_record import EvidenceRecord
        from db.repositories.baseline_repository import BaselineRepository
        from drift.core.detector import DriftDetector

        baseline_repo = BaselineRepository(session)
        baseline = baseline_repo.get_active(ctx.target_repo)
        if baseline is None:
            logger.info("no_baseline_skip_drift", extra={"target": ctx.target_repo})
            return

        def as_findings(scan_id: str) -> list[dict]:
            rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars())
            return [
                {
                    "algorithm": r.algorithm,
                    "key_size": r.key_size,
                    "mode": r.mode,
                    "purpose": r.purpose,
                    "file_path": r.file_path,
                    "line_number": r.line_number,
                    "compliance_status": r.compliance_status,
                    "is_hardcoded_key": r.is_hardcoded_key,
                }
                for r in rows
            ]

        detector = DriftDetector()
        detection = detector.detect_drift(
            baseline_findings=as_findings(baseline.approved_scan_id),
            current_findings=as_findings(ctx.scan_id or ""),
            baseline_scan_id=baseline.approved_scan_id,
            current_scan_id=ctx.scan_id or "",
        )
        now = datetime.now(timezone.utc)
        events = []
        for change in detection.changes:
            details = {
                "change_type": change.change_type,
                "reason": change.reason,
                "algorithm": change.affected_algorithm,
            }
            session.add(
                DriftEvent(
                    baseline_id=baseline.id,
                    current_scan_id=ctx.scan_id or "",
                    detected_at=now,
                    drift_type=change.change_type,
                    severity=change.severity,
                    drift_details=details,
                    resolution_status="OPEN",
                )
            )
            events.append(
                {
                    "drift_type": change.change_type,
                    "severity": change.severity,
                    "reason": change.reason,
                    "algorithm": change.affected_algorithm,
                }
            )
        ctx.drift_events = events
        session.flush()
        logger.info("stage_drift_done", extra={"events": len(events)})

    def _alert(self, ctx: PipelineContext) -> None:
        critical = [e for e in ctx.drift_events if e.get("severity") in {"CRITICAL", "HIGH"}]
        if not critical:
            return
        logger.warning("drift_alert", extra={"job_id": ctx.job_id, "scan_id": ctx.scan_id, "events": critical})
        if settings.SMTP_HOST:
            try:
                from drift.alerts.email_alerter import EmailAlerter

                EmailAlerter().send_drift_alert(ctx.target_repo, critical)
            except Exception:
                logger.exception("email_alert_failed")
