"""8-stage scan pipeline (sync)."""

from __future__ import annotations

from db.tenancy import filtered_get

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


def _exclude_tests() -> bool:
    """Test code is scanned by default and tagged ``code_origin=test`` (test keystores and
    hard-coded fixture keys are inventory). Set CRYPTOSCAN_EXCLUDE_TESTS=1 to skip it."""
    import os

    return os.environ.get("CRYPTOSCAN_EXCLUDE_TESTS", "0").lower() in ("1", "true", "yes")


def ctx_name(scan_id: str) -> str:
    return f"scan:{scan_id}"
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
    container_result: dict[str, Any] = field(default_factory=dict)
    tls_result: dict[str, Any] = field(default_factory=dict)
    cloud_result: dict[str, Any] = field(default_factory=dict)
    ot_result: dict[str, Any] = field(default_factory=dict)
    current_stage: str = ""
    logs: list[dict[str, Any]] = field(default_factory=list)
    compliance_scopes: list[str] = field(default_factory=list)
    system_id: str | None = None
    scan_persisted: bool = False

    def update(self, **kwargs) -> "PipelineContext":
        for key, value in kwargs.items():
            setattr(self, key, value)
        return self



def _bounded_cascade(cascade: dict, *, max_providers: int = 500, max_list: int = 300) -> dict:
    """The dependency & cascade report travels in ``Scan.statistics`` (JSON); keep it bounded for monoliths."""
    out = dict(cascade)
    out["providers"] = list(cascade.get("providers") or [])[:max_providers]
    for k in ("libraries", "package_dependencies", "shared_keys", "key_references", "weak_parameters", "systems"):
        out[k] = list(cascade.get(k) or [])[:max_list]
    out["unresolved_relationships"] = list(cascade.get("unresolved_relationships") or [])[:max_list]
    out["truncated"] = {
        "providers": max(0, len(cascade.get("providers") or []) - max_providers),
        **{k: max(0, len(cascade.get(k) or []) - max_list) for k in ("libraries", "package_dependencies", "unresolved_relationships", "shared_keys", "key_references", "weak_parameters", "systems")},
    }
    return out


def _evidence_sources(findings: list) -> dict[str, int]:
    """Findings per evidence source type (SOURCE_CODE / RUNTIME_LOG / KEY_INVENTORY / …) — lets the API and UI
    tell a code scan from a log-drop or key-export scan without opening every finding."""
    out: dict[str, int] = {}
    for f in findings:
        t = ((f.get("source") or {}).get("type") if isinstance(f, dict) else None) or "UNKNOWN"
        out[t] = out.get(t, 0) + 1
    return out


def inventory_certificates(findings: list, *, now: "datetime | None" = None) -> list[dict]:
    """Certificate rows from KEY_INVENTORY findings (keytool / RACDCERT / openssl text / cert CSV / cloud KMS).

    Exports rarely include a SHA-256 fingerprint, so the row key is derived
    deterministically from subject | issuer | not_after | serial and flagged
    ``extra.fingerprint_derived`` so the UI can say so. Metadata only.
    """
    import hashlib
    from datetime import datetime as _dt, timezone as _tz

    now = now or _dt.now(_tz.utc)
    out: dict[str, dict] = {}
    for f in findings:
        d = f if isinstance(f, dict) else f.model_dump()
        if ((d.get("source") or {}).get("type")) != "KEY_INVENTORY":
            continue
        inv = d.get("inventory") or {}
        subject = inv.get("subject")
        if not subject or inv.get("role"):  # role rows are signature-digest side findings, not the certificate itself
            continue
        crypto = d.get("crypto") or {}
        fp = inv.get("fingerprint_sha256") or inv.get("fingerprint")
        derived = False
        if not fp or len(str(fp).replace(":", "")) != 64:
            basis = "|".join(str(inv.get(k) or "") for k in ("subject", "issuer", "not_after", "serial_number"))
            fp = hashlib.sha256(f"key-inventory|{basis}".encode()).hexdigest()
            derived = True
        fp = str(fp).replace(":", "").lower()
        not_after = inv.get("not_after")
        days = None
        if not_after:
            try:
                days = (_dt.fromisoformat(str(not_after)[:10]).replace(tzinfo=_tz.utc) - now).days
            except ValueError:
                days = None
        status = None if days is None else ("EXPIRED" if days < 0 else "EXPIRING_SOON" if days <= 90 else "VALID")
        location = (d.get("source") or {}).get("file_path")
        payload = out.get(fp) or {
            "fingerprint_sha256": fp,
            "subject": subject,
            "issuer": inv.get("issuer"),
            "serial_number": inv.get("serial_number"),
            "not_before": inv.get("not_before"),
            "not_after": not_after,
            "public_key_algorithm": crypto.get("algorithm") if crypto.get("algorithm") != "UNKNOWN" else None,
            "public_key_size": crypto.get("key_size"),
            "expiry_status": status,
            "days_until_expiry": days,
            "is_self_signed": bool(inv.get("self_signed")),
            "usages": [],
            "extra": {
                "source": "KEY_INVENTORY",
                "fingerprint_derived": derived,
                "library": (d.get("metadata") or {}).get("library"),
                "key_label": inv.get("key_label"),
                "key_store": inv.get("key_store"),
                "entry_type": inv.get("entry_type"),
                "signature_algorithm": inv.get("signature_algorithm"),
                "state": inv.get("state"),
            },
        }
        if location and location not in payload["usages"]:
            payload["usages"].append(location)
        out[fp] = payload
    return list(out.values())


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
        system_id: str | None = None,
        **kwargs,
    ):
        if job is not None:
            job_id = job_id or getattr(job, "job_id", None) or getattr(job, "id", None)
            target_repo = target_repo or getattr(job, "target_repo", None)
            target_branch = target_branch or getattr(job, "target_branch", None) or "main"
            triggered_by = triggered_by or getattr(job, "triggered_by", None) or "system"
            target_commit = target_commit or getattr(job, "target_commit", None)
            system_id = system_id or getattr(job, "system_id", None)

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
            system_id=system_id,
        )
        stage = "init"
        try:
            self._advance(session, ctx, "clone", status="RUNNING")
            self._post_github(ctx, "pending", "CryptoScan pipeline running")
            self._clone(ctx)
            stage = "language_detect"
            self._advance(session, ctx, "language_detect")
            self._language_detect(ctx)
            stage = "scan"
            self._advance(session, ctx, "scan")
            self._scan(ctx)
            stage = "evidence"
            self._advance(session, ctx, "evidence", extra={"findings": len(ctx.findings)})
            self._evidence(ctx)
            stage = "load"
            self._advance(session, ctx, "load")
            self._load(ctx, session)
            stage = "normalize"
            self._advance(session, ctx, "normalize")
            self._normalize(ctx, session)
            stage = "policy"
            self._advance(session, ctx, "policy")
            self._policy(ctx, session)
            stage = "drift"
            self._advance(session, ctx, "drift")
            self._drift(ctx, session)
            stage = "quantum"
            self._advance(session, ctx, "quantum")
            self._quantum(ctx, session)
            stage = "gate"
            self._advance(session, ctx, "gate")
            self._gate(ctx, session)
            stage = "cbom"
            self._advance(session, ctx, "cbom")
            self._cbom(ctx)
            self._stamp_coverage(ctx, session, status="CURRENT")
            stage = "alert"
            self._advance(session, ctx, "alert")
            self._alert(ctx)
            if owns_session:
                session.commit()
            else:
                session.flush()
            self._advance(session, ctx, "alert", status="COMPLETED")
            self._post_github(ctx, "success", f"Scan completed ({len(ctx.findings)} findings)")
            if owns_session:
                session.commit()
            return ctx.scan_id
        except Exception as exc:
            logger.exception("pipeline_failed", extra={"job_id": job_id, "stage": stage})
            self._stamp_coverage_failed(ctx, str(exc))
            if owns_session:
                session.rollback()
            try:
                self._advance(session, ctx, stage, status="FAILED", message=str(exc))
                self._post_github(ctx, "failure", f"Pipeline failed at {stage}")
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
        """Publish job status/progress so it is visible WHILE the job runs.

        BaseRepository.update only flushes, and run() commits its own session
        once, after the final stage. Every progress update therefore sat in an
        uncommitted transaction that no other connection could read: the API
        reported QUEUED with started_at NULL for the whole scan and then
        jumped straight to COMPLETED, because that was the moment the work
        became visible rather than the moment it happened. A nine-minute scan
        was indistinguishable from a wedged one.

        Committing inline on the pipeline session is not the fix -- that would
        also commit the half-built scan and evidence rows it is carrying, and
        the evidence load is deliberately atomic.

        So status, progress and error_message travel on their own short-lived
        session and commit immediately: they are operational telemetry about
        the job, not part of the scan's data transaction. scan_id is the one
        exception. It is a foreign key to scans.id, so it cannot be written
        before the scan row commits and stays on the pipeline's transaction.
        """
        from db.repositories.job_repository import JobRepository

        scan_id = kwargs.pop("scan_id", None)
        if scan_id is not None:
            # FK-bound: must land in the same transaction as the scan row.
            try:
                JobRepository(session).update(job_id, {"scan_id": scan_id})
            except Exception:
                logger.warning("job_scan_id_update_failed",
                               extra={"job_id": job_id, "scan_id": scan_id})

        from db.connection.session import SessionLocal

        telemetry = None
        try:
            telemetry = SessionLocal()
            updated = JobRepository(telemetry).update_status(job_id, status, **kwargs)
            if updated is None:
                # The job row is not visible on a fresh connection -- it was
                # created in the caller's uncommitted transaction, which is
                # what the in-process tests do. Fall back to that session so
                # their behaviour is unchanged.
                telemetry.rollback()
                JobRepository(session).update_status(job_id, status, **kwargs)
            else:
                telemetry.commit()
        except Exception:
            if telemetry is not None:
                try:
                    telemetry.rollback()
                except Exception:
                    logger.debug("job_status_rollback_failed", extra={"job_id": job_id})
            # A second connection cannot always write. SQLite allows one
            # writer at a time, so while the pipeline holds its transaction
            # the telemetry session is locked out -- and this backend is
            # supported (ALLOW_SQLITE, the staging estate the backup drill
            # runs against). Falling back to the pipeline's own session
            # keeps the update deferred-but-applied, which is exactly the
            # old behaviour, instead of dropping it on the floor. On a
            # backend with concurrent writers the fast path above wins and
            # progress is live.
            try:
                JobRepository(session).update_status(job_id, status, **kwargs)
                logger.debug("job_status_deferred_to_pipeline_session",
                             extra={"job_id": job_id, "status": status})
            except Exception:
                # Previously the only outcome, logged at debug, so a failing
                # status update was invisible. A job whose progress stops
                # updating is what an operator needs told.
                logger.warning("job_status_update_failed",
                               extra={"job_id": job_id, "status": status})
        finally:
            if telemetry is not None:
                telemetry.close()

    def _advance(
        self,
        session,
        ctx: PipelineContext,
        stage: str,
        *,
        status: str = "RUNNING",
        message: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        from worker.pipeline.progress import build_progress, utcnow

        ctx.current_stage = stage
        entry = {
            "ts": utcnow(),
            "stage": stage,
            "level": "ERROR" if status == "FAILED" else "INFO",
            "message": message or stage,
        }
        if extra:
            entry["extra"] = extra
        ctx.logs.append(entry)
        self._publish_event(ctx, stage, status, message, extra)
        progress = build_progress(current_stage=stage, status=status, logs=ctx.logs, extra={"scan_id": ctx.scan_id})
        kwargs: dict[str, Any] = {"progress": progress}
        if ctx.scan_id and ctx.scan_persisted:
            kwargs["scan_id"] = ctx.scan_id
        if status == "FAILED" and message:
            kwargs["error_message"] = message
        self._set_job_status(session, ctx.job_id, status, **kwargs)

    def _publish_event(
        self,
        ctx: PipelineContext,
        stage: str,
        status: str,
        message: str,
        extra: dict[str, Any] | None,
    ) -> None:
        """Real-time stream (no-op outside the API process / when bus absent)."""
        try:
            from api.events.bus import get_event_bus

            event_type = "scan.stage" if status == "RUNNING" else f"scan.{status.lower()}"
            if stage == "alert" and status == "COMPLETED":
                event_type = "scan.completed"
                gate = (ctx.scan_meta.get("gate") or {})
                extra = {
                    "findings": len(ctx.findings),
                    "gate_decision": gate.get("decision"),
                    "blocking": (gate.get("counts") or {}).get("blocking"),
                }
            get_event_bus().publish(
                event_type,
                {
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "stage": stage,
                    "status": status,
                    "message": message or stage,
                    "extra": extra or {},
                },
                source="pipeline",
            )
        except Exception as _handler_exc:  # standalone worker process has no bus — polling covers it
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass

    def _post_github(
        self,
        ctx: PipelineContext,
        state: str,
        description: str,
        *,
        context: str = "cryptoscan/compliance",
    ) -> None:
        token = getattr(settings, "GITHUB_TOKEN", "") or ""
        if not token:
            return
        try:
            from api.github.status_poster import post_pipeline_status

            dashboard = getattr(settings, "DASHBOARD_URL", "") or ""
            target = f"{dashboard}/#job/{ctx.job_id}" if dashboard else ""
            post_pipeline_status(
                token=token,
                repo_url=ctx.target_repo,
                commit=ctx.target_commit,
                state=state,
                description=description,
                target_url=target,
                context=context,
            )
        except Exception:
            logger.debug("github_status_skipped", exc_info=True)

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

    def _language_detect(self, ctx: PipelineContext) -> None:
        from worker.pipeline.stage_language_detect import execute as detect

        detect(ctx)

    def _cbom(self, ctx: PipelineContext) -> None:
        from worker.pipeline.stage_cbom_generate import execute as generate

        generate(ctx)

    def _scan(self, ctx: PipelineContext) -> None:
        from scanner.core.scanner import Scanner

        scanner = Scanner(exclude_test_dirs=_exclude_tests())
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
        cascade = getattr(scan_result, "cascade", None)
        if cascade:
            stats["cascade"] = _bounded_cascade(cascade)
        stats["evidence_sources"] = _evidence_sources(findings)
        languages = list((ctx.scan_meta or {}).get("languages") or [])
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
            "languages": languages,
        }
        self._container(ctx)
        self._tls(ctx)
        self._cloud(ctx)
        self._ot_findings(ctx)
        logger.info("stage_scan_done", extra={"findings": len(ctx.findings)})

    def _ot_findings(self, ctx: PipelineContext) -> None:
        try:
            from worker.pipeline.stage_ot_scan import execute as ot_scan
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        ot_scan(ctx, session=None)

    def _cloud(self, ctx: PipelineContext) -> None:
        try:
            from worker.pipeline.stage_cloud_scan import execute as cloud_scan
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        cloud_scan(ctx)

    def _tls(self, ctx: PipelineContext) -> None:
        try:
            from worker.pipeline.stage_network_scan import execute as network_scan
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        network_scan(ctx)
        try:
            from worker.pipeline.stage_cert_inventory import execute as cert_inventory

            cert_inventory(ctx)
        except Exception:
            logger.debug("cert_inventory_skipped", exc_info=True)

    def _container(self, ctx: PipelineContext) -> None:
        root = Path(ctx.repo_path)
        if not root.exists():
            return
        markers = {"dockerfile", "requirements.txt", "package.json", "pom.xml", "go.mod"}
        has_manifest = False
        has_binary = False
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name.lower()
            if name in markers or path.suffix.lower() == ".csproj":
                has_manifest = True
            if path.suffix.lower() == ".jar" or name.startswith("libcrypto"):
                has_binary = True
            if has_manifest or has_binary:
                break
        if not has_manifest and not has_binary:
            return
        try:
            from container_scanner.core.scanner import ContainerScanner
        except Exception:
            logger.debug("container_scanner_unavailable")
            return
        result = ContainerScanner(live_cve=False).scan_filesystem(root, scan_id=ctx.scan_id)
        ctx.container_result = result
        ctx.findings.extend(result.get("findings") or [])
        ctx.scan_meta["container"] = {
            "packages": len(result.get("packages") or []),
            "libraries": len(result.get("libraries") or []),
            "vulnerabilities": len(result.get("vulnerabilities") or []),
        }

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
        ctx.scan_persisted = True
        if ctx.container_result:
            try:
                from db.models.container_scan import ContainerScan
                from db.repositories.vulnerability_repository import VulnerabilityRepository

                result = ctx.container_result
                session.add(
                    ContainerScan(
                        scan_id=scan.id,
                        target=str(Path(ctx.repo_path)),
                        package_count=len(result.get("packages") or []),
                        library_count=len(result.get("libraries") or []),
                        vuln_count=len(result.get("vulnerabilities") or []),
                        result=result,
                    )
                )
                if result.get("vulnerabilities"):
                    VulnerabilityRepository(session).replace_for_scan(scan.id, result["vulnerabilities"])
            except Exception:
                logger.debug("container_scan_persist_skipped", exc_info=True)
        if ctx.tls_result and ctx.tls_result.get("certificates"):
            try:
                from db.repositories.certificate_repository import CertificateRepository
                from db.repositories.maturity_repository import MaturityRepository

                repo = CertificateRepository(session)
                usages = MaturityRepository(session)
                for cert in ctx.tls_result["certificates"]:
                    if cert.get("fingerprint_sha256"):
                        repo.upsert(cert)
                for usage in ctx.tls_result.get("usages") or []:
                    if usage.get("fingerprint_sha256") and usage.get("location"):
                        usages.upsert_usage(
                            usage["fingerprint_sha256"],
                            usage["location"],
                            usage.get("usage_type") or "UNKNOWN",
                        )
            except Exception:
                logger.debug("certificate_persist_skipped", exc_info=True)
        inv_certs = inventory_certificates(ctx.findings or [])
        if inv_certs:
            try:
                from db.repositories.certificate_repository import CertificateRepository

                repo = CertificateRepository(session)
                for cert in inv_certs:
                    repo.upsert(cert)
                logger.info("inventory_certificates_persisted", extra={"count": len(inv_certs)})
            except Exception:
                logger.debug("inventory_certificate_persist_skipped", exc_info=True)
        if ctx.ot_result and (ctx.ot_result.get("devices") or ctx.ot_result.get("findings")):
            try:
                from db.repositories.maturity_repository import MaturityRepository

                repo = MaturityRepository(session)
                id_by_ip = {}
                for device in ctx.ot_result.get("devices") or []:
                    row = repo.upsert_ot_device(device)
                    id_by_ip[device.get("ip_address")] = row.id
                for finding in ctx.ot_result.get("findings") or []:
                    ip = (finding.get("device") or {}).get("ip_address")
                    repo.add_ot_finding(id_by_ip.get(ip), finding)
            except Exception:
                logger.debug("ot_persist_skipped", exc_info=True)
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
        self._resolve_system(ctx, session)
        declared_scopes = self._declared_scope_index(ctx)
        for row in rows:
            finding_data = dict(row.finding_data or {})
            # scopes = repo-level System scopes ∪ scopes of the declared business system that owns this file
            scopes = list(ctx.compliance_scopes or [])
            for scope in self._scopes_for_path(row.file_path, declared_scopes):
                if scope not in scopes:
                    scopes.append(scope)
            if scopes and sorted(scopes) != sorted(finding_data.get("compliance_scopes") or []):
                finding_data["compliance_scopes"] = list(scopes)
                row.finding_data = finding_data
            payload = {
                "id": row.id,
                "evidence_id": row.id,
                "algorithm": row.algorithm,
                "key_size": row.key_size,
                "mode": row.mode,
                "purpose": row.purpose,
                "is_hardcoded_key": row.is_hardcoded_key,
                "normalized_crypto": row.normalized_crypto or {},
                "finding_data": finding_data,
                "compliance_scopes": scopes or finding_data.get("compliance_scopes") or [],
            }
            evaluation = engine.evaluate(payload)
            row.policy_evaluation = evaluation.model_dump(mode="json")
            row.compliance_status = evaluation.overall_status
        session.flush()
        self._dedup(ctx, session, rows)
        self._graph(ctx, session)
        self._business(ctx, session)
        self._agility(ctx, session)
        logger.info("stage_policy_done", extra={"count": len(rows)})

    def _dedup(self, ctx: PipelineContext, session, rows) -> None:
        try:
            from deduplication.core.engine import DeduplicationEngine
            from db.repositories.asset_repository import AssetRepository
        except Exception:
            logger.debug("dedup_unavailable")
            return
        findings = []
        for row in rows:
            payload = dict(row.finding_data or {})
            payload["evidence_id"] = row.id
            payload["finding_id"] = row.id
            payload["algorithm"] = row.algorithm
            payload["purpose"] = row.purpose
            payload["mode"] = row.mode
            payload["key_size"] = row.key_size
            payload["file_path"] = row.file_path
            payload["line_number"] = row.line_number
            payload["is_hardcoded_key"] = row.is_hardcoded_key
            payload["confidence"] = row.confidence
            findings.append(payload)
        merged = DeduplicationEngine().merge_with_stats(findings)
        assets = merged["assets"]
        ctx.scan_meta["dedup"] = merged["stats"]
        stored = AssetRepository(session).replace_for_scan(ctx.scan_id or "", assets)
        self._link_system_assets(ctx, session, stored)
        self._sync_declared_systems(ctx, session, stored)
        self._quantum_assets(ctx, session, stored)
        try:
            from sqlalchemy.orm.attributes import flag_modified

            from db.models.scan import Scan

            scan = filtered_get(session, Scan, ctx.scan_id) if ctx.scan_id else None
            if scan is not None:
                stats = dict(scan.statistics or {})
                stats["dedup"] = merged["stats"]
                scan.statistics = stats
                flag_modified(scan, "statistics")
        except Exception:
            logger.debug("dedup_stats_not_persisted", exc_info=True)
        session.flush()
        logger.info("stage_dedup_done", extra={"assets": len(assets)})

    def _resolve_system(self, ctx: PipelineContext, session) -> None:
        try:
            from db.repositories.system_repository import SystemRepository
            from worker.pipeline.progress import system_name_from_repo
        except Exception:
            logger.debug("system_repo_unavailable")
            return
        repo = SystemRepository(session)
        system = repo.get_by_id(ctx.system_id) if ctx.system_id else None
        if system is None:
            name = system_name_from_repo(ctx.target_repo)
            system = repo.get_or_create(
                name,
                owner=ctx.triggered_by,
                environment="dev" if ctx.target_repo.startswith(("local://", "file://", "/")) else "prod",
                description=ctx.target_repo,
                scan_target=ctx.target_repo,
                scan_branch=ctx.target_branch,
            )
        if not system.scan_target:
            system.scan_target = ctx.target_repo
        if ctx.target_branch and not system.scan_branch:
            system.scan_branch = ctx.target_branch
        ctx.system_id = system.id
        ctx.compliance_scopes = list(system.compliance_scopes or [])
        logger.info("stage_systems_resolved", extra={"system": system.name, "scopes": ctx.compliance_scopes})

    def _stamp_coverage(self, ctx: PipelineContext, session, *, status: str = "CURRENT") -> None:
        if not ctx.system_id:
            self._resolve_system(ctx, session)
        if not ctx.system_id:
            return
        try:
            from collections import Counter

            from db.repositories.system_repository import SystemRepository
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        algorithms: Counter[str] = Counter()
        for record in ctx.evidence_records or ctx.findings or []:
            algorithms[self._record_algorithm(record)] += 1
        posture = self._scan_posture(session, ctx.scan_id)
        try:
            SystemRepository(session).stamp_scan(
                ctx.system_id,
                scan_id=ctx.scan_id,
                status=status,
                target=ctx.target_repo,
                branch=ctx.target_branch,
                component_count=sum(algorithms.values()),
                algorithms=dict(algorithms),
                posture_score=posture.get("score"),
                posture_grade=posture.get("grade"),
            )
        except Exception:
            logger.debug("coverage_stamp_skipped", exc_info=True)

    def _scan_posture(self, session, scan_id: str | None) -> dict[str, Any]:
        """Assess scan posture from the normalized evidence rows (the same
        source of truth the CBOM generator uses)."""
        if not scan_id:
            return {}
        try:
            from cbom.assessment import assess_cbom
            from cbom.generator import CbomGenerator
            from db.models.evidence_record import EvidenceRecord
            from sqlalchemy import select as _select
        except Exception:
            return {}
        try:
            rows = list(
                session.execute(_select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars()
            )
            if not rows:
                return {}
            records = [
                {
                    "algorithm": row.algorithm,
                    "mode": row.mode,
                    "key_size": row.key_size,
                    "file_path": getattr(row, "file_path", None) or "scan",
                    "line_number": getattr(row, "line_number", 0) or 0,
                    "normalized_crypto": row.normalized_crypto,
                    "id": getattr(row, "evidence_id", None) or getattr(row, "id", None),
                }
                for row in rows
            ]
            bom = CbomGenerator().from_records(records, name=ctx_name(scan_id))
            report = assess_cbom(bom)
            return {"score": report["score"], "grade": report["grade"]}
        except Exception:
            logger.debug("posture_stamp_skipped", exc_info=True)
            return {}

    @staticmethod
    def _record_algorithm(record) -> str:
        """Extract the algorithm name from a finding-shaped record.

        Handles the three shapes that reach coverage stamping:
        RawFinding dumps (``crypto.algorithm``), EvidenceRecord dumps
        (``finding.crypto.algorithm`` / ``finding.algorithm``), and flat
        dicts from auxiliary scanners (``algorithm``).
        """
        if not isinstance(record, dict):
            return str(getattr(record, "algorithm", "") or "UNKNOWN")
        crypto = record.get("crypto")
        if isinstance(crypto, dict) and crypto.get("algorithm"):
            return str(crypto["algorithm"])
        finding = record.get("finding")
        if isinstance(finding, dict):
            inner = finding.get("crypto")
            if isinstance(inner, dict) and inner.get("algorithm"):
                return str(inner["algorithm"])
            if finding.get("algorithm"):
                return str(finding["algorithm"])
        if record.get("algorithm"):
            return str(record["algorithm"])
        return "UNKNOWN"

    def _stamp_coverage_failed(self, ctx: PipelineContext, message: str) -> None:
        if not ctx.system_id:
            return
        try:
            from db.connection.session import SessionLocal
            from db.repositories.system_repository import SystemRepository

            session = SessionLocal()
            try:
                SystemRepository(session).stamp_scan(
                    ctx.system_id,
                    scan_id=ctx.scan_id,
                    status="FAILED",
                    target=ctx.target_repo,
                    branch=ctx.target_branch,
                    error=message[:500],
                )
                session.commit()
            finally:
                session.close()
        except Exception:
            logger.debug("coverage_fail_stamp_skipped", exc_info=True)

    @staticmethod
    def _declared_scope_index(ctx: PipelineContext) -> list[tuple[list[str], list[str]]]:
        """[(paths, scopes)] for every system in cryptoscan-systems.yml that declares compliance_scopes."""
        cascade = ((ctx.scan_meta or {}).get("statistics") or {}).get("cascade") or {}
        out = []
        for row in cascade.get("systems") or []:
            if isinstance(row, dict) and row.get("compliance_scopes") and row.get("paths"):
                out.append(([str(p) for p in row["paths"]], [str(s).upper() for s in row["compliance_scopes"]]))
        return out

    @staticmethod
    def _scopes_for_path(file_path: str | None, index: list[tuple[list[str], list[str]]]) -> list[str]:
        if not file_path or not index:
            return []
        from fnmatch import fnmatch

        path = str(file_path).split("!", 1)[0].lstrip("./")
        scopes: list[str] = []
        for globs, declared in index:
            for g in globs:
                base = str(g).rstrip("/").removesuffix("/**").removesuffix("/*").lstrip("./")
                if path == base or path.startswith(base + "/") or fnmatch(path, str(g)):
                    scopes.extend(s for s in declared if s not in scopes)
                    break
        return scopes

    def _link_system_assets(self, ctx: PipelineContext, session, assets) -> None:
        if not ctx.system_id:
            self._resolve_system(ctx, session)
        if not ctx.system_id:
            return
        try:
            from db.repositories.system_repository import SystemRepository
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        repo = SystemRepository(session)
        for asset in assets:
            repo.attach_asset(ctx.system_id, asset.id)

    def _sync_declared_systems(self, ctx: PipelineContext, session, assets) -> None:
        """Persist the business systems declared in ``cryptoscan-systems.yml`` (cascade ``systems`` rollup).

        Each declared system becomes a DB ``System`` (criticality/owner filled when the row is new or blank), owns the
        stored assets whose file path falls under its declared paths, and gets ``system_dependencies`` edges:
        repo-system → declared system (``contains``) and declared → declared for ``depends_on_systems``
        (``imports-crypto``). This is what makes the estate CBOM / graph / migration order system-aware without a
        manual CMDB import. Idempotent; never removes edges or systems.
        """
        cascade = ((ctx.scan_meta or {}).get("statistics") or {}).get("cascade") or {}
        declared = [row for row in (cascade.get("systems") or []) if isinstance(row, dict) and row.get("system")]
        if not declared:
            return
        try:
            from fnmatch import fnmatch

            from db.repositories.system_repository import SystemRepository
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        repo = SystemRepository(session)

        def _under(path: str, globs: list[str]) -> bool:
            path = str(path).split("!", 1)[0].lstrip("./")
            for g in globs:
                base = str(g).rstrip("/").removesuffix("/**").removesuffix("/*").lstrip("./")
                if path == base or path.startswith(base + "/") or fnmatch(path, str(g)):
                    return True
            return False

        by_name: dict[str, str] = {}
        from collections import Counter

        entity_counts = Counter(str(row.get("legal_entity")).strip().lower() for row in declared if row.get("legal_entity"))
        repo_entity = None
        if entity_counts:
            top, n = entity_counts.most_common(1)[0]
            # the repository-level system belongs to the entity that owns (a strict majority of) its declared systems —
            # e.g. a bank repo with one DIFC-branch system still rolls up under the bank; a 50/50 split stays unassigned
            if n * 2 > sum(entity_counts.values()):
                repo_entity = top
        if repo_entity and ctx.system_id:
            try:
                repo_system = repo.get_by_id(ctx.system_id)
                if repo_system is not None and (repo_system.extra or {}).get("legal_entity") != repo_entity:
                    repo_system.extra = {**(repo_system.extra or {}), "legal_entity": repo_entity}
            except Exception:
                logger.debug("repo_system_entity_failed", exc_info=True)
        for row in declared:
            name = str(row["system"]).strip()
            db_name = name
            entity = str(row.get("legal_entity") or "").strip().lower() or None
            try:
                existing = repo.get_by_name(name)
                owner_entity = (existing.extra or {}).get("legal_entity") if existing is not None else None
                if existing is not None and entity and owner_entity and owner_entity != entity:
                    # ``System.name`` is unique across the whole estate; two banks in one group both declaring "CORE"
                    # must not be merged into one row (that would put bank A's evidence under bank B in the
                    # supervisor view). Qualify the later one with its entity code and say so.
                    db_name = f"{entity}/{name}"
                    logger.warning("system_name_collision_across_entities",
                                   extra={"system": name, "owned_by": owner_entity, "declared_by": entity, "stored_as": db_name})
                system = repo.get_or_create(
                    db_name,
                    owner=row.get("owner"),
                    environment="prod",
                    description=f"declared in cryptoscan-systems.yml ({ctx.target_repo})",
                    criticality=row.get("criticality"),
                )
                if row.get("criticality") and not system.criticality:
                    system.criticality = str(row["criticality"])
                if row.get("owner") and not system.owner:
                    system.owner = str(row["owner"])
                if row.get("compliance_scopes") and not system.compliance_scopes:
                    system.compliance_scopes = [str(x) for x in row["compliance_scopes"]]
                if row.get("business_unit") and not system.business_unit:
                    system.business_unit = str(row["business_unit"])
                if entity:
                    extra = dict(system.extra or {})
                    if extra.get("legal_entity") != entity:
                        extra["legal_entity"] = entity
                        system.extra = extra
                if db_name != name:
                    extra = dict(system.extra or {})
                    if extra.get("declared_name") != name:
                        system.extra = {**extra, "declared_name": name}
                by_name[name] = system.id
                paths = [str(p) for p in (row.get("paths") or [])]
                if paths:
                    for asset in assets:
                        if _under(asset.file_path, paths):
                            repo.attach_asset(system.id, asset.id)
                if ctx.system_id and ctx.system_id != system.id:
                    repo.add_dependency(ctx.system_id, system.id, "contains")
            except Exception:
                logger.debug("declared_system_sync_failed", extra={"system": name}, exc_info=True)
        for row in declared:
            src = by_name.get(str(row["system"]).strip())
            for dep in row.get("depends_on_systems") or []:
                dst = by_name.get(str(dep).strip())
                if src and dst and src != dst:
                    try:
                        repo.add_dependency(src, dst, "imports-crypto")
                    except Exception:
                        logger.debug("declared_system_edge_failed", exc_info=True)
        session.flush()
        logger.info("stage_declared_systems_synced", extra={"systems": len(by_name)})

    def _quantum(self, ctx: PipelineContext, session) -> None:
        try:
            from worker.pipeline.stage_quantum import execute as quantum_stage

            quantum_stage(ctx, session=session)
        except Exception:
            logger.debug("quantum_stage_skipped", exc_info=True)

    def _graph(self, ctx: PipelineContext, session) -> None:
        try:
            from worker.pipeline.stage_graph_sync import execute as graph_sync

            graph_sync(ctx, session=session)
        except Exception:
            logger.debug("graph_sync_skipped", exc_info=True)

    def _business(self, ctx: PipelineContext, session) -> None:
        try:
            from worker.pipeline.stage_business_enrich import execute as enrich

            enrich(ctx, session=session)
        except Exception:
            logger.debug("business_enrich_skipped", exc_info=True)

    def _agility(self, ctx: PipelineContext, session) -> None:
        try:
            from worker.pipeline.stage_agility import execute as score

            score(ctx, session=session)
        except Exception:
            logger.debug("agility_stage_skipped", exc_info=True)

    def _quantum_assets(self, ctx: PipelineContext, session, assets) -> None:
        try:
            from db.models.system import System
            from quantum.risk import score_asset
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return
        system = filtered_get(session, System, ctx.system_id) if ctx.system_id else None
        system_payload = system.to_dict() if system is not None else {}
        for asset in assets:
            try:
                extra = dict(asset.extra or {})
                extra["quantum_risk"] = score_asset(
                    {
                        "algorithm": asset.algorithm,
                        "key_size": asset.key_size,
                        "purpose": asset.purpose,
                        "file_path": asset.file_path,
                    },
                    system=system_payload,
                )
                asset.extra = extra
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue

    def _drift(self, ctx: PipelineContext, session) -> None:
        from sqlalchemy import select

        from db.models.drift_event import DriftEvent
        from db.models.evidence_record import EvidenceRecord
        from db.repositories.baseline_repository import BaselineRepository
        from drift.core.detector import DriftDetector

        # Key-inventory drift needs no approved baseline (previous export of the same drop is the reference).
        inventory_events: list[dict] = []
        try:
            from worker.pipeline.inventory_drift import detect_inventory_drift

            inventory_events = detect_inventory_drift(session, ctx.scan_id or "")
        except Exception:
            logger.debug("inventory_drift_skipped", exc_info=True)

        baseline_repo = BaselineRepository(session)
        baseline = baseline_repo.get_active(ctx.target_repo)
        if baseline is None:
            logger.info("no_baseline_skip_drift", extra={"target": ctx.target_repo})
            ctx.drift_events = inventory_events
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

        # Configuration drift (Drift v2.0): first-class CONFIG_* events from
        # crypto *settings* in deploy/config files, compared against the same
        # approved baseline. Facts carry only normalized values — secrets are
        # represented by length + truncated hash, never by their value.
        try:
            from drift.core.config_detector import detect_config_drift
            from drift.core.config_facts import extract_config_facts

            def as_config_findings(scan_id: str) -> list[dict]:
                rows = list(
                    session.execute(
                        select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
                    ).scalars()
                )
                payloads = []
                for r in rows:
                    payload = dict(r.finding_data or {})
                    payload.update(
                        {
                            "algorithm": r.algorithm,
                            "key_size": r.key_size,
                            "mode": r.mode,
                            "purpose": r.purpose,
                            "file_path": r.file_path,
                            "line_number": r.line_number,
                            "is_hardcoded_key": r.is_hardcoded_key,
                        }
                    )
                    payloads.append(payload)
                return payloads

            baseline_facts = extract_config_facts(as_config_findings(baseline.approved_scan_id))
            current_facts = extract_config_facts(as_config_findings(ctx.scan_id or ""))
            for change in detect_config_drift(baseline_facts, current_facts).changes:
                details = dict(change.to_event_dict())
                details["change_type"] = change.change_type
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
                        "algorithm": change.algorithm,
                        "config_key": change.config_key,
                    }
                )
        except Exception:
            logger.debug("config_drift_skipped", exc_info=True)

        ctx.drift_events = inventory_events + events
        session.flush()
        logger.info("stage_drift_done", extra={"events": len(ctx.drift_events)})

    def _gate(self, ctx: PipelineContext, session) -> None:
        from sqlalchemy import select
        from sqlalchemy.orm.attributes import flag_modified

        from db.models.evidence_record import EvidenceRecord
        from db.models.scan import Scan
        from drift.core.gate import evaluate_gate
        from evidence.intelligence.agility import compute_agility
        from evidence.intelligence.work_orders import build_work_orders

        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
        findings = [
            {
                "evidence_id": row.id,
                "algorithm": row.algorithm,
                "key_size": row.key_size,
                "mode": row.mode,
                "purpose": row.purpose,
                "file_path": row.file_path,
                "line_number": row.line_number,
                "compliance_status": row.compliance_status,
                "is_hardcoded_key": row.is_hardcoded_key,
                "finding_data": row.finding_data or {},
                "policy_evaluation": row.policy_evaluation or {},
            }
            for row in rows
        ]
        gate = evaluate_gate(findings, ctx.drift_events)
        agility = compute_agility(findings)
        orders = build_work_orders(findings)
        ctx.scan_meta["gate"] = gate
        ctx.scan_meta["agility"] = agility
        scan = filtered_get(session, Scan, ctx.scan_id) if ctx.scan_id else None
        if scan is not None:
            stats = dict(scan.statistics or {})
            stats["gate"] = {key: value for key, value in gate.items()}
            stats["agility"] = agility
            stats["work_orders"] = {
                "total_orders": orders["total_orders"],
                "total_sites": orders["total_sites"],
            }
            scan.statistics = stats
            try:
                flag_modified(scan, "statistics")
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
            session.flush()
        gh_state = "success" if gate["decision"] != "FAIL" else "failure"
        self._post_github(ctx, gh_state, gate["summary"][:140], context="cryptoscan/drift-gate")
        logger.info("stage_gate_done", extra={"decision": gate["decision"]})

    def _alert(self, ctx: PipelineContext) -> None:
        quantum = ctx.scan_meta.get("quantum") or {}
        mosca_verdict = (quantum.get("mosca") or {}).get("verdict")
        if quantum.get("overall_hndl_risk") == "CRITICAL" or mosca_verdict in {"ALREADY_LATE", "AT_RISK"}:
            logger.warning(
                "quantum_migration_alert",
                extra={
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "hndl": quantum.get("overall_hndl_risk"),
                    "mosca": mosca_verdict,
                    "wave1_sites": quantum.get("wave1_sites"),
                },
            )
        critical = [e for e in ctx.drift_events if e.get("severity") in {"CRITICAL", "HIGH"}]
        if critical:
            logger.warning("drift_alert", extra={"job_id": ctx.job_id, "scan_id": ctx.scan_id, "events": critical})
            if settings.SMTP_HOST:
                try:
                    from drift.alerts.email_alerter import EmailAlerter

                    EmailAlerter().send_drift_alert(ctx.target_repo, critical)
                except Exception:
                    logger.exception("email_alert_failed")
        try:
            from business_context.alerts.stakeholder import notify_stakeholders

            notify_stakeholders(ctx.findings)
        except Exception:
            logger.debug("stakeholder_alert_skipped", exc_info=True)
