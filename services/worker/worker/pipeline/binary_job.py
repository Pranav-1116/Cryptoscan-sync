"""Execute a binary/firmware scan job: ``binary://<path>``, no clone involved.

A binary scan used to exist only as a synchronous API call, which meant a
firmware image or a multi-gigabyte artefact bundle had to fit inside one request.
Queued as a job it gets what every other scan gets: a row that can be retried,
progress the console can follow, and a failure that is recorded rather than
dropped.

The API's synchronous ``POST /devsecops/binary/scan`` and this job write the
*same* artifact because both go through :mod:`devsecops.artifact_store` — same
manifest, same signature, same storage keys. The artifact id is chosen by the
caller (the endpoint mints it and returns it with the job id), so a poller can
follow ``/devsecops/sbom/<artifact_id>/report`` from the moment the job is
accepted, and a retry rewrites its own artifact instead of adding a duplicate.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

#: a target that names a filesystem path rather than a repository to clone
BINARY_TARGET_SCHEME = "binary://"

#: the stages this job reports, in order — the honest sequence of work, not a
#: decoration: the console renders these as the job's progress
BINARY_STAGES = ("binary_target", "binary_scan", "binary_sbom", "binary_store", "binary_ingest")


def is_binary_target(target: str | None) -> bool:
    """Is this job target a binary scan (``binary://<path>``)?"""
    return str(target or "").startswith(BINARY_TARGET_SCHEME)


def binary_target_path(target: str | None) -> str:
    """The filesystem path inside a ``binary://`` target."""
    raw = str(target or "")
    return raw[len(BINARY_TARGET_SCHEME):] if raw.startswith(BINARY_TARGET_SCHEME) else raw


def scan_options(job) -> dict:
    """The scan options the endpoint queued with the job (``job.progress``).

    A queued binary scan needs to know *what* to scan with — the rule files, the
    SBOM format, whether to descend into archives — and those have to survive a
    restart, so they travel in the job row's progress JSON rather than in the
    worker's memory.
    """
    options = getattr(job, "scan_options", None)
    if isinstance(options, dict) and options:
        return dict(options)
    progress = getattr(job, "progress", None)
    if isinstance(progress, dict):
        carried = progress.get("scan_options")
        if isinstance(carried, dict):
            return dict(carried)
    return {}


def _stage(current: str, *, status: str = "RUNNING", options: dict | None = None,
           logs: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    """Progress JSON for one stage, with the options carried forward.

    ``scan_options`` is re-published on every update on purpose: a retry reads
    the job row, and a row whose options a later progress write dropped would
    re-run the scan with defaults the caller never asked for.
    """
    names = list(BINARY_STAGES)
    index = names.index(current) if current in names else 0
    complete = len(names) if status == "COMPLETED" else index
    stages = []
    for position, name in enumerate(names):
        if status == "COMPLETED" or position < complete:
            state = "COMPLETED"
        elif status == "FAILED" and position == index:
            state = "FAILED"
        elif position == index:
            state = "RUNNING"
        else:
            state = "PENDING"
        stages.append({"name": name, "index": position + 1, "state": state})
    payload: dict[str, Any] = {
        "current_stage": current,
        "stages_complete": complete,
        "total_stages": len(names),
        "percent": int(round(100 * complete / len(names))),
        "status": status,
        "stages": stages,
        "logs": list(logs or [])[-200:],
        "scan_options": options or {},
    }
    payload.update(extra)
    return payload


def run_binary_job(job) -> bool:
    """Run one binary scan job; returns True on success.

    Fail-closed: an unreadable target, a refused path, a render error, or a
    storage failure marks the job FAILED with the reason. A walk that finds no
    binaries is *not* a failure — it completes, and the result says how many
    files were walked and how many were parsed, so "0 findings" cannot be
    mistaken for "0 files looked at".
    """
    from db.connection.session import SessionLocal
    from db.repositories.job_repository import JobRepository

    session = SessionLocal()
    jobs = JobRepository(session)
    options = scan_options(job)

    def report(stage: str, *, status: str = "RUNNING", **extra: Any) -> None:
        jobs.update_status(job.job_id, status if status == "FAILED" else "RUNNING",
                           progress=_stage(stage, status=status, options=options, **extra))
        session.commit()

    try:
        report("binary_target", note="resolving the scan target")
        artifact = _run(session, job, options, report)
        jobs.update_status(
            job.job_id,
            "COMPLETED",
            progress=_stage("binary_ingest", status="COMPLETED", options=options,
                            artifact_id=artifact["artifact_id"],
                            binary={key: artifact[key] for key in (
                                "artifact_id", "target", "format", "sha256",
                                "binaries_scanned", "files_walked", "findings",
                                "findings_by_severity", "yara_matches", "ruleset_digest",
                                "signed", "cbom_ingested", "note")}
                            | {
                                "report_url": f"/api/v1/devsecops/sbom/{artifact['artifact_id']}/report?fmt=markdown",
                                "download_url": f"/api/v1/devsecops/sbom/{artifact['artifact_id']}/download",
                            }),
        )
        session.commit()
        logger.info("binary_job_done", extra={"job_id": job.job_id,
                                             "artifact_id": artifact["artifact_id"],
                                             "binaries": artifact["binaries_scanned"],
                                             "findings": artifact["findings"]})
        return True
    except Exception as exc:  # noqa: BLE001 — the job's failure is the report
        logger.exception("binary_job_failed", extra={"job_id": job.job_id})
        try:
            session.rollback()
            jobs.update_status(
                job.job_id,
                "FAILED",
                error_message=str(exc)[:500],
                progress=_stage("binary_scan", status="FAILED", options=options,
                                error=f"{type(exc).__name__}: {exc}"[:500],
                                stage_failed="binary_scan"),
            )
            session.commit()
        except Exception:
            session.rollback()
        return False
    finally:
        session.close()


def _run(session, job, options: dict, report: Callable[..., None]) -> dict[str, Any]:
    """Scan, render, store, optionally ingest. Returns the artifact summary."""
    from devsecops import binary_scan as bs
    from devsecops import sbom_scan as sb
    from devsecops.artifact_store import audit_artifact, store_binary_artifact

    resolved = _resolve_target(job.target_repo)
    fmt = str(options.get("format") or "cyclonedx").lower()
    recursive = bool(options.get("recursive", True))
    include_raw = bool(options.get("include_raw", False))
    rule_paths = [str(entry) for entry in (options.get("yara_rules") or []) if str(entry).strip()]
    actor = job.triggered_by or "worker"

    report("binary_scan", note=f"scanning {resolved} with {len(rule_paths)} rule source(s)")
    scan = bs.scan_path(resolved, recursive=recursive, include_raw=include_raw,
                        yara_rules=tuple(rule_paths))
    result = bs.sbom_result(scan)

    report("binary_sbom", note=f"rendering {fmt} SBOM and CBOM",
           binaries_scanned=result.get("binaries_scanned", 0),
           files_walked=result.get("files_walked", 0))
    bom = sb.render_sbom(result, fmt=fmt, created_by=actor)
    cbom = bs.cbom_document(scan, target=str(scan.get("target") or resolved), created_by=actor)

    # the artifact id is the job's own id unless the caller chose one: a retry of
    # this job rewrites this artifact instead of adding a duplicate
    artifact_id = str(options.get("artifact_id") or job.job_id)
    report("binary_store", note=f"storing artifact {artifact_id}", artifact_id=artifact_id)
    stored = store_binary_artifact(
        scan=scan, result=result, bom=bom, cbom=cbom, fmt=fmt, created_by=actor, db=session,
        artifact_id=artifact_id, job_id=job.job_id, feed_supplied=False,
        recursive=recursive, include_raw=include_raw, secret=_signing_secret(session))
    manifest = stored["manifest"]
    audit_artifact(session, actor, artifact_id=stored["artifact_id"], target=manifest["target"],
                   binaries=manifest["binary_count"], findings=len(result.get("findings") or []),
                   sha256=stored["payload_sha256"], job_id=job.job_id)

    ingested: dict[str, Any] = {"ingested": False}
    if options.get("ingest_cbom"):
        report("binary_ingest", note="loading the CBOM into the crypto inventory")
        ingested = _ingest_cbom(session, cbom, job, options, resolved)
    if getattr(job, "system_id", None):
        _stamp_system(session, job, manifest, result)

    findings = result.get("findings") or []
    summary = manifest["binary_summary"]
    return {
        "artifact_id": stored["artifact_id"],
        "target": manifest["target"],
        "format": fmt,
        "sha256": stored["payload_sha256"],
        "binaries_scanned": result.get("binaries_scanned", 0),
        "files_walked": result.get("files_walked", 0),
        "findings": len(findings),
        "findings_by_severity": summary.get("findings_by_severity") or {},
        "yara_matches": (summary.get("yara") or {}).get("matches", 0),
        "ruleset_digest": manifest.get("ruleset_digest"),
        "signed": bool(stored.get("signed")),
        "cbom_ingested": bool(ingested.get("ingested")),
        "note": (ingested.get("error") and f"CBOM not ingested: {ingested['error']}")
                or _empty_scan_note(result),
    }


def _resolve_target(target: str | None) -> str:
    """Validate the path before touching it (fail-closed, same guard as the API)."""
    from api.security.target_validation import TargetValidationError, validate_source_target

    raw = binary_target_path(target)
    try:
        resolved = validate_source_target(raw, label="binary target")
    except TargetValidationError as exc:
        raise PermissionError(f"binary target refused: {exc}") from exc
    if not Path(resolved).exists():
        raise FileNotFoundError(f"target not found: {resolved}")
    return resolved


def _signing_secret(session) -> tuple[str | None, str]:
    """The platform signing order, with this process's SECRET_KEY as last resort.

    A job's artifact must verify against the same key the API signs with, so this
    is the same resolution the endpoint performs — not a worker-local key.
    """
    from devsecops.artifact_store import resolve_signing_secret

    try:
        from api.config.settings import get_settings

        configured = (get_settings().SECRET_KEY or "").strip() or None
    except Exception:  # noqa: BLE001 — settings must never break a scan
        configured = None
    return resolve_signing_secret(session, fallback_secret=configured)


def _ingest_cbom(session, cbom: dict, job, options: dict, resolved: str) -> dict[str, Any]:
    """Load the CBOM into the crypto inventory through the API's ingest path.

    ``ingest_document`` refuses a document it cannot trust; that is a real answer
    about the document, so it is reported next to the artifact (which is already
    stored) rather than failing a scan that succeeded.
    """
    from api.routers.cbom import ingest_document

    system_name = options.get("system_name") or f"binaries:{Path(resolved).name}"
    try:
        loaded = ingest_document(bom=cbom, db=session, system_name=system_name,
                                 owner=job.triggered_by or "worker")
        session.commit()
        return {"ingested": True, "records": loaded.get("imported"),
                "system": (loaded.get("system") or {}).get("name")}
    except Exception as exc:  # noqa: BLE001 — inventory unavailable is reported, never faked
        session.rollback()
        logger.warning("binary_job_cbom_ingest_failed",
                       extra={"job_id": job.job_id, "error": str(exc)})
        return {"ingested": False, "error": str(exc)[:300]}


def _stamp_system(session, job, manifest: dict, result: dict) -> None:
    """Record the scan against the system the job was queued for."""
    try:
        from db.repositories.system_repository import SystemRepository

        SystemRepository(session).stamp_scan(
            job.system_id,
            scan_id=job.job_id,
            status="CURRENT",
            target=manifest["target"],
            component_count=int(manifest.get("component_count") or 0),
            algorithms={row.get("name"): 1 for row in (result.get("libraries") or [])},
        )
        session.commit()
    except Exception as exc:  # noqa: BLE001 — a stamp failure must not lose the artifact
        session.rollback()
        logger.warning("binary_job_stamp_failed",
                       extra={"job_id": job.job_id, "error": str(exc)})


def _empty_scan_note(result: dict) -> str | None:
    """Say so when a scan looked at nothing it could parse."""
    walked = int(result.get("files_walked") or 0)
    scanned = int(result.get("binaries_scanned") or 0)
    if scanned:
        return None
    if not walked:
        return "the target held no files to walk"
    return (f"{walked} files were walked and none was a format the scanner parses; "
            "the findings list what was refused and why")
