"""One job, described the same way to REST, GraphQL and the WebSocket stream.

Three surfaces now report a running scan: ``GET /jobs/{id}``, the GraphQL ``job``
fields, and the WebSocket progress stream. If each shaped the row itself they
would drift, and an operator comparing a stream frame with a status page would
have to work out which one was lying. So the shaping lives here, once, and every
surface calls it.

The card keeps the *stored* vocabulary — camelCase keys, the same names the
GraphQL schema and the socket frames use, so a field renamed here is renamed in
every client at once. Stage names come from the pipeline
(``binary_target`` → … → ``binary_ingest``), the status is the job's own
(``QUEUED``/``RUNNING``/``COMPLETED``/``FAILED``), and ``percent`` is the pipeline's
own arithmetic. Nothing here invents a friendlier synonym for a state.
"""

from __future__ import annotations

from typing import Any

#: terminal job states — a stream can close on these
TERMINAL_STATES = ("COMPLETED", "FAILED", "CANCELLED")


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def job_card(job: Any) -> dict[str, Any]:
    """One job row as a plain dictionary every surface can serialise.

    Binary jobs carry their scan options and their result summary on ``progress``;
    both are passed through, because the batch lookup, the report URL and the
    artifact id all live there and a caller should not have to re-derive them.
    """
    progress = getattr(job, "progress", None)
    if not isinstance(progress, dict):
        progress = {}
    options = progress.get("scan_options") or {}
    binary = progress.get("binary") or {}
    artifact_id = binary.get("artifact_id") or options.get("artifact_id")
    job_id = str(getattr(job, "job_id", None) or getattr(job, "id", "") or "")
    status = str(getattr(job, "status", "") or "")
    return {
        "jobId": job_id,
        "jobType": getattr(job, "job_type", None),
        "status": status,
        "terminal": status.upper() in TERMINAL_STATES,
        "target": options.get("target") or getattr(job, "target_repo", None),
        "stage": binary.get("stage") or progress.get("current_stage"),
        "percent": progress.get("percent"),
        "stagesComplete": progress.get("stages_complete"),
        "totalStages": progress.get("total_stages"),
        "stages": progress.get("stages") or [],
        "batchId": options.get("batch_id"),
        "artifactId": str(artifact_id) if artifact_id else None,
        "reportUrl": binary.get("report_url") or (
            f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown" if artifact_id else None),
        "downloadUrl": binary.get("download_url") or (
            f"/api/v1/devsecops/sbom/{artifact_id}/download" if artifact_id else None),
        "error": getattr(job, "error_message", None),
        "createdAt": _iso(getattr(job, "created_at", None)),
        "startedAt": _iso(getattr(job, "started_at", None)),
        "completedAt": _iso(getattr(job, "completed_at", None)),
        "binary": binary or None,
        "scanOptions": options or None,
    }


def job_snapshot(session: Any, job_id: str) -> dict[str, Any] | None:
    """Read one job by id and describe it. ``None`` when there is no such job."""
    if session is None:
        raise ValueError("a database session is required to read a job")
    from db.repositories.job_repository import JobRepository

    repo = JobRepository(session)
    job = repo.get_by_id(job_id)
    if job is None:
        return None
    return job_card(job)


def changed(before: dict[str, Any] | None, after: dict[str, Any]) -> bool:
    """Whether a stream should send this frame: anything that moved, plus first sight."""
    if before is None:
        return True
    keys = ("status", "stage", "percent", "stagesComplete", "artifactId", "error",
            "completedAt")
    return any(before.get(key) != after.get(key) for key in keys)
