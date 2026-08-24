"""Named pipeline stages used for job progress reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

PIPELINE_STAGES = (
    "clone",
    "scan",
    "evidence",
    "load",
    "normalize",
    "policy",
    "dedup",
    "systems",
    "drift",
    "alert",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_progress(
    *,
    current_stage: str,
    status: str = "RUNNING",
    logs: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    names = list(PIPELINE_STAGES)
    if current_stage in names:
        complete = names.index(current_stage)
        if status in {"COMPLETED", "FAILED"}:
            complete = len(names) if status == "COMPLETED" else complete
    else:
        complete = 0
    stages = []
    for index, name in enumerate(names):
        if status == "COMPLETED":
            state = "COMPLETED"
        elif status == "FAILED" and name == current_stage:
            state = "FAILED"
        elif index < complete:
            state = "COMPLETED"
        elif name == current_stage:
            state = "RUNNING"
        else:
            state = "PENDING"
        stages.append({"name": name, "index": index + 1, "state": state})
    payload: dict[str, Any] = {
        "current_stage": current_stage,
        "stages_complete": complete if status != "COMPLETED" else len(names),
        "total_stages": len(names),
        "percent": int(round(100 * (len(names) if status == "COMPLETED" else complete) / len(names))),
        "status": status,
        "updated_at": utcnow(),
        "stages": stages,
        "logs": list(logs or [])[-200:],
    }
    if extra:
        payload.update(extra)
    return payload


def system_name_from_repo(repo_url: str) -> str:
    raw = (repo_url or "").rstrip("/")
    for prefix in ("local://", "file://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix) :]
    if raw.endswith(".git"):
        raw = raw[:-4]
    if "github.com" in raw:
        raw = raw.split("github.com", 1)[1].lstrip("/:")
    name = raw.split("/")[-1] or "unnamed-system"
    return name or "unnamed-system"
