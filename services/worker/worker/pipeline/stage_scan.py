"""Pipeline stage: static multi-language scan."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def _exclude_tests() -> bool:
    """Test code is scanned by default and tagged ``code_origin=test`` (test keystores and
    hard-coded fixture keys are inventory). Set CRYPTOSCAN_EXCLUDE_TESTS=1 to skip it."""
    import os

    return os.environ.get("CRYPTOSCAN_EXCLUDE_TESTS", "0").lower() in ("1", "true", "yes")


def execute(ctx: PipelineContext) -> PipelineContext:
    from scanner.core.scanner import Scanner
    from worker.pipeline.stage_language_detect import execute as detect_languages

    detect_languages(ctx)
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
    ctx.scan_meta = {
        **dict(ctx.scan_meta or {}),
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
    output = Path(ctx.workspace_dir) / f"scan-results-{ctx.job_id}.json"
    try:
        output.write_text(__import__("json").dumps({"findings": findings, **ctx.scan_meta}, indent=2), encoding="utf-8")
        ctx.scan_meta["scan_results_file"] = str(output)
    except OSError:
        pass
    try:
        from scanner.core.plugin import observations_from_findings

        ctx.scan_meta["observations"] = observations_from_findings(findings, scan_id=ctx.scan_id)
        ctx.scan_meta["observation_count"] = len(ctx.scan_meta["observations"])
    except Exception:
        ctx.scan_meta["observation_count"] = len(findings)
    logger.info("stage_scan_done", extra={"findings": len(ctx.findings)})
    return ctx


class StageScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)


def _evidence_sources(findings: list) -> dict[str, int]:
    """Findings per evidence source type (SOURCE_CODE / RUNTIME_LOG / KEY_INVENTORY / …) — lets the API and UI
    tell a code scan from a log-drop or key-export scan without opening every finding."""
    out: dict[str, int] = {}
    for f in findings:
        t = ((f.get("source") or {}).get("type") if isinstance(f, dict) else None) or "UNKNOWN"
        out[t] = out.get(t, 0) + 1
    return out


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
