"""Optional container / image-root inventory stage."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def _target_relative(value: Any, root: Path) -> Any:
    """Express one path in the TARGET's coordinates, not the worker's staging dir.

    ``ContainerScanner.scan_filesystem`` discovers manifests and binaries by
    walking ``ctx.repo_path`` — the job's staged checkout, whose name carries
    the job id (``data/workspaces/job-<uuid>/repo``). It records what it walked,
    so without this step the job id becomes part of the evidence identity.

    That is not cosmetic. Remediation verification fingerprints a finding as
    ``(file_path, line_number, algorithm)``
    (services/remediation/remediation/verification.py:_fingerprint) and compares
    the rescan against the original scan target-wide: a path that changes on
    every job makes every dependency finding look brand-new, so an honestly
    fixed condition could never read as VERIFIED — it degraded to REGRESSION on
    any target that declares a crypto dependency. Drift and baseline comparison
    inherit the same instability.

    A path that is not under ``root`` is returned unchanged: inventing a
    relative path for something outside the target would be a lie.
    """
    if not isinstance(value, str) or not value:
        return value
    candidate = Path(value)
    bases = [root]
    try:
        bases.append(root.resolve())
    except OSError:
        pass
    candidates = [candidate]
    try:
        candidates.append(candidate.resolve())
    except OSError:
        pass
    for cand in candidates:
        for base in bases:
            try:
                return cand.relative_to(base).as_posix()
            except ValueError:
                continue
    return value


def _rebase_findings(findings: list[dict[str, Any]], root: Path) -> int:
    """Rewrite ``source.file_path`` in place; return how many changed.

    In place on purpose: ``ctx.container_result`` and ``ctx.findings`` share
    these dicts, so the stored container artifact and the evidence records
    cannot disagree about where a finding came from.
    """
    rebased = 0
    for finding in findings:
        source = finding.get("source") if isinstance(finding, dict) else None
        if not isinstance(source, dict):
            continue
        before = source.get("file_path")
        after = _target_relative(before, root)
        if after != before:
            source["file_path"] = after
            rebased += 1
    return rebased


def execute(ctx: PipelineContext) -> PipelineContext:
    root = Path(ctx.repo_path)
    if not root.exists():
        return ctx
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
        return ctx
    try:
        from container_scanner.core.scanner import ContainerScanner
    except Exception:
        logger.debug("container_scanner_unavailable")
        # A manifest or binary IS present, so this is a soft skip of a wanted
        # collector, not "nothing to inventory". Say so on the context: the
        # caller (pipeline runner / multi-scanner stage) turns it into the §4.8
        # optional_stage_failures disclosure instead of a silent COMPLETED.
        ctx.scan_meta = dict(ctx.scan_meta or {})
        ctx.scan_meta["container_scanner_unavailable"] = True
        return ctx
    result = ContainerScanner(live_cve=False).scan_filesystem(root, scan_id=ctx.scan_id)
    ctx.container_result = result
    findings = list(result.get("findings") or [])
    rebased = _rebase_findings(findings, root)
    ctx.findings.extend(findings)
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["container"] = {
        "packages": len(result.get("packages") or []),
        "libraries": len(result.get("libraries") or []),
        "vulnerabilities": len(result.get("vulnerabilities") or []),
        # how many evidence paths were lifted out of the staging directory —
        # disclosed so a silent zero is distinguishable from "nothing to rebase"
        "evidence_paths_rebased": rebased,
    }
    logger.info("stage_container_scan_done", extra=ctx.scan_meta["container"])
    return ctx


class StageContainerScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
