"""Static scanner orchestrator — single public API used by CLI and worker."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from scanner.config.scanner_config import ScannerConfig
from scanner.core.file_discovery import FileDiscovery
from scanner.core.language_detector import detect_languages_in_repo
from scanner.core.scan_context import ScanContext
from scanner.git.git_client import GitClient
from scanner.models.raw_finding import GitContext, RawFinding
from scanner.models.scan_result import ScanResult, ScanTarget
from scanner.core.constant_index import ConstantIndex

_CASCADE_SKIP_DIRS = {"node_modules", ".git", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}
from scanner.registry.language_scanners import scan_file

logger = logging.getLogger(__name__)


def _scan_one(args: tuple[Path, Path]) -> tuple[Path, list[RawFinding], Optional[str]]:
    source_file, root = args
    from scanner.core.sandbox import per_file_timeout

    try:
        # §4.1: one hostile file gets a bounded wall-clock budget — a runaway
        # detector fails THIS file (recorded as a parse error), not the scan
        with per_file_timeout():
            return source_file, scan_file(source_file, root), None
    except Exception as exc:  # noqa: BLE001 — one bad file must not sink the scan
        # always name the exception type — str(MemoryError()) is empty, and
        # an anonymous parse error is useless diagnostics (and would hide a
        # sandbox refusal as a blank string)
        return source_file, [], (type(exc).__name__ + (f": {exc}" if str(exc) else ""))


def scan_processes() -> int:
    """Per-file parallelism. ``CRYPTOSCAN_SCAN_PROCESSES`` = N | auto (cpu count); default 1.

    The parsers are regex/CPU bound, so threads do not help (GIL); processes do. One
    scan job then uses N cores; the worker pool's ``max_workers`` stays the number of
    concurrent *jobs*. Set both from the same core budget.
    """
    raw = (os.environ.get("CRYPTOSCAN_SCAN_PROCESSES") or "1").strip().lower()
    if raw == "auto":
        return max(1, os.cpu_count() or 1)
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def _scan_files(source_files: list[Path], root: Path) -> Iterator[tuple[Path, list[RawFinding], Optional[str]]]:
    n = scan_processes()
    if n <= 1 or len(source_files) < 64:
        for f in source_files:
            yield _scan_one((f, root))
        return
    import multiprocessing as mp

    # §4.1 hostile-input bounds: pool children run under rlimits (CPU /
    # address space / file size, env-tunable) so a hostile file fails itself
    # instead of consuming unbounded worker resources. Process-level bounds,
    # not a container — see scanner/core/sandbox.py for the honest scope.
    from scanner.core.sandbox import apply_child_limits

    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    chunk = max(8, len(source_files) // (n * 16))
    with ctx.Pool(processes=n, initializer=apply_child_limits) as pool:
        for item in pool.imap_unordered(_scan_one, [(f, root) for f in source_files], chunksize=chunk):
            yield item


class Scanner:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        exclude_test_dirs: bool = False,
        **kwargs,
    ):
        if config is None:
            try:
                config = ScannerConfig()
            except Exception:
                config = None
        self.config = config
        self.exclude_test_dirs = exclude_test_dirs or kwargs.get("exclude_test_dirs", False)
        # Config directories are *added* to the discovery defaults (never replace them —
        # an env override of SCANNER_EXCLUDE_DIRS must not re-enable node_modules/.git).
        from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS

        extra = frozenset(getattr(config, "exclude_dirs", None) or []) if config is not None else frozenset()
        self.file_discovery = FileDiscovery(
            exclude_dirs=DEFAULT_EXCLUDED_DIRS | extra,
            exclude_test_dirs=self.exclude_test_dirs,
        )
        self.git_client = GitClient()

    def scan(
        self,
        root_path: str | Path | None = None,
        repo_path: str | Path | None = None,
        *,
        scan_id: Optional[str] = None,
        target_type: str = "LOCAL_DIRECTORY",
        target_location: Optional[str] = None,
        target_commit: Optional[str] = None,
        target_branch: Optional[str] = None,
        target_url: Optional[str] = None,
        **kwargs,
    ) -> ScanResult:
        path = Path(root_path or repo_path or kwargs.get("source_dir") or ".")
        scan_id = scan_id or str(uuid.uuid4())
        started = datetime.now(timezone.utc)
        location = target_location or target_url or str(path)

        git_meta = None
        try:
            git_meta = self.git_client.get_metadata(path, location)
            target_commit = target_commit or git_meta.commit_hash
            target_branch = target_branch or git_meta.branch
        except Exception:
            git_meta = None

        languages = detect_languages_in_repo(path)
        _context = ScanContext(
            root_path=path,
            scan_id=scan_id,
            target_type=target_type,
            target_location=location,
            target_commit=target_commit,
            target_branch=target_branch,
            languages=languages,
            exclude_test_dirs=self.exclude_test_dirs,
        )
        source_files = list(self.file_discovery.discover(path))
        findings: list[RawFinding] = []
        parse_errors: list[dict] = []
        scanned_paths: set[Path] = set()

        git_ctx = None
        if git_meta:
            git_ctx = GitContext(
                commit_hash=git_meta.commit_hash,
                commit_author=git_meta.commit_author,
                commit_timestamp=git_meta.commit_timestamp,
                branch=git_meta.branch,
                repository_url=git_meta.repository_url,
                commit_message=git_meta.commit_message,
            )

        from scanner.core.file_receipts import capture, finish
        byte_identity_before = capture(path, source_files)
        constant_index = ConstantIndex.build(source_files)

        for source_file, file_findings, error in _scan_files(source_files, path):
            if error is not None:
                logger.warning("parse_error", extra={"file": str(source_file), "error": error})
                parse_errors.append({"file": str(source_file), "error": error})
                continue
            scanned_paths.add(source_file)
            if git_ctx:
                for finding in file_findings:
                    finding.git_context = git_ctx
            findings.extend(file_findings)

        # Second hop: algorithm strings declared in another file (constants classes).
        resolved_cross_file = constant_index.resolve(findings)

        try:
            from scanner.parsers.config_crypto_parser import scan_config_tree

            # The tree pass is a fallback for config paths discovery missed; files already
            # dispatched by scan_file (including named configs and AT-TLS) must not be parsed twice.
            config_findings = scan_config_tree(path, repo_root=path, skip_paths=scanned_paths)
            if git_ctx:
                for finding in config_findings:
                    finding.git_context = git_ctx
            findings.extend(config_findings)
        except Exception as exc:
            logger.warning("config_scan_failed", extra={"error": str(exc)})

        try:
            from scanner.detectors.materials.pem_scanner import scan_materials

            material_findings = scan_materials(path, repo_root=path)
            if git_ctx:
                for finding in material_findings:
                    finding.git_context = git_ctx
            findings.extend(material_findings)
        except Exception as exc:
            logger.warning("material_scan_failed", extra={"error": str(exc)})

        # JAR/WAR/EAR and .NET assemblies are archive "source files": FileDiscovery lists them and
        # scan_file() dispatches to the bytecode scanners, so no separate rglob pass (it used to
        # produce every archive finding twice).

        # Third hop: dependency & cascade analysis — who imports the crypto, which libraries carry it,
        # which key material is shared, which parameters are below the registry floor, migration order.
        cascade = None
        if os.environ.get("CRYPTOSCAN_CASCADE", "1") != "0":
            try:
                from scanner.analysis.cascade import analyse_cascade, is_manifest

                manifests = [
                    p
                    for p in path.rglob("*")
                    if p.is_file()
                    and is_manifest(p)
                    and not any(part in _CASCADE_SKIP_DIRS for part in p.relative_to(path).parts)
                ]
                cascade = analyse_cascade(findings, source_files + manifests, path)
            except Exception as exc:
                logger.warning("cascade_analysis_failed", extra={"error": str(exc)})

        # Raw snippets are needed by detectors and the import cascade, but no
        # source text may leave the scanner in a finding or CLI/worker output.
        from shared_models.safe_finding import safe_finding

        public_findings = []
        for finding in findings:
            data = finding.model_dump(mode="json")
            # The transient transformation can identify a safe digest family,
            # but the original string itself must never leave the scanner.
            data["crypto"]["raw_transformation"] = finding.crypto.raw_transformation
            public_findings.append(RawFinding.model_validate(safe_finding(data)))
        findings = public_findings
        scanner_id = "static-multi-scanner-v1.0" if set(languages) - {"JAVA"} else "static-java-scanner-v0.1"
        scanner_version = "1.0.0" if scanner_id.endswith("v1.0") else "0.1.0"
        result = ScanResult(
            scan_id=scan_id,
            scan_start=started.isoformat(),
            scanner_id=scanner_id,
            scanner_version=scanner_version,
            scan_target=ScanTarget(
                type=target_type,
                location=location,
                commit=target_commit,
                branch=target_branch,
            ),
            findings=findings,
            parse_errors=parse_errors,
            status="COMPLETED",
        )
        result.statistics.file_observation_receipts = finish(path, source_files, byte_identity_before, scanned_paths)
        result.statistics.file_receipts_complete = len(result.statistics.file_observation_receipts) == len(source_files)
        result.statistics.files_scanned = len(source_files)
        result.statistics.files_with_errors = len(parse_errors)
        result.statistics.resolved_cross_file = resolved_cross_file
        if cascade is not None:
            result.cascade = cascade.model_dump()
            result.statistics.cascade_providers = cascade.summary["providers"]
            result.statistics.cascade_shared_keys = cascade.summary["shared_key_identifiers"]
            result.statistics.cascade_weak_parameters = cascade.summary["weak_parameters"]
        result.finalize()
        logger.info(
            "scan_completed",
            extra={
                "scan_id": scan_id,
                "findings": len(findings),
                "files": len(source_files),
                "languages": languages,
            },
        )
        return result


CryptoScanner = Scanner
MultiLanguageScanner = Scanner
