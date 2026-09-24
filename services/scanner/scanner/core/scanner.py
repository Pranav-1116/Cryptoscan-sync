"""Static scanner orchestrator — single public API used by CLI and worker."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner.config.scanner_config import ScannerConfig
from scanner.core.file_discovery import FileDiscovery
from scanner.core.language_detector import detect_languages_in_repo
from scanner.core.scan_context import ScanContext
from scanner.git.git_client import GitClient
from scanner.models.raw_finding import GitContext, RawFinding
from scanner.models.scan_result import ScanResult, ScanTarget
from scanner.registry.language_scanners import scan_file

logger = logging.getLogger(__name__)


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
        exclude_dirs = None
        if config is not None:
            exclude_dirs = frozenset(getattr(config, "exclude_dirs", None) or [])
        self.file_discovery = FileDiscovery(
            exclude_dirs=exclude_dirs or None,
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

        for source_file in source_files:
            try:
                file_findings = scan_file(source_file, path)
                if git_ctx:
                    for finding in file_findings:
                        finding.git_context = git_ctx
                findings.extend(file_findings)
            except Exception as exc:
                logger.warning("parse_error", extra={"file": str(source_file), "error": str(exc)})
                parse_errors.append({"file": str(source_file), "error": str(exc)})

        try:
            from scanner.parsers.config_crypto_parser import scan_config_tree

            config_findings = scan_config_tree(path, repo_root=path)
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
        result.statistics.files_scanned = len(source_files)
        result.statistics.files_with_errors = len(parse_errors)
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
