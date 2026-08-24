"""Static scanner orchestrator — single public API used by CLI and worker."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner.config.scanner_config import ScannerConfig
from scanner.core.file_discovery import FileDiscovery
from scanner.git.git_client import GitClient
from scanner.models.raw_finding import RawFinding
from scanner.models.scan_result import ScanResult, ScanStatistics, ScanTarget
from scanner.parsers.java_parser import JavaParser

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

        parser = JavaParser(repo_root=path)
        java_files = list(self.file_discovery.discover(path))
        findings: list[RawFinding] = []
        parse_errors: list[dict] = []

        for java_file in java_files:
            try:
                file_findings = parser.parse_file(java_file)
                if git_meta:
                    from scanner.models.raw_finding import GitContext

                    ctx = GitContext(
                        commit_hash=git_meta.commit_hash,
                        commit_author=git_meta.commit_author,
                        commit_timestamp=git_meta.commit_timestamp,
                        branch=git_meta.branch,
                        repository_url=git_meta.repository_url,
                        commit_message=git_meta.commit_message,
                    )
                    for finding in file_findings:
                        finding.git_context = ctx
                findings.extend(file_findings)
            except Exception as exc:
                logger.warning("parse_error", extra={"file": str(java_file), "error": str(exc)})
                parse_errors.append({"file": str(java_file), "error": str(exc)})

        result = ScanResult(
            scan_id=scan_id,
            scan_start=started.isoformat(),
            scanner_id="static-java-scanner-v0.1",
            scanner_version="0.1.0",
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
        result.statistics.files_scanned = len(java_files)
        result.statistics.files_with_errors = len(parse_errors)
        result.finalize()
        logger.info(
            "scan_completed",
            extra={"scan_id": scan_id, "findings": len(findings), "files": len(java_files)},
        )
        return result


CryptoScanner = Scanner
