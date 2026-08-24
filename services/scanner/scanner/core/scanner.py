"""
Production-grade static code scanner orchestrator.
Handles multi-language scanning with error resilience.
"""

import logging
import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime
import uuid

from scanner.models.raw_finding import RawFinding
from scanner.models.scan_result import ScanResult
from scanner.core.file_discovery import FileDiscovery
from scanner.parsers.java_parser import JavaParser
from scanner.git.git_client import GitClient
from scanner.config.scanner_config import ScannerConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """Metadata for a scan session."""
    scan_id: str
    scan_start: datetime
    repo_path: str
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    target_url: Optional[str] = None


class Scanner:
    """
    Main scanner orchestrator.
    
    Responsibilities:
    - Coordinate file discovery
    - Delegate to language-specific parsers
    - Aggregate findings
    - Handle errors gracefully
    """
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.file_discovery = FileDiscovery(config)
        self.java_parser = JavaParser(config)
        self.git_client = GitClient()
        self.logger = logger
    
    def scan(self, repo_path: str, target_url: Optional[str] = None) -> ScanResult:
        """
        Execute full scan on a repository.
        
        Args:
            repo_path: Local path to repository
            target_url: Optional Git repo URL for context
            
        Returns:
            ScanResult with findings, metadata, and statistics
        """
        scan_id = str(uuid.uuid4())
        scan_start = datetime.utcnow()
        
        context = ScanContext(
            scan_id=scan_id,
            scan_start=scan_start,
            repo_path=repo_path,
            target_url=target_url
        )
        
        try:
            # Extract Git metadata if applicable
            git_context = self._extract_git_context(repo_path)
            if git_context:
                context.commit_hash = git_context.get("commit_hash")
                context.branch = git_context.get("branch")
            
            # Discover files
            self.logger.info(f"[{scan_id}] Starting file discovery in {repo_path}")
            java_files = self.file_discovery.discover_java_files(repo_path)
            self.logger.info(f"[{scan_id}] Found {len(java_files)} Java files")
            
            if not java_files:
                self.logger.warning(f"[{scan_id}] No Java files found")
                return self._create_empty_result(context)
            
            # Parse Java files
            findings = []
            parse_errors = []
            
            for java_file in java_files:
                try:
                    self.logger.debug(f"[{scan_id}] Parsing {java_file}")
                    file_findings = self.java_parser.parse(
                        java_file,
                        repo_path,
                        git_context or {}
                    )
                    findings.extend(file_findings)
                    self.logger.debug(f"[{scan_id}] Found {len(file_findings)} findings in {java_file}")
                except Exception as e:
                    self.logger.warning(f"[{scan_id}] Parse error in {java_file}: {str(e)}")
                    parse_errors.append({
                        "file": java_file,
                        "error": str(e)
                    })
            
            scan_end = datetime.utcnow()
            
            result = ScanResult(
                scan_id=scan_id,
                scan_start=scan_start,
                scan_end=scan_end,
                scanner_id="static-java-scanner-v0.1",
                scanner_version="0.1.0",
                target_type="LOCAL_DIR" if not target_url else "GIT_REPOSITORY",
                target_location=target_url or repo_path,
                target_commit=context.commit_hash,
                target_branch=context.branch,
                findings=findings,
                statistics={
                    "files_scanned": len(java_files),
                    "files_with_findings": len(set(f.source.file_path for f in findings)),
                    "total_findings": len(findings),
                    "high_confidence": len([f for f in findings if f.metadata.confidence == "HIGH"]),
                    "medium_confidence": len([f for f in findings if f.metadata.confidence == "MEDIUM"]),
                    "low_confidence": len([f for f in findings if f.metadata.confidence == "LOW"]),
                    "parse_errors": len(parse_errors)
                },
                parse_errors=parse_errors if parse_errors else None,
                status="COMPLETED"
            )
            
            self.logger.info(
                f"[{scan_id}] Scan completed: {len(findings)} findings, "
                f"duration: {(scan_end - scan_start).total_seconds():.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"[{scan_id}] Scan failed: {str(e)}", exc_info=True)
            return ScanResult(
                scan_id=scan_id,
                scan_start=scan_start,
                scan_end=datetime.utcnow(),
                scanner_id="static-java-scanner-v0.1",
                scanner_version="0.1.0",
                target_type="LOCAL_DIR" if not target_url else "GIT_REPOSITORY",
                target_location=target_url or repo_path,
                findings=[],
                statistics={},
                status="FAILED",
                error_message=str(e)
            )
    
    def _extract_git_context(self, repo_path: str) -> Optional[dict]:
        """Extract Git metadata if this is a Git repository."""
        try:
            return self.git_client.extract_context(repo_path)
        except Exception as e:
            self.logger.debug(f"Could not extract Git context: {str(e)}")
            return None
    
    def _create_empty_result(self, context: ScanContext) -> ScanResult:
        """Create empty scan result."""
        return ScanResult(
            scan_id=context.scan_id,
            scan_start=context.scan_start,
            scan_end=datetime.utcnow(),
            scanner_id="static-java-scanner-v0.1",
            scanner_version="0.1.0",
            target_type="LOCAL_DIR",
            target_location=context.repo_path,
            findings=[],
            statistics={
                "files_scanned": 0,
                "files_with_findings": 0,
                "total_findings": 0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0,
            },
            status="COMPLETED"
        )