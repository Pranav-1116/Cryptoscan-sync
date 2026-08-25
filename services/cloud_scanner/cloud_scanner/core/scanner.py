"""Scan a tree for cloud crypto config (IaC always, live APIs only when enabled)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_scanner.aws.live import live_enabled, scan_aws
from cloud_scanner.iac.cloudformation import parse_cloudformation
from cloud_scanner.iac.kubernetes import parse_kubernetes_tree
from cloud_scanner.iac.terraform import parse_terraform
from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS


class CloudScanner:
    def __init__(self, *, live: bool | None = None):
        self.live = live_enabled(live)

    def scan_filesystem(self, root: str | Path, *, scan_id: str | None = None) -> dict[str, Any]:
        root_path = Path(root)
        findings: list[dict[str, Any]] = []
        if root_path.exists():
            for path in root_path.rglob("*"):
                if not path.is_file():
                    continue
                if any(part in DEFAULT_EXCLUDED_DIRS or part.startswith(".") for part in path.parts):
                    continue
                suffix = path.suffix.lower()
                name = path.name.lower()
                if suffix == ".tf" or name.endswith(".tf.json"):
                    findings.extend(parse_terraform(path))
                elif suffix in {".yml", ".yaml", ".json"} and (
                    "template" in name or "cloudformation" in name or name.endswith(".cfn.yaml") or '"AWSTemplateFormatVersion"' in _head(path)
                ):
                    findings.extend(parse_cloudformation(path))
            findings.extend(parse_kubernetes_tree(root_path))
        if self.live:
            findings.extend(scan_aws())
        issues = [row for row in findings if row.get("compliance_issue")]
        return {
            "scan_id": scan_id,
            "live": self.live,
            "findings": findings,
            "resources": len(findings),
            "issues": len(issues),
            "providers": sorted({(row.get("metadata") or {}).get("cloud_provider") for row in findings if row.get("metadata")}),
        }


def _head(path: Path, n: int = 400) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:n]
    except OSError:
        return ""
