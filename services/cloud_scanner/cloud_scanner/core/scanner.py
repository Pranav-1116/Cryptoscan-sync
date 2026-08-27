"""Scan a tree for cloud crypto config (IaC always, live APIs only when enabled)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_scanner.aws.live import live_enabled, scan_aws
from cloud_scanner.azure.live import scan_azure
from cloud_scanner.gcp.live import scan_gcp
from cloud_scanner.iac.arm import looks_like_arm, parse_arm
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
                    continue
                head = _head(path)
                if suffix == ".json" and looks_like_arm(path, head):
                    findings.extend(parse_arm(path))
                    continue
                if suffix in {".yml", ".yaml", ".json"} and (
                    "template" in name
                    or "cloudformation" in name
                    or name.endswith(".cfn.yaml")
                    or '"AWSTemplateFormatVersion"' in head
                ):
                    findings.extend(parse_cloudformation(path))
            findings.extend(parse_kubernetes_tree(root_path))
        if self.live:
            live = self.scan_live(scan_id=scan_id)
            findings.extend(live.get("findings") or [])
        issues = [row for row in findings if row.get("compliance_issue")]
        return {
            "scan_id": scan_id,
            "live": self.live,
            "findings": findings,
            "resources": len(findings),
            "issues": len(issues),
            "providers": sorted({(row.get("metadata") or {}).get("cloud_provider") for row in findings if row.get("metadata")}),
        }

    def scan_live(
        self,
        *,
        providers: list[str] | None = None,
        regions: list[str] | None = None,
        role_arn: str | None = None,
        azure_subscription: str | None = None,
        gcp_project: str | None = None,
        scan_id: str | None = None,
    ) -> dict[str, Any]:
        """Call cloud APIs. Never implied by constructing CloudScanner()."""
        from cloud_scanner.core.reliability import ScanTelemetry

        wanted = {str(item).upper() for item in (providers or ["AWS", "AZURE", "GCP"])}
        findings: list[dict[str, Any]] = []
        telemetry = ScanTelemetry(max_resources=_max_resources())
        if "AWS" in wanted:
            telemetry.providers_attempted.add("AWS")
            try:
                before = telemetry.resources_scanned
                rows = scan_aws(regions=regions, role_arn=role_arn, telemetry=telemetry)
                findings.extend(rows)
                if telemetry.resources_scanned == before:
                    telemetry.record_resources(len(rows))
            except Exception as exc:
                telemetry.record_error("AWS", "provider", "global", exc)
        if "AZURE" in wanted:
            telemetry.providers_attempted.add("AZURE")
            try:
                before = telemetry.resources_scanned
                rows = scan_azure(subscription_id=azure_subscription, telemetry=telemetry)
                findings.extend(rows)
                if telemetry.resources_scanned == before:
                    telemetry.record_resources(len(rows))
            except Exception as exc:
                telemetry.record_error("AZURE", "provider", "global", exc)
        if "GCP" in wanted:
            telemetry.providers_attempted.add("GCP")
            try:
                before = telemetry.resources_scanned
                rows = scan_gcp(project=gcp_project, telemetry=telemetry)
                findings.extend(rows)
                if telemetry.resources_scanned == before:
                    telemetry.record_resources(len(rows))
            except Exception as exc:
                telemetry.record_error("GCP", "provider", "global", exc)
        errors = telemetry.errors
        issues = [row for row in findings if row.get("compliance_issue")]
        seen = sorted(
            {
                str((row.get("metadata") or {}).get("cloud_provider"))
                for row in findings
                if (row.get("metadata") or {}).get("cloud_provider")
            }
        )
        return {
            "scan_id": scan_id,
            "live": True,
            "findings": findings,
            "resources": len(findings),
            "issues": len(issues),
            "providers": seen,
            "errors": errors,
            "live_scan": telemetry.summary(enabled=True),
        }


def _max_resources() -> int:
    import os

    try:
        return max(1, int(os.environ.get("CRYPTOSCAN_CLOUD_MAX_RESOURCES") or 500))
    except ValueError:
        return 500


def _head(path: Path, n: int = 400) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:n]
    except OSError:
        return ""
