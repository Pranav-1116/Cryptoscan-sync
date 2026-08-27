"""One org, one scan: enumerate -> fan out -> roll up.

Used by the worker's org job (cloud://aws-org/<mgmt-id> style targets).
Each discovered account is scanned with the existing CloudScanner live
path (cross-account role / subscription / project), on the bounded pool,
and everything lands in one org-level result with per-account telemetry.
"""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.core.reliability import ScanTelemetry
from cloud_scanner.org.enumerators import enumerate_org
from cloud_scanner.org.pool import scan_accounts_parallel

_ACCOUNT_KEY = {"aws": "role_arn", "azure": "subscription_id", "gcp": "project_id"}


def scan_org(
    provider: str,
    *,
    session: Any = None,
    credential: Any = None,
    client: Any = None,
    role_name: str | None = None,
    folder: str | None = None,
    organization: str | None = None,
    regions: list[str] | None = None,
    max_accounts: int | None = None,
    max_workers: int | None = None,
    telemetry: ScanTelemetry | None = None,
) -> dict[str, Any]:
    """Enumerate an org and scan every discovered account in parallel."""
    telemetry = telemetry or ScanTelemetry()
    base = str(provider).lower().replace("-org", "")
    discovery = enumerate_org(
        base,
        session=session,
        credential=credential,
        client=client,
        role_name=role_name,
        folder=folder,
        organization=organization,
        telemetry=telemetry,
        max_accounts=max_accounts,
    )
    accounts = discovery.get("accounts") or []

    def _scan_account(account: dict[str, Any]) -> dict[str, Any]:
        from cloud_scanner.core.scanner import CloudScanner

        kwargs: dict[str, Any] = {"providers": [base.upper()], "regions": regions}
        if base == "aws":
            kwargs["role_arn"] = account.get("role_arn")
        elif base == "azure":
            kwargs["azure_subscription"] = account.get("subscription_id") or account.get("account_id")
        elif base == "gcp":
            kwargs["gcp_project"] = account.get("project_id") or account.get("account_id")
        result = CloudScanner(live=False).scan_live(**kwargs)
        # stamp the account on every finding so estate ingest can group
        for finding in result.get("findings") or []:
            metadata = finding.setdefault("metadata", {}) if isinstance(finding, dict) else None
            if isinstance(metadata, dict):
                metadata["cloud_account"] = str(account.get("account_id") or "")
                extra = finding.get("extra") if isinstance(finding, dict) else None
                if isinstance(extra, dict) and not extra.get("account"):
                    extra["account"] = str(account.get("account_id") or "")
        return result

    fanout = scan_accounts_parallel(_scan_account, accounts, max_workers=max_workers)
    rollup = fanout["rollup"]

    findings: list[dict[str, Any]] = []
    account_rows: list[dict[str, Any]] = []
    for row in fanout["results"]:
        findings.extend(row.get("findings") or [])
        account_rows.append(
            {
                "account_id": row.get("account"),
                "ok": bool(row.get("ok")),
                "resources": row.get("resources") or 0,
                "status": (row.get("live_scan") or {}).get("status") or ("FAILED" if not row.get("ok") else "SKIPPED"),
                "error": row.get("error"),
            }
        )

    discovery_truncations = [
        {"provider": base, "service": "org-discovery", "region": "global", "cap": str(max_accounts or os.environ.get("CRYPTOSCAN_CLOUD_ORG_MAX_ACCOUNTS") or 200)}
    ] if discovery.get("truncated") else []

    live_scan = {
        "enabled": True,
        "status": rollup["status"],
        "resources_scanned": rollup["resources_scanned"],
        "errors": rollup["errors"],
        "truncations": discovery_truncations,
        "error_count": rollup["error_count"],
        "truncation_count": len(discovery_truncations),
    }
    for row in account_rows:
        telemetry.resources_scanned += int(row.get("resources") or 0)

    return {
        "provider": base,
        "org": True,
        "accounts_discovered": len(accounts),
        "truncated": bool(discovery.get("truncated")),
        "accounts": account_rows,
        "findings": findings,
        "resources": len(findings),
        "issues": sum(1 for row in findings if row.get("compliance_issue")),
        "errors": telemetry.errors,
        "live_scan": live_scan,
    }
