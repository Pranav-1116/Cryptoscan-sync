"""Live scanner adapters for the monitor — one per target type.

Each runner uses the same live scanning code as the manual/API flows. What a
runner needs but does not have (credentials, files, a registry) is returned as
``blocked_reason`` so the target shows BLOCKED with the exact fix, instead of
pretending to have scanned.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ network

def network_runner(config: dict, session: Any) -> dict:
    """Live TLS probe of a set of endpoints — needs nothing but reachability."""
    endpoints = [str(e) for e in (config.get("endpoints") or []) if str(e).strip()]
    if not endpoints and config.get("endpoint"):
        endpoints = [str(config["endpoint"])]
    if not endpoints:
        return {"blocked_reason": "no endpoints configured (set config.endpoints = ['host:port', …])"}

    from network_scanner.core.scanner import NetworkTlsScanner

    timeout = float(config.get("timeout", 5.0))
    result = NetworkTlsScanner(live=True, timeout=timeout).scan_hosts(endpoints)
    issues: list[str] = []
    ok = unreachable = 0
    for finding in result.get("findings") or []:
        endpoint = finding.get("endpoint") or "?"
        if finding.get("status") != "OK":
            unreachable += 1
            issues.append(f"UNREACHABLE:{endpoint}:{finding.get('status')}")
            continue
        ok += 1
        for issue in finding.get("policy_issues") or []:
            issues.append(f"{issue}:{endpoint}")
        crypto = finding.get("crypto") or {}
        if str(crypto.get("tls_version") or "") in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
            issues.append(f"WEAK_TLS_VERSION:{endpoint}")

    # certificates feed the shared inventory, exactly like POST /network-scans
    _persist_certificates(result, session)

    summary = {
        "endpoints": len(endpoints),
        "probed_ok": ok,
        "unreachable": unreachable,
        "issues": sorted(set(issues)),
    }
    return {"summary": summary, "degraded": bool(issues), "issues": sorted(set(issues))}


def _persist_certificates(result: dict, session: Any) -> None:
    try:
        from db.repositories.certificate_repository import CertificateRepository
        from db.repositories.maturity_repository import MaturityRepository

        certs = CertificateRepository(session)
        usages = MaturityRepository(session)
        for cert in result.get("certificates") or []:
            if cert.get("fingerprint_sha256"):
                certs.upsert(cert)
        for usage in result.get("usages") or []:
            if usage.get("fingerprint_sha256") and usage.get("location"):
                usages.upsert_usage(
                    usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN"
                )
    except Exception:
        logger.debug("monitor_cert_persist_skipped", exc_info=True)  # scanning still succeeded


# --------------------------------------------------------------------- cloud

def cloud_runner(config: dict, session: Any) -> dict:
    """Live cloud crypto inventory via CloudScanner.scan_live (bring-your-own-creds)."""
    provider = str(config.get("provider") or "").lower()
    identifier = str(config.get("account") or config.get("identifier") or "")
    if provider not in {"aws", "azure", "gcp"} or not identifier:
        return {
            "blocked_reason": (
                "config needs provider ('aws'|'azure'|'gcp') and account identifier "
                "(e.g. {'provider': 'aws', 'account': '123456789012', 'role_arn': …})"
            )
        }

    role_arn = config.get("role_arn")
    regions = config.get("regions")
    from cloud_scanner.core.scanner import CloudScanner

    result = CloudScanner(live=True).scan_live(
        providers=[provider.upper()],
        regions=regions,
        role_arn=role_arn,
        azure_subscription=identifier if provider == "azure" else None,
        gcp_project=identifier if provider == "gcp" else None,
    )
    live_scan = result.get("live_scan") or {}
    if live_scan.get("status") == "FAILED":
        # credentials missing/expired or every API call errored — honest failure
        errors = live_scan.get("errors") or [{}]
        first = errors[0]
        raise RuntimeError(
            f"live cloud scan failed ({live_scan.get('error_count', len(errors))} errors; "
            f"{first.get('provider', '?')}/{first.get('service', '?')}: {str(first.get('error', ''))[:160]})"
        )
    findings = result.get("findings") or []
    issues = sorted({str(f.get("compliance_issue") or f.get("issue") or "") for f in findings} - {""})
    summary = {
        "resources": int(live_scan.get("resource_count") or live_scan.get("resources") or len(findings)),
        "findings": len(findings),
        "issues": issues,
    }
    return {"summary": summary, "degraded": bool(issues), "issues": issues}


# ---------------------------------------------------------------- repository

def repo_runner(config: dict, session: Any) -> dict:
    """Source scans run through the standard job pipeline — the monitor enqueues."""
    target = str(config.get("repo") or config.get("url") or "").strip()
    if not target:
        return {"blocked_reason": "config needs repo URL (e.g. {'repo': 'https://github.com/org/x.git'})"}
    from datetime import datetime, timezone

    from db.repositories.job_repository import JobRepository
    from worker.core.job_consumer import enqueue_job

    branch = str(config.get("branch") or "main")
    job = JobRepository(session).create_job(
        job_type="MANUAL", target_repo=target, target_branch=branch, triggered_by="monitor"
    )
    payload = {
        "job_id": job.job_id,
        "job_type": "MANUAL",
        "target_repo": target,
        "target_branch": branch,
        "triggered_by": "monitor",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        enqueue_job(payload)  # Redis when configured; otherwise in-process memory queue
        queued_via = "redis-or-memory"
    except Exception:
        queued_via = "db-only (job row QUEUED; start the worker to drain)"
    return {
        "summary": {"job_id": job.job_id, "queued_via": queued_via, "issues": []},
        "degraded": False,
        "issues": [],
    }


# ----------------------------------------------------------------- container

def container_runner(config: dict, session: Any) -> dict:
    """Container image scan via the container scanner (registry/local reference)."""
    reference = str(config.get("image") or config.get("reference") or "").strip()
    if not reference:
        return {"blocked_reason": "config needs image reference (e.g. {'image': 'registry/app:tag'})"}
    from container_scanner.core.scanner import ContainerScanner

    result = ContainerScanner().scan_image(reference)
    libraries = result.get("libraries") or []
    vulnerabilities = result.get("vulnerabilities") or []
    issues = sorted({f"CVE:{v.get('id', v.get('cve', '?'))}" for v in vulnerabilities})
    for library in libraries:
        if str(library.get("risk") or "").upper() in {"HIGH", "CRITICAL"}:
            issues.append(f"LIBRARY_RISK:{library.get('name', '?')}")
    summary = {
        "libraries": len(libraries),
        "vulnerabilities": len(vulnerabilities),
        "secrets": len(result.get("secrets") or []),
        "issues": sorted(set(issues)),
    }
    return {"summary": summary, "degraded": bool(issues), "issues": sorted(set(issues))}
