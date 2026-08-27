"""Turn cloud / IaC findings into estate systems.

A bank does not get a CBOM from registering an AWS account. Live APIs or
IaC must be scanned; each cryptographic resource becomes a system (or
attaches to one) and is stamped CURRENT only after that scan.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any
from urllib.parse import urlparse

CLOUD_SCHEMES = frozenset({"cloud", "aws", "azure", "gcp"})
GIT_PREFIXES = ("http://", "https://", "git@", "ssh://", "local://", "file://", "/")
def _resource_cap() -> int:
    import os

    try:
        return max(1, int(os.environ.get("CRYPTOSCAN_CLOUD_MAX_ESTATE") or RESOURCE_CAP))
    except ValueError:
        return RESOURCE_CAP


RESOURCE_CAP = 2000
CAMPAIGN_LOOKAHEAD = 2000


def is_cloud_target(target: str | None) -> bool:
    text = str(target or "").strip().lower()
    if not text:
        return False
    if text.startswith(("aws://", "azure://", "gcp://", "cloud://")):
        return True
    if text.startswith(GIT_PREFIXES):
        return False
    scheme = urlparse(text).scheme or (text.split(":", 1)[0] if ":" in text else "")
    return scheme in CLOUD_SCHEMES


def job_type_for_target(target: str | None) -> str:
    return "CLOUD" if is_cloud_target(target) else "SYSTEM"


def should_run_cloud_job(job: Any) -> bool:
    if isinstance(job, dict):
        job_type = str(job.get("job_type") or "")
        target = job.get("target_repo") or job.get("repo_url")
    else:
        job_type = str(getattr(job, "job_type", "") or "")
        target = getattr(job, "target_repo", None)
    return job_type.upper() == "CLOUD" or is_cloud_target(target)


def parse_cloud_target(target: str | None) -> tuple[str, str | None]:
    text = str(target or "").strip()
    if text.startswith("cloud://"):
        rest = text[len("cloud://") :]
        scheme = "cloud"
    elif "://" in text:
        scheme, rest = text.split("://", 1)
    else:
        scheme, rest = "cloud", text
    parts = [part for part in rest.split("/") if part]
    scheme_l = scheme.lower()
    if scheme_l in {"aws", "azure", "gcp"}:
        return scheme_l, parts[0] if parts else None
    if parts and parts[0].lower() in {"aws", "azure", "gcp"}:
        provider = parts[0].lower()
        return provider, parts[1] if len(parts) > 1 else None
    return "aws", parts[0] if parts else None


def cloud_group_key(target: str | None) -> str:
    provider, _account = parse_cloud_target(target)
    return provider


def campaign_group_key(system: Any) -> tuple[str, str]:
    target = _attr(system, "scan_target")
    provider, account = parse_cloud_target(target)
    tagged = _attr(system, "cloud_account") or account or ""
    tagged_provider = str(_attr(system, "cloud_provider") or provider or "aws").lower()
    return tagged_provider, str(tagged)


def plan_campaign(
    systems: list[Any],
    *,
    limit: int = 25,
    include_git: bool = True,
    include_cloud: bool = True,
    providers: list[str] | None = None,
) -> list[dict[str, Any]]:
    """One CLOUD job per cloud account, plus one SYSTEM job per git target.

    Never enqueue a job per KMS key / vault / bucket.
    """
    cap = max(1, min(int(limit or 25), 100))
    allow = {str(item).lower() for item in (providers or []) if item}
    git_jobs: list[dict[str, Any]] = []
    cloud_groups: dict[tuple[str, str], dict[str, Any]] = {}
    for system in systems:
        target = str(_attr(system, "scan_target") or "").strip()
        if not target:
            continue
        if is_cloud_target(target):
            if not include_cloud:
                continue
            key = campaign_group_key(system)
            if allow and key[0] not in allow:
                continue
            cloud_groups.setdefault(
                key,
                {
                    "job_type": "CLOUD",
                    "target": f"cloud://{key[0]}" + (f"/{key[1]}" if key[1] else ""),
                    "provider": key[0],
                    "account": key[1] or None,
                    "system_id": _attr(system, "id"),
                    "name": _attr(system, "name"),
                    "branch": _attr(system, "scan_branch") or "main",
                    "members": 0,
                },
            )
            cloud_groups[key]["members"] += 1
            continue
        if include_git:
            git_jobs.append(
                {
                    "job_type": "SYSTEM",
                    "target": target,
                    "provider": None,
                    "account": None,
                    "system_id": _attr(system, "id"),
                    "name": _attr(system, "name"),
                    "branch": _attr(system, "scan_branch") or "main",
                    "members": 1,
                }
            )
    planned: list[dict[str, Any]] = []
    remaining = cap
    for item in cloud_groups.values():
        if remaining <= 0:
            break
        planned.append(item)
        remaining -= 1
    for item in git_jobs:
        if remaining <= 0:
            break
        planned.append(item)
        remaining -= 1
    return planned


def _attr(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def system_name_for_finding(finding: dict[str, Any]) -> str:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    provider = str(meta.get("cloud_provider") or "cloud").lower()
    resource = str(meta.get("resource") or finding.get("file_path") or "resource")
    raw = f"{provider}:{resource}".replace(" ", "_")
    if len(raw) <= 200:
        return raw
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    return f"{raw[:180]}:{digest}"


def scan_target_for_finding(finding: dict[str, Any]) -> str:
    path = str(finding.get("file_path") or "")
    if "://" in path:
        scheme, rest = path.split("://", 1)
        if scheme.lower() in CLOUD_SCHEMES:
            return f"cloud://{rest}"
        if scheme.lower() in {"http", "https", "git", "local", "file"}:
            return path
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    provider = str(meta.get("cloud_provider") or "cloud").lower()
    resource = str(meta.get("resource") or "resource")
    return f"cloud://{provider}/{resource}"


def row_from_finding(finding: dict[str, Any], *, account: str | None = None) -> dict[str, Any]:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    provider = str(meta.get("cloud_provider") or "AWS").upper()
    return {
        "name": system_name_for_finding(finding),
        "scan_target": scan_target_for_finding(finding),
        "environment": "prod",
        "description": str(meta.get("resource") or finding.get("file_path") or ""),
        "cloud_provider": provider,
        "cloud_account": account,
        "algorithm": finding.get("algorithm") or "UNKNOWN",
        "purpose": finding.get("purpose"),
        "mode": finding.get("mode"),
        "key_size": finding.get("key_size"),
        "file_path": finding.get("file_path") or "",
        "line_number": int(finding.get("line_number") or 0),
        "confidence": finding.get("confidence") or "HIGH",
        "scanner_ids": [finding.get("scanner_id") or "cloud-config-scanner-v1.0"],
        "extra": meta,
    }


def ingest_findings(
    session,
    findings: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
    account: str | None = None,
    stamp: bool = True,
    limit: int | None = None,
) -> dict[str, Any]:
    """Upsert one system + asset per cryptographic cloud resource."""
    from db.repositories.asset_repository import AssetRepository
    from db.repositories.system_repository import SystemRepository

    sys_repo = SystemRepository(session)
    asset_repo = AssetRepository(session)
    created = 0
    updated = 0
    limit = int(limit or _resource_cap())
    truncated = len(findings) > limit
    stored_ids: list[str] = []
    algorithms: Counter[str] = Counter()
    for finding in findings[: int(limit)]:
        row = row_from_finding(finding, account=account)
        algorithms[str(row["algorithm"])] += 1
        system, is_new = sys_repo.upsert_imported(
            {
                "name": row["name"],
                "scan_target": row["scan_target"],
                "environment": row["environment"],
                "description": row["description"],
                "cloud_provider": row["cloud_provider"],
                "cloud_account": row["cloud_account"],
            }
        )
        created += int(is_new)
        updated += int(not is_new)
        if row["cloud_provider"] and not getattr(system, "cloud_provider", None):
            system.cloud_provider = row["cloud_provider"]
        if row["cloud_account"] and not getattr(system, "cloud_account", None):
            system.cloud_account = row["cloud_account"]
        assets = asset_repo.replace_for_scan(
            scan_id or f"cloud:{system.id}",
            [
                {
                    "algorithm": row["algorithm"],
                    "purpose": row["purpose"],
                    "mode": row["mode"],
                    "key_size": row["key_size"],
                    "file_path": row["file_path"] or row["scan_target"],
                    "line_number": row["line_number"],
                    "confidence": row["confidence"],
                    "scanner_ids": row["scanner_ids"],
                    "libraries": [row["cloud_provider"].lower()],
                }
            ],
        )
        for asset in assets:
            sys_repo.attach_asset(system.id, asset.id)
        if stamp:
            sys_repo.stamp_scan(
                system.id,
                scan_id=scan_id,
                status="CURRENT",
                target=row["scan_target"],
                component_count=1,
                algorithms={row["algorithm"]: 1},
            )
        stored_ids.append(system.id)
    session.flush()
    return {
        "created": created,
        "updated": updated,
        "systems": created + updated,
        "truncated": truncated,
        "algorithms": dict(algorithms),
        "system_ids": stored_ids[:50],
        "message": (
            f"Registered {created + updated} cloud systems from this scan. "
            "Algorithms stay unknown on systems that were not in this inventory."
        ),
    }
