"""System inventory persistence."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from db.import_provenance import coverage_scanned_at_clause, legacy_coverage_review_clause
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.repositories.base_repository import BaseRepository

try:
    from cbom.coverage import STALE_DAYS, effective_status, initial_status, rollup
except Exception:  # pragma: no cover - cbom optional in some unit contexts
    STALE_DAYS = 90

    def initial_status(scan_target: str | None) -> str:
        return "NEVER_SCANNED" if scan_target else "NO_TARGET"

    def effective_status(**kwargs) -> str:
        return str(kwargs.get("coverage_status") or initial_status(kwargs.get("scan_target")))

    def rollup(counts: dict[str, int]) -> dict[str, Any]:
        total = sum(int(v) for v in counts.values())
        return {"systems": total, "counts": counts, "message": ""}


class SystemRepository(BaseRepository[System]):
    def __init__(self, session: Session):
        super().__init__(System, session)

    def list_systems(
        self,
        page: int = 1,
        page_size: int = 50,
        *,
        coverage: str | None = None,
        q: str | None = None,
        business_unit: str | None = None,
        cloud_provider: str | None = None,
    ) -> tuple[list[System], int]:
        stmt = select(System)
        count_stmt = select(func.count()).select_from(System)
        conds = []
        if coverage:
            conds.append(self._coverage_clause(coverage))
        if business_unit:
            conds.append(System.business_unit == business_unit)
        if cloud_provider:
            conds.append(func.upper(func.coalesce(System.cloud_provider, "")) == cloud_provider.upper())
        if q:
            needle = f"%{q.lower()}%"
            conds.append(
                or_(
                    func.lower(System.name).like(needle),
                    func.lower(func.coalesce(System.scan_target, "")).like(needle),
                    func.lower(func.coalesce(System.owner, "")).like(needle),
                )
            )
        for cond in conds:
            if cond is None:
                continue
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = stmt.order_by(System.name).offset((page - 1) * page_size).limit(page_size)
        return list(self.session.execute(stmt).scalars().all()), total

    def list_all_bounded(
        self,
        *,
        page_size: int = 500,
        max_rows: int = 50_000,
    ) -> tuple[list[System], bool]:
        """Every system, paged — bounded by ``max_rows`` and SAYS so.

        Estate-wide views (graph payload, agility, portfolio, exposure,
        due-scan planning) previously fetched a single ``page_size=500``
        page and silently dropped every system beyond it: re-scans were
        never scheduled for them and aggregates under-counted (the same
        failure class TD-007 fixed for the CBOM portfolio). This walks all
        pages and returns ``(rows, truncated)`` so callers can report the
        bound instead of hiding it.
        """
        out: list[System] = []
        page = 1
        total = 0
        while True:
            rows, total = self.list_systems(page=page, page_size=page_size)
            if not rows:
                break
            out.extend(rows)
            if len(out) >= total:
                break  # walked every page
            if len(out) >= max_rows:
                break  # budget hit while total says more exist
            page += 1
        truncated = len(out) < total
        if len(out) > max_rows:
            out = out[:max_rows]
        return out, truncated

    def _coverage_clause(self, coverage: str):
        token = coverage.upper().strip()
        cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
        review = legacy_coverage_review_clause()
        observed_at = coverage_scanned_at_clause()
        has_target = func.coalesce(System.scan_target, "") != ""
        if token == "STALE":
            return ~review & or_(
                System.coverage_status == "STALE",
                (System.coverage_status == "CURRENT") & (observed_at.is_not(None)) & (observed_at < cutoff),
            )
        if token == "CURRENT":
            return ~review & (System.coverage_status == "CURRENT") & (
                observed_at.is_(None) | (observed_at >= cutoff)
            )
        if token == "SCANNABLE":
            return or_(
                review,
                System.coverage_status.in_(("NEVER_SCANNED", "STALE", "FAILED")),
                (System.coverage_status == "CURRENT") & (observed_at.is_not(None)) & (observed_at < cutoff),
            ) & (func.coalesce(System.scan_target, "") != "")
        if token in {"NO_TARGET", "NEVER_SCANNED"}:
            target_clause = has_target if token == "NEVER_SCANNED" else ~has_target
            return or_(and_(review, target_clause), and_(~review, System.coverage_status == token))
        return System.coverage_status == token

    def get_by_name(self, name: str) -> System | None:
        # A name is never an estate-global key. Outside a request an unset
        # context means platform, not "search all banks".
        from db.tenancy import current_tenant
        return self.session.execute(select(System).where(
            System.name == name, System.tenant_id == current_tenant()
        )).scalar_one_or_none()

    def get_or_create(
        self,
        name: str,
        *,
        owner: str | None = None,
        technical_owner: str | None = None,
        security_owner: str | None = None,
        environment: str | None = None,
        description: str | None = None,
        compliance_scopes: list[str] | None = None,
        scan_target: str | None = None,
        scan_branch: str | None = None,
        business_unit: str | None = None,
        criticality: str | None = None,
        cloud_provider: str | None = None,
        cloud_account: str | None = None,
    ) -> System:
        existing = self.get_by_name(name)
        if existing:
            if description and not existing.description:
                existing.description = description
            if scan_target and not existing.scan_target:
                existing.scan_target = scan_target
                if not existing.coverage_status or existing.coverage_status == "NO_TARGET":
                    existing.coverage_status = initial_status(scan_target)
            if scan_branch and not existing.scan_branch:
                existing.scan_branch = scan_branch
            if cloud_provider and not getattr(existing, "cloud_provider", None):
                existing.cloud_provider = cloud_provider
            if cloud_account and not getattr(existing, "cloud_account", None):
                existing.cloud_account = cloud_account
            self.session.flush()
            return existing
        row = System(
            name=name,
            owner=owner,
            technical_owner=technical_owner,
            security_owner=security_owner,
            environment=environment,
            description=description,
            compliance_scopes=compliance_scopes or [],
            scan_target=scan_target,
            scan_branch=scan_branch,
            business_unit=business_unit,
            criticality=criticality,
            cloud_provider=cloud_provider,
            cloud_account=cloud_account,
            coverage_status=initial_status(scan_target),
        )
        return self.create(row)

    def upsert_imported(self, item: dict[str, Any]) -> tuple[System, bool]:
        name = str(item.get("name") or "").strip()
        existing = self.get_by_name(name)
        created = existing is None
        if existing is None:
            existing = self.get_or_create(
                name,
                owner=item.get("owner"),
                technical_owner=item.get("technical_owner"),
                security_owner=item.get("security_owner"),
                environment=item.get("environment"),
                description=item.get("description"),
                compliance_scopes=item.get("compliance_scopes") or [],
                scan_target=item.get("scan_target"),
                scan_branch=item.get("scan_branch"),
                business_unit=item.get("business_unit"),
                criticality=item.get("criticality"),
                cloud_provider=item.get("cloud_provider"),
                cloud_account=item.get("cloud_account"),
            )
            return existing, created
        for field in (
            "owner",
            "technical_owner",
            "security_owner",
            "environment",
            "description",
            "scan_target",
            "scan_branch",
            "business_unit",
            "criticality",
            "cloud_provider",
            "cloud_account",
        ):
            value = item.get(field)
            if value and not getattr(existing, field, None):
                setattr(existing, field, value)
        if item.get("compliance_scopes") and not existing.compliance_scopes:
            existing.compliance_scopes = item["compliance_scopes"]
        if existing.scan_target and (not existing.coverage_status or existing.coverage_status == "NO_TARGET"):
            existing.coverage_status = initial_status(existing.scan_target)
        self.session.flush()
        return existing, created

    def attach_asset(self, system_id: str, asset_id: str) -> SystemAsset:
        # Lock the asset before linking: concurrent historical reconciliation
        # must not archive a newly shared declaration or resurrect an archive.
        from shared_models.import_provenance import ARCHIVED_DECLARATION
        asset = self.session.execute(select(CryptoAsset).where(CryptoAsset.id == asset_id)
            .with_for_update().execution_options(populate_existing=True)).scalar_one_or_none()
        if asset is None:
            raise ValueError("Asset not found")
        if asset.to_dict().get("source_disposition") == ARCHIVED_DECLARATION:
            raise ValueError("Archived historical declarations cannot be reattached; reimport the source")
        existing = self.session.execute(
            select(SystemAsset).where(SystemAsset.system_id == system_id, SystemAsset.asset_id == asset_id)
        ).scalar_one_or_none()
        if existing:
            return existing
        link = SystemAsset(system_id=system_id, asset_id=asset_id)
        self.session.add(link)
        self.session.flush()
        return link

    def assets_for(self, system_id: str) -> list[CryptoAsset]:
        stmt = (
            select(CryptoAsset)
            .join(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
            .where(SystemAsset.system_id == system_id)
        )
        return list(self.session.execute(stmt).scalars().all())

    def add_dependency(self, parent_id: str, child_id: str, relation: str | None = None) -> SystemDependency:
        existing = self.session.execute(
            select(SystemDependency).where(
                SystemDependency.parent_id == parent_id,
                SystemDependency.child_id == child_id,
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        edge = SystemDependency(parent_id=parent_id, child_id=child_id, relation=relation)
        self.session.add(edge)
        self.session.flush()
        return edge

    def dependencies_for(self, system_id: str) -> list[SystemDependency]:
        stmt = select(SystemDependency).where(SystemDependency.parent_id == system_id)
        return list(self.session.execute(stmt).scalars().all())

    def list_uncovered(
        self,
        *,
        limit: int = 25,
        business_unit: str | None = None,
        cloud_provider: str | None = None,
    ) -> list[System]:
        stmt = select(System).where(self._coverage_clause("SCANNABLE"))
        if business_unit:
            stmt = stmt.where(System.business_unit == business_unit)
        if cloud_provider:
            stmt = stmt.where(func.upper(func.coalesce(System.cloud_provider, "")) == cloud_provider.upper())
        stmt = stmt.order_by(func.coalesce(System.criticality, "ZZZ"), System.name).limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def coverage_summary(self, *, stale_days: int = STALE_DAYS) -> dict[str, Any]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(stale_days))
        from db.models.scan import Scan

        # the latest recorded job decides: a stored CURRENT over a FAILED last
        # scan is a failed collection, not current coverage
        rows = list(
            self.session.execute(
                select(System.coverage_status, System.scan_target, coverage_scanned_at_clause(),
                       legacy_coverage_review_clause(), Scan.status)
                .outerjoin(Scan, Scan.id == System.last_scan_id)
            ).all()
        )
        counts = {key: 0 for key in ("NO_TARGET", "NEVER_SCANNED", "CURRENT", "STALE", "FAILED")}
        for status, target, scanned, review, last_job in rows:
            if str(last_job or "").upper() == "FAILED" and not review:
                status = "FAILED"
            key = initial_status(target) if review else effective_status(
                coverage_status=status,
                scan_target=target,
                last_scanned_at=scanned,
                stale_days=stale_days,
            )
            counts[key] = counts.get(key, 0) + 1
        summary = rollup(counts)
        summary["legacy_coverage_unproven"] = sum(bool(row[3]) for row in rows)
        summary["last_job_failed"] = sum(str(row[4] or "").upper() == "FAILED" for row in rows)
        summary["stale_after_days"] = stale_days
        summary["cutoff"] = cutoff.isoformat()
        return summary

    def stamp_scan(
        self,
        system_id: str,
        *,
        scan_id: str | None,
        status: str = "CURRENT",
        target: str | None = None,
        branch: str | None = None,
        component_count: int = 0,
        algorithms: dict[str, int] | None = None,
        posture_score: int | None = None,
        posture_grade: str | None = None,
        error: str | None = None,
    ) -> System | None:
        system = self.get_by_id(system_id)
        if system is None:
            return None
        now = datetime.now(timezone.utc)
        system.coverage_status = status
        if scan_id:
            system.last_scan_id = scan_id
        if status != "FAILED":
            system.last_scanned_at = now
        if target and not system.scan_target:
            system.scan_target = target
        if branch and not system.scan_branch:
            system.scan_branch = branch
        extra = dict(system.extra or {})
        extra["cbom"] = {
            "scan_id": scan_id,
            "stamped_at": now.isoformat(),
            "component_count": int(component_count),
            "algorithms": algorithms or {},
            "posture_score": posture_score,
            "posture_grade": posture_grade,
            "status": status,
            "source": "scan",
        }
        if error:
            extra["last_scan_error"] = error
        else:
            extra.pop("last_scan_error", None)
        system.extra = extra
        try:
            flag_modified(system, "extra")
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass
        self.session.flush()
        return system

    def catalog_rows(self, systems: list[System]) -> list[dict[str, Any]]:
        """Batch provenance query, not a per-system N+1 or a stale cache."""
        if not systems:
            return []
        facts = {row[0]:(bool(row[1]), row[2]) for row in self.session.execute(select(
            System.id, legacy_coverage_review_clause(), coverage_scanned_at_clause()).where(
            System.id.in_([system.id for system in systems]))).all()}
        return [self.catalog_row(system, provenance_review=facts[system.id][0], observed_at=facts[system.id][1]) for system in systems]

    def catalog_row(self, system: System, *, provenance_review: bool | None = None, observed_at: datetime | None = None) -> dict[str, Any]:
        extra = system.extra if isinstance(system.extra, dict) else {}
        imported = extra.get("cbom") if isinstance(extra, dict) else None
        if provenance_review is None:
            review, observed_at = self.session.execute(select(legacy_coverage_review_clause(), coverage_scanned_at_clause()).select_from(System).where(
                System.id == system.id)).one()
            provenance_review = bool(review)
        status = initial_status(system.scan_target) if provenance_review else effective_status(
            coverage_status=system.coverage_status,
            scan_target=system.scan_target,
            last_scanned_at=observed_at,
        )
        components = 0
        algorithms: dict[str, int] = {}
        if isinstance(imported, dict):
            components = int(imported.get("component_count") or 0)
            raw = imported.get("algorithms") or {}
            if isinstance(raw, dict):
                algorithms = {str(k): int(v) for k, v in raw.items()}
        return {
            "source_type": "system",
            "source_id": system.id,
            "name": system.name,
            "environment": system.environment,
            "owner": system.owner,
            "business_unit": system.business_unit,
            "criticality": system.criticality,
            "cloud_provider": getattr(system, "cloud_provider", None),
            "cloud_account": getattr(system, "cloud_account", None),
            "scan_target": system.scan_target,
            "scan_branch": system.scan_branch,
            "coverage_status": status,
            "coverage_requires_review": provenance_review,
            "reported_coverage_status": system.coverage_status,
            "reported_last_scanned_at": system.last_scanned_at.isoformat() if system.last_scanned_at else None,
            "last_scan_id": None if provenance_review else system.last_scan_id,
            "last_scanned_at": None if provenance_review else (observed_at.isoformat() if observed_at else None),
            "spec": "CycloneDX 1.5",
            "components": components,
            "algorithms": algorithms,
            "algorithm_count": len(algorithms),
            "imported": imported,
        }
