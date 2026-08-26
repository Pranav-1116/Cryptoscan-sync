"""System inventory persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
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

    def _coverage_clause(self, coverage: str):
        token = coverage.upper().strip()
        cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
        if token == "STALE":
            return or_(
                System.coverage_status == "STALE",
                (System.coverage_status == "CURRENT") & (System.last_scanned_at.is_not(None)) & (System.last_scanned_at < cutoff),
            )
        if token == "CURRENT":
            return (System.coverage_status == "CURRENT") & (
                System.last_scanned_at.is_(None) | (System.last_scanned_at >= cutoff)
            )
        if token == "SCANNABLE":
            return or_(
                System.coverage_status.in_(("NEVER_SCANNED", "STALE", "FAILED")),
                (System.coverage_status == "CURRENT") & (System.last_scanned_at.is_not(None)) & (System.last_scanned_at < cutoff),
            ) & (func.coalesce(System.scan_target, "") != "")
        return System.coverage_status == token

    def get_by_name(self, name: str) -> System | None:
        return self.session.execute(select(System).where(System.name == name)).scalar_one_or_none()

    def get_or_create(
        self,
        name: str,
        *,
        owner: str | None = None,
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
        rows = list(
            self.session.execute(select(System.coverage_status, System.scan_target, System.last_scanned_at)).all()
        )
        counts = {key: 0 for key in ("NO_TARGET", "NEVER_SCANNED", "CURRENT", "STALE", "FAILED")}
        for status, target, scanned in rows:
            key = effective_status(
                coverage_status=status,
                scan_target=target,
                last_scanned_at=scanned,
                stale_days=stale_days,
            )
            counts[key] = counts.get(key, 0) + 1
        summary = rollup(counts)
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
        except Exception:
            pass
        self.session.flush()
        return system

    def catalog_row(self, system: System) -> dict[str, Any]:
        extra = system.extra if isinstance(system.extra, dict) else {}
        imported = extra.get("cbom") if isinstance(extra, dict) else None
        status = effective_status(
            coverage_status=system.coverage_status,
            scan_target=system.scan_target,
            last_scanned_at=system.last_scanned_at,
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
            "last_scan_id": system.last_scan_id,
            "last_scanned_at": system.last_scanned_at.isoformat() if system.last_scanned_at else None,
            "spec": "CycloneDX 1.5",
            "components": components,
            "algorithms": algorithms,
            "algorithm_count": len(algorithms),
            "imported": imported,
        }
