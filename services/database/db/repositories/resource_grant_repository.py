"""Repository for resource-level access grants (report 13 §2.2)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.resource_grant import ResourceGrant
from db.repositories.base_repository import BaseRepository

#: resource-role ordering: owner > operator > viewer
ROLE_RANK = {"viewer": 0, "operator": 1, "owner": 2}

#: minimum role required per action class (enforced by the API layer)
READ_ROLE = "viewer"
WRITE_ROLE = "operator"


class ResourceGrantRepository(BaseRepository[ResourceGrant]):
    def __init__(self, session: Session):
        super().__init__(ResourceGrant, session)

    def grants_for(self, resource_type: str, resource_id: str) -> list[ResourceGrant]:
        stmt = (
            select(ResourceGrant)
            .where(
                ResourceGrant.resource_type == resource_type,
                ResourceGrant.resource_id == resource_id,
            )
            .order_by(ResourceGrant.subject)
        )
        return list(self.session.execute(stmt).scalars().all())

    def grants_by(self, subject: str, *, resource_type: str | None = None) -> list[ResourceGrant]:
        stmt = select(ResourceGrant).where(ResourceGrant.subject == subject)
        if resource_type:
            stmt = stmt.where(ResourceGrant.resource_type == resource_type)
        return list(self.session.execute(stmt).scalars().all())

    def grant(
        self,
        subject: str,
        resource_type: str,
        resource_id: str,
        role: str,
        *,
        granted_by: str | None = None,
    ) -> ResourceGrant:
        """Idempotent upsert: re-granting updates the role in place."""
        role = str(role).lower().strip()
        if role not in ROLE_RANK:
            raise ValueError(f"role must be one of {sorted(ROLE_RANK)}, not {role!r}")
        existing = self.session.execute(
            select(ResourceGrant).where(
                ResourceGrant.subject == subject,
                ResourceGrant.resource_type == resource_type,
                ResourceGrant.resource_id == resource_id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.role = role
            existing.granted_by = granted_by or existing.granted_by
            self.session.flush()
            return existing
        row = ResourceGrant(
            subject=subject,
            resource_type=resource_type,
            resource_id=resource_id,
            role=role,
            granted_by=granted_by,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def revoke(
        self, subject: str, resource_type: str, resource_id: str
    ) -> bool:
        row = self.session.execute(
            select(ResourceGrant).where(
                ResourceGrant.subject == subject,
                ResourceGrant.resource_type == resource_type,
                ResourceGrant.resource_id == resource_id,
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    def is_restricted(self, resource_type: str, resource_id: str) -> bool:
        """A resource is under grant control once ANY grant exists for it."""
        row = self.session.execute(
            select(ResourceGrant.id).where(
                ResourceGrant.resource_type == resource_type,
                ResourceGrant.resource_id == resource_id,
            ).limit(1)
        ).scalar_one_or_none()
        return row is not None

    def effective_role(self, subject: str, resource_type: str, resource_id: str) -> str | None:
        """The subject's granted role for this resource (None = no grant)."""
        rows = self.grants_for(resource_type, resource_id)
        best: int | None = None
        for row in rows:
            if row.subject == subject:
                rank = ROLE_RANK.get(row.role)
                if rank is not None and (best is None or rank > best):
                    best = rank
        if best is None:
            return None
        for role, rank in ROLE_RANK.items():
            if rank == best:
                return role
        return None

    # ------------------------------------------------------------------ #
    # BU -> System -> Asset inheritance (report 13 §2.2, round 22)
    # ------------------------------------------------------------------ #

    def _system_business_unit(self, system_id: str) -> str | None:
        from db.models.system import System

        row = self.session.execute(
            select(System.business_unit).where(System.id == system_id)
        ).scalar_one_or_none()
        return row

    def system_is_restricted(self, system_id: str) -> bool:
        """A system is under grant control when it has grants OR its
        business unit does — restriction flows down the hierarchy exactly
        like permission does."""
        if self.is_restricted("SYSTEM", system_id):
            return True
        bu = self._system_business_unit(system_id)
        return bool(bu) and self.is_restricted("BUSINESS_UNIT", bu)

    def system_effective_role(self, subject: str, system_id: str) -> str | None:
        """max(direct SYSTEM grant, inherited BUSINESS_UNIT grant)."""
        best: int | None = None
        for role in (
            self.effective_role(subject, "SYSTEM", system_id),
            self.effective_role(subject, "BUSINESS_UNIT", self._system_business_unit(system_id) or "")
            if self._system_business_unit(system_id)
            else None,
        ):
            rank = ROLE_RANK.get(role) if role else None
            if rank is not None and (best is None or rank > best):
                best = rank
        if best is None:
            return None
        for role, rank in ROLE_RANK.items():
            if rank == best:
                return role
        return None

    def system_check_access(
        self, subject: str, system_id: str, minimum_role: str
    ) -> bool:
        minimum_rank = ROLE_RANK.get(str(minimum_role).lower())
        if minimum_rank is None:
            return False
        if not self.system_is_restricted(system_id):
            return True
        role = self.system_effective_role(subject, system_id)
        return role is not None and ROLE_RANK[role] >= minimum_rank

    def _asset_system_ids(self, asset_id: str) -> list[str]:
        from db.models.system_asset import SystemAsset

        rows = self.session.execute(
            select(SystemAsset.system_id).where(SystemAsset.asset_id == asset_id)
        ).scalars().all()
        return [str(row) for row in rows]

    def asset_is_restricted(self, asset_id: str) -> bool:
        """An asset is under grant control when it has grants, any owning
        system does, or any owning system's business unit does."""
        if self.is_restricted("ASSET", asset_id):
            return True
        return any(self.system_is_restricted(sid) for sid in self._asset_system_ids(asset_id))

    def asset_effective_role(self, subject: str, asset_id: str) -> str | None:
        """max(direct ASSET grant, owning systems' grants, their BU grants)."""
        candidates: list[str | None] = [self.effective_role(subject, "ASSET", asset_id)]
        for sid in self._asset_system_ids(asset_id):
            candidates.append(self.system_effective_role(subject, sid))
        best: int | None = None
        for role in candidates:
            rank = ROLE_RANK.get(role) if role else None
            if rank is not None and (best is None or rank > best):
                best = rank
        if best is None:
            return None
        for role, rank in ROLE_RANK.items():
            if rank == best:
                return role
        return None

    def asset_check_access(self, subject: str, asset_id: str, minimum_role: str) -> bool:
        minimum_rank = ROLE_RANK.get(str(minimum_role).lower())
        if minimum_rank is None:
            return False
        if not self.asset_is_restricted(asset_id):
            return True
        role = self.asset_effective_role(subject, asset_id)
        return role is not None and ROLE_RANK[role] >= minimum_rank

    def check_access(
        self, subject: str, resource_type: str, resource_id: str, minimum_role: str
    ) -> bool:
        """Grant-based access decision (no platform-role logic here).

        ``True`` when the resource is unrestricted OR the subject holds a
        grant at or above ``minimum_role``. Platform-role bypasses are the
        API layer's charter, not the repository's.
        """
        minimum_rank = ROLE_RANK.get(str(minimum_role).lower())
        if minimum_rank is None:
            return False
        if not self.is_restricted(resource_type, resource_id):
            return True
        role = self.effective_role(subject, resource_type, resource_id)
        if role is None:
            return False
        return ROLE_RANK[role] >= minimum_rank
