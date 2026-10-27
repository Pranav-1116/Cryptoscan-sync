"""System inventory, CMDB import, and per-system scan."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository, require_admin
from db.models.system import System
from db.repositories.asset_repository import AssetRepository
from db.repositories.job_repository import JobRepository
from db.repositories.resource_grant_repository import (
    READ_ROLE,
    WRITE_ROLE,
    ResourceGrantRepository,
)
from db.repositories.system_repository import SystemRepository

router = APIRouter(prefix="/systems", tags=["systems"])


def _system_access(
    db: Session, user: str, system_id: str, minimum_role: str, *, read_only: bool
) -> None:
    """Resource-level check (report 13 §2.2). Restrictive-only-when-present:
    unrestricted systems behave exactly as before; once grants exist for a
    system — or for its business unit (round 22: BU → System → Asset
    inheritance; restriction flows down like permission) — the subject
    must hold a grant at or above ``minimum_role`` (direct, or inherited
    from the business unit). Platform superadmin always passes; auditor
    passes read-only checks.
    """
    grants = ResourceGrantRepository(db)
    if not grants.system_is_restricted(system_id):
        return
    from api.dependencies import _user_roles
    from api.security.rbac import normalize_roles

    platform = set(normalize_roles(_user_roles(user, None, db)))
    if platform & {"superadmin", "admin"}:
        return
    if read_only and platform & {"auditor"}:
        return
    if grants.system_check_access(user, system_id, minimum_role):
        return
    raise HTTPException(
        status_code=403,
        detail=(
            f"System is grant-restricted; user {user} lacks {minimum_role} "
            f"access (needed for this {'read' if read_only else 'write'} operation)"
        ),
    )


class SystemCreate(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    technical_owner: str | None = None
    security_owner: str | None = None
    environment: str | None = None
    compliance_scopes: list[str] = []
    scan_target: str | None = None
    scan_branch: str | None = None
    business_unit: str | None = None
    criticality: str | None = None
    cloud_provider: str | None = None
    cloud_account: str | None = None


class AttachAsset(BaseModel):
    asset_id: str


class DependencyCreate(BaseModel):
    child_id: str
    relation: str | None = "depends-on"


class ImportSystemsRequest(BaseModel):
    systems: list[dict] | None = None
    csv: str | None = None


@router.get("")
def list_systems(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    coverage: str | None = None,
    q: str | None = None,
    business_unit: str | None = None,
    cloud_provider: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    rows, total = repo.list_systems(
        page=page,
        page_size=page_size,
        coverage=coverage,
        q=q,
        business_unit=business_unit,
        cloud_provider=cloud_provider,
    )
    catalog = repo.catalog_rows(rows)
    return {
        "systems": [{**row.to_dict(), **meta, "coverage":meta["coverage_status"]} for row, meta in zip(rows, catalog)],
        "total_count": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("")
def create_system(
    body: SystemCreate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    existing = repo.get_by_name(body.name)
    if existing:
        raise HTTPException(status_code=409, detail="System name already exists")
    from cbom.coverage import initial_status

    row = repo.create(
        System(
            name=body.name,
            description=body.description,
            owner=body.owner,
            technical_owner=body.technical_owner,
            security_owner=body.security_owner,
            environment=body.environment,
            compliance_scopes=body.compliance_scopes,
            scan_target=body.scan_target,
            scan_branch=body.scan_branch,
            business_unit=body.business_unit,
            criticality=body.criticality,
            cloud_provider=body.cloud_provider,
            cloud_account=body.cloud_account,
            coverage_status=initial_status(body.scan_target),
        )
    )
    return row.to_dict()


@router.post("/import")
def import_systems(
    body: ImportSystemsRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from cbom.coverage import parse_system_import

    try:
        rows = parse_system_import(body.systems if body.systems is not None else body.csv)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not rows:
        raise HTTPException(status_code=422, detail="No systems in import payload")
    repo = SystemRepository(db)
    created = 0
    updated = 0
    imported = []
    for item in rows[:5000]:
        system, is_new = repo.upsert_imported(item)
        created += int(is_new)
        updated += int(not is_new)
        imported.append(system.to_dict())
    return {
        "created": created,
        "updated": updated,
        "total": created + updated,
        "systems": imported[:50],
        "truncated": len(rows) > 5000,
    }


class SystemUpdate(BaseModel):
    scan_target: str | None = None
    scan_branch: str | None = None
    owner: str | None = None
    technical_owner: str | None = None
    security_owner: str | None = None
    environment: str | None = None
    business_unit: str | None = None
    criticality: str | None = None
    description: str | None = None
    compliance_scopes: list[str] | None = None
    cloud_provider: str | None = None
    cloud_account: str | None = None


@router.patch("/{system_id}")
def update_system(
    system_id: str,
    body: SystemUpdate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    row = repo.get_by_id(system_id)
    if row is None:
        raise HTTPException(status_code=404, detail="System not found")
    _system_access(db, user, system_id, WRITE_ROLE, read_only=False)
    data = body.model_dump(exclude_unset=True)
    ownership_keys = ("owner", "technical_owner", "security_owner")
    ownership_before = {k: getattr(row, k, None) for k in ownership_keys}
    for key, value in data.items():
        setattr(row, key, value)
    if "scan_target" in data:
        from cbom.coverage import initial_status

        if not row.last_scan_id:
            row.coverage_status = initial_status(row.scan_target)
    db.flush()
    # Ownership changes are accountability decisions — audit who changed
    # them, from what, to what (report 55: ownership must be auditable).
    changed = {
        k: {"from": ownership_before[k], "to": data[k]}
        for k in ownership_keys
        if k in data and (data[k] or None) != (ownership_before[k] or None)
    }
    if changed:
        try:
            from db.repositories.user_repository import UserRepository

            UserRepository(db).audit(
                user,
                "system.ownership_change",
                target_type="system",
                target_id=str(system_id),
                detail={"changes": changed},
            )
            db.commit()
        except Exception:
            db.rollback()
            raise HTTPException(status_code=503, detail="Ownership audit is unavailable")
    return row.to_dict()


@router.get("/{system_id}")
def get_system(
    system_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    row = repo.get_by_id(system_id)
    if row is None:
        raise HTTPException(status_code=404, detail="System not found")
    _system_access(db, user, system_id, READ_ROLE, read_only=True)
    payload = row.to_dict()
    payload["assets"] = [asset.to_dict() for asset in repo.assets_for(system_id)]
    payload["dependencies"] = [edge.to_dict() for edge in repo.dependencies_for(system_id)]
    payload.update(repo.catalog_row(row))
    return payload


@router.post("/{system_id}/scan")
def scan_system(
    system_id: str,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    _system_access(db, user, system_id, WRITE_ROLE, read_only=False)
    target = (system.scan_target or "").strip()
    if not target:
        raise HTTPException(
            status_code=422,
            detail="Set scan_target (git URL or local:// path) before scanning. Algorithms are unknown until a scan produces a CBOM.",
        )
    from api.routers.trigger import enqueue_scan_job

    return enqueue_scan_job(
        jobs,
        background_tasks,
        repo_url=target,
        branch=system.scan_branch or "main",
        triggered_by=user,
        job_type="SYSTEM",
        system_id=system.id,
    )


@router.post("/{system_id}/assets")
def attach_asset(
    system_id: str,
    body: AttachAsset,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    if repo.get_by_id(system_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    _system_access(db, user, system_id, WRITE_ROLE, read_only=False)
    # Graph node ids ("asset:<uuid>") are accepted alongside raw asset ids.
    asset_id = body.asset_id.removeprefix("asset:")
    if AssetRepository(db).get_by_id(asset_id) is None:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    try:
        link = repo.attach_asset(system_id, asset_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return link.to_dict()


@router.post("/{system_id}/dependencies")
def add_dependency(
    system_id: str,
    body: DependencyCreate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    if repo.get_by_id(system_id) is None or repo.get_by_id(body.child_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    _system_access(db, user, system_id, WRITE_ROLE, read_only=False)
    from db.models.system_dependency import SystemDependency

    if db.query(SystemDependency).filter(
            SystemDependency.parent_id == system_id,
            SystemDependency.child_id == body.child_id).first() is not None:
        raise HTTPException(status_code=409, detail="edge already exists")
    edge = repo.add_dependency(system_id, body.child_id, body.relation)
    # provenance parity with POST /graph/edges (the consolidated surface)
    edge.source = "manual"
    edge.created_by = user
    db.commit()
    return edge.to_dict()


class GrantCreate(BaseModel):
    subject: str = Field(..., min_length=1, description="Username receiving the grant")
    role: str = Field("viewer", description="owner | operator | viewer")


@router.get("/{system_id}/grants")
def list_grants(
    system_id: str,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Who has resource-level access to this system (admin view)."""
    if SystemRepository(db).get_by_id(system_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    repo = ResourceGrantRepository(db)
    rows = repo.grants_for("SYSTEM", system_id)
    system = SystemRepository(db).get_by_id(system_id)
    bu = getattr(system, "business_unit", None)
    bu_rows = repo.grants_for("BUSINESS_UNIT", bu) if bu else []
    return {
        "system_id": system_id,
        "restricted": repo.system_is_restricted(system_id),
        "restricted_by": "SYSTEM" if rows else ("BUSINESS_UNIT" if bu_rows else None),
        "business_unit": bu,
        "business_unit_grants": [
            {"subject": g.subject, "role": g.role, "granted_by": g.granted_by,
             "created_at": g.created_at.isoformat() if g.created_at else None}
            for g in bu_rows
        ],
        "grants": [
            {"subject": g.subject, "role": g.role, "granted_by": g.granted_by,
             "created_at": g.created_at.isoformat() if g.created_at else None}
            for g in rows
        ],
    }


@router.post("/{system_id}/grants")
def add_grant(
    system_id: str,
    body: GrantCreate,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Put a system under grant control / adjust one subject's role.

    Admin-only: creating the first grant switches the system from
    "unrestricted" to "grant-restricted" — a security decision, so it is
    audited like the other admin actions.
    """
    if SystemRepository(db).get_by_id(system_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    try:
        grants = ResourceGrantRepository(db)
        was_restricted = grants.is_restricted("SYSTEM", system_id)
        row = grants.grant(body.subject, "SYSTEM", system_id, body.role, granted_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    from db.repositories.user_repository import UserRepository

    try:
        UserRepository(db).audit(
            user,
            "system.grant" if was_restricted else "system.restrict",
            target_type="system",
            target_id=str(system_id),
            detail={"subject": body.subject, "role": row.role,
                    "first_grant": not was_restricted},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Grant audit is unavailable")
    return {"system_id": system_id, "subject": row.subject, "role": row.role,
            "restricted": True}


@router.delete("/{system_id}/grants/{subject}")
def revoke_grant(
    system_id: str,
    subject: str,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Remove one subject's grant. Revoking the last grant returns the
    system to unrestricted (also audited — that is a security decision)."""
    if SystemRepository(db).get_by_id(system_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    grants = ResourceGrantRepository(db)
    was_restricted = grants.is_restricted("SYSTEM", system_id)
    removed = grants.revoke(subject, "SYSTEM", system_id)
    if not removed:
        raise HTTPException(status_code=404, detail="No such grant")
    still_restricted = grants.is_restricted("SYSTEM", system_id)
    from db.repositories.user_repository import UserRepository

    try:
        UserRepository(db).audit(
            user,
            "system.unrestrict" if was_restricted and not still_restricted else "system.revoke",
            target_type="system",
            target_id=str(system_id),
            detail={"subject": subject},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Revoke audit is unavailable")
    return {"system_id": system_id, "subject": subject, "revoked": True,
            "restricted": still_restricted}


# --------------------------------------------------------------------------- #
# Business-unit grants (round 22, report 13 §2.2): BU → System → Asset
# inheritance. A grant on a business unit applies to every system whose
# ``business_unit`` matches and to those systems' assets; restriction flows
# down the same path (a restricted BU puts its systems under grant control).
# --------------------------------------------------------------------------- #


@router.get("/business-units/{business_unit}/grants")
def list_bu_grants(
    business_unit: str,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Who has inherited access to a business unit's systems (admin view)."""
    rows = ResourceGrantRepository(db).grants_for("BUSINESS_UNIT", business_unit)
    affected = [
        sid
        for (sid, bu) in db.query(System.id, System.business_unit).filter(
            System.business_unit == business_unit
        ).all()
    ]
    return {
        "business_unit": business_unit,
        "restricted": bool(rows),
        "systems_inheriting": affected,
        "grants": [
            {"subject": g.subject, "role": g.role, "granted_by": g.granted_by,
             "created_at": g.created_at.isoformat() if g.created_at else None}
            for g in rows
        ],
    }


@router.post("/business-units/{business_unit}/grants")
def add_bu_grant(
    business_unit: str,
    body: GrantCreate,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Grant on a business unit — inherited by its systems and their assets."""
    try:
        grants = ResourceGrantRepository(db)
        was_restricted = grants.is_restricted("BUSINESS_UNIT", business_unit)
        row = grants.grant(body.subject, "BUSINESS_UNIT", business_unit, body.role, granted_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    from db.repositories.user_repository import UserRepository

    try:
        UserRepository(db).audit(
            user,
            "bu.grant" if was_restricted else "bu.restrict",
            target_type="business_unit",
            target_id=business_unit,
            detail={"subject": body.subject, "role": row.role,
                    "first_grant": not was_restricted},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Grant audit is unavailable")
    return {"business_unit": business_unit, "subject": row.subject, "role": row.role,
            "restricted": True}


@router.delete("/business-units/{business_unit}/grants/{subject}")
def revoke_bu_grant(
    business_unit: str,
    subject: str,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Remove one subject's business-unit grant. Revoking the last grant
    returns the BU (and its unrestricted systems) to open access."""
    grants = ResourceGrantRepository(db)
    was_restricted = grants.is_restricted("BUSINESS_UNIT", business_unit)
    removed = grants.revoke(subject, "BUSINESS_UNIT", business_unit)
    if not removed:
        raise HTTPException(status_code=404, detail="No such grant")
    still_restricted = grants.is_restricted("BUSINESS_UNIT", business_unit)
    from db.repositories.user_repository import UserRepository

    try:
        UserRepository(db).audit(
            user,
            "bu.unrestrict" if was_restricted and not still_restricted else "bu.revoke",
            target_type="business_unit",
            target_id=business_unit,
            detail={"subject": subject},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Revoke audit is unavailable")
    return {"business_unit": business_unit, "subject": subject, "revoked": True,
            "restricted": still_restricted}
