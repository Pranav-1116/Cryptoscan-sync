"""Multi-tenant SaaS control plane: signup, tenancy context, members, usage.

Isolation model (enforced, not cosmetic):
- every tenant-scoped row carries tenant_id; repositories filter by it and
  routers resolve the active tenant from TenantContext — cross-tenant reads
  are 404 (no existence oracle);
- suspension is 423 and takes effect on the very next request;
- plans enforce quotas with 402 quota_exceeded (targets, monthly scans,
  seats) — unlimited for ENTERPRISE;
- platform operators (superadmin) keep the global estate and can administer
  every tenant explicitly.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext,
    get_current_user,
    get_db_session,
    get_tenant_context,
    require_roles,
    require_tenant_roles,
)
from api.security.passwords import hash_password, verify_password
from api.security.tenancy import (
    PLANS,
    grantable_roles,
    plan_limits,
    quota_check,
    unique_slug,
)

router = APIRouter(prefix="/saas", tags=["saas"])


def _tenant_repo(db: Session):
    from db.repositories.tenant_repository import TenantRepository

    return TenantRepository(db)


def _user_repo(db: Session):
    from db.repositories.user_repository import UserRepository

    return UserRepository(db)


class SignupRequest(BaseModel):
    org_name: str = Field(..., min_length=2, max_length=200)
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=12, max_length=200)
    email: str | None = Field(None, max_length=320)


class InviteCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    tenant_role: str = "member"
    email: str | None = Field(None, max_length=320)
    days: int = Field(7, ge=1, le=30)


class InviteAccept(BaseModel):
    token: str = Field(..., min_length=10, max_length=200)
    password: str | None = Field(None, min_length=12, max_length=200)  # required when the invited user has no account yet


class MemberCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    tenant_role: str = "member"
    password: str | None = Field(None, min_length=12, max_length=200)  # required for NEW users
    email: str | None = Field(None, max_length=320)


@router.post("/signup", status_code=201)
def signup(body: SignupRequest, request: Request, db: Session = Depends(get_db_session)):
    """Self-serve tenant provisioning: creates the organization and its owner.

    If the username already exists the password must match (the founder is
    authenticated before the account gains a second organization) — this
    prevents polluting an existing identity with attacker-chosen memberships.
    """
    from api.security.passwords import PasswordPolicyError, validate_password_policy

    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=f"Weak password: {exc}")

    users = _user_repo(db)
    existing = users.get_by_username(body.username)
    if existing is not None and not verify_password(body.password, existing.password_hash):
        raise HTTPException(status_code=401, detail="Username exists — credentials do not match")

    tenants = _tenant_repo(db)
    slug = unique_slug(body.org_name, tenants.existing_slugs())
    if existing is None:
        user = users.create_user(
            body.username, hash_password(body.password), roles=["readonly"],
            email=(body.email or "").strip().lower() or None,
        )
    else:
        user = existing
    tenant = tenants.create(name=body.org_name.strip(), slug=slug, created_by=user.username)
    tenants.add_member(tenant.id, user.username, "owner", actor=user.username)
    users.audit(
        user.username, "tenant.signup", target_type="tenant", target_id=tenant.id,
        detail={"org": tenant.name, "slug": tenant.slug},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {
        "tenant": {"id": tenant.id, "name": tenant.name, "slug": tenant.slug, "plan": tenant.plan},
        "username": user.username,
        "tenant_role": "owner",
        "message": "organization created — sign in and send X-Tenant-ID (or rely on sole membership)",
    }


def _usage_block(db: Session, ctx: TenantContext) -> dict:
    t_repo = _tenant_repo(db)
    limits = plan_limits(ctx.plan or "FREE")
    targets = t_repo.live_target_count(ctx.tenant_id)
    members = t_repo.member_count(ctx.tenant_id)
    scans = t_repo.month_usage(ctx.tenant_id, "scan_run")
    out: dict[str, dict] = {
        "targets": {"used": targets, "limit": limits["max_targets"]},
        "seats": {"used": members, "limit": limits["max_users"]},
        "scans_this_month": {"used": scans, "limit": limits["max_scans_per_month"]},
    }
    for meter in out.values():
        meter["remaining"] = None if meter["limit"] is None else max(0, meter["limit"] - meter["used"])
    return out


@router.get("/whoami")
def whoami(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    """The active tenancy: who you are, which org, your role, plan and usage."""
    base = {
        "username": ctx.username,
        "tenant_id": ctx.tenant_id,
        "tenant_role": ctx.tenant_role,
        "plan": ctx.plan,
        "tenant_status": ctx.tenant_status,
        "is_platform_admin": ctx.is_platform_admin,
    }
    if ctx.tenant_id:
        tenant = _tenant_repo(db).get(ctx.tenant_id)
        if tenant is not None:
            base["tenant_name"] = tenant.name
            base["tenant_slug"] = tenant.slug
            base["usage"] = _usage_block(db, ctx)
    return base


@router.get("/usage")
def usage(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context has no usage — send X-Tenant-ID")
    t_repo = _tenant_repo(db)
    return {
        "tenant_id": ctx.tenant_id,
        "plan": ctx.plan,
        "limits": plan_limits(ctx.plan or "FREE"),
        "meters": _usage_block(db, ctx),
        "month_breakdown": t_repo.usage_breakdown(ctx.tenant_id),
    }


@router.get("/members")
def list_members(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    return {
        "members": [
            {"username": m.username, "tenant_role": m.tenant_role, "added_at": m.created_at.isoformat()}
            for m in _tenant_repo(db).members_of(ctx.tenant_id)
        ]
    }


@router.post("/members", status_code=201)
def add_member(
    body: MemberCreate,
    ctx: TenantContext = Depends(require_tenant_roles("owner", "admin")),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    if body.tenant_role not in grantable_roles(ctx.tenant_role or ""):
        raise HTTPException(
            status_code=403,
            detail=f"role '{ctx.tenant_role}' may grant: {list(grantable_roles(ctx.tenant_role or ''))}",
        )
    t_repo = _tenant_repo(db)
    allowed, reason = quota_check(ctx.plan or "FREE", "member_create",
                                  t_repo.member_count(ctx.tenant_id))
    if not allowed:
        raise HTTPException(status_code=402, detail=f"quota_exceeded: {reason}")

    users = _user_repo(db)
    user = users.get_by_username(body.username)
    if user is None:
        from api.security.passwords import PasswordPolicyError, validate_password_policy

        if not body.password:
            raise HTTPException(status_code=422,
                                detail=f"new user '{body.username}' needs an initial password")
        try:
            validate_password_policy(body.password)
        except PasswordPolicyError as exc:
            raise HTTPException(status_code=422, detail=f"Weak password: {exc}")
        user = users.create_user(body.username, hash_password(body.password),
                                 roles=["readonly"], email=body.email)
    try:
        membership = t_repo.add_member(ctx.tenant_id, body.username,
                                       body.tenant_role, actor=ctx.username)
    except Exception as exc:  # duplicate membership / unknown role -> 409/422
        msg = str(exc)
        raise HTTPException(status_code=409 if "already a member" in msg else 422, detail=msg)
    users.audit(ctx.username, "tenant.member_add", target_type="tenant",
                target_id=ctx.tenant_id, detail={"member": body.username,
                                                 "role": body.tenant_role})
    db.commit()
    return {"username": membership.username, "tenant_role": membership.tenant_role}


@router.delete("/members/{username}")
def remove_member(
    username: str,
    ctx: TenantContext = Depends(require_tenant_roles("owner", "admin")),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    t_repo = _tenant_repo(db)
    target = t_repo.membership(ctx.tenant_id, username)
    if target is None:
        raise HTTPException(status_code=404, detail="Not a member of this tenant")
    # an admin may not remove an owner; nobody may remove the last owner
    if target.tenant_role == "owner" and ctx.tenant_role != "owner":
        raise HTTPException(status_code=403, detail="Only an owner can remove an owner")
    if target.tenant_role == "owner" and t_repo.owner_count(ctx.tenant_id) <= 1:
        raise HTTPException(status_code=409, detail="Cannot remove the last owner")
    t_repo.remove_member(ctx.tenant_id, username)
    _user_repo(db).audit(ctx.username, "tenant.member_remove", target_type="tenant",
                         target_id=ctx.tenant_id, detail={"member": username})
    db.commit()
    return {"removed": username}


# ------------------------------------------------------------------ invites

@router.post("/invites", status_code=201)
def create_invite(
    body: InviteCreate,
    ctx: TenantContext = Depends(require_tenant_roles("owner", "admin")),
    db: Session = Depends(get_db_session),
):
    """Invite a user to this tenant. The raw token is returned ONCE (like an
    API key) — deliver it out-of-band; only its hash is stored."""
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    if body.tenant_role not in grantable_roles(ctx.tenant_role or ""):
        raise HTTPException(
            status_code=403,
            detail=f"role '{ctx.tenant_role}' may grant: {list(grantable_roles(ctx.tenant_role or ''))}",
        )
    t_repo = _tenant_repo(db)
    try:
        row, raw = t_repo.create_invite(
            ctx.tenant_id, body.username, body.tenant_role,
            invited_by=ctx.username, days=body.days, email=body.email)
    except Exception as exc:
        msg = str(exc)
        raise HTTPException(status_code=409 if "already a member" in msg else 422, detail=msg)
    _user_repo(db).audit(ctx.username, "tenant.invite_create", target_type="tenant",
                         target_id=ctx.tenant_id, detail={"invite": body.username,
                                                          "role": body.tenant_role})
    db.commit()
    return {
        "invite_id": row.id,
        "username": row.username,
        "tenant_role": row.tenant_role,
        "expires_at": row.expires_at.isoformat(),
        "token": raw,  # shown once
    }


@router.get("/invites")
def list_invites(
    ctx: TenantContext = Depends(require_tenant_roles("owner", "admin")),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    return {"invites": [
        {
            "invite_id": i.id,
            "username": i.username,
            "tenant_role": i.tenant_role,
            "invited_by": i.invited_by,
            "expires_at": i.expires_at.isoformat(),
            "accepted": i.accepted_at is not None,
        }
        for i in _tenant_repo(db).invites_for(ctx.tenant_id)
    ]}


@router.delete("/invites/{invite_id}")
def revoke_invite(
    invite_id: str,
    ctx: TenantContext = Depends(require_tenant_roles("owner", "admin")),
    db: Session = Depends(get_db_session),
):
    if not ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Platform context — send X-Tenant-ID")
    row = _tenant_repo(db).revoke_invite(ctx.tenant_id, invite_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pending invite not found")
    _user_repo(db).audit(ctx.username, "tenant.invite_revoke", target_type="tenant",
                         target_id=ctx.tenant_id, detail={"invite": row.username})
    db.commit()
    return {"revoked": row.username}


@router.post("/invites/accept")
def accept_invite(
    body: InviteAccept,
    request: Request,
    db: Session = Depends(get_db_session),
):
    """Redeem an invite token.

    - invited user does not exist yet: the token + a policy-passing password
      provision the account (the invitee keeps their password private).
    - invited user exists: the caller must be signed in AS that username —
      a stolen token can never rebind or reset an existing identity.
    Seat quota is enforced at accept time (pending invites hold no seat).
    """
    t_repo = _tenant_repo(db)
    invite = t_repo.get_invite_by_raw(body.token)
    if invite is None or invite.is_dead:
        raise HTTPException(status_code=404,
                            detail="invite is invalid, expired, revoked or already used")
    tenant = t_repo.get(invite.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="invite tenant no longer exists")
    if tenant.status == "SUSPENDED":
        raise HTTPException(status_code=423, detail="This organization is suspended")

    users = _user_repo(db)
    existing = users.get_by_username(invite.username)
    if existing is not None:
        # must be signed in as the invited identity
        user = get_current_user(request)
        if user != invite.username:
            raise HTTPException(status_code=403,
                                detail="sign in as the invited username to accept this invite")
    else:
        from api.security.passwords import PasswordPolicyError, validate_password_policy

        if not body.password:
            raise HTTPException(status_code=422,
                                detail="set a password to create the invited account")
        try:
            validate_password_policy(body.password)
        except PasswordPolicyError as exc:
            raise HTTPException(status_code=422, detail=f"Weak password: {exc}")
        user = users.create_user(invite.username, hash_password(body.password),
                                 roles=["readonly"], email=invite.email)

    allowed, reason = quota_check(tenant.plan, "member_create",
                                  t_repo.member_count(tenant.id))
    if not allowed:
        raise HTTPException(status_code=402, detail=f"quota_exceeded: {reason}")
    try:
        membership = t_repo.accept_invite(body.token, actor=invite.username)
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    users.audit(invite.username, "tenant.invite_accept", target_type="tenant",
                target_id=tenant.id, detail={"role": membership.tenant_role},
                ip=request.client.host if request.client else None)
    db.commit()
    return {
        "tenant": {"id": tenant.id, "name": tenant.name, "slug": tenant.slug},
        "username": membership.username,
        "tenant_role": membership.tenant_role,
    }


# ------------------------------------------------------- platform administration

class SuspendRequest(BaseModel):
    reason: str = Field(..., min_length=4, max_length=500)


class PlanRequest(BaseModel):
    plan: str


@router.get("/admin/tenants")
def admin_list_tenants(
    user: str = Depends(require_roles("superadmin", "admin")),
    db: Session = Depends(get_db_session),
):
    t_repo = _tenant_repo(db)
    return {"tenants": [
        {
            "id": t.id, "name": t.name, "slug": t.slug, "plan": t.plan,
            "status": t.status, "created_at": t.created_at.isoformat(),
            "members": t_repo.member_count(t.id),
            "targets": t_repo.live_target_count(t.id),
            "scans_this_month": t_repo.month_usage(t.id, "scan_run"),
        }
        for t in t_repo.list_tenants()
    ]}


@router.post("/admin/tenants/{tenant_id}/suspend")
def admin_suspend(
    tenant_id: str,
    body: SuspendRequest,
    request: Request,
    user: str = Depends(require_roles("superadmin", "admin")),
    db: Session = Depends(get_db_session),
):
    row = _tenant_repo(db).set_status(tenant_id, "SUSPENDED", actor=user, reason=body.reason)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    _user_repo(db).audit(user, "tenant.suspend", target_type="tenant",
                         target_id=tenant_id, detail=body.reason,
                         ip=request.client.host if request.client else None,
                         outcome="DENY")
    db.commit()
    return {"tenant_id": tenant_id, "status": row.status,
            "note": "member requests now 423; daemon skips this tenant's targets"}


@router.post("/admin/tenants/{tenant_id}/restore")
def admin_restore(
    tenant_id: str,
    user: str = Depends(require_roles("superadmin", "admin")),
    db: Session = Depends(get_db_session),
):
    row = _tenant_repo(db).set_status(tenant_id, "ACTIVE", actor=user)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    _user_repo(db).audit(user, "tenant.restore", target_type="tenant", target_id=tenant_id)
    db.commit()
    return {"tenant_id": tenant_id, "status": row.status}


@router.post("/admin/tenants/{tenant_id}/plan")
def admin_set_plan(
    tenant_id: str,
    body: PlanRequest,
    user: str = Depends(require_roles("superadmin", "admin")),
    db: Session = Depends(get_db_session),
):
    if body.plan not in PLANS:
        raise HTTPException(status_code=422, detail=f"plan must be one of {list(PLANS)}")
    row = _tenant_repo(db).set_plan(tenant_id, body.plan, actor=user)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    _user_repo(db).audit(user, "tenant.plan_change", target_type="tenant",
                         target_id=tenant_id, detail=body.plan)
    db.commit()
    return {"tenant_id": tenant_id, "plan": row.plan}
