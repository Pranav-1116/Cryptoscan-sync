"""Which tenant a request resolves to, and what happens when that is unclear.

fix.md item 9 lists these as their own categories: missing/ambiguous tenant
header, suspended tenant, known-ID lookup, API-key tenant binding, and
supervisor/platform scope. They were untested. That mattered, because the
cross-tenant leak found earlier today was not a filtering bug at all -- the
ORM guard worked correctly throughout. It was a *resolution* bug: refusals
here were swallowed into "no scope", and no scope means every tenant's rows.

So these exercise _resolve_tenant_context directly, against real repositories
and a real schema rather than mocks. A mocked membership lookup would have
happily reproduced the bug.

Each refusal asserts its specific status, because the statuses carry meaning:
404 rather than 403 for a foreign tenant is deliberate (no existence oracle
for the tenant registry), and collapsing them would leak the registry.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import _resolve_tenant_context
from db.connection.session import Base
from db.repositories.tenant_repository import TenantRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()
    engine.dispose()


def _request(tenant_header: str | None = None, *, key_tenant: str | None = None):
    """A request stub carrying only what resolution reads."""
    headers = {}
    if tenant_header is not None:
        headers["x-tenant-id"] = tenant_header
    state = SimpleNamespace()
    if key_tenant is not None:
        state.tenant_id = key_tenant
    return SimpleNamespace(headers=headers, cookies={}, state=state)


def _user(db, username: str, roles: list[str] | None = None):
    UserRepository(db).create_user(username, "x" * 60, roles=roles or ["viewer"])
    return username


def _tenant(db, name: str, slug: str, *, status: str = "ACTIVE"):
    repo = TenantRepository(db)
    row = repo.create(name=name, slug=slug)
    if status != "ACTIVE":
        row.status = status
        db.commit()
    return row


# --------------------------------------------------------------------------- #
# ambiguous / missing header
# --------------------------------------------------------------------------- #

def test_one_membership_resolves_without_a_header(db):
    user = _user(db, "solo")
    t = _tenant(db, "Bank A", "bank-a")
    TenantRepository(db).add_member(t.id, user, "member")

    ctx = _resolve_tenant_context(_request(), user, db)
    assert ctx.tenant_id == t.id
    assert ctx.is_platform_admin is False


def test_two_memberships_without_a_header_is_refused_not_guessed(db):
    """The bug that leaked the estate: this used to fall through to no scope.

    A member of two tenants sending no X-Tenant-ID is genuinely ambiguous.
    Picking one would be wrong; proceeding unscoped is far worse, because
    outside a scope the ORM guard is inert and the request reads everything.
    """
    user = _user(db, "dual")
    a = _tenant(db, "Bank A", "bank-a")
    b = _tenant(db, "Bank B", "bank-b")
    TenantRepository(db).add_member(a.id, user, "member")
    TenantRepository(db).add_member(b.id, user, "member")

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request(), user, db)
    assert caught.value.status_code == 400
    assert "X-Tenant-ID" in str(caught.value.detail)


def test_two_memberships_with_a_header_resolve_to_the_named_one(db):
    user = _user(db, "dual2")
    a = _tenant(db, "Bank A", "bank-a")
    b = _tenant(db, "Bank B", "bank-b")
    TenantRepository(db).add_member(a.id, user, "member")
    TenantRepository(db).add_member(b.id, user, "member")

    assert _resolve_tenant_context(_request(b.id), user, db).tenant_id == b.id


def test_no_membership_at_all_is_403(db):
    user = _user(db, "orphan")
    _tenant(db, "Bank A", "bank-a")

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request(), user, db)
    assert caught.value.status_code == 403


# --------------------------------------------------------------------------- #
# known-ID lookup: a foreign tenant must not be confirmed to exist
# --------------------------------------------------------------------------- #

def test_a_members_request_for_a_foreign_tenant_is_404_not_403(db):
    """404 and 403 must not be distinguishable, or the header becomes an oracle.

    A 403 would confirm "that tenant exists, you just cannot have it", which
    lets an attacker enumerate the customer list one id at a time.
    """
    user = _user(db, "curious")
    mine = _tenant(db, "Bank A", "bank-a")
    theirs = _tenant(db, "Bank B", "bank-b")
    TenantRepository(db).add_member(mine.id, user, "member")

    with pytest.raises(HTTPException) as real_but_foreign:
        _resolve_tenant_context(_request(theirs.id), user, db)

    with pytest.raises(HTTPException) as entirely_invented:
        _resolve_tenant_context(_request("99999999-9999-9999-9999-999999999999"), user, db)

    assert real_but_foreign.value.status_code == 404
    assert entirely_invented.value.status_code == 404
    assert str(real_but_foreign.value.detail) == str(entirely_invented.value.detail), (
        "a real-but-foreign tenant answers differently from an invented one, "
        "which turns X-Tenant-ID into an existence oracle for the customer list"
    )


# --------------------------------------------------------------------------- #
# suspended tenant
# --------------------------------------------------------------------------- #

def test_a_suspended_tenant_is_423_for_its_own_member(db):
    user = _user(db, "member-of-suspended")
    t = _tenant(db, "Bank S", "bank-s", status="SUSPENDED")
    TenantRepository(db).add_member(t.id, user, "member")

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request(), user, db)
    assert caught.value.status_code == 423


def test_suspension_is_refused_rather_than_downgraded_to_no_scope(db):
    """A suspended tenant must never resolve to tenant_id=None.

    None means "platform estate" to the guard, so a downgrade here would hand
    a suspended customer a wider view than an active one.
    """
    user = _user(db, "suspended-user")
    t = _tenant(db, "Bank S2", "bank-s2", status="SUSPENDED")
    TenantRepository(db).add_member(t.id, user, "member")

    with pytest.raises(HTTPException):
        _resolve_tenant_context(_request(), user, db)


# --------------------------------------------------------------------------- #
# API-key tenant binding
# --------------------------------------------------------------------------- #

def test_a_keys_tenant_binding_wins_over_the_header(db):
    """The binding is the tenancy for a machine principal; a lying header loses."""
    t = _tenant(db, "Bank K", "bank-k")
    ctx = _resolve_tenant_context(_request(key_tenant=t.id), "svc", db)
    assert ctx.tenant_id == t.id


def test_a_header_contradicting_the_keys_tenant_is_403(db):
    a = _tenant(db, "Bank A", "bank-a")
    b = _tenant(db, "Bank B", "bank-b")

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request(b.id, key_tenant=a.id), "svc", db)
    assert caught.value.status_code == 403
    assert "different tenant" in str(caught.value.detail)


def test_a_key_bound_to_a_suspended_tenant_is_423(db):
    t = _tenant(db, "Bank KS", "bank-ks", status="SUSPENDED")

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request(key_tenant=t.id), "svc", db)
    assert caught.value.status_code == 423


def test_a_key_bound_to_a_deleted_tenant_is_404(db):
    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(
            _request(key_tenant="00000000-0000-0000-0000-000000000000"), "svc", db)
    assert caught.value.status_code == 404


# --------------------------------------------------------------------------- #
# supervisor / platform scope
# --------------------------------------------------------------------------- #

def test_a_superadmin_without_a_header_sees_the_platform_estate(db):
    user = _user(db, "root", roles=["superadmin"])
    ctx = _resolve_tenant_context(_request(), user, db)
    assert ctx.tenant_id is None
    assert ctx.is_platform_admin is True


def test_a_superadmin_can_scope_into_a_named_tenant(db):
    user = _user(db, "root2", roles=["superadmin"])
    t = _tenant(db, "Bank A", "bank-a")

    ctx = _resolve_tenant_context(_request(t.id), user, db)
    assert ctx.tenant_id == t.id
    assert ctx.is_platform_admin is True


def test_a_superadmin_naming_a_tenant_that_does_not_exist_is_404(db):
    user = _user(db, "root3", roles=["superadmin"])

    with pytest.raises(HTTPException) as caught:
        _resolve_tenant_context(_request("11111111-2222-3333-4444-555555555555"), user, db)
    assert caught.value.status_code == 404


def test_an_ordinary_member_cannot_reach_the_platform_estate(db):
    """Only a superadmin resolves to tenant_id=None with a membership present."""
    user = _user(db, "plain")
    t = _tenant(db, "Bank A", "bank-a")
    TenantRepository(db).add_member(t.id, user, "member")

    ctx = _resolve_tenant_context(_request(), user, db)
    assert ctx.tenant_id == t.id, "an ordinary member resolved to the unfiltered estate"
    assert ctx.is_platform_admin is False
