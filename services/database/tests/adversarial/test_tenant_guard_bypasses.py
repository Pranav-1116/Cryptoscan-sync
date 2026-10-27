"""Adversarial battery: escape hatches out of the tenant guard.

The original tenancy tests exercise the happy paths — ORM selects, repository
calls, bulk writes shaped the way production code shapes them. This battery
attacks the guard from the outside instead: every statement shape that does
NOT carry an ORM mapper, plus the flush-path writes that bypass
``before_flush``. Each case below was an actual read or write bypass against
the pre-hardening guard (verified empirically before the fix), not a
theoretical concern:

* ``session.execute(text("select * from scans"))`` returned every tenant's
  rows — ``with_loader_criteria`` never sees a TextClause.
* ``update(Scan.__table__).where(Scan.__table__.c.target_location == ...)``
  rewrote another tenant's row — the DML predicate branch early-returns when
  a statement carries no mappers, and pure-Core statements carry none.
* ``session.execute(insert(Model).values(rows))`` skipped ``before_flush``
  entirely, so unstamped rows landed as platform estate, visible to every
  tenant.

The guard now fails closed on all three shapes. These tests keep it that way.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, delete, exists, func, insert, select, text, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.models.user import User
from db.tenancy import (
    TenantScopeViolation,
    install_tenant_guard,
    platform_scope,
    scoped_tables,
    tenant_scope,
)

BANK_A = "11111111-1111-1111-1111-111111111111"
BANK_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def session():
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()
    engine.dispose()


def _seed(session) -> None:
    for tenant, target in ((BANK_A, "bank-a-core"), (BANK_B, "bank-b-core")):
        session.add(Scan(id=f"scan-{tenant[:8]}", target_location=target, status="COMPLETED",
                         tenant_id=tenant, scan_start=datetime.now(timezone.utc)))
    session.add(Scan(id="scan-platform", target_location="legacy", status="COMPLETED",
                     tenant_id=None, scan_start=datetime.now(timezone.utc)))
    session.add(User(username="u1", password_hash="x"))
    session.commit()


# --------------------------------------------------------------------- #
# raw textual SQL
# --------------------------------------------------------------------- #

def test_raw_text_select_touching_a_scoped_table_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(text("SELECT id FROM scans"))


def test_raw_text_update_touching_a_scoped_table_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation):
            session.execute(text("UPDATE scans SET target_location = 'pwned'"))


def test_raw_text_delete_touching_a_scoped_table_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation):
            session.execute(text("DELETE FROM scans"))


def test_raw_text_cannot_hide_a_scoped_table_in_a_subquery(session):
    """The guard matches compiled SQL, not just top-level FROM clauses."""
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation):
            session.execute(text("SELECT (SELECT count(*) FROM scans) AS n FROM users"))


def test_scoped_table_name_as_a_substring_is_not_a_false_positive(session):
    _seed(session)
    with tenant_scope(BANK_A):
        # 'scans' inside 'scan_statistics' (word characters continue) must not
        # match the \bscans\b pattern — unscoped auxiliary SQL stays usable.
        session.execute(text("SELECT 1 AS audit_scans_total"))


# --------------------------------------------------------------------- #
# pure-Core statements (Table.c columns only, no ORM attributes)
# --------------------------------------------------------------------- #

def test_core_select_built_from_table_columns_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(select(Scan.__table__))


def test_core_update_with_where_on_table_columns_only_raises(session):
    """The exact statement shape that cross-tenant-wrote before the fix."""
    _seed(session)
    with tenant_scope(BANK_A):
        stmt = update(Scan.__table__).where(Scan.__table__.c.target_location == "bank-b-core")
        with pytest.raises(TenantScopeViolation):
            session.execute(stmt)


def test_core_delete_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation):
            session.execute(delete(Scan.__table__))


def test_core_select_with_scoped_table_in_a_subquery_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        inner = select(Scan.__table__.c.id).scalar_subquery()
        with pytest.raises(TenantScopeViolation):
            session.execute(select(User.username, inner.label("sid")))


# --------------------------------------------------------------------- #
# ORM-shaped statements embedding Core fragments
# --------------------------------------------------------------------- #

def test_orm_select_with_core_scalar_subquery_raises(session):
    """with_loader_criteria never reaches a Table.c-built subquery."""
    _seed(session)
    with tenant_scope(BANK_A):
        count = select(func.count(Scan.__table__.c.id)).scalar_subquery()
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(select(User.username, count.label("n")))


def test_orm_in_clause_with_core_subquery_over_the_same_table_raises(session):
    """The ORM reference at the outer level must not mask the inner one."""
    _seed(session)
    with tenant_scope(BANK_A):
        stmt = select(Scan.id).where(Scan.id.in_(select(Scan.__table__.c.id)))
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.scalars(stmt).all()


def test_core_exists_embedded_in_an_orm_statement_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        probe = exists(select(Scan.__table__.c.id))
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(select(User.username).where(probe))


def test_core_select_from_table_inside_orm_select_raises(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(select(func.count()).select_from(Scan.__table__))


def test_orm_join_to_a_bare_table_raises(session):
    """Joining a scoped Table (not the entity) bypasses the loader criteria."""
    _seed(session)
    with tenant_scope(BANK_A):
        stmt = select(User.username).join(Scan.__table__, User.username == Scan.__table__.c.operator)
        with pytest.raises(TenantScopeViolation, match="scans"):
            session.execute(stmt).fetchall()


def test_legitimate_orm_subqueries_still_work(session):
    """Embedded ORM subqueries DO receive the propagated criteria — allowed."""
    _seed(session)
    with tenant_scope(BANK_A):
        ids = session.scalars(select(Scan.id).where(Scan.id.in_(select(Scan.id)))).all()
        assert len(ids) == 2  # bank A's row + the platform row
        count = select(func.count(Scan.id)).scalar_subquery()
        row = session.execute(select(User.username, count.label("n"))).mappings().first()
        assert row["n"] == 2  # not 3: bank B's row is filtered inside the subquery


def test_orm_count_select_from_entity_still_works(session):
    """The repository workhorse shape (list_scans pagination count)."""
    _seed(session)
    with tenant_scope(BANK_A):
        assert session.execute(select(func.count()).select_from(Scan)).scalar_one() == 2


# --------------------------------------------------------------------- #
# no false positives: unscoped tables and the ORM stay fully usable
# --------------------------------------------------------------------- #

def test_raw_sql_against_an_unscoped_table_still_works(session):
    """Isolation must not break platform tables (users, tenants, ...)."""
    _seed(session)
    with tenant_scope(BANK_A):
        count = session.execute(text("SELECT count(*) FROM users")).scalar_one()
        assert count == 1
        rows = session.execute(select(User.__table__)).fetchall()
        assert len(rows) == 1


def test_orm_shaped_table_update_is_filtered_not_raised(session):
    """update(Table).where(ORM attribute) is ORM-aware: still filtered to 0."""
    _seed(session)
    other = session.execute(text("SELECT id FROM scans WHERE target_location = 'bank-b-core'")).scalar_one()
    with tenant_scope(BANK_A):
        stmt = update(Scan.__table__).where(Scan.id == other).values(status="RUNNING")
        # Must not raise — and must not touch the other tenant's row.
        result = session.execute(stmt)
        session.commit()
    assert result.rowcount == 0
    status = session.execute(text("SELECT status FROM scans WHERE id = :i"), {"i": other}).scalar_one()
    assert status == "COMPLETED"


def test_platform_scope_is_the_greppable_opt_out_for_raw_sql(session):
    _seed(session)
    with tenant_scope(BANK_A):
        with platform_scope():
            ids = session.execute(text("SELECT count(*) FROM scans")).scalar_one()
            assert ids == 3  # every row, deliberately, as a platform operator
        # The bypass is scoped: back inside the tenant it fails closed again.
        with pytest.raises(TenantScopeViolation):
            session.execute(text("SELECT count(*) FROM scans"))


# --------------------------------------------------------------------- #
# bulk INSERT: the before_flush bypass
# --------------------------------------------------------------------- #

def test_bulk_orm_insert_is_stamped_with_the_active_tenant(session):
    """execute(insert(Model), rows) skips before_flush — the guard stamps it."""
    _seed(session)
    with tenant_scope(BANK_B):
        session.execute(insert(Scan).values([
            dict(id="bulk-1", target_location="b1", status="COMPLETED",
                 scan_start=datetime.now(timezone.utc)),
            dict(id="bulk-2", target_location="b2", status="COMPLETED",
                 scan_start=datetime.now(timezone.utc)),
        ]))
        session.commit()
    rows = {r.id: r.tenant_id for r in session.execute(text("SELECT id, tenant_id FROM scans")).fetchall()}
    assert rows["bulk-1"] == BANK_B
    assert rows["bulk-2"] == BANK_B


def test_bulk_insert_with_a_single_row_in_list_form_is_stamped(session):
    """One dict inside a list is the multi-values format, not single-values."""
    _seed(session)
    with tenant_scope(BANK_B):
        session.execute(insert(Scan).values([
            dict(id="solo-1", target_location="solo", status="COMPLETED",
                 scan_start=datetime.now(timezone.utc)),
        ]))
        session.commit()
    tenant = session.execute(text("SELECT tenant_id FROM scans WHERE id = 'solo-1'")).scalar_one()
    assert tenant == BANK_B


def test_bulk_insert_with_a_foreign_claim_is_rejected(session):
    _seed(session)
    with tenant_scope(BANK_B):
        with pytest.raises(TenantScopeViolation, match="claims tenant"):
            session.execute(insert(Scan).values([
                dict(id="bulk-3", tenant_id=BANK_A, target_location="evil",
                     status="COMPLETED", scan_start=datetime.now(timezone.utc)),
            ]))
        session.rollback()


def test_single_value_orm_insert_is_stamped_too(session):
    _seed(session)
    with tenant_scope(BANK_B):
        session.execute(insert(Scan).values(id="single-1", target_location="s1",
                                            status="COMPLETED",
                                            scan_start=datetime.now(timezone.utc)))
        session.commit()
    tenant = session.execute(text("SELECT tenant_id FROM scans WHERE id = 'single-1'")).scalar_one()
    assert tenant == BANK_B


def test_bulk_insert_into_an_unscoped_table_is_untouched(session):
    with tenant_scope(BANK_B):
        session.execute(insert(User).values(username="core-insert", password_hash="x"))
        session.commit()
    assert session.execute(text("SELECT count(*) FROM users")).scalar_one() == 1


# --------------------------------------------------------------------- #
# identity-map hardening
# --------------------------------------------------------------------- #

def test_session_get_respects_a_scope_installed_after_the_load(session):
    """A row loaded unscoped must not be served from the identity map later."""
    _seed(session)
    other_id = session.execute(
        text("SELECT id FROM scans WHERE target_location = 'bank-b-core'")).scalar_one()
    assert session.get(Scan, other_id) is not None  # platform view, no scope
    with tenant_scope(BANK_A):
        assert session.get(Scan, other_id) is None


# --------------------------------------------------------------------- #
# registry conformance: every scoped model, not just Scan
# --------------------------------------------------------------------- #

def test_scoped_table_registry_covers_every_tenant_scoped_model():
    """__init_subclass__ registration must track the real model registry."""
    from db.connection.session import Base  # noqa: F401  (loads every model)
    registry = Base.registry
    scoped = {
        mapper.class_.__tablename__
        for mapper in registry.mappers
        if getattr(mapper.class_, "__tablename__", None)
        and "tenant_id" in getattr(mapper.class_, "__table__", None).columns
    }
    assert scoped, "no scoped models found — registry walk is broken"
    missing = scoped - scoped_tables()
    assert not missing, f"models whose table escaped the Core guard: {sorted(missing)}"


@pytest.mark.parametrize("table_name", sorted([
    "scans", "evidence_records", "crypto_assets", "systems", "monitor_targets",
]))
def test_repr_of_guard_covers_the_core_scan_surface(table_name):
    """Spot-check that the highest-value tables are in the guard's registry."""
    assert table_name in scoped_tables()
