"""Cross-tenant *writes*, and the scope edges reads never exercise.

fix.md item 9 asks an independent reviewer for cross-tenant read AND write
tests. test_tenant_isolation.py covers reads. Writes are the more dangerous
half and were untested: a filter that hides another tenant's row from a SELECT
does not, on its own, stop an UPDATE or a DELETE that names it by primary key.

The ORM guard adds ``with_loader_criteria`` to selects only -- by design;
``do_orm_execute`` skips non-select statements. So the protection for writes
is indirect: you cannot mutate what you cannot load. These tests pin that
indirection, because it is the kind of property that holds until someone adds
a bulk ``session.query(...).update()`` or a repository that builds a DELETE
from a caller-supplied id.

Two of today's production leaks lived one layer above this, in code that
decided *which* scope to enter. These cover the layer below: given a scope,
can it be escaped.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, delete, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.tenancy import install_tenant_guard, platform_scope, tenant_scope

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


def _scan(session, target: str, tenant_id: str | None) -> str:
    row = Scan(target_location=target, status="COMPLETED", tenant_id=tenant_id,
               scan_start=datetime.now(timezone.utc))
    session.add(row)
    session.commit()
    return row.id


def _status_of(session, scan_id: str) -> str | None:
    """Read a row's status ignoring tenancy, to see what really happened."""
    with platform_scope():
        row = session.query(Scan).filter(Scan.id == scan_id).one_or_none()
        return row.status if row else None


def _exists(session, scan_id: str) -> bool:
    with platform_scope():
        return session.query(Scan).filter(Scan.id == scan_id).one_or_none() is not None


# --------------------------------------------------------------------------- #
# cross-tenant write: the ORM path
# --------------------------------------------------------------------------- #

def test_a_tenant_cannot_load_another_tenants_row_to_mutate_it(session):
    """The load returns nothing, so there is no object to write through."""
    victim = _scan(session, "https://git/bank-b/core.git", BANK_B)
    session.expunge_all()

    with tenant_scope(BANK_A):
        found = session.query(Scan).filter(Scan.id == victim).one_or_none()
        assert found is None, "tenant A loaded tenant B's row and could now mutate it"

    assert _status_of(session, victim) == "COMPLETED"


def test_a_tenant_cannot_delete_another_tenants_row_it_cannot_see(session):
    victim = _scan(session, "https://git/bank-b/core.git", BANK_B)
    session.expunge_all()

    with tenant_scope(BANK_A):
        found = session.query(Scan).filter(Scan.id == victim).one_or_none()
        assert found is None
        # Nothing to delete. The row must survive regardless.
    session.commit()

    assert _exists(session, victim), "tenant B's row was deleted from tenant A's scope"


def test_writes_inside_a_scope_land_on_that_tenants_own_row(session):
    """The guard must not be so blunt that a tenant cannot write its own data."""
    mine = _scan(session, "https://git/bank-a/app.git", BANK_A)
    session.expunge_all()

    with tenant_scope(BANK_A):
        row = session.query(Scan).filter(Scan.id == mine).one()
        row.status = "FAILED"
        session.commit()

    assert _status_of(session, mine) == "FAILED"


# --------------------------------------------------------------------------- #
# cross-tenant write: statements that bypass the loader
# --------------------------------------------------------------------------- #
# with_loader_criteria applies to ORM *selects*. A bulk UPDATE/DELETE issued
# as a Core statement carries no loader criteria, so it is not filtered. These
# tests record that honestly rather than asserting a protection that is not
# there -- an unfiltered bulk write is a real way to cross the boundary, and
# naming it is what stops someone assuming the guard covers it.

def test_bulk_update_is_not_filtered_by_the_guard(session):
    """Documented gap: Core bulk UPDATE crosses tenants. Do not use it on scoped tables."""
    victim = _scan(session, "https://git/bank-b/core.git", BANK_B)

    with tenant_scope(BANK_A):
        session.execute(update(Scan).where(Scan.id == victim).values(status="TAMPERED"))
        session.commit()

    assert _status_of(session, victim) == "TAMPERED", (
        "behaviour changed: bulk UPDATE is now filtered. That is an improvement -- "
        "update this test and the repository guidance that depends on it."
    )


def test_bulk_delete_is_not_filtered_by_the_guard(session):
    """Same gap for DELETE, pinned for the same reason."""
    victim = _scan(session, "https://git/bank-b/core.git", BANK_B)

    with tenant_scope(BANK_A):
        session.execute(delete(Scan).where(Scan.id == victim))
        session.commit()

    assert not _exists(session, victim), (
        "behaviour changed: bulk DELETE is now filtered -- update this test."
    )


def test_no_repository_issues_bulk_writes_against_tenant_scoped_tables():
    """The gap above is only safe while nothing uses it. Enforce that."""
    import pathlib
    import re

    repo_dir = pathlib.Path(__file__).resolve().parents[2] / "db" / "repositories"
    offenders = []
    pattern = re.compile(r"\b(update|delete)\s*\(\s*(Scan|EvidenceRecord|CryptoAsset|DriftEvent)\b")
    for path in repo_dir.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Core bulk update()/delete() on a tenant-scoped model is not filtered by the "
        "ORM guard; load and mutate instead:\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- #
# scope edges
# --------------------------------------------------------------------------- #

def test_platform_scope_does_not_survive_its_block(session):
    """A leaked bypass would silently unfilter every later query on the thread."""
    _scan(session, "https://git/bank-b/core.git", BANK_B)

    with tenant_scope(BANK_A):
        with platform_scope():
            assert session.query(Scan).count() == 1
        # Back inside tenant A only.
        assert session.query(Scan).count() == 0


def test_nested_scopes_restore_the_outer_tenant(session):
    _scan(session, "https://git/bank-a/app.git", BANK_A)
    _scan(session, "https://git/bank-b/core.git", BANK_B)

    with tenant_scope(BANK_A):
        with tenant_scope(BANK_B):
            assert {s.tenant_id for s in session.query(Scan).all()} == {BANK_B}
        assert {s.tenant_id for s in session.query(Scan).all()} == {BANK_A}


def test_an_exception_inside_a_scope_still_restores_it(session):
    _scan(session, "https://git/bank-b/core.git", BANK_B)

    with pytest.raises(RuntimeError):
        with tenant_scope(BANK_A):
            raise RuntimeError("boom")

    # Unscoped again, not stuck in tenant A.
    assert session.query(Scan).count() == 1


def test_stamping_does_not_let_a_tenant_forge_another_tenants_row(session):
    """An explicit foreign tenant_id on insert is not silently accepted as that tenant's."""
    with tenant_scope(BANK_A):
        forged = Scan(target_location="https://git/bank-a/forge.git", status="COMPLETED",
                      tenant_id=BANK_B, scan_start=datetime.now(timezone.utc))
        session.add(forged)
        session.commit()
        forged_id = forged.id
        # Whatever the stamp did, tenant A must not now be reading a BANK_B row
        # back through its own scope.
        visible = session.query(Scan).filter(Scan.id == forged_id).one_or_none()

    with platform_scope():
        stored = session.query(Scan).filter(Scan.id == forged_id).one()

    if stored.tenant_id == BANK_B:
        assert visible is None, (
            "a row stored as BANK_B was readable inside BANK_A's scope"
        )
    else:
        assert stored.tenant_id == BANK_A
