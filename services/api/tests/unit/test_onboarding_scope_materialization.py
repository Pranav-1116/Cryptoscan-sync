"""Authorized scope materialization: ranges are not probe targets, and
removing scope revokes what it materialized.

The onboarding registration previously turned every network scope entry —
including whole CIDRs like 10.0.0.0/16 — into an always-enabled TLS target in
the due-scan rotation, and scope deletion left those targets probing forever
(PRODUCTION-GAP-HANDOFF-2026-10-08.md, P0 "authorized/passive discovery").
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from db.connection import engine as engine_mod
from db.connection.session import SessionLocal
from db.models.network_scan_target import NetworkScanTarget
from db.repositories.onboarding_repository import OnboardingRepository


@pytest.fixture()
def session(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/onboarding.db")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine_mod._ENGINE = None
    import db.connection.session as session_mod

    session_mod.SessionLocal.configure(bind=engine_mod.get_engine())
    from db.models.base import BaseModel

    BaseModel.metadata.create_all(engine_mod.get_engine())
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _org_with_scope(session: Session, targets: list[tuple[str, str]]):
    repo = OnboardingRepository(session)
    org = repo.create_org("ScopeTest Bank")
    for kind, target in targets:
        repo.add_scope(org.id, kind, target)
    session.commit()
    return repo, org


def _targets(session: Session) -> dict[str, NetworkScanTarget]:
    return {
        t.endpoint: t
        for t in session.query(NetworkScanTarget).all()
    }


def test_cidr_scope_never_materializes_as_probe_target(session):
    """10.0.0.0/16 is authorization, not a probe target: registering it must
    not put it into the due-scan rotation as an enabled TLS target."""
    from api.routers.onboarding import _register_scope_into_engine

    repo, org = _org_with_scope(session, [("network", "10.0.0.0/16")])
    registered = _register_scope_into_engine(repo, org, repo.scope_summary(org.id), [])
    assert registered["network_targets"] == 0
    assert registered["network_scope_ranges"] == 1
    assert _targets(session) == {}  # nothing materialized


def test_concrete_host_scope_materializes_with_provenance(session):
    from api.routers.onboarding import _register_scope_into_engine

    repo, org = _org_with_scope(
        session, [("network", "10.0.0.7"), ("network", "hsm.bank.example")]
    )
    registered = _register_scope_into_engine(repo, org, repo.scope_summary(org.id), [])
    assert registered["network_targets"] == 2
    targets = _targets(session)
    assert set(targets) == {"10.0.0.7", "hsm.bank.example"}
    assert all(t.enabled for t in targets.values())
    assert all(t.source == "onboarding" for t in targets.values())


def test_vlan_and_snmp_references_stay_out(session):
    from api.routers.onboarding import _register_scope_into_engine

    repo, org = _org_with_scope(session, [("network", "vlan:ot-segment"),
                                          ("network", "snmp:10.0.0.9")])
    registered = _register_scope_into_engine(repo, org, repo.scope_summary(org.id), [])
    assert registered["network_targets"] == 0
    assert _targets(session) == {}


def test_scope_deletion_revokes_only_what_it_materialized(session):
    from api.routers.onboarding import (
        _register_scope_into_engine,
        _revoke_materialized_targets,
    )

    repo, org = _org_with_scope(session, [("network", "10.0.0.7")])
    _register_scope_into_engine(repo, org, repo.scope_summary(org.id), [])
    # an operator also hand-registers a different host
    session.add(NetworkScanTarget(endpoint="10.0.0.99", enabled=True, source="manual"))
    session.commit()

    entry = repo.list_scope(org.id)[0]
    repo.delete_scope_entry(entry.id)
    revoked = _revoke_materialized_targets(repo, org, entry)
    session.commit()

    assert revoked == ["10.0.0.7"]
    targets = _targets(session)
    assert targets["10.0.0.7"].enabled is False  # scope's target revoked
    assert targets["10.0.0.99"].enabled is True  # manual target untouched


def test_revocation_spares_target_still_declared_by_other_scope(session):
    from api.routers.onboarding import (
        _register_scope_into_engine,
        _revoke_materialized_targets,
    )

    repo, org = _org_with_scope(session, [("network", "10.0.0.7")])
    _register_scope_into_engine(repo, org, repo.scope_summary(org.id), [])
    # a second scope entry declares the same host
    repo.add_scope(org.id, "network", "10.0.0.7")
    session.commit()

    entries = repo.list_scope(org.id)
    repo.delete_scope_entry(entries[0].id)
    revoked = _revoke_materialized_targets(repo, org, entries[0])
    session.commit()

    assert revoked == []  # still authorized by the other entry
    assert _targets(session)["10.0.0.7"].enabled is True


def test_range_scope_deletion_has_nothing_to_revoke(session):
    from api.routers.onboarding import _revoke_materialized_targets

    repo, org = _org_with_scope(session, [("network", "10.0.0.0/16")])
    entry = repo.list_scope(org.id)[0]
    repo.delete_scope_entry(entry.id)
    assert _revoke_materialized_targets(repo, org, entry) == []
