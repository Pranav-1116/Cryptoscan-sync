"""PQC Migration Intelligence API — the acceptance rows of the plan register.

The register (shared_models.state_machines) is the authority for every state
write here. These tests pin the rows that matter:

- a recorded progress claim is never progress proven;
- a verified verdict without an evidence reference is refused;
- a wave is verified only over verified progress records — nothing promotes it;
- accepted is a recorded decision, never a silent close;
- illegal transitions and self-loops are refused;
- every write is authenticated.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    from db.models.pqc_migration import (
        PqcInteropNote,
        PqcMigrationBlocker,
        PqcMigrationWave,
        PqcProgressRecord,
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'pqc.db'}")
    Base.metadata.create_all(engine, tables=[
        PqcMigrationWave.__table__,
        PqcMigrationBlocker.__table__,
        PqcInteropNote.__table__,
        PqcProgressRecord.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def api(session):
    from api import dependencies
    from api.routers import pqc_migration

    app = FastAPI()
    app.include_router(pqc_migration.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_auditor] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_admin] = lambda: "admin"
    return TestClient(app)


@pytest.fixture()
def anonymous(session):
    """A client whose only override is the DB — writes must still be refused."""
    from api import dependencies
    from api.routers import pqc_migration

    app = FastAPI()
    app.include_router(pqc_migration.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def make_wave(api, key="wave-1", title="Consolidate TLS terminators"):
    r = api.post("/api/pqc-migration/waves",
                 json={"wave_key": key, "title": title,
                       "scope_note": "edge TLS", "planned_window": "2027 H1"})
    assert r.status_code == 200, r.text
    return r.json()


class TestWorkspace:

    def test_an_empty_workspace_is_absence_not_health(self, api):
        body = api.get("/api/pqc-migration/workspace").json()
        assert body["waves"] == [] and body["progress"] == []
        assert body["summary"]["wave_count"] == 0
        assert body["summary"]["progress_verified"] == 0
        # honesty is stated even when the register is empty
        assert "not progress proven" in body["summary"]["honesty"]

    def test_workspace_reports_every_register(self, api):
        make_wave(api)
        api.post("/api/pqc-migration/waves/wave-1/progress",
                 json={"claim": "six terminators on ML-KEM", "evidence_ids": ["ev-1"]})
        body = api.get("/api/pqc-migration/workspace").json()
        assert body["summary"]["wave_count"] == 1
        assert body["summary"]["progress_recorded"] == 1
        assert body["progress"][0]["claim_is_not_proof"] is True


class TestWaveLifecycle:

    def test_a_wave_starts_planned_because_a_plan_is_never_progress(self, api):
        row = make_wave(api)
        assert row["status"] == "planned"

    def test_a_direct_planned_to_verified_move_is_refused(self, api):
        make_wave(api)
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "verified"})
        assert r.status_code == 409
        assert "not a transition the code makes" in r.json()["detail"]

    def test_self_loops_are_not_transitions(self, api):
        make_wave(api)
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "planned"})
        assert r.status_code == 409
        assert "self-loops are not transitions" in r.json()["detail"]

    def test_a_wave_is_verified_only_over_verified_progress(self, api):
        make_wave(api)
        api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "active"})
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "verified"})
        assert r.status_code == 409
        assert "not verified" in r.json()["detail"]

    def test_a_wave_verifies_when_every_claim_is_verified(self, api):
        make_wave(api)
        api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "active"})
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "terminators done", "evidence_ids": ["ev-9"]}).json()
        api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                 json={"to": "verified", "evidence_ids": ["ev-9"]})
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "verified"})
        assert r.status_code == 200
        assert r.json()["status"] == "verified"

    def test_an_unverified_claim_blocks_the_wave_even_when_others_verify(self, api):
        make_wave(api)
        api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "active"})
        p1 = api.post("/api/pqc-migration/waves/wave-1/progress",
                      json={"claim": "done part", "evidence_ids": ["ev-1"]}).json()
        api.post("/api/pqc-migration/waves/wave-1/progress",
                 json={"claim": "unproven part", "evidence_ids": []})
        api.post(f"/api/pqc-migration/progress/{p1['id']}/transition",
                 json={"to": "verified", "evidence_ids": ["ev-1"]})
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "verified"})
        assert r.status_code == 409
        assert "1 of 2 claims are not verified" in r.json()["detail"]

    def test_a_blocked_wave_resumes(self, api):
        make_wave(api)
        api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "active"})
        api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "blocked"})
        r = api.post("/api/pqc-migration/waves/wave-1/transition", json={"to": "active"})
        assert r.status_code == 200
        assert r.json()["status"] == "active"


class TestProgressVerdicts:

    def test_a_recorded_claim_is_not_progress_proven(self, api):
        make_wave(api)
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "pilot complete", "evidence_ids": []}).json()
        assert p["verification_status"] == "recorded"
        assert p["claim_is_not_proof"] is True

    def test_verified_without_an_evidence_reference_is_refused(self, api):
        make_wave(api)
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "pilot complete", "evidence_ids": []}).json()
        r = api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                     json={"to": "verified", "evidence_ids": []})
        assert r.status_code == 422
        assert "verdict without evidence is refused" in r.json()["detail"]

    def test_verified_with_evidence_records_the_verifier(self, api):
        make_wave(api)
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "pilot complete", "evidence_ids": ["ev-1"]}).json()
        r = api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                     json={"to": "verified", "evidence_ids": ["ev-2"]})
        assert r.status_code == 200
        out = r.json()
        assert out["verification_status"] == "verified"
        assert out["verified_by"] == "auditor"
        assert set(out["evidence_ids"]) == {"ev-1", "ev-2"}

    def test_refuted_is_a_failure_of_the_claim_counted(self, api):
        make_wave(api)
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "pilot complete", "evidence_ids": []}).json()
        r = api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                     json={"to": "refuted", "note": "rescan shows no change"})
        assert r.status_code == 200
        assert r.json()["verification_status"] == "refuted"

    def test_a_withdrawn_verdict_goes_stale_and_can_be_reverified(self, api):
        make_wave(api)
        p = api.post("/api/pqc-migration/waves/wave-1/progress",
                     json={"claim": "pilot complete", "evidence_ids": ["ev-1"]}).json()
        api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                 json={"to": "verified", "evidence_ids": ["ev-1"]})
        r = api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                     json={"to": "stale", "note": "evidence ev-1 withdrawn"})
        assert r.json()["verification_status"] == "stale"
        r = api.post(f"/api/pqc-migration/progress/{p['id']}/transition",
                     json={"to": "verified", "evidence_ids": ["ev-7"]})
        assert r.json()["verification_status"] == "verified"


class TestBlockersAndInterop:

    def test_a_blocker_is_open_by_construction(self, api):
        make_wave(api)
        b = api.post("/api/pqc-migration/waves/wave-1/blockers",
                     json={"title": "HSM firmware lacks ML-KEM", "detail": "vendor ETA unknown"}).json()
        assert b["state"] == "open"
        assert b["raised_by"] == "auditor"

    def test_accepted_is_a_recorded_decision_never_a_silent_close(self, api):
        make_wave(api)
        b = api.post("/api/pqc-migration/waves/wave-1/blockers",
                     json={"title": "legacy payment HSM", "detail": ""}).json()
        r = api.post(f"/api/pqc-migration/blockers/{b['id']}/transition",
                     json={"to": "accepted", "note": "risk accepted by CISO, review 2027-06"})
        out = r.json()
        assert out["state"] == "accepted"
        assert out["resolved_by"] == "auditor"
        assert "CISO" in out["resolution_note"]

    def test_a_returned_blocker_reopens(self, api):
        make_wave(api)
        b = api.post("/api/pqc-migration/waves/wave-1/blockers",
                     json={"title": "vendor interop", "detail": ""}).json()
        api.post(f"/api/pqc-migration/blockers/{b['id']}/transition", json={"to": "cleared"})
        r = api.post(f"/api/pqc-migration/blockers/{b['id']}/transition",
                     json={"to": "open", "note": "regression in peer build"})
        out = r.json()
        assert out["state"] == "open"
        assert out["resolved_by"] is None

    def test_interop_notes_carry_their_evidence(self, api):
        make_wave(api)
        n = api.post("/api/pqc-migration/waves/wave-1/interop",
                     json={"peer_system": "CLS settlement gateway",
                           "protocol": "TLS 1.3 hybrid", "note": "handshake OK in lab",
                           "evidence_ids": ["ev-4"]}).json()
        assert n["peer_system"] == "CLS settlement gateway"
        assert n["evidence_ids"] == ["ev-4"]


class TestAuthorization:

    def test_every_write_is_authenticated(self, anonymous, session):
        for method, path, body in [
            ("post", "/api/pqc-migration/waves", {"wave_key": "w", "title": "t"}),
            ("post", "/api/pqc-migration/waves/w/transition", {"to": "active"}),
            ("post", "/api/pqc-migration/waves/w/progress", {"claim": "c"}),
            ("post", "/api/pqc-migration/progress/x/transition", {"to": "verified"}),
            ("post", "/api/pqc-migration/waves/w/blockers", {"title": "b"}),
            ("post", "/api/pqc-migration/blockers/x/transition", {"to": "cleared"}),
            ("post", "/api/pqc-migration/waves/w/interop", {"peer_system": "p"}),
        ]:
            r = getattr(anonymous, method)(path, json=body)
            assert r.status_code in (401, 403), (path, r.status_code)
        from db.models.pqc_migration import PqcMigrationWave, PqcProgressRecord
        assert session.query(PqcMigrationWave).count() == 0
        assert session.query(PqcProgressRecord).count() == 0
