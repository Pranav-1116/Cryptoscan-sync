"""Migration execution engine — end-to-end through the real API.

Round 30 (advanced/61 §4.2+§5, deep/29 §9.2): dependency-aware task
ordering, gated starts, wave advance, rollback cascade, and
system-edge auto-derivation.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.system import System
from db.models.system_dependency import SystemDependency

pytestmark = pytest.mark.asyncio


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "planner"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


async def _client():
    app, _session, _engine = _make_app()
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _add_task(client, project_id, title, **extra):
    body = {"title": title, **extra}
    r = await client.post(f"/api/v1/migrations/{project_id}/tasks", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def test_execution_engine_lifecycle():
    async with await _client() as client:
        project = (await client.post(
            "/api/v1/migrations",
            json={"name": "PQC rollout", "algorithm_from": "RSA-2048", "algorithm_to": "ML-KEM-768"},
        )).json()
        pid = project["id"]

        a = await _add_task(client, pid, "rotate keys on payments")
        b = await _add_task(client, pid, "upgrade TLS on edge")
        c = await _add_task(client, pid, "cut over core API")
        d = await _add_task(client, pid, "decommission old HSM pool")

        # ── dependency linking: C after A+B, D after C ───────────────
        for dep in (a["id"], b["id"]):
            r = await client.post(
                f"/api/v1/migrations/{pid}/tasks/{c['id']}/dependencies",
                json={"depends_on_task_id": dep},
            )
            assert r.status_code == 200, r.text
            assert dep in r.json()["depends_on"]
        r = await client.post(
            f"/api/v1/migrations/{pid}/tasks/{d['id']}/dependencies",
            json={"depends_on_task_id": c["id"]},
        )
        assert r.status_code == 200

        # cycle: A may not depend on D (D -> C -> A already)
        r = await client.post(
            f"/api/v1/migrations/{pid}/tasks/{a['id']}/dependencies",
            json={"depends_on_task_id": d["id"]},
        )
        assert r.status_code == 400
        assert "cycle" in r.json()["detail"]

        # unknown reference rejected
        r = await client.post(
            f"/api/v1/migrations/{pid}/tasks/{a['id']}/dependencies",
            json={"depends_on_task_id": "no-such-task"},
        )
        assert r.status_code == 404

        # ── execution plan: staging + parallelization ────────────────
        plan = (await client.get(f"/api/v1/migrations/{pid}/execution-plan")).json()
        assert plan["tasks_total"] == 4
        assert plan["max_parallelism"] == 2                     # A ∥ B
        assert plan["critical_path"] == [a["id"], c["id"], d["id"]]
        assert sorted(plan["ready_now"]) == sorted([a["id"], b["id"]])
        assert plan["stage_of_task"][c["id"]] == 1
        assert plan["stage_of_task"][d["id"]] == 2

        # ── gated start ─────────────────────────────────────────────
        r = await client.post(f"/api/v1/migrations/tasks/{c['id']}/start")
        assert r.status_code == 409
        blockers = r.json()["detail"]["blocking_tasks"]
        assert {b["task_id"] for b in blockers} == {a["id"], b["id"]}

        # direct DONE without starting is refused
        r = await client.post(f"/api/v1/migrations/tasks/{a['id']}/complete")
        assert r.status_code == 400

        # ── wave advance starts the ready set ───────────────────────
        advance = (await client.post(
            f"/api/v1/migrations/{pid}/execute/advance", json={"limit": 10}
        )).json()
        assert sorted(advance["started"]) == sorted([a["id"], b["id"]])

        # C is still gated: A and B are IN_PROGRESS, not DONE
        r = await client.post(f"/api/v1/migrations/tasks/{c['id']}/start")
        assert r.status_code == 409

        for tid in (a["id"], b["id"]):
            r = await client.post(f"/api/v1/migrations/tasks/{tid}/complete")
            assert r.status_code == 200, r.text

        # now C is ready — advance picks it up alone (D still gated)
        advance = (await client.post(
            f"/api/v1/migrations/{pid}/execute/advance", json={}
        )).json()
        assert advance["started"] == [c["id"]]

        await client.post(f"/api/v1/migrations/tasks/{c['id']}/complete")
        await client.post(f"/api/v1/migrations/tasks/{d['id']}/start")
        await client.post(f"/api/v1/migrations/tasks/{d['id']}/complete")

        progress = (await client.get(f"/api/v1/migrations/{pid}/progress")).json()
        assert progress["task_progress_pct"] == 100.0

        # ── rollback: C rolls back, D (done on top) cascades ────────
        rb = (await client.post(
            f"/api/v1/migrations/tasks/{c['id']}/rollback",
            json={"reason": "core API cutover failed regression suite"},
        )).json()
        assert sorted(rb["rolled_back"]) == sorted([c["id"], d["id"]])
        assert rb["blocked"] == []

        tasks = {t["id"]: t for t in
                 (await client.get(f"/api/v1/migrations/{pid}/tasks")).json()["tasks"]}
        assert tasks[c["id"]]["status"] == "TODO"
        assert tasks[d["id"]]["status"] == "TODO"

        # progress recomputed after rollback
        progress = (await client.get(f"/api/v1/migrations/{pid}/progress")).json()
        assert progress["task_progress_pct"] == 50.0

        # rollback requires a reason
        r = await client.post(f"/api/v1/migrations/tasks/{a['id']}/rollback",
                              json={"reason": "  "})
        assert r.status_code == 400

        # ── rollback blocks in-progress dependents ──────────────────
        await client.post(f"/api/v1/migrations/tasks/{c['id']}/start")
        await client.post(f"/api/v1/migrations/tasks/{c['id']}/complete")
        await client.post(f"/api/v1/migrations/tasks/{d['id']}/start")
        rb = (await client.post(
            f"/api/v1/migrations/tasks/{c['id']}/rollback",
            json={"reason": "second cutover failed"},
        )).json()
        assert rb["rolled_back"] == [c["id"]]
        assert rb["blocked"] == [d["id"]]
        tasks = {t["id"]: t for t in
                 (await client.get(f"/api/v1/migrations/{pid}/tasks")).json()["tasks"]}
        assert tasks[d["id"]]["status"] == "BLOCKED"
        assert "rolled back" in tasks[d["id"]]["blocked_reason"]


async def test_auto_derive_orders_tasks_by_system_edges():
    app, session, _engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # two systems: payments CALLS auth
        session.add(System(id="sys-auth", name="Auth service", environment="PROD"))
        session.add(System(id="sys-pay", name="Payments", environment="PROD"))
        session.add(SystemDependency(parent_id="sys-pay", child_id="sys-auth", relation="CALLS"))
        session.flush()

        project = (await client.post(
            "/api/v1/migrations",
            json={"name": "estate rollout"},
        )).json()
        pid = project["id"]
        pay = await _add_task(client, pid, "migrate payments", system_id="sys-pay")
        auth = await _add_task(client, pid, "migrate auth", system_id="sys-auth")

        derived = (await client.post(
            f"/api/v1/migrations/{pid}/dependencies/auto"
        )).json()
        assert derived["derived"] == 1
        assert derived["edges"][0]["depends_on_task_id"] == auth["id"]
        assert derived["edges"][0]["task_id"] == pay["id"]
        assert "CALLS" in derived["edges"][0]["reason"]

        plan = (await client.get(f"/api/v1/migrations/{pid}/execution-plan")).json()
        assert plan["stage_of_task"][auth["id"]] == 0
        assert plan["stage_of_task"][pay["id"]] == 1
        assert plan["ready_now"] == [auth["id"]]
