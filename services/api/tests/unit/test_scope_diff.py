"""Scope revisions and the server-side scope diff (GET /api/v1/scope/diff).

The diff is computed by the control plane only — the CLI renders whatever
this route returned and never derives the verdicts itself. `blocked` rows
are the discipline here: a declared-but-disabled or excluded addition must
never be read as a widening of authority.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.onboarding import Organization, ScopeEntry


@pytest.fixture
def ctx():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "scope-tester"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    yield {"client": client, "session": session}
    session.close()


def _seed(session, entries: list[dict]) -> Organization:
    org = Organization(name="First Bank")
    session.add(org)
    session.flush()
    for e in entries:
        session.add(ScopeEntry(org_id=org.id, kind=e["kind"], target=e["target"],
                               enabled=e.get("enabled", True),
                               detail=e.get("detail")))
    session.commit()
    return org


@pytest.mark.asyncio
async def test_snapshot_captures_and_lists(ctx):
    _seed(ctx["session"], [{"kind": "network", "target": "10.0.0.0/24"}])
    created = await ctx["client"].post("/api/v1/scope/snapshots?label=before-change")
    assert created.status_code == 201
    body = created.json()
    assert body["label"] == "before-change"
    assert body["entries"] == 1
    assert len(body["content_hash"]) == 64

    listing = await ctx["client"].get("/api/v1/scope/snapshots")
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) == 1 and rows[0]["id"] == body["id"]


@pytest.mark.asyncio
async def test_diff_classifies_added_removed_changed_and_blocked(ctx):
    session = ctx["session"]
    org = _seed(session, [
        {"kind": "network", "target": "10.0.0.0/24"},
        {"kind": "cloud", "target": "aws-prod"},
    ])
    created = await ctx["client"].post("/api/v1/scope/snapshots?label=v1")
    v1 = created.json()["id"]

    # mutate: drop the network range, change aws-prod's detail, and add four
    # entries — one effective, one disabled, one effective-but-excluded and
    # one carrying the exclusion itself.
    for row in list(session.query(ScopeEntry).all()):
        if row.target == "10.0.0.0/24":
            session.delete(row)
        elif row.target == "aws-prod":
            row.detail = {"tier": "gold"}
    session.add(ScopeEntry(org_id=org.id, kind="application",
                           target="pay.example", enabled=True))
    session.add(ScopeEntry(org_id=org.id, kind="application",
                           target="blocked.example", enabled=False))
    session.add(ScopeEntry(org_id=org.id, kind="network",
                           target="10.9.9.9", enabled=True))
    session.add(ScopeEntry(org_id=org.id, kind="network", target="10.8.8.0/24",
                           enabled=True, detail={"exclusions": ["10.9.9.9"]}))
    session.commit()

    diff = await ctx["client"].get(f"/api/v1/scope/diff?from={v1}&to=current")
    assert diff.status_code == 200
    body = diff.json()

    removed = {(r["kind"], r["target"]) for r in body["removed"]}
    assert removed == {("network", "10.0.0.0/24")}
    assert body["removed"][0]["was_effective"] is True

    added = {(a["kind"], a["target"]) for a in body["added"]}
    assert ("application", "pay.example") in added
    assert ("network", "10.8.8.0/24") in added

    changed = {(c["kind"], c["target"]) for c in body["changed"]}
    assert changed == {("cloud", "aws-prod")}
    row = body["changed"][0]
    assert row["before"] == {"enabled": True, "detail": {}}
    assert row["after"] == {"enabled": True, "detail": {"tier": "gold"}}

    blocked = {(b["kind"], b["target"], b["reason"]) for b in body["blocked"]}
    assert ("application", "blocked.example", "disabled") in blocked
    assert ("network", "10.9.9.9", "excluded") in blocked
    excluded_by = {b["target"]: b.get("excluded_by") for b in body["blocked"]}
    assert excluded_by["10.9.9.9"] == "10.9.9.9"

    assert "exclusions" in body["envelope_changed"], \
        "an envelope field difference is reported, never silently dropped"

    s = body["summary"]
    assert s["added"] == 2 and s["removed"] == 1 and s["changed"] == 1
    assert s["blocked"] == 2
    assert body["from"]["snapshot_id"] == v1
    assert body["to"]["ref"] == "current"


@pytest.mark.asyncio
async def test_diff_between_two_captured_revisions(ctx):
    session = ctx["session"]
    org = _seed(session, [{"kind": "network", "target": "10.0.0.0/24"}])
    v1 = (await ctx["client"].post("/api/v1/scope/snapshots?label=v1")).json()
    session.add(ScopeEntry(org_id=org.id, kind="cloud", target="aws-dr"))
    session.commit()
    v2 = (await ctx["client"].post("/api/v1/scope/snapshots?label=v2")).json()

    diff = await ctx["client"].get(
        f"/api/v1/scope/diff?from={v1['id']}&to={v2['id']}")
    body = diff.json()
    assert body["summary"]["added"] == 1
    assert body["added"][0]["target"] == "aws-dr"
    assert body["from"]["content_hash"] == v1["content_hash"]
    assert body["to"]["content_hash"] == v2["content_hash"]
    assert body["from"]["content_hash"] != body["to"]["content_hash"], \
        "different revisions must not hash the same"


@pytest.mark.asyncio
async def test_diff_of_identical_revisions_is_empty_but_not_proof(ctx):
    _seed(ctx["session"], [{"kind": "network", "target": "10.0.0.0/24"}])
    v1 = (await ctx["client"].post("/api/v1/scope/snapshots")).json()
    v2 = (await ctx["client"].post("/api/v1/scope/snapshots")).json()
    diff = await ctx["client"].get(
        f"/api/v1/scope/diff?from={v1['id']}&to={v2['id']}")
    body = diff.json()
    assert body["summary"] == {"added": 0, "removed": 0, "changed": 0,
                               "blocked": 0, "envelope_fields_changed": 0}
    assert v1["content_hash"] == v2["content_hash"], \
        "the same authorization state hashes the same"


@pytest.mark.asyncio
async def test_diff_unknown_revision_is_404(ctx):
    _seed(ctx["session"], [{"kind": "network", "target": "10.0.0.0/24"}])
    diff = await ctx["client"].get("/api/v1/scope/diff?from=no-such-snapshot")
    assert diff.status_code == 404
    assert "does not exist" in diff.json()["detail"]


@pytest.mark.asyncio
async def test_disabled_entry_added_is_blocked_not_added(ctx):
    session = ctx["session"]
    org = _seed(session, [{"kind": "network", "target": "10.0.0.0/24"}])
    v1 = (await ctx["client"].post("/api/v1/scope/snapshots")).json()
    session.add(ScopeEntry(org_id=org.id, kind="network",
                           target="10.1.1.0/24", enabled=False))
    session.commit()
    diff = await ctx["client"].get(
        f"/api/v1/scope/diff?from={v1['id']}&to=current")
    body = diff.json()
    assert body["added"] == []
    assert body["blocked"] == [{"kind": "network", "target": "10.1.1.0/24",
                                "reason": "disabled"}]
