"""Step 10: real sessions + tenant middleware, never mocked authentication.

Derived analyses/snapshots are private even when platform inventory is shared:
platform analyses can contain a privileged aggregate of several banks.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient

from db.models import System, SystemDependency
from db.models.cascade_run import CascadeRun
from db.models.cascade_extensions import CascadeWatch, TwinSnapshot
from db.models.graph_snapshot import GraphSnapshot
from db.models.relationship_lifecycle import RelationshipLifecycleEvent
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository
from test_software_supply_chain_api import banks as banks

ROOT = "/api/v1/technology-bom"


def run(client, target="system-a", **body):
    response = client.post(ROOT + "/cascade", json={"target": target, "kind": "system", **body})
    assert response.status_code == 200, response.text
    return response.json()


def watch(client, target="system-a"):
    response = client.post(ROOT + "/cascade/watch", json={"target": target, "kind": "system"})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def footprint(db):
    db.expire_all()
    return {
        model.__tablename__: [r.to_dict() for r in db.query(model).order_by(model.id).all()]
        for model in (SystemDependency, CascadeRun, CascadeWatch, RelationshipLifecycleEvent)
    }


def test_privileged_platform_answer_is_not_shared_inventory(banks):
    clients, db, _ = banks
    platform = run(clients["platform_admin"])
    assert "system-a" in json.dumps(platform)  # privileged aggregate, unsafe to share
    frozen = deepcopy(db.query(CascadeRun).filter_by(id=platform["run_id"]).one().result)
    a = run(clients["bank_a"])
    b = run(clients["bank_b"], "system-b")
    for username, own, forbidden in (("bank_a", a, (platform, b)), ("bank_b", b, (platform, a))):
        client = clients[username]
        history = client.get(ROOT + "/cascade/runs").json()["runs"]
        assert {r["id"] for r in history} == {own["run_id"]}
        for foreign in forbidden:
            assert client.get(ROOT + f"/cascade/runs/{foreign['run_id']}").status_code == 404
            assert (
                client.get(
                    ROOT + f"/cascade/runs/{own['run_id']}/diff", params={"against": foreign["run_id"]}
                ).status_code
                == 404
            )
    # Platform history is exact-estate too. Explicit privileged tenant selection
    # is an authorized operation, unlike a bank member's forged header.
    assert clients["platform_admin"].get(ROOT + f"/cascade/runs/{a['run_id']}").status_code == 404
    assert (
        clients["platform_admin"].get(ROOT + f"/cascade/runs/{a['run_id']}", headers={"X-Tenant-ID": "a"}).status_code
        == 200
    )
    db.expire_all()
    assert db.query(CascadeRun).filter_by(id=platform["run_id"]).one().result == frozen


@pytest.mark.parametrize("route", ["/digital-twin/snapshots/7", "/technology-bom/cascade"])
def test_platform_capture_cannot_supply_a_bank_replay_even_by_version(banks, route):
    clients, db, _ = banks
    state = {"systems": [{"id": "SECRET-FOREIGN", "name": "secret-bank-system"}], "dependencies": []}
    db.add(TwinSnapshot(version=7, fingerprint="a" * 64, state=state))
    db.commit()
    before = db.query(CascadeRun).count()
    if route.endswith("cascade"):
        response = clients["bank_b"].post(
            "/api/v1" + route, params={"version": 7}, json={"target": "SECRET-FOREIGN", "kind": "system"}
        )
    else:
        response = clients["bank_b"].get("/api/v1" + route)
    assert response.status_code == 404
    assert "secret-bank-system" not in response.text
    assert db.query(CascadeRun).count() == before


def test_colliding_capture_versions_resolve_in_exact_estate(banks):
    clients, db, _ = banks
    for tenant, sid in ((None, "platform-system"), ("a", "system-a"), ("b", "system-b")):
        db.add(
            TwinSnapshot(
                version=1,
                tenant_id=tenant,
                fingerprint=(tenant or "f") * 64,
                state={"systems": [{"id": sid, "name": sid}], "dependencies": []},
            )
        )
    db.commit()
    for key in ("a", "b"):
        client = clients["bank_" + key]
        selected = client.get("/api/v1/digital-twin/snapshots/1").json()
        assert [r["id"] for r in selected["state"]["systems"]] == ["system-" + key]
        assert client.get("/api/v1/digital-twin/snapshots").json()["count"] == 1
        response = client.post(
            ROOT + "/cascade", params={"version": 1}, json={"target": "system-" + key, "kind": "system"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["impact"]["affected_systems"] == ["system-" + key]


def test_graph_versions_and_fallback_do_not_import_platform_aggregate(banks):
    clients, db, _ = banks
    db.add(
        GraphSnapshot(
            version=99,
            fingerprint="f" * 64,
            nodes=[{"key": ["FOREIGN-SECRET", "System"]}],
            edges=[{"from": "system:system-a", "to": "system:FOREIGN-SECRET", "label": "CALLS"}],
        )
    )
    db.commit()
    a = clients["bank_a"]
    assert a.get("/api/v1/graph/timeline").json()["versions"] == []
    assert a.get("/api/v1/graph/compare", params={"from_version": 99, "to_version": 99}).status_code == 404
    result = run(a)
    assert result["coverage"]["collections"]["dependencies"]["returned"] == 0
    assert "FOREIGN-SECRET" not in json.dumps(result)


def test_watches_do_not_execute_or_delete_platform_aggregate_targets(banks):
    clients, db, _ = banks
    p = watch(clients["platform_admin"])
    b = watch(clients["bank_b"], "system-b")
    a = watch(clients["bank_a"])
    before = deepcopy(db.query(CascadeWatch).filter_by(id=p).one().to_dict())
    client = clients["bank_a"]
    assert {r["id"] for r in client.get(ROOT + "/cascade/watches").json()["watches"]} == {a}
    assert client.delete(ROOT + f"/cascade/watch/{p}").status_code == 404
    assert client.delete(ROOT + f"/cascade/watch/{b}").status_code == 404
    due = client.post(ROOT + "/cascade/watches/run-due")
    assert due.status_code == 200, due.text
    assert {w["watch_id"] for w in due.json()["watches"]} == {a}
    db.expire_all()
    assert db.query(CascadeWatch).filter_by(id=p).one().to_dict() == before


@pytest.mark.parametrize("role", ["readonly", "auditor", "supervisor", "developer", "bank-custom-empty", ""])
@pytest.mark.parametrize("action", ["create", "delete", "run"])
def test_provisioned_nonwriters_cannot_manage_watches(banks, role, action):
    clients, db, _ = banks
    identifier = watch(clients["bank_a"])
    user = UserRepository(db).get_by_username("reader_a")
    user.roles = role
    db.commit()
    before = footprint(db)
    reader = clients["reader_a"]
    if action == "create":
        response = reader.post(ROOT + "/cascade/watch", json={"target": "system-a"})
    elif action == "delete":
        response = reader.delete(ROOT + f"/cascade/watch/{identifier}")
    else:
        response = reader.post(ROOT + "/cascade/watches/run-due")
    assert response.status_code == 403
    assert footprint(db) == before


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("get", "/cascade/runs", None),
        ("get", "/cascade/watches", None),
        ("post", "/cascade", {"target": "system-a"}),
        ("post", "/cascade/watch", {"target": "system-a"}),
        ("post", "/cascade/watches/run-due", None),
    ],
)
def test_no_credentials_cannot_read_or_schedule_bank_analysis(banks, method, path, body):
    clients, db, _ = banks
    before = footprint(db)
    with TestClient(clients["bank_a"].app) as anonymous:
        kwargs = {"json": body} if body else {}
        response = getattr(anonymous, method)(ROOT + path, **kwargs)
    assert response.status_code == 401
    assert footprint(db) == before


@pytest.mark.parametrize("condition,expected", [("forged", 404), ("suspended", 423), ("ambiguous", 400)])
def test_refused_tenant_context_never_falls_back_to_global_history(banks, condition, expected):
    clients, db, _ = banks
    run(clients["platform_admin"])
    headers = {}
    if condition == "forged":
        headers = {"X-Tenant-ID": "b"}
    elif condition == "suspended":
        db.query(Tenant).filter_by(id="a").one().status = "SUSPENDED"
    else:
        db.add(TenantMembership(tenant_id="b", username="bank_a", tenant_role="member"))
    db.commit()
    before = footprint(db)
    response = clients["bank_a"].get(ROOT + "/cascade/runs", headers=headers)
    assert response.status_code == expected
    assert "system-a" not in response.text
    assert footprint(db) == before


def test_missing_or_foreign_watch_baseline_is_not_silently_rebased(banks):
    clients, db, _ = banks
    identifier = watch(clients["bank_a"])
    foreign = run(clients["platform_admin"])
    row = db.query(CascadeWatch).filter_by(id=identifier).one()
    row.last_run_id = foreign["run_id"]
    db.commit()
    response = clients["bank_a"].post(ROOT + "/cascade/watches/run-due")
    assert response.status_code == 200, response.text
    entry = response.json()["watches"][0]
    assert entry["attention_required"]
    assert "diff" not in entry
    db.expire_all()
    assert db.query(CascadeWatch).filter_by(id=identifier).one().last_run_id == foreign["run_id"]


@pytest.fixture()
def bank_edge(banks):
    clients, db, _ = banks
    db.add(System(id="mobile-a", tenant_id="a", name="Mobile channel"))
    db.add(
        SystemDependency(
            id="bank-a-edge",
            tenant_id="a",
            parent_id="mobile-a",
            child_id="system-a",
            relation="CALLS",
            valid_until=datetime.now(timezone.utc) + timedelta(days=1),
            operational_dependency={"mode": "HARD"},
        )
    )
    db.commit()
    return clients, db


@pytest.mark.parametrize("principal,expected", [("reader_a", 403), ("bank_b", 404), ("platform_admin", 404)])
@pytest.mark.parametrize("surface", ["mode", "state", "claim"])
def test_denied_bank_relationship_writes_have_no_domain_or_audit_side_effect(bank_edge, principal, expected, surface):
    clients, db = bank_edge
    before = footprint(db)
    if surface == "mode":
        response = clients[principal].patch(
            "/api/v1/graph/edges/mobile-a/system-a/operational-dependency",
            json={
                "expected_revision": 0,
                "operational_dependency": {"mode": "OPTIONAL"},
                "reason": "review",
                "evidence_ref": "change/10",
            },
        )
    else:
        body = {"expected_revision": 0, "reason": "review", "evidence_ref": "change/10"}
        body.update(
            {"state": "DELETED"} if surface == "state" else {"expected_source": "manual", "source_id": "imported-bank"}
        )
        response = clients[principal].post(
            f"/api/v1/relationship-lifecycle/system_dependency/bank-a-edge/{surface}", json=body
        )
    assert response.status_code == expected, response.text
    assert footprint(db) == before


@pytest.mark.parametrize("failure", ["foreign_alternative", "stale_revision", "terminal", "source_owned"])
def test_rejected_operational_edits_never_refresh_or_revive_relationship(bank_edge, failure):
    clients, db = bank_edge
    edge = db.query(SystemDependency).filter_by(id="bank-a-edge").one()
    if failure == "terminal":
        edge.lifecycle_state = "DELETED"
    if failure == "source_owned":
        edge.lifecycle_source = "bank-scanner"
    db.commit()
    before = footprint(db)
    assertion = (
        {"mode": "FAILOVER", "failover_system_ids": ["system-b"]}
        if failure == "foreign_alternative"
        else {"mode": "HARD"}
    )
    response = clients["bank_a"].patch(
        "/api/v1/graph/edges/mobile-a/system-a/operational-dependency",
        json={
            "expected_revision": 1 if failure == "stale_revision" else 0,
            "operational_dependency": assertion,
            "reason": "review",
            "evidence_ref": "change/10",
        },
    )
    assert response.status_code == (404 if failure == "foreign_alternative" else 409), response.text
    assert footprint(db) == before


def test_reader_can_review_frozen_history_but_replay_never_uses_live_modes_or_caps(bank_edge, monkeypatch):
    from api.routers.digital_twin import SNAPSHOT_CAPS

    clients, db = bank_edge
    a, reader = clients["bank_a"], clients["reader_a"]
    old = run(a)
    frozen_result = deepcopy(db.query(CascadeRun).filter_by(id=old["run_id"]).one().result)
    capture = a.post("/api/v1/digital-twin/snapshot")
    assert capture.status_code == 200, capture.text
    version = capture.json()["version"]
    state = deepcopy(a.get(f"/api/v1/digital-twin/snapshots/{version}").json()["state"])
    changed = a.patch(
        "/api/v1/graph/edges/mobile-a/system-a/operational-dependency",
        json={
            "expected_revision": 0,
            "operational_dependency": {"mode": "OPTIONAL"},
            "reason": "owner review",
            "evidence_ref": "change/10",
        },
    )
    assert changed.status_code == 200, changed.text
    monkeypatch.setitem(SNAPSHOT_CAPS, "dependencies", 0)
    assert run(a)["coverage"]["known_input_truncation"]
    replay = reader.post(ROOT + "/cascade", params={"version": version}, json={"target": "system-a", "kind": "system"})
    assert replay.status_code == 200, replay.text
    answer = replay.json()
    assert answer["impact"]["operational_impact"]["mode_counts"]["HARD"] == 1
    assert not answer["coverage"]["known_input_truncation"]
    assert answer["impact"]["system_classification"] == old["impact"]["system_classification"]
    assert reader.get(ROOT + f"/cascade/runs/{old['run_id']}").json()["result"] == frozen_result
    assert reader.get(f"/api/v1/digital-twin/snapshots/{version}").json()["state"] == state
    db.expire_all()
    assert db.query(SystemDependency).filter_by(id="bank-a-edge").one().operational_dependency["mode"] == "OPTIONAL"


@pytest.mark.parametrize("route", ["/cascade/runs", "/cascade/watches"])
def test_invalid_session_cannot_reach_bank_history(banks, route):
    clients, db, _ = banks
    before = footprint(db)
    clients["bank_a"].cookies.set("cryptoscan_session", "revoked-or-forged-session")
    response = clients["bank_a"].get(ROOT + route)
    assert response.status_code == 401
    assert footprint(db) == before


def test_foreign_target_is_unresolved_not_a_fabricated_safe_bank_result(banks):
    clients, _db, _ = banks
    result = run(clients["bank_a"], "system-b")
    assert result["analysis_performed"] is False
    assert result["target_resolution"]["candidates"] == []
    assert result["coverage"]["estate_completeness"] == "UNKNOWN"
    assert "Core b" not in json.dumps(result)
    assert any("not" in message.lower() and "zero" in message.lower() for message in result["honest_unknowns"])


def test_untrusted_request_cannot_choose_watch_owner_or_overwrite_frozen_run(banks):
    clients, db, _ = banks
    old = run(clients["bank_a"])
    stored = deepcopy(db.query(CascadeRun).filter_by(id=old["run_id"]).one().result)
    response = clients["bank_a"].post(
        ROOT + "/cascade/watch", json={"target": "system-a", "tenant_id": "b", "created_by": "platform_admin"}
    )
    assert response.status_code == 200, response.text
    row = db.query(CascadeWatch).filter_by(id=response.json()["id"]).one()
    assert row.tenant_id == "a" and row.created_by == "bank_a"
    second = run(clients["bank_a"], run_id=old["run_id"], tenant_id="b")
    assert second["run_id"] != old["run_id"]
    db.expire_all()
    assert db.query(CascadeRun).filter_by(id=old["run_id"]).one().result == stored
    assert db.query(CascadeRun).filter_by(id=second["run_id"]).one().tenant_id == "a"
