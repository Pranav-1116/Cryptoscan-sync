"""Real SQL/API operational annotations: tenant, revision, history and uncertainty."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from db.models.system import System
from db.models.system_dependency import SystemDependency
from db.models.cascade_run import CascadeRun
from db.models.relationship_lifecycle import RelationshipLifecycleEvent
from test_software_supply_chain_api import estate as estate, banks as banks

ROOT = "/api/v1/graph/edges/web/pay/operational-dependency"


def patch(client, mode="HARD", revision=0, **extra):
    return client.patch(
        ROOT,
        json={
            "expected_revision": revision,
            "operational_dependency": {"mode": mode, **extra},
            "reason": "Bank-approved dependency review",
            "evidence_ref": "change/BANK-8",
        },
    )


def cascade(client, **params):
    response = client.post("/api/v1/technology-bom/cascade", json={"target": "pay", "kind": "system"}, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_revision_audit_mode_edit_is_not_a_confirmation_or_revival(estate):
    client, db, _, _ = estate
    row = db.query(SystemDependency).filter_by(parent_id="web").one()
    row.lifecycle_state = "STALE"
    row.valid_until = datetime.now(timezone.utc) - timedelta(hours=1)
    row.last_verified = datetime(2026, 1, 1, tzinfo=timezone.utc)
    db.commit()
    before = deepcopy(row.to_dict())
    result = patch(client, "OPTIONAL", evidence_ref="contract/8", assumptions=["Feature is nonessential"])
    assert result.status_code == 200, result.text
    edge = result.json()["edge"]
    assert edge["operational_dependency"]["mode"] == "OPTIONAL" and edge["lifecycle_revision"] == 1
    assert edge["lifecycle_state"] == "STALE" and edge.get("last_confirmed_at") == before.get("last_confirmed_at")
    from shared_models.relationship_lifecycle import utc

    assert utc(edge["last_verified"]) == utc(before["last_verified"])
    assert utc(edge["valid_until"]) == utc(before["valid_until"])
    event = db.query(RelationshipLifecycleEvent).one()
    assert event.before["operational_dependency"] is None
    assert event.after["operational_dependency"]["mode"] == "OPTIONAL"
    assert event.evidence_ref == "change/BANK-8"
    assert patch(client, "HARD", revision=0).status_code == 409
    assert db.query(RelationshipLifecycleEvent).count() == 1


@pytest.mark.parametrize("mode", ["HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED", "UNKNOWN"])
def test_modes_roundtrip_and_do_not_reduce_review_or_process_exposure(estate, mode):
    client, db, _, _ = estate
    assert patch(client, mode).status_code == 200
    answer = cascade(client)
    assert answer["impact"]["system_classification"]["review_system_count"] == 3
    assert answer["impact"]["system_classification"]["exposure_system_count"] == 2
    projected = answer["impact"]["operational_impact"]
    assert projected["mode_counts"][mode] >= 1 and projected["provider_disruption_assumed"] is False
    stored = client.get(f"/api/v1/technology-bom/cascade/runs/{answer['run_id']}").json()["result"]
    assert stored["impact"]["operational_impact"] == projected
    assert all(e["relationship_evidence"]["source"] == "manual" for e in projected["edges"])


def test_failover_references_are_validated_without_partial_inserts_or_foreign_lookups(estate):
    client, db, _, _ = estate
    db.add_all([System(id="alt", name="Standby"), System(id="other-bank", tenant_id="foreign", name="Secret")])
    db.commit()
    assert patch(client, "FAILOVER", failover_system_ids=["other-bank"]).status_code == 404
    assert patch(client, "FAILOVER", failover_system_ids=["web"]).status_code == 422
    assert patch(client, "FAILOVER", failover_system_ids=["pay"]).status_code == 422
    assert patch(client, "FAILOVER", failover_system_ids=["Standby"]).status_code == 404
    result = patch(client, "FAILOVER", failover_system_ids=["alt"])
    assert result.status_code == 200
    answer = cascade(client)
    projected = next(e for e in answer["impact"]["operational_impact"]["edges"] if e["from"] == "web")
    assert projected["condition"]["failover_references"]["loaded_system_ids"] == ["alt"]
    assert "alt" not in answer["impact"]["affected_systems"]
    assert projected["condition"]["verified"] is False
    bad = client.post(
        "/api/v1/graph/edges",
        json={
            "parent_id": "alt",
            "child_id": "pay",
            "operational_dependency": {"mode": "FAILOVER", "failover_system_ids": ["other-bank"]},
        },
    )
    assert bad.status_code == 404
    db.commit()  # later work cannot accidentally commit a rejected insert
    assert db.query(SystemDependency).filter_by(parent_id="alt").count() == 0


@pytest.mark.parametrize(
    "bad",
    [
        {"mode": "HARD", "buffer_capacity_messages": 1},
        {"mode": "OPTIONAL", "failover_system_ids": ["db"]},
        {"mode": "ASYNC_BUFFERED", "buffer_capacity_messages": True},
        {"mode": "ASYNC_BUFFERED", "buffer_retention_seconds": 0},
        {"mode": "FAILOVER", "failover_system_ids": ["db", "db"]},
        {"mode": "HARD", "runtime_verified": True},
    ],
)
def test_invalid_or_incompatible_metadata_is_422_and_not_written(estate, bad):
    client, db, _, _ = estate
    response = client.patch(
        ROOT,
        json={"expected_revision": 0, "operational_dependency": bad, "reason": "review", "evidence_ref": "change/8"},
    )
    assert response.status_code == 422
    assert db.query(SystemDependency).filter_by(parent_id="web").one().operational_dependency is None
    assert db.query(RelationshipLifecycleEvent).count() == 0


def test_source_owner_terminal_and_revision_conflicts_are_not_bypassed(estate):
    client, db, _, _ = estate
    row = db.query(SystemDependency).filter_by(parent_id="web").one()
    row.lifecycle_source = "collector-pay"
    db.commit()
    assert patch(client).status_code == 409
    row.lifecycle_source = "manual"
    row.lifecycle_state = "DELETED"
    db.commit()
    assert patch(client).status_code == 409
    assert db.query(RelationshipLifecycleEvent).count() == 0


def test_mode_only_diff_is_visible_without_changed_membership_and_replay_is_frozen(estate):
    client, db, _, _ = estate
    assert patch(client, "HARD").status_code == 200
    old = cascade(client)
    version = client.post("/api/v1/digital-twin/snapshot").json()["version"]
    assert patch(client, "OPTIONAL", revision=1).status_code == 200
    new = cascade(client)
    diff = client.get(
        f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff", params={"against": old["run_id"]}
    ).json()
    assert diff["affected_systems"]["added"] == diff["affected_systems"]["removed"] == []
    assert diff["operational_comparison"]["comparable"] and len(diff["operational_comparison"]["changed_edges"]) == 1
    replay = cascade(client, version=version)
    assert replay["impact"]["operational_impact"]["mode_counts"]["HARD"] == 1
    assert new["impact"]["operational_impact"]["mode_counts"]["OPTIONAL"] == 1
    assert (
        client.get(f"/api/v1/technology-bom/cascade/runs/{old['run_id']}").json()["result"]["impact"] == old["impact"]
    )
    row = db.query(CascadeRun).filter_by(id=old["run_id"]).one()
    legacy = deepcopy(row.result)
    legacy["impact"].pop("operational_impact")
    row.result = legacy
    db.commit()
    diff = client.get(
        f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff", params={"against": old["run_id"]}
    ).json()
    assert diff["operational_comparison"]["comparable"] is False


def test_watch_reports_mode_change_separately_from_unchanged_review_union(estate):
    client, db, _, _ = estate
    client.post("/api/v1/technology-bom/cascade/watch", json={"target": "pay", "kind": "system"})
    client.post("/api/v1/technology-bom/cascade/watches/run-due")
    assert patch(client, "OPTIONAL").status_code == 200
    entry = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
    assert entry["operational_conditions_changed"] is True
    assert entry["diff"] == {"added": [], "removed": []}
    assert "blast_radius_changed" not in entry


def test_unknown_clear_is_audited_and_no_implicit_mode_is_derived(estate):
    client, db, _, _ = estate
    assert patch(client, "HARD").status_code == 200
    response = client.patch(
        ROOT,
        json={
            "expected_revision": 1,
            "operational_dependency": None,
            "reason": "Withdraw unsubstantiated declaration",
            "evidence_ref": "change/9",
        },
    )
    assert response.status_code == 200
    assert response.json()["edge"]["operational_condition"]["assertion_status"] == "UNSPECIFIED"
    assert cascade(client)["impact"]["operational_impact"]["mode_counts"]["UNKNOWN"] == 2


def test_new_mode_write_surface_denies_readonly_and_foreign_endpoints(banks):
    clients, db, _ = banks
    db.add(System(id="consumer-a", tenant_id="a", name="Bank A consumer"))
    db.add(SystemDependency(id="dep-a", tenant_id="a", parent_id="consumer-a", child_id="system-a", relation="CALLS"))
    db.commit()
    route = "/api/v1/graph/edges/consumer-a/system-a/operational-dependency"
    body = {
        "expected_revision": 0,
        "operational_dependency": {"mode": "HARD"},
        "reason": "review",
        "evidence_ref": "change/8",
    }
    assert clients["reader_a"].patch(route, json=body).status_code == 403
    assert clients["bank_b"].patch(route, json=body).status_code == 404
    assert clients["platform_admin"].patch(route, json=body).status_code == 404
    body["operational_dependency"] = {"mode": "FAILOVER", "failover_system_ids": ["system-b"]}
    assert clients["bank_a"].patch(route, json=body).status_code == 404
    body["operational_dependency"] = {"mode": "HARD"}
    assert clients["bank_a"].patch(route, json=body).status_code == 200
