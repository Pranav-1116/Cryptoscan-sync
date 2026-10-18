"""Lifecycle APIs operate on real rows; no destructive collector adoption."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import pytest
from db.models.relationship_lifecycle import RelationshipCollection, RelationshipLifecycleEvent, RelationshipSource
from db.models.system_dependency import SystemDependency
# Reuse the actual SQL/file-store estate, not an in-memory lifecycle mock.
from test_software_supply_chain_api import estate as estate, banks as banks
from test_software_supply_chain_api import register, scan, attach, deploy, cascade

ROOT = "/api/v1/relationship-lifecycle"
EVIDENCE = {"reason": "approved lifecycle change", "evidence_ref": "change/BANK-456"}


def path(kind, row):
    return f"{ROOT}/{kind}/{row['id']}"


def state(client, kind, row, value, **extra):
    return client.post(path(kind, row) + "/state", json={"expected_revision": row["lifecycle_revision"], "state": value, **EVIDENCE, **extra})


def claim(client, kind, row, source="cluster-payments"):
    result = client.post(path(kind, row) + "/claim", json={"expected_revision": row["lifecycle_revision"],
        "expected_source": row["lifecycle_source"], "source_id": source, **EVIDENCE})
    assert result.status_code == 200, result.text
    return result.json()


def collect(client, kind, *, rows=(), sequence=1, outcome="COMPLETE", source="cluster-payments", key=None, **extra):
    payload = {"collection_key": key or f"run-{sequence}", "sequence": sequence, "outcome": outcome,
               "observed_at": datetime.now(timezone.utc).isoformat(), "truncated": False,
               "reported_count": len(rows), "observed": [{"id": r["id"], "expected_revision": r["lifecycle_revision"]} for r in rows],
               "evidence_ref": "collector/receipt-1", **extra}
    return client.post(f"{ROOT}/{kind}/sources/{source}/collections", json=payload), payload


def edge_rows(client):
    return client.get("/api/v1/graph/edges").json()["edges"]


@pytest.mark.parametrize("kind", ["system_dependency", "sbom_binding", "deployment"])
def test_complete_missing_is_stale_partial_failed_do_not_retire_and_terminals_do_not_resurrect(estate, kind):
    client, db, tmp, _ = estate
    artifact = register(client)
    sbom, _ = scan(client, tmp)
    rows = {"system_dependency": edge_rows(client)[0], "sbom_binding": attach(client, artifact, sbom), "deployment": deploy(client, artifact).json()}
    row = claim(client, kind, rows[kind])
    for sequence, outcome in [(1, "PARTIAL"), (2, "FAILED")]:
        response, _ = collect(client, kind, sequence=sequence, outcome=outcome)
        assert response.status_code == 200, response.text
        assert client.get(path(kind, row)).json()["lifecycle_state"] == "ACTIVE"
    response, payload = collect(client, kind, sequence=3)
    assert response.status_code == 200, response.text
    assert response.json()["stale_ids"] == [row["id"]]
    assert db.query(RelationshipCollection).count() == 3
    # Identical retries are immutable receipts, not another version increment.
    retry = client.post(f"{ROOT}/{kind}/sources/cluster-payments/collections", json=payload)
    assert retry.json() == response.json()
    row = client.get(path(kind, row)).json()
    assert row["lifecycle_state"] == "STALE"
    response, _ = collect(client, kind, rows=[row], sequence=4, outcome="PARTIAL")
    assert response.status_code == 200, response.text
    row = client.get(path(kind, row)).json()
    assert row["lifecycle_state"] == "ACTIVE"
    response = state(client, kind, row, "DELETED")
    assert response.status_code == 200, response.text
    row = response.json()
    response, _ = collect(client, kind, rows=[row], sequence=5)
    assert response.status_code == 200, response.text
    assert response.json()["terminal_ids_not_reactivated"] == [row["id"]]
    assert client.get(path(kind, row)).json()["lifecycle_state"] == "DELETED"
    events = client.get(path(kind, row) + "/events").json()
    assert events["total_count"] == 4  # claim, stale, confirm, explicit deletion
    assert events["events"][-1]["identity"]
    assert events["events"][-1]["before"]["lifecycle_state"] == "ACTIVE"


def test_no_implicit_adoption_complete_requires_explicit_completeness_and_failed_cannot_confirm(estate):
    client, db, _, _ = estate
    row = edge_rows(client)[0]
    response, payload = collect(client, "system_dependency", rows=[row])
    assert response.status_code == 404
    assert db.query(RelationshipSource).count() == 0  # transaction rolled back
    assert db.query(RelationshipCollection).count() == 0
    assert db.query(RelationshipLifecycleEvent).count() == 0
    assert client.get(path("system_dependency", row)).json()["lifecycle_source"] == "manual"
    for changes in [{"truncated": True}, {"reported_count": 2}, {"outcome": "FAILED"}]:
        response = client.post(f"{ROOT}/system_dependency/sources/cluster-payments/collections", json={**payload, **changes})
        assert response.status_code == 422


def test_source_ownership_cas_clock_and_payload_conflicts_are_atomic(estate):
    client, db, _, _ = estate
    first, second = edge_rows(client)
    first = claim(client, "system_dependency", first)
    # Other/manual evidence is never retired by this source's complete empty run.
    response, payload = collect(client, "system_dependency", rows=[first], sequence=7)
    assert response.status_code == 200, response.text
    first = client.get(path("system_dependency", first)).json()
    assert client.get(path("system_dependency", second)).json()["lifecycle_state"] == "ACTIVE"
    for changes, expected in [({"collection_key": "late", "sequence": 6}, 409),
                              ({"evidence_ref": "tampered"}, 409),
                              ({"collection_key": "future", "sequence": 8, "observed_at": (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}, 422),
                              ({"collection_key": "old-time", "sequence": 8, "observed_at": "2020-01-01T00:00:00Z"}, 409)]:
        response = client.post(f"{ROOT}/system_dependency/sources/cluster-payments/collections", json={**payload, **changes})
        assert response.status_code == expected, response.text
    # The first row must not be changed if a later entry has a stale revision.
    second = claim(client, "system_dependency", second)
    before = client.get(path("system_dependency", first)).json()
    response, _ = collect(client, "system_dependency", sequence=8, rows=[first, {**second, "lifecycle_revision": 0}])
    assert response.status_code == 409
    assert client.get(path("system_dependency", first)).json() == before
    assert db.query(RelationshipSource).one().last_sequence == 7
    assert db.query(RelationshipCollection).count() == 1


def test_expired_binding_or_deployment_never_seeds_current_systems_but_retains_uncertainty(estate):
    client, db, tmp, _ = estate
    artifact = register(client)
    sbom, purl = scan(client, tmp)
    binding = attach(client, artifact, sbom)
    deployment = deploy(client, artifact).json()
    assert cascade(client, purl)["impact"]["affected_system_count"] == 3
    response = state(client, "deployment", deployment, "STALE")
    assert response.status_code == 200
    result = cascade(client, purl)
    assert result["impact"]["affected_system_count"] == 0
    assert result["impact"]["lifecycle_uncertainty"]["possible_additional_systems"] == ["db", "pay", "web"]
    assert result["layers"]["software"]["deployments"][0]["id"] == deployment["id"]
    restored = state(client, "deployment", response.json(), "ACTIVE").json()
    # A state change can record historical expiry without fabricating freshness.
    response = state(client, "sbom_binding", binding, "STALE", valid_until="2020-01-01T00:00:00Z")
    assert response.json()["effective_state"] == "EXPIRED"
    assert cascade(client, purl)["impact"]["affected_system_count"] == 0
    assert state(client, "sbom_binding", response.json(), "ACTIVE").status_code == 409
    active = state(client, "sbom_binding", response.json(), "ACTIVE", valid_until=None)
    assert active.status_code == 200
    assert cascade(client, purl)["impact"]["affected_system_count"] == 3
    assert state(client, "deployment", restored, "SUPERSEDED").status_code == 200
    assert cascade(client, purl)["layers"]["software"]["historical_systems"] == ["pay"]


def test_soft_delete_requires_revision_preserves_row_and_explicit_reactivation(estate):
    client, db, _, _ = estate
    row = edge_rows(client)[0]
    endpoint = f"/api/v1/graph/edges/{row['parent_id']}/{row['child_id']}"
    assert client.delete(endpoint).status_code == 422
    response = client.delete(endpoint, params={"expected_revision": row["lifecycle_revision"], **EVIDENCE})
    assert response.status_code == 200, response.text
    assert response.json()["retained"] is True
    assert db.query(SystemDependency).count() == 2
    assert db.query(RelationshipLifecycleEvent).one().after["lifecycle_state"] == "DELETED"
    assert state(client, "system_dependency", row, "ACTIVE").status_code == 409
    assert state(client, "system_dependency", response.json()["edge"], "ACTIVE").status_code == 200


def test_replay_uses_capture_clock_unless_explicitly_reevaluated_and_keeps_old_run(estate):
    client, db, tmp, _ = estate
    artifact = register(client)
    sbom, purl = scan(client, tmp)
    attach(client, artifact, sbom)
    deployment = deploy(client, artifact).json()
    deadline = datetime.now(timezone.utc) + timedelta(hours=1)
    response = state(client, "deployment", deployment, "ACTIVE", valid_until=deadline.isoformat())
    assert response.status_code == 200
    capture = client.post("/api/v1/digital-twin/snapshot").json()
    version = capture["version"]
    endpoint = f"/api/v1/technology-bom/cascade?version={version}"
    body = {"target": purl, "kind": "package"}
    initial = client.post(endpoint, json=body).json()
    assert initial["impact"]["affected_system_count"] == 3
    assert initial["replayed_over"]["clock_source"] == "snapshot_capture"
    reevaluated = client.post(endpoint, json={**body, "as_of": (deadline+timedelta(seconds=1)).isoformat()}).json()
    assert reevaluated["impact"]["affected_system_count"] == 0
    assert reevaluated["replayed_over"]["clock_source"] == "explicit_request"
    assert client.post(endpoint, json=body).json()["as_of"] == initial["as_of"]
    stored = client.get(f"/api/v1/technology-bom/cascade/runs/{initial['run_id']}").json()
    assert stored["result"]["impact"]["affected_system_count"] == 3
    assert client.post("/api/v1/technology-bom/cascade", json={**body, "as_of": deadline.isoformat()}).status_code == 422


def test_graph_snapshot_records_lifecycle_change_without_claiming_edge_disappearance(estate):
    client, db, _, _ = estate
    row = edge_rows(client)[0]
    initial = client.post("/api/v1/graph/snapshot").json()
    assert "version" in initial, initial
    assert state(client, "system_dependency", row, "STALE").status_code == 200
    changed = client.post("/api/v1/graph/snapshot").json()
    assert changed["version"] == initial["version"] + 1
    assert changed["edge_count"] == initial["edge_count"]
    compared = client.get("/api/v1/graph/compare", params={"from_version": initial["version"], "to_version": changed["version"]}).json()
    assert compared["changed"] is True
    assert compared["removed_edges"] == []
    assert len(compared["relationship_lifecycle_changes"]) == 1
    assert compared["policy_comparison"]["comparable"] is True


def test_new_mutations_require_credentials_and_writer_role(estate, monkeypatch):
    client, db, _, _ = estate
    row = edge_rows(client)[0]
    payload = {"expected_revision": 0, "state": "DELETED", **EVIDENCE}
    endpoint = path("system_dependency", row) + "/state"
    assert client.post(endpoint, json=payload, headers={"Authorization": ""}).status_code == 401
    import api.dependencies as deps
    monkeypatch.setattr(deps, "_user_roles", lambda *_: ["readonly"])
    assert client.get(path("system_dependency", row)).status_code == 200
    assert client.post(endpoint, json=payload).status_code == 403
    assert db.query(RelationshipLifecycleEvent).count() == 0


@pytest.mark.parametrize("kind", ["deployment", "sbom_binding"])
def test_actual_two_bank_and_platform_lifecycle_sources_and_audit_are_isolated(banks, kind):
    clients, db, tmp = banks
    a, b, platform = (clients[n] for n in ["bank_a", "bank_b", "platform_admin"])
    rows = {}
    for name, client, sid in [("a", a, "system-a"), ("b", b, "system-b"), ("p", platform, "platform-system")]:
        artifact = register(client)
        if kind == "deployment":
            row = deploy(client, artifact, system_id=sid).json()
        else:
            sbom, _ = scan(client, tmp)
            row = attach(client, artifact, sbom)
        rows[name] = claim(client, kind, row, source="same-source")
    for foreign in [rows["b"], rows["p"]]:
        assert a.get(path(kind, foreign)).status_code == 404
        assert state(a, kind, foreign, "DELETED").status_code == 404
        assert a.get(path(kind, foreign) + "/events").json()["events"] == []
        response, _ = collect(a, kind, rows=[foreign], source="same-source")
        assert response.status_code == 404
    assert platform.get(path(kind, rows["a"])).status_code == 404
    assert state(clients["reader_a"], kind, rows["a"], "DELETED").status_code == 403
    # Identical source name/key/sequence in distinct estates is legitimate.
    for client, key in [(a, "a"), (b, "b"), (platform, "p")]:
        response, _ = collect(client, kind, source="same-source", rows=[rows[key]])
        assert response.status_code == 200, response.text
        receipts = client.get(f"{ROOT}/{kind}/sources/same-source/collections").json()
        assert receipts["last_sequence"] == 1 and receipts["total_count"] == 1
        assert receipts["collections"][0]["result"]["confirmed_ids"] == [rows[key]["id"]]
    # A forged selector is rejected by real tenant middleware.
    assert a.get(path(kind, rows["b"]), headers={"X-Tenant-ID": "b"}).status_code in (403, 404)


def test_system_relationship_claim_reconciliation_and_endpoint_ownership_are_exact_estate(banks):
    from db.models import System
    clients, db, _ = banks
    for tenant in ["a", "b", None]:
        sid = "platform-system" if tenant is None else "system-" + tenant
        child = "second-" + (tenant or "platform")
        db.add(System(id=child, tenant_id=tenant, name=child, environment="prod"))
        db.flush()
        db.add(SystemDependency(id="edge-" + (tenant or "platform"), tenant_id=tenant, parent_id=sid, child_id=child, relation="CALLS"))
    # A forged edge owner is not authority over a foreign endpoint.
    db.add(SystemDependency(id="wrong-endpoint-owner", tenant_id="a", parent_id="system-a", child_id="system-b", relation="CALLS"))
    db.commit()
    a, b, platform = (clients[n] for n in ["bank_a", "bank_b", "platform_admin"])
    for identifier in ["edge-b", "edge-platform", "wrong-endpoint-owner"]:
        url = f"{ROOT}/system_dependency/{identifier}"
        assert a.get(url).status_code == 404
        assert a.post(url + "/claim", json={"expected_revision": 0, "expected_source": "manual", "source_id": "bank-feed", **EVIDENCE}).status_code == 404
    for client, identifier in [(a, "edge-a"), (b, "edge-b"), (platform, "edge-platform")]:
        row = client.get(f"{ROOT}/system_dependency/{identifier}").json()
        row = claim(client, "system_dependency", row, source="bank-feed")
        result, _ = collect(client, "system_dependency", source="bank-feed")
        assert result.status_code == 200, result.text
        assert result.json()["stale_ids"] == [identifier]
    assert db.query(SystemDependency).filter_by(id="wrong-endpoint-owner").one().lifecycle_state == "ACTIVE"


def test_complete_source_bound_never_silently_stales_a_truncated_owned_tail(estate):
    from db.models.software_supply_chain import SoftwareDeployment
    client, db, _, _ = estate
    artifact = register(client)
    for i in range(5001):
        db.add(SoftwareDeployment(tenant_id=None, scope_key="platform", artifact_id=artifact["id"], system_id="pay",
            deployment_key=f"revision-{i}", environment="prod", assertion_source="OPERATOR_DECLARED",
            evidence_ref="test/owned-source", created_by="operator", lifecycle_source="large-feed"))
    db.commit()
    response, _ = collect(client, "deployment", source="large-feed")
    assert response.status_code == 409
    assert db.query(SoftwareDeployment).filter_by(lifecycle_state="ACTIVE").count() == 5001
    assert db.query(RelationshipSource).count() == 0
    assert db.query(RelationshipCollection).count() == 0
    assert db.query(RelationshipLifecycleEvent).count() == 0


def test_collection_hash_distinguishes_omitted_deadline_from_explicit_clear(estate):
    client, db, _, _ = estate
    row = claim(client, "system_dependency", edge_rows(client)[0])
    response, payload = collect(client, "system_dependency", rows=[row])
    assert response.status_code == 200
    payload["observed"][0]["valid_until"] = None
    response = client.post(f"{ROOT}/system_dependency/sources/cluster-payments/collections", json=payload)
    assert response.status_code == 409


def test_non_utc_source_and_operator_deadlines_are_normalized_before_sqlite_loses_offset(estate):
    client, db, _, _ = estate
    offset = timezone(timedelta(hours=5, minutes=30))
    row = edge_rows(client)[0]
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).astimezone(offset)
    response = state(client, "system_dependency", row, "STALE", valid_until=past.isoformat())
    assert response.status_code == 200
    assert response.json()["effective_state"] == "EXPIRED"
    from shared_models.relationship_lifecycle import utc
    assert utc(response.json()["valid_until"]) == past.astimezone(timezone.utc)
    row = claim(client, "system_dependency", response.json())
    observed = (datetime.now(timezone.utc) - timedelta(minutes=2)).astimezone(offset)
    response, payload = collect(client, "system_dependency", rows=[row],
        observed_at=observed.isoformat(), observed=[{"id": row["id"], "expected_revision": row["lifecycle_revision"], "valid_until": past.isoformat()}])
    assert response.status_code == 200, response.text
    current_row = client.get(path("system_dependency", row)).json()
    assert current_row["effective_state"] == "EXPIRED"
    assert utc(current_row["last_confirmed_at"]) == observed.astimezone(timezone.utc)
    # Equivalent UTC instants are the same immutable collection, not a conflict.
    payload["observed_at"] = observed.astimezone(timezone.utc).isoformat()
    payload["observed"][0]["valid_until"] = past.astimezone(timezone.utc).isoformat()
    retry = client.post(f"{ROOT}/system_dependency/sources/cluster-payments/collections", json=payload)
    assert retry.status_code == 200 and retry.json() == response.json()
    new_edge = client.post("/api/v1/graph/edges", json={"parent_id": "web", "child_id": "db", "valid_until": past.isoformat()})
    assert new_edge.status_code == 200, new_edge.text
    assert new_edge.json()["edge"]["effective_state"] == "EXPIRED"
