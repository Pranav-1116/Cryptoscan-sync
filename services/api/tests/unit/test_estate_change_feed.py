"""Live change detection, and the feed of what moved (spec 94 §17–§18, §23).

A change feed is only worth having if it can be trusted in both directions: it must
name what moved specifically enough to act on, and it must not manufacture movement
out of a quiet scan or a gap in collection.

The properties under test:

* every claim names a subject and what it was before and after — "drift detected" is
  not an answer to "what changed";
* a lost plane outranks anything else, because the estate under it is UNKNOWN;
* losing proof is not the cryptography being removed, and a demotion says so;
* identical observations produce **no** event — storing "nothing happened" on every
  quiet scan would bury the one afternoon something did;
* a replayed detection appends nothing: the same transition increments an
  observation counter;
* ``NO_CHANGE`` is not "safe", ``BASELINE`` is not "no change", and an empty feed is
  not an empty estate;
* a simulation never appears in the feed — a what-if is not an observation.
"""

from __future__ import annotations

import copy

import pytest

from api import estate_change_feed as feed
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
CHANGES = f"{BASE}/changes"


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "environment": "production"},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production"},
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "LB-07", "environment": "production"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"}},
            {"evidence_id": "ev-2", "source": "/etc/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "HSM",
             "facts": {"hsm_reference": "HSM-03"}},
            {"evidence_id": "ev-3", "source": "probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "lb", "layer": "NETWORK_TRANSPORT",
             "facts": {"protocol": "TLSv1.3", "algorithm": "AES-256-GCM"}},
        ],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
        ],
        "collectors": [
            {"plane": "APPLICATION", "expected": 1, "collected": 1, "status": "COMPLETE"},
            {"plane": "HSM", "expected": 1, "collected": 1, "status": "COMPLETE"},
            {"plane": "NETWORK", "expected": 1, "collected": 1, "status": "COMPLETE"},
        ],
        "coverage": [
            {"target": "APPLICATION", "expected": 1, "collected": 1, "status": "COMPLETE"},
            {"target": "HSM", "expected": 1, "collected": 1, "status": "COMPLETE"},
            {"target": "NETWORK", "expected": 1, "collected": 1, "status": "COMPLETE"},
        ],
    }


def _graph(payload: dict | None = None):
    return build_graph(payload or _payload())


def _payload_with_hsm_04() -> dict:
    payload = _payload()
    payload["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04",
                              "environment": "production"})
    return payload


def _payload_with_coverage(status: str) -> dict:
    """A payload where the HSM plane answered, then stopped answering."""
    payload = _payload()
    collected = 3 if status == "COMPLETE" else 0
    payload["collectors"] = [
        {"plane": "HSM", "status": status, "expected": 3, "collected": collected,
         "reason": None if status == "COMPLETE" else "pkcs11 provider did not answer"}
    ]
    payload["coverage"] = [
        {"plane": "HSM", "target": "HSM appliances", "expected": 3, "collected": collected,
         "status": status}
    ]
    return payload


def _kinds(detection: dict) -> list[str]:
    return [change["kind"] for change in detection["changes"]]


# -- the baseline case is not a change ------------------------------------- #


def test_a_first_observation_is_a_baseline_not_an_empty_change():
    detection = feed.describe(None, _graph())
    assert detection["verdict"] == "BASELINE"
    assert detection["severity"] == "BASELINE"
    assert detection["changed"] is None
    assert detection["changes"] == []
    assert "not 'no change'" in detection["meaning"]


def test_identical_observations_are_not_storable():
    graph = _graph()
    detection = feed.describe(graph, graph)
    assert detection["verdict"] == "NO_CHANGE"
    assert detection["severity"] == "NONE"
    assert detection["changed"] is False
    assert detection["storable"] is False
    assert detection["changes"] == []
    assert "not a statement that the estate is safe" in detection["severity_meaning"]


# -- what changed, specifically -------------------------------------------- #


def test_a_new_asset_is_named_with_its_type_and_environment():
    before = _payload()
    after = copy.deepcopy(before)
    after["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04", "environment": "production"})
    detection = feed.describe(_graph(before), _graph(after))
    added = [c for c in detection["changes"] if c["kind"] == "ASSET_ADDED"]
    assert len(added) == 1
    assert "HSM-04" in added[0]["detail"] and "HSM" in added[0]["detail"]
    assert added[0]["severity"] == "WARNING"
    assert detection["severity"] == "WARNING"


def test_a_changed_field_names_the_field_the_before_and_the_after():
    before = _payload()
    after = copy.deepcopy(before)
    after["assets"][0]["environment"] = "staging"
    detection = feed.describe(_graph(before), _graph(after))
    changed = [c for c in detection["changes"] if c["kind"] == "ASSET_CHANGED"]
    assert changed, _kinds(detection)
    entry = changed[0]
    assert "environment" in entry["detail"]
    assert entry["before"].get("environment") == "production"
    assert entry["after"].get("environment") == "staging"


def test_losing_usage_proof_is_a_demotion_that_does_not_claim_removal():
    before = _payload()
    after = copy.deepcopy(before)
    # the runtime observation becomes a configuration statement: the same algorithm,
    # weaker proof
    after["evidence"][0]["evidence_type"] = "CONFIGURED"
    detection = feed.describe(_graph(before), _graph(after))
    demoted = [c for c in detection["changes"] if c["kind"] == "CRYPTO_DEMOTED"]
    assert demoted, _kinds(detection)
    assert demoted[0]["before"] == "OBSERVED"
    assert demoted[0]["after"] == "CONFIGURED"
    assert "proof was lost" in demoted[0]["means"]
    assert detection["severity"] == "WARNING"


def test_a_lost_plane_is_critical_and_outranks_a_crypto_change():
    before = _payload()
    after = copy.deepcopy(before)
    after["evidence"][0]["evidence_type"] = "STATIC_OBSERVED"  # a crypto move as well
    after["collectors"][1]["status"] = "FAILED"
    after["collectors"][1]["collected"] = 0
    after["coverage"][1]["status"] = "FAILED"
    after["coverage"][1]["collected"] = 0
    after["coverage"][1]["reason"] = "API unavailable"
    detection = feed.describe(_graph(before), _graph(after))

    kinds = _kinds(detection)
    assert "COVERAGE_DEGRADED" in kinds
    assert detection["severity"] == "CRITICAL"
    degraded = next(c for c in detection["changes"] if c["kind"] == "COVERAGE_DEGRADED")
    assert degraded["subject"] == "HSM"
    assert degraded["before"] == "COMPLETE" and degraded["after"] == "FAILED"
    assert "API unavailable" in degraded["detail"]
    assert "UNKNOWN" in degraded["means"]
    assert detection["next_action"].startswith("restore the plane")


def test_a_lost_relationship_is_named_with_its_predicate_and_basis():
    before = _payload()
    after = copy.deepcopy(before)
    after["relationships"] = []
    detection = feed.describe(_graph(before), _graph(after))
    lost = [c for c in detection["changes"] if c["kind"] == "RELATIONSHIP_LOST"]
    assert lost, _kinds(detection)
    assert "uses_hsm" in lost[0]["subject"]
    assert "PKCS11_REFERENCE" in lost[0]["detail"]
    assert lost[0]["severity"] == "WARNING"


def test_an_asset_that_stops_carrying_crypto_evidence_is_unknown_not_clean():
    before = _payload()
    after = copy.deepcopy(before)
    after["assets"].append({"ref": "bare", "type": "HOST", "name": "legacy-box"})
    detection = feed.describe(_graph(before), _graph(after))
    kinds = _kinds(detection)
    assert "ASSET_ADDED" in kinds
    assert "UNKNOWN_GAINED" in kinds
    gained = next(c for c in detection["changes"] if c["kind"] == "UNKNOWN_GAINED")
    assert "uncharacterised, not crypto-free" in gained["means"]


def test_the_headline_counts_kinds_rather_than_saying_drift_detected():
    before = _payload()
    after = copy.deepcopy(before)
    after["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    after["assets"].append({"ref": "hsm3", "type": "HSM", "name": "HSM-05"})
    detection = feed.describe(_graph(before), _graph(after))
    assert "2× asset added" in detection["headline"]


# -- the feed stores movement, and only movement --------------------------- #


def test_a_quiet_observation_stores_nothing(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    http.post(f"{BASE}/discover", json=_payload())  # identical evidence
    body = http.get(CHANGES).json()
    assert body["count"] == 1  # only the baseline
    assert [event["verdict"] for event in body["events"]] == ["BASELINE"]


def test_the_baseline_is_recorded_so_the_feed_has_a_start(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    body = http.get(CHANGES).json()
    first = body["events"][0]
    assert first["verdict"] == "BASELINE"
    assert first["changed"] is None
    assert first["changes"] == []


def test_a_real_change_is_recorded_and_readable(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    changed = _payload()
    changed["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    http.post(f"{BASE}/discover", json=changed)

    body = http.get(CHANGES).json()
    assert body["count"] == 2
    newest = body["events"][0]
    assert newest["verdict"] in {"ESTATE_CHANGED", "CRYPTO_CHANGED"}
    assert newest["severity"] == "WARNING"
    assert body["by_kind"].get("ASSET_ADDED") == 1
    assert any("HSM-04" in c["detail"] for c in newest["changes"])
    assert newest["is_estate_state"] is True

    single = http.get(f"{CHANGES}/{newest['event_id']}").json()
    assert single["event_id"] == newest["event_id"]
    assert single["next_action"]


def test_a_redetected_transition_is_not_a_second_event(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    changed = _payload()
    changed["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    http.post(f"{BASE}/discover", json=changed)

    before = http.get(CHANGES).json()["count"]
    detected = http.post(f"{CHANGES}/detect").json()
    assert detected["stored"]["created"] is False
    assert http.get(CHANGES).json()["count"] == before


def test_detect_re_derives_the_feed_from_stored_observations(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    detected = http.post(f"{CHANGES}/detect").json()
    # one observation: there is nothing to compare against, so it is a baseline
    assert detected["verdict"] == "BASELINE"
    assert detected["stored"]["created"] is False


def test_detect_without_any_observation_is_a_404(api):
    http, _session = api
    response = http.post(f"{CHANGES}/detect")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"


def test_coverage_loss_is_recorded_as_critical_in_the_feed(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    degraded = _payload()
    degraded["collectors"][1]["status"] = "FAILED"
    degraded["collectors"][1]["collected"] = 0
    degraded["coverage"][1]["status"] = "FAILED"
    degraded["coverage"][1]["collected"] = 0
    degraded["evidence"] = [item for item in degraded["evidence"] if item["target"] != "api"
                            or item["layer"] != "HSM"]
    http.post(f"{BASE}/discover", json=degraded)

    newest = http.get(CHANGES).json()["events"][0]
    assert newest["severity"] == "CRITICAL"
    assert newest["counts"].get("COVERAGE_DEGRADED") == 1
    assert newest["next_action"].startswith("restore the plane")


def test_the_feed_can_be_filtered_to_critical_and_unacknowledged(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    degraded = _payload()
    degraded["collectors"][1]["status"] = "FAILED"
    degraded["collectors"][1]["collected"] = 0
    degraded["coverage"][1]["status"] = "FAILED"
    degraded["coverage"][1]["collected"] = 0
    http.post(f"{BASE}/discover", json=degraded)

    critical = http.get(CHANGES, params={"severity": "CRITICAL"}).json()
    assert critical["count"] == 1
    assert critical["events"][0]["severity"] == "CRITICAL"

    kinds = http.get(CHANGES, params={"kind": "COVERAGE_DEGRADED"}).json()
    assert kinds["count"] == 1

    assert http.get(CHANGES, params={"unacknowledged_only": True}).json()["unacknowledged"] == 2


def test_acknowledging_records_who_saw_it_and_changes_nothing_else(api):
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    changed = _payload()
    changed["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    http.post(f"{BASE}/discover", json=changed)
    event = http.get(CHANGES).json()["events"][0]

    acked = http.post(f"{CHANGES}/{event['event_id']}/acknowledge", json={"note": "ticket CR-4471"}).json()
    assert acked["acknowledged"] is True
    assert acked["acknowledgement_note"] == "ticket CR-4471"
    assert acked["changes"] == event["changes"]
    assert acked["severity"] == event["severity"]
    assert http.get(CHANGES, params={"unacknowledged_only": True}).json()["count"] == 1


def test_an_unknown_change_is_a_404_not_an_empty_answer(api):
    http, _session = api
    assert http.get(f"{CHANGES}/chg_nope").status_code == 404
    assert http.post(f"{CHANGES}/chg_nope/acknowledge", json={}).status_code == 404


def test_a_simulation_never_appears_in_the_change_feed(api):
    """A what-if is not an observation, and cannot enter the record of what happened."""
    http, _session = api
    http.post(f"{BASE}/discover", json=_payload())
    before = http.get(CHANGES).json()
    simulated = http.post(
        f"{BASE}/twin/simulate",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM", "persist": True},
    ).json()
    assert simulated["persisted"] is True
    after = http.get(CHANGES).json()
    assert after["count"] == before["count"]
    assert after["by_kind"] == before["by_kind"]


def test_a_detection_failure_does_not_fail_the_run():
    """A broken feed must not cost a scan: detection is best-effort by construction."""
    from api import estate_discovery

    class _Broken:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("feed table unavailable")

        def rollback(self):
            raise RuntimeError("rollback also unavailable")

    report = estate_discovery.run(
        _Broken(),
        estate="synthetic",
        planes=[],
        collectors={},
        persist=False,
        include_boms=False,
        previous=_payload(),
    )
    # the observation still returned: the run happened, only the feed is missing it
    assert report["detection"]["recorded"]["created"] is False
    assert report["detection"]["recorded"]["error"].startswith("RuntimeError")
    assert "could not be stored" in report["detection"]["recorded"]["note"]


def test_the_feed_says_what_a_quiet_feed_does_not_mean(api):
    http, _session = api
    body = http.get(CHANGES).json()
    assert body["count"] == 0
    assert "not that the estate is safe" in body["meaning"]
    assert any("scheduler that stopped running" in limit for limit in body["limits"])


# -- announcing a change, so it is not just a row in a table ----------------- #


def _session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _journal(session, event_type: str | None = None) -> list:
    from db.models.monitor import MonitorEvent

    query = session.query(MonitorEvent)
    if event_type:
        query = query.filter(MonitorEvent.event_type == event_type)
    return query.all()


def test_a_detected_change_is_announced_on_the_platform_journal():
    before, after = _graph(), _graph(_payload_with_hsm_04())
    session = _session()

    detection = feed.observe(session, before, after, tenant_id=None, run_id="run-2")

    assert detection["recorded"]["created"] is True
    assert detection["announced"]["published"] is True
    assert detection["announced"]["event_types"] == ["estate.change.detected"]
    rows = _journal(session, "estate.change.detected")
    assert len(rows) == 1, "an unannounced change only reaches the person who opens the console"
    assert rows[0].payload["changes"], "the announcement says what moved, not merely that it moved"


def test_losing_a_plane_is_announced_as_coverage_lost_not_as_a_change_to_read():
    before = _graph(_payload_with_coverage("COMPLETE"))
    after = _graph(_payload_with_coverage("FAILED"))
    session = _session()

    detection = feed.observe(session, before, after, tenant_id=None, run_id="run-2")

    assert detection["severity"] == "CRITICAL"
    types = detection["announced"]["event_types"]
    assert "estate.change.detected" in types
    assert "estate.coverage.lost" in types, "a dark plane is a measurement that stopped, not a change"
    lost = _journal(session, "estate.coverage.lost")
    assert lost, "a CRITICAL coverage loss must be announced on its own event type"
    assert "HSM" in lost[0].payload["planes"]


def test_a_quiet_observation_announces_nothing():
    graph = _graph()
    session = _session()

    detection = feed.observe(session, graph, graph, tenant_id=None, run_id="run-2")

    assert detection["recorded"]["created"] is False
    assert "announced" not in detection
    assert _journal(session) == []


def test_a_broken_journal_never_fails_the_observation():
    class _NoJournal:
        def execute(self, *args, **kwargs):
            raise RuntimeError("journal unavailable")

        def rollback(self):
            raise RuntimeError("rollback unavailable too")

    before, after = _graph(), _graph(_payload_with_hsm_04())

    # neither the storage failure nor the failing rollback may escape
    detection = feed.observe(_NoJournal(), before, after, tenant_id=None, run_id="run-2")

    assert detection["recorded"]["created"] is False
    assert "journal unavailable" in detection["recorded"]["error"]
    assert detection["changes"], "the detection itself is still returned to the caller"


def test_the_change_classes_are_routable_and_mapped():
    from control_plane.notification_routing import CATALOG, EVENT_CLASS_MAP

    classes = {entry["id"]: entry for entry in CATALOG}
    assert classes["estate_change"]["channels"]["inApp"] is True
    assert classes["estate_coverage_lost"]["severity"] == "CRITICAL"
    assert EVENT_CLASS_MAP["estate.change.detected"] == "estate_change"
    assert EVENT_CLASS_MAP["estate.coverage.lost"] == "estate_coverage_lost"


def test_an_announced_change_reaches_the_in_app_notification_feed(api):
    """The loop closes: detect, journal, and the notification feed serves it when routed."""
    from db.repositories.monitor_repository import MonitorRepository

    client, session = api
    shim = type("T", (), {"id": None, "name": "estate", "tenant_id": None})()
    MonitorRepository(session).add_event(
        target=shim,
        event_type="estate.change.detected",
        detail="1 change(s): 1x asset added",
        payload={"changes": [{"kind": "ASSET_ADDED", "subject": "HSM-04"}]},
    )
    session.commit()

    body = client.get("/api/v1/notifications/feed").json()

    classes = {item["event_class"] for item in body["notifications"]}
    assert "estate_change" in classes, (
        "an estate change with no catalog mapping is invisible to the notification matrix"
    )
    assert "estate.change.detected" in body["mapped_event_types"]
