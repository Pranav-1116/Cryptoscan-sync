"""The live pipeline over HTTP: baseline once, store changes only, download the current BOMs."""
from __future__ import annotations


import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.models.base import Base
from shared_models import release_signature


@pytest.fixture
def api():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


@pytest.fixture
def keys(tmp_path):
    return release_signature.generate_keypair(tmp_path / "keys", name="collector")


def _trust(monkeypatch, keys):
    import api.routers.ingestion as ingestion

    trusted = release_signature.load_public_key(keys["public_key"])
    monkeypatch.setattr(ingestion, "trusted_keys", lambda: [trusted])


def _observation(*, extra: bool = False, version: str = "3.0.13") -> dict:
    assets = [
        {"ref": "host-01", "type": "HOST", "name": "host-01", "identity": {"hostname": "host-01.bank.local"}},
        {"ref": "api", "type": "APPLICATION", "name": "payments-api", "owner": "Payments"},
        {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "identity": {"name": "OpenSSL", "version": version}},
    ]
    evidence = [
        {
            "evidence_id": "ev-lib",
            "source": "linux-static",
            "evidence_type": "STATIC_OBSERVED",
            "target": "ossl",
            "layer": "APPLICATION",
            "facts": {"name": "OpenSSL", "version": version, "algorithm": "AES", "key_size": 256, "mode": "GCM"},
        },
        {
            "evidence_id": "ev-host",
            "source": "linux-static",
            "evidence_type": "STATIC_OBSERVED",
            "target": "host-01",
            "layer": "PLATFORM",
            "facts": {"hostname": "host-01.bank.local"},
        },
    ]
    if extra:
        assets.append({"ref": "host-02", "type": "HOST", "name": "host-02", "identity": {"hostname": "host-02"}})
        evidence.append(
            {
                "evidence_id": "ev-host-2",
                "source": "linux-static",
                "evidence_type": "STATIC_OBSERVED",
                "target": "host-02",
                "layer": "PLATFORM",
                "facts": {"hostname": "host-02"},
            }
        )
    return {
        "estate": "payments",
        "scope": "production",
        "inventory_id": "INV-1",
        "observed_at": "2026-10-29T17:00:00Z",
        "assets": assets,
        "evidence": evidence,
        "relationships": [],
        "collectors": [{"plane": "Linux hosts", "state": "COMPLETE", "expected": 2, "collected": 2}],
        "coverage": [{"plane": "Linux hosts", "expected": 2, "collected": 2}],
    }


def test_the_first_observation_is_stored_in_full(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)

    response = http.post("/api/v1/ingestion/observations", json=_observation())

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "FIRST_BASELINE"
    assert body["stored"] is True
    assert body["run_id"]
    assert body["comparison"]["full_write"] is True
    assert body["detection"]["verdict"] in {"BASELINE", "ESTATE_CHANGED"}
    assert body["bom_counts"]["SBOM"] >= 1


def test_an_unchanged_observation_stores_nothing_but_keeps_the_connection(api, keys, monkeypatch):
    http, session = api
    _trust(monkeypatch, keys)
    first = http.post("/api/v1/ingestion/observations", json=_observation()).json()

    second = http.post("/api/v1/ingestion/observations", json=_observation())

    assert second.status_code == 200
    body = second.json()
    assert body["state"] == "NO_CHANGE"
    assert body["stored"] is False
    assert body["projection_id"] == first["projection_id"]
    assert body["run_id"] is None
    assert body["heartbeat"]["state"] == "NO_CHANGE"
    assert body["heartbeat"]["stores_estate"] is False
    # one stored observation, not two: the estate was not copied again
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 1

    status = http.get("/api/v1/ingestion/live/status").json()
    assert status["connection"]["state"] == "LIVE"
    assert status["twin"]["state"] == "OBSERVED"


def test_a_changed_observation_is_stored_as_a_change_with_the_affected_projections(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())

    response = http.post("/api/v1/ingestion/observations", json=_observation(version="3.0.11"))

    assert response.status_code == 201
    body = response.json()
    assert body["state"] == "CHANGED"
    assert body["stored"] is True
    assert body["detection"]["changes"], "a changed observation with no named change is not a change"
    assert "TECHBOM" in body["bom_impact"]["affected"]
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 2


def test_the_current_bom_can_be_downloaded_from_the_live_twin(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    body = http.post("/api/v1/ingestion/observations", json=_observation()).json()

    response = http.get("/api/v1/estate/evidence/boms/CBOM/export?fmt=cyclonedx")

    assert response.status_code == 200, response.text
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-cryptoscan-projection-id"] == body["projection_id"]
    document = response.json()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"

    native = http.get("/api/v1/estate/evidence/boms/TECHBOM/export?fmt=json").json()
    assert native["projection"]["projection_id"] == body["projection_id"]

    every = http.get("/api/v1/estate/evidence/boms/export").json()
    assert set(every["projections"]) == {"SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"}
    assert every["projection_id"] == body["projection_id"]


def test_downloading_a_bom_before_any_observation_is_404_not_an_empty_document(api):
    http, _session = api

    response = http.get("/api/v1/estate/evidence/boms/CBOM/export")

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"

    status = http.get("/api/v1/ingestion/live/status").json()
    assert status["connection"]["state"] == "NEVER_CONNECTED"
    assert status["twin"]["state"] == "NOT_OBSERVED"
    assert status["boms"]["projection_id"] is None


def test_a_signed_observation_is_verified_against_the_configured_key(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    payload = _observation()
    document = {"schema": "cryptoscan.live-observation/1", **payload}
    signature = release_signature.sign_document(
        document, release_signature.load_private_key(keys["private_key"])
    )

    response = http.post("/api/v1/ingestion/observations", json={**payload, "signature": signature})

    assert response.status_code == 201, response.text
    authenticity = response.json()["authenticity"]
    assert authenticity["status"] == "VALID"
    assert authenticity["store_authorised_for_authenticity"] is True


def test_an_unsigned_observation_is_stored_as_unauthenticated_and_says_so(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)

    body = http.post("/api/v1/ingestion/observations", json=_observation()).json()

    authenticity = body["authenticity"]
    assert authenticity["status"] == "UNSIGNED"
    assert authenticity["store_authorised_for_authenticity"] is False
    assert any("not authenticated" in finding for finding in authenticity["deployment_findings"])


def test_a_deployment_with_no_trust_key_reports_that_instead_of_trusting_anything(api, keys):
    http, _session = api
    payload = _observation()
    signature = release_signature.sign_document(
        {"schema": "cryptoscan.live-observation/1", **payload},
        release_signature.load_private_key(keys["private_key"]),
    )

    response = http.post(
        "/api/v1/ingestion/observations",
        json={**payload, "signature": signature},
    ).json()

    # a signature checked against nothing is not a valid signature
    assert response["authenticity"]["status"] == "SIGNED_UNVERIFIED"
    assert response["authenticity"]["trust_keys_configured"] == 0
    assert any("NO_TRUSTED_COLLECTOR_KEY" in finding for finding in response["authenticity"]["deployment_findings"])


def test_a_deployment_can_require_signatures(api, monkeypatch):
    http, _session = api
    monkeypatch.setenv("CRYPTOSCAN_REQUIRE_SIGNED_OBSERVATIONS", "1")

    response = http.post("/api/v1/ingestion/observations", json=_observation())

    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "observation_not_authentic"
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 0


def test_the_agent_state_hash_is_compared_rather_than_trusted(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)

    body = http.post(
        "/api/v1/ingestion/observations",
        json={**_observation(), "state_hash": "0" * 64},
    ).json()

    assert body["state_hash"]["claimed"] == "0" * 64
    assert body["state_hash"]["agrees"] is False
    assert body["projection_id"] != body["state_hash"]["claimed"]


def test_a_payload_with_a_dangling_evidence_target_is_refused_and_nothing_is_stored(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    payload = _observation()
    payload["evidence"].append(
        {
            "evidence_id": "ev-dangling",
            "source": "linux-static",
            "evidence_type": "STATIC_OBSERVED",
            "target": "ghost",
            "layer": "APPLICATION",
            "facts": {"algorithm": "RSA"},
        }
    )

    response = http.post("/api/v1/ingestion/observations", json=payload)

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "observation_rejected"
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 0


def test_the_change_feed_and_the_patterns_read_the_same_stored_changes(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())
    http.post("/api/v1/ingestion/observations", json=_observation(extra=True))

    feed = http.get("/api/v1/estate/evidence/changes").json()
    assert feed["count"] >= 1

    patterns = http.get("/api/v1/estate/evidence/threat/patterns?window_seconds=604800").json()
    assert patterns["events_considered"] >= 1
    assert patterns["schema"] == "cryptoscan.attack-patterns/1"
    assert patterns["highest_level"] != 3
    # a stored change is correlated into at least one named pattern or none — never into "safe"
    assert "not that the estate is safe" in patterns["note"]


# -- retention: the change feed grows, the twin does not ------------------------------- #


def _backdate(session, days: int, *, keep_newest: int = 1) -> None:
    """Age every stored observation except the newest N — the newest is the twin."""
    from datetime import datetime, timedelta, timezone

    from db.models.network_scan_run import NetworkScanRun

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = sorted(
        session.query(NetworkScanRun).filter(NetworkScanRun.target_kind == "estate-discovery").all(),
        key=lambda row: (row.created_at, row.id),
        reverse=True,
    )
    for row in rows[keep_newest:]:
        row.created_at = cutoff
    session.commit()


def test_compaction_is_a_dry_run_until_confirmed(api, keys, monkeypatch):
    http, session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())
    http.post("/api/v1/ingestion/observations", json=_observation(extra=True))
    _backdate(session, 90)

    plan = http.post(
        "/api/v1/ingestion/live/compact", json={"keep_days": 30, "keep_latest_observations": 1}
    )

    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert body["dry_run"] is True
    assert body["candidates"]["observations"] == 1, "the newest observation must never be a candidate"
    assert body["deleted"] == {"observations": 0, "change_events": 0}
    assert "nothing was deleted" in body["note"]
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 2


def test_compaction_keeps_the_twin_and_the_newest_change_event(api, keys, monkeypatch):
    http, session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())
    http.post("/api/v1/ingestion/observations", json=_observation(extra=True))
    latest = http.get("/api/v1/ingestion/live/status").json()
    _backdate(session, 90)

    applied = http.post(
        "/api/v1/ingestion/live/compact",
        json={"keep_days": 30, "keep_latest_observations": 1, "confirm": True, "include_change_events": False},
    ).json()

    assert applied["dry_run"] is False
    assert applied["deleted"]["observations"] == 1
    assert http.get("/api/v1/ingestion/observations").json()["count"] == 1
    # the twin the BOM download projects from is still there and unchanged
    status = http.get("/api/v1/ingestion/live/status").json()
    assert status["twin"]["state"] == "OBSERVED"
    assert status["twin"]["projection_id"] == latest["twin"]["projection_id"]
    assert http.get("/api/v1/estate/evidence/boms/CBOM/export").status_code == 200


def test_an_unacknowledged_claim_is_never_trimmed(api, keys, monkeypatch):
    http, session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())
    http.post("/api/v1/ingestion/observations", json=_observation(extra=True))
    _backdate(session, 90)

    from db.models.estate_change_event import EstateChangeEvent

    events = session.query(EstateChangeEvent).all()
    assert events, "the changed observation should have produced a change event"
    for row in events:
        row.last_detected_at = row.last_detected_at.replace(year=2025)
    session.commit()

    result = http.post(
        "/api/v1/ingestion/live/compact",
        json={"keep_days": 30, "confirm": True, "include_change_events": True, "acknowledged_only": True},
    ).json()

    assert result["candidates"]["change_events"] == 0, "an unread claim is not history yet"
    assert session.query(EstateChangeEvent).count() == len(events)


# -- the collection path stores changes too -------------------------------------------- #


def test_a_second_scan_of_an_unchanged_estate_writes_nothing(api):
    http, _session = api

    first = http.post("/api/v1/estate/evidence/scan", json={"persist": True})
    second = http.post("/api/v1/estate/evidence/scan", json={"persist": True})

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["storage"]["state"] in {"FIRST_BASELINE", "CHANGED"}
    assert first.json()["storage"]["stored"] is True
    assert second.json()["storage"]["state"] == "NO_CHANGE"
    assert second.json()["storage"]["stored"] is False
    assert second.json()["run_id"] is None


def test_a_forced_scan_stores_a_revision_even_when_nothing_changed(api):
    http, _session = api
    http.post("/api/v1/estate/evidence/scan", json={"persist": True})

    forced = http.post("/api/v1/estate/evidence/scan", json={"persist": True, "force": True})

    assert forced.json()["storage"]["stored"] is True
    assert forced.json()["run_id"]


# -- corroboration is read from the evidence store, not invented ----------------------- #


def _attributed_observation() -> dict:
    document = _observation(extra=True)
    document["evidence"] = [{**item, "collector": "linux-static/1.4.0"} for item in document["evidence"]]
    # an edge appearing at the same time as a crypto artefact is the pair TRUST_PATH_MUTATION
    # needs; the edge carries its own evidence so a second collector is traceable
    document["relationships"] = [
        {
            "subject": "api",
            "predicate": "routes_to",
            "object": "host-02",
            "basis": "NETWORK_OBSERVATION",
            "evidence_ids": ["ev-tls"],
        }
    ]
    document["evidence"].append(
        {
            "evidence_id": "ev-tls",
            "source": "network-tls",
            "collector": "network-tls/0.9.1",
            "evidence_type": "RUNTIME_OBSERVED",
            "target": "host-02",
            "layer": "NETWORK_TRANSPORT",
            "facts": {"endpoint": "host-02:443", "protocol": "TLSv1.3", "algorithm": "AES", "key_size": 256},
        }
    )
    return document


def test_patterns_carry_the_collectors_whose_evidence_stands_behind_them(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    http.post("/api/v1/ingestion/observations", json=_observation())
    stored = http.post("/api/v1/ingestion/observations", json=_attributed_observation())
    assert stored.status_code == 201, stored.text
    assert stored.json()["stored"] is True

    patterns = http.get("/api/v1/estate/evidence/threat/patterns", params={"window_seconds": 86400})

    assert patterns.status_code == 200, patterns.text
    body = patterns.json()
    traced = {
        collector
        for item in body["patterns"]
        for collector in item["corroboration"]["collectors"]
    }
    assert traced & {"linux-static/1.4.0", "network-tls/0.9.1"}, "no pattern traced to a collector"
    for item in body["patterns"]:
        assert item["corroboration"]["does_not_change_level"]
        assert item["level"] <= 4
    assert body["corroboration"]["evidence_mapped"] >= 1


def test_the_storage_note_never_claims_nothing_was_written_when_a_revision_was(api):
    http, _session = api
    http.post("/api/v1/estate/evidence/scan", json={"persist": True})

    forced = http.post("/api/v1/estate/evidence/scan", json={"persist": True, "force": True}).json()

    assert forced["storage"]["stored"] is True
    assert "nothing was written" not in forced["storage"]["note"]
    quiet = http.post("/api/v1/estate/evidence/scan", json={"persist": True}).json()
    assert quiet["storage"]["stored"] is False
    assert "nothing was written" in quiet["storage"]["note"]
