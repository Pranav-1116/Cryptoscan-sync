"""Evidence records and per-fact observation history (spec 94 §11, §19, §28).

The catalogue (0113) remembers assets. It cannot answer "what was this asset's
algorithm on Tuesday", because a changed attribute used to be an overwritten column,
and it cannot answer "which record, from which collector, when" without re-reading the
stored payload. These tests pin the rules that make the new tables trustworthy:

* a fact is a value with a window — a change adds a row and retires the previous one,
  and nothing is deleted;
* re-observing the same value is a *refresh*, not a change, so a quiet estate does not
  look busy;
* a value that returns is revived rather than duplicated (one row, two windows);
* two values still asserted stay two ``CURRENT`` rows and are reported as a conflict —
  the twin never picks one;
* a fact that stops being observed is retired, not deleted, which is what makes
  "when did we stop seeing this" answerable;
* evidence is content-addressed, so a record seen forty times is one row;
* every answer stops where the evidence stops: attribution is asset-scoped and says so.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_catalog as catalog
from api import estate_observations as history
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)


@pytest.fixture
def db():
    """A real session over the real models: the rules are about rows, not mocks."""
    from db.models.base import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()

BASE = "/api/v1/estate/evidence"


def _payload(
    algorithm: str = "AES-256-GCM",
    region: str | None = "me-central-1",
    assets: int = 2,
    evidence: int = 2,
) -> dict:
    entries = {
        "api": {"ref": "api", "type": "APPLICATION", "name": "Payment API",
                "environment": "production", "owner": "Payments Platform",
                "attributes": {"region": region} if region else {}},
        "hsm": {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production"},
    }
    if assets == 1:
        entries.pop("hsm")
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": list(entries.values()),
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": algorithm, "role": "encrypt"}},
            {"evidence_id": "ev-2", "source": "/etc/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "HSM",
             "facts": {"hsm_reference": "HSM-03"}},
        ][:evidence],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
        ] if assets > 1 else [],
        "crypto": [
            {"asset": "api", "algorithm": algorithm, "usage_state": "OBSERVED",
             "evidence_ids": ["ev-1"], "layer": "APPLICATION"},
        ],
    }


def _naive(moment: datetime) -> datetime:
    """SQLite hands datetimes back without a zone; compare on the wall clock."""
    return moment.replace(tzinfo=None) if moment else moment


def _observations(db):
    from db.models.estate_catalog import EstateObservationRecord

    return list(db.execute(select(EstateObservationRecord)).scalars())


def _evidence(db):
    from db.models.estate_catalog import EstateEvidenceRecord

    return list(db.execute(select(EstateEvidenceRecord)).scalars())


def _now(offset: int = 0) -> datetime:
    return datetime(2026, 3, 1, tzinfo=timezone.utc) + timedelta(days=offset)


def test_one_observation_records_each_fact_with_the_value_and_its_window(db):
    graph = build_graph(_payload())

    result = history.sync(db, graph, tenant_id=None, observed_at=_now())

    rows = _observations(db)
    facts = {row.fact_type for row in rows}
    assert {"asset_type", "name", "environment", "owner", "attribute:region"} <= facts
    assert "crypto:algorithm" in facts
    assert "relationship:USES_HSM" in facts
    assert result["created"] == len(rows)
    assert result["superseded"] == 0
    assert all(row.lifecycle_state == "CURRENT" for row in _observations(db))
    # every fact cites the evidence that establishes its asset, not an invented per-value id
    region = next(row for row in rows if row.fact_type == "attribute:region")
    assert region.evidence_id in {"ev-1", "ev-2"}
    assert region.value_kind == "text"


def test_the_same_observation_again_is_a_refresh_not_a_change(db):
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None, observed_at=_now())
    count = len(_observations(db))

    result = history.sync(db, graph, tenant_id=None, observed_at=_now(1))

    assert len(_observations(db)) == count, "a quiet estate must not look busy"
    assert result["created"] == 0
    assert result["superseded"] == 0
    assert result["refreshed"] == count
    assert all(row.lifecycle_state == "CURRENT" for row in _observations(db))
    assert all(row.observation_count == 2 for row in _observations(db)), [
        (row.fact_type, row.observation_count) for row in _observations(db)
    ]


def test_a_changed_value_retires_the_previous_row_and_keeps_its_window(db):
    history.sync(db, build_graph(_payload(region="me-central-1")), tenant_id=None, observed_at=_now())
    result = history.sync(
        db, build_graph(_payload(region="me-west-1")), tenant_id=None, observed_at=_now(5)
    )

    regions = [row for row in _observations(db) if row.fact_type == "attribute:region"]
    assert len(regions) == 2, "a change is a new window, not an overwritten column"
    old = next(row for row in regions if row.value == "me-central-1")
    new = next(row for row in regions if row.value == "me-west-1")
    assert old.lifecycle_state == "HISTORICAL"
    assert new.lifecycle_state == "CURRENT"
    assert result["superseded"] >= 1
    assert _naive(old.first_seen_at) == _naive(_now())
    assert _naive(old.last_seen_at) == _naive(_now())


def test_a_value_that_comes_back_is_revived_rather_than_duplicated(db):
    history.sync(db, build_graph(_payload(region="me-central-1")), tenant_id=None, observed_at=_now())
    history.sync(db, build_graph(_payload(region="me-west-1")), tenant_id=None, observed_at=_now(1))
    result = history.sync(
        db, build_graph(_payload(region="me-central-1")), tenant_id=None, observed_at=_now(2)
    )

    regions = [row for row in _observations(db) if row.fact_type == "attribute:region"]
    assert len(regions) == 2, "a region we return to is the same value, not a third fact"
    assert result["revived"] >= 1
    assert next(row for row in regions if row.value == "me-central-1").lifecycle_state == "CURRENT"


def test_a_fact_no_longer_observed_is_retired_not_deleted(db):
    history.sync(db, build_graph(_payload()), tenant_id=None, observed_at=_now())
    removed = [row for row in _observations(db) if row.fact_type == "attribute:region"]

    result = history.sync(db, build_graph(_payload(region=None)), tenant_id=None, observed_at=_now(1))

    assert result["retired"] >= 1
    assert removed[0] in _observations(db), "history is appended to, never pruned"
    assert removed[0].lifecycle_state == "HISTORICAL"
    assert _naive(removed[0].last_seen_at) == _naive(_now())


def test_an_asset_that_disappears_retires_all_of_its_facts(db):
    history.sync(db, build_graph(_payload(assets=2)), tenant_id=None, observed_at=_now())
    hsm_id = next(row.asset_id for row in _observations(db)
                  if row.fact_type == "name" and row.value == "HSM-03")
    hsm_facts = [row for row in _observations(db) if row.asset_id == hsm_id]
    assert hsm_facts

    history.sync(db, build_graph(_payload(assets=1)), tenant_id=None, observed_at=_now(1))

    assert hsm_facts[0] in _observations(db)
    assert all(row.lifecycle_state == "HISTORICAL" for row in hsm_facts)


def test_two_values_asserted_in_one_observation_are_a_conflict_not_a_choice(db):
    """The graph can hold two objects for one predicate; the twin keeps both."""
    payload = _payload()
    payload["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04",
                              "environment": "production"})
    payload["relationships"].append(
        {"subject": "api", "predicate": "uses_hsm", "object": "hsm2",
         "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]}
    )
    result = history.sync(db, build_graph(payload), tenant_id=None, observed_at=_now())

    assert [item["fact_type"] for item in result["conflicts"]] == ["relationship:USES_HSM"]
    current = [row for row in _observations(db)
               if row.fact_type == "relationship:USES_HSM" and row.lifecycle_state == "CURRENT"]
    assert len(current) == 2, "two asserted objects stay two rows — picking one would be a lie"

    summary = history.summary(db, tenant_id=None)
    assert summary["observations"]["disputed_facts"] == 1
    assert summary["disputes"][0]["fact_type"] == "relationship:USES_HSM"


def test_a_changed_value_is_reported_as_superseded(db):
    history.sync(db, build_graph(_payload()), tenant_id=None, observed_at=_now())
    result = history.sync(
        db, build_graph(_payload(algorithm="AES-128-GCM")), tenant_id=None, observed_at=_now(1)
    )

    assert result["superseded"] >= 1
    # one asset, one value per fact: a change is supersession, not a dispute
    assert result["conflicts"] == []
    algorithms = [row for row in _observations(db) if row.fact_type == "crypto:algorithm"]
    assert {row.lifecycle_state for row in algorithms} == {"CURRENT", "HISTORICAL"}


def test_evidence_is_content_addressed_so_a_repeat_observation_is_one_row(db):
    history.sync_evidence(db, build_graph(_payload()), tenant_id=None, observed_at=_now())
    rows = _evidence(db)
    history.sync_evidence(db, build_graph(_payload()), tenant_id=None, observed_at=_now(1))

    assert len(_evidence(db)) == len(rows), "the same record twice is still one record"
    assert all(row.observation_count == 2 for row in _evidence(db))
    assert all(row.lifecycle_state == "ACTIVE" for row in _evidence(db))
    assert _naive(rows[0].first_seen_at) == _naive(_now())

    result = history.sync_evidence(
        db, build_graph(_payload(evidence=1)), tenant_id=None, observed_at=_now(2)
    )
    assert result["stale"] == 1, "evidence no longer produced is stale, never deleted"
    assert len(_evidence(db)) == len(rows), "and it is still there"


# -- API surface ------------------------------------------------------------ #


def test_a_name_resolves_to_its_asset_id_without_a_catalogue_row(db):
    """History is written by the observation path; a name must resolve on its own."""
    history.sync_all(db, build_graph(_payload()), tenant_id=None)

    resolved = history.resolve_asset_id(db, "Payment API", tenant_id=None)
    assert resolved.startswith("application:")
    assert history.history(db, "Payment API", tenant_id=None)["fact_count"] > 0
    # and an unknown name is returned unchanged rather than guessed at
    assert history.resolve_asset_id(db, "not-an-asset", tenant_id=None) == "not-an-asset"


def test_history_endpoints_explain_absence_instead_of_returning_an_empty_list(api, db):
    client, _session = api
    assert client.get(f"{BASE}/history/summary").status_code == 200

    missing = client.get(f"{BASE}/history/assets/APPLICATION:never-seen")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error"] == "no_history"
    assert "not an assertion" in missing.json()["detail"]["reason"]

    why = client.get(f"{BASE}/why/APPLICATION:never-seen", params={"fact_type": "environment"})
    assert why.status_code == 404
    assert why.json()["detail"]["error"] == "nothing_to_explain"


def test_history_survives_a_real_session_round_trip(api):
    """The write path and the read path agree, through an actual database session."""
    client, db = api
    catalog.sync(db, build_graph(_payload()), tenant_id=None)
    history.sync_all(db, build_graph(_payload()), tenant_id=None)
    first = [row for row in _observations(db) if row.lifecycle_state == "CURRENT"]
    assert first

    history.sync_all(db, build_graph(_payload(region="me-west-1")), tenant_id=None)
    db.expire_all()
    regions = [row for row in _observations(db) if row.fact_type == "attribute:region"]
    assert {row.lifecycle_state for row in regions} == {"CURRENT", "HISTORICAL"}

    asset_id = next(row.asset_id for row in regions)
    detail = client.get(f"{BASE}/history/assets/{asset_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["fact_count"] > 0
    region_fact = next(item for item in body["facts"] if item["fact_type"] == "attribute:region")
    assert region_fact["current_values"] == ["me-west-1"]
    assert len(region_fact["timeline"]) == 2
    assert region_fact["timeline"][0]["state"] in {"CURRENT", "HISTORICAL"}

    why = client.get(f"{BASE}/why/{asset_id}", params={"fact_type": "attribute:region"})
    assert why.status_code == 200
    answer = why.json()
    assert answer["evidence_scope"] == "ASSET"
    assert "attribute" in answer["limit"]
    assert answer["evidence"], "the answer must show the evidence behind the asset"
    assert answer["current_values"] == ["me-west-1"]

    records = client.get(f"{BASE}/evidence/records", params={"target": asset_id})
    assert records.status_code == 200
    assert records.json()["count"] >= 1


def test_an_evidence_record_keeps_the_collector_version_and_where_its_output_lives(db):
    """§11: "linux-static" does not identify a build, and a path alone cannot be re-read."""
    from shared_models.estate_graph import build_graph

    payload = _payload()
    payload["evidence"][1]["collector_version"] = "1.4.0"
    payload["evidence"][1]["raw_reference"] = "artifact://runs/42/pkcs11.conf"
    history.sync_evidence(db, build_graph(payload), tenant_id=None)

    records = history.evidence_for(db, target=None, tenant_id=None)["records"]
    configured = next(item for item in records if item["evidence_id"] == "ev-2")

    assert configured["collector"] == "linux-static"
    assert configured["collector_version"] == "1.4.0"
    assert configured["raw_reference"] == "artifact://runs/42/pkcs11.conf"


def test_a_collector_upgrade_corrects_the_provenance_and_does_not_add_a_record(db):
    """The fact did not change; the probe did. One row, newer provenance."""
    from shared_models.estate_graph import build_graph

    first = _payload()
    first["evidence"][1]["collector_version"] = "1.4.0"
    history.sync_evidence(db, build_graph(first), tenant_id=None)

    second = _payload()
    second["evidence"][1]["collector_version"] = "1.5.0"
    second["evidence"][1]["raw_reference"] = "artifact://runs/43/pkcs11.conf"
    history.sync_evidence(db, build_graph(second), tenant_id=None)

    records = history.evidence_for(db, target=None, tenant_id=None)["records"]
    rows = [item for item in records if item["evidence_id"] == "ev-2"]

    assert len(rows) == 1
    assert rows[0]["collector_version"] == "1.5.0"
    assert rows[0]["observation_count"] == 2
    assert rows[0]["raw_reference"] == "artifact://runs/43/pkcs11.conf"


def test_a_record_without_a_version_does_not_claim_one(db):
    from shared_models.estate_graph import build_graph

    history.sync_evidence(db, build_graph(_payload()), tenant_id=None)

    records = history.evidence_for(db, target=None, tenant_id=None)["records"]

    assert all(item["collector_version"] is None for item in records)
