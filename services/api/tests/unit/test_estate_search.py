"""One search over the recorded estate (spec 94 §26).

A bank question arrives as one sentence and is really four: "where is RSA-2048?" means
*which assets, which artefacts, which edges, and which evidence says so*. The search
module answers all four in one call, and these tests hold it to the two things that make
a search result trustworthy:

* **it never turns capability into use** — an algorithm hit is grouped by `usage_state`,
  so a library that supports RSA-2048 and an API observed using it are different rows;
* **a miss is reported as a miss of the record, not of the estate** — zero results comes
  back with the sentence that says so, because an empty list is read as a finding by
  everyone who did not write the query.

Also covered: grouping by kind, per-kind truncation stated rather than hidden, an empty
query refused rather than answered with everything, an unknown kind refused rather than
ignored, and a claim inside a change event being findable (otherwise "who demoted
RSA-2048?" would be unanswerable).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_catalog as catalog
from api import estate_change_feed as change_feed
from api import estate_observations as history
from api import estate_search as search
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
SEARCH = f"{BASE}/search"


@pytest.fixture()
def db():
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


def _payload(algorithm: str = "RSA-2048", region: str = "me-central-1") -> dict:
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API",
             "environment": "production", "owner": "Payments Platform",
             "attributes": {"region": region}},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production"},
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "environment": "production"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "collector": "linux-runtime",
             "evidence_type": "RUNTIME_OBSERVED", "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": algorithm, "role": "encrypt"}},
            {"evidence_id": "ev-2", "source": "/etc/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "HSM",
             "facts": {"hsm_reference": "HSM-03"}},
            {"evidence_id": "ev-3", "source": "sast", "collector": "sbom-parser",
             "evidence_type": "STATIC_OBSERVED", "target": "ossl", "layer": "PLATFORM",
             "facts": {"supported_algorithms": [algorithm]}},
        ],
        "crypto": [
            {"asset": "api", "algorithm": algorithm, "usage_state": "OBSERVED",
             "evidence_ids": ["ev-1"], "layer": "APPLICATION"},
            {"asset": "ossl", "algorithm": algorithm, "usage_state": "SUPPORTED",
             "evidence_ids": ["ev-3"], "layer": "PLATFORM"},
        ],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
        ],
        "collectors": [
            {"plane": "RUNTIME", "status": "COMPLETE", "expected": 1, "collected": 1},
        ],
    }


def _seed(session, payload: dict | None = None) -> dict:
    graph = build_graph(payload or _payload())
    catalog.sync(session, graph, tenant_id=None)
    history.sync_all(session, graph, tenant_id=None)
    return {"graph": graph}


def test_one_query_reaches_assets_artefacts_edges_evidence_and_facts(db):
    _seed(db)

    result = search.search(db, "RSA-2048", tenant_id=None)

    assert set(result["groups"]) == {"ASSETS", "CRYPTO", "RELATIONSHIPS", "EVIDENCE", "FACTS", "CHANGES"}
    assert result["groups"]["CRYPTO"]["count"] == 2
    assert result["groups"]["EVIDENCE"]["count"] >= 1
    # the asset search matches an algorithm only through what it carries, not by name
    assert result["matched"] > 0
    assert result["query"] == "RSA-2048"


def test_capability_and_use_are_never_summed_into_one_count(db):
    _seed(db)

    crypto = search.search(db, "RSA-2048", tenant_id=None, kinds=["CRYPTO"])["groups"]["CRYPTO"]

    assert crypto["usage_states"] == {"OBSERVED": 1, "SUPPORTED": 1}
    assert "capability" in crypto["note"]
    observed = next(hit for hit in crypto["hits"] if hit["label"].startswith("Payment API"))
    supported = next(hit for hit in crypto["hits"] if hit["label"].startswith("OpenSSL"))
    assert observed["usage_states"] == {"OBSERVED": 1}
    assert supported["usage_states"] == {"SUPPORTED": 1}


def test_an_asset_search_matches_name_owner_environment_and_type(db):
    _seed(db)

    for needle in ("Payment", "Payments Platform", "production", "HSM"):
        result = search.search(db, needle, tenant_id=None, kinds=["ASSETS"])
        assert result["groups"]["ASSETS"]["count"] >= 1, needle


def test_a_fact_search_answers_where_something_is_placed(db):
    _seed(db)

    result = search.search(db, "me-central-1", tenant_id=None, kinds=["FACTS"])

    facts = result["groups"]["FACTS"]
    assert facts["count"] == 1
    assert facts["hits"][0]["label"] == "attribute:region = me-central-1"
    assert facts["hits"][0]["state"] == "CURRENT"
    assert facts["hits"][0]["asset_id"].startswith("application:")


def test_an_empty_result_says_it_is_a_gap_in_the_record(db):
    _seed(db)

    result = search.search(db, "Kyber-1024", tenant_id=None)

    assert result["matched"] == 0
    assert any("not that the bank has none" in limit for limit in result["limits"])


def test_results_are_bounded_and_truncation_is_stated(db):
    payload = _payload()
    for index in range(12):
        payload["assets"].append({
            "ref": f"hsml{index}", "type": "HSM", "name": f"HSM-{index:02d}",
            "environment": "production",
        })
    _seed(db, payload)

    result = search.search(db, "HSM", tenant_id=None, kinds=["ASSETS"], limit=5)

    group = result["groups"]["ASSETS"]
    assert len(group["hits"]) == 5
    assert group["truncated"] is True
    assert group["limit"] == 5


def test_an_unresolved_candidate_is_findable_and_labelled(db):
    payload = _payload()
    payload["relationships"].append({
        "subject": "api", "predicate": "depends_on", "object": "ossl", "basis": "PROXIMITY",
    })
    _seed(db, payload)

    hits = search.search(db, "OpenSSL", tenant_id=None, kinds=["RELATIONSHIPS"])["groups"]["RELATIONSHIPS"]["hits"]

    statuses = {hit["status"] for hit in hits}
    assert "UNRESOLVED" in statuses
    unresolved = next(hit for hit in hits if hit["status"] == "UNRESOLVED")
    assert unresolved["reason"], "a candidate must carry why it was refused"


def test_a_claim_inside_a_change_event_is_searchable(db):
    before = build_graph(_payload(algorithm="RSA-2048"))
    after = build_graph(_payload(algorithm="ML-DSA-65"))
    change_feed.observe(db, before, after, tenant_id=None, run_id="run-2")

    hits = search.search(db, "ML-DSA-65", tenant_id=None, kinds=["CHANGES"])["groups"]["CHANGES"]["hits"]

    assert hits, "a demotion nobody can find is a demotion nobody acts on"
    assert hits[0]["id"].startswith("chg_")


def test_an_empty_query_is_refused_rather_than_answered_with_everything(db):
    _seed(db)
    with pytest.raises(ValueError, match="empty query"):
        search.search(db, "   ", tenant_id=None)


def test_an_unknown_kind_is_refused_rather_than_silently_ignored(db):
    _seed(db)
    with pytest.raises(ValueError, match="unknown search kind"):
        search.search(db, "RSA", tenant_id=None, kinds=["ASSETS", "SECRETS"])


def test_kind_filtering_limits_the_work_and_the_answer(db):
    _seed(db)

    result = search.search(db, "RSA-2048", tenant_id=None, kinds=["CRYPTO", "EVIDENCE"])

    assert set(result["groups"]) == {"CRYPTO", "EVIDENCE"}
    assert result["kinds"] == ["CRYPTO", "EVIDENCE"]


# -- API surface ------------------------------------------------------------ #


def test_search_endpoint_groups_by_kind(api, db):
    client, session = api
    _seed(session)

    response = client.get(SEARCH, params={"q": "RSA-2048"})

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "cryptoscan.estate-search/1"
    assert body["groups"]["CRYPTO"]["usage_states"] == {"OBSERVED": 1, "SUPPORTED": 1}
    assert body["limits"]


def test_search_endpoint_refuses_an_unknown_kind_with_a_reason(api):
    client, _session = api

    response = client.get(SEARCH, params={"q": "RSA", "kinds": "ASSETS,SECRETS"})

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "bad_search"
    assert "SECRETS" in response.json()["detail"]["reason"]
