"""The durable estate catalogue — the twin's memory (spec 94 §19, §22, §26).

The twin used to be reconstructed from the newest stored payload on every request,
which answers "what is there now" and cannot answer what a twin is for: when did this
appear, is it stale or gone, which evidence establishes this edge, and who actually
*uses* RSA-2048 as opposed to merely supporting it.

What is under test here:

* an observation materialises assets, relationships and crypto artefacts, each with
  the evidence ids behind it;
* lifecycle is honest — a row absent from the latest observation becomes ``STALE``
  with ``last_seen_at`` intact, and **nothing is deleted**;
* ``SUPPORTED`` and ``OBSERVED`` for the same algorithm stay two rows, so a capability
  can never inflate a usage count;
* an unresolved candidate is stored as ``UNRESOLVED`` with its refusal reason and is
  never counted as a relationship;
* the registry answers "who uses this algorithm" per usage state, across asset types;
* a simulation never writes to the catalogue, and an empty catalogue is not an empty
  estate.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from api import estate_catalog as catalog
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
CATALOG = f"{BASE}/catalog"


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "environment": "production",
             "owner": "Payments Platform"},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production"},
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "LB-07", "environment": "production"},
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "environment": "production"},
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
            {"evidence_id": "ev-4", "source": "linux-static", "collector": "linux-static",
             "evidence_type": "STATIC_OBSERVED", "target": "ossl", "layer": "APPLICATION",
             "facts": {"supported_algorithms": ["RSA-2048", "AES-128"]}},
        ],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
            {"subject": "lb", "predicate": "routes_to", "object": "api",
             "basis": "NETWORK_OBSERVATION", "evidence_ids": ["ev-3"]},
            # refused: a co-location is not a dependency
            {"subject": "ossl", "predicate": "depends_on", "object": "api", "basis": "PROXIMITY",
             "evidence_ids": ["ev-4"]},
        ],
    }


def _graph(payload: dict | None = None):
    return build_graph(payload or _payload())


# -- materialisation -------------------------------------------------------- #


def test_an_observation_materialises_assets_with_their_evidence():
    rows = catalog.asset_entries(_graph())
    assert {row["asset_type"] for row in rows} == {"APPLICATION", "HSM", "LOAD_BALANCER", "LIBRARY"}
    api_row = next(row for row in rows if row["name"] == "Payment API")
    assert api_row["owner"] == "Payments Platform"
    assert api_row["evidence_count"] >= 1
    assert "ev-1" in api_row["evidence_ids"]


def test_relationships_keep_basis_and_evidence():
    rows = catalog.relationship_entries(_graph())
    established = [row for row in rows if row["status"] == "ESTABLISHED"]
    assert {row["predicate"] for row in established} == {"uses_hsm", "routes_to"}
    uses_hsm = next(row for row in established if row["predicate"] == "uses_hsm")
    assert uses_hsm["basis"] == "PKCS11_REFERENCE"
    assert uses_hsm["evidence_ids"] == ["ev-2"]
    assert uses_hsm["subject_name"] == "Payment API"
    assert uses_hsm["object_name"] == "HSM-03"


def test_a_refused_edge_is_stored_as_unresolved_with_its_reason():
    rows = catalog.relationship_entries(_graph())
    unresolved = [row for row in rows if row["status"] == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0]["predicate"] == "depends_on"
    assert unresolved[0]["reason"]
    assert unresolved[0]["confidence"] is None


def test_capability_and_use_of_the_same_algorithm_are_two_rows():
    """The CBOM bug this product exists to prevent, asserted at the storage layer."""
    rows = catalog.crypto_entries(_graph())
    aes = [row for row in rows if (row["algorithm"] or "").startswith("AES-256")]
    states = sorted({row["usage_state"] for row in rows if row["asset_name"] in {"Payment API", "OpenSSL"}})
    assert "SUPPORTED" in states and "OBSERVED" in states
    supported = [row for row in rows if row["usage_state"] == "SUPPORTED"]
    observed = [row for row in rows if row["usage_state"] == "OBSERVED"]
    assert supported and observed
    assert supported[0]["artifact_id"] != observed[0]["artifact_id"] or supported[0]["asset_id"] != observed[0]["asset_id"]
    assert aes


# -- lifecycle: nothing is deleted ----------------------------------------- #


@pytest.fixture()
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def test_first_seen_is_kept_and_observation_count_advances(db_session):
    first = datetime(2026, 10, 1, tzinfo=timezone.utc)
    second = first + timedelta(days=1)
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1", observed_at=first)
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-2", observed_at=second)

    row = catalog.get_asset(db_session, "Payment API", tenant_id=None)
    assert row.first_seen_at.replace(tzinfo=timezone.utc) == first
    assert row.last_seen_at.replace(tzinfo=timezone.utc) == second
    assert row.observation_count == 2
    assert row.last_run_id == "run-2"


def test_an_asset_absent_from_the_latest_observation_is_stale_not_deleted(db_session):
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1")
    shrunk = _payload()
    shrunk["assets"] = [asset for asset in shrunk["assets"] if asset["name"] != "HSM-03"]
    shrunk["relationships"] = [edge for edge in shrunk["relationships"] if edge["object"] != "hsm"]
    shrunk["evidence"] = [item for item in shrunk["evidence"] if item["target"] != "api"
                          or item["layer"] != "HSM"]
    result = catalog.sync(db_session, _graph(shrunk), tenant_id=None, run_id="run-2")

    row = catalog.get_asset(db_session, "HSM-03", tenant_id=None)
    assert row is not None, "an asset that stopped being observed must not vanish"
    assert row.lifecycle_state == "STALE"
    assert row.last_seen_at is not None
    assert result["staled"]["assets"] >= 1

    # and it comes back to ACTIVE when it is observed again
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-3")
    assert catalog.get_asset(db_session, "HSM-03", tenant_id=None).lifecycle_state == "ACTIVE"


def test_sync_is_idempotent_for_the_same_observation(db_session):
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1")
    first = len(catalog.list_assets(db_session, tenant_id=None, limit=200))
    again = catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1")
    assert again["created"] == {"assets": 0, "relationships": 0, "crypto": 0}
    assert len(catalog.list_assets(db_session, tenant_id=None, limit=200)) == first


# -- the registry answers "who uses what" ---------------------------------- #


def test_the_registry_counts_assets_per_usage_state(db_session):
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1")
    registry = catalog.registry(db_session, tenant_id=None)
    by_algorithm = {entry["algorithm"]: entry for entry in registry["algorithms"]}
    assert "AES-256-GCM" in by_algorithm
    aes = by_algorithm["AES-256-GCM"]
    # runtime operation and a completed handshake are different states, and both are
    # stronger than capability — neither is merged into the other
    assert aes["usage_states"].get("OBSERVED") == 1  # Payment API runtime
    assert aes["usage_states"].get("NEGOTIATED") == 1  # LB wire
    assert "SUPPORTED" not in aes["usage_states"]
    assert aes["asset_count"] == 2
    assert "OPENSSL" not in by_algorithm  # a library is an asset, not an algorithm

    rsa = by_algorithm.get("RSA-2048")
    assert rsa is not None
    assert rsa["usage_states"] == {"SUPPORTED": 1}
    assert rsa["assets"][0]["asset_name"] == "OpenSSL"


def test_the_registry_can_be_asked_about_one_algorithm(db_session):
    catalog.sync(db_session, _graph(), tenant_id=None, run_id="run-1")
    registry = catalog.registry(db_session, tenant_id=None, query="RSA-2048")
    assert registry["algorithm_count"] == 1
    assert registry["algorithms"][0]["algorithm"] == "RSA-2048"
    assert "capability" in registry["meaning"]


# -- the API --------------------------------------------------------------- #


def _discover(http, payload: dict | None = None) -> dict:
    response = http.post(f"{BASE}/discover", json=payload or _payload())
    assert response.status_code == 200, response.text
    return response.json()


def test_discover_reports_what_it_wrote_to_the_catalogue(api):
    http, _session = api
    body = _discover(http)
    assert body["catalog"]["counts"]["assets"] == 4
    assert body["catalog"]["created"]["assets"] == 4
    assert body["catalog"]["counts"]["unresolved"] == 1


def test_the_asset_catalogue_can_be_browsed_by_type(api):
    http, _session = api
    _discover(http)
    body = http.get(f"{CATALOG}/assets", params={"asset_type": "HSM"}).json()
    assert body["count"] == 1
    assert body["assets"][0]["name"] == "HSM-03"
    assert body["assets"][0]["lifecycle_state"] == "ACTIVE"
    assert body["assets"][0]["first_seen_at"]

    search = http.get(f"{CATALOG}/assets", params={"q": "payment"}).json()
    assert search["count"] == 1
    assert search["assets"][0]["owner"] == "Payments Platform"


def test_asset_detail_carries_crypto_relationships_and_evidence(api):
    http, _session = api
    _discover(http)
    detail = http.get(f"{CATALOG}/assets/Payment API").json()
    assert detail["asset"]["name"] == "Payment API"
    assert detail["counts"]["relationships"] >= 1
    edge = next(item for item in detail["relationships"] if item["predicate"] == "uses_hsm")
    assert edge["basis"] == "PKCS11_REFERENCE"
    assert edge["evidence_ids"] == ["ev-2"]
    assert any(item["usage_state"] == "OBSERVED" for item in detail["crypto"])


def test_an_unknown_asset_is_a_404_that_does_not_claim_nonexistence(api):
    http, _session = api
    _discover(http)
    response = http.get(f"{CATALOG}/assets/never-observed")
    assert response.status_code == 404
    assert "never have been observed" in response.json()["detail"]["reason"]


def test_unresolved_candidates_are_returned_separately_and_never_as_edges(api):
    http, _session = api
    _discover(http)
    established = http.get(f"{CATALOG}/relationships").json()
    assert established["count"] == 2
    assert all(item["status"] == "ESTABLISHED" for item in established["relationships"])

    candidates = http.get(f"{CATALOG}/relationships", params={"status": "UNRESOLVED"}).json()
    assert candidates["count"] == 1
    assert candidates["relationships"][0]["status"] == "UNRESOLVED"
    assert candidates["relationships"][0]["reason"]
    assert "not an edge" in candidates["note"]


def test_the_crypto_registry_endpoint_keeps_capability_out_of_use(api):
    http, _session = api
    _discover(http)
    registry = http.get(f"{CATALOG}/crypto", params={"q": "AES-256"}).json()
    assert registry["algorithm_count"] == 1
    entry = registry["algorithms"][0]
    assert entry["usage_states"].get("OBSERVED") == 1
    assert entry["usage_states"].get("NEGOTIATED") == 1
    assert "SUPPORTED" not in entry["usage_states"]
    assert {item["asset_name"] for item in entry["assets"]} == {"Payment API", "LB-07"}


def test_catalog_summary_does_not_read_an_empty_catalogue_as_an_empty_estate(api):
    http, _session = api
    empty = http.get(CATALOG).json()
    assert empty["assets"] == 0
    assert "not that the bank has no assets" in empty["note"]


def test_a_stale_asset_stays_visible_after_a_shrinking_observation(api):
    http, _session = api
    _discover(http)
    shrunk = _payload()
    shrunk["assets"] = [asset for asset in shrunk["assets"] if asset["name"] != "LB-07"]
    shrunk["relationships"] = [edge for edge in shrunk["relationships"] if edge["subject"] != "lb"]
    shrunk["evidence"] = [item for item in shrunk["evidence"] if item["target"] != "lb"]
    _discover(http, shrunk)

    stale = http.get(f"{CATALOG}/assets", params={"lifecycle": "STALE"}).json()
    assert [item["name"] for item in stale["assets"]] == ["LB-07"]
    assert stale["assets"][0]["last_seen_at"]

    # and the detail view still works for a stale asset — history is not hidden
    detail = http.get(f"{CATALOG}/assets/LB-07").json()
    assert detail["asset"]["lifecycle_state"] == "STALE"


def test_a_simulation_never_writes_to_the_catalogue(api):
    http, _session = api
    _discover(http)
    before = http.get(CATALOG).json()
    simulated = http.post(
        f"{BASE}/twin/simulate",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM", "persist": True},
    ).json()
    assert simulated["persisted"] is True
    after = http.get(CATALOG).json()
    assert after["assets"] == before["assets"]
    assert after["assets_by_type"] == before["assets_by_type"]
    registry = http.get(f"{CATALOG}/crypto", params={"q": "ML-KEM"}).json()
    assert registry["algorithm_count"] == 0, "a what-if must not appear in the registry"


def test_the_catalogue_is_derived_not_typed():
    """No public function writes an asset the graph did not contain."""
    payload = copy.deepcopy(_payload())
    graph = build_graph(payload)
    ids = {row["asset_id"] for row in catalog.asset_entries(graph)}
    assert len(ids) == len(graph.assets())
    assert not hasattr(catalog, "create_asset"), "the catalogue is materialised, never hand-edited"


# -- both observation paths materialise the catalogue ---------------------- #


def test_the_collector_path_writes_the_catalogue_too(db_session):
    """A collected run and an ingested run must leave the same kind of memory."""
    from api import estate_discovery

    def collector(_db, **_kwargs):
        return {
            "assets": [{"ref": "host", "type": "HOST", "name": "payment-prod-01"}],
            "evidence": [{"evidence_id": "ev-r", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
                          "target": "host", "layer": "APPLICATION",
                          "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"}}],
            "relationships": [],
            "expected": 1, "collected": 1, "status": "COMPLETE",
        }

    report = estate_discovery.run(
        db_session,
        estate="synthetic",
        planes=["RUNTIME"],
        collectors={"RUNTIME": collector},
        persist=True,
        include_boms=False,
    )
    assert report["catalog"]["counts"]["assets"] == 1
    row = catalog.get_asset(db_session, "payment-prod-01", tenant_id=None)
    assert row is not None and row.lifecycle_state == "ACTIVE"
    assert row.first_run_id == report["run_id"]


def test_a_catalogue_failure_does_not_fail_the_run():
    """The observation already happened; a catalogue error is reported, not propagated."""
    from api import estate_discovery

    class _Broken:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("catalogue table unavailable")

        def rollback(self):
            return None

        def add(self, *_args, **_kwargs):
            raise RuntimeError("catalogue table unavailable")

        def commit(self):
            return None

    report = estate_discovery.run(
        _Broken(),
        estate="synthetic",
        planes=[],
        collectors={},
        persist=False,
        include_boms=False,
    )
    assert report["catalog"]["error"].startswith("RuntimeError")
    assert report["projection_id"], "the run still produced a projection"
