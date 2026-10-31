"""Runtime observation → walkable twin edges (the link both gaps needed).

Gap B ends at "we saw the call". Gap C ends at "we can follow the chain". In between
sits the producer nobody had written: a stored runtime event became an evidence
record and a crypto *artefact*, and never an asset or an edge, so the twin's chain
stopped dead at the application.

This test drives the whole loop over the real HTTP surface:

    approved runtime scope → runtime events ingested → RUNTIME plane collected
        → estate discovery run stored → GET /twin/path walks it

and pins the refusals that keep it honest: no provider means no library edge, no
algorithm means no algorithm edge, and a walk over observed edges says it was
observed rather than configured.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.main import create_app
from db.connection.session import Base

from api import estate_discovery
from api import estate_runtime_edges


def _scope() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "name": "payments-runtime",
        "hosts": ["payments-prod-01"],
        "applications": ["payments-api"],
        "processes": ["payments-api"],
        "runtime_methods": ["CRYPTO_API_TRACE", "PROCESS_TELEMETRY"],
        "data_restrictions": ["NO_PLAINTEXT", "NO_PRIVATE_KEYS", "NO_CUSTOMER_DATA"],
        "collection_window": {
            "from": (now - timedelta(hours=1)).isoformat(),
            "to": (now + timedelta(hours=1)).isoformat(),
        },
    }


def _observation(**overrides) -> dict:
    observation = {
        "source": "OPENSSL_TRACE",
        "runtime_method": "CRYPTO_API_TRACE",
        "host": "payments-prod-01",
        "application": "payments-api",
        "process": "payments-api",
        "pid": 1842,
        "executable": "/opt/payments/payment-api",
        "executable_digest": "sha256:abc123",
        "crypto_provider": "OpenSSL",
        "algorithm": "AES-256-GCM",
        "key_size": 256,
        "mode": "GCM",
        "operation": "ENCRYPT",
    }
    observation.update(overrides)
    return observation


@pytest.fixture()
def api(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    app.dependency_overrides[get_tenant_context] = lambda: type(
        "Ctx", (), {"tenant_id": None, "roles": ["superadmin"], "username": "tester"}
    )()
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def _ingest(http, observations: list[dict]) -> dict:
    assert http.put("/api/v1/runtime/crypto-scope", json=_scope()).status_code == 200
    response = http.post("/api/v1/runtime/crypto-events", json={"observations": observations})
    assert response.status_code == 200, response.text
    return response.json()


def _discover(session) -> dict:
    return estate_discovery.run(session, estate="payments", planes=["RUNTIME"])


# --------------------------------------------------------------------------- #
# the producer
# --------------------------------------------------------------------------- #


def test_a_named_provider_becomes_a_library_edge_on_a_runtime_basis():
    built = estate_runtime_edges.build([
        {"app_ref": "app", "evidence_ref": "ev-1", "provider": "OpenSSL",
         "algorithm": "AES-256-GCM", "operation": "ENCRYPT", "key_size": 256},
    ])
    edges = {(edge["subject"], edge["predicate"], edge["object"]) for edge in built["relationships"]}
    assert edges == {
        ("app", "uses_crypto_library", "crypto-library:openssl"),
        ("app", "uses_algorithm", "crypto-algorithm:aes-256-gcm"),
        ("crypto-library:openssl", "uses_algorithm", "crypto-algorithm:aes-256-gcm"),
    }
    for edge in built["relationships"]:
        assert edge["basis"] == "RUNTIME_OBSERVATION"
        assert edge["attributes"]["usage_state"] == "OBSERVED"
        assert edge["evidence_refs"] == ["ev-1"]
    library = next(asset for asset in built["assets"] if asset["type"] == "LIBRARY")
    assert library["attributes"]["version"] == "UNKNOWN", (
        "a traced provider name is not a version; inventing one would be a fabricated fact"
    )


def test_an_unnamed_provider_produces_no_library_edge_and_is_counted():
    built = estate_runtime_edges.build([
        {"app_ref": "app", "evidence_ref": "ev-1", "provider": None, "algorithm": "AES-256-GCM"},
        {"app_ref": "app", "evidence_ref": "ev-2", "provider": "UNKNOWN", "algorithm": "AES-256-GCM"},
    ])
    predicates = {edge["predicate"] for edge in built["relationships"]}
    assert predicates == {"uses_algorithm"}
    assert built["summary"]["events_without_provider"] == 2


def test_an_algorithmless_call_produces_no_algorithm_edge_and_is_counted():
    built = estate_runtime_edges.build([
        {"app_ref": "app", "evidence_ref": "ev-1", "provider": "OpenSSL", "algorithm": None},
    ])
    predicates = {edge["predicate"] for edge in built["relationships"]}
    assert predicates == {"uses_crypto_library"}
    assert built["summary"]["events_without_algorithm"] == 1


def test_evidence_is_cited_once_per_edge_and_capped_honestly():
    rows = [
        {"app_ref": "app", "evidence_ref": f"ev-{index}", "provider": "OpenSSL",
         "algorithm": "AES-256-GCM"}
        for index in range(estate_runtime_edges.MAX_EVIDENCE_PER_EDGE + 10)
    ]
    rows.append(rows[0])  # a repeated ref must not be cited twice
    built = estate_runtime_edges.build(rows)
    library_edge = next(e for e in built["relationships"] if e["predicate"] == "uses_crypto_library")
    assert len(library_edge["evidence_refs"]) == estate_runtime_edges.MAX_EVIDENCE_PER_EDGE
    assert library_edge["attributes"]["evidence_incomplete"] is True
    assert library_edge["attributes"]["evidence_total"] == estate_runtime_edges.MAX_EVIDENCE_PER_EDGE + 10
    assert library_edge["attributes"]["observation_count"] == len(rows)


# --------------------------------------------------------------------------- #
# the loop, over HTTP + the discovery job
# --------------------------------------------------------------------------- #


def test_ingested_runtime_events_become_a_walkable_observed_chain(api):
    http, session = api
    _ingest(http, [_observation()])
    report = _discover(session)
    assert report["failed_planes"] == []
    assert report["collectors"][0]["plane"] == "RUNTIME"
    assert report["collectors"][0]["status"] == "COMPLETE"
    assert report["summary"]["assets"] >= 3
    assert report["unresolved_relationships"] == []

    chain = http.get(
        "/api/v1/estate/evidence/twin/path",
        params={
            "asset": "payments-api",
            "pattern": "uses_crypto_library:LIBRARY,uses_algorithm:CRYPTO_ASSET",
        },
    )
    assert chain.status_code == 200, chain.text
    body = chain.json()
    assert body["status"] == "COMPLETE", body
    assert [hop["basis"] for hop in body["hops"]] == ["RUNTIME_OBSERVATION", "RUNTIME_OBSERVATION"]
    assert all(hop["evidence_ids"] for hop in body["hops"])
    assert body["requires_runtime_observation"] is False
    assert body["hops"][0]["usage_state"] == "OBSERVED"
    assert body["rendered"] == "payments-api —uses_crypto_library→ OpenSSL —uses_algorithm→ AES-256-GCM"


def test_a_chain_from_configuration_alone_is_flagged(api):
    """The same two hops, claimed from a manifest instead of from a trace."""
    http, session = api
    discovered = http.post("/api/v1/estate/evidence/discover", json={
        "estate": "payments",
        "assets": [
            {"ref": "app", "type": "APPLICATION", "name": "payments-api"},
            {"ref": "lib", "type": "LIBRARY", "name": "OpenSSL"},
            {"ref": "alg", "type": "CRYPTO_ASSET", "name": "AES-256-GCM"},
        ],
        "evidence": [
            {"ref": "ev-manifest", "source": "kubernetes", "evidence_type": "CONFIGURED",
             "target": "app", "layer": "APPLICATION", "facts": {"dependency": "libssl3"}},
        ],
        "relationships": [
            {"subject": "app", "predicate": "uses_crypto_library", "object": "lib",
             "basis": "DEPLOYMENT_CONFIG", "evidence_refs": ["ev-manifest"]},
            {"subject": "app", "predicate": "uses_algorithm", "object": "alg",
             "basis": "DEPLOYMENT_CONFIG", "evidence_refs": ["ev-manifest"]},
        ],
    })
    assert discovered.status_code == 200, discovered.text
    assert discovered.json()["unresolved_relationships"] == []

    body = http.get(
        "/api/v1/estate/evidence/twin/path",
        params={
            "asset": "payments-api",
            "pattern": "uses_crypto_library:LIBRARY,uses_algorithm:CRYPTO_ASSET",
        },
    ).json()
    assert body["status"] == "COMPLETE"
    assert body["requires_runtime_observation"] is True
    assert body["unobserved_hop_indexes"] == [1, 2]


def test_an_evidence_ref_that_cites_nothing_leaves_the_edge_unresolved():
    """A label nobody declared cannot establish an edge — and the graph says why."""
    from shared_models.estate_graph import build_graph

    graph = build_graph({
        "assets": [
            {"ref": "app", "type": "APPLICATION", "name": "payments-api"},
            {"ref": "lib", "type": "LIBRARY", "name": "OpenSSL"},
        ],
        "relationships": [
            {"subject": "app", "predicate": "uses_crypto_library", "object": "lib",
             "basis": "RUNTIME_OBSERVATION", "evidence_refs": ["ev-does-not-exist"]},
        ],
    })
    assert graph.relationships() == []
    unresolved = graph.unresolved_relationships()
    assert unresolved and unresolved[0]["status"] == "UNKNOWN"
    assert "evidence" in unresolved[0]["reason"].lower()
