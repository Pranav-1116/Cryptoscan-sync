"""Certificate chains as the evidence describes them (spec 94 §24, *trust paths*).

The interesting property of a trust path is what its absence proves. An issuer the estate
never collected and an invalid chain look identical from a walk, and certificate tooling
that reports both as "broken" teaches operators to ignore the word. These tests hold the
module to reporting *where the walk stopped*:

* **ROOTED** — reaches a CA with no issuer of its own. A root as far as this evidence goes,
  which is not a statement about what an operating system trusts;
* **BROKEN** — a named issuer the estate holds no asset for, with both readings stated;
* **SELF_SIGNED** — the certificate names itself;
* **CYCLE** — the walk returns to a node it has seen; reported and stopped;
* **UNKNOWN_ISSUER** — no issuer edge, so nothing can be judged.

Also covered: a refused issuer edge is not a root, a chain longer than the walk limit says
so instead of inventing an end, and no signature or expiry is claimed anywhere.
"""

from __future__ import annotations

import pytest

from api import estate_trust as trust
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
TRUST_URL = f"{BASE}/twin/trust-paths"


def _payload(*relationships: dict, extra_assets: tuple[dict, ...] = ()) -> dict:
    assets = [
        {"ref": "leaf", "type": "CERTIFICATE", "name": "api.example.com"},
        {"ref": "intermediate", "type": "CA", "name": "Bank Issuing CA"},
        {"ref": "root", "type": "CA", "name": "Bank Root CA"},
    ] + [dict(item) for item in extra_assets]
    evidence = [
        {"evidence_id": "ev-cert", "source": "tls-scan", "collector": "tls-probe",
         "evidence_type": "CERTIFICATE_OBSERVED", "target": "leaf", "layer": "NETWORK_TRANSPORT",
         "facts": {"algorithm": "RSA-2048", "protocol": "TLSv1.3"}},
        {"evidence_id": "ev-root", "source": "pki", "collector": "pki-import",
         "evidence_type": "IMPORTED", "target": "root", "layer": "NETWORK_TRANSPORT",
         "facts": {"role": "issuer"}},
    ]
    return {"estate": "Synthetic Bank", "assets": assets, "evidence": evidence,
            "relationships": list(relationships)}


def _issued(subject: str, obj: str, *, basis: str = "IMPORTED") -> dict:
    return {"subject": subject, "predicate": "issued_by", "object": obj,
            "basis": basis, "evidence_ids": ["ev-cert"]}


def _by_name(body: dict) -> dict:
    return {entry["asset_name"]: entry for entry in body["chains"]}


def test_a_chain_that_reaches_a_collected_root_is_rooted_as_far_as_the_evidence_goes():
    graph = build_graph(_payload(_issued("leaf", "intermediate"), _issued("intermediate", "root")))

    body = trust.survey(graph)
    leaf = _by_name(body)["api.example.com"]

    assert leaf["status"] == "ROOTED"
    assert leaf["length"] == 3
    assert [step["asset_name"] for step in leaf["chain"]] == [
        "api.example.com", "Bank Issuing CA", "Bank Root CA"
    ]
    assert "as far as this evidence goes" in leaf["reason"]
    assert all(step["evidence_ids"] for step in leaf["chain"][1:])


def test_a_root_asset_with_no_issuer_is_not_itself_a_chain_finding():
    graph = build_graph(_payload(_issued("leaf", "intermediate"), _issued("intermediate", "root")))

    body = trust.survey(graph)

    # every CA is walked too: the intermediate is rooted, and the root CA claims no issuer, so
    # its own walk stops where the evidence stops rather than inventing a self-signed finding
    chains = _by_name(body)
    assert chains["api.example.com"]["status"] == "ROOTED"
    assert chains["Bank Issuing CA"]["status"] == "ROOTED"
    assert chains["Bank Root CA"]["status"] == "UNKNOWN_ISSUER"
    assert body["rooted_count"] == 2


def test_an_issuer_that_cannot_issue_a_certificate_breaks_the_chain():
    """The graph only accepts edges to assets it knows, so this is the realistic BROKEN case."""
    graph = build_graph(_payload(
        _issued("leaf", "vendor"),
        extra_assets=({"ref": "vendor", "type": "VENDOR", "name": "Thales"},),
    ))

    leaf = _by_name(trust.survey(graph))["api.example.com"]

    assert leaf["status"] == "BROKEN"
    assert "cannot vouch for a certificate" in leaf["reason"]
    assert leaf["chain"][-1]["asset_type"] == "VENDOR"


def test_a_self_signed_certificate_is_named_as_one():
    graph = build_graph(_payload(_issued("leaf", "leaf")))

    leaf = _by_name(trust.survey(graph))["api.example.com"]

    assert leaf["status"] == "SELF_SIGNED"
    assert "nobody else vouches" in leaf["reason"]


def test_no_issuer_edge_is_unjudged_rather_than_broken():
    graph = build_graph(_payload())

    leaf = _by_name(trust.survey(graph))["api.example.com"]

    assert leaf["status"] == "UNKNOWN_ISSUER"
    assert "not a broken one" in leaf["reason"]


def test_a_refused_issuer_edge_is_not_read_as_a_root():
    """A proximity-based `issued_by` is refused by the graph, and that is not a trust anchor."""
    graph = build_graph(_payload(
        {"subject": "leaf", "predicate": "issued_by", "object": "intermediate",
         "basis": "PROXIMITY", "evidence_ids": ["ev-cert"]}
    ))

    leaf = _by_name(trust.survey(graph))["api.example.com"]

    assert leaf["status"] == "BROKEN"
    assert "refused the edge" in leaf["reason"]
    assert "PROXIMITY" in graph.unresolved_relationships()[0]["reason"]


def test_a_loop_in_the_evidence_is_reported_and_the_walk_stops():
    assets = (
        {"ref": "ca-a", "type": "CA", "name": "CA A"},
        {"ref": "ca-b", "type": "CA", "name": "CA B"},
    )
    graph = build_graph(_payload(
        _issued("ca-a", "ca-b"), _issued("ca-b", "ca-a"), extra_assets=assets,
    ))

    body = trust.survey(graph)

    cycle = [entry for entry in body["chains"] if entry["status"] == "CYCLE"]
    assert cycle, [(entry["asset_name"], entry["status"]) for entry in body["chains"]]
    assert "loop" in cycle[0]["reason"]


def test_the_payload_never_claims_validation():
    graph = build_graph(_payload(_issued("leaf", "intermediate"), _issued("intermediate", "root")))
    body = trust.survey(graph)

    joined = " ".join(body["limits"])
    assert "no signature is verified" in joined
    assert "no expiry is checked" in joined
    assert "no revocation" in joined
    assert "not a validation of the certificate" in joined


def test_the_walk_reports_its_own_depth_limit_rather_than_inventing_a_root():
    chain = [f"ca-{index}" for index in range(trust.MAX_DEPTH + 3)]
    assets = tuple({"ref": name, "type": "CA", "name": name.upper()} for name in chain)
    edges = [_issued(chain[index], chain[index + 1]) for index in range(len(chain) - 1)]
    graph = build_graph(_payload(*edges, extra_assets=assets))

    body = trust.survey(graph)

    stopped = [entry for entry in body["chains"] if "longer than" in entry["reason"]]
    assert stopped
    # the start node is counted, so a walk that hit its limit is one link longer
    assert stopped[0]["length"] == trust.MAX_DEPTH + 1


def test_the_endpoint_refuses_to_read_absence_as_an_empty_estate(api):
    client, session = api

    body = client.get(TRUST_URL).json()

    assert body["status"] == "NOT_OBSERVED"
    assert "not the same as an estate with no certificates" in body["detail"]
    assert body["count"] == 0
