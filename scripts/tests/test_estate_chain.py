"""The Digital Twin chain, walked link by link, and stopped where it stops.

The vision's chain is:

    Payment API → runs on → Container → runs on → Kubernetes → uses → OpenSSL
        → runtime observed → AES-256-GCM → TLS terminates at → Load Balancer
        → uses → HSM

`EstateGraph` already refuses a single edge with no basis or no evidence. What it
did not do is walk a *pattern* of hops, and that is where a twin starts lying: a
missing hop silently dropped renders a six-link chain as if it were the seven-link
one. `shared_models.estate_chain.trace` walks only established edges and reports
the hop it could not take, with the graph's own refusal reason when there is one.

These tests build the chain with real evidence and then break it, one way at a
time, to prove each failure is reported as itself rather than as a shorter chain.
"""

from __future__ import annotations

from shared_models.estate_chain import (
    APPLICATION_CRYPTO_PATH,
    APPLICATION_CRYPTO_USAGE,
    COMPLETE,
    NO_ASSET,
    NO_EDGE,
    REFUSED_EDGE,
    Hop,
    requires_observation,
    trace,
    weakest_hop,
)
from shared_models.estate_graph import EstateGraph, make_evidence


def _graph() -> tuple[EstateGraph, dict[str, str]]:
    """The vision's estate: every hop carries evidence."""
    graph = EstateGraph(estate="payments", scope="prod")
    ids = {
        "api": graph.add_asset("APPLICATION", "Payment API", environment="prod"),
        "container": graph.add_asset("CONTAINER", "payments-api-7d9f", environment="prod"),
        "cluster": graph.add_asset("CLUSTER", "k8s-payments-prod", environment="prod"),
        "openssl": graph.add_asset("LIBRARY", "OpenSSL 3.0.13", environment="prod"),
        "aes": graph.add_asset("CRYPTO_ASSET", "AES-256-GCM", environment="prod"),
        "lb": graph.add_asset("LOAD_BALANCER", "alb-payments-01", environment="prod"),
        "hsm": graph.add_asset("HSM", "hsm-01", environment="prod"),
    }
    evidence = {
        "deployment": graph.add_evidence(make_evidence(
            source="kubernetes", evidence_type="CONFIGURED", target=ids["api"],
            facts={"deployment": "payments-api", "namespace": "payments"}, layer="APPLICATION",
        )),
        "runtime": graph.add_evidence(make_evidence(
            source="ld-preload", evidence_type="RUNTIME_OBSERVED", target=ids["api"],
            facts={"library": "OpenSSL 3.0.13", "calls": 1421}, layer="APPLICATION",
        )),
        "tls": graph.add_evidence(make_evidence(
            source="network", evidence_type="NETWORK_ACTIVE_OBSERVED", target=ids["lb"],
            facts={"port": 443, "protocol": "TLSv1.3"}, layer="NETWORK_TRANSPORT",
        )),
        "pkcs11": graph.add_evidence(make_evidence(
            source="pkcs11", evidence_type="CONFIGURED", target=ids["hsm"],
            facts={"slot": 0, "mechanism": "CKM_AES_GCM"}, layer="HSM",
        )),
    }
    graph.assert_relationship(
        ids["api"], "runs_on", ids["container"], basis="DEPLOYMENT_CONFIG",
        evidence_ids=[evidence["deployment"]],
    )
    graph.assert_relationship(
        ids["container"], "runs_on", ids["cluster"], basis="DEPLOYMENT_CONFIG",
        evidence_ids=[evidence["deployment"]],
    )
    graph.assert_relationship(
        ids["cluster"], "uses_crypto_library", ids["openssl"], basis="RUNTIME_OBSERVATION",
        evidence_ids=[evidence["runtime"]],
    )
    graph.assert_relationship(
        ids["openssl"], "uses_algorithm", ids["aes"], basis="RUNTIME_OBSERVATION",
        evidence_ids=[evidence["runtime"]], attributes={"usage_state": "OBSERVED"},
    )
    graph.assert_relationship(
        ids["api"], "terminates_tls_for", ids["lb"], basis="NETWORK_OBSERVATION",
        evidence_ids=[evidence["tls"]],
    )
    graph.assert_relationship(
        ids["lb"], "uses", ids["hsm"], basis="PKCS11_REFERENCE",
        evidence_ids=[evidence["pkcs11"]],
    )
    return graph, ids


def test_the_whole_vision_chain_resolves_with_evidence_on_every_hop():
    """Seven hops, application to HSM, each one backed by an evidence id."""
    graph, ids = _graph()
    chain = trace(graph, ids["api"], APPLICATION_CRYPTO_PATH)

    assert chain["status"] == COMPLETE, chain
    assert chain["complete"] is True
    assert [hop["predicate"] for hop in chain["hops"]] == [
        "runs_on",
        "runs_on",
        "uses_crypto_library",
        "uses_algorithm",
        "terminates_tls_for",
        "uses",
    ]
    assert [hop["to_type"] for hop in chain["hops"]] == [
        "CONTAINER", "CLUSTER", "LIBRARY", "CRYPTO_ASSET", "LOAD_BALANCER", "HSM",
    ]
    for hop in chain["hops"]:
        assert hop["evidence_ids"], f"hop {hop['index']} carries no evidence id"
        assert hop["confidence"] in {"HIGH", "MEDIUM"}
    assert chain["rendered"] == (
        "Payment API —runs_on→ payments-api-7d9f —runs_on→ k8s-payments-prod"
        " —uses_crypto_library→ OpenSSL 3.0.13 —uses_algorithm→ AES-256-GCM"
        " —terminates_tls_for→ alb-payments-01 —uses→ hsm-01"
    )


def test_the_usage_path_stops_at_the_algorithm():
    graph, ids = _graph()
    chain = trace(graph, ids["api"], APPLICATION_CRYPTO_USAGE)
    assert chain["status"] == COMPLETE, chain
    assert [hop["predicate"] for hop in chain["hops"]] == [
        "runs_on",
        "runs_on",
        "uses_crypto_library",
        "uses_algorithm",
    ]
    assert chain["hops"][-1]["object"] == ids["aes"]


def test_a_hop_with_no_edge_is_reported_as_the_hop_it_is():
    """Breaking the middle of the chain must not return a shorter chain."""
    broken = EstateGraph(estate="payments")
    api = broken.add_asset("APPLICATION", "Payment API")
    broken.add_asset("CONTAINER", "payments-api")
    chain = trace(broken, api, APPLICATION_CRYPTO_USAGE)
    assert chain["status"] == NO_EDGE, chain
    assert chain["complete"] is False
    assert chain["stop"]["predicate"] == "runs_on"
    assert "no established edge" in chain["stop"]["reason"]
    assert chain["hops"] == []


def test_a_broken_middle_hop_keeps_the_hops_that_did_resolve():
    """The four-link chain with its second hop missing reports link 2, not link 1."""
    graph = EstateGraph(estate="payments")
    api = graph.add_asset("APPLICATION", "Payment API")
    container = graph.add_asset("CONTAINER", "payments-api")
    openssl = graph.add_asset("LIBRARY", "OpenSSL 3.0.13")
    evidence = graph.add_evidence(make_evidence(
        source="kubernetes", evidence_type="CONFIGURED", target=api, facts={"d": 1},
    ))
    graph.assert_relationship(api, "runs_on", container, basis="DEPLOYMENT_CONFIG", evidence_ids=[evidence])
    graph.assert_relationship(container, "uses_crypto_library", openssl, basis="DEPLOYMENT_CONFIG",
                              evidence_ids=[evidence])

    chain = trace(graph, api, APPLICATION_CRYPTO_USAGE)
    # hop 2 in the pattern is `runs_on → CLUSTER`, which this estate has no cluster for
    assert chain["status"] == NO_EDGE, chain
    assert chain["hop_count"] == 1
    assert chain["stop"]["expected"] == "runs on"
    assert chain["stop"]["to_type"] == "CLUSTER"
    # the library relation exists in this estate, and the chain must NOT skip ahead to it
    assert "uses_crypto_library" in chain["stop"]["available_predicates"]


def test_a_refused_edge_surfaces_the_graphs_own_reason():
    """The most useful failure: the edge was attempted and the graph said no."""
    graph = EstateGraph(estate="payments")
    api = graph.add_asset("APPLICATION", "Payment API")
    hsm = graph.add_asset("HSM", "hsm-01")
    refused = graph.assert_relationship(api, "uses", hsm, basis=None)
    assert refused["status"] == "UNKNOWN"

    chain = trace(graph, api, [Hop("uses", "HSM", "uses")])
    assert chain["status"] == REFUSED_EDGE, chain
    assert chain["stop"]["refused_basis"] is None
    assert "basis" in chain["stop"]["reason"].lower()


def test_an_asset_nobody_discovered_is_not_a_chain():
    graph = EstateGraph(estate="payments")
    chain = trace(graph, "asset-that-does-not-exist", APPLICATION_CRYPTO_USAGE)
    assert chain["status"] == NO_ASSET
    assert chain["complete"] is False
    assert chain["hops"] == []
    assert "nothing discovered it" in chain["stop"]["reason"]


def test_weakest_hop_names_the_link_that_sets_the_strength():
    graph, ids = _graph()
    chain = trace(graph, ids["api"], APPLICATION_CRYPTO_PATH)
    weakest = weakest_hop(chain)
    assert weakest is not None
    assert weakest["confidence"] == "MEDIUM"
    # MEDIUM hops are the deployment and network observations; never a HIGH-only view
    assert weakest["basis"] in {"DEPLOYMENT_CONFIG", "NETWORK_OBSERVATION"}


def test_a_configuration_only_chain_is_flagged_as_needing_observation():
    """`uses` from a manifest is a configuration claim, not a runtime one."""
    graph = EstateGraph(estate="payments")
    api = graph.add_asset("APPLICATION", "Payment API")
    library = graph.add_asset("LIBRARY", "OpenSSL 3.0.13")
    evidence = graph.add_evidence(make_evidence(
        source="deployment", evidence_type="CONFIGURED", target=api,
        facts={"dependency": "libssl3"}, layer="APPLICATION",
    ))
    graph.assert_relationship(
        api, "uses_crypto_library", library, basis="DEPLOYMENT_CONFIG", evidence_ids=[evidence]
    )
    chain = trace(graph, api, [Hop("uses_crypto_library", "LIBRARY", "uses")])
    assert chain["status"] == COMPLETE
    assert requires_observation(chain) is True, (
        "a chain built from configuration must not be presented as runtime-observed"
    )

    observed, ids = _graph()
    runtime_chain = trace(observed, ids["api"], APPLICATION_CRYPTO_USAGE)
    assert requires_observation(runtime_chain) is False
