"""System policy: normalization is explicit; transport is not a relation."""
import pytest

from shared_models.dependency_semantics import (
    POLICY_VERSION, cypher_dependency_predicate, edge_relation, normalize_relation,
    policy_metadata, propagates, query_parameters, stored_relation, system_id,
)


@pytest.mark.parametrize("raw,canonical", [
    (None, "CALLS"), ("", "CALLS"), ("  ", "CALLS"), (" calls ", "CALLS"),
    ("imports", "IMPORTS"), ("imports-crypto", "IMPORTS_CRYPTO"),
    (False, "FALSE"), (0, "0"),
    ("depends on", "DEPENDS_ON"), ("contains", "CONTAINS"), ("custom", "CUSTOM"),
])
def test_normalization(raw, canonical):
    assert normalize_relation(raw) == canonical


@pytest.mark.parametrize("label", ["CALLS", "IMPORTS", "imports-crypto", "depends-on"])
def test_dependency_allowlist(label):
    assert propagates(label)


@pytest.mark.parametrize("label", ["CONTAINS", "USES", "SUPPORTS", "OWNED_BY", "RELATED", "CUSTOM", "HTTP", "FAILOVER", "OPTIONAL"])
def test_other_labels_do_not_silently_become_hard_dependencies(label):
    assert not propagates(label)


def test_edge_shapes_and_transport_separation():
    assert edge_relation({"type": "imports-crypto"}) == "IMPORTS_CRYPTO"
    assert edge_relation({"label": "contains"}) == "CONTAINS"
    assert edge_relation({"protocol": "https"}) == "CALLS"
    assert edge_relation({"relation": "HTTP", "protocol": "HTTPS"}) == "HTTP"
    assert stored_relation({"protocol": "https"}) == "CALLS"  # legacy physical CALLS
    assert stored_relation({"relation": "HTTP", "protocol": "https"}) == "HTTP"
    assert stored_relation({"protocol": "contains"}) == "CONTAINS"
    assert not propagates(stored_relation({"protocol": "arbitrary-custom"}))


def test_versioned_metadata_and_safe_bound_parameters():
    assert policy_metadata()["version"] == POLICY_VERSION
    assert policy_metadata()["direction"] == "consumer_to_provider"
    assert policy_metadata()["unknown_relations"] == "non_propagating"
    params = query_parameters()
    assert "HTTP" not in params["dependency_relations"]
    assert "HTTP" in params["legacy_dependency_relations"]
    predicate = cypher_dependency_predicate()
    assert "r.relation IS NOT NULL" in predicate
    assert "$dependency_relations" in predicate and "$legacy_dependency_relations" in predicate
    with pytest.raises(ValueError):
        cypher_dependency_predicate("r) RETURN 1 //")
    assert system_id("system:pay") == "pay"
    assert system_id("asset:key") == "asset:key"  # not silently converted to a system
