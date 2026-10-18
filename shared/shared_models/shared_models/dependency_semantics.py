"""Versioned system-dependency semantics shared by graph and cascade engines.

This is modeled change exposure, not runtime failure simulation. Membership
links (USES/SUPPORTS/CONTAINS) remain available for domain-specific seed/context
resolution but must not bridge two systems during dependency propagation.
"""
from __future__ import annotations

from typing import Any, Mapping

POLICY_VERSION = "cryptoscan.system-dependency-policy/1"
MAX_SYSTEM_HOPS = 12
PROPAGATING_RELATIONS = frozenset({"CALLS", "IMPORTS", "IMPORTS_CRYPTO", "DEPENDS_ON"})
CONTEXT_RELATIONS = frozenset({
    "CONTAINS", "USES", "SUPPORTS", "OWNED_BY", "MUST_COMPLY_WITH",
    "SECURED_BY", "DEPLOYED_ON", "DEPENDS_ON_VENDOR", "CONNECTS_TO",
    "RUNS", "PROTECTED_BY", "RELATED",
})
# Previous Neo4j writers used one CALLS relationship and overloaded `protocol`
# with either a relation label or transport. Recognize only explicit legacy
# transports; an arbitrary old protocol/custom label must not become CALLS.
LEGACY_CALL_PROTOCOLS = frozenset({"HTTP", "HTTPS", "TCP", "TLS", "GRPC", "ISTIO", "MESH"})


def normalize_relation(value: Any) -> str:
    text = "CALLS" if value is None else str(value)
    return text.strip().upper().replace("-", "_").replace(" ", "_") or "CALLS"


def edge_relation(edge: Mapping[str, Any]) -> str:
    """Explicit relation/type/label; transport is never a new relation label."""
    for key in ("relation", "type", "label"):
        if edge.get(key) is not None:
            return normalize_relation(edge[key])
    return "CALLS"  # historical nullable/unspecified system dependencies


def propagates(relation: Any) -> bool:
    return normalize_relation(relation) in PROPAGATING_RELATIONS


def stored_relation(properties: Mapping[str, Any]) -> str:
    """Read new explicit Neo4j semantics or the old overloaded protocol field."""
    if properties.get("relation") is not None:
        return normalize_relation(properties["relation"])
    legacy = normalize_relation(properties.get("protocol"))
    return "CALLS" if legacy in LEGACY_CALL_PROTOCOLS else legacy


def system_id(value: Any) -> str:
    """Accept a raw system ID or a graph-vis system: ID, never other prefixes."""
    return str(value or "").strip().removeprefix("system:")


def policy_metadata() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "direction": "consumer_to_provider",
        "propagating_relations": sorted(PROPAGATING_RELATIONS),
        "context_relations": sorted(CONTEXT_RELATIONS),
        "unknown_relations": "non_propagating",
        "unspecified_relation": "CALLS",
        "max_system_hops": MAX_SYSTEM_HOPS,
    }


def query_parameters() -> dict[str, list[str]]:
    return {"dependency_relations": sorted(PROPAGATING_RELATIONS),
            "legacy_dependency_relations": sorted(PROPAGATING_RELATIONS | LEGACY_CALL_PROTOCOLS)}


def cypher_dependency_predicate(variable: str = "r") -> str:
    """Trusted variable name only; values are bound parameters, not input text."""
    if not variable.isidentifier():
        raise ValueError("invalid Cypher relationship variable")

    def normalized(expression: str) -> str:
        return ("replace(replace(toUpper(CASE WHEN trim(coalesce(" + expression
                + ", '')) = '' THEN 'CALLS' ELSE trim(" + expression
                + ") END), '-', '_'), ' ', '_')")
    return (f"CASE WHEN {variable}.relation IS NOT NULL THEN "
            f"{normalized(f'{variable}.relation')} IN $dependency_relations ELSE "
            f"{normalized(f'{variable}.protocol')} IN $legacy_dependency_relations END")
