"""Hop attribution for LB / API gateway / service-mesh paths (spec 67 §15–§17, §25).

A TLS observation on ``lb.bank:443`` and another on ``payments.svc:8443`` are
two facts, not one chain. This module attaches *roles* to declared hops and
answers the questions a bank actually asks:

    where does TLS terminate?
    is the internal leg a separate TLS session or a pass-through?
    which crypto belongs to the sidecar and which to the application?

Every answer is bounded by evidence: a hop nobody observed is ``UNKNOWN``, and
a termination is only called ``TERMINATES_AND_REORIGINATES`` when both sides
presented *different* observed certificates. A sidecar's TLS is never reported
as the application's crypto (§17, §27).
"""

from __future__ import annotations

from typing import Any, Iterable

from network_scanner.inventory.network_evidence import (
    OBSERVED_EVIDENCE_TYPES,
    build_crypto_path,
)

MODEL = "cryptoscan.network-hop-attribution/1"

#: roles a hop may carry (§14–§17)
HOP_ROLES = (
    "CLIENT",
    "WAF",
    "LOAD_BALANCER",
    "API_GATEWAY",
    "PROXY",
    "VPN_GATEWAY",
    "SERVICE_MESH_SIDECAR",
    "SERVICE",
    "DATABASE",
    "MESSAGE_BROKER",
    "CACHE",
    "UNKNOWN",
)

#: roles that can terminate the client-facing TLS session and re-originate it
TERMINATING_ROLES = frozenset({"WAF", "LOAD_BALANCER", "API_GATEWAY", "PROXY", "VPN_GATEWAY"})

#: label fragments used only to *suggest* a role; the suggestion is always
#: labelled ``INFERRED_FROM_LABEL`` so an inference is never mistaken for a
#: declaration.
ROLE_TOKENS = (
    ("service-mesh", "SERVICE_MESH_SIDECAR"),
    ("sidecar", "SERVICE_MESH_SIDECAR"),
    ("istio", "SERVICE_MESH_SIDECAR"),
    ("envoy", "SERVICE_MESH_SIDECAR"),
    ("ingress", "API_GATEWAY"),
    ("api-gw", "API_GATEWAY"),
    ("api_gateway", "API_GATEWAY"),
    ("gateway", "API_GATEWAY"),
    ("apigw", "API_GATEWAY"),
    ("kong", "API_GATEWAY"),
    ("waf", "WAF"),
    ("lb", "LOAD_BALANCER"),
    ("loadbalancer", "LOAD_BALANCER"),
    ("load-balancer", "LOAD_BALANCER"),
    ("alb", "LOAD_BALANCER"),
    ("nlb", "LOAD_BALANCER"),
    ("vpn", "VPN_GATEWAY"),
    ("ipsec", "VPN_GATEWAY"),
    ("proxy", "PROXY"),
    ("squid", "PROXY"),
    ("kafka", "MESSAGE_BROKER"),
    ("broker", "MESSAGE_BROKER"),
    ("rabbitmq", "MESSAGE_BROKER"),
    ("ibmmq", "MESSAGE_BROKER"),
    ("db", "DATABASE"),
    ("postgres", "DATABASE"),
    ("mysql", "DATABASE"),
    ("oracle", "DATABASE"),
    ("redis", "CACHE"),
    ("memcached", "CACHE"),
    ("client", "CLIENT"),
    ("internet", "CLIENT"),
    ("user", "CLIENT"),
    ("svc", "SERVICE"),
    ("service", "SERVICE"),
    ("app", "SERVICE"),
)

#: how an edge is described in the hop chain
SEGMENT_KINDS = (
    "CLIENT_TO_EDGE",
    "EDGE_TO_INTERNAL",
    "INTERNAL_TO_INTERNAL",
    "SERVICE_TO_DATA",
    "MESH_SIDECAR_PATH",
    "UNKNOWN",
)


def infer_role(label: str | None) -> tuple[str, str]:
    """Return ``(role, source)`` for a hop label; never pretends to be certain."""
    if not label:
        return "UNKNOWN", "UNDECLARED"
    lowered = str(label).lower()
    for token, role in ROLE_TOKENS:
        if token in lowered:
            return role, "INFERRED_FROM_LABEL"
    return "UNKNOWN", "UNDECLARED"


def normalize_hops(hops: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep declared roles; otherwise infer from the label.

    Accepted per hop: ``from``, ``to``, ``from_role``, ``to_role``, ``label``.
    Unknown role strings are reported as ``UNKNOWN`` rather than dropped.
    """
    normalized: list[dict[str, Any]] = []
    for hop in hops:
        source = str(hop.get("from") or "").strip()
        target = str(hop.get("to") or "").strip()
        if not source or not target:
            continue
        entry: dict[str, Any] = {"from": source, "to": target, "label": hop.get("label")}
        for side in ("from", "to"):
            declared = str(hop.get(f"{side}_role") or "").upper()
            if declared in HOP_ROLES:
                entry[f"{side}_role"] = declared
                entry[f"{side}_role_source"] = "DECLARED"
            else:
                role, source_kind = infer_role(hop.get(f"{side}_label") or (hop.get("label") if side == "from" else None) or (source if side == "from" else target))
                entry[f"{side}_role"] = role
                entry[f"{side}_role_source"] = declared and "DECLARED_UNKNOWN" or source_kind
        normalized.append(entry)
    return normalized


def _segment_kind(from_role: str, to_role: str) -> str:
    if from_role == "CLIENT":
        return "CLIENT_TO_EDGE"
    if from_role in TERMINATING_ROLES:
        return "EDGE_TO_INTERNAL"
    if "SERVICE_MESH_SIDECAR" in {from_role, to_role}:
        return "MESH_SIDECAR_PATH"
    if to_role in {"DATABASE", "MESSAGE_BROKER", "CACHE"}:
        return "SERVICE_TO_DATA"
    if from_role == "SERVICE" or to_role == "SERVICE":
        return "INTERNAL_TO_INTERNAL"
    return "UNKNOWN"


def _fingerprint(record: dict[str, Any] | None) -> str | None:
    if not record:
        return None
    return (record.get("certificate") or {}).get("fingerprint_sha256")


def _termination_verdict(
    client_facing: dict[str, Any] | None,
    internal: dict[str, Any] | None,
    role: str,
) -> dict[str, Any]:
    """Decide where TLS terminates, only from observed certificates.

    ``client_facing`` is the terminator's own observation (the handshake clients
    complete with it); ``internal`` is the observation of the node it forwards
    to (the handshake it originates itself).
    """
    client_observed = bool(client_facing) and client_facing.get("evidence_type") in OBSERVED_EVIDENCE_TYPES
    internal_observed = bool(internal) and internal.get("evidence_type") in OBSERVED_EVIDENCE_TYPES
    client_fp = _fingerprint(client_facing)
    internal_fp = _fingerprint(internal)

    if not client_observed and not internal_observed:
        return {
            "verdict": "UNDETERMINED",
            "reason": "neither leg was observed — the termination point is NOT_OBSERVED, not absent",
            "certificate_comparison": "NOT_COMPARABLE",
        }
    if client_observed and not internal_observed:
        return {
            "verdict": "UNDETERMINED",
            "reason": "client-facing leg observed but no internal leg evidence — re-origination cannot be proven",
            "certificate_comparison": "NOT_COMPARABLE",
        }
    if internal_observed and not client_observed:
        return {
            "verdict": "UNDETERMINED",
            "reason": "internal leg observed but the client-facing session was not — termination is unproven",
            "certificate_comparison": "NOT_COMPARABLE",
        }
    if client_fp and internal_fp and client_fp == internal_fp:
        return {
            "verdict": "PASS_THROUGH",
            "reason": "both legs presented the same certificate fingerprint — one certificate, two legs",
            "certificate_comparison": "SAME_FINGERPRINT",
        }
    if client_fp and internal_fp:
        return {
            "verdict": "TERMINATES_AND_REORIGINATES",
            "reason": (
                f"{role} presents a different certificate on each side — TLS terminates here and a "
                "separate internal TLS session starts"
            ),
            "certificate_comparison": "DIFFERENT_FINGERPRINT",
        }
    return {
        "verdict": "UNDETERMINED",
        "reason": "both legs observed but a certificate fingerprint is missing — pass-through vs re-origination is unproven",
        "certificate_comparison": "FINGERPRINT_MISSING",
    }


def attribute_path(
    records: Iterable[dict[str, Any]],
    hops: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Annotate a declared hop chain with roles, segments and TLS termination.

    Returns the §25 path (unchanged keys) plus an ``attribution`` block. Hops
    are never invented and roles are never promoted from inference to fact.
    """
    records = list(records)
    normalized = normalize_hops(hops)
    path = build_crypto_path(records, normalized)

    by_endpoint: dict[str, dict[str, Any]] = {}
    for record in records:
        endpoint = str((record.get("target") or {}).get("endpoint") or "")
        if endpoint and endpoint not in by_endpoint:
            by_endpoint[endpoint] = record

    roles: dict[str, str] = {}
    role_sources: dict[str, str] = {}
    for hop in normalized:
        for side in ("from", "to"):
            node = hop[side]
            roles[node] = hop[f"{side}_role"]
            role_sources[node] = hop[f"{side}_role_source"]

    for node in path.get("nodes") or []:
        node["role"] = roles.get(node["id"], "UNKNOWN")
        node["role_source"] = role_sources.get(node["id"], "UNDECLARED")
        node["role_inferred"] = node["role_source"] == "INFERRED_FROM_LABEL"

    segments: list[dict[str, Any]] = []
    for edge in path.get("edges") or []:
        from_role = roles.get(edge["from"], "UNKNOWN")
        to_role = roles.get(edge["to"], "UNKNOWN")
        kind = _segment_kind(from_role, to_role)
        edge["segment"] = kind
        edge["from_role"] = from_role
        edge["to_role"] = to_role
        segments.append(
            {
                "from": edge["from"],
                "to": edge["to"],
                "kind": kind,
                "from_role": from_role,
                "to_role": to_role,
                "crypto": {
                    "evidence_type": edge["evidence_type"],
                    "evidence_mode": edge["evidence_mode"],
                    "tls_version": edge["tls_version"],
                    "cipher_suite": edge["cipher_suite"],
                    "mutual_tls": edge["mutual_tls"],
                    "certificate_fingerprint_sha256": _fingerprint(by_endpoint.get(edge["from"])),
                    "evidence_id": edge["evidence_id"],
                },
                "attack_surface_note": None
                if edge["evidence_type"] in OBSERVED_EVIDENCE_TYPES
                else "no observation on this segment — its transport crypto is UNKNOWN, not absent",
            }
        )

    # A node is a candidate terminator when a declared (or inferred) role says
    # so *and* it has both an inbound and an outbound edge.
    upstream: dict[str, dict[str, Any]] = {}
    downstream: dict[str, dict[str, Any]] = {}
    for edge in path.get("edges") or []:
        downstream.setdefault(edge["from"], edge)
        upstream.setdefault(edge["to"], edge)

    termination_points: list[dict[str, Any]] = []
    for node, role in roles.items():
        if role not in TERMINATING_ROLES:
            continue
        internal_hop = (downstream.get(node) or {}).get("to")
        verdict = _termination_verdict(by_endpoint.get(node), by_endpoint.get(internal_hop), role)
        termination_points.append(
            {
                "node": node,
                "role": role,
                "role_source": role_sources.get(node),
                "client_side_from": (upstream.get(node) or {}).get("from"),
                "internal_side_to": internal_hop,
                "client_facing_observed": node in by_endpoint,
                "internal_observed": internal_hop in by_endpoint,
                "upstream_edge_evidence": (upstream.get(node) or {}).get("evidence_type") or "UNKNOWN",
                "downstream_edge_evidence": (downstream.get(node) or {}).get("evidence_type") or "UNKNOWN",
                **verdict,
            }
        )

    sidecars = [
        {
            "node": node,
            "role": role,
            "note": (
                "sidecar TLS protects the mesh hop; the application's own crypto is different "
                "and out of network reach (§17, §27)"
            ),
            "observed": node in by_endpoint,
        }
        for node, role in roles.items()
        if role == "SERVICE_MESH_SIDECAR"
    ]

    unattributed = sorted(node for node, role in roles.items() if role == "UNKNOWN")
    observed_nodes = sum(1 for node in roles if node in by_endpoint)

    return {
        **path,
        "attribution": {
            "model": MODEL,
            "roles": {node: roles[node] for node in sorted(roles)},
            "role_sources": {node: role_sources[node] for node in sorted(roles)},
            "segments": segments,
            "segment_kinds": _counts(segment["kind"] for segment in segments),
            "termination_points": termination_points,
            "terminating_nodes": [point["node"] for point in termination_points],
            "sidecars": sidecars,
            "unattributed_nodes": unattributed,
            "nodes_observed": observed_nodes,
            "nodes_declared": len(roles),
            "complete": bool(segments)
            and all(segment["crypto"]["evidence_type"] in OBSERVED_EVIDENCE_TYPES for segment in segments),
            "limitations": [
                "hop roles are declared by the operator or inferred from labels — inference is labelled, never promoted",
                "an unobserved hop is UNKNOWN; a pass-through verdict requires matching observed fingerprints",
                "application-layer crypto behind a sidecar or gateway is out of network reach",
            ],
            "boundary": "hops are declared; only the annotated crypto and certificates are observed",
        },
    }


def _counts(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out
