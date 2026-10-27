"""Coverage is a qualification of loaded evidence, never a safety percentage."""

from collections import defaultdict, deque
from copy import deepcopy

from shared_models.dependency_semantics import edge_relation, propagates, system_id
from shared_models.relationship_lifecycle import current, possible
from shared_models.traversal_evidence import MAX_WITNESSES

SCHEMA = "cryptoscan.analysis-coverage/1"
SOURCE_SCHEMA = "cryptoscan.source-coverage/1"


def collection_read(returned, limit, *, more=False, total=None, unit="rows"):
    return {
        "returned": returned,
        "limit": limit,
        "truncated": bool(more),
        "known_total": total,
        "observed_lower_bound": max(returned + int(bool(more)), total or 0),
        "unit": unit,
        "status": "TRUNCATED" if more else "WITHIN_READ_LIMIT",
        "scope": "authorized query only; not proof of complete discovery",
    }


def traversal_bound(edges, seeds, *, known, hops, now, reverse=False, potential=False):
    """Probe one loaded adjacency beyond the BFS horizon, without widening scope."""
    known = {system_id(s) for s in known}
    seeds = {system_id(s) for s in seeds} & known
    adjacency = defaultdict(set)
    for edge in edges:
        src = system_id(edge.get("from") or edge.get("source"))
        dst = system_id(edge.get("to") or edge.get("target"))
        if (
            src in known
            and dst in known
            and propagates(edge_relation(edge))
            and (possible if potential else current)(edge, now=now)
        ):
            adjacency[dst if reverse else src].add(src if reverse else dst)
    depths = dict.fromkeys(seeds, 0)
    queue = deque(sorted(seeds))
    while queue:
        node = queue.popleft()
        if depths[node] >= hops:
            continue
        for neighbour in sorted(adjacency[node]):
            if neighbour not in depths:
                depths[neighbour] = depths[node] + 1
                queue.append(neighbour)
    frontier = {s for s, depth in depths.items() if depth == hops}
    extra = {n for s in frontier for n in adjacency[s] if n not in depths}
    return {
        "scope": "potential" if potential else "current",
        "unit": "systems",
        "direction": "upstream" if reverse else "downstream",
        "max_depth": hops,
        "reached_system_count": len(depths) - len(seeds),
        "frontier_system_count": len(frontier),
        "extension_check": "LOADED_ELIGIBLE_GRAPH",
        "more_loaded_systems": bool(extra),
        "unvisited_neighbour_count": len(extra),
        "note": "Horizon probe does not add exposure. No further loaded neighbour is not proof the estate graph is complete.",
    }


def native_traversal_bound(rows, hops, *, reverse=False):
    return {
        "scope": "current",
        "unit": "systems",
        "direction": "upstream" if reverse else "downstream",
        "max_depth": hops,
        "reached_system_count": len(rows),
        "frontier_system_count": sum(r.get("hops") == hops for r in rows),
        "extension_check": "NOT_EVALUATED",
        "more_loaded_systems": None,
        "unvisited_neighbour_count": None,
        "note": "Native walk is hop-bounded; extension beyond the horizon was not probed. Unknown is not zero.",
    }


def analysis_coverage(snapshot, result, *, traversals=None):
    """Combine independent source, walk, explanation and linkage qualifications.

    Do not sum unlike denominators or derive impact counts from listed details.
    """
    source = snapshot.get("source_coverage") or {}
    collections = deepcopy(source.get("collections") or {})
    for key, value in ((snapshot.get("software_supply_chain_coverage") or {}).get("collections") or {}).items():
        collections["software_" + key] = deepcopy(value)
    for key, value in (snapshot.get("collector_coverage") or {}).items():
        if key.endswith("_truncated") and type(value) is bool:
            collections["collector_" + key.removesuffix("_truncated")] = {
                "truncated": value,
                "returned": None,
                "limit": None,
                "known_total": None,
                "unit": "collector subset",
                "scope": "collector-reported bound; row totals unavailable",
            }
    input_truncated = any(c.get("truncated") is True for c in collections.values())
    unknown_source = source.get("schema") != SOURCE_SCHEMA
    impact = result.get("impact") or result
    layers = result.get("layers") or {}
    explanation = result.get("traversal_evidence") or {}
    listings = []
    for key in ("dependent_consumers", "supporting_context", "potential", "vendor_subtiers"):
        value = explanation.get(key)
        if isinstance(value, dict):
            listings.append(
                {
                    "name": key + "_witnesses",
                    "requested": value.get("requested_count"),
                    "returned": value.get("returned_count"),
                    "limit": value.get("limit"),
                    "truncated": value.get("truncated"),
                    "missing_within_selected_count": value.get("missing_witness_count"),
                    "scope": "one minimum-hop witness per selected system, not all paths",
                }
            )
    for key in ("direct", "potential_direct"):
        if key + "_count" in explanation:
            listings.append(
                {
                    "name": key + "_seeds",
                    "requested": explanation[key + "_count"],
                    "returned": len(explanation.get(key) or []),
                    "limit": MAX_WITNESSES,
                    "truncated": explanation.get(key + "_truncated"),
                    "scope": "seed explanations; does not limit system classification",
                }
            )
    process = (impact.get("process_impact") or {}).get("coverage") or {}
    if process:
        listings.append(
            {
                "name": "process_details",
                "requested": process.get("total_process_count"),
                "returned": process.get("returned_process_count"),
                "limit": process.get("process_limit"),
                "truncated": process.get("processes_truncated"),
                "scope": "process details; compact process counts are independent",
            }
        )
        reasons = (impact.get("process_impact") or {}).get("processes") or []
        listings.append(
            {
                "name": "process_reasons",
                "truncated": any(p.get("reasons_truncated") for p in reasons),
                "limit": process.get("reason_limit_per_process"),
                "scope": "reasons per returned process only; not all support links",
            }
        )
        listings.append(
            {
                "name": "missing_process_systems",
                "requested": process.get("systems_without_recorded_links_count"),
                "returned": len(process.get("systems_without_recorded_links") or []),
                "limit": process.get("process_limit"),
                "truncated": process.get("missing_system_list_truncated"),
                "scope": "unmapped system ID listing; gap count is independent",
            }
        )
    seed_rows = [row for key in ("direct", "potential_direct") for row in explanation.get(key) or []]
    listings.append(
        {
            "name": "seed_context_records",
            "limit": 20,
            "truncated": any(row.get("record_listing_truncated") for row in seed_rows),
            "scope": "context records per returned seed; not all contributing records",
        }
    )
    path_edges = [edge for row in seed_rows for edge in (row.get("path") or {}).get("edges") or []]
    for group in ("dependent_consumers", "supporting_context", "potential", "vendor_subtiers"):
        path_edges.extend(
            edge for path in (explanation.get(group) or {}).get("paths") or [] for edge in path.get("edges") or []
        )
    listings.append(
        {
            "name": "witness_evidence_references",
            "limit": 50,
            "truncated": any(edge.get("references_truncated") for edge in path_edges),
            "scope": "references per returned path-edge occurrence; not a graph-wide evidence audit",
        }
    )
    operational = impact.get("operational_impact") or {}
    if operational:
        listings.append(
            {
                "name": "operational_details",
                "requested": operational.get("edge_count"),
                "returned": len(operational.get("edges") or []),
                "limit": operational.get("edge_limit"),
                "truncated": operational.get("edges_truncated"),
                "scope": "loaded review-edge variants; mode counts are independent",
            }
        )
    resolution = result.get("target_resolution") or {}
    if resolution:
        listings.append(
            {
                "name": "target_candidates",
                "requested": resolution.get("candidate_count"),
                "returned": len(resolution.get("candidates") or []),
                "limit": resolution.get("candidate_limit"),
                "truncated": resolution.get("candidates_truncated"),
                "scope": "loaded canonical candidate listing",
            }
        )
    cert = (layers.get("network") or {}).get("certificate_join") or {}
    if cert:
        listings.append(
            {
                "name": "certificate_subject_only_endpoints",
                "requested": cert.get("subject_only_endpoint_count"),
                "returned": len(cert.get("subject_only_endpoints") or []),
                "limit": 200,
                "truncated": cert.get("subject_only_endpoints_truncated"),
                "scope": "unbound equal-subject endpoints; not selected certificate exposure",
            }
        )
    gaps = []

    def gap(name, count, scope, denominator=None):
        gaps.append(
            {
                "name": name,
                "count": count,
                "denominator": denominator,
                "scope": scope,
                "status": "NOT_EVALUATED" if count is None else "GAP_REPORTED" if count else "NO_GAP_IN_LOADED_SUBSET",
            }
        )

    if explanation:
        gap(
            "returned_path_edges_without_evidence",
            sum(bool(e.get("evidence_missing")) for e in path_edges),
            "returned path-edge occurrences only; repeated edges may occur in several witnesses",
            len(path_edges),
        )
    gap(
        "systems_without_process_support",
        process.get("systems_without_recorded_links_count"),
        "requested review/potential systems only",
        process.get("requested_system_count"),
    )
    gap(
        "unresolved_process_links",
        process.get("unresolved_or_invalid_link_count"),
        "loaded support records; not proof of unregistered processes",
    )
    if operational:
        gap(
            "unknown_operational_dependency_modes",
            (operational.get("mode_counts") or {}).get("UNKNOWN"),
            "current review-edge assertion variants without usable operational mode; not failure predictions",
            operational.get("edge_count"),
        )
    kind = (result.get("target") or {}).get("kind")
    cert = (layers.get("network") or {}).get("certificate_join") or {}
    gap(
        "certificate_subject_only_endpoints",
        cert.get("subject_only_endpoint_count"),
        "selected certificate's equal-subject endpoints without usable fingerprint",
    )
    if kind == "certificate" and result.get("analysis_performed"):
        gap(
            "certificate_without_exact_owner",
            int(not (layers.get("system") or {}).get("systems")),
            "selected certificate's loaded exact usage/endpoint ownership",
            1,
        )
    if kind == "device" and result.get("analysis_performed"):
        gap(
            "device_without_crypto_link",
            int(bool((layers.get("hardware") or {}).get("inventory_only"))),
            "selected device only",
            1,
        )
    software = layers.get("software")
    for field in ("unbound_artifact_ids", "unlinked_deployment_ids"):
        gap(
            field,
            len(software.get(field) or []) if isinstance(software, dict) else None,
            "selected software assertions in loaded input",
        )
    known = {system_id(s.get("id")) for s in snapshot.get("systems") or []}
    for field, name, link in (
        ("network_endpoints", "endpoint_records_without_loaded_system_owner", lambda row: [row.get("system_id")]),
        ("assets", "assets_without_loaded_system_link", lambda row: row.get("system_ids") or []),
    ):
        if field in snapshot:
            records = snapshot[field] or []
            gap(
                name,
                sum(not any(system_id(sid) in known for sid in link(row)) for row in records),
                "loaded projection records only; absent registry references may reflect read limits, not proof of unregistered systems",
                len(records),
            )
    dependencies = snapshot.get("dependencies")
    if dependencies is not None:
        context_prefixes = ("asset:", "library:", "vendor:", "process:", "certificate:", "hardware:")
        eligible = [
            e
            for e in dependencies
            if propagates(edge_relation(e))
            and not any(str(e.get(key) or "").startswith(context_prefixes) for key in ("source", "target"))
        ]
        unresolved = sum(
            1 for e in eligible if system_id(e.get("source")) not in known or system_id(e.get("target")) not in known
        )
        gap(
            "dependency_endpoint_references",
            unresolved,
            "loaded propagating dependency rows whose endpoints are not both in the loaded system registry",
            len(eligible),
        )
    if "vendor_dependencies" in snapshot:
        vendors = {str(v.get("id")) for v in snapshot.get("vendors") or []}
        vendor_edges = snapshot.get("vendor_dependencies") or []
        gap(
            "vendor_dependency_registry_references",
            sum(str(e.get("parent")) not in vendors or str(e.get("child")) not in vendors for e in vendor_edges),
            "loaded vendor assertion rows with an endpoint absent from the loaded vendor registry; external IDs are retained by the vendor adapter",
            len(vendor_edges),
        )
    walks = deepcopy(traversals or [])
    detail_truncated = any(r.get("truncated") is True for r in listings)
    more = any(r.get("more_loaded_systems") is True or r.get("more_loaded_entities") is True for r in walks)
    unknown_horizon = any(r.get("extension_check") == "NOT_EVALUATED" for r in walks)
    has_gaps = any((r.get("count") or 0) > 0 for r in gaps) or any(
        (r.get("missing_within_selected_count") or 0) > 0 for r in listings
    )
    attention = input_truncated or detail_truncated or more or has_gaps
    return {
        "schema": SCHEMA,
        "status": "GAPS_REPORTED"
        if attention
        else "UNKNOWN"
        if unknown_source or unknown_horizon or result.get("analysis_performed") is False
        else "BOUNDED_REVIEW",
        "analysis_performed": result.get("analysis_performed", True),
        "dependency_source": str(
            "system_dependencies"
            if snapshot.get("dependency_source") == "none"
            else snapshot.get("dependency_source") or "unknown"
        ).split(":v")[0],
        "source_metadata_available": not unknown_source,
        "known_input_truncation": input_truncated,
        "known_horizon_omission": more,
        "horizon_extension_unknown": unknown_horizon,
        "explanation_truncation": detail_truncated,
        "collections": collections,
        "traversals": walks,
        "missing_links": gaps,
        "explanations": listings,
        "estate_completeness": "UNKNOWN",
        "note": "Counts describe loaded modeled evidence, not complete estate discovery or operational failure. Missing links, omitted rows and unknown metadata are not zero exposure or proof of safety. No coverage percentage is inferred.",
    }


def coverage_summary(result):
    c = (result or {}).get("coverage") or {}
    if c.get("schema") != SCHEMA:
        return None
    return {
        key: c[key]
        for key in (
            "schema",
            "status",
            "known_input_truncation",
            "known_horizon_omission",
            "explanation_truncation",
            "horizon_extension_unknown",
            "source_metadata_available",
            "estate_completeness",
        )
    }


def compare_coverage(old, new):
    left, right = [(r or {}).get("coverage") or {} for r in (old, new)]

    def profile(c):
        return (
            {k: (v.get("limit"), v.get("unit")) for k, v in c.get("collections", {}).items()},
            [
                (w.get("scope"), w.get("unit"), w.get("direction"), w.get("max_depth"))
                for w in c.get("traversals") or []
            ],
            c.get("dependency_source"),
        )

    comparable = all(
        c.get("schema") == SCHEMA
        and c.get("source_metadata_available")
        and not c.get("known_input_truncation")
        and not c.get("known_horizon_omission")
        and not c.get("horizon_extension_unknown")
        for c in (left, right)
    ) and profile(left) == profile(right)
    return {
        "comparable": bool(comparable),
        "reason": None
        if comparable
        else "Input coverage is unknown/truncated, a loaded traversal horizon omits systems, or read/depth policies differ; impact deltas withheld. Explanation-only truncation does not change membership counts.",
        "note": "Comparable bounded inputs are not proof of full discovery or remediation.",
    }


def vendor_traversal_bound(edges, seeds, *, known, now):
    """Same declared vendor-of-vendor horizon as the adapter (three hops).

    This is separate from system propagation and does not infer supply edges.
    """
    # Unlike system propagation, the vendor adapter walks declared identifiers
    # even when an external vendor has no registry row. Do not prune its actual
    # horizon here; missing registry references are reported independently.
    known = set(known) | {str(e.get(key)) for e in edges for key in ("parent", "child")}
    result = traversal_bound(
        [{"source": str(e.get("parent")), "target": str(e.get("child")), "type": "DEPENDS_ON"} for e in edges],
        seeds,
        known=known,
        hops=3,
        now=now,
    )
    result.update(scope="vendor_supply_chain", unit="vendors")
    for old, new in (
        ("more_loaded_systems", "more_loaded_entities"),
        ("frontier_system_count", "frontier_entity_count"),
        ("reached_system_count", "reached_entity_count"),
    ):
        result[new] = result.pop(old)
    return result
