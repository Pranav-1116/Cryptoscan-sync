"""The whole CBOM chain over one estate, with the invariants that must hold.

Every guide in this series proved one layer. This module runs them **together**,
because the failures a reviewer finds are rarely inside a layer — they are at the
seams:

    SBOM ─┐
    static ├─→ evidence classes ─→ usage profile ─→ promotion ─→ CBOM document
    config │                                              │
    runtime┤                                              ├─→ PQC handoff
    network┘                                              └─→ twin edges ─→ drift
    KMS ──→ key records ─→ configured vs used
    coverage ──→ what the document may say about totals

``run`` takes one estate description and returns every layer's answer plus a list
of ``checks`` — the invariants that must hold across them regardless of the input:

1. **no false usage** — every component in the produced document is `OBSERVED`;
   a capability never becomes a document asset;
2. **attribution** — every document component carries an evidence id;
3. **level honesty** — a document asset's promotion level matches the classes its
   profile observed (runtime alone never reads as VERIFIED);
4. **conflicts survive** — a disagreement stays an edge and is never resolved
   silently;
5. **keys are not operations** — an operation recorded against a disabled key is
   carried as a refusal with its reason, never as runtime evidence;
6. **coverage is stated** — the document carries its coverage and its
   `may_report_total` flag;
7. **emptiness is explained** — an empty document says why.

A failed check is a bug in the pipeline, not a warning: the module reports it
rather than adjusting the document to fit.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from cbom import coverage_render as cr
from cbom import kms_collectors as kc
from cbom import network_assets as na
from cbom import pqc_handoff as pq
from cbom import process_tracing as pt
from cbom import promotion as promo
from cbom import usage_collectors as uc
from cbom import usage_evidence as ue
from cbom import usage_graph as ug

SCHEMA = "cryptoscan.cbom-estate-chain/1"

#: The invariants, in the order a reviewer would check them.
CHECKS: tuple[str, ...] = (
    "no_capability_is_documented_as_usage",
    "every_documented_asset_is_attributable",
    "promotion_level_matches_the_evidence",
    "conflicts_survive_to_the_graph",
    "a_disabled_key_never_produces_runtime_evidence",
    "coverage_travels_with_the_document",
    "emptiness_is_explained",
)


def _usage_by_algorithm(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for component in (document or {}).get("components") or []:
        properties = {str(row.get("name")): row.get("value")
                      for row in component.get("properties") or [] if isinstance(row, Mapping)}
        rows[str(component.get("name"))] = {
            "usage": properties.get("cryptoscan:usage"),
            "level": properties.get("cryptoscan:promotion_level"),
            "evidence_ids": [row["value"] for row in component.get("properties") or []
                             if isinstance(row, Mapping)
                             and row.get("name") == "cryptoscan:evidence_id"],
            "confidence": properties.get("cryptoscan:confidence"),
        }
    return rows


def _document_properties(document: Mapping[str, Any]) -> dict[str, Any]:
    metadata = (document or {}).get("metadata") or {}
    return {str(row.get("name")): row.get("value")
            for row in metadata.get("properties") or [] if isinstance(row, Mapping)}


def suppress_unusable_key_events(
    events: list[dict[str, Any]], records: list[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """A recorded operation on a key that cannot be used is a discrepancy, not usage.

    The key layer is right to report both facts — the key's status and the recorded
    operation — because a decrypt against a ``DISABLED`` key means either the record
    is wrong or the key was used while disabled. Neither reading makes the algorithm
    *in use*, so the event is kept out of the evidence set and carried as a refusal
    with its reason. Silently dropping it would be the failure the check below
    exists to catch.
    """
    unusable = {str(record.get("key_ref")): record
                for record in records if not record.get("usable")}
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for event in events:
        ref = str(event.get("key_ref") or "")
        if str(event.get("class")) == "RUNTIME_OBSERVED" and ref in unusable:
            status = str(unusable[ref].get("status") or "not usable")
            suppressed.append({
                "key_ref": ref,
                "evidence_id": event.get("evidence_id"),
                "operation": event.get("operation"),
                "reason": (f"the key is {status}, so a recorded operation on it is a "
                           "discrepancy, not evidence that the algorithm is in use"),
            })
            continue
        kept.append(event)
    return kept, suppressed


def disabled_key_check(
    events: list[Mapping[str, Any]],
    records: list[Mapping[str, Any]],
    *,
    suppressed: list[Mapping[str, Any]] | None = None,
    configured: int = 0,
) -> dict[str, Any]:
    """The invariant: an unusable key never reaches the evidence set unexplained."""
    unusable = {str(record.get("key_ref")) for record in records
                if not record.get("usable")}
    leaked = [event for event in events
              if str(event.get("class")) == "RUNTIME_OBSERVED"
              and str(event.get("key_ref") or "") in unusable]
    unexplained = [row for row in (suppressed or []) if not row.get("reason")]
    return {
        "check": "a_disabled_key_never_produces_runtime_evidence",
        "ok": not leaked and not unexplained,
        "detail": (f"{len(suppressed or [])} operation(s) on an unusable key refused with a "
                   f"reason, {configured} configured key event(s), "
                   f"{len(leaked)} leaked into the evidence"),
    }


def run(estate: Mapping[str, Any]) -> dict[str, Any]:
    """Run every CBOM layer over one estate and check the seams between them.

    The estate description is data, not code — the same shape a scan or an
    integration would produce::

        {"name": "estate-2026-11",
         "components": [{"name": "openssl", "version": "3.0.13",
                         "algorithms": ["AES-256-GCM", "RSA-2048"],
                         "evidence_id": "SBOM-1"}],
         "operations": [...runtime rows...],
         "keys": [...kms rows...], "key_uses": [...],
         "probes": [...tls probe rows...], "findings": [...static rows...],
         "conflicts": [...claims...],
         "coverage": {"rollup": {...}, "assets": 12, "files_scanned": 900}}
    """
    if not isinstance(estate, Mapping):
        raise ValueError("an estate description must be an object")
    name = str(estate.get("name") or "cryptoscan-estate").strip()

    # 1. runtime: the process chain and the provider the process loaded
    traced = pt.trace(estate.get("operations") or [])
    providers = pt.provider_observations(traced["traces"])
    correlation = pt.correlate(providers, estate.get("declared_versions")
                               or estate.get("components") or [])

    # 2. keys: inventory facts, separate from operations
    key_records = kc.key_records_from_kms(estate.get("keys") or [])
    key_events = kc.usage_events_from_keys(key_records["records"],
                                           estate.get("key_uses") or [])
    key_posture = kc.posture(key_records["records"])

    # 3. network, static and the runtime rows, as one evidence set
    network = uc.network_events_from_probes(estate.get("probes") or [])
    static = uc.static_events_from_assets(estate.get("findings") or [])
    runtime = uc.runtime_events_from_operations(estate.get("operations") or [])

    events: list[dict[str, Any]] = []
    for body in (network, static, runtime, key_events):
        events.extend(body.get("events") or [])
    events, suppressed = suppress_unusable_key_events(events, key_records["records"])
    event_counts = Counter(str(event.get("class")) for event in events)

    # 4. profiles per algorithm, then promotion into a document
    profiled = uc.profiles(events, purposes=estate.get("purposes") or {})
    promoted = promo.promote(estate.get("components") or [], events,
                             purposes=estate.get("purposes") or {},
                             primitives=estate.get("primitives") or {})

    # 5. coverage, then the document (coverage first, so it cannot be forgotten)
    coverage_block = cr.inventory_coverage(
        (estate.get("coverage") or {}).get("rollup") or {},
        assets=len(promoted["assets"]),
        as_of=estate.get("as_of"))
    document = promo.to_cbom(promoted, name=name)
    document = cr.render_coverage(document, coverage_block)
    empty = cr.empty_reasons(
        components=len(document.get("components") or []),
        files_scanned=int((estate.get("coverage") or {}).get("files_scanned") or 0),
        files_skipped=int((estate.get("coverage") or {}).get("files_skipped") or 0),
        errors=(estate.get("coverage") or {}).get("errors"),
        coverage_block=coverage_block,
    )
    if empty["empty"]:
        document = cr.render_empty(document, **{
            key: value for key, value in {
                "files_scanned": int((estate.get("coverage") or {}).get("files_scanned") or 0),
                "files_skipped": int((estate.get("coverage") or {}).get("files_skipped") or 0),
                "errors": (estate.get("coverage") or {}).get("errors"),
                "coverage_block": coverage_block,
            }.items()})

    # 6. the PQC handoff, and the conflicts kept as edges
    assets_for_handoff = [
        {"algorithm": asset["algorithm"], "component": asset.get("component"),
         "key_size": (asset["profile"].get("asset") or {}).get("parameters", {}).get("key_size"),
         "purpose": (asset["profile"].get("asset") or {}).get("purpose"),
         "usage": asset.get("promotion_level"),
         "evidence_ids": asset["profile"].get("evidence_ids") or []}
        for asset in promoted["assets"]
    ]
    handoff = pq.handoff(assets_for_handoff, as_of=estate.get("as_of"))
    reconciled = ue.reconcile(estate.get("conflicts") or [])
    conflicts = ug.conflict_edges(reconciled)
    graph = ug.build_graph(profiled["profiles"], reconciled=reconciled, system=name)

    # the network assets keep their own attribution: a handshake terminated by the LB
    # is the LB's cipher policy, and the graph audit says where that was overclaimed
    network_block = na.assets(network.get("hops") or [],
                              applications=estate.get("applications") or ())
    network_block["components"] = na.to_components(network_block)["components"]
    network_block["audit"] = na.audit_graph(graph, network_block)

    # 7. the checks, over everything above
    documented = _usage_by_algorithm(document)
    levels = {asset["algorithm"]: asset.get("promotion_level") for asset in promoted["assets"]}
    observed = {asset["algorithm"]: asset["profile"].get("observed_classes") or []
                for asset in promoted["assets"]}
    properties = _document_properties(document)

    checks = [
        {"check": "no_capability_is_documented_as_usage",
         "ok": all(row["usage"] == "OBSERVED" for row in documented.values()),
         "detail": ("every documented asset is OBSERVED"
                    if documented else "the document carries no assets, so nothing is claimed")},
        {"check": "every_documented_asset_is_attributable",
         "ok": all(row["evidence_ids"] for row in documented.values()),
         "detail": (f"{sum(1 for row in documented.values() if row['evidence_ids'])} of "
                    f"{len(documented)} documented asset(s) carry an evidence id")},
        {"check": "promotion_level_matches_the_evidence",
         "ok": all(levels.get(algorithm) == promo.promotion_level(classes)
                   for algorithm, classes in observed.items()),
         "detail": "; ".join(f"{algorithm}={levels.get(algorithm)}"
                             for algorithm in sorted(levels)) or "no promoted assets"},
        {"check": "conflicts_survive_to_the_graph",
         "ok": len(conflicts["edges"]) == len(reconciled["conflicts"])
               and all(row["value"] is None for row in reconciled["resolved"]
                       if row["field"] in {conflict["field"]
                                           for conflict in reconciled["conflicts"]}),
         "detail": f"{len(conflicts['edges'])} conflict edge(s) for "
                   f"{len(reconciled['conflicts'])} conflict(s); "
                   f"{len(reconciled['rows'])} claim row(s) kept"},
        disabled_key_check(events, key_records["records"], suppressed=suppressed,
                           configured=key_events.get("configured", 0)),
        {"check": "coverage_travels_with_the_document",
         "ok": cr.PROPERTY_COVERAGE in properties
               and bool(properties.get(cr.PROPERTY_COMPLETENESS)),
         "detail": (f"completeness={properties.get(cr.PROPERTY_COMPLETENESS)}, "
                    f"pct={properties.get(cr.PROPERTY_PCT)}")},
        {"check": "emptiness_is_explained",
         "ok": bool(document.get("components"))
               or properties.get(cr.PROPERTY_EMPTY) == "true",
         "detail": (empty["statement"] if empty["empty"]
                    else f"{len(document.get('components') or [])} component(s)")},
    ]
    failed = [check for check in checks if not check["ok"]]

    return {
        "schema": SCHEMA,
        "estate": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime": {"traces": traced["traces"], "refused": traced["refused"],
                    "providers": providers["providers"],
                    "correlation": correlation["correlations"],
                    "correlation_counts": correlation["counts"]},
        "keys": {"records": key_records["records"], "refused": key_records["refused"],
                 "events": key_events, "posture": key_posture},
        "evidence": {"counts": dict(sorted(event_counts.items())),
                     "events": events,
                     "suppressed": suppressed,
                     "refused": (network.get("refused", []) + static.get("refused", [])
                                 + runtime.get("refused", []) + key_events.get("refused", [])
                                 + suppressed + network_block.get("refused", []))},
        "profiles": profiled,
        "promotion": {key: promoted[key] for key in
                      ("assets", "candidates", "refused", "levels", "statement")},
        "document": document,
        "empty": empty,
        "handoff": handoff,
        "conflicts": {**conflicts, "reconciled": reconciled},
        "graph": graph,
        "network": network_block,
        "coverage": {**coverage_block, "quotable": cr.quotable_counts(coverage_block)},
        "checks": checks,
        "statement": (
            f"{name}: {len(promoted['assets'])} documented asset(s), "
            f"{len(promoted['candidates'])} candidate(s), "
            f"{len(graph['edges'])} graph edge(s), "
            f"{len(network_block['assets'])} network asset(s), "
            f"{len(handoff['rows'])} handoff row(s); "
            + ("every cross-layer check holds" if not failed
               else f"{len(failed)} check(s) failed: "
                    + ", ".join(check["check"] for check in failed))),
    }


def summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """The one-screen answer: what was proved, what was not, what needs attention."""
    checks = list(result.get("checks") or [])
    failed = [check for check in checks if not check["ok"]]
    handoff = result.get("handoff") or {}
    rows = list(handoff.get("rows") or [])
    urgent = [row for row in rows if row.get("migration_priority") == "IMMEDIATE"]
    return {
        "schema": SCHEMA,
        "estate": result.get("estate"),
        "checks_passed": len(checks) - len(failed),
        "checks_total": len(checks),
        "failed_checks": [check["check"] for check in failed],
        "documented_assets": len((result.get("document") or {}).get("components") or []),
        "candidates_excluded": len((result.get("promotion") or {}).get("candidates") or []),
        "graph_edges": len((result.get("graph") or {}).get("edges") or []),
        "migration_immediate": [row.get("algorithm") for row in urgent],
        "coverage_completeness": (result.get("coverage") or {}).get("completeness"),
        "status": "HOLDS" if not failed else "BROKEN",
        "statement": (
            f"{len(checks) - len(failed)}/{len(checks)} cross-layer checks hold"
            + (f"; {len(failed)} failed" if failed else "")
            + (f"; {len(urgent)} algorithm(s) at IMMEDIATE migration priority"
               if urgent else "")),
    }
