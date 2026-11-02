"""The CBOM as graph facts: algorithms, endpoints and conflicts as edges.

A CBOM document is a snapshot; a bank's questions are relational — *which systems
depend on RSA-2048*, *which endpoints terminate with a certificate whose signature
algorithm is ECDSA*, *which sources disagree about this library's version*. Those
are edges, and each one carries the evidence that produced it, in the same
vocabulary the rest of the platform uses:

``DECLARED``
    an SBOM/register/CMDB statement (``IMPORTED``, ``VENDOR_DECLARED``)
``OBSERVED``
    a collector saw it: ``STATIC_OBSERVED``, ``RUNTIME_OBSERVED``,
    ``NETWORK_OBSERVED``, ``CONFIGURED``
``INFERRED``
    a capability, never an invocation

A conflict is an edge too. Two sources disagreeing about one field is a fact
about the estate, and collapsing it into a chosen value — which is what a CBOM
document has to do to stay valid CycloneDX — is exactly the information loss this
module refuses. :func:`conflict_edges` emits the disagreement as
``CONFLICTS_WITH`` with both evidence ids attached.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom import usage_evidence as ue

SCHEMA = "cryptoscan.cbom-usage-graph/1"

#: Evidence class -> provenance class, so an edge says how it is known.
PROVENANCE_FOR_CLASS: dict[str, str] = {
    "OBSERVED": "OBSERVED",
    "STATIC_OBSERVED": "OBSERVED",
    "RUNTIME_OBSERVED": "OBSERVED",
    "NETWORK_OBSERVED": "OBSERVED",
    "CONFIGURED": "OBSERVED",
    "IMPORTED": "DECLARED",
    "VENDOR_DECLARED": "DECLARED",
    "INFERRED": "INFERRED",
    "UNKNOWN": "UNATTRIBUTED",
}

NODE_KINDS: dict[str, str] = {
    "system": "SYSTEM",
    "application": "APPLICATION",
    "algorithm": "CRYPTO_ALGORITHM",
    "component": "COMPONENT",
    "endpoint": "ENDPOINT",
    "certificate": "CERTIFICATE",
    "key": "KEY",
    "source": "EVIDENCE_SOURCE",
}


def _provenance(classes: Iterable[str]) -> str:
    """The strongest provenance any contributing evidence earns."""
    order = ("OBSERVED", "DECLARED", "INFERRED", "UNATTRIBUTED")
    seen = {PROVENANCE_FOR_CLASS.get(str(value).strip().upper(), "UNATTRIBUTED")
            for value in classes}
    return next((value for value in order if value in seen), "UNATTRIBUTED")


def _edge(source: str, kind: str, target: str, *, evidence: list[str],
          classes: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "from": source,
        "kind": kind,
        "to": target,
        "evidence_ids": sorted({value for value in evidence if value}),
        "evidence_classes": sorted({value for value in classes if value}),
        "provenance": _provenance(classes),
        **{key: value for key, value in extra.items() if value not in (None, "", [])},
    }


def usage_edges(profiles: Iterable[Mapping[str, Any]], *, system: str | None = None,
                application: str | None = None,
                component: str | None = None) -> dict[str, Any]:
    """One ``USES_CRYPTO`` edge per (subject, algorithm), classified by evidence.

    The subject is the system when one is named, else the application, else the
    component — and the edge's provenance is the strongest class that observed
    it. An algorithm seen only in an SBOM is therefore a ``DECLARED`` edge: the
    graph can show it, and nothing downstream may read it as use.
    """
    subject = (f"system:{system}" if system else
               f"application:{application}" if application else
               f"component:{component}" if component else None)
    if subject is None:
        raise ValueError("a usage graph needs a system, an application or a component")
    edges: list[dict[str, Any]] = []
    undeclared: list[str] = []
    for profile in profiles:
        asset = profile.get("asset") or {}
        algorithm = str(asset.get("algorithm") or "").strip()
        if not algorithm:
            continue
        classes = list(profile.get("observed_classes") or [])
        if not classes:
            classes = [str(key) for key, row in (profile.get("classes") or {}).items()
                       if isinstance(row, Mapping) and row.get("count")]
        if not classes:
            undeclared.append(algorithm)
            continue
        edges.append(_edge(
            subject, "USES_CRYPTO", f"algorithm:{algorithm}",
            evidence=list(profile.get("evidence_ids") or []), classes=classes,
            confidence=profile.get("confidence"), usage=profile.get("usage"),
            purpose=asset.get("purpose")))
    return {
        "schema": SCHEMA,
        "edges": edges,
        "algorithms": sorted({edge["to"].split(":", 1)[1] for edge in edges}),
        "undeclared": sorted(undeclared),
        "statement": (
            f"{len(edges)} USES_CRYPTO edge(s) from {subject}"
            + ("; none of them observed, so every one is DECLARED"
               if edges and all(edge["provenance"] == "DECLARED" for edge in edges) else "")
            + (f"; {len(undeclared)} algorithm(s) had no evidence and got no edge" if undeclared
               else "")),
    }


def conflict_edges(reconciled: Mapping[str, Any]) -> dict[str, Any]:
    """Every conflict becomes one edge, with both sides' evidence kept.

    ``resolved`` is deliberately ignored: an edge that carried the chosen value
    would hide the disagreement, and the disagreement is the finding a reviewer
    needs. The edge names the field, the values and the evidence ids.
    """
    edges: list[dict[str, Any]] = []
    for conflict in reconciled.get("conflicts") or ():
        if not isinstance(conflict, Mapping):
            continue
        field = str(conflict.get("field") or "")
        values = conflict.get("values") or {}
        evidence = conflict.get("evidence") or {}
        if not values:
            continue
        sources = sorted(str(name) for name in values)
        for index, left in enumerate(sources):
            for right in sources[index + 1:]:
                edges.append(_edge(
                    f"source:{left}", "CONFLICTS_WITH", f"source:{right}",
                    evidence=[str(evidence.get(left) or ""), str(evidence.get(right) or "")],
                    classes=["OBSERVED", "OBSERVED"],
                    field=field, kind_detail=conflict.get("kind"),
                    left_value=values.get(left), right_value=values.get(right),
                    statement=conflict.get("statement")))
    return {
        "schema": SCHEMA,
        "edges": edges,
        "fields": sorted({str(edge.get("field")) for edge in edges}),
        "statement": (
            f"{len(edges)} CONFLICTS_WITH edge(s)"
            + (f" across {len({edge.get('field') for edge in edges})} field(s); no conflict is "
               "resolved into an edge" if edges else "; the sources agree")),
    }


def tls_edges(paths: Mapping[str, Any]) -> dict[str, Any]:
    """Endpoints, their certificates, and the hops between them as edges.

    A terminating hop is ``TERMINATES`` on the endpoint, never on the application
    behind it: the graph must not let a load balancer's TLS 1.3 become an
    application's property.
    """
    edges: list[dict[str, Any]] = []
    for row in paths.get("paths") or ():
        if not isinstance(row, Mapping):
            continue
        endpoint = str(row.get("endpoint") or "").strip()
        if not endpoint:
            continue
        evidence = [str(row.get("evidence_id") or "")]
        classes = [str(row.get("class") or "NETWORK_OBSERVED")]
        suite = row.get("cipher_suite")
        for fact in _suite_facts(suite):
            edges.append(_edge(f"endpoint:{endpoint}", "NEGOTIATES", f"algorithm:{fact}",
                               evidence=evidence, classes=classes,
                               tls_version=row.get("tls_version"), cipher_suite=suite))
        certificate = row.get("certificate_ref")
        if certificate:
            edges.append(_edge(f"endpoint:{endpoint}", "TERMINATES",
                               f"certificate:{certificate}", evidence=evidence,
                               classes=classes, tls_version=row.get("tls_version")))
        if row.get("from") and row.get("to"):
            edges.append(_edge(f"endpoint:{endpoint}", "SERVES_HOP",
                               f"source:{row.get('to')}", evidence=evidence, classes=classes))
    return {
        "schema": SCHEMA,
        "edges": edges,
        "endpoints": sorted({edge["from"].split(":", 1)[1] for edge in edges
                             if edge["from"].startswith("endpoint:")}),
        "statement": (
            f"{len(edges)} edge(s) from {len({edge['from'] for edge in edges})} endpoint(s); "
            "a terminator's algorithms belong to the terminator"),
    }


def _suite_facts(suite: Any) -> list[str]:
    """Cipher-suite algorithms, via the collector's table (one contract)."""
    if not suite:
        return []
    from cbom.usage_collectors import algorithms_from_cipher_suite

    return [str(fact["algorithm"]) for fact in algorithms_from_cipher_suite(str(suite))]


def build_graph(profiles: Iterable[Mapping[str, Any]] | None = None, *,
                reconciled: Mapping[str, Any] | None = None,
                paths: Mapping[str, Any] | None = None,
                system: str | None = None, application: str | None = None,
                component: str | None = None) -> dict[str, Any]:
    """The three edge families together, with a count per family."""
    families: dict[str, Any] = {}
    edges: list[dict[str, Any]] = []
    if profiles is not None:
        families["usage"] = usage_edges(profiles, system=system, application=application,
                                       component=component)
        edges += families["usage"]["edges"]
    if reconciled is not None:
        families["conflicts"] = conflict_edges(reconciled)
        edges += families["conflicts"]["edges"]
    if paths is not None:
        families["tls"] = tls_edges(paths)
        edges += families["tls"]["edges"]
    undeclared = sorted({name for family in families.values()
                         for name in family.get("undeclared", ())})
    return {
        "schema": SCHEMA,
        "edges": edges,
        "nodes": sorted({node for edge in edges for node in (edge["from"], edge["to"])}),
        "families": {name: len(value["edges"]) for name, value in families.items()},
        "undeclared": undeclared,
        "provenance": {value: sum(1 for edge in edges if edge["provenance"] == value)
                       for value in ("OBSERVED", "DECLARED", "INFERRED", "UNATTRIBUTED")},
        "statement": (
            f"{len(edges)} edge(s) across {len(families)} family(ies); every edge carries the "
            "evidence that produced it"),
    }


def apply_graph(engine: Any, edges: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Write the edges into a graph engine, refusing any without evidence.

    Duck-typed on ``add_node``/``add_edge`` like the twin bridge, and strict about
    the same thing: an edge with no evidence id is not written, because an
    unattributable crypto relationship is a guess drawn on a diagram.
    """
    written = 0
    refused: list[dict[str, Any]] = []
    nodes: set[str] = set()
    by_provenance: dict[str, int] = {}
    for edge in edges:
        source, target = str(edge.get("from") or ""), str(edge.get("to") or "")
        evidence = [value for value in (edge.get("evidence_ids") or []) if value]
        if not evidence or not source or not target:
            refused.append({"edge": dict(edge),
                            "reason": "an edge with no evidence id or no endpoint is not written"})
            continue
        for node in (source, target):
            if node not in nodes:
                head = node.split(":", 1)[0]
                engine.add_node(node, kind=NODE_KINDS.get(head, "ENTITY"))
                nodes.add(node)
        provenance = str(edge.get("provenance") or "UNATTRIBUTED")
        engine.add_edge(source, target, str(edge.get("kind") or "USES_CRYPTO"),
                        provenance=provenance, source=edge.get("evidence_classes"),
                        evidence_ref=",".join(sorted(evidence)),
                        confidence=edge.get("confidence"))
        written += 1
        by_provenance[provenance] = by_provenance.get(provenance, 0) + 1
    return {
        "written": written,
        "nodes": len(nodes),
        "refused": refused,
        "by_provenance": dict(sorted(by_provenance.items())),
        "statement": (f"{written} edge(s) written across {len(nodes)} node(s)"
                      + (f"; {len(refused)} refused for carrying no evidence" if refused else "")),
    }


def coverage_note(coverage: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the estate's coverage to the graph, so no count is read as a total."""
    report = ue.coverage(int(coverage.get("systems_total") or 0),
                         int(coverage.get("systems_inspected") or 0),
                         int(coverage.get("assets_discovered") or 0))
    return {"schema": SCHEMA, **report,
            "statement": report["statement"] + "; the graph is what was collected, not the estate"}
