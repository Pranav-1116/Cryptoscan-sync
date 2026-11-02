"""CBOM → digital twin: one graph, three consumers, no claim upgrades.

Review item 20 draws the architecture this increment implements:

    EVIDENCE (SBOM · STATIC · NETWORK · RUNTIME · HSM/KMS)
                        │
                   CRYPTO GRAPH
                        │
                       CBOM
                        │
                  DIGITAL TWIN
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
      DRIFT           PQC            THREAT
    ANALYSIS       MIGRATION      INTELLIGENCE

The twin is a projection, not a second inventory. Every node and edge is built from
:mod:`cbom.estate_chain`'s output, which is itself built from the collectors, so
there is exactly one place where an evidence class is decided. What the twin adds
is the question an inventory cannot answer: **who is connected to what, and how
does anybody know?**

Three rules hold the projection together:

* a node carries the evidence classes that produced it, and never more than its
  strongest source. A capability node (a library, an algorithm it merely supports)
  is ``CAPABILITY`` even when the same algorithm is ``OBSERVED`` elsewhere, because
  the two are different claims about different things;
* a consumer answers exactly one question and may only *read* the twin's claims.
  Drift, PQC migration and threat intelligence each produce items with a
  ``claim_level`` copied from the node they read — a downstream report that says
  "in use" about a capability is the failure this module refuses to make;
* an absence is not evidence. A node nobody observed is ``NOT_OBSERVED``, and every
  consumer that reports a gap says so in those words.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cbom import estate_chain as ec
from cbom import pqc_handoff as pq
from cbom import usage_graph as ug

SCHEMA = "cryptoscan.cbom-digital-twin/1"

#: The five evidence families the review stacks under the graph.
FAMILIES: tuple[str, ...] = ("sbom", "static", "network", "runtime", "kms")

#: Node kinds. A node kind is a question shape: ENDPOINT terminates, PROCESS runs,
#: KEY signs or unwraps, ALGORITHM is the thing that is weak or strong.
NODE_KINDS: tuple[str, ...] = ("SYSTEM", "COMPONENT", "PROVIDER", "PROCESS",
                               "ALGORITHM", "KEY", "ENDPOINT", "CERTIFICATE")

#: Consumers, in the order the review draws them.
CONSUMERS: tuple[str, ...] = ("drift", "pqc_migration", "threat_intelligence")

#: Read-only claim levels a consumer may inherit. The order matters: a consumer may
#: never produce a level above the level of the node it read.
CLAIM_LEVELS: tuple[str, ...] = ("CAPABILITY", "IMPORTED", "CONFIGURED", "STATIC",
                                 "NETWORK", "RUNTIME")

#: Evidence class -> the claim level a consumer may inherit, and the family it came
#: from. One table, because a downstream report that ranks a class differently from
#: the graph is the bug this guide exists to prevent.
_CLASS_CLAIM = {
    "CAPABILITY": "CAPABILITY",
    "IMPORTED": "IMPORTED",
    "VENDOR_DECLARED": "IMPORTED",
    "CONFIGURED": "CONFIGURED",
    "HSM_OBSERVED": "CONFIGURED",
    "STATIC_OBSERVED": "STATIC",
    "NETWORK_OBSERVED": "NETWORK",
    "RUNTIME_OBSERVED": "RUNTIME",
}

_FAMILY_BY_CLASS = {
    "IMPORTED": "sbom",
    "VENDOR_DECLARED": "sbom",
    "CAPABILITY": "sbom",
    "STATIC_OBSERVED": "static",
    "NETWORK_OBSERVED": "network",
    "RUNTIME_OBSERVED": "runtime",
    "CONFIGURED": "kms",
    "HSM_OBSERVED": "kms",
}


def _provenance(classes: Iterable[str]) -> str:
    """The strongest provenance a set of classes earns, using the graph's own rule."""
    order = ("OBSERVED", "DECLARED", "INFERRED", "UNATTRIBUTED")
    seen = {ug.PROVENANCE_FOR_CLASS.get(str(name).strip().upper(), "UNATTRIBUTED")
            for name in classes}
    return next((value for value in order if value in seen), "UNATTRIBUTED")


def _properties(component: Mapping[str, Any]) -> dict[str, Any]:
    return {str(row.get("name")): row.get("value")
            for row in component.get("properties") or [] if isinstance(row, Mapping)}


def _evidence_ids(component: Mapping[str, Any]) -> list[str]:
    return sorted({str(row.get("value")) for row in component.get("properties") or []
                   if isinstance(row, Mapping)
                   and str(row.get("name")) == "cryptoscan:evidence_id"
                   and row.get("value")})


def _level(classes: Iterable[str]) -> str:
    """The strongest claim a set of evidence classes supports, never above it."""
    claims = {_CLASS_CLAIM[name] for name in set(classes) if name in _CLASS_CLAIM}
    ranked = [CLAIM_LEVELS.index(name) for name in CLAIM_LEVELS if name in claims]
    return CLAIM_LEVELS[max(ranked)] if ranked else "CAPABILITY"


def _node(node_id: str, kind: str, *, classes: Iterable[str] = (), evidence: Iterable[str] = (),
          **extra: Any) -> dict[str, Any]:
    class_list = sorted({str(name) for name in classes if name})
    return {
        "id": node_id,
        "kind": kind,
        "evidence_classes": class_list,
        "evidence_ids": sorted({str(value) for value in evidence if value}),
        "claim_level": _level(class_list),
        "families": sorted({_FAMILY_BY_CLASS[name] for name in class_list
                            if name in _FAMILY_BY_CLASS}),
        **{key: value for key, value in extra.items() if value not in (None, "", [], {})},
    }


def build(estate: Mapping[str, Any]) -> dict[str, Any]:
    """One estate description -> the crypto graph, the CBOM, and the twin.

    The chain is computed by :func:`cbom.estate_chain.run`, so the twin cannot
    disagree with the document: both are projections of the same evidence set.
    """
    if not isinstance(estate, Mapping):
        raise ValueError("an estate description must be an object")
    chain = estate.get("chain") if isinstance(estate.get("chain"), Mapping) else ec.run(estate)
    name = str(chain.get("estate") or estate.get("name") or "cryptoscan-estate")
    nodes: list[dict[str, Any]] = [
        _node(f"system:{name}", "SYSTEM", kind_hint="estate")]
    edges: list[dict[str, Any]] = []

    # 1. documented algorithms: the only nodes allowed to say "in use"
    for component in (chain.get("document") or {}).get("components") or []:
        properties = _properties(component)
        classes = [value for value in str(
            properties.get("cryptoscan:observed_classes") or "").split(",") if value]
        algorithm = str(component.get("name"))
        parameters = ((component.get("cryptoProperties") or {}).get("algorithmProperties")
                      or {})
        node_id = f"algorithm:{algorithm}"
        nodes.append(_node(
            node_id, "ALGORITHM", classes=classes, evidence=_evidence_ids(component),
            usage=properties.get("cryptoscan:usage"),
            promotion_level=properties.get("cryptoscan:promotion_level"),
            purpose=properties.get("cryptoscan:purpose"),
            key_size=(properties.get("cryptoscan:key_size")
                      or parameters.get("parameterSetIdentifier"))))
        edges.append(ug.evidence_edge(f"system:{name}", "USES_CRYPTO", node_id,
                                      evidence=_evidence_ids(component),
                                      classes=classes or ["CAPABILITY"]))

    # 2. libraries: capability, whatever the algorithms do elsewhere
    for row in estate.get("components") or []:
        if not isinstance(row, Mapping) or not row.get("name"):
            continue
        node_id = f"component:{row['name']}"
        nodes.append(_node(node_id, "COMPONENT", classes=["CAPABILITY"],
                           evidence=[row.get("evidence_id")], version=row.get("version"),
                           declares=row.get("algorithms") or []))
        for algorithm in row.get("algorithms") or []:
            # a candidate algorithm is a node too, so the SUPPORTS edge has both ends.
            # It is a CAPABILITY node: it exists because a library lists it, and it
            # stays that weak even when the same algorithm is observed elsewhere.
            nodes.append(_node(f"algorithm:{algorithm}", "ALGORITHM",
                               usage="CAPABILITY", declared_by=[str(row["name"])]))
            edges.append(ug.evidence_edge(node_id, "SUPPORTS", f"algorithm:{algorithm}",
                                          evidence=[row.get("evidence_id")],
                                          classes=["CAPABILITY"]))

    # 3. runtime: process -> provider -> operation already walked by process tracing
    for provider in (chain.get("runtime") or {}).get("providers") or []:
        name_ = provider.get("name") or str(provider.get("provider") or "").split(":")[0]
        version = provider.get("version")
        node_id = f"provider:{name_}@{version or 'unknown'}"
        nodes.append(_node(node_id, "PROVIDER", classes=["RUNTIME_OBSERVED"],
                           evidence=provider.get("evidence_ids"),
                           component=name_,
                           version=version,
                           algorithms=provider.get("algorithms"),
                           processes=provider.get("processes")))
    for trace in (chain.get("runtime") or {}).get("traces") or []:
        process = f"process:{trace['application']}/{trace['pid']}"
        nodes.append(_node(process, "PROCESS", classes=["RUNTIME_OBSERVED"],
                           evidence=[trace.get("evidence_id")],
                           last_observed_at=trace.get("observed_at")))
        edges.append(ug.evidence_edge(f"system:{name}", "RUNS_PROCESS", process,
                                      evidence=[trace.get("evidence_id")],
                                      classes=["RUNTIME_OBSERVED"]))
        edges.append(ug.evidence_edge(process, "PERFORMS", f"algorithm:{trace['algorithm']}",
                                      evidence=[trace.get("evidence_id")],
                                      classes=["RUNTIME_OBSERVED"]))
        if trace.get("provider"):
            provider = (f"provider:{trace['provider']}@"
                        f"{trace.get('provider_version') or 'unknown'}")
            edges.append(ug.evidence_edge(process, "LOADS_PROVIDER", provider,
                                          evidence=[trace.get("evidence_id")],
                                          classes=["RUNTIME_OBSERVED"]))

    # 4. network: an endpoint terminates its own algorithms
    network = chain.get("network") or {}
    for asset in network.get("assets") or []:
        endpoint = f"endpoint:{asset.get('endpoint') or asset.get('name')}"
        nodes.append(_node(endpoint, "ENDPOINT", classes=["NETWORK_OBSERVED"],
                           evidence=asset.get("evidence_ids"),
                           tls_version=asset.get("tls_version")))
        edges.append(ug.evidence_edge(f"system:{name}", "EXPOSES", endpoint,
                                      evidence=asset.get("evidence_ids") or [],
                                      classes=["NETWORK_OBSERVED"]))
        for algorithm in ([asset["algorithm"]] if asset.get("algorithm") else []):
            edges.append(ug.evidence_edge(endpoint, "NEGOTIATES", f"algorithm:{algorithm}",
                                          evidence=asset.get("evidence_ids") or [],
                                          classes=["NETWORK_OBSERVED"]))
        if asset.get("certificate_ref"):
            certificate = f"certificate:{asset['certificate_ref']}"
            nodes.append(_node(certificate, "CERTIFICATE", classes=["NETWORK_OBSERVED"],
                               evidence=asset.get("evidence_ids")))
            edges.append(ug.evidence_edge(endpoint, "PRESENTS", certificate,
                                          evidence=asset.get("evidence_ids") or [],
                                          classes=["NETWORK_OBSERVED"]))

    # 5. keys: configured, and never a statement that the algorithm is used
    for record in (chain.get("keys") or {}).get("records") or []:
        node_id = f"key:{record.get('key_ref')}"
        nodes.append(_node(node_id, "KEY", classes=["CONFIGURED"],
                           evidence=[record.get("evidence_id")],
                           algorithm=record.get("algorithm"),
                           key_size=record.get("key_size"),
                           status=record.get("status"),
                           private_material=record.get("private_material")))
        if record.get("algorithm"):
            edges.append(ug.evidence_edge(node_id, "HOLDS_KEY_FOR",
                                          f"algorithm:{record['algorithm']}",
                                          evidence=[record.get("evidence_id")],
                                          classes=["CONFIGURED"]))

    # 6. the conflicts the evidence could not resolve, as edges
    for edge in (chain.get("graph") or {}).get("edges") or []:
        if str(edge.get("kind")) not in {"CONFLICTS_WITH", "TERMINATES", "NEGOTIATES"}:
            continue
        for endpoint in (edge["from"], edge["to"]):
            if endpoint.startswith("source:"):
                nodes.append(_node(endpoint, "SYSTEM",
                                   evidence=edge.get("evidence_ids") or []))
        edges.append(dict(edge))

    # an edge whose other end nobody described still gets a node, so the twin has no
    # dangling references: a key held for an algorithm is a capability, not a use
    kind_by_prefix = {"algorithm": "ALGORITHM", "endpoint": "ENDPOINT",
                      "component": "COMPONENT", "provider": "PROVIDER",
                      "process": "PROCESS", "key": "KEY", "certificate": "CERTIFICATE",
                      "source": "SYSTEM", "system": "SYSTEM"}
    known = {node["id"] for node in nodes}
    for edge in edges:
        for endpoint in (edge["from"], edge["to"]):
            if endpoint in known:
                continue
            prefix = endpoint.split(":", 1)[0]
            nodes.append(_node(endpoint, kind_by_prefix.get(prefix, "SYSTEM"),
                               usage="CAPABILITY"))
            known.add(endpoint)

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in edges:
        key = (edge["from"], edge["kind"], edge["to"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(edge)
            continue
        existing["evidence_ids"] = sorted({*existing["evidence_ids"],
                                           *edge["evidence_ids"]})
        existing["evidence_classes"] = sorted({*existing["evidence_classes"],
                                               *edge["evidence_classes"]})
        existing["provenance"] = _provenance(existing["evidence_classes"])
    by_id: dict[str, dict[str, Any]] = {}
    for node in nodes:
        existing = by_id.get(node["id"])
        if existing is None:
            by_id[node["id"]] = node
            continue
        existing["evidence_classes"] = sorted({*existing["evidence_classes"],
                                               *node["evidence_classes"]})
        existing["evidence_ids"] = sorted({*existing["evidence_ids"],
                                           *node["evidence_ids"]})
        existing["claim_level"] = _level(existing["evidence_classes"])
        existing["families"] = sorted({*existing["families"], *node["families"]})
        for key, value in node.items():
            if key in {"id", "kind", "evidence_classes", "evidence_ids", "claim_level",
                       "families"}:
                continue
            existing.setdefault(key, value)

    family_counts = {family: 0 for family in FAMILIES}
    for node in by_id.values():
        for family in node["families"]:
            family_counts[family] = family_counts.get(family, 0) + 1
    missing = [family for family, count in family_counts.items() if not count]
    return {
        "schema": SCHEMA,
        "estate": name,
        "chain_schema": chain.get("schema"),
        "cbom": chain.get("document"),
        "nodes": sorted(by_id.values(), key=lambda row: row["id"]),
        "edges": [merged[key] for key in sorted(merged)],
        "families": family_counts,
        "unrepresented_families": missing,
        "claim_levels": {label: sum(1 for node in by_id.values()
                                    if node["claim_level"] == label)
                         for label in CLAIM_LEVELS},
        "statement": (
            f"{name}: {len(by_id)} twin node(s), {len(merged)} edge(s) from "
            f"{sum(1 for count in family_counts.values() if count)} of "
            f"{len(FAMILIES)} evidence families"
            + (f"; no evidence yet from {', '.join(missing)}" if missing else "")),
    }


def _algorithms(twin: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The algorithm nodes that are *in use*, not the ones a library merely lists.

    A candidate that appears as a SUPPORTS target is a capability node, and a
    consumer that treated it as usage would be doing exactly what review item 21
    forbids.
    """
    return {node["id"].split(":", 1)[1]: node for node in twin.get("nodes") or []
            if node["kind"] == "ALGORITHM" and node.get("usage") == "OBSERVED"}


# --------------------------------------------------------------------------- #
# consumers


def drift(twin: Mapping[str, Any], expected: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Observed use against the crypto policy the bank intended.

    Four findings, and the difference between them is the whole point:

    * ``UNEXPECTED_USE`` — something ran that policy does not allow;
    * ``POLICY_NOT_OBSERVED`` — policy allows it, nothing was seen doing it. This is
      *not* evidence that nothing does;
    * ``PARAMETER_DRIFT`` — the right algorithm with the wrong parameters;
    * ``PARAMETER_UNKNOWN`` — policy names a size and nothing observed one, so drift
      is not asserted either way;
    * ``UNATTRIBUTED`` — observed, and policy is silent, so nobody has decided.
    """
    observed = _algorithms(twin)
    policy = {}
    for row in expected or ():
        if isinstance(row, Mapping) and row.get("algorithm"):
            policy[str(row["algorithm"])] = row
    findings: list[dict[str, Any]] = []
    for algorithm in sorted(set(policy) | set(observed)):
        node = observed.get(algorithm)
        rule = policy.get(algorithm)
        if node is not None and rule is None:
            findings.append({
                "algorithm": algorithm, "state": "UNATTRIBUTED",
                "detail": "observed in use and no policy row mentions it",
                "claim_level": node["claim_level"],
                "evidence_ids": node["evidence_ids"]})
            continue
        if node is None:
            findings.append({
                "algorithm": algorithm, "state": "POLICY_NOT_OBSERVED",
                "detail": ("policy lists this algorithm and nothing was observed using "
                           "it; that is not evidence that nothing does"),
                "claim_level": "CAPABILITY", "evidence_ids": []})
            continue
        expected_size = rule.get("key_size")
        observed_size = str(node.get("key_size") or "")
        if expected_size not in (None, "") and not observed_size:
            findings.append({
                "algorithm": algorithm, "state": "PARAMETER_UNKNOWN",
                "detail": (f"policy expects key_size {expected_size} and the observation "
                           "recorded no size, so drift cannot be asserted"),
                "claim_level": node["claim_level"],
                "evidence_ids": node["evidence_ids"]})
        elif expected_size not in (None, "") and str(expected_size) != observed_size:
            findings.append({
                "algorithm": algorithm, "state": "PARAMETER_DRIFT",
                "detail": (f"policy expects key_size {expected_size}, the observation "
                           f"recorded {observed_size}"),
                "claim_level": node["claim_level"],
                "evidence_ids": node["evidence_ids"]})
        elif rule.get("allowed", True) is False:
            findings.append({
                "algorithm": algorithm, "state": "UNEXPECTED_USE",
                "detail": "policy forbids this algorithm and it was observed in use",
                "claim_level": node["claim_level"],
                "evidence_ids": node["evidence_ids"]})
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["state"]] = counts.get(finding["state"], 0) + 1
    return {
        "schema": SCHEMA,
        "consumer": "drift",
        "findings": findings,
        "counts": dict(sorted(counts.items())),
        "clean": not [row for row in findings if row["state"] in {"UNEXPECTED_USE",
                                                                  "PARAMETER_DRIFT"}],
        "statement": (
            f"{len(findings)} drift finding(s) against {len(policy)} policy row(s): "
            + (", ".join(f"{count} {state.lower().replace('_', ' ')}"
                         for state, count in sorted(counts.items())) or "none")
            + "; a policy row nobody observed is reported as not observed, not as drift"),
    }


def pqc_migration(twin: Mapping[str, Any],
                  *, as_of: str | None = None) -> dict[str, Any]:
    """The migration queue, ordered by what the twin can actually prove.

    Each row keeps the registry basis for its quantum verdict and the promotion
    level of the node it read, so a migration plan built from capabilities is
    visibly weaker than one built from runtime observations.
    """
    rows: list[dict[str, Any]] = []
    for algorithm, node in sorted(_algorithms(twin).items()):
        key_size = node.get("key_size")
        try:
            size = int(key_size) if key_size not in (None, "") else None
        except (TypeError, ValueError):
            size = None
        status = pq.quantum_status(algorithm, size)
        risk = pq.quantum_risk(algorithm, size, node.get("purpose"),
                               None if node.get("usage") else "CAPABILITY")
        priority = pq.migration_priority(risk=risk["risk"], status=status["status"],
                                         usage=node.get("promotion_level"),
                                         purpose=node.get("purpose"))
        rows.append({
            "algorithm": algorithm,
            "quantum_status": status["status"],
            "status_basis": status["basis"],
            "risk": risk["risk"],
            "risk_basis": risk["basis"],
            "migration_priority": priority["priority"],
            "claim_level": node["claim_level"],
            "evidence_ids": node["evidence_ids"],
            "detail": (f"{status['status']} ({status['basis']}); "
                       f"{node['claim_level']} evidence; "
                       f"{priority['priority']}"),
        })
    rows.sort(key=lambda row: ({"IMMEDIATE": 0, "NEAR_TERM": 1, "PLANNED": 2,
                                "MONITOR": 3}.get(row["migration_priority"], 4),
                               row["algorithm"]))
    urgent = [row["algorithm"] for row in rows
              if row["migration_priority"] == "IMMEDIATE"]
    return {
        "schema": SCHEMA,
        "consumer": "pqc_migration",
        "as_of": as_of,
        "rows": rows,
        "counts": {priority: sum(1 for row in rows
                                 if row["migration_priority"] == priority)
                   for priority in ("IMMEDIATE", "NEAR_TERM", "PLANNED", "MONITOR")},
        "statement": (
            f"{len(rows)} algorithm(s) in the migration queue"
            + (f"; {len(urgent)} at IMMEDIATE priority: {', '.join(urgent)}"
               if urgent else "; nothing at IMMEDIATE priority")
            + "; every verdict comes from the registry, never from the document"),
    }


def threat_intelligence(twin: Mapping[str, Any],
                        advisories: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Advisories matched against what the twin knows, with the exposure stated.

    An advisory names a component and a version range. Exposure is a *different*
    claim from presence:

    * ``EXECUTING`` — a provider node with a runtime observation is loaded by a
      process, so the vulnerable code is running;
    * ``PRESENT`` — a component node from an SBOM is installed, and nothing says it
      is loaded;
    * ``VERSION_UNKNOWN`` — the component is known and its version is not, so the
      advisory can be neither confirmed nor cleared.

    A capability-only algorithm node never produces exposure on its own: a library
    that *supports* AES-128-CBC is not exploiting anything.
    """
    nodes = list(twin.get("nodes") or [])
    findings: list[dict[str, Any]] = []
    for advisory in advisories or ():
        if not isinstance(advisory, Mapping) or not advisory.get("component"):
            continue
        wanted = str(advisory["component"]).lower()
        affected = {str(version) for version in advisory.get("affected_versions") or []}
        fixed_in = advisory.get("fixed_in")
        matched = [node for node in nodes
                   if node["kind"] in {"COMPONENT", "PROVIDER"}
                   and str(node.get("component") or node["id"].split(":", 1)[1]
                           ).split("@")[0].lower() == wanted]
        if not matched:
            findings.append({
                "advisory": advisory.get("id"), "component": advisory.get("component"),
                "exposure": "NOT_PRESENT", "claim_level": "CAPABILITY",
                "detail": "the twin knows no component or provider of this name",
                "evidence_ids": [], "nodes": []})
            continue
        for node in matched:
            version = node.get("version")
            if not version:
                exposure, detail = "VERSION_UNKNOWN", (
                    "the component is known and its version is not, so the advisory "
                    "can be neither confirmed nor cleared")
            elif version in affected or _below(version, fixed_in):
                exposure = ("EXECUTING" if node["kind"] == "PROVIDER" else "PRESENT")
                detail = (f"version {version} is inside the affected range"
                          + ("; a process has it loaded" if node["kind"] == "PROVIDER"
                             else "; installed, with nothing saying it is loaded"))
            else:
                exposure, detail = "NOT_AFFECTED", (
                    f"version {version} is outside the affected range")
            findings.append({
                "advisory": advisory.get("id"),
                "component": node["id"].split(":", 1)[1].split("@")[0],
                "severity": advisory.get("severity"),
                "exposure": exposure,
                "claim_level": node["claim_level"],
                "detail": detail,
                "evidence_ids": node["evidence_ids"],
                "nodes": [node["id"]]})
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["exposure"]] = counts.get(finding["exposure"], 0) + 1
    exposed = [row for row in findings if row["exposure"] in {"EXECUTING", "PRESENT"}]
    return {
        "schema": SCHEMA,
        "consumer": "threat_intelligence",
        "findings": findings,
        "counts": dict(sorted(counts.items())),
        "exposed": len(exposed),
        "statement": (
            f"{len(findings)} advisory match(es) over {len(advisories or ())} advisory"
            f"(ies): "
            + (", ".join(f"{count} {state.lower().replace('_', ' ')}"
                         for state, count in sorted(counts.items())) or "none")
            + "; installed and running are different exposures"),
    }


def _below(version: str, fixed_in: Any) -> bool:
    """True when ``version`` is strictly below ``fixed_in`` (numeric, dotted)."""
    if not fixed_in:
        return False

    def parts(value: Any) -> tuple[int, ...]:
        numbers = []
        for chunk in str(value).split("."):
            digits = "".join(char for char in chunk if char.isdigit())
            numbers.append(int(digits) if digits else 0)
        return tuple(numbers)

    return parts(version) < parts(fixed_in)


def consumers(twin: Mapping[str, Any],
              *, policy: Iterable[Mapping[str, Any]] = (),
              advisories: Iterable[Mapping[str, Any]] = (),
              as_of: str | None = None) -> dict[str, Any]:
    """All three consumers over one twin, plus the check that nothing was upgraded."""
    blocks = {
        "drift": drift(twin, policy),
        "pqc_migration": pqc_migration(twin, as_of=as_of),
        "threat_intelligence": threat_intelligence(twin, advisories),
    }
    source_levels = {node["id"]: node["claim_level"] for node in twin.get("nodes") or []}
    upgrades: list[dict[str, Any]] = []
    for name, block in blocks.items():
        for row in block.get("rows") or block.get("findings") or []:
            level = row.get("claim_level")
            if level is None:
                continue
            limits = [source_levels[node] for node in row.get("nodes") or []
                      if node in source_levels]
            if limits and CLAIM_LEVELS.index(level) > min(
                    CLAIM_LEVELS.index(limit) for limit in limits):
                upgrades.append({"consumer": name, "algorithm": row.get("algorithm"),
                                 "claim_level": level, "node_levels": limits})
    return {
        "schema": SCHEMA,
        "consumers": blocks,
        "claim_check": {
            "ok": not upgrades,
            "upgrades": upgrades,
            "detail": (f"{len(upgrades)} consumer row(s) claim more than their node"
                       if upgrades else "no consumer claims more than the node it read"),
        },
        "statement": " · ".join(block["statement"] for block in blocks.values()),
    }


def summary(twin: Mapping[str, Any], consumers_result: Mapping[str, Any]) -> dict[str, Any]:
    """The one-screen answer for an operator: the twin, then the three questions."""
    blocks = consumers_result.get("consumers") or {}
    return {
        "schema": SCHEMA,
        "estate": twin.get("estate"),
        "nodes": len(twin.get("nodes") or []),
        "edges": len(twin.get("edges") or []),
        "families": twin.get("families"),
        "unrepresented_families": twin.get("unrepresented_families"),
        "drift": (blocks.get("drift") or {}).get("counts"),
        "migration": (blocks.get("pqc_migration") or {}).get("counts"),
        "advisories": (blocks.get("threat_intelligence") or {}).get("counts"),
        "claim_check": (consumers_result.get("claim_check") or {}).get("ok"),
        "statement": (
            f"{twin.get('estate')}: {len(twin.get('nodes') or [])} node(s), "
            f"{len(twin.get('edges') or [])} edge(s); "
            f"drift clean={bool((blocks.get('drift') or {}).get('clean'))}, "
            f"advisories exposed={(blocks.get('threat_intelligence') or {}).get('exposed', 0)}"
            + ("" if (consumers_result.get("claim_check") or {}).get("ok", True)
               else "; a consumer claimed more than its node")),
    }
