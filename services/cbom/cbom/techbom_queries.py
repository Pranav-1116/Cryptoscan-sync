"""The questions a TechBOM has to answer, asked of the graph rather than the inventory.

:mod:`cbom.techbom` builds the graph and guards it: an asset is an identity, an edge is a
claim with a basis, and nothing joins two assets because they were seen together. That
graph is only worth building if it can answer the questions an estate actually asks, which
is what this module does — and the answers are only trustworthy if they inherit the
graph's rules:

* **a roll-up counts proven descendants only.** A business system's "5 applications"
  must not include an application that a CMDB import claims and nothing else supports;
  the declared-but-unproven remainder is reported as its own number, never folded in;
* **a request path is a path, not a list of endpoints.** Every hop carries the crypto it
  negotiates — version, cipher, certificate, SNI, ALPN, mTLS — and a hop that has none
  says `NOT_RECORDED` instead of being drawn as if it were clean;
* **impact is a vocabulary, not a dump.** The counts an owner asks for (applications,
  systems, certificates, HSMs, vendors, network paths), the ones that decide urgency
  (critical, legacy) and the migration blockers, typed by *who has to do what*: an HSM
  lacking a required algorithm, firmware that has to be upgraded, a certificate whose
  lifetime outlives the migration, an application whose cryptography is not recorded;
* **a timeline needs more than one snapshot.** One snapshot is a state, not a series, and
  saying "no changes" from one point in time is the oldest lie in change management;
* **threat context is read from the graph and never invented.** An event naming an asset
  the TechBOM does not hold produces a refusal, not a plausible-looking pattern;
* **a claim can be promoted, but only by evidence.** `IMPORTED` becomes `OBSERVED` when a
  probe says so, with the previous class kept in the claim's history — the model never
  rewrites what it used to believe.

Each answer carries the limits it cannot cross, because the failure mode of a good graph
is a confident sentence that the graph never supported.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cbom.techbom import (
    BASES,
    CONFIDENCE,
    NOT_A_BASIS,
    PROVEN,
    SCHEMA,
    ClaimRefused,
    _norm,
    _quantum_sensitive,
)

#: the crypto a hop negotiates, in the order an operator reads it
HOP_CRYPTO: tuple[tuple[str, str], ...] = (
    ("tls_version", "TLS version"),
    ("cipher", "cipher suite"),
    ("certificate", "certificate"),
    ("sni", "SNI"),
    ("alpn", "ALPN"),
    ("mtls", "mTLS"),
)

#: kinds counted in an impact answer, in the order the review lists them
IMPACT_KINDS: tuple[str, ...] = (
    "APPLICATION", "BUSINESS_SYSTEM", "SERVICE", "CONTAINER", "POD", "PROCESS",
    "PACKAGE", "CRYPTO_LIBRARY", "CRYPTO_ASSET", "DATABASE", "NETWORK_ENDPOINT",
    "WAF", "LOAD_BALANCER", "API_GATEWAY", "SERVICE_MESH", "CERTIFICATE",
    "CERTIFICATE_AUTHORITY", "HSM", "KMS", "KEY_REFERENCE", "FIRMWARE",
    "VENDOR_PRODUCT", "VENDOR", "HOST", "VM", "PHYSICAL_SERVER", "TPM",
)

#: statuses that make an asset legacy. A version nobody maintains is not a version.
LEGACY_STATUSES = frozenset({"LEGACY", "EOL", "END_OF_LIFE", "RETIRED", "DEPRECATED"})

#: how a blocker is named, and who has to act
BLOCKERS: dict[str, str] = {
    "HSM_PQC_UNSUPPORTED": "the HSM's firmware does not list a required algorithm",
    "HSM_PQC_CAPABILITY_UNKNOWN": "no evidence of what the HSM can do, so it is a blocker "
                                 "until someone reads its capability list",
    "FIRMWARE_UPGRADE_REQUIRED": "the firmware in place does not support a required "
                                 "algorithm",
    "CERTIFICATE_LIFECYCLE_INCOMPATIBLE": "the certificate's lifetime outlives the "
                                          "migration deadline",
    "LEGACY_APPLICATION_UNKNOWN": "the application's cryptography is not recorded, so a "
                                  "migration cannot plan around it",
    "UNPROVEN_DEPENDENCY": "the dependency is declared rather than proven, so the plan "
                           "rests on a claim",
}

NOT_PROVEN = [
    "that a roll-up is the system: it counts the assets the graph proves belong to that "
    "system, and an asset nobody connected to a system is in no system",
    "that a request path is the only path: the graph holds the routes a source asserted, "
    "and an unrecorded route is missing rather than absent",
    "that an impact is a breakage: reachability is exposure, and whether a named "
    "application stops working is its owner's assessment",
    "that a blocker is the only blocker: the model names what it can see on the path, and "
    "a vendor's roadmap is not on the path",
    "that a timeline's absence is stability: a change that both layers missed is not a "
    "change the timeline can report",
]


# --------------------------------------------------------------------------- #
# Graph helpers over an already-built TechBOM
# --------------------------------------------------------------------------- #

def _assets(bom: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(bom, Mapping) or bom.get("schema") != SCHEMA:
        raise ValueError(f"this answer takes a {SCHEMA} document")
    return bom.get("by_key") or {}


def _edges(bom: Mapping[str, Any]) -> list[dict[str, Any]]:
    return list(bom.get("claims") or [])


def _outbound(bom: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for row in _edges(bom):
        index.setdefault(row["from_key"], []).append(row)
    return index


def _inbound(bom: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for row in _edges(bom):
        index.setdefault(row["to_key"], []).append(row)
    return index


def _resolve(bom: Mapping[str, Any], reference: Any) -> str | None:
    text = _norm(reference)
    if not text:
        return None
    assets = _assets(bom)
    for key in assets:
        if key.lower() == text.lower() or assets[key]["id"].lower() == text.lower():
            return key
    matches = [key for key, row in assets.items() if row["name"].lower() == text.lower()]
    return matches[0] if len(matches) == 1 else None


def _walk(bom: Mapping[str, Any], roots: Iterable[str], *,
          direction: str) -> tuple[set[str], set[str]]:
    """Reach from ``roots``: what is proven, and what is only declared.

    Taint propagates. A node is proven only when *every* edge on the path that reached it
    is `OBSERVED` or `CONFIGURED`; one declared hop makes everything above it declared,
    which is the difference between "the CMDB says this container runs here" and "this
    container runs here".
    """
    index = _outbound(bom) if direction == "forward" else _inbound(bom)
    link = "to_key" if direction == "forward" else "from_key"
    starts = list(roots)
    state: dict[str, bool] = {key: True for key in starts}
    proven: set[str] = set()
    declared: set[str] = set()
    frontier = list(starts)
    for _ in range(12):
        if not frontier:
            break
        upcoming: list[str] = []
        for key in frontier:
            for edge in index.get(key, []):
                other = edge[link]
                if other in state:
                    continue
                path_proven = state[key] and edge["confidence"] in PROVEN
                state[other] = path_proven
                (proven if path_proven else declared).add(other)
                upcoming.append(other)
        frontier = upcoming
    return proven - set(starts), declared - set(starts)


# --------------------------------------------------------------------------- #
# 1. Roll-up: the business system, with its technology counted
# --------------------------------------------------------------------------- #

LABELS: dict[str, tuple[str, str]] = {
    "HSM": ("HSM", "HSMs"),
    "KMS": ("KMS", "KMSes"),
    "WAF": ("WAF", "WAFs"),
    "API_GATEWAY": ("API gateway", "API gateways"),
    "SERVICE_MESH": ("service mesh", "service meshes"),
    "CERTIFICATE": ("certificate", "certificates"),
    "CERTIFICATE_AUTHORITY": ("certificate authority", "certificate authorities"),
    "PUBLIC_KEY": ("public key", "public keys"),
    "NETWORK_ENDPOINT": ("network endpoint", "network endpoints"),
    "CRYPTO_ASSET": ("crypto asset", "crypto assets"),
    "CRYPTO_LIBRARY": ("crypto library", "crypto libraries"),
    "VENDOR_PRODUCT": ("vendor product", "vendor products"),
    "KEY_REFERENCE": ("key reference", "key references"),
    "LOAD_BALANCER": ("load balancer", "load balancers"),
    "BUSINESS_SYSTEM": ("business system", "business systems"),
    "TPM": ("TPM", "TPMs"),
    "VM": ("VM", "VMs"),
    "POD": ("pod", "pods"),
    "HOST": ("host", "hosts"),
}


def _label(kind: str, count: int | None = None) -> str:
    singular = kind.lower().replace("_", " ")
    plural = f"{singular}es" if singular.endswith("s") else f"{singular}s"
    singular, plural = LABELS.get(kind, (singular, plural))
    if count is None:
        return plural
    return singular if count == 1 else plural


def _profile(bom: Mapping[str, Any], key: str) -> dict[str, Any]:
    assets = _assets(bom)
    row = assets[key]
    proven, declared = _walk(bom, [key], direction="forward")
    proven.discard(key)
    counts: dict[str, int] = {}
    for member in proven:
        kind = assets[member]["kind"]
        counts[kind] = counts.get(kind, 0) + 1
    declared_counts: dict[str, int] = {}
    for member in declared:
        kind = assets[member]["kind"]
        declared_counts[kind] = declared_counts.get(kind, 0) + 1
    sensitive = sorted(assets[member]["name"] for member in proven
                       if assets[member]["kind"] == "CRYPTO_ASSET"
                       and _quantum_sensitive(assets[member]["name"]))
    legacy = sorted(assets[member]["id"] for member in proven
                    if str(assets[member]["status"]).upper() in LEGACY_STATUSES)
    vendors = sorted(assets[member]["name"] for member in proven
                     if assets[member]["kind"] in ("VENDOR", "VENDOR_PRODUCT"))
    headline = ", ".join(f"{count} {_label(kind, count)}"
                         for kind in IMPACT_KINDS if (count := counts.get(kind)))
    return {
        "system": row["id"],
        "name": row["name"],
        "criticality": str(row["attributes"].get("criticality") or "UNSTATED").upper(),
        "owner": row["owner"],
        "counts": dict(sorted(counts.items())),
        "declared_only": dict(sorted(declared_counts.items())),
        "proven_assets": len(proven),
        "declared_only_assets": len(declared),
        "systems": [],  # a profile is one system; nesting is a portfolio question
        "quantum_sensitive": sensitive,
        "vendors": vendors,
        "legacy_assets": legacy,
        "statement": (
            f"{row['name']} ({row['attributes'].get('criticality') or 'UNSTATED'}): "
            f"{headline or 'no assets proven'} across {len(counts)} kind(s)"
            + (f"; {len(declared)} more asset(s) declared but not proven"
               if declared else "")),
        "not_proven": [
            "that this is the system's whole technology estate: only assets the graph "
            "connects to the system are counted, and an unconnected asset belongs to no "
            "system here",
            "that the owner's criticality is current: it is an attribute of the system "
            "row, not a measured property",
        ],
    }


def rollup(bom: Mapping[str, Any], *, system: Any = None) -> dict[str, Any]:
    """Business system → the technology it actually holds, counted by kind."""
    assets = _assets(bom)
    if system is not None:
        key = _resolve(bom, system)
        if not key or assets[key]["kind"] != "BUSINESS_SYSTEM":
            raise ValueError(f"{_norm(system) or '(none)'} is not a business system in "
                             "this TechBOM")
        profile = _profile(bom, key)
        return {"schema": SCHEMA, "systems": [profile], "statement": profile["statement"],
                "not_proven": profile["not_proven"]}
    profiles = [_profile(bom, key) for key, row in sorted(assets.items())
                if row["kind"] == "BUSINESS_SYSTEM"]
    return {
        "schema": SCHEMA,
        "systems": profiles,
        "statement": (f"{len(profiles)} business system(s): "
                      + ", ".join(f"{row['name']} ({row['proven_assets']})"
                                  for row in profiles)
                      if profiles else "no business system in this TechBOM"),
        "not_proven": [
            "that a system with no assets is empty: it is unconnected, which the graph "
            "cannot tell apart from uncollected",
        ],
    }


# --------------------------------------------------------------------------- #
# 2. Request paths: which technology a request travels through, hop by hop
# --------------------------------------------------------------------------- #

def path(bom: Mapping[str, Any], *, source: Any, target: Any = None,
         max_paths: int = 5, max_hops: int = 8) -> dict[str, Any]:
    """Every route the graph asserts from ``source`` (optionally to ``target``)."""
    assets = _assets(bom)
    start = _resolve(bom, source)
    if not start:
        raise ValueError(f"{_norm(source) or '(none)'} is not in this TechBOM")
    finish = _resolve(bom, target) if target is not None else None
    if target is not None and not finish:
        raise ValueError(f"{_norm(target)} is not in this TechBOM")
    outbound = _outbound(bom)
    routes: list[list[dict[str, Any]]] = []

    def walk(hop: str, trail: list[dict[str, Any]], seen: set[str]) -> None:
        if len(routes) >= max_paths or len(trail) >= max_hops:
            return
        if finish is not None and hop == finish and trail:
            routes.append(list(trail))
            return
        if finish is None and trail and not trail[-1]["chain"] == "SOFTWARE":
            routes.append(list(trail))
        for edge in outbound.get(hop, []):
            if edge["chain"] not in ("NETWORK", "SOFTWARE"):
                continue
            if edge["to_key"] in seen:
                continue
            walk(edge["to_key"], [*trail, edge], seen | {edge["to_key"]})

    walk(start, [], {start})
    rendered: list[dict[str, Any]] = []
    for trail in routes:
        hops = [_hop(bom, start, None)] + [_hop(bom, edge["to_key"], edge)
                                          for edge in trail]
        confidences = [edge["confidence"] for edge in trail]
        recorded = [hop for hop in hops if hop["crypto_recorded"]]
        rendered.append({
            "hops": hops,
            "edges": [edge["id"] for edge in trail],
            "weakest": _weakest(confidences),
            "unproven_edges": sum(1 for value in confidences if value not in PROVEN),
            "crypto_recorded": f"{len(recorded)}/{len(hops)}",
            "statement": " → ".join(hop["name"] for hop in hops),
        })
    rendered.sort(key=lambda row: (row["unproven_edges"], len(row["hops"])))
    return {
        "schema": SCHEMA,
        "source": assets[start]["id"],
        "target": assets[finish]["id"] if finish else None,
        "paths": rendered,
        "statement": (
            f"{len(rendered)} path(s) from {assets[start]['name']}"
            + (f" to {assets[finish]['name']}" if finish else "")
            + (f"; first: {rendered[0]['statement']}" if rendered
               else "; no route is asserted from here")),
        "not_proven": [
            "that a request takes this path: the graph holds the routes a source "
            "asserted, and load balancers route by rules this model does not read",
            "that a hop with no crypto recorded is unencrypted: it means the hop's TLS "
            "properties were not collected, which is different",
        ],
    }


def _weakest(values: list[str]) -> str | None:
    if not values:
        return None
    return min(values, key=lambda value: CONFIDENCE[value])


def _hop(bom: Mapping[str, Any], key: str, edge: Mapping[str, Any] | None) -> dict[str, Any]:
    row = _assets(bom)[key]
    attributes = row["attributes"]
    crypto = {name: attributes.get(name) for name, _ in HOP_CRYPTO
              if attributes.get(name) not in (None, "")}
    certificate = _presented_certificate(bom, key)
    return {
        "asset": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "role": edge["relation"] if edge else "START",
        "evidence": edge["confidence"] if edge else None,
        "crypto": crypto,
        "certificate": certificate,
        "crypto_recorded": bool(crypto) or bool(certificate),
        "note": None if crypto or certificate else "NOT_RECORDED",
    }


def _presented_certificate(bom: Mapping[str, Any], key: str) -> str | None:
    assets = _assets(bom)
    for edge in _edges(bom):
        if edge["from_key"] == key and edge["relation"] == "PRESENTS":
            return assets[edge["to_key"]]["id"]
    return None


# --------------------------------------------------------------------------- #
# 3. Impact: the vocabulary an owner asks for, and typed blockers
# --------------------------------------------------------------------------- #

def impact(bom: Mapping[str, Any], *, query: Any, required_algorithms: Iterable[str] | None = None,
           deadline: Any = None) -> dict[str, Any]:
    """Everything reachable from a technology, counted the way an owner reads it."""
    assets = _assets(bom)
    text = _norm(query).lower()
    if not text:
        raise ValueError("an impact answer needs something to start from")
    seeds = [key for key, row in assets.items()
             if row["name"].lower() == text or row["id"].lower() == text
             or text in row["name"].lower()
             or any(text in str(value).lower() for value in row["attributes"].values())]
    if not seeds:
        return {
            "schema": SCHEMA, "query": _norm(query), "seeds": [], "counts": {},
            "statement": f"nothing in this TechBOM matches {_norm(query)}",
            "pqc_blockers": [], "blocker_counts": {}, "not_proven": list(NOT_PROVEN),
        }
    proven, declared = _walk(bom, seeds, direction="back")
    proven -= set(seeds)
    counts: dict[str, int] = {}
    for member in proven:
        kind = assets[member]["kind"]
        if kind in IMPACT_KINDS:
            counts[kind] = counts.get(kind, 0) + 1
    systems = sorted(key for key in proven if assets[key]["kind"] == "BUSINESS_SYSTEM")
    critical = [key for key in systems
                if str(assets[key]["attributes"].get("criticality")).upper()
                in ("CRITICAL", "HIGH")]
    legacy = sorted(key for key in proven
                    if str(assets[key]["status"]).upper() in LEGACY_STATUSES)
    required = {str(value).strip().upper() for value in (required_algorithms or [])}
    sites = _migration_sites(bom, seeds, proven)
    blockers = _blockers(bom, seeds, proven, sites, required, deadline)
    blocker_counts: dict[str, int] = {}
    for blocker in blockers:
        blocker_counts[blocker["code"]] = blocker_counts.get(blocker["code"], 0) + 1
    network_edges = {edge["id"] for edge in _edges(bom)
                     if edge["chain"] == "NETWORK"
                     and (edge["to_key"] in proven or edge["from_key"] in proven)}
    return {
        "schema": SCHEMA,
        "query": _norm(query),
        "seeds": sorted(assets[key]["id"] for key in seeds),
        "counts": dict(sorted(counts.items())),
        "systems": sorted(assets[key]["id"] for key in systems),
        "primary_system": (assets[systems[0]]["id"] if systems else None),
        "critical_systems": sorted(assets[key]["id"] for key in critical),
        "legacy_assets": [assets[key]["id"] for key in legacy],
        "vendors": sorted({assets[key]["name"] for key in proven
                           if assets[key]["kind"] == "VENDOR"}),
        "network_paths": len(network_edges),
        "quantum_sensitive": sorted({assets[key]["name"] for key in proven
                                     if assets[key]["kind"] == "CRYPTO_ASSET"
                                     and _quantum_sensitive(assets[key]["name"])}),
        "declared_only": sorted(assets[key]["id"] for key in declared - proven),
        "migration_sites": sorted(assets[key]["id"] for key in sites),
        "pqc_blockers": blockers,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "statement": (
            f"{_norm(query)}: " + ", ".join(f"{count} {_label(kind, count)}"
                                            for kind, count in sorted(counts.items()))
            if counts else _norm(query) + ": no dependent asset")
                   + (f"; {len(critical)} critical system(s)" if critical else "")
                   + (f"; {len(blockers)} blocker(s)" if blockers else ""),
        "not_proven": list(NOT_PROVEN) + [
            "that the count is the impact: it is what the graph proves depends on this "
            "technology, and an owner's business impact assessment sits above it",
        ],
    }


def _migration_sites(bom: Mapping[str, Any], seeds: list[str],
                     proven: set[str]) -> set[str]:
    """The devices an application's migration has to pass through.

    A dependency walk answers "who breaks if this algorithm goes", which is not the same
    question as "who has to change": the HSM a *dependent* application uses is where the
    migration stops, even though nothing about the algorithm points at it.
    """
    assets = _assets(bom)
    outbound = _outbound(bom)
    sites: set[str] = set()
    for key in {*seeds, *proven}:
        if assets[key]["kind"] not in ("APPLICATION", "SERVICE", "PROCESS"):
            continue
        for edge in outbound.get(key, []):
            if edge["relation"] != "USES_HSM":
                continue
            hsm = edge["to_key"]
            sites.add(hsm)
            for second in outbound.get(hsm, []):
                if second["relation"] == "RUNS_FIRMWARE":
                    sites.add(second["to_key"])
    return sites


def _blockers(bom: Mapping[str, Any], seeds: list[str], proven: set[str],
              sites: set[str], required: set[str],
              deadline: Any) -> list[dict[str, Any]]:
    assets = _assets(bom)
    found: list[dict[str, Any]] = []

    def add(code: str, key: str, detail: str) -> None:
        found.append({"code": code, "asset": assets[key]["id"],
                      "kind": assets[key]["kind"], "name": assets[key]["name"],
                      "detail": detail, "who_acts": BLOCKERS[code]})

    for key in sorted(proven | set(seeds) | sites):
        row = assets[key]
        supports = {str(value).strip().upper()
                    for value in (row["attributes"].get("supports") or [])}
        if row["kind"] == "HSM":
            if not required:
                continue
            if not supports:
                add("HSM_PQC_CAPABILITY_UNKNOWN", key,
                    "no capability list was collected for this HSM")
            elif not required <= supports:
                add("HSM_PQC_UNSUPPORTED", key,
                    f"does not list {', '.join(sorted(required - supports))}")
        elif row["kind"] == "FIRMWARE":
            if required and supports and not required <= supports:
                add("FIRMWARE_UPGRADE_REQUIRED", key,
                    f"firmware {row['version'] or '(unknown)'} does not list "
                    f"{', '.join(sorted(required - supports))}")
        elif row["kind"] == "CERTIFICATE":
            algorithm = _certificate_algorithm(bom, key)
            if not _quantum_sensitive(algorithm):
                continue
            not_after = row["attributes"].get("not_after")
            if deadline and not_after and str(not_after) > str(deadline):
                add("CERTIFICATE_LIFECYCLE_INCOMPATIBLE", key,
                    f"{algorithm} certificate valid until {not_after}, after the "
                    f"migration deadline {deadline}")
        elif row["kind"] == "APPLICATION":
            uses_crypto = any(edge["relation"] == "USES_CRYPTO"
                              for edge in _outbound(bom).get(key, []))
            if not uses_crypto:
                add("LEGACY_APPLICATION_UNKNOWN", key,
                    "no cryptography is recorded for this application, in any layer")
    return found


def _certificate_algorithm(bom: Mapping[str, Any], key: str) -> str | None:
    assets = _assets(bom)
    for edge in _outbound(bom).get(key, []):
        if edge["relation"] == "CONTAINS_KEY":
            for second in _outbound(bom).get(edge["to_key"], []):
                if second["relation"] == "USES_ALGORITHM":
                    return assets[second["to_key"]]["name"]
    return None


# --------------------------------------------------------------------------- #
# 4. Time: a series of snapshots, not one state
# --------------------------------------------------------------------------- #

#: the nine changes the review asks a TechBOM to be able to report
CHANGE_CATEGORIES: tuple[str, ...] = (
    "TECHNOLOGY_CHANGED", "SBOM_CHANGED", "CRYPTO_CHANGED", "NETWORK_CHANGED",
    "CERTIFICATE_CHANGED", "VENDOR_CHANGED", "HARDWARE_CHANGED",
    "DEPLOYMENT_CHANGED",
)


def timeline(snapshots: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Several TechBOM snapshots → one change series, category by category."""
    from cbom.techbom import diff  # noqa: PLC0415 — kept local to avoid a cycle

    series = list(snapshots or [])
    for row in series:
        if not isinstance(row, Mapping) or row.get("schema") != SCHEMA:
            raise ValueError(f"a timeline takes {SCHEMA} snapshots")
    if len(series) < 2:
        return {
            "schema": SCHEMA, "snapshots": len(series), "measurable": False,
            "changes": [], "by_category": {}, "by_change": {}, "steps": [],
            "series": [{"snapshot": 1, "assets": len(series[0].get("assets") or []),
                        "claims": len(series[0].get("claims") or [])}
                       ] if series else [],
            "statement": ("one snapshot is a state, not a series: nothing can be said "
                          "about change from one point in time"),
            "not_proven": list(NOT_PROVEN),
        }
    changes: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    for index in range(1, len(series)):
        step = diff(series[index - 1], series[index])
        steps.append({"from": index - 1, "to": index,
                      "changes": len(step["events"]),
                      "by_category": step["by_category"],
                      "statement": step["statement"]})
        for event in step["events"]:
            changes.append({**event, "step": index,
                            "from_snapshot": index - 1})
    by_category: dict[str, int] = {}
    for event in changes:
        category = event["category"]
        if category not in CHANGE_CATEGORIES:
            category = "TECHNOLOGY_CHANGED"
        by_category[category] = by_category.get(category, 0) + 1
    by_change: dict[str, int] = {}
    for event in changes:
        by_change[event["change"]] = by_change.get(event["change"], 0) + 1
    return {
        "schema": SCHEMA,
        "snapshots": len(series),
        "measurable": True,
        "changes": changes,
        "steps": steps,
        "by_category": dict(sorted(by_category.items())),
        "by_change": dict(sorted(by_change.items())),
        "series": [{"snapshot": index,
                    "assets": len(row.get("assets") or []),
                    "claims": len(row.get("claims") or [])}
                   for index, row in enumerate(series, start=1)],
        "statement": (
            f"{len(series)} snapshot(s), {len(changes)} change(s)"
            + (": " + ", ".join(f"{name} {count}" for name, count
                                in sorted(by_category.items())) if by_category else
               "; nothing moved")),
        "not_proven": list(NOT_PROVEN) + [
            "that a gap between snapshots is empty: sampling two states says nothing "
            "about what happened between them",
        ],
    }


# --------------------------------------------------------------------------- #
# 5. Threat context: an event, placed in the estate it happened to
# --------------------------------------------------------------------------- #

CONTEXT_KINDS: tuple[str, ...] = ("TLS_DOWNGRADE", "CERTIFICATE_CHANGE",
                                  "CRYPTO_REGRESSION", "NEW_EXPOSURE")


def threat_context(bom: Mapping[str, Any], event: Mapping[str, Any]) -> dict[str, Any]:
    """A live network event → a correlated pattern with the estate behind it."""
    if not isinstance(event, Mapping):
        raise ValueError("a threat context needs an event object")
    kind = str(event.get("kind") or "").strip().upper()
    if kind not in CONTEXT_KINDS:
        raise ValueError(f"{kind or '(none)'} is not one of {', '.join(CONTEXT_KINDS)}")
    evidence = [_norm(value) for value in (event.get("evidence_ids") or [])
                if _norm(value)]
    if not evidence:
        raise ValueError("an event with no evidence id is a rumour, not a context")
    assets = _assets(bom)
    key = _resolve(bom, event.get("asset"))
    if not key:
        raise ValueError(
            f"{_norm(event.get('asset')) or '(none)'} is not in this TechBOM; a pattern "
            "naming an asset the estate does not hold would be fabricated context")
    proven, declared = _walk(bom, [key], direction="back")
    proven.discard(key)
    systems = [member for member in sorted(proven)
               if assets[member]["kind"] == "BUSINESS_SYSTEM"]
    nearest = _nearest(bom, key, ("APPLICATION",))
    related = _related(bom, key)
    before = _norm(event.get("before")) or None
    after = _norm(event.get("after")) or None
    return {
        "schema": SCHEMA,
        "pattern": "CORRELATED_PATTERN",
        "event": {"kind": kind, "asset": assets[key]["id"],
                  "asset_kind": assets[key]["kind"], "name": assets[key]["name"],
                  "before": before, "after": after,
                  "evidence_ids": evidence,
                  "observed_at": _norm(event.get("observed_at")) or None},
        "systems": [{"id": assets[member]["id"], "name": assets[member]["name"],
                     "criticality": str(assets[member]["attributes"].get(
                         "criticality") or "UNSTATED").upper()}
                    for member in systems],
        "technology": [{"id": assets[member]["id"], "kind": assets[member]["kind"],
                        "name": assets[member]["name"]} for member in
                       ([nearest] if nearest else [])],
        "related": related,
        "change": ({"attribute": "tls_version", "from": before, "to": after}
                   if kind in ("TLS_DOWNGRADE", "CRYPTO_REGRESSION")
                   else {"attribute": "certificate", "from": before, "to": after}
                   if kind == "CERTIFICATE_CHANGE" else None),
        "declared_only": sorted(assets[member]["id"] for member in declared),
        "statement": (
            f"{kind.replace('_', ' ').lower()} on {assets[key]['name']}"
            + (f" ({before} → {after})" if before and after else "")
            + (f"; business system {assets[systems[0]]['name']}"
               if systems else "; no business system is proven upstream")
            + (f"; {len(related)} related asset(s)" if related else "")),
        "not_proven": [
            "that the event caused the pattern: the context is the estate the event "
            "happened to, not a causal chain",
            "that a downgrade is an attack: a client negotiating lower is the most common "
            "cause of the same observation",
            "that a system not listed is unaffected: an unproven containment is missing, "
            "not disproven",
        ],
    }


def _nearest(bom: Mapping[str, Any], key: str, kinds: tuple[str, ...]) -> str | None:
    inbound = _inbound(bom)
    frontier, seen = [key], {key}
    for _ in range(10):
        upcoming: list[str] = []
        for node in frontier:
            for edge in inbound.get(node, []):
                other = edge["from_key"]
                if other in seen:
                    continue
                seen.add(other)
                if _assets(bom)[other]["kind"] in kinds:
                    return other
                upcoming.append(other)
        frontier = upcoming
    return None


def _related(bom: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    assets = _assets(bom)
    out: list[dict[str, Any]] = []
    for edge in _outbound(bom).get(key, []):
        out.append({"relation": edge["relation"],
                    "asset": assets[edge["to_key"]]["id"],
                    "kind": assets[edge["to_key"]]["kind"],
                    "name": assets[edge["to_key"]]["name"],
                    "confidence": edge["confidence"]})
    for edge in _inbound(bom).get(key, []):
        if edge["relation"] in ("CONTAINS", "PROVIDES", "RUNS", "FROM_IMAGE", "SHIPS",
                                "USES_CRYPTO", "USES_HSM"):
            continue  # the estate above this asset is reported as technology/systems
        out.append({"relation": edge["relation"],
                    "asset": assets[edge["from_key"]]["id"],
                    "kind": assets[edge["from_key"]]["kind"],
                    "name": assets[edge["from_key"]]["name"],
                    "confidence": edge["confidence"]})
    return out


# --------------------------------------------------------------------------- #
# 6. Promotion: a claim gets stronger only with evidence
# --------------------------------------------------------------------------- #

def verify(row: Mapping[str, Any], *, basis: Any, evidence_ids: Iterable[Any] | None = None,
           at: Any = None) -> dict[str, Any]:
    """Promote an existing claim with new evidence, keeping what it used to be."""
    if not isinstance(row, Mapping):
        raise ClaimRefused("CLAIM_INVALID", "a verification applies to a claim object")
    current = str(row.get("confidence") or "").strip().upper()
    if current not in CONFIDENCE:
        raise ClaimRefused("CLAIM_INVALID", "the claim has no readable confidence class")
    basis_text = _norm(basis).lower()
    if not basis_text:
        raise ClaimRefused("NO_BASIS", "a promotion needs a basis")
    if basis_text in NOT_A_BASIS:
        raise ClaimRefused("CO_OCCURRENCE_NOT_EVIDENCE",
                           f"{basis_text} is not evidence: {NOT_A_BASIS[basis_text]}")
    if basis_text not in BASES:
        raise ClaimRefused("UNKNOWN_BASIS",
                           f"{basis_text} is not a basis this model can classify")
    ceiling = BASES[basis_text]
    if CONFIDENCE[ceiling] <= CONFIDENCE[current]:
        raise ClaimRefused(
            "NOT_A_VERIFICATION",
            f"{basis_text} supports {ceiling}, which is not stronger than the claim's "
            f"{current}; promoting it would only change the label")
    new_evidence = [_norm(value) for value in (evidence_ids or []) if _norm(value)]
    old_evidence = [_norm(value) for value in (row.get("evidence_ids") or []) if _norm(value)]
    fresh = [value for value in new_evidence if value not in old_evidence]
    if not fresh:
        raise ClaimRefused(
            "NO_NEW_EVIDENCE",
            "verification needs evidence the claim did not already cite; otherwise the "
            "promotion records a belief, not an observation")
    return {
        "schema": SCHEMA,
        "id": row.get("id"),
        "from": row.get("from"),
        "relation": row.get("relation"),
        "to": row.get("to"),
        "basis": basis_text,
        "confidence": ceiling,
        "evidence_ids": [*old_evidence, *fresh],
        "verified": True,
        "promoted_from": current,
        "history": [
            {"confidence": current, "basis": row.get("basis"),
             "evidence_ids": old_evidence,
             "note": row.get("note")},
            {"confidence": ceiling, "basis": basis_text,
             "evidence_ids": [*old_evidence, *fresh], "at": _norm(at) or None},
        ],
        "statement": (f"{row.get('from')} {row.get('relation')} {row.get('to')}: "
                      f"{current} → {ceiling} on {basis_text} "
                      f"({', '.join(fresh)}); the earlier class is kept in the history"),
    }
