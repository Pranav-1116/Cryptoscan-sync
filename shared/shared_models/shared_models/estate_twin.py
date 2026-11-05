"""The CryptoScan Digital Twin (spec 94).

Design spec: ``docs/bank-environment/94-cryptoscan-digital-twin.md``.

The estate graph (spec 93) is the correlated model. This module is the *twin* on
top of it: the parts of spec 94 that turn a graph into something you can
investigate, size, and simulate.

Seven layers, and the rule each one keeps:

* **Estate placement** — where an asset belongs. An asset with no environment or
  location is reported as ``UNPLACED``; it is never attached to the estate root to
  make the tree look complete.
* **Assets** — canonical, stable ids (``estate_graph``).
* **Relationships** — every edge carries a basis and evidence; anything else is
  ``UNKNOWN`` (``estate_graph``).
* **Crypto** — capability, configuration, negotiation and observation kept apart
  (``estate_graph.crypto_artifacts``).
* **Evidence** — ``why()`` answers with the collector, source, timestamp and hash
  behind a fact, and refuses to answer for an edge that does not exist.
* **Time** — ``snapshot()`` is content-addressed by the projection id, so two
  snapshots are comparable exactly when nothing about the evidence changed.
* **Simulation** — ``simulate()`` runs on a *copy*: it rebuilds a graph from a
  snapshot payload and re-projects the six BOMs. It reports the live projection id
  before and after so "the production twin was not touched" is a checked fact, not
  a promise.

Two refusals worth stating out loud, because they are what make the twin
trustworthy:

* ``completeness()`` measures **how well the estate is described**, not how good
  its cryptography is. A twin at 100% completeness may be entirely classical.
* ``impact()`` / ``simulate()`` return ``NO_MATCH`` rather than an empty impact
  list when a scenario matched nothing — "nothing was affected" and "we could not
  find the thing you asked about" are different answers, and only one of them is
  usually true.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from shared_models.estate_graph import (
    ASSET_TYPES,
    BOM_KINDS,
    EVIDENCE_TYPES,
    PLACEMENT_LABELS,
    POLICY_VERSION,
    EstateGraph,
    build_graph,
)
from shared_models.quantum_classify import is_shor_vulnerable

TWIN_SCHEMA = "cryptoscan.estate-twin/1"
SNAPSHOT_SCHEMA = "cryptoscan.estate-twin-snapshot/1"
COMPLETENESS_SCHEMA = "cryptoscan.estate-twin-completeness/1"
INVESTIGATION_SCHEMA = "cryptoscan.estate-twin-asset/1"
WHY_SCHEMA = "cryptoscan.estate-twin-why/1"
SEARCH_SCHEMA = "cryptoscan.estate-twin-search/1"
IMPACT_SCHEMA = "cryptoscan.estate-twin-impact/1"
SIMULATION_SCHEMA = "cryptoscan.estate-twin-simulation/1"
#: what a scenario *would* touch, before it is run against a copy
SIMULATION_PREVIEW_SCHEMA = "cryptoscan.estate-twin-simulation-preview/1"

#: §4 layer 1 — the placement levels the twin understands. The organisation chart
#: sits above the infrastructure: a bank is a set of legal entities, each of which
#: owns departments, each of which runs systems in regions and data centres. Every
#: level is derived from an *asserted* attribute and never inferred from the one
#: below it (see _attribute).
ESTATE_LEVELS: tuple[str, ...] = (
    "BANK",
    "ORGANIZATION",
    "DEPARTMENT",
    "REGION",
    "DATA_CENTER",
    "CLOUD_ENVIRONMENT",
    "ENVIRONMENT",
    "BUSINESS_SYSTEM",
)

#: §15 — what a simulation is allowed to change
#: Scenarios that change an evidence fact on a copy of the twin. Each one answers a
#: different question about the *contents* of the estate, and each needs the inputs
#: listed in :data:`SCENARIO_INPUTS`.
#:
#: ``CUSTOM`` is the operator-authored one: seven built-in kinds answer the seven
#: questions the product anticipated, and the eighth lets a bank ask its own without
#: waiting for a release. It is an *expression over one evidence record's facts* — see
#: :data:`CUSTOM_OPERATORS` — not a scripting language, and it cannot forge provenance
#: (see :data:`CUSTOM_PROTECTED_FIELDS`).
SCENARIO_KINDS: tuple[str, ...] = (
    "REPLACE_ALGORITHM",
    "RETIRE_ALGORITHM",
    "DISABLE_PROTOCOL",
    "UPGRADE_COMPONENT",
    "REMOVE_COMPONENT",
    "CHANGE_KEY_SIZE",
    "MIGRATE_QUANTUM_VULNERABLE",
    "CUSTOM",
)

#: Scenarios that model a *failure* travelling through the topology. They change no
#: evidence at all — which is why they have no BOM diff — and answer "what is reached".
CASCADE_KINDS: tuple[str, ...] = (
    "CASCADE_ASSET_UNAVAILABLE",
    "CASCADE_CRYPTO_COMPROMISE",
    "CASCADE_ALGORITHM_BREAK",
    # trust-path compromise: only the *vouching* edges carry it (issued_by, signed_by,
    # verified_by), so a CA compromise reaches what that CA vouches for and nothing
    # that merely runs on the same host. The difference from CRYPTO_COMPROMISE is the
    # carrier set, not the seed.
    "CASCADE_TRUST_COMPROMISE",
)

#: ``COMPOSITE`` is not a fourth family: it is a bounded *sequence* of the scenarios
#: above, applied to one copy in order. A bank whose migration is "retire TLS 1.0, then
#: replace RSA on what is left, then resize the surviving keys" should not have to run
#: three simulations and reconcile three BOM diffs by hand — but a general scripting
#: language is exactly what this engine must not become, because "run these commands"
#: is not an answer and a simulation that executes arbitrary code cannot be audited.
#: So the grammar is the closed set of primitive kinds, the order is explicit, and the
#: step count is capped.
COMPOSITE_KIND = "COMPOSITE"
MAX_COMPOSITE_STEPS = 5
COMPOSITE_STEP_KINDS: tuple[str, ...] = SCENARIO_KINDS

#: A ``COMPOSITE`` step may name a stored twin snapshot with ``as_of``. The step then
#: *matches* against the evidence as that snapshot recorded it — the facts the operator
#: wrote the step against — and the change is applied to the single working copy of the
#: estate as it stands now. That is the difference between a migration plan and a
#: fiction: a plan reviewed in Q2 is evaluated against Q2's evidence, but a run today
#: edits today's records, and a record that has since been retired is counted
#: (``not_in_current_estate``) rather than resurrected into the copy. There is still no
#: clock: ``as_of`` names a *stored snapshot*, and an id that names no stored snapshot is
#: refused, because "the estate looked like this then" is a claim only a captured
#: snapshot can support.
COMPOSITE_AS_OF_FIELD = "as_of"
MAX_AS_OF_LENGTH = 120

SIMULATION_KINDS: tuple[str, ...] = SCENARIO_KINDS + CASCADE_KINDS + (COMPOSITE_KIND,)

# -- a protocol floor, which is a question and not a scenario ----------------- #
#
# "If we only accepted TLS 1.2 from Friday, what is already below it?" is not a
# what-if on a copy and it is not a cascade: it edits nothing, and its answer is read
# off the handshakes the estate has already observed. It is a *check*, so it has no
# kind in ``SIMULATION_KINDS`` and no place in the run store.
#
# The half it can answer is the actionable one: which endpoints negotiated a protocol
# below the floor. The half it cannot answer is a client's acceptance — a client that
# only speaks TLS 1.0 is not an asset, and the twin never sees one. That distinction is
# an output (``blind_spots``), not a footnote in a document.
PROTOCOL_FLOOR_SCHEMA = "cryptoscan.estate-twin-protocol-floor/1"

#: The version ladder this build can rank. A protocol string outside it is reported as
#: UNRECOGNISED — never as compliant, because "I do not know this value" and "this value
#: is fine" are different findings.
PROTOCOL_FLOOR_RANKS: dict[str, int] = {
    "SSLV2": 0,
    "SSLV3": 1,
    "TLSV1.0": 2,
    "TLSV1.1": 3,
    "TLSV1.2": 4,
    "TLSV1.3": 5,
}

PROTOCOL_FLOOR_CHOICES: tuple[str, ...] = (
    "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3",
)

#: §12 — strongest evidence first. Used to answer "how well is this described".
STRENGTH_ORDER: tuple[str, ...] = (
    "RUNTIME_OBSERVED",
    "AUDIT_OBSERVED",
    "NETWORK_ACTIVE_OBSERVED",
    "CERTIFICATE_OBSERVED",
    "NETWORK_PASSIVE_OBSERVED",
    "STATIC_OBSERVED",
    "CONFIGURED",
    "IMPORTED",
    "VENDOR_DECLARED",
    "INFERRED",
    "UNKNOWN",
)

MAX_LISTED = 50

#: BOM projections are stable when these change nothing; used by the simulator
#: to tell a real projection difference from a re-render.
_VOLATILE_COMPONENT_KEYS = frozenset({"generated_at"})


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _percent(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(100.0 * numerator / denominator, 1)


def _strength(evidence_types: Iterable[str]) -> str:
    seen = {str(item) for item in evidence_types}
    for level in STRENGTH_ORDER:
        if level in seen:
            return level
    return "UNKNOWN"


def _record_hash(record: Mapping[str, Any]) -> str:
    """Content hash of one observation, so a "why" answer can be checked later.

    The evidence id is already content-addressed; this is the same idea stated in
    the auditor's terms — hash the fact, the source and the time, so a re-read
    either reproduces the hash or proves the record moved.
    """
    return "sha256:" + _canonical(
        {
            "evidence_type": record.get("evidence_type"),
            "target": record.get("target"),
            "layer": record.get("layer"),
            "source": record.get("source"),
            "collector": record.get("collector"),
            "observed_at": record.get("observed_at"),
            "facts": record.get("facts") or {},
        }
    )


def _is_site(value: Any) -> bool:
    """Is this a place an asset runs, or just where a file was found?

    ``/srv/app/Crypto.java`` and ``s3://bucket/key`` are provenance; ``UAE DC1``
    and ``aws:eu-west-1`` are placement. The twin refuses to promote the first
    kind into the second.
    """
    text = _text(value)
    if not text:
        return False
    if text.startswith("/") or "\\" in text or text.startswith("./") or text.startswith("~"):
        return False
    if "://" in text:
        return False
    return True


def _asset_card(asset: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": asset["asset_id"],
        "type": asset["type"],
        "name": asset["name"],
        "environment": asset.get("environment"),
        "owner": asset.get("owner"),
        "location": asset.get("location"),
        "status": asset.get("status") or asset.get("attributes", {}).get("status"),
        "identity": asset.get("identity") or {},
    }


def _matches_selector(facts: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
    """Does one evidence fact set match the selector?

    Every stated field must match; an unstated field never excludes. A selector
    that does not constrain anything is rejected by the caller, because "match
    everything" is how an impact report becomes a wall of numbers.
    """
    for field in ("algorithm", "protocol", "mode", "key_size", "curve", "version", "name"):
        wanted = selector.get(field)
        if wanted in (None, ""):
            continue
        value = facts.get(field)
        if value in (None, ""):
            return False
        if field == "key_size":
            if str(value).strip() != str(wanted).strip():
                return False
            continue
        if str(wanted).strip().lower() not in str(value).strip().lower():
            return False
    return True


def _selector_is_meaningful(selector: Mapping[str, Any]) -> bool:
    return any(
        selector.get(field) not in (None, "")
        for field in ("algorithm", "protocol", "mode", "key_size", "curve", "version", "name", "asset")
    )


def _resolve(graph: EstateGraph, ref: Any) -> str | None:
    """Resolve an asset_id, an exact name, or a unique name fragment (§24)."""
    text = _text(ref)
    if not text:
        return None
    if graph.asset(text) is not None:
        return text
    lowered = text.lower()
    for asset in graph.assets():
        if str(asset.get("name") or "").lower() == lowered:
            return asset["asset_id"]
    candidates = [
        asset["asset_id"]
        for asset in graph.assets()
        if lowered in str(asset.get("name") or "").lower()
    ]
    return candidates[0] if len(candidates) == 1 else None


def _adjacency(graph: EstateGraph) -> dict[str, list[dict[str, Any]]]:
    """Undirected view over *established* edges only.

    A refused edge is not in the topology. Traversing through an ``UNKNOWN``
    relationship would let the blast radius inherit an assumption.
    """
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.relationships():
        adjacency.setdefault(edge["subject"], []).append(edge)
        adjacency.setdefault(edge["object"], []).append(edge)
    return adjacency


def _walk(
    graph: EstateGraph,
    seeds: Iterable[str],
    *,
    depth: int,
) -> tuple[dict[str, int], dict[str, str]]:
    """Breadth-first over established edges. Returns distance and parent maps."""
    adjacency = _adjacency(graph)
    distance: dict[str, int] = {}
    parent: dict[str, str] = {}
    frontier = [seed for seed in seeds if seed]
    for seed in frontier:
        distance[seed] = 0
    current = 0
    while frontier and current < depth:
        nxt: list[str] = []
        for node in frontier:
            for edge in adjacency.get(node, []):
                other = edge["object"] if edge["subject"] == node else edge["subject"]
                if other in distance:
                    continue
                distance[other] = current + 1
                parent[other] = node
                nxt.append(other)
        frontier = nxt
        current += 1
    return distance, parent


def _path_to(parent: Mapping[str, str], node: str, graph: EstateGraph) -> list[dict[str, Any]]:
    """Rebuild one hop-by-hop path, so an impact number can be read as a route."""
    hops: list[str] = [node]
    current = node
    while current in parent:
        current = parent[current]
        hops.append(current)
    hops.reverse()
    path: list[dict[str, Any]] = []
    for index, asset_id in enumerate(hops):
        asset = graph.asset(asset_id) or {}
        path.append(
            {
                "asset_id": asset_id,
                "name": asset.get("name"),
                "type": asset.get("type"),
                "via": None if index == 0 else path_edge(graph, hops[index - 1], asset_id),
            }
        )
    return path


def path_edge(graph: EstateGraph, source: str, target: str) -> dict[str, Any] | None:
    for edge in graph.relationships():
        if {edge["subject"], edge["object"]} == {source, target}:
            return {
                "predicate": edge["predicate"],
                "basis": edge.get("basis"),
                "confidence": edge.get("confidence"),
                "evidence_ids": edge.get("evidence_ids"),
            }
    return None


# --------------------------------------------------------------------------- #
# layer 6 — snapshots
# --------------------------------------------------------------------------- #


def snapshot(graph: EstateGraph, *, scope: str | None = None) -> dict[str, Any]:
    """A content-addressed twin snapshot (§14, §19).

    The id is the projection id, so two snapshots are comparable exactly when the
    evidence behind them is identical. ``created_at`` is bookkeeping and is
    deliberately *not* part of the id — otherwise every re-read would be a new
    snapshot and every diff would be full.
    """
    payload = {
        "estate": graph.estate,
        "scope": scope or graph.scope,
        "assets": [
            {
                "type": asset["type"],
                "name": asset["name"],
                "identity": asset.get("identity") or {},
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "location": asset.get("location"),
                "source": asset.get("source"),
                "attributes": asset.get("attributes") or {},
            }
            for asset in graph.assets()
        ],
        "evidence": [dict(record) for record in graph.evidence()],
        "relationships": [
            {
                "subject": edge["subject"],
                "predicate": edge["predicate"],
                "object": edge["object"],
                "basis": edge.get("basis"),
                "evidence_ids": list(edge.get("evidence_ids") or []),
                "confidence": edge.get("confidence"),
                "attributes": edge.get("attributes") or {},
            }
            for edge in graph.relationships()
        ],
        "collectors": [
            {
                "plane": collector.get("plane"),
                "status": collector.get("status"),
                "expected": collector.get("expected"),
                "collected": collector.get("collected"),
                "reason": collector.get("reason"),
                "impact": collector.get("impact"),
            }
            for collector in graph.coverage().get("collectors") or []
        ],
        "coverage": [dict(row) for row in graph.coverage_rows()],
    }
    projection_id = graph.fingerprint()
    return {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": f"twin:{projection_id}",
        "projection_id": projection_id,
        "created_at": _now(),
        "estate": graph.estate,
        "scope": payload["scope"],
        "counts": {
            "assets": len(payload["assets"]),
            "evidence": len(payload["evidence"]),
            "relationships": len(payload["relationships"]),
            "collectors": len(payload["collectors"]),
            "coverage_rows": len(payload["coverage"]),
        },
        # §19: what read this evidence, and — separately — which build of each collector
        # produced it. The previous version listed collector NAMES here, which made a
        # collector upgrade invisible: the estate changed nothing and the list changed
        # nothing either. A name without a version cannot be reproduced, so both are kept,
        # and an unknown version says so rather than being dropped
        "collector_versions": sorted(
            {
                f"{record.get('collector')}@{record['collector_version']}"
                if record.get("collector_version")
                else str(record.get("collector"))
                for record in payload["evidence"]
                if record.get("collector")
            }
        ),
        "policy_version": POLICY_VERSION,
        "payload": payload,
        "note": (
            "the snapshot id is the projection id: two snapshots are comparable when the evidence "
            "behind them is identical, and created_at is bookkeeping rather than identity"
        ),
    }


def graph_from_snapshot(snapshot_doc: Mapping[str, Any]) -> EstateGraph:
    """Rebuild a graph from a snapshot — the only way a simulation gets a graph."""
    payload = snapshot_doc.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("snapshot has no payload — a twin snapshot must carry its evidence")
    return build_graph(payload)


# --------------------------------------------------------------------------- #
# layer 1 — estate placement
# --------------------------------------------------------------------------- #


#: §4 — the attribute keys a collector may use to assert each level. Only these
#: count: a level is present when evidence says so, never because a string looked
#: like a region name.
_PLACEMENT_KEYS: dict[str, tuple[str, ...]] = {
    "ORGANIZATION": ("organization", "organisation", "org", "legal_entity", "group"),
    "DEPARTMENT": ("department", "dept", "business_unit", "cost_center"),
    "REGION": ("region", "cloud_region", "aws_region", "azure_region", "gcp_region"),
    "DATA_CENTER": ("data_center", "datacenter", "dc", "site", "facility"),
    "CLOUD_ENVIRONMENT": ("cloud_account", "account_id", "subscription_id", "project_id"),
}
_CLOUD_PROVIDER_KEYS = ("provider", "cloud_provider", "cloud")


def _attribute(asset: Mapping[str, Any], keys: Sequence[str]) -> str:
    """The first asserted value for one placement level, from attributes only.

    ``food for thought``: ``location`` is deliberately not consulted for region or data
    centre. ``UAE DC1`` is a site we already place under its environment; deriving a
    *region* from it would be inventing a level the evidence never asserted.
    """
    attributes = {str(key).lower(): value for key, value in (asset.get("attributes") or {}).items()}
    for key in keys:
        value = _text(attributes.get(key))
        if value:
            return value
    return ""


def _placement_hierarchy(graph: EstateGraph) -> dict[str, Any]:
    """§4 — the levels above the environment, only where evidence puts something.

    Returns the five upper levels (the organisation chart, then the infrastructure
    placement), plus an explicit account of what nothing asserts.
    An asset that no evidence places at a level is counted under ``unassigned`` with
    the reason, so "we do not know the region" is visible rather than rendered as a
    blank that a reader fills in mentally.
    """
    total = len(graph.assets())
    regions: dict[str, dict[str, Any]] = {}
    data_centers: dict[str, dict[str, Any]] = {}
    clouds: dict[str, dict[str, Any]] = {}
    organizations: dict[str, dict[str, Any]] = {}
    departments: dict[str, dict[str, Any]] = {}
    assigned = {
        "ORGANIZATION": 0,
        "DEPARTMENT": 0,
        "REGION": 0,
        "DATA_CENTER": 0,
        "CLOUD_ENVIRONMENT": 0,
    }

    for asset in graph.assets():
        organization = _attribute(asset, _PLACEMENT_KEYS["ORGANIZATION"])
        department = _attribute(asset, _PLACEMENT_KEYS["DEPARTMENT"])
        region = _attribute(asset, _PLACEMENT_KEYS["REGION"])
        data_center = _attribute(asset, _PLACEMENT_KEYS["DATA_CENTER"])
        account = _attribute(asset, _PLACEMENT_KEYS["CLOUD_ENVIRONMENT"])
        provider = _attribute(asset, _CLOUD_PROVIDER_KEYS).upper()
        owner = _text(asset.get("owner"))

        # a data centre whose value is a file path is provenance, not a site
        if data_center and not _is_site(data_center):
            data_center = ""

        # The organisation chart is only as real as the attribute that asserts it:
        # no asset with a department is placed in an invented parent organisation.
        if organization:
            assigned["ORGANIZATION"] += 1
            bucket = organizations.setdefault(
                organization,
                {"name": organization, "assets": 0, "by_type": {}, "departments": {}, "environments": {}},
            )
            bucket["assets"] += 1
            bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
            environment = _text(asset.get("environment")) or "UNSPECIFIED_ENVIRONMENT"
            bucket["environments"][environment] = bucket["environments"].get(environment, 0) + 1
            if department:
                bucket["departments"][department] = bucket["departments"].get(department, 0) + 1
        if department:
            assigned["DEPARTMENT"] += 1
            bucket = departments.setdefault(
                department,
                {
                    "name": department,
                    "organization": organization or None,
                    "assets": 0,
                    "by_type": {},
                    "owners": {},
                    "environments": {},
                },
            )
            bucket["assets"] += 1
            bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
            environment = _text(asset.get("environment")) or "UNSPECIFIED_ENVIRONMENT"
            bucket["environments"][environment] = bucket["environments"].get(environment, 0) + 1
            if owner:
                bucket["owners"][owner] = bucket["owners"].get(owner, 0) + 1

        if region:
            assigned["REGION"] += 1
            bucket = regions.setdefault(region, {"name": region, "assets": 0, "environments": {}, "by_type": {}})
            bucket["assets"] += 1
            bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
            environment = _text(asset.get("environment")) or "UNSPECIFIED_ENVIRONMENT"
            bucket["environments"][environment] = bucket["environments"].get(environment, 0) + 1
        if data_center:
            assigned["DATA_CENTER"] += 1
            bucket = data_centers.setdefault(
                data_center, {"name": data_center, "assets": 0, "regions": {}, "environments": {}}
            )
            bucket["assets"] += 1
            if region:
                bucket["regions"][region] = bucket["regions"].get(region, 0) + 1
            environment = _text(asset.get("environment")) or "UNSPECIFIED_ENVIRONMENT"
            bucket["environments"][environment] = bucket["environments"].get(environment, 0) + 1
        if provider or account:
            assigned["CLOUD_ENVIRONMENT"] += 1
            key = f"{provider or 'UNKNOWN_PROVIDER'}{':' + account if account else ''}"
            bucket = clouds.setdefault(
                key,
                {"name": key, "provider": provider or None, "account": account or None,
                 "assets": 0, "regions": {}, "by_type": {}},
            )
            bucket["assets"] += 1
            bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
            if region:
                bucket["regions"][region] = bucket["regions"].get(region, 0) + 1

    unassigned = [
        {
            "level": level,
            "assets": total - assigned[level],
            "reason": {
                "REGION": (
                    "no evidence asserts a region for these assets. A region is never derived from a "
                    "'location' string: 'UAE DC1' is a site, and reading a cloud region out of it would "
                    "be inventing the level the bank is trying to inventory"
                ),
                "DATA_CENTER": (
                    "no evidence asserts a data centre or facility for these assets. A file path in "
                    "'location' is provenance, not a building"
                ),
                "CLOUD_ENVIRONMENT": (
                    "no evidence asserts a cloud provider or account for these assets. On-premise "
                    "assets are not 'unassigned cloud' and are not counted as one"
                ),
                "ORGANIZATION": (
                    "no evidence names the legal entity or group that owns these assets. The bank "
                    "itself is not read downward into its subsidiaries: an asset whose owner is a "
                    "team is not thereby owned by one entity rather than another"
                ),
                "DEPARTMENT": (
                    "no evidence asserts a department or business unit for these assets. An owner "
                    "name is a person or team, not a cost centre, and is not promoted into one"
                ),
            }[level],
        }
        for level in ("ORGANIZATION", "DEPARTMENT", "REGION", "DATA_CENTER", "CLOUD_ENVIRONMENT")
        if total - assigned[level] > 0
    ]

    observed = [level for level in ESTATE_LEVELS if level in {"BANK", "ENVIRONMENT", "BUSINESS_SYSTEM"}]
    for level, present in (
        ("ORGANIZATION", organizations),
        ("DEPARTMENT", departments),
        ("REGION", regions),
        ("DATA_CENTER", data_centers),
        ("CLOUD_ENVIRONMENT", clouds),
    ):
        if present:
            observed.append(level)
    ordered = [level for level in ESTATE_LEVELS if level in set(observed)]

    return {
        "organizations": [
            {
                "name": bucket["name"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "departments": [
                    {"name": name, "assets": count}
                    for name, count in sorted(bucket["departments"].items())
                ],
                "environments": [
                    {"name": name, "assets": count}
                    for name, count in sorted(bucket["environments"].items())
                ],
            }
            for _, bucket in sorted(organizations.items())
        ],
        "departments": [
            {
                "name": bucket["name"],
                "organization": bucket["organization"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "owners": [
                    {"name": name, "assets": count}
                    for name, count in sorted(bucket["owners"].items())
                ],
                "environments": [
                    {"name": name, "assets": count}
                    for name, count in sorted(bucket["environments"].items())
                ],
            }
            for _, bucket in sorted(departments.items())
        ],
        "regions": [
            {
                "name": bucket["name"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "environments": [
                    {"name": name, "assets": count}
                    for name, count in sorted(bucket["environments"].items())
                ],
            }
            for _, bucket in sorted(regions.items())
        ],
        "data_centers": [
            {
                "name": bucket["name"],
                "assets": bucket["assets"],
                "regions": [{"name": name, "assets": count}
                            for name, count in sorted(bucket["regions"].items())],
                "environments": [{"name": name, "assets": count}
                                 for name, count in sorted(bucket["environments"].items())],
            }
            for _, bucket in sorted(data_centers.items())
        ],
        "cloud_environments": [
            {
                "name": bucket["name"],
                "provider": bucket["provider"],
                "account": bucket["account"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "regions": [{"name": name, "assets": count}
                            for name, count in sorted(bucket["regions"].items())],
            }
            for _, bucket in sorted(clouds.items())
        ],
        "unassigned": unassigned,
        "levels_observed": ordered,
        "levels_unobserved": [level for level in ESTATE_LEVELS if level not in set(ordered)],
    }


def placement_model(graph: EstateGraph) -> dict[str, Any]:
    """§4 — where everything belongs, with the unplaced called out.

    The twin refuses to invent a hierarchy: an asset with neither an environment
    nor a location lands in ``unplaced`` with a reason, because "we do not know
    where this runs" is a finding in its own right.
    """
    bank = graph.estate or "UNNAMED_ESTATE"
    environments: dict[str, dict[str, Any]] = {}
    unplaced: list[dict[str, Any]] = []
    systems: dict[str, list[dict[str, Any]]] = {}

    for asset in graph.assets():
        environment = _text(asset.get("environment"))
        location = _text(asset.get("location"))
        if not environment:
            # A file path in `location` is provenance, not a site: a static-scan hit
            # says where the code lives, not which data centre runs it. Calling that
            # "placement" would put an asset in a building it has never been in.
            reason = (
                "no environment in any evidence"
                if location and not _is_site(location)
                else "no environment and no site location in any evidence"
            )
            unplaced.append({**_asset_card(asset), "reason": reason})
            continue
        if location and not _is_site(location):
            location = ""
        key = environment or "UNSPECIFIED_ENVIRONMENT"
        bucket = environments.setdefault(
            key,
            {
                "name": key,
                "assets": 0,
                "by_type": {},
                "locations": {},
                "business_systems": [],
            },
        )
        bucket["assets"] += 1
        bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
        location_key = location or "UNSPECIFIED_LOCATION"
        bucket["locations"].setdefault(location_key, 0)
        bucket["locations"][location_key] += 1
        if asset["type"] in {"SYSTEM"}:
            bucket["business_systems"].append(asset.get("name"))
            systems.setdefault(key, []).append(asset.get("name"))

    tree = []
    for name in sorted(environments):
        bucket = environments[name]
        tree.append(
            {
                "name": bucket["name"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "business_systems": sorted(item for item in bucket["business_systems"] if item),
                "locations": [
                    {"name": location, "assets": count}
                    for location, count in sorted(bucket["locations"].items())
                ],
            }
        )

    hierarchy = _placement_hierarchy(graph)

    return {
        "schema": TWIN_SCHEMA,
        "model": "cryptoscan.estate-placement/3",
        "levels": list(ESTATE_LEVELS),
        "organizations": hierarchy["organizations"],
        "departments": hierarchy["departments"],
        "levels_observed": hierarchy["levels_observed"],
        "levels_unobserved": hierarchy["levels_unobserved"],
        "bank": bank,
        "estate": bank,
        "environments": tree,
        "regions": hierarchy["regions"],
        "data_centers": hierarchy["data_centers"],
        "cloud_environments": hierarchy["cloud_environments"],
        "unassigned": hierarchy["unassigned"],
        "business_systems": sorted({name for names in systems.values() for name in names if name}),
        "unplaced": unplaced[:MAX_LISTED],
        "unplaced_count": len(unplaced),
        "placeable": len(graph.assets()) - len(unplaced),
        "note": (
            "placement is derived from evidence, never assumed: an asset without an environment or "
            "location is UNPLACED rather than attached to the estate root, and a level nothing asserts "
            "is listed as unobserved instead of being filled in with a guess"
        ),
    }


# --------------------------------------------------------------------------- #
# §29 — twin completeness (description quality, not crypto posture)
# --------------------------------------------------------------------------- #


def _dimension(
    name: str,
    numerator: int,
    denominator: int,
    *,
    meaning: str,
    state: str | None = None,
) -> dict[str, Any]:
    percent = _percent(numerator, denominator)
    if state is None:
        state = "MEASURED" if percent is not None else "NOT_OBSERVED"
    return {
        "dimension": name,
        "numerator": numerator,
        "denominator": denominator,
        "percent": percent,
        "state": state,
        "meaning": meaning,
    }


def completeness(graph: EstateGraph) -> dict[str, Any]:
    """§29 — how completely the twin describes the estate.

    This is a **description** score. It says nothing about whether the crypto it
    describes is any good, and it is never called readiness. The unmeasured
    dimensions are listed rather than counted as 0% (which would look like a
    failure) or as 100% (which would look like a pass).
    """
    assets = graph.assets()
    evidence = graph.evidence()
    edges = graph.relationships()
    coverage = graph.coverage()

    described = {str(record["target"]) for record in evidence}
    asset_ids = {asset["asset_id"] for asset in assets}
    with_evidence = [edge for edge in edges if edge.get("evidence_ids")]

    dimensions: list[dict[str, Any]] = [
        _dimension(
            "ASSET_EVIDENCE",
            len(described & asset_ids),
            len(assets),
            meaning="assets with at least one evidence record behind them",
        ),
        _dimension(
            "RELATIONSHIP_EVIDENCE",
            len(with_evidence),
            len(edges),
            meaning="edges that carry the evidence they were established on",
        ),
    ]

    summary = coverage["summary"]
    rows = coverage.get("targets") or []
    attempted_planes = [
        row for row in rows if str(row.get("status") or "") not in {"NOT_ATTEMPTED", "UNKNOWN"}
    ]
    dimensions.append(
        _dimension(
            "PLANE_COVERAGE",
            len(attempted_planes),
            len(rows),
            meaning=(
                "collector planes that ran at all versus expected. 100% target coverage inside one "
                "plane still leaves every other plane of this estate NOT_OBSERVED"
            ),
            state="MEASURED" if rows else "NOT_OBSERVED",
        )
    )
    dimensions.append(
        _dimension(
            "TARGET_COVERAGE",
            int(summary.get("collected") or 0),
            int(summary.get("expected") or 0),
            meaning="collector targets actually attempted versus expected",
            state=str(summary.get("coverage_state") or "NOT_OBSERVED"),
        )
    )

    visibility: list[dict[str, Any]] = []
    for row in coverage.get("targets") or []:
        entry = _dimension(
            str(row.get("target") or "UNKNOWN"),
            int(row.get("collected") or 0),
            int(row.get("expected") or 0),
            meaning=f"visibility into {row.get('target')}",
            state=str(row.get("status") or "UNKNOWN"),
        )
        entry["reason"] = row.get("reason")
        visibility.append(entry)

    measured = [item for item in dimensions + visibility if item["percent"] is not None]
    unmeasured = [
        {"dimension": item["dimension"], "state": item["state"], "reason": item.get("reason")}
        for item in dimensions + visibility
        if item["percent"] is None
    ]
    overall = round(sum(item["percent"] for item in measured) / len(measured), 1) if measured else None
    weakest = min(measured, key=lambda item: item["percent"]) if measured else None

    unknown = graph.unknown_inventory()
    conflicts = graph.conflicts()
    why_not_100: list[dict[str, Any]] = []
    if unknown["assets_without_evidence"]:
        why_not_100.append(
            {
                "reason": "assets with no evidence at all",
                "count": len(unknown["assets_without_evidence"]),
                "next_action": "run an approved collector against these targets, or declare them out of scope",
            }
        )
    if unknown["failed_collectors"]:
        why_not_100.append(
            {
                "reason": "collectors that failed — their estate is NOT_OBSERVED, not empty",
                "count": len(unknown["failed_collectors"]),
                "next_action": "restore collector access, then re-run; the plane stays UNKNOWN until then",
            }
        )
    if unknown["unresolved_relationships"]:
        why_not_100.append(
            {
                "reason": "relationships without a basis or evidence",
                "count": len(unknown["unresolved_relationships"]),
                "next_action": "supply the configuration/PKCS#11/runtime observation that would establish the edge",
            }
        )
    if conflicts:
        why_not_100.append(
            {
                "reason": "conflicting observations of the same fact",
                "count": len(conflicts),
                "next_action": "find out which source is describing which artefact — do not pick a winner",
            }
        )
    if unknown["capability_only"]:
        why_not_100.append(
            {
                "reason": "crypto artefacts known only as capability or configuration",
                "count": unknown["capability_only"],
                "next_action": "observe them at runtime or on the wire before calling them 'in use'",
            }
        )
    for row in visibility:
        if row["state"] in {"FAILED", "NOT_ATTEMPTED", "PARTIAL", "NOT_OBSERVED"}:
            why_not_100.append(
                {
                    "reason": f"{row['dimension']} is {row['state']}",
                    "count": row["denominator"] - row["numerator"] if row["denominator"] else 0,
                    "next_action": row.get("reason") or f"restore visibility into {row['dimension']}",
                }
            )

    return {
        "schema": COMPLETENESS_SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "dimensions": dimensions,
        "visibility": visibility,
        "measured": len(measured),
        "unmeasured": unmeasured,
        "overall_percent": overall,
        "overall_state": "MEASURED" if overall is not None else "NOT_OBSERVED",
        "overall_label": "twin completeness",
        "weakest_dimension": (
            {
                "dimension": weakest["dimension"],
                "percent": weakest["percent"],
                "reason": weakest.get("reason") or weakest["meaning"],
            }
            if weakest
            else None
        ),
        "overall_note": (
            "an average hides its worst term: read weakest_dimension before quoting overall_percent"
            if weakest
            else "no dimension was measurable, so there is no overall figure to quote"
        ),
        "is_posture_score": False,
        "meaning": (
            "this measures how completely the twin describes the estate. It is not crypto readiness: "
            "a fully described estate can be entirely classical, and a twin cannot be more complete "
            "than its collectors"
        ),
        "why_not_100": why_not_100[:MAX_LISTED],
    }


# --------------------------------------------------------------------------- #
# §25 — asset investigation
# --------------------------------------------------------------------------- #


def investigate(graph: EstateGraph, ref: Any, *, depth: int = 3) -> dict[str, Any] | None:
    """One asset, everything the twin knows, and the strength of each part."""
    asset_id = _resolve(graph, ref)
    if asset_id is None:
        return None
    asset = graph.asset(asset_id)
    if asset is None:
        return None

    records = [record for record in graph.evidence() if str(record["target"]) == asset_id]
    by_type: dict[str, int] = {}
    for record in records:
        key = str(record["evidence_type"])
        by_type[key] = by_type.get(key, 0) + 1

    artifacts = [item for item in graph.crypto_artifacts() if item["asset_id"] == asset_id]
    outgoing = [edge for edge in graph.relationships() if edge["subject"] == asset_id]
    incoming = [edge for edge in graph.relationships() if edge["object"] == asset_id]

    def _edges(items: Sequence[Mapping[str, Any]], *, inbound: bool) -> list[dict[str, Any]]:
        out = []
        for edge in items:
            other_id = edge["subject"] if inbound else edge["object"]
            other = graph.asset(other_id) or {}
            out.append(
                {
                    "predicate": edge["predicate"],
                    "direction": "in" if inbound else "out",
                    "asset_id": other_id,
                    "name": other.get("name"),
                    "type": other.get("type"),
                    "basis": edge.get("basis"),
                    "confidence": edge.get("confidence"),
                    "evidence_ids": edge.get("evidence_ids") or [],
                }
            )
        return out

    dependencies = [item for item in _edges(outgoing, inbound=False) if item["predicate"] in
                    {"depends_on", "uses", "runs_on", "hosted_on", "connects_to", "backs_with"}]

    distance, parent = _walk(graph, [asset_id], depth=depth)
    reached = [node for node in distance if node != asset_id]

    return {
        "schema": INVESTIGATION_SCHEMA,
        "model": "cryptoscan.estate-asset-view/1",
        "projection_id": graph.fingerprint(),
        "estate": graph.estate,
        "asset": _asset_card(asset),
        "attributes": asset.get("attributes") or {},
        "placement": {
            "environment": asset.get("environment"),
            "location": asset.get("location"),
            "owner": asset.get("owner"),
            "placed": bool(asset.get("environment") or asset.get("location")),
        },
        "crypto": {
            "artifacts": artifacts,
            "by_usage_state": {
                state: sum(1 for item in artifacts if item["usage_state"] == state)
                for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
            },
            "observed": [item for item in artifacts if item["usage_state"] == "OBSERVED"],
            "capability_only": [item for item in artifacts if item["usage_state"] in {"SUPPORTED", "CONFIGURED"}],
            "note": "capability is not use: SUPPORTED/CONFIGURED artefacts are not evidence of operation",
        },
        "relationships": {
            "outgoing": _edges(outgoing, inbound=False),
            "incoming": _edges(incoming, inbound=True),
            "dependencies": dependencies,
            "count": len(outgoing) + len(incoming),
        },
        "evidence": {
            "count": len(records),
            "by_type": by_type,
            "strongest": _strength(by_type),
            "records": [
                {**record, "hash": _record_hash(record)}
                for record in sorted(records, key=lambda item: str(item.get("observed_at") or ""))
            ],
        },
        "unknown": {
            "unresolved_relationships": [
                edge
                for edge in graph.unresolved_relationships()
                if asset_id in {edge.get("subject"), edge.get("object")}
            ],
            "conflicts": [item for item in graph.conflicts() if item.get("asset_id") == asset_id],
            "no_evidence": not records,
        },
        "neighbourhood": {
            "depth": depth,
            "reached": len(reached),
            "assets": [
                {
                    "asset_id": node,
                    "name": (graph.asset(node) or {}).get("name"),
                    "type": (graph.asset(node) or {}).get("type"),
                    "hops": distance[node],
                }
                for node in sorted(reached, key=lambda node: (distance[node], node))[:MAX_LISTED]
            ],
            "truncated": len(reached) > MAX_LISTED,
        },
    }


# --------------------------------------------------------------------------- #
# §28 — "why is this relationship present?"
# --------------------------------------------------------------------------- #


def why(
    graph: EstateGraph,
    *,
    subject: Any = None,
    predicate: str | None = None,
    obj: Any = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Answer with provenance — or refuse, naming what is missing.

    An edge that was refused is the more interesting answer: the twin explains
    *why* it is not a relationship rather than drawing it anyway.
    """
    if evidence_id:
        for record in graph.evidence():
            if str(record["evidence_id"]) == str(evidence_id):
                return {
                    "schema": WHY_SCHEMA,
                    "status": "EVIDENCE",
                    "evidence": record,
                    "collector": record.get("collector"),
                    "source": record.get("source"),
                    "observed_at": record.get("observed_at"),
                    "evidence_type": record.get("evidence_type"),
                    "confidence": record.get("confidence"),
                    "hash": _record_hash(record),
                }
        return {"schema": WHY_SCHEMA, "status": "NO_SUCH_EVIDENCE", "evidence_id": evidence_id}

    source = _resolve(graph, subject) if subject is not None else None
    target = _resolve(graph, obj) if obj is not None else None
    verb = _text(predicate).lower() or None

    if subject is not None and source is None:
        return {
            "schema": WHY_SCHEMA,
            "status": "UNKNOWN_ASSET",
            "detail": f"no asset matches {subject!r}; nothing can be established about it",
        }

    matches = [
        edge
        for edge in graph.relationships()
        if (source is None or edge["subject"] == source)
        and (target is None or edge["object"] == target)
        and (verb is None or edge["predicate"] == verb)
    ]

    if not matches:
        refused = [
            edge
            for edge in graph.unresolved_relationships()
            if (source is None or edge.get("subject") == source)
            and (target is None or edge.get("object") == target)
            and (verb is None or edge.get("predicate") == verb)
        ]
        if refused:
            return {
                "schema": WHY_SCHEMA,
                "status": "NOT_ESTABLISHED",
                "answer": (
                    "this relationship does not exist in the twin. It was refused, and the reason is "
                    "the answer to 'why'"
                ),
                "refused": refused[:MAX_LISTED],
                "note": "an UNKNOWN edge is not a weak relationship — it is the absence of one",
            }
        return {
            "schema": WHY_SCHEMA,
            "status": "NO_SUCH_RELATIONSHIP",
            "subject": source,
            "predicate": verb,
            "object": target,
            "answer": "no such relationship is recorded; the twin does not draw edges it cannot evidence",
        }

    explanations = []
    for edge in matches[:MAX_LISTED]:
        evidence = [record for record in graph.evidence() if str(record["evidence_id"]) in set(edge["evidence_ids"])]
        explanations.append(
            {
                "edge": {
                    "subject": edge["subject"],
                    "subject_name": (graph.asset(edge["subject"]) or {}).get("name"),
                    "predicate": edge["predicate"],
                    "object": edge["object"],
                    "object_name": (graph.asset(edge["object"]) or {}).get("name"),
                    "basis": edge.get("basis"),
                    "confidence": edge.get("confidence"),
                },
                "answer": (
                    f"{edge['predicate'].replace('_', ' ')} is established by {edge.get('basis')} evidence "
                    f"at {edge.get('confidence')} confidence"
                ),
                "evidence": [
                    {
                        "evidence_id": record["evidence_id"],
                        "evidence_type": record["evidence_type"],
                        "collector": record.get("collector"),
                        "source": record.get("source"),
                        "observed_at": record.get("observed_at"),
                        "confidence": record.get("confidence"),
                        "hash": _record_hash(record),
                        "facts": record.get("facts"),
                    }
                    for record in evidence
                ],
            }
        )

    return {
        "schema": WHY_SCHEMA,
        "status": "ESTABLISHED",
        "matches": explanations,
        "note": "every edge in the twin answers 'why' with a collector, a source, a timestamp and a hash",
    }


# --------------------------------------------------------------------------- #
# §26 — search
# --------------------------------------------------------------------------- #


def search(graph: EstateGraph, query: str, *, limit: int = MAX_LISTED) -> dict[str, Any]:
    """Search the twin by algorithm, key size, protocol, name, type or owner."""
    text = _text(query)
    if not text:
        return {
            "schema": SEARCH_SCHEMA,
            "query": text,
            "status": "EMPTY_QUERY",
            "assets": [],
            "artifacts": [],
            "by_asset_type": {},
            "counts": {"assets": 0, "artifacts": 0},
        }
    needle = text.lower()

    def _hit(*values: Any) -> bool:
        return any(needle in str(value).lower() for value in values if value not in (None, ""))

    matched_artifacts = [
        item
        for item in graph.crypto_artifacts()
        if _hit(item.get("algorithm"), item.get("protocol"), item.get("mode"), item.get("curve"), item.get("key_size"))
    ]
    artifact_assets = {item["asset_id"] for item in matched_artifacts}

    matched_assets = [
        asset
        for asset in graph.assets()
        if _hit(asset.get("name"), asset.get("type"), asset.get("environment"), asset.get("owner"))
        or asset["asset_id"] in artifact_assets
    ]

    by_type: dict[str, int] = {}
    for asset in matched_assets:
        by_type[asset["type"]] = by_type.get(asset["type"], 0) + 1

    by_artifact_type: dict[str, int] = {}
    for item in matched_artifacts:
        key = str(item.get("asset_type") or "UNKNOWN")
        by_artifact_type[key] = by_artifact_type.get(key, 0) + 1

    return {
        "schema": SEARCH_SCHEMA,
        "query": text,
        "status": "MATCHED" if matched_assets or matched_artifacts else "NO_MATCH",
        "assets": [ _asset_card(asset) for asset in matched_assets[:limit] ],
        "artifacts": matched_artifacts[:limit],
        "by_asset_type": by_type,
        "by_artifact_asset_type": by_artifact_type,
        "by_usage_state": {
            state: sum(1 for item in matched_artifacts if item["usage_state"] == state)
            for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
        },
        "counts": {"assets": len(matched_assets), "artifacts": len(matched_artifacts)},
        "truncated": len(matched_assets) > limit or len(matched_artifacts) > limit,
        "note": (
            "a match on a capability artefact is a match on what the estate *supports*; only "
            "OBSERVED/NEGOTIATED matches describe cryptography that ran"
        ),
    }


# --------------------------------------------------------------------------- #
# §27 — blast radius
# --------------------------------------------------------------------------- #


def _protocol_key(value: Any) -> str | None:
    """Normalise a protocol string to a ladder key, or ``None`` when there is no version.

    ``TLSv1.2``, ``TLS 1.2``, ``TLS1.2``, ``tlsv1_2`` and ``TLSV1.2`` all name the same
    ladder rung — collectors spell it five ways and refusing four of them would report a
    spelling as a protocol gap. ``TLS`` on its own carries no version, so it is not a rung.
    """
    text = _text(value).upper().replace(" ", "").replace("_", ".").replace("/", "")
    if not text:
        return None
    if text.startswith("TLSV"):
        return text
    if text.startswith("TLS") and len(text) > 3:
        return f"TLSV{text[3:]}"
    if text.startswith("SSLV"):
        return text
    if text in ("TLS", "SSL"):
        # a protocol named without a version is not a rung on the ladder
        return None
    return text


def protocol_floor(graph: EstateGraph, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """§7/§9 — if the accepted protocol floor were X, what is already below it?

    Reads the handshakes the estate has *observed* and ranks each against the requested
    floor. It edits nothing, so it is not a simulation: there is no copy, no BOM diff and
    no ``live_state_modified`` flag to check — the graph is only ever read.

    Three groups are kept apart, because collapsing any two of them would be a lie:

    * **below the floor** — an endpoint that negotiated something weaker than the floor.
      This is the finding the question was asked for;
    * **unrecognised** — a protocol value this build cannot rank. Reported as
      UNRECOGNISED, never as compliant: "I do not know this value" is not "this is fine";
    * **no negotiated evidence** — assets with no handshake evidence at all. Counted as a
      collection gap, never as above the floor.

    What it cannot answer is stated in ``blind_spots``: a client that only speaks an older
    protocol is not an asset, so client acceptance, fallback behaviour and enforcement are
    not in this answer.
    """
    floor_raw = _text(scenario.get("floor"))
    floor_key = _protocol_key(floor_raw)
    if not floor_raw:
        return {
            "schema": PROTOCOL_FLOOR_SCHEMA,
            "status": "INVALID_SCENARIO",
            "detail": (
                "a floor check needs a 'floor' — the weakest protocol that would be accepted, "
                f"one of {', '.join(PROTOCOL_FLOOR_CHOICES)}"
            ),
            "choices": list(PROTOCOL_FLOOR_CHOICES),
        }
    if floor_key not in PROTOCOL_FLOOR_RANKS:
        return {
            "schema": PROTOCOL_FLOOR_SCHEMA,
            "status": "INVALID_SCENARIO",
            "detail": (
                f"{floor_raw!r} is not a protocol version this build can rank, so nothing can be "
                f"compared to it. Known: {', '.join(PROTOCOL_FLOOR_CHOICES)}"
            ),
            "choices": list(PROTOCOL_FLOOR_CHOICES),
        }

    floor_rank = PROTOCOL_FLOOR_RANKS[floor_key]
    payload = snapshot(graph)["payload"]

    requested = [ref for ref in scenario.get("targets") or [] if _text(ref)]
    target_refs = {_resolve(graph, ref) for ref in requested} - {None}
    unresolved_targets = [str(ref) for ref in requested if _resolve(graph, ref) is None]

    below: list[dict[str, Any]] = []
    at: list[dict[str, Any]] = []
    above: list[dict[str, Any]] = []
    unrecognised: list[dict[str, Any]] = []
    measured_assets: set[str] = set()

    for record in payload["evidence"]:
        target = str(record.get("target"))
        if target_refs and target not in target_refs:
            continue
        facts = record.get("facts") or {}
        if "protocol" not in facts:
            # a fact set without a protocol says nothing about the floor. Library versions,
            # key sizes and certificates are other questions.
            continue
        measured_assets.add(target)
        negotiated = facts.get("protocol")
        asset = graph.asset(target) or {}
        entry = {
            "asset_id": target,
            "asset_name": asset.get("name"),
            "asset_type": asset.get("type"),
            "evidence_id": record.get("evidence_id"),
            "evidence_type": record.get("evidence_type"),
            "collector": record.get("collector"),
            "observed_at": record.get("observed_at"),
            "negotiated": negotiated,
        }
        rank = PROTOCOL_FLOOR_RANKS.get(_protocol_key(negotiated) or "")
        if rank is None:
            entry["position"] = "UNRECOGNISED"
            unrecognised.append(entry)
        elif rank < floor_rank:
            entry["position"] = "BELOW_FLOOR"
            below.append(entry)
        elif rank == floor_rank:
            entry["position"] = "AT_FLOOR"
            at.append(entry)
        else:
            entry["position"] = "ABOVE_FLOOR"
            above.append(entry)

    all_assets = {
        str(item.get("asset_id")) for item in graph.assets() if item.get("asset_id")
    }
    if target_refs:
        all_assets &= target_refs
    without_evidence = sorted(all_assets - measured_assets)

    if not measured_assets and not unrecognised:
        status = "INSUFFICIENT_EVIDENCE"
    elif below:
        status = "BELOW_FLOOR_PRESENT"
    else:
        status = "AT_OR_ABOVE_FLOOR"

    records_seen = len(below) + len(at) + len(above) + len(unrecognised)
    below_assets = {entry["asset_id"] for entry in below}
    counting = (
        f"{len(below)} of {records_seen} observed handshake record(s) negotiated a protocol below "
        f"{floor_raw} — {len(below_assets)} asset(s), {len(at)} record(s) at the floor and "
        f"{len(above)} above it"
        if records_seen
        else "no evidence record in this estate carries a negotiated protocol"
    )
    return {
        "schema": PROTOCOL_FLOOR_SCHEMA,
        "status": status,
        "floor": floor_raw,
        "floor_rank": floor_rank,
        "projection_id": graph.fingerprint(),
        "counts": {
            "below_floor": len(below),
            "at_floor": len(at),
            "above_floor": len(above),
            "unrecognised": len(unrecognised),
            "protocol_records": records_seen,
            "assets_below_floor": len(below_assets),
            "assets_with_negotiated_evidence": len(measured_assets),
            "assets_without_negotiated_evidence": len(without_evidence),
            "assets_in_scope": len(all_assets),
        },
        "below_floor": below[:MAX_LISTED],
        "at_floor": at[:MAX_LISTED],
        "unrecognised": unrecognised[:MAX_LISTED],
        "above_floor": above[:MAX_LISTED],
        "without_negotiated_evidence": without_evidence[:MAX_LISTED],
        "unresolved_targets": unresolved_targets,
        "live_state_modified": False,
        "note": (
            f"{counting}. This is a check over handshakes the estate has already observed, "
            "not a forecast: nothing is edited and no copy is made"
        ),
        "blind_spots": [
            "client acceptance: a client that only offers an older protocol is not an asset, so "
            "which clients would fail after the floor moves is not in this answer",
            "enforcement: whether a policy floor is actually applied at the endpoint, the load "
            "balancer and the load balancer's back end is configuration the twin does not read",
            "an asset with no negotiated protocol evidence is counted, not assumed compliant",
        ],
        "limits": [
            "the ranking is a version ladder only — a downgrade inside one version (a weaker "
            "cipher, a shorter key, a missing extended master secret) is a different question",
            "one record per handshake: the same endpoint measured twice appears twice, which is "
            "deliberate — two observations that disagree are a conflict, not a vote",
        ],
    }


def impact(
    graph: EstateGraph,
    selector: Mapping[str, Any],
    *,
    depth: int = 3,
) -> dict[str, Any]:
    """Blast radius for an algorithm, protocol, component or asset.

    The traversal uses established edges only, and every report carries its
    unknowns: refused edges touching the reachable set, reachable assets with no
    evidence, and conflicts. A blast radius without its blind spots is a guess
    with a number attached.
    """
    selector = dict(selector or {})
    if not _selector_is_meaningful(selector):
        return {
            "schema": IMPACT_SCHEMA,
            "status": "EMPTY_SELECTOR",
            "detail": "a blast radius needs something to select: an algorithm, protocol, key size, version or asset",
        }

    asset_ref = selector.get("asset")
    seed_assets: set[str] = set()
    matching_artifacts: list[dict[str, Any]] = []

    if asset_ref:
        resolved = _resolve(graph, asset_ref)
        if resolved:
            seed_assets.add(resolved)
    else:
        matching_artifacts = [
            item for item in graph.crypto_artifacts() if _matches_selector(item, selector)
        ]
        seed_assets.update(item["asset_id"] for item in matching_artifacts)

    if not seed_assets:
        return {
            "schema": IMPACT_SCHEMA,
            "status": "NO_MATCH",
            "selector": selector,
            "seed_assets": [],
            "by_type": {},
            "direct": [],
            "transitive": [],
            "detail": (
                "nothing in the twin matches this selector. That is NOT 'no impact' — the estate may "
                "not have been collected, or the algorithm may only exist in sources that were not read"
            ),
            "coverage": graph.coverage()["summary"],
        }

    distance, parent = _walk(graph, seed_assets, depth=depth)
    reached = sorted(distance, key=lambda node: (distance[node], node))
    transitive = [node for node in reached if distance[node] > 0]
    direct = [node for node in reached if distance[node] == 1]

    def _cards(nodes: Iterable[str]) -> list[dict[str, Any]]:
        out = []
        for node in nodes:
            asset = graph.asset(node) or {}
            out.append({**_asset_card(asset), "hops": distance[node]})
        return out

    by_type: dict[str, int] = {}
    for node in reached:
        asset = graph.asset(node) or {}
        key = str(asset.get("type") or "UNKNOWN")
        by_type[key] = by_type.get(key, 0) + 1

    reachable_set = set(reached)
    reachable_artifacts = [
        item for item in graph.crypto_artifacts() if item["asset_id"] in reachable_set
    ]
    unknown_edges = [
        edge
        for edge in graph.unresolved_relationships()
        if {edge.get("subject"), edge.get("object")} & reachable_set
    ]
    no_evidence = [
        node for node in reached if not (graph.asset(node) or {}).get("evidence_refs")
    ]
    conflicts = [item for item in graph.conflicts() if item.get("asset_id") in reachable_set]

    paths = []
    for node in transitive[:10]:
        paths.append({"asset_id": node, "path": _path_to(parent, node, graph)})

    return {
        "schema": IMPACT_SCHEMA,
        "status": "MATCHED",
        "selector": selector,
        "projection_id": graph.fingerprint(),
        "seed_assets": _cards(sorted(seed_assets)),
        "matching_artifacts": matching_artifacts[:MAX_LISTED],
        "matching_artifacts_count": len(matching_artifacts),
        "depth": depth,
        "counts": {
            "seed": len(seed_assets),
            "direct": len(direct),
            "transitive": len(transitive),
            "total": len(reached),
            "business_systems": by_type.get("SYSTEM", 0),
        },
        # the full reachable set, untruncated: a caller comparing this against a graph
        # store's own answer needs every id, and a truncated list would make a store look
        # wrong (or right) for reasons that have nothing to do with the store
        "reachable_ids": reached,
        "seed_ids": sorted(seed_assets),
        "by_type": by_type,
        "direct": _cards(direct)[:MAX_LISTED],
        "transitive": _cards(transitive)[:MAX_LISTED],
        "truncated": len(transitive) > MAX_LISTED,
        "paths": paths,
        "crypto_in_radius": {
            "artifacts": len(reachable_artifacts),
            "by_usage_state": {
                state: sum(1 for item in reachable_artifacts if item["usage_state"] == state)
                for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
            },
        },
        "blockers": [
            {
                "kind": "UNRESOLVED_RELATIONSHIP",
                "detail": "an edge in this radius is UNKNOWN, so the radius may be larger than shown",
                "subject": edge.get("subject"),
                "predicate": edge.get("predicate"),
                "object": edge.get("object"),
                "reason": edge.get("reason"),
            }
            for edge in unknown_edges[:MAX_LISTED]
        ],
        "unknown": {
            "assets_without_evidence": no_evidence[:MAX_LISTED],
            "assets_without_evidence_count": len(no_evidence),
            "unresolved_relationships": len(unknown_edges),
            "conflicts": conflicts,
        },
        "note": (
            "the radius travels established edges only; refused edges and unevidenced assets are listed "
            "as blind spots instead of being assumed away"
        ),
    }


# --------------------------------------------------------------------------- #
# layer 7 — simulation (§15–§17)
# --------------------------------------------------------------------------- #


def _bom_diff(base: Mapping[str, Any], simulated: Mapping[str, Any]) -> dict[str, Any]:
    def _index(bom: Mapping[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for component in bom.get("components") or []:
            ref = str(component.get("bom_ref") or component.get("asset_id") or component.get("name"))
            body = {key: value for key, value in component.items() if key not in _VOLATILE_COMPONENT_KEYS}
            out[ref] = _canonical(body)
        return out

    per_bom: dict[str, Any] = {}
    for kind in BOM_KINDS:
        before = _index(base.get(kind) or {})
        after = _index(simulated.get(kind) or {})
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(ref for ref in set(before) & set(after) if before[ref] != after[ref])
        per_bom[kind] = {
            "added": added[:MAX_LISTED],
            "removed": removed[:MAX_LISTED],
            "changed": changed[:MAX_LISTED],
            "counts": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
                "unchanged": len(set(before) & set(after)) - len(changed),
            },
        }
    return {
        "boms": per_bom,
        "any_change": any(
            entry["counts"]["added"] or entry["counts"]["removed"] or entry["counts"]["changed"]
            for entry in per_bom.values()
        ),
    }


def _capability_blockers(
    graph: EstateGraph,
    affected: Iterable[str],
    *,
    target: str | None,
) -> list[dict[str, Any]]:
    """Asserts a blocker only where the twin actually holds capability evidence."""
    if not target:
        return []
    wanted = target.strip().upper()
    blockers: list[dict[str, Any]] = []
    for asset_id in affected:
        for record in graph.evidence():
            if str(record["target"]) != asset_id:
                continue
            facts = record.get("facts") or {}
            declared = facts.get("supported_algorithms") or facts.get("capabilities")
            if not declared:
                continue
            if isinstance(declared, str):
                declared = [declared]
            supported = [str(item).upper() for item in declared]
            if any(wanted in item or item in wanted for item in supported):
                continue
            blockers.append(
                {
                    "kind": "CAPABILITY_NOT_EVIDENCED",
                    "asset_id": asset_id,
                    "asset_name": (graph.asset(asset_id) or {}).get("name"),
                    "detail": (
                        f"{record.get('source')} declares {', '.join(supported) or 'no algorithms'}; "
                        f"nothing in the evidence supports {target} here"
                    ),
                    "evidence_id": record.get("evidence_id"),
                }
            )
    return blockers


#: §15 — what a scenario changes, once per evidence record. One implementation serves both
#: "what would this touch" (a preview) and "apply it to a copy" (the simulation), so a
#: preview can never disagree with the run it is previewing.
# --------------------------------------------------------------------------- #
# layer 7 — CUSTOM: an operator-authored expression over one evidence record
# --------------------------------------------------------------------------- #
#
# The seven built-in kinds answer the seven questions the product anticipated. A bank
# always has an eighth, and the honest choices are to make it wait for a release or to
# let it say what it means in a form the engine can refuse.
#
# The form is deliberately small. It is a condition tree over **one evidence record's
# facts** plus a list of assignments:
#
#     {"when": {"all": [{"fact": "algorithm", "op": "eq", "value": "RSA"},
#                       {"fact": "usage_state", "op": "ne", "value": "SUPPORTED"}]},
#      "then": {"set": {"algorithm": "ML-DSA-65", "key_size": 3300}}}
#
# What it refuses, and why each refusal is the feature:
#
# * **provenance** — ``evidence_id``, ``source``, ``collector``, ``observed_at`` and the
#   evidence type are not writable. A simulation may change what the estate *says*; it
#   may not change who said it.
# * **arithmetic, functions, joins** — no expression can compute a new value from
#   another asset, another record or the clock. A scenario that did would answer with a
#   number no collector ever produced.
# * **unbounded size** — eight conditions, eight assignments, depth three. A scenario
#   larger than that is a program, and this is not a place to run one.

CUSTOM_SCHEMA = "cryptoscan.twin-custom-scenario/1"

#: the whole operator vocabulary. A condition is ``{"fact", "op", "value"}``.
CUSTOM_OPERATORS: dict[str, str] = {
    "eq": "the fact equals the value exactly",
    "ne": "the fact does not equal the value",
    "in": "the fact is one of a listed value",
    "contains": "the fact (a string or list) contains the value",
    "present": "the fact exists and is not empty",
    "absent": "the fact is missing or empty",
}

#: combinators: ``{"all": [...]}``, ``{"any": [...]}``, ``{"not": {...}}``
CUSTOM_COMBINATORS: tuple[str, ...] = ("all", "any", "not")

#: fact keys a scenario may never write. Provenance is not a value a simulation authors,
#: and a raised evidence class is the one edit that would make a fabricated fact look
#: better sourced than the record it came from.
CUSTOM_PROTECTED_FIELDS: frozenset[str] = frozenset({
    "evidence_id", "record_id", "source", "collector", "collector_version",
    "evidence_type", "observed_at", "hash", "layer", "target", "asset_id",
})

MAX_CUSTOM_CONDITIONS = 8
MAX_CUSTOM_ASSIGNMENTS = 8
MAX_CUSTOM_DEPTH = 3

_ABSENT = object()


def _composite_refusal(steps: Any) -> dict[str, Any] | None:
    """Why this sequence cannot be run — structurally, without looking at the estate.

    Three refusals, each for a reason a reviewer can act on: an empty sequence asks
    nothing, a sequence longer than ``MAX_COMPOSITE_STEPS`` is a script wearing a
    scenario's shape, and a step that is itself a cascade or a composite would make
    the result undecidable ("apply a change, then propagate a failure, then apply a
    change to the failure" has no single BOM diff to report).
    """
    if steps is None:
        return {
            "status": "INVALID_SCENARIO",
            "detail": (
                "COMPOSITE needs 'steps': a list of the primitive scenarios to apply in order, "
                f"at most {MAX_COMPOSITE_STEPS} of them"
            ),
        }
    if not isinstance(steps, list):
        return {"status": "INVALID_SCENARIO", "detail": "'steps' must be a list of scenarios"}
    if not steps:
        return {
            "status": "INVALID_SCENARIO",
            "detail": "a composite with no steps asks nothing; use the scenario kind directly",
        }
    if len(steps) > MAX_COMPOSITE_STEPS:
        return {
            "status": "INVALID_SCENARIO",
            "detail": (
                f"{len(steps)} steps exceeds the {MAX_COMPOSITE_STEPS}-step bound. A longer sequence "
                "is a migration plan, not a simulation: run it in stages and compare the results"
            ),
        }
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, Mapping):
            return {"status": "INVALID_SCENARIO", "detail": f"step {index} is not a scenario object"}
        step_kind = _text(step.get("kind")).upper()
        if step_kind not in COMPOSITE_STEP_KINDS:
            return {
                "status": "INVALID_SCENARIO",
                "detail": (
                    f"step {index} names {step_kind or 'no kind'}; a composite step must be one of "
                    f"{', '.join(COMPOSITE_STEP_KINDS)}. Cascades and composites do not nest"
                ),
            }
        as_of = step.get(COMPOSITE_AS_OF_FIELD)
        if as_of is not None:
            if not isinstance(as_of, str) or not _text(as_of):
                return {
                    "status": "INVALID_SCENARIO",
                    "detail": (
                        f"step {index} names an 'as_of' that is not a snapshot id. 'as_of' must be "
                        "the id of a *stored* twin snapshot — a step is not evaluated against a "
                        "date, because a date is not evidence"
                    ),
                }
            if len(_text(as_of)) > MAX_AS_OF_LENGTH:
                return {
                    "status": "INVALID_SCENARIO",
                    "detail": f"step {index} has an 'as_of' longer than {MAX_AS_OF_LENGTH} characters",
                }
        refusal = _scenario_refusal(step_kind, step)
        if refusal:
            return {
                "status": "INVALID_SCENARIO",
                "detail": f"step {index} ({step_kind}): {refusal.get('detail')}",
            }
    return None


def _composite_as_of_refusal(
    steps: list[Mapping[str, Any]], as_of_graphs: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """Which ``as_of`` step names a snapshot this build does not hold.

    Resolved before anything is applied, because a run that quietly ignored an unknown
    ``as_of`` would answer about today's evidence while the operator believed it answered
    about the snapshot they named — the most expensive way to be wrong.
    """
    available = set((as_of_graphs or {}).keys())
    missing = [
        {"step": index, "as_of": _text(step.get(COMPOSITE_AS_OF_FIELD))}
        for index, step in enumerate(steps, start=1)
        if _text(step.get(COMPOSITE_AS_OF_FIELD))
        and _text(step.get(COMPOSITE_AS_OF_FIELD)) not in available
    ]
    if not missing:
        return None
    return {
        "status": "UNKNOWN_SNAPSHOT",
        "detail": (
            "step "
            + ", ".join(f"{row['step']} (as_of {row['as_of']!r})" for row in missing)
            + " names a twin snapshot this run does not hold. That is not 'the estate looked the "
            "same then': an as-of step is evaluated against a captured snapshot, so the snapshot "
            "has to exist. Capture it with POST /estate/evidence/twin/snapshots, or drop 'as_of' "
            "to evaluate the step against the estate as it stands now"
        ),
        "unknown_as_of": missing,
    }


def _custom_refusal(expression: Any, *, depth: int = 0) -> dict[str, Any] | None:
    """Why this expression cannot be run — or ``None`` when it can.

    Structural only: it never looks at the estate. A syntactically valid expression
    that matches nothing is a ``NO_MATCH``, not an invalid scenario, and the difference
    matters — the first says "the estate does not describe this", the second says "you
    typed a program".
    """
    if not isinstance(expression, Mapping):
        return {
            "status": "INVALID_SCENARIO",
            "detail": (
                "CUSTOM needs an 'expression' object with 'when' and 'then' "
                "({'then': {'set': {...}, 'unset': [...]}}). The expression is data, "
                "never code — the engine has no evaluator beyond these operators"
            ),
        }
    unknown = sorted(set(expression) - {"when", "then", "label", "description"})
    if unknown:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"unknown expression key(s) {', '.join(unknown)}; allowed: when, then, label, description",
        }
    when = expression.get("when")
    then = expression.get("then")
    if when is None or then is None:
        return {
            "status": "INVALID_SCENARIO",
            "detail": "an expression needs both 'when' (what it matches) and 'then' (what it changes)",
        }
    if not isinstance(then, Mapping):
        return {"status": "INVALID_SCENARIO", "detail": "'then' must be an object with 'set' and/or 'unset'"}
    unknown_then = sorted(set(then) - {"set", "unset"})
    if unknown_then:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"unknown 'then' key(s) {', '.join(unknown_then)}; allowed: set, unset",
        }
    set_values = then.get("set") or {}
    unset_values = then.get("unset") or []
    if not isinstance(set_values, Mapping):
        return {"status": "INVALID_SCENARIO", "detail": "'then.set' must be an object of fact -> value"}
    if not isinstance(unset_values, (list, tuple)) or any(not isinstance(item, str) for item in unset_values):
        return {"status": "INVALID_SCENARIO", "detail": "'then.unset' must be a list of fact names"}
    if not set_values and not unset_values:
        return {"status": "INVALID_SCENARIO", "detail": "a scenario that changes nothing has no answer"}
    if len(set_values) + len(unset_values) > MAX_CUSTOM_ASSIGNMENTS:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"at most {MAX_CUSTOM_ASSIGNMENTS} assignments per scenario; this one is a program",
        }
    for field in (*set_values, *unset_values):
        if str(field) in CUSTOM_PROTECTED_FIELDS:
            return {
                "status": "REFUSED_PROVENANCE_WRITE",
                "detail": (
                    f"'{field}' records where a fact came from. A simulation may change what the "
                    "estate says, never who said it — writing provenance would make the copy's "
                    "evidence stronger or weaker than the record it was derived from"
                ),
                "field": str(field),
            }
    return _custom_condition_refusal(when, depth=depth, counter=[0])


def _custom_condition_refusal(condition: Any, *, depth: int, counter: list[int]) -> dict[str, Any] | None:
    if depth > MAX_CUSTOM_DEPTH:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"conditions nest at most {MAX_CUSTOM_DEPTH} levels; deeper is a program, not a scenario",
        }
    if not isinstance(condition, Mapping) or not condition:
        return {"status": "INVALID_SCENARIO", "detail": "a condition must be a non-empty object"}
    unknown = sorted(set(condition) - {"fact", "op", "value", *CUSTOM_COMBINATORS})
    if unknown:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"unknown condition key(s) {', '.join(unknown)}; allowed: fact, op, value, "
                      f"{', '.join(CUSTOM_COMBINATORS)}",
        }
    combinators = [name for name in CUSTOM_COMBINATORS if name in condition]
    if combinators and len(combinators) > 1:
        return {"status": "INVALID_SCENARIO", "detail": "a condition combines once: all, any or not"}
    if combinators:
        name = combinators[0]
        children = condition[name]
        if name == "not":
            children = [children]
        if not isinstance(children, (list, tuple)) or not children:
            return {"status": "INVALID_SCENARIO", "detail": f"'{name}' needs a non-empty list of conditions"}
        counter[0] += len(children)
        if counter[0] > MAX_CUSTOM_CONDITIONS:
            return {
                "status": "INVALID_SCENARIO",
                "detail": f"at most {MAX_CUSTOM_CONDITIONS} conditions; this one is a program",
            }
        for child in children:
            refusal = _custom_condition_refusal(child, depth=depth + 1, counter=counter)
            if refusal:
                return refusal
        return None
    fact = condition.get("fact")
    op = str(condition.get("op") or "eq").lower()
    if not isinstance(fact, str) or not fact.strip():
        return {"status": "INVALID_SCENARIO", "detail": "a condition needs a 'fact' name"}
    if op not in CUSTOM_OPERATORS:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"unknown operator '{op}'; allowed: {', '.join(sorted(CUSTOM_OPERATORS))}",
        }
    if op in {"eq", "ne", "in", "contains"} and "value" not in condition:
        return {"status": "INVALID_SCENARIO", "detail": f"operator '{op}' needs a 'value'"}
    if op == "in" and not isinstance(condition.get("value"), (list, tuple)):
        return {"status": "INVALID_SCENARIO", "detail": "operator 'in' needs a list value"}
    counter[0] += 1
    if counter[0] > MAX_CUSTOM_CONDITIONS:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"at most {MAX_CUSTOM_CONDITIONS} conditions; this one is a program",
        }
    return None


def _custom_matches(condition: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Evaluate one condition against one record's facts. Deterministic, no clock."""

    def _value(fact: str) -> Any:
        lowered = {str(key).lower(): value for key, value in facts.items()}
        return lowered.get(str(fact).lower(), _ABSENT)

    if "all" in condition:
        return all(_custom_matches(child, facts) for child in condition["all"])
    if "any" in condition:
        return any(_custom_matches(child, facts) for child in condition["any"])
    if "not" in condition:
        return not _custom_matches(condition["not"], facts)

    value = _value(condition["fact"])
    op = str(condition.get("op") or "eq").lower()
    wanted = condition.get("value")
    present = value is not _ABSENT and value not in (None, "", [], {}, ())
    if op == "present":
        return present
    if op == "absent":
        return not present
    if op == "eq":
        return present and str(value) == str(wanted)
    if op == "ne":
        return value is _ABSENT or str(value) != str(wanted)
    if op == "in":
        return present and any(str(value) == str(item) for item in wanted)
    if op == "contains":
        if isinstance(value, (list, tuple, set)):
            return any(str(item) == str(wanted) for item in value)
        return present and str(wanted) in str(value)
    return False


def _custom_effect(
    expression: Mapping[str, Any], facts: Mapping[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """``(matched, updates)`` for a custom expression against one record's facts.

    An assignment whose value is already there is not an effect: a scenario that
    changes nothing must not report a change, or every "before/after" in the result
    becomes noise a reviewer has to filter by hand.
    """
    if not _custom_matches(expression["when"], facts):
        return False, {}
    then = expression["then"]
    updates: dict[str, Any] = {}
    lowered = {str(key).lower(): key for key in facts}
    for field, value in (then.get("set") or {}).items():
        existing_key = lowered.get(str(field).lower(), str(field))
        if facts.get(existing_key) == value:
            continue
        updates[existing_key] = value
    for field in then.get("unset") or []:
        existing_key = lowered.get(str(field).lower(), str(field))
        if existing_key not in facts:
            continue
        updates[existing_key] = None
    return (bool(updates), updates)


def _scenario_effect(
    kind: str,
    facts: Mapping[str, Any],
    scenario: Mapping[str, Any],
    *,
    source: str,
    target: str,
) -> tuple[bool, dict[str, Any]]:
    """``(matched, updates)`` — the facts this record would carry after the scenario.

    ``updates`` is empty when nothing matched, and is never applied to the caller's
    mapping: a preview discards it, a simulation merges it into its own copy.
    """
    updates: dict[str, Any] = {}
    if kind == "REPLACE_ALGORITHM":
        hit = _matches_selector(facts, {"algorithm": source}) or _matches_selector(facts, {"protocol": source})
        if hit:
            if facts.get("algorithm"):
                updates["simulated_from_algorithm"] = facts["algorithm"]
                updates["algorithm"] = target
            if facts.get("protocol"):
                updates["simulated_from_protocol"] = facts["protocol"]
                updates["protocol"] = target
            if scenario.get("key_size"):
                updates["key_size"] = scenario["key_size"]
        return hit, updates
    if kind == "RETIRE_ALGORITHM":
        hit = _matches_selector(facts, {"algorithm": source}) or _matches_selector(facts, {"protocol": source})
        if hit:
            updates["simulated_retired"] = {
                "algorithm": facts.get("algorithm"),
                "protocol": facts.get("protocol"),
                "key_size": facts.get("key_size"),
            }
            updates["algorithm"] = None
            updates["protocol"] = None
        return hit, updates
    if kind == "DISABLE_PROTOCOL":
        hit = _matches_selector(facts, {"protocol": source})
        if hit:
            updates["simulated_disabled_protocol"] = facts["protocol"]
            updates["protocol"] = None
        return hit, updates
    if kind == "UPGRADE_COMPONENT":
        hit = False
        for field in ("version", "component", "name"):
            value = facts.get(field)
            if value and source.lower() in str(value).lower():
                updates["simulated_from_version"] = value
                updates[f"simulated_{field}"] = target or value
                if field == "version":
                    updates["version"] = target or value
                hit = True
        return hit, updates
    if kind == "REMOVE_COMPONENT":
        # the component is gone rather than replaced, and it goes as a whole: a name that
        # matched takes its version with it, because a version without a component is not
        # an artefact the estate still has
        matched = any(
            facts.get(field) and source.lower() in str(facts[field]).lower()
            for field in ("name", "component", "version")
        )
        if not matched:
            return False, updates
        # the whole component identity goes, not only the field that matched the selector,
        # and the record of what was removed keeps all of it
        removed = {field: facts[field] for field in ("name", "component", "version") if facts.get(field)}
        updates["simulated_removed_component"] = removed
        for field in removed:
            updates[field] = None
        return True, updates
    if kind == "CHANGE_KEY_SIZE":
        hit = _matches_selector(facts, {"algorithm": source}) or _matches_selector(facts, {"protocol": source})
        if hit and scenario.get("key_size"):
            updates["simulated_from_key_size"] = facts.get("key_size")
            updates["key_size"] = scenario["key_size"]
        return hit, updates
    if kind == "MIGRATE_QUANTUM_VULNERABLE":
        # the sweep an operator actually wants: every Shor-vulnerable algorithm at once,
        # chosen by the registry rather than by a list typed into a form
        algorithm = facts.get("algorithm")
        if algorithm and is_shor_vulnerable(algorithm):
            updates["simulated_from_algorithm"] = algorithm
            updates["algorithm"] = target
            if scenario.get("key_size"):
                updates["key_size"] = scenario["key_size"]
            return True, updates
        return False, updates
    return False, updates


def _scenario_refusal(kind: str, scenario: Mapping[str, Any]) -> dict[str, Any] | None:
    """The reason a scenario cannot be answered, or ``None`` when it is answerable."""
    if kind in CASCADE_KINDS:
        return _cascade_refusal(kind, scenario)
    if kind == COMPOSITE_KIND:
        return _composite_refusal(scenario.get("steps"))
    if kind not in SCENARIO_KINDS:
        return {
            "status": "INVALID_SCENARIO",
            "detail": f"expected one of {', '.join(SIMULATION_KINDS)}",
        }
    if kind == "CUSTOM":
        return _custom_refusal(scenario.get("expression"))
    for field in SCENARIO_INPUTS[kind]:
        present = bool(scenario.get("key_size")) if field == "key_size" else bool(_text(scenario.get(field)))
        if not present:
            return {"status": "INVALID_SCENARIO", "detail": _INPUT_REFUSALS[field]}
    return None


def _apply_composite(
    graph: EstateGraph,
    payload: dict[str, Any],
    steps: list[Mapping[str, Any]],
    as_of_graphs: Mapping[str, EstateGraph] | None = None,
) -> tuple[int, set[str], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Apply the steps to one copy, in order, and report each one.

    Order is the point: a step sees the facts the previous step wrote, so "retire
    TLS 1.0, then replace RSA on what is left" behaves the way an operator reads it.
    A step that matches nothing is reported as such and does not abort the sequence —
    that is a fact about the estate, not an error.

    A step that names ``as_of`` *matches* against that stored snapshot's evidence and
    applies its edit to the copy: the plan is judged on the evidence it was written
    against, the change lands on the estate that exists. A matched record the copy no
    longer holds is counted as ``not_in_current_estate`` — retired, not resurrected.
    """
    matched_total = 0
    affected: set[str] = set()
    effects: list[dict[str, Any]] = []
    report: list[dict[str, Any]] = []
    as_of_graphs = as_of_graphs or {}
    copy_by_evidence_id = {str(record.get("evidence_id")): record for record in payload["evidence"]}
    as_of_used: set[str] = set()
    from_snapshot = 0
    not_in_current = 0

    for index, step in enumerate(steps, start=1):
        step_kind = _text(step.get("kind")).upper()
        step_source = _text(step.get("from"))
        step_target = _text(step.get("to"))
        as_of_id = _text(step.get(COMPOSITE_AS_OF_FIELD)) or None
        as_of_graph = as_of_graphs.get(as_of_id) if as_of_id else None
        # the records this step is judged against: the snapshot's, or the copy's own
        considered = (
            snapshot(as_of_graph)["payload"]["evidence"] if as_of_graph is not None
            else payload["evidence"]
        )
        if as_of_id:
            as_of_used.add(as_of_id)
        refs = (
            {_resolve(as_of_graph if as_of_graph is not None else graph, ref)
             for ref in step.get("targets") or []}
            - {None}
        )
        step_matched = 0
        step_from_snapshot = 0
        step_not_current = 0
        for record in considered:
            if refs and str(record.get("target")) not in refs:
                continue
            facts = record.get("facts") or {}
            if step_kind == "CUSTOM":
                hit, updates = _custom_effect(step.get("expression"), facts)
            else:
                hit, updates = _scenario_effect(
                    step_kind, facts, step, source=step_source, target=step_target
                )
            if not hit:
                continue
            target_record = record if as_of_graph is None else copy_by_evidence_id.get(
                str(record.get("evidence_id"))
            )
            if target_record is None:
                # matched against the snapshot, absent from the estate this run applies to
                step_not_current += 1
                not_in_current += 1
                continue
            target_facts = target_record.get("facts") or {}
            before = copy.deepcopy(target_facts)
            target_facts.update(updates)
            target_record["facts"] = target_facts
            step_matched += 1
            matched_total += 1
            if as_of_graph is not None:
                step_from_snapshot += 1
                from_snapshot += 1
            affected.add(str(target_record.get("target")))
            effect = {
                "step": index,
                "step_kind": step_kind,
                "evidence_id": target_record.get("evidence_id"),
                "asset_id": target_record.get("target"),
                "asset_name": (graph.asset(str(target_record.get("target"))) or {}).get("name"),
                "layer": target_record.get("layer"),
                "evidence_type": target_record.get("evidence_type"),
                "before": before,
                "after": copy.deepcopy(target_facts),
            }
            if as_of_graph is not None:
                # the facts the *step* was judged on, when they are not the ones applied to
                effect["evaluated_against"] = as_of_id
                if facts != before:
                    effect["facts_at_as_of"] = copy.deepcopy(facts)
            effects.append(effect)
        step_report = {
            "step": index,
            "kind": step_kind,
            "matched_evidence": step_matched,
            "matched_nothing": step_matched == 0,
            "targets": list(step.get("targets") or []),
            "from": step_source or None,
            "to": step_target or None,
            "as_of": as_of_id,
        }
        if as_of_id:
            step_report.update(
                {
                    "evaluated_against_snapshot": True,
                    "evidence_in_snapshot": len(considered),
                    "matched_from_snapshot": step_from_snapshot,
                    "not_in_current_estate": step_not_current,
                }
            )
            if step_matched == 0 and step_not_current:
                step_report["matched_nothing_because"] = (
                    "every record this step matches in the snapshot has since left the estate. "
                    "The plan still describes the snapshot; it no longer describes today"
                )
        report.append(step_report)

    as_of_summary: dict[str, Any] = {
        "snapshots": sorted(as_of_used),
        "steps_with_as_of": sum(1 for step in steps if _text(step.get(COMPOSITE_AS_OF_FIELD))),
        "matched_from_snapshot": from_snapshot,
        "not_in_current_estate": not_in_current,
    }
    if as_of_used:
        as_of_summary["meaning"] = (
            "these steps were matched against the evidence their snapshot recorded and applied to "
            "the estate as it stands now; a matched record that has since left the estate is "
            "counted, never resurrected into the copy"
        )
    return matched_total, affected, effects, report, as_of_summary


def _composite_preview(
    graph: EstateGraph,
    scenario: Mapping[str, Any],
    base_projection: str,
    as_of_graphs: Mapping[str, EstateGraph] | None = None,
) -> dict[str, Any]:
    """Would each step match anything? Counted against the evidence each step reads.

    A step that names ``as_of`` is counted against that stored snapshot — the evidence
    the operator wrote the step against — and not against today's. The honest limit is
    stated in ``note``: the steps are previewed independently, because the copies that
    later steps will see do not exist until the run. A preview is a spelling check, and
    pretending otherwise would be a cheaper simulation — which is the thing this
    function is explicitly not.
    """
    payload = snapshot(graph)["payload"]
    steps = list(scenario.get("steps") or [])
    copy_by_evidence_id = {str(record.get("evidence_id")): record for record in payload["evidence"]}
    report: list[dict[str, Any]] = []
    affected: set[str] = set()
    total = 0
    as_of_used: set[str] = set()
    not_in_current = 0
    for index, step in enumerate(steps, start=1):
        step_kind = _text(step.get("kind")).upper()
        step_source = _text(step.get("from"))
        step_target = _text(step.get("to"))
        as_of_id = _text(step.get(COMPOSITE_AS_OF_FIELD)) or None
        as_of_graph = (as_of_graphs or {}).get(as_of_id) if as_of_id else None
        if as_of_id:
            as_of_used.add(as_of_id)
        considered = (
            snapshot(as_of_graph)["payload"]["evidence"] if as_of_graph is not None
            else payload["evidence"]
        )
        refs = (
            {_resolve(as_of_graph if as_of_graph is not None else graph, ref)
             for ref in step.get("targets") or []}
            - {None}
        )
        matched = 0
        step_not_current = 0
        for record in considered:
            if refs and str(record.get("target")) not in refs:
                continue
            facts = record.get("facts") or {}
            if step_kind == "CUSTOM":
                hit, _updates = _custom_effect(step.get("expression"), facts)
            else:
                hit, _updates = _scenario_effect(
                    step_kind, facts, step, source=step_source, target=step_target
                )
            if not hit:
                continue
            if as_of_graph is not None:
                current = copy_by_evidence_id.get(str(record.get("evidence_id")))
                if current is None:
                    step_not_current += 1
                    not_in_current += 1
                    continue
                affected.add(str(current.get("target")))
            else:
                affected.add(str(record.get("target")))
            matched += 1
        total += matched
        step_report = {
            "step": index,
            "kind": step_kind,
            "matched_evidence": matched,
            "matched_nothing": matched == 0,
            "targets": list(step.get("targets") or []),
            "from": step_source or None,
            "to": step_target or None,
            "as_of": as_of_id,
        }
        if as_of_id:
            step_report.update(
                {
                    "evaluated_against_snapshot": True,
                    "evidence_in_snapshot": len(considered),
                    "not_in_current_estate": step_not_current,
                }
            )
        report.append(step_report)
    empty = [row["step"] for row in report if row["matched_nothing"]]
    return {
        "schema": SIMULATION_PREVIEW_SCHEMA,
        "status": "WOULD_MATCH" if total else "WOULD_NOT_MATCH",
        "kind": COMPOSITE_KIND,
        "scenario": scenario,
        "base_projection_id": base_projection,
        "live_state_modified": False,
        "evidence_considered": len(payload["evidence"]),
        "matched_evidence": total,
        "affected_assets": [],
        "affected_asset_count": len(affected),
        "steps": report,
        "steps_matching_nothing": empty,
        **(
            {
                "as_of": {
                    "snapshots": sorted(as_of_used),
                    "steps_with_as_of": sum(
                        1 for step in steps if _text(step.get(COMPOSITE_AS_OF_FIELD))
                    ),
                    "not_in_current_estate": not_in_current,
                    "meaning": (
                        "these steps are counted against the evidence their snapshot recorded. A "
                        "matched record that has since left the estate is counted, not applied"
                    ),
                }
            }
            if as_of_used
            else {}
        ),
        "note": (
            f"{total} evidence record(s) match these {len(steps)} step(s) against the evidence each "
            "step reads — a step with 'as_of' reads its snapshot, a step without reads today's. Later "
            "steps are previewed against that same evidence, not against the copy the earlier steps "
            "produce, so a run can match more than this preview counts"
            if total
            else (
                (
                    "no step matches any evidence record read by this preview, and "
                    f"{not_in_current} record(s) matched only in a snapshot have since left the "
                    "estate. That is not 'no impact': a step with 'as_of' reads its snapshot, so a "
                    "plan can describe an estate that no longer exists — which is precisely what "
                    "the count reports"
                )
                if as_of_used
                else (
                    "no step matches any evidence record. That is not 'no impact': the estate may "
                    "not describe the artefact, or it may live in a source that was never collected"
                )
            )
        ),
        "limits": [
            "steps are previewed independently against the live evidence (or, for an 'as_of' step, "
            "against its snapshot); the run applies them in order to one copy, so a later step can "
            "match records an earlier step changed",
            "a preview counts the evidence records each step would touch; it does not project the six "
            "BOMs or compute the blast radius — those need the simulation",
        ],
    }


def preview(
    graph: EstateGraph,
    scenario: Mapping[str, Any],
    *,
    as_of_graphs: Mapping[str, EstateGraph] | None = None,
) -> dict[str, Any]:
    """What a scenario *would* touch — cheaply, without building a copy.

    The question this answers is the one that wastes an operator's time: "did I type
    the algorithm name the estate actually uses?". ``NO_MATCH`` from a full
    simulation is honest but arrives after the work; a preview says it up front and
    lists the values the estate does hold, so the fix is a pick rather than a guess.

    It reads the live graph and mutates nothing. It is not a cheaper simulation:
    it says how many records matched, not what the six BOMs would become — that
    requires applying the scenario to a copy, and the copy is what ``simulate`` does.
    """
    scenario = dict(scenario or {})
    kind = _text(scenario.get("kind")).upper()
    if kind in CASCADE_KINDS:
        return cascade_preview(graph, scenario)
    refusal = _scenario_refusal(kind, scenario)
    if not refusal and kind == COMPOSITE_KIND:
        refusal = _composite_as_of_refusal(list(scenario.get("steps") or []), as_of_graphs)
    base_projection = graph.fingerprint()
    if refusal:
        return {
            "schema": SIMULATION_PREVIEW_SCHEMA,
            "kind": kind or None,
            "scenario": scenario,
            "base_projection_id": base_projection,
            **refusal,
            "live_state_modified": False,
        }

    if kind == COMPOSITE_KIND:
        return _composite_preview(graph, scenario, base_projection, as_of_graphs)

    source = _text(scenario.get("from"))
    target = _text(scenario.get("to"))
    requested = [ref for ref in scenario.get("targets") or [] if _text(ref)]
    target_refs = {_resolve(graph, ref) for ref in requested if _resolve(graph, ref)}
    unresolved_targets = [
        str(ref) for ref in requested if _resolve(graph, ref) is None
    ]

    payload = snapshot(graph)["payload"]
    matched = 0
    affected: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    considered = 0
    # a selector naming only assets the twin does not hold narrows to nothing. Treating that
    # as "no filter" would answer about the whole estate, which is the opposite of the ask
    narrowed_to_nothing = bool(requested) and not target_refs

    def _preview_effect(facts: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
        if kind == "CUSTOM":
            return _custom_effect(scenario["expression"], facts)
        return _scenario_effect(kind, facts, scenario, source=source, target=target)

    for record in ([] if narrowed_to_nothing else payload["evidence"]):
        if target_refs and str(record.get("target")) not in target_refs:
            continue
        considered += 1
        hit, _updates = _preview_effect(record.get("facts") or {})
        if not hit:
            continue
        matched += 1
        asset_id = str(record.get("target"))
        affected[asset_id] = affected.get(asset_id, 0) + 1
        layer = str(record.get("layer") or "UNKNOWN")
        by_layer[layer] = by_layer.get(layer, 0) + 1

    status = "WOULD_MATCH" if matched else "WOULD_NOT_MATCH"
    assets = []
    for asset_id, count in sorted(affected.items(), key=lambda item: (-item[1], item[0])):
        record = graph.asset(asset_id) or {}
        assets.append(
            {
                "asset_id": asset_id,
                "name": record.get("name"),
                "type": record.get("type"),
                "evidence_matched": count,
            }
        )
    if matched:
        note = (
            f"{matched} evidence record(s) on {len(affected)} asset(s) would change; run the scenario "
            "to see what the six BOMs become and what the blast radius holds"
        )
    elif narrowed_to_nothing or (considered == 0 and requested):
        note = (
            "the scenario names targets the twin does not hold, so nothing was considered. That is "
            "not 'no impact': the assets may never have been collected"
        )
    else:
        note = (
            f"no evidence matched '{source}'. That is not 'no impact': the estate may not describe the "
            "artefact, or it may live in a source that was never collected"
        )
    return {
        "schema": SIMULATION_PREVIEW_SCHEMA,
        "status": status,
        "kind": kind,
        "scenario": scenario,
        "base_projection_id": base_projection,
        "live_state_modified": False,
        "evidence_considered": considered,
        "matched_evidence": matched,
        "affected_assets": assets[:MAX_LISTED],
        "affected_asset_count": len(affected),
        "by_layer": dict(sorted(by_layer.items())),
        "unresolved_targets": unresolved_targets,
        "coverage": graph.coverage()["summary"],
        "note": note,
        "limits": [
            "a preview counts the evidence records a scenario would touch; it does not project the six "
            "BOMs, compute the blast radius or list capability blockers — those need the simulation",
            "it reads the live graph and changes nothing; the live projection id is included so a "
            "consumer can tell which estate the answer was measured against",
            "matching is by fact fields, not by intent: an asset whose crypto is described loosely will "
            "match loosely, and an asset described nowhere will never match",
        ],
    }


def _simulation_result(
    graph: EstateGraph,
    *,
    scenario: Mapping[str, Any],
    kind: str,
    live_projection_before: str,
    base_snapshot: Mapping[str, Any],
    payload: Mapping[str, Any],
    matched: int,
    affected: set[str],
    effects: list[dict[str, Any]],
    source: str,
    target: str,
    steps_report: list[dict[str, Any]] | None = None,
    as_of: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Everything a simulation reports once the edits are on the copy.

    Shared by the single-step path and by ``COMPOSITE``, so a three-step sequence and a
    one-step scenario are measured the same way: the same BOM re-projection, the same
    live-projection assertion, the same blind spots.
    """
    extra: dict[str, Any] = {"steps": steps_report} if steps_report is not None else {}
    if as_of and as_of.get("snapshots"):
        extra["as_of"] = dict(as_of)

    if matched == 0:
        return {
            "schema": SIMULATION_SCHEMA,
            "status": "NO_MATCH",
            "kind": kind,
            "scenario": scenario,
            "base_projection_id": live_projection_before,
            "live_state_modified": False,
            "detail": (
                "no evidence matched this scenario, so nothing can be said about its impact. This is "
                "not 'no impact': the estate may not describe the artefact, or it may live in a "
                "source that was never collected"
            ),
            "coverage": graph.coverage()["summary"],
            **extra,
        }

    simulated_graph = build_graph(payload)
    simulated_snapshot = snapshot(simulated_graph)

    base_boms = graph.project_all()
    simulated_boms = simulated_graph.project_all()
    diff = _bom_diff(base_boms["boms"], simulated_boms["boms"])

    simulated_impact = impact(simulated_graph, {"asset": None, "algorithm": target or source}, depth=3) \
        if (target or source) else {"status": "NO_MATCH"}
    if simulated_impact.get("status") != "MATCHED":
        # fall back to the affected assets themselves rather than an empty radius
        distance, parent = _walk(simulated_graph, affected, depth=3)
        simulated_impact = {
            "status": "MATCHED",
            "counts": {"total": len(distance), "seed": len(affected)},
            "by_type": {
                type_name: sum(
                    1 for node in distance
                    if (simulated_graph.asset(node) or {}).get("type") == type_name
                )
                for type_name in sorted({
                    (simulated_graph.asset(node) or {}).get("type") or "UNKNOWN" for node in distance
                })
            },
            "note": "radius computed from the changed assets themselves",
        }

    # a capability blocker is worth reporting anywhere in the radius, not only on
    # the asset that changed: a library three hops away that cannot do the new
    # algorithm is exactly the thing a migration plan needs to see
    radius, _parents = _walk(graph, affected, depth=3)
    blockers = list(_capability_blockers(graph, set(affected) | set(radius), target=target or None))
    for edge in graph.unresolved_relationships():
        if {edge.get("subject"), edge.get("object")} & affected:
            blockers.append(
                {
                    "kind": "UNRESOLVED_RELATIONSHIP",
                    "detail": "a refused edge touches a changed asset, so its true radius is unknown",
                    "subject": edge.get("subject"),
                    "predicate": edge.get("predicate"),
                    "object": edge.get("object"),
                    "reason": edge.get("reason"),
                }
            )

    live_projection_after = graph.fingerprint()

    return {
        "schema": SIMULATION_SCHEMA,
        "status": "SIMULATED",
        "simulation_id": f"sim:{_canonical({'projection': live_projection_before, 'scenario': scenario})[:24]}",
        "kind": kind,
        "scenario": scenario,
        "base_snapshot": base_snapshot["snapshot_id"],
        "base_projection_id": live_projection_before,
        "simulated_projection_id": simulated_snapshot["projection_id"],
        "live_state_modified": live_projection_before != live_projection_after,
        "live_projection_unchanged": live_projection_before == live_projection_after,
        "matched_evidence": matched,
        "affected_assets": [
            {"asset_id": asset_id, "name": (graph.asset(asset_id) or {}).get("name"),
             "type": (graph.asset(asset_id) or {}).get("type")}
            for asset_id in sorted(affected)
        ],
        "effects": effects[:MAX_LISTED],
        "impact": {
            "counts": simulated_impact.get("counts"),
            "by_type": simulated_impact.get("by_type"),
        },
        "bom_diff": diff["boms"],
        "bom_changes": diff["any_change"],
        "blockers": blockers[:MAX_LISTED],
        "unknown": {
            "unresolved_relationships_touching_affected": sum(
                1 for edge in graph.unresolved_relationships()
                if {edge.get("subject"), edge.get("object")} & affected
            ),
            "affected_assets_without_evidence": sum(
                1 for asset_id in affected if not (graph.asset(asset_id) or {}).get("evidence_refs")
            ),
            "affected_assets_without_evidence_note": (
                "these assets are in the blast radius but the twin holds no evidence for them, so "
                "their role in the change is unknown rather than absent"
            ),
        },
        "note": (
            "the scenario was applied to a copy of the twin; the six BOMs are projections of that copy, "
            "and the live projection id is identical before and after"
        ),
        **extra,
    }


def simulate(
    graph: EstateGraph,
    scenario: Mapping[str, Any],
    *,
    as_of_graphs: Mapping[str, EstateGraph] | None = None,
) -> dict[str, Any]:
    """§15–§17 — ask "what if" on a copy of the twin.

    The live graph is only ever *read*. The scenario is applied to the snapshot
    payload, a new graph is built from it, and the six BOMs are re-projected from
    that graph. The live projection id is captured before and after, so
    "simulation changed nothing" is a checked assertion rather than a promise.

    ``as_of_graphs`` maps a snapshot id to the graph rebuilt from that stored
    snapshot. Only ``COMPOSITE`` steps read it, and only the steps that name an
    ``as_of``: the caller resolves the snapshots so this module never learns about the
    database, and an ``as_of`` the mapping does not hold is refused rather than
    ignored.
    """
    scenario = dict(scenario or {})
    kind = _text(scenario.get("kind")).upper()
    if kind in CASCADE_KINDS:
        return cascade(graph, scenario)
    refusal = _scenario_refusal(kind, scenario)
    if refusal:
        return {
            "schema": SIMULATION_SCHEMA,
            "kind": kind or None,
            **refusal,
        }
    if kind == COMPOSITE_KIND:
        as_of_refusal = _composite_as_of_refusal(
            list(scenario.get("steps") or []), as_of_graphs
        )
        if as_of_refusal:
            return {
                "schema": SIMULATION_SCHEMA,
                "kind": kind,
                "scenario": scenario,
                "live_state_modified": False,
                **as_of_refusal,
            }

    live_projection_before = graph.fingerprint()
    base_snapshot = snapshot(graph)
    payload = copy.deepcopy(base_snapshot["payload"])

    if kind == COMPOSITE_KIND:
        steps = list(scenario.get("steps") or [])
        matched, affected, effects, steps_report, as_of_summary = _apply_composite(
            graph, payload, steps, as_of_graphs
        )
        first = steps[0] if steps else {}
        last = steps[-1] if steps else {}
        return _simulation_result(
            graph,
            scenario=scenario,
            kind=kind,
            live_projection_before=live_projection_before,
            base_snapshot=base_snapshot,
            payload=payload,
            matched=matched,
            affected=affected,
            effects=effects,
            # the radius is anchored on the first step's selector and the last step's
            # target: "what did this migration touch" starts where the operator started
            # and ends with the algorithm everything was moved to
            source=_text(first.get("from")),
            target=_text(last.get("to")),
            steps_report=steps_report,
            as_of=as_of_summary,
        )

    source = _text(scenario.get("from"))
    target = _text(scenario.get("to"))
    target_refs = {_resolve(graph, ref) for ref in scenario.get("targets") or [] if _resolve(graph, ref)}

    matched = 0
    affected: set[str] = set()
    effects: list[dict[str, Any]] = []

    def _record_effect(facts: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
        if kind == "CUSTOM":
            return _custom_effect(scenario["expression"], facts)
        return _scenario_effect(kind, facts, scenario, source=source, target=target)

    for record in payload["evidence"]:
        facts = record.get("facts") or {}
        if target_refs and str(record.get("target")) not in target_refs:
            continue
        hit, updates = _record_effect(facts)
        if hit:
            # the "before" half has to be captured *before* the merge: facts is the same
            # dict the record holds, so a later read would show the scenario's own edit and
            # every effect would report "nothing changed"
            before = copy.deepcopy(facts)
            facts.update(updates)
            matched += 1
            affected.add(str(record.get("target")))
            effects.append(
                {
                    "evidence_id": record.get("evidence_id"),
                    "asset_id": record.get("target"),
                    "asset_name": (graph.asset(str(record.get("target"))) or {}).get("name"),
                    "layer": record.get("layer"),
                    "evidence_type": record.get("evidence_type"),
                    "before": before,
                    "after": copy.deepcopy(facts),
                }
            )




    return _simulation_result(
        graph,
        scenario=scenario,
        kind=kind,
        live_projection_before=live_projection_before,
        base_snapshot=base_snapshot,
        payload=payload,
        matched=matched,
        affected=affected,
        effects=effects,
        source=source,
        target=target,
    )



# --------------------------------------------------------------------------- #
# cascade — how far a failure travels (§15–§17)
# --------------------------------------------------------------------------- #
#
# A scenario changes a fact and asks what the BOMs become. A cascade asks a different
# question: something *stops*, and the answer is what is reached from there, wave by
# wave. It changes no evidence at all — which is why it has no BOM diff and says so
# rather than printing six empty diffs that read like "nothing changes".
#
# The propagation rules are declared, not implied: only listed predicates carry a
# failure, in a stated direction. An unlisted predicate is a place the failure does not
# travel *in this model*, and the payload lists them, because "the estate holds no such
# edge" and "the failure stops here" are different claims.

CASCADE_SCHEMA = "cryptoscan.estate-twin-cascade/1"

#: ``object_to_subject`` — the subject rests on the object (``api runs_on host``), so when
#: the object stops, the subject is impacted. ``both`` — containment read in both
#: directions: a workload of a stopped system stops with it, and a system holding a
#: stopped workload is degraded.
CASCADE_RULES: dict[str, dict[str, Any]] = {
    "CASCADE_ASSET_UNAVAILABLE": {
        "name": "Asset unavailable",
        "seeds": "targets",
        "carries": [
            ("runs_on", "object_to_subject", "a workload on a stopped host stops with it"),
            ("hosted_on", "object_to_subject", "anything placed on a stopped host stops"),
            ("depends_on", "object_to_subject", "a declared dependency on a stopped service is unmet"),
            ("connects_to", "object_to_subject", "a caller of a stopped service loses its connection"),
            ("routes_to", "object_to_subject", "traffic routed to a stopped endpoint has nowhere to go"),
            ("protected_by", "object_to_subject", "something that stopped no longer protects"),
            ("uses_hsm", "object_to_subject", "key operations on a stopped HSM fail closed"),
            ("uses_kms", "object_to_subject", "key operations on a stopped KMS fail closed"),
            ("contains", "both", "a system holding a stopped component is degraded"),
            ("part_of", "both", "the same containment, read from the other side"),
        ],
        "not_modelled": [
            "redundancy: a second node, a failover pair or a load-balancer pool is evidence the twin "
            "does not hold, so a wave says what *would be reached* — never that service stops",
            "traffic and time: a wave number is graph distance. It is not seconds, not request loss, "
            "and not an order of failure",
            "retries, queues and circuit breakers absorb a failure in ways no collector reported",
        ],
    },
    "CASCADE_CRYPTO_COMPROMISE": {
        "name": "Crypto compromise",
        "seeds": "targets",
        "carries": [
            ("signed_by", "object_to_subject", "a signature by a compromised signer is not assurance"),
            ("issued_by", "object_to_subject", "a certificate from a compromised issuer is not trust"),
            ("verified_by", "object_to_subject", "a checker that cannot be trusted verifies nothing"),
            ("uses_certificate", "object_to_subject", "a certificate that is compromised compromises its user"),
            ("uses_key", "object_to_subject", "a compromised key compromises what it protects"),
            ("uses_algorithm", "object_to_subject", "a broken algorithm breaks what relies on it"),
            ("encrypts_with", "object_to_subject", "ciphertext under compromised parameters is exposed"),
            ("signs_with", "object_to_subject", "a signature under a compromised key is repudiable"),
            ("authenticates_with", "object_to_subject", "authentication on compromised crypto is not authentication"),
            ("protected_by", "object_to_subject", "protection that is compromised protects nothing"),
            ("uses_crypto_library", "object_to_subject", "a library that is compromised compromises its callers"),
            ("uses_hsm", "object_to_subject", "key operations on a compromised HSM carry no assurance"),
            ("uses_kms", "object_to_subject", "key operations on a compromised KMS carry no assurance"),
            ("terminates_tls_for", "object_to_subject", "TLS terminated on compromised crypto carries no assurance"),
            ("depends_on", "object_to_subject", "a declared dependency inherits the assurance it rests on"),
            ("connects_to", "object_to_subject", "a connection to a compromised peer is a compromised connection"),
            ("contains", "both", "a system holding a compromised component is exposed"),
            ("part_of", "both", "the same containment, read from the other side"),
        ],
        "not_modelled": [
            "exploitability: that a compromise is *possible* is not that it happened. This models the "
            "assurance a dependency inherits, not an incident",
            "data exposure: the twin records that crypto is used, not what it protected",
            "key rotation and re-issuance: a cascade says who is reached, not how to repair it",
        ],
    },
    "CASCADE_TRUST_COMPROMISE": {
        "name": "Trust path compromised (CA / PKI)",
        "seeds": "targets",
        "carries": [
            ("issued_by", "object_to_subject", "anything issued by a compromised issuer is no longer vouched for"),
            ("signed_by", "object_to_subject", "a signature by a compromised signer is not assurance"),
            ("verified_by", "object_to_subject", "a verifier that cannot be trusted verifies nothing"),
            ("uses_certificate", "object_to_subject", "a certificate that cannot be trusted is not a credential"),
            ("terminates_tls_for", "object_to_subject", "TLS terminated on a chain that no longer holds carries no assurance"),
        ],
        "not_modelled": [
            "trust stores: a host that trusts a root the twin never collected is invisible here, so "
            "a walk that stops means the issuer edge is missing, not that trust stops",
            "cross-signing and alternate chains: a certificate with two parents is reached through "
            "the edge that was collected, not through the shortest chain",
            "revocation: CRL and OCSP publication, propagation delay and soft-fail behaviour are not "
            "in the model, and 'reached' never means 'rejected by every verifier'",
            "name constraints, pinning and policy OIDs: policy that restricts what a CA may sign is "
            "not recorded, so the radius is a superset of a correct PKI walk",
        ],
    },
    "CASCADE_ALGORITHM_BREAK": {
        "name": "Algorithm breaks everywhere",
        "seeds": "algorithm",
        "carries": [
            ("uses_algorithm", "object_to_subject", "an artefact using the broken algorithm is broken at once"),
            ("encrypts_with", "object_to_subject", "ciphertext under the broken algorithm is exposed"),
            ("signs_with", "object_to_subject", "signatures under the broken algorithm are worthless"),
            ("authenticates_with", "object_to_subject", "authentication on the broken algorithm fails"),
            ("signed_by", "object_to_subject", "anything relying on that signature is reached"),
            ("issued_by", "object_to_subject", "anything relying on that issuer is reached"),
            ("verified_by", "object_to_subject", "anything relying on that verifier is reached"),
            ("uses_certificate", "object_to_subject", "certificates carrying it are reached"),
            ("uses_key", "object_to_subject", "keys under it are reached"),
            ("uses_crypto_library", "object_to_subject", "libraries that implement it are reached"),
            ("protected_by", "object_to_subject", "protection resting on it is reached"),
            ("terminates_tls_for", "object_to_subject", "termination resting on it is reached"),
            ("depends_on", "object_to_subject", "a dependent inherits the breakage"),
            ("connects_to", "object_to_subject", "a peer connection inherits the breakage"),
            ("contains", "both", "a system holding a broken component is reached"),
            ("part_of", "both", "the same containment, read from the other side"),
        ],
        "not_modelled": [
            "harvest-now-decrypt-later: the twin cannot say whether traffic was recorded before the break",
            "hybrid and fallback negotiation: a peer may use a second algorithm, which is a configuration "
            "claim the collectors did not make",
            "amortisation: one break reaching forty assets is one event, not forty incidents",
        ],
    },
}

#: Kinds whose effect is a fact edit on a copy, and the inputs each one needs.
SCENARIO_INPUTS: dict[str, tuple[str, ...]] = {
    "REPLACE_ALGORITHM": ("from", "to"),
    "RETIRE_ALGORITHM": ("from",),
    "DISABLE_PROTOCOL": ("from",),
    "UPGRADE_COMPONENT": ("from",),
    "REMOVE_COMPONENT": ("from",),
    "CHANGE_KEY_SIZE": ("from", "key_size"),
    "MIGRATE_QUANTUM_VULNERABLE": ("to",),
    # the custom kind carries its whole query in one object, validated by _custom_refusal
    "CUSTOM": ("expression",),
}

_INPUT_REFUSALS = {
    "from": "scenario needs 'from' — a change with no before-state has no measurable effect",
    "to": "scenario needs 'to' — a replacement with no target changes nothing",
    "key_size": "scenario needs 'key_size' — a resize with no size has no measurable effect",
}


def _cascade_carriers(kind: str) -> dict[str, str]:
    """predicate -> direction, for the edges that carry this kind of failure."""
    return {predicate: direction for predicate, direction, _meaning in CASCADE_RULES[kind]["carries"]}


def _cascade_meaning(kind: str, predicate: str) -> str | None:
    for name, _direction, meaning in CASCADE_RULES[kind]["carries"]:
        if name == predicate:
            return meaning
    return None


def _cascade_seeds(
    graph: EstateGraph,
    kind: str,
    scenario: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """The assets a cascade starts from, with the reason each one is a seed."""
    seeds: list[dict[str, Any]] = []
    unresolved: list[str] = []
    seen: set[str] = set()

    if CASCADE_RULES[kind]["seeds"] == "algorithm":
        source = _text(scenario.get("from"))
        by_asset: dict[str, int] = {}
        for item in graph.crypto_artifacts():
            if not _matches_selector(item, {"algorithm": source}) and not _matches_selector(
                item, {"protocol": source}
            ):
                continue
            by_asset[item["asset_id"]] = by_asset.get(item["asset_id"], 0) + 1
        for asset_id, count in sorted(by_asset.items()):
            asset = graph.asset(asset_id) or {}
            seeds.append(
                {
                    "asset_id": asset_id,
                    "name": asset.get("name"),
                    "type": asset.get("type"),
                    "reason": f"uses {source} in {count} artefact(s)",
                }
            )
            seen.add(asset_id)
        return seeds, unresolved

    for ref in scenario.get("targets") or []:
        resolved = _resolve(graph, ref)
        if not resolved:
            unresolved.append(str(ref))
            continue
        if resolved in seen:
            continue
        asset = graph.asset(resolved) or {}
        seeds.append(
            {
                "asset_id": resolved,
                "name": asset.get("name"),
                "type": asset.get("type"),
                "reason": "named by the scenario",
            }
        )
        seen.add(resolved)
    return seeds, unresolved


def _cascade_reach(
    graph: EstateGraph,
    kind: str,
    seed_ids: Iterable[str],
    *,
    depth: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, int]]:
    """Breadth-first over the edges this kind carries. Returns waves, via-map, distances."""
    carriers = _cascade_carriers(kind)
    outgoing: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for edge in graph.relationships():
        direction = carriers.get(str(edge.get("predicate")))
        if direction is None:
            continue
        if direction in {"object_to_subject", "both"}:
            outgoing.setdefault(str(edge.get("object")), []).append((str(edge.get("subject")), edge))
        if direction in {"subject_to_object", "both"}:
            outgoing.setdefault(str(edge.get("subject")), []).append((str(edge.get("object")), edge))

    distance: dict[str, int] = {seed: 0 for seed in seed_ids if seed}
    via: dict[str, dict[str, Any]] = {}
    waves: list[dict[str, Any]] = []
    frontier = sorted(distance)
    current = 0

    while frontier and current < depth:
        reached: list[dict[str, Any]] = []
        next_frontier: list[str] = []
        for node in frontier:
            for other, edge in outgoing.get(node, []):
                if other in distance:
                    continue
                distance[other] = current + 1
                asset = graph.asset(other) or {}
                predicate = str(edge.get("predicate"))
                via[other] = {
                    "from_asset": node,
                    "from_name": (graph.asset(node) or {}).get("name"),
                    "predicate": predicate,
                    "meaning": _cascade_meaning(kind, predicate),
                    "edge": {
                        "subject": edge.get("subject"),
                        "predicate": predicate,
                        "object": edge.get("object"),
                        "basis": edge.get("basis"),
                        "confidence": edge.get("confidence"),
                        "evidence_ids": edge.get("evidence_ids"),
                    },
                }
                reached.append(
                    {
                        "asset_id": other,
                        "name": asset.get("name"),
                        "type": asset.get("type"),
                        "via": via[other],
                    }
                )
                next_frontier.append(other)
        if not reached:
            break
        reached.sort(key=lambda item: str(item.get("name") or item["asset_id"]))
        waves.append(
            {
                "depth": current + 1,
                "count": len(reached),
                "assets": reached[:MAX_LISTED],
                "truncated": max(0, len(reached) - MAX_LISTED),
            }
        )
        frontier = next_frontier
        current += 1

    return waves, via, distance


def _cascade_path(via: Mapping[str, dict[str, Any]], asset_id: str, graph: EstateGraph) -> list[dict[str, Any]]:
    """One hop-by-hop route from a seed to a reached asset, so a wave can be read as a route."""
    hops: list[dict[str, Any]] = []
    current = asset_id
    guard = 0
    while current in via and guard < 32:
        step = via[current]
        asset = graph.asset(current) or {}
        hops.append(
            {
                "asset_id": current,
                "name": asset.get("name"),
                "type": asset.get("type"),
                "via_predicate": step["predicate"],
                "via_asset": step["from_asset"],
            }
        )
        current = step["from_asset"]
        guard += 1
    seed = graph.asset(current) or {}
    hops.append(
        {"asset_id": current, "name": seed.get("name"), "type": seed.get("type"),
         "via_predicate": None, "via_asset": None}
    )
    hops.reverse()
    return hops


def _cascade_refusal(kind: str, scenario: Mapping[str, Any]) -> dict[str, Any] | None:
    rule = CASCADE_RULES[kind]
    if rule["seeds"] == "targets" and not (scenario.get("targets") or []):
        return {
            "status": "INVALID_SCENARIO",
            "detail": (
                "a cascade needs at least one seed asset in 'targets' — a failure with no starting "
                "point has nothing to propagate"
            ),
        }
    if rule["seeds"] == "algorithm" and not _text(scenario.get("from")):
        return {
            "status": "INVALID_SCENARIO",
            "detail": (
                "CASCADE_ALGORITHM_BREAK needs 'from' — the algorithm, protocol or component whose "
                "failure is being modelled"
            ),
        }
    return None


def _cascade_depth(scenario: Mapping[str, Any], *, default: int = 3) -> int:
    try:
        depth = int(scenario.get("depth") or default)
    except (TypeError, ValueError):
        depth = default
    return max(1, min(depth, 8))


def _cascade_rules_payload(kind: str) -> list[dict[str, Any]]:
    return [
        {"predicate": predicate, "direction": direction, "meaning": meaning}
        for predicate, direction, meaning in CASCADE_RULES[kind]["carries"]
    ]


def _cascade_limits(kind: str) -> list[str]:
    return [
        "a cascade propagates over established edges only: a refused relationship is not in the "
        "topology, and the blind spots are listed rather than assumed away",
        *CASCADE_RULES[kind]["not_modelled"],
        "a cascade changes no evidence fact, so it has no BOM diff and no simulated projection id — "
        "it answers which assets are reached, not what the six BOMs become",
    ]


def cascade(graph: EstateGraph, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Model a failure travelling through the estate graph.

    Nothing is copied and nothing is mutated: the answer is a traversal of the live
    topology, and the live projection id is captured before and after so the claim that
    it is a read is checked in the same way a scenario's is.
    """
    scenario = dict(scenario or {})
    kind = _text(scenario.get("kind")).upper()
    refusal = _cascade_refusal(kind, scenario)
    if refusal:
        return {"schema": CASCADE_SCHEMA, "kind": kind or None, **refusal}

    depth = _cascade_depth(scenario)
    live_projection_before = graph.fingerprint()
    seeds, unresolved_seeds = _cascade_seeds(graph, kind, scenario)

    if not seeds:
        return {
            "schema": CASCADE_SCHEMA,
            "status": "NO_MATCH",
            "kind": kind,
            "scenario": scenario,
            "base_projection_id": live_projection_before,
            "live_state_modified": False,
            "live_projection_unchanged": True,
            "seeds": [],
            "unresolved_seeds": unresolved_seeds,
            "depth": depth,
            "detail": (
                "no asset in the twin matches this cascade's starting point, so nothing can be "
                "propagated. This is not 'no impact': the asset may live in a source that was "
                "never collected"
                + (
                    f" (named: {', '.join(unresolved_seeds)})" if unresolved_seeds else ""
                )
            ),
            "coverage": graph.coverage()["summary"],
            "rules": _cascade_rules_payload(kind),
            "limits": _cascade_limits(kind),
        }

    seed_ids = [seed["asset_id"] for seed in seeds]
    waves, via, distance = _cascade_reach(graph, kind, seed_ids, depth=depth)
    reached = [node for node in distance if distance[node] > 0]

    if not reached:
        return {
            "schema": CASCADE_SCHEMA,
            "status": "NO_MATCH",
            "kind": kind,
            "scenario": scenario,
            "base_projection_id": live_projection_before,
            "live_state_modified": False,
            "live_projection_unchanged": True,
            "seeds": seeds,
            "unresolved_seeds": unresolved_seeds,
            "depth": depth,
            "detail": (
                f"{len(seeds)} seed asset(s) resolved, but no established edge carries this failure "
                f"out of them within {depth} hop(s). The estate may hold the dependency without an "
                "established edge, or may not have collected it — that is not 'nothing is affected'"
            ),
            "blind_spots": {
                "unresolved_relationships_touching_seeds": sum(
                    1
                    for edge in graph.unresolved_relationships()
                    if {edge.get("subject"), edge.get("object")} & set(seed_ids)
                ),
                "note": (
                    "a refused edge touching a seed is exactly the edge that would have carried this "
                    "failure further, so it is counted here instead of being traversed"
                ),
            },
            "coverage": graph.coverage()["summary"],
            "rules": _cascade_rules_payload(kind),
            "limits": _cascade_limits(kind),
        }

    by_type: dict[str, int] = {}
    for node in reached:
        key = str((graph.asset(node) or {}).get("type") or "UNKNOWN")
        by_type[key] = by_type.get(key, 0) + 1
    by_seed: dict[str, int] = {}
    for node in reached:
        root = node
        guard = 0
        while root in via and guard < 32:
            root = via[root]["from_asset"]
            guard += 1
        by_seed[root] = by_seed.get(root, 0) + 1

    business_systems = [
        {
            "asset_id": node,
            "name": (graph.asset(node) or {}).get("name"),
            "hops": distance[node],
            "path": _cascade_path(via, node, graph),
        }
        for node in sorted(
            (node for node in reached if (graph.asset(node) or {}).get("type") == "SYSTEM"),
            key=lambda node: (distance[node], str(node)),
        )
    ]
    seed_evidence = sum(
        len((graph.asset(node) or {}).get("evidence_refs") or []) for node in seed_ids
    )
    unresolved_touching = [
        edge
        for edge in graph.unresolved_relationships()
        if {edge.get("subject"), edge.get("object")} & set(seed_ids) | set(reached)
    ]
    without_evidence = [
        node for node in reached if not (graph.asset(node) or {}).get("evidence_refs")
    ]
    live_projection_after = graph.fingerprint()

    return {
        "schema": CASCADE_SCHEMA,
        "status": "SIMULATED",
        "simulation_id": f"sim:{_canonical({'projection': live_projection_before, 'scenario': scenario, 'engine': 'cascade'})[:24]}",
        "engine": "CASCADE",
        "kind": kind,
        "scenario": scenario,
        # the snapshot id is derived from the projection id, so no payload is built for a walk
        "base_snapshot": f"twin:{live_projection_before}",
        "base_projection_id": live_projection_before,
        # a cascade reads the topology; it does not build a second estate to compare with
        "simulated_projection_id": live_projection_before,
        "estate_copy": None,
        "live_state_modified": live_projection_before != live_projection_after,
        "live_projection_unchanged": live_projection_before == live_projection_after,
        "depth": depth,
        "seeds": seeds,
        "unresolved_seeds": unresolved_seeds,
        "waves": waves,
        "wave_count": len(waves),
        "affected_assets": [
            {
                "asset_id": node,
                "name": (graph.asset(node) or {}).get("name"),
                "type": (graph.asset(node) or {}).get("type"),
                "hops": distance[node],
                "via_predicate": (via.get(node) or {}).get("predicate"),
            }
            for node in sorted(reached, key=lambda node: (distance[node], str(node)))
        ],
        "matched_evidence": seed_evidence,
        "impact": {
            "counts": {
                "seed": len(seeds),
                "direct": sum(1 for node in reached if distance[node] == 1),
                "transitive": sum(1 for node in reached if distance[node] > 1),
                "total": len(reached),
            },
            "by_type": dict(sorted(by_type.items())),
            "by_seed": dict(sorted(by_seed.items())),
            "business_systems": business_systems,
        },
        "bom_diff": {},
        "bom_diff_note": (
            "a cascade changes no evidence fact, so the six BOMs are identical before and after. "
            "There is deliberately no diff here: six empty diffs would read as 'nothing changes'"
        ),
        "blockers": [
            {
                "kind": "UNRESOLVED_RELATIONSHIP",
                "detail": "a refused edge touches an asset in this cascade, so its true radius is unknown",
                "subject": edge.get("subject"),
                "predicate": edge.get("predicate"),
                "object": edge.get("object"),
                "reason": edge.get("reason"),
            }
            for edge in unresolved_touching
        ][:MAX_LISTED],
        "unknown": {
            "unresolved_relationships_in_radius": len(unresolved_touching),
            "reached_assets_without_evidence": len(without_evidence),
            "reached_assets_without_evidence_note": (
                "these assets are reached but the twin holds no evidence for them, so their role in "
                "the cascade is unknown rather than absent"
            ),
        },
        "coverage": graph.coverage()["summary"],
        "rules": _cascade_rules_payload(kind),
        "limits": _cascade_limits(kind),
        "note": (
            "the cascade was computed over the live topology and read it only: no copy was made, no "
            "evidence fact changed, and the live projection id is identical before and after"
        ),
    }


def cascade_preview(graph: EstateGraph, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Would this cascade reach anything? Answered before the run, from the same rules."""
    scenario = dict(scenario or {})
    kind = _text(scenario.get("kind")).upper()
    refusal = _cascade_refusal(kind, scenario)
    if refusal:
        return {"schema": SIMULATION_PREVIEW_SCHEMA, "kind": kind or None, **refusal}

    depth = _cascade_depth(scenario)
    seeds, unresolved_seeds = _cascade_seeds(graph, kind, scenario)
    if not seeds:
        return {
            "schema": SIMULATION_PREVIEW_SCHEMA,
            "status": "WOULD_NOT_MATCH",
            "kind": kind,
            "scenario": scenario,
            "base_projection_id": graph.fingerprint(),
            "live_state_modified": False,
            "seeds": [],
            "unresolved_seeds": unresolved_seeds,
            "depth": depth,
            "evidence_considered": 0,
            "matched_evidence": 0,
            "affected_assets": [],
            "affected_asset_count": 0,
            "by_layer": {},
            "unresolved_targets": unresolved_seeds,
            "coverage": graph.coverage()["summary"],
            "rules": _cascade_rules_payload(kind),
            "limits": _cascade_limits(kind),
            "note": (
                "no asset matches this cascade's starting point. That is not 'no impact' — the asset "
                "may not have been collected"
            ),
        }

    seed_ids = [seed["asset_id"] for seed in seeds]
    waves, via, distance = _cascade_reach(graph, kind, seed_ids, depth=depth)
    reached = [node for node in distance if distance[node] > 0]
    by_type: dict[str, int] = {}
    for node in reached:
        key = str((graph.asset(node) or {}).get("type") or "UNKNOWN")
        by_type[key] = by_type.get(key, 0) + 1
    business = [node for node in reached if (graph.asset(node) or {}).get("type") == "SYSTEM"]

    return {
        "schema": SIMULATION_PREVIEW_SCHEMA,
        "status": "WOULD_MATCH" if reached else "WOULD_NOT_MATCH",
        "engine": "CASCADE",
        "kind": kind,
        "scenario": scenario,
        "base_projection_id": graph.fingerprint(),
        "live_state_modified": False,
        "depth": depth,
        "seeds": seeds,
        "unresolved_seeds": unresolved_seeds,
        "evidence_considered": sum(
            len((graph.asset(node) or {}).get("evidence_refs") or []) for node in seed_ids
        ),
        "matched_evidence": sum(
            len((graph.asset(node) or {}).get("evidence_refs") or []) for node in seed_ids
        ),
        "affected_assets": [
            {
                "asset_id": node,
                "name": (graph.asset(node) or {}).get("name"),
                "type": (graph.asset(node) or {}).get("type"),
                "hops": distance[node],
                "via_predicate": (via.get(node) or {}).get("predicate"),
            }
            for node in sorted(reached, key=lambda node: (distance[node], str(node)))
        ][:MAX_LISTED],
        "affected_asset_count": len(reached),
        "by_layer": dict(sorted(by_type.items())),
        "wave_counts": [
            {"depth": wave["depth"], "count": wave["count"]} for wave in waves
        ],
        "business_systems_reached": len(business),
        "unresolved_targets": unresolved_seeds,
        "coverage": graph.coverage()["summary"],
        "rules": _cascade_rules_payload(kind),
        "limits": _cascade_limits(kind),
        "note": (
            f"{len(reached)} asset(s) would be reached from {len(seeds)} seed(s) within {depth} hop(s); "
            "run the cascade to see each wave, the route each asset was reached by, and the blind spots"
            if reached
            else (
                f"{len(seeds)} seed(s) resolved but no established edge carries this failure within "
                f"{depth} hop(s) — that is 'nothing reached', not 'nothing affected'"
            )
        ),
    }


# --------------------------------------------------------------------------- #
# layer 6 — comparing two twins (§13, §14, §24 "Compare")
# --------------------------------------------------------------------------- #

COMPARE_SCHEMA = "cryptoscan.estate-twin-compare/1"

#: verdict order, worst first. A coverage loss outranks a crypto change on purpose:
#: "we stopped looking" makes every downstream comparison unreliable, and a reader
#: who sees only "crypto changed" will miss that the estate got darker.
COMPARE_VERDICTS: tuple[str, ...] = (
    "COVERAGE_DEGRADED",
    "CRYPTO_CHANGED",
    "ESTATE_CHANGED",
    "NO_CHANGE",
    "NOT_COMPARABLE",
)


def _asset_view(asset: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": asset.get("name"),
        "type": asset.get("type"),
        "environment": asset.get("environment"),
        "owner": asset.get("owner"),
        "location": asset.get("location"),
        "attributes": asset.get("attributes") or {},
        "identity": asset.get("identity") or {},
    }


def _artifact_key(item: Mapping[str, Any]) -> str:
    return "|".join(
        str(item.get(field) or "")
        for field in ("asset_id", "algorithm", "role", "protocol", "key_size", "layer")
    )


def compare(before: EstateGraph, after: EstateGraph, *, depth: int = 3) -> dict[str, Any]:
    """Diff two twins — before ("T0") and after ("T1").

    This is not a BOM diff. A BOM diff answers "did a document change"; this
    answers "did the estate change, or did we just stop looking at it":

    * **assets** added / removed / changed, with the fields that moved;
    * **relationships** established / lost, keyed by predicate + basis so a
      re-stated edge with weaker evidence shows up;
    * **crypto** movement by ``usage_state`` — a ``SUPPORTED`` → ``OBSERVED``
      transition is a promotion the bank cares about, and ``OBSERVED`` →
      ``SUPPORTED`` is a loss of proof that must not read as "no change";
    * **coverage** per plane, because a plane that stopped running makes the rest
      of the comparison meaningless and outranks everything else in the verdict;
    * **unknowns** gained and lost.

    Refusals: one side missing is ``NOT_COMPARABLE``; identical projections are
    ``NO_CHANGE`` and say explicitly that this is not a safety statement.
    """
    if before is None or after is None:
        return {
            "schema": COMPARE_SCHEMA,
            "verdict": "NOT_COMPARABLE",
            "reason": "one of the two snapshots is missing — there is nothing to compare against",
        }

    before_id, after_id = before.fingerprint(), after.fingerprint()

    # -- assets ------------------------------------------------------------ #
    before_assets = {asset["asset_id"]: asset for asset in before.assets()}
    after_assets = {asset["asset_id"]: asset for asset in after.assets()}
    added_assets = sorted(set(after_assets) - set(before_assets))
    removed_assets = sorted(set(before_assets) - set(after_assets))
    changed_assets: list[dict[str, Any]] = []
    for asset_id in sorted(set(before_assets) & set(after_assets)):
        old, new = _asset_view(before_assets[asset_id]), _asset_view(after_assets[asset_id])
        fields = [field for field in old if old.get(field) != new.get(field)]
        if fields:
            changed_assets.append(
                {
                    "asset_id": asset_id,
                    "name": new.get("name"),
                    "type": new.get("type"),
                    "changed_fields": fields,
                    "before": {field: old.get(field) for field in fields},
                    "after": {field: new.get(field) for field in fields},
                }
            )

    def _card(asset_id_value: str, source: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        asset = source.get(asset_id_value) or {}
        return {
            "asset_id": asset_id_value,
            "name": asset.get("name"),
            "type": asset.get("type"),
            "environment": asset.get("environment"),
        }

    # -- relationships ------------------------------------------------------ #
    def _edges(graph: EstateGraph) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for edge in graph.relationships():
            key = f"{edge['subject']}|{edge['predicate']}|{edge['object']}|{edge.get('basis')}"
            out[key] = edge
        return out

    before_edges, after_edges = _edges(before), _edges(after)
    added_edges = sorted(set(after_edges) - set(before_edges))
    removed_edges = sorted(set(before_edges) - set(after_edges))

    def _edge_card(key: str, graph: EstateGraph) -> dict[str, Any]:
        edge = (after_edges if graph is after else before_edges).get(key) or {}
        return {
            "subject": edge.get("subject"),
            "subject_name": (graph.asset(str(edge.get("subject"))) or {}).get("name"),
            "predicate": edge.get("predicate"),
            "object": edge.get("object"),
            "object_name": (graph.asset(str(edge.get("object"))) or {}).get("name"),
            "basis": edge.get("basis"),
            "confidence": edge.get("confidence"),
        }

    # -- crypto ------------------------------------------------------------- #
    before_artifacts = {_artifact_key(item): item for item in before.crypto_artifacts()}
    after_artifacts = {_artifact_key(item): item for item in after.crypto_artifacts()}
    usage_states = ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")

    def _rank(state: str) -> int:
        return usage_states.index(state) if state in usage_states else -1

    promoted: list[dict[str, Any]] = []
    demoted: list[dict[str, Any]] = []
    for key in sorted(set(before_artifacts) & set(after_artifacts)):
        old, new = before_artifacts[key], after_artifacts[key]
        if old["usage_state"] == new["usage_state"]:
            continue
        entry = {
            "asset_id": new["asset_id"],
            "asset_name": new.get("asset_name"),
            "algorithm": new.get("algorithm"),
            "protocol": new.get("protocol"),
            "layer": new.get("layer"),
            "before": old["usage_state"],
            "after": new["usage_state"],
        }
        (promoted if _rank(new["usage_state"]) > _rank(old["usage_state"]) else demoted).append(entry)

    crypto_added = [after_artifacts[key] for key in sorted(set(after_artifacts) - set(before_artifacts))]
    crypto_removed = [before_artifacts[key] for key in sorted(set(before_artifacts) - set(after_artifacts))]

    # -- coverage ----------------------------------------------------------- #
    def _planes(graph: EstateGraph) -> dict[str, dict[str, Any]]:
        return {
            str(row.get("target")): row for row in (graph.coverage().get("targets") or [])
        }

    before_planes, after_planes = _planes(before), _planes(after)
    degraded_planes: list[dict[str, Any]] = []
    improved_planes: list[dict[str, Any]] = []
    rank = {"COMPLETE": 4, "PARTIAL": 3, "UNKNOWN": 2, "NOT_OBSERVED": 1, "NOT_ATTEMPTED": 0, "FAILED": 0}
    for name in sorted(set(before_planes) | set(after_planes)):
        old = before_planes.get(name) or {}
        new = after_planes.get(name) or {}
        old_state = str(old.get("status") or "UNKNOWN")
        new_state = str(new.get("status") or "UNKNOWN")
        if old_state == new_state and (old.get("collected") or 0) == (new.get("collected") or 0):
            continue
        entry = {
            "plane": name,
            "before": old_state,
            "after": new_state,
            "before_collected": old.get("collected"),
            "after_collected": new.get("collected"),
            "reason": new.get("reason") or old.get("reason"),
        }
        (degraded_planes if rank.get(new_state, 2) < rank.get(old_state, 2) else improved_planes).append(entry)

    # -- evidence and unknowns ---------------------------------------------- #
    def _evidence_types(graph: EstateGraph) -> dict[str, int]:
        out: dict[str, int] = {}
        for record in graph.evidence():
            key = str(record["evidence_type"])
            out[key] = out.get(key, 0) + 1
        return out

    before_evidence, after_evidence = _evidence_types(before), _evidence_types(after)
    weak = {"IMPORTED", "VENDOR_DECLARED", "INFERRED", "UNKNOWN"}
    strong_gained = sum(
        max(0, after_evidence.get(state, 0) - before_evidence.get(state, 0))
        for state in after_evidence if state not in weak
    )
    strong_lost = sum(
        max(0, before_evidence.get(state, 0) - after_evidence.get(state, 0))
        for state in before_evidence if state not in weak
    )
    before_unknown = before.unknown_inventory()
    after_unknown = after.unknown_inventory()

    # -- verdict ------------------------------------------------------------ #
    if before_id == after_id:
        verdict = "NO_CHANGE"
        reason = "the two snapshots have the same projection id — the evidence is identical"
    elif degraded_planes or strong_lost > strong_gained:
        verdict = "COVERAGE_DEGRADED"
        reason = (
            "a plane stopped being observed, or stronger evidence was lost. Nothing below should be "
            "read as the estate improving until collection is restored"
        )
    elif crypto_added or crypto_removed or promoted or demoted:
        verdict = "CRYPTO_CHANGED"
        reason = "cryptographic artefacts or their usage state moved between the two snapshots"
    elif added_assets or removed_assets or changed_assets or added_edges or removed_edges:
        verdict = "ESTATE_CHANGED"
        reason = "the estate changed, but no cryptographic artefact or usage state did"
    else:
        verdict = "ESTATE_CHANGED"
        reason = (
            "the projection ids differ but no compared surface did — most often a metadata-only "
            "difference such as a timestamp; treat it as unexplained rather than as clean"
        )

    return {
        "schema": COMPARE_SCHEMA,
        "verdict": verdict,
        "reason": reason,
        "before": {
            "projection_id": before_id,
            "snapshot_id": f"twin:{before_id}",
            "assets": len(before_assets),
            "relationships": len(before_edges),
            "crypto_artifacts": len(before_artifacts),
            "completeness_percent": completeness(before)["overall_percent"],
        },
        "after": {
            "projection_id": after_id,
            "snapshot_id": f"twin:{after_id}",
            "assets": len(after_assets),
            "relationships": len(after_edges),
            "crypto_artifacts": len(after_artifacts),
            "completeness_percent": completeness(after)["overall_percent"],
        },
        "sameness": before_id == after_id,
        "assets": {
            "added": [_card(asset_id, after_assets) for asset_id in added_assets[:MAX_LISTED]],
            "removed": [_card(asset_id, before_assets) for asset_id in removed_assets[:MAX_LISTED]],
            "changed": changed_assets[:MAX_LISTED],
            "counts": {
                "added": len(added_assets),
                "removed": len(removed_assets),
                "changed": len(changed_assets),
                "unchanged": len(set(before_assets) & set(after_assets)) - len(changed_assets),
            },
        },
        "relationships": {
            "established": [_edge_card(key, after) for key in added_edges[:MAX_LISTED]],
            "lost": [_edge_card(key, before) for key in removed_edges[:MAX_LISTED]],
            "counts": {"established": len(added_edges), "lost": len(removed_edges),
                       "unchanged": len(set(before_edges) & set(after_edges))},
        },
        "crypto": {
            "added": crypto_added[:MAX_LISTED],
            "removed": crypto_removed[:MAX_LISTED],
            "promoted": promoted[:MAX_LISTED],
            "demoted": demoted[:MAX_LISTED],
            "counts": {
                "added": len(crypto_added),
                "removed": len(crypto_removed),
                "promoted": len(promoted),
                "demoted": len(demoted),
            },
            "note": (
                "promoted = the same artefact now has stronger evidence (SUPPORTED -> CONFIGURED -> "
                "NEGOTIATED -> OBSERVED); demoted = proof was lost, which is not the same as the "
                "cryptography being removed"
            ),
        },
        "coverage": {
            "degraded": degraded_planes[:MAX_LISTED],
            "improved": improved_planes[:MAX_LISTED],
            "counts": {"degraded": len(degraded_planes), "improved": len(improved_planes)},
        },
        "evidence": {
            "before": before_evidence,
            "after": after_evidence,
            "stronger_gained": strong_gained,
            "stronger_lost": strong_lost,
            "note": "IMPORTED / VENDOR_DECLARED / INFERRED are excluded from stronger/weaker on purpose",
        },
        "unknown": {
            "before": before_unknown["unknown_count"],
            "after": after_unknown["unknown_count"],
            "delta": after_unknown["unknown_count"] - before_unknown["unknown_count"],
            "unresolved_gained": len(after.unresolved_relationships()) - len(before.unresolved_relationships()),
        },
        "moves": {
            "assets": added_assets or removed_assets or changed_assets,
            "confirmed": any(
                [added_assets, removed_assets, changed_assets, added_edges, removed_edges,
                 crypto_added, crypto_removed, promoted, demoted, degraded_planes, improved_planes]
            ),
        },
        "note": (
            "NO_CHANGE is not a safety statement: it means the evidence is identical, including the "
            "evidence that says nothing is observed"
        ),
    }



# --------------------------------------------------------------------------- #
# layer 4 — the crypto graph (§9, §10)
# --------------------------------------------------------------------------- #

CRYPTO_GRAPH_SCHEMA = "cryptoscan.estate-crypto-graph/1"

#: The four planes a cryptographic fact can live on. They are drawn separately
#: because merging them is exactly the CBOM bug this product exists to fix:
#: "the library supports AES-128" and "the API used AES-256-GCM" are both true.
CRYPTO_PLANES: tuple[str, ...] = ("CAPABILITY", "CONFIGURED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED")


def _crypto_plane(item: Mapping[str, Any]) -> str:
    state = str(item.get("usage_state") or "")
    evidence = str(item.get("evidence_type") or "")
    if evidence.startswith("NETWORK"):
        return "NETWORK_OBSERVED"
    if state == "SUPPORTED":
        return "CAPABILITY"
    if state == "OBSERVED":
        return "RUNTIME_OBSERVED"
    if state == "NEGOTIATED":
        return "NETWORK_OBSERVED"
    return "CONFIGURED"


def _algo_label(item: Mapping[str, Any]) -> str:
    for field in ("algorithm", "protocol"):
        value = item.get(field)
        if value:
            size = item.get("key_size")
            return f"{value}-{size}" if field == "algorithm" and size else str(value)
    return "UNKNOWN"


def crypto_graph(graph: EstateGraph) -> dict[str, Any]:
    """The crypto graph, with capability and use kept on separate planes (§9, §10).

    The spec's example is the whole point of this view::

        OpenSSL     CAPABILITY        {AES-128, AES-256, RSA}
        Payment API RUNTIME_OBSERVED  {AES-256-GCM}
        LB-07       NETWORK_OBSERVED  {TLSv1.3, AES-256-GCM, X25519}

    A scanner that merges those into one list produces a contradiction. The twin
    keeps the three facts, and this method states *why* they can co-exist. When the
    same artefact genuinely disagrees across two sources of the *same* plane, that
    is reported as a conflict with the evidence on both sides — not resolved.
    """
    artifacts = graph.crypto_artifacts()
    planes: dict[str, list[dict[str, Any]]] = {plane: [] for plane in CRYPTO_PLANES}
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for item in artifacts:
        plane = _crypto_plane(item)
        asset_id = str(item.get("asset_id"))
        node = nodes.setdefault(
            asset_id,
            {
                "node_id": asset_id,
                "kind": "ASSET",
                "name": item.get("asset_name"),
                "type": item.get("asset_type"),
                "planes": {candidate: [] for candidate in CRYPTO_PLANES},
            },
        )
        entry = {
            "label": _algo_label(item),
            "algorithm": item.get("algorithm"),
            "protocol": item.get("protocol"),
            "key_size": item.get("key_size"),
            "mode": item.get("mode"),
            "curve": item.get("curve"),
            "layer": item.get("layer"),
            "usage_state": item.get("usage_state"),
            "evidence_type": item.get("evidence_type"),
            "confidence": item.get("confidence"),
            "evidence_ids": item.get("evidence_ids"),
            "asset_id": asset_id,
            "asset_name": item.get("asset_name"),
            "asset_type": item.get("asset_type"),
        }
        planes[plane].append(entry)
        node["planes"][plane].append(entry["label"])
        edges.append(
            {
                "from": asset_id,
                "to": f"algo:{entry['label']}",
                "predicate": {
                    "CAPABILITY": "supports",
                    "CONFIGURED": "configured_with",
                    "RUNTIME_OBSERVED": "used_at_runtime",
                    "NETWORK_OBSERVED": "observed_on_wire",
                }[plane],
                "plane": plane,
                "layer": entry["layer"],
                "evidence_ids": entry["evidence_ids"],
            }
        )
        nodes.setdefault(
            f"algo:{entry['label']}",
            {"node_id": f"algo:{entry['label']}", "kind": "ALGORITHM", "name": entry["label"], "planes": {}},
        )

    # §10 — the capability-vs-use pair, stated as a non-contradiction
    coexistence: list[dict[str, Any]] = []
    for asset_id, node in nodes.items():
        if node["kind"] != "ASSET":
            continue
        capability = set(node["planes"].get("CAPABILITY") or [])
        used = set(node["planes"].get("RUNTIME_OBSERVED") or []) | set(node["planes"].get("NETWORK_OBSERVED") or [])
        if not capability or not used:
            continue
        unused = sorted(capability - used)
        coexistence.append(
            {
                "asset_id": asset_id,
                "asset_name": node["name"],
                "capability": sorted(capability),
                "in_use": sorted(used),
                "supported_but_not_observed": unused,
                "explanation": (
                    "this asset can do more than it was seen doing. That is not a contradiction: the "
                    "capability list is what it supports, the observed list is what ran"
                ),
                "next_action": (
                    "if any of the unused algorithms matters (legacy RSA, AES-128), it is a candidate for "
                    "removal; the twin will not assume it is unused elsewhere"
                ),
            }
        )

    # conflicts, split into "same plane disagreement" (real) and "cross plane" (explainable)
    real_conflicts: list[dict[str, Any]] = []
    explained: list[dict[str, Any]] = []
    for conflict in graph.conflicts():
        values = conflict.get("values") or []
        plane_of = {
            str(item.get("evidence_type")): _crypto_plane(
                {"evidence_type": item.get("evidence_type"), "usage_state": "CONFIGURED"}
            )
            for item in values
        }
        if conflict.get("field") in {"algorithm", "key_size", "mode", "digest", "public_key_algorithm"}:
            per_plane: dict[str, set[str]] = {}
            for item, plane in zip(values, [plane_of.get(str(item.get("evidence_type")), "CONFIGURED") for item in values]):
                per_plane.setdefault(plane, set()).add(str(item.get("value")))
            if any(len(found) > 1 for found in per_plane.values()):
                real_conflicts.append(conflict)
            else:
                explained.append(
                    {
                        **conflict,
                        "explanation": (
                            "the values disagree across *different* planes (capability vs configured vs "
                            "observed). Both can be true at once; this is the case spec 94 §10 describes, "
                            "not a data-quality defect"
                        ),
                    }
                )
        else:
            real_conflicts.append(conflict)

    return {
        "schema": CRYPTO_GRAPH_SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "planes": planes,
        "plane_meanings": {
            "CAPABILITY": "what the artefact can do (declared/compiled in) — never proof of use",
            "CONFIGURED": "what configuration says it should do — not proof it ran",
            "RUNTIME_OBSERVED": "what a runtime collector saw it do",
            "NETWORK_OBSERVED": "what a peer saw on the wire — transport only",
        },
        "nodes": sorted(nodes.values(), key=lambda node: (node["kind"], str(node["name"]))),
        "edges": edges,
        "counts": {
            plane: len(items) for plane, items in planes.items()
        } | {
            "nodes": len(nodes),
            "assets": sum(1 for node in nodes.values() if node["kind"] == "ASSET"),
            "algorithms": sum(1 for node in nodes.values() if node["kind"] == "ALGORITHM"),
        },
        "coexistence": coexistence[:MAX_LISTED],
        "conflicts": real_conflicts[:MAX_LISTED],
        "explained_disagreements": explained[:MAX_LISTED],
        "conflict_counts": {"real": len(real_conflicts), "explained": len(explained)},
        "note": (
            "capability, configuration, runtime and wire observations are drawn on separate planes. "
            "Two of them disagreeing is information; two sources on the SAME plane disagreeing is a "
            "conflict and is never auto-resolved"
        ),
    }


# --------------------------------------------------------------------------- #
# §20 — graph projection for a graph database
# --------------------------------------------------------------------------- #

GRAPH_EXPORT_SCHEMA = "cryptoscan.estate-graph-export/1"


def _placement_nodes(graph: EstateGraph) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The organisation chart and the sites, as nodes with ``CONTAINS`` edges.

    Derived from asserted attributes only — the same rule the placement model uses —
    so a graph query cannot reach a level the evidence never asserted. An asset with
    no organisation contributes no ORGANIZATION node, which is why "the chart is
    empty" reads as a collection gap rather than as a flat bank.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    parent: dict[str, str] = {}

    def _node(level: str, name: str) -> str:
        node_id = f"placement:{level.lower()}:{_canonical({'level': level, 'name': name})[:16]}"
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "labels": ["PLACEMENT", level],
                "properties": {"level": level, "name": name, "estate": graph.estate},
            }
        return node_id

    def _edge(kind: str, start: str, end: str, evidence_ids: Sequence[str] = ()) -> None:
        key = (kind, start, end)
        if key not in edges:
            edges[key] = {
                "type": kind,
                "from": start,
                "to": end,
                # a placement edge is established by the attribute that places the asset,
                # so it cites that asset's evidence rather than appearing from nowhere
                "properties": {"basis": "PLACEMENT_ATTRIBUTE", "evidence_ids": []},
            }
        properties = edges[key]["properties"]
        for evidence_id in evidence_ids:
            if evidence_id not in properties["evidence_ids"]:
                properties["evidence_ids"].append(evidence_id)
        if not properties["evidence_ids"]:
            # an asset whose placement is asserted but which carries no evidence record
            # of its own: the edge is real, its provenance is not. Saying so is the
            # difference between a documented gap and an edge that looks sourced
            properties["uncited_because"] = (
                "the placed asset carries no evidence record; its placement attribute is assertion-only"
            )
        elif "uncited_because" in properties:
            del properties["uncited_because"]

    for asset in graph.assets():
        asset_id = asset["asset_id"]
        organization = _attribute(asset, _PLACEMENT_KEYS["ORGANIZATION"])
        department = _attribute(asset, _PLACEMENT_KEYS["DEPARTMENT"])
        region = _attribute(asset, _PLACEMENT_KEYS["REGION"])
        data_center = _attribute(asset, _PLACEMENT_KEYS["DATA_CENTER"])
        account = _attribute(asset, _PLACEMENT_KEYS["CLOUD_ENVIRONMENT"])
        provider = _attribute(asset, _CLOUD_PROVIDER_KEYS).upper()
        environment = _text(asset.get("environment"))
        if data_center and not _is_site(data_center):
            data_center = ""

        hierarchy: list[tuple[str, str]] = []
        if organization:
            hierarchy.append(("ORGANIZATION", organization))
        if department:
            hierarchy.append(("DEPARTMENT", department))
        if environment:
            hierarchy.append(("ENVIRONMENT", environment))
        if region:
            hierarchy.append(("REGION", region))
        if data_center:
            hierarchy.append(("DATA_CENTER", data_center))
        if provider or account:
            hierarchy.append(
                ("CLOUD_ENVIRONMENT", f"{provider or 'UNKNOWN_PROVIDER'}"
                                       f"{':' + account if account else ''}")
            )

        ids = {level: _node(level, name) for level, name in hierarchy}
        cites = [str(ref) for ref in (asset.get("evidence_refs") or [])]
        for level, _name in hierarchy:
            _edge("CONTAINS", ids[level], asset_id, cites)
        # the chart's own shape, asserted or absent: a department is not placed under
        # an organisation the evidence never named for any asset in it
        if "DEPARTMENT" in ids and "ORGANIZATION" in ids:
            parent.setdefault(ids["DEPARTMENT"], ids["ORGANIZATION"])
        if "DATA_CENTER" in ids and "REGION" in ids:
            parent.setdefault(ids["DATA_CENTER"], ids["REGION"])
        if "ENVIRONMENT" in ids and "DATA_CENTER" in ids:
            parent.setdefault(ids["ENVIRONMENT"], ids["DATA_CENTER"])

    for child, ancestor in sorted(parent.items()):
        _edge("PART_OF", child, ancestor)

    return (
        [nodes[key] for key in sorted(nodes)],
        [edges[key] for key in sorted(edges)],
    )


#: The specification's §7 Neo4j vocabulary (§7, "Suggested Neo4j graph model"),
#: mapped onto what this build emits. Kept as data so the claim "the projection
#: covers the specification's labels" is checked rather than asserted in prose: a
#: spec label whose target stops existing fails ``test_graph_export`` instead of
#: quietly becoming a missing node type. Where the specification's name differs
#: from this build's, the mapping says so instead of emitting a second spelling of
#: the same thing.
SPEC_GRAPH_LABELS: dict[str, tuple[str, tuple[str, ...]]] = {
    # spec label: (family, this build's labels)
    "Organization": ("PLACEMENT", ("ORGANIZATION",)),
    "Region": ("PLACEMENT", ("REGION",)),
    "DataCenter": ("PLACEMENT", ("DATA_CENTER",)),
    "Environment": ("PLACEMENT", ("ENVIRONMENT",)),
    "BusinessSystem": ("ASSET", ("SYSTEM",)),
    "Application": ("ASSET", ("APPLICATION",)),
    "Service": ("ASSET", ("SERVICE",)),
    "Host": ("ASSET", ("HOST",)),
    "Container": ("ASSET", ("CONTAINER",)),
    "Package": ("ASSET", ("PACKAGE",)),
    "Library": ("ASSET", ("LIBRARY",)),
    "CryptoAsset": ("ASSET", ("CRYPTO_ASSET",)),
    "Certificate": ("ASSET", ("CERTIFICATE",)),
    "HSM": ("ASSET", ("HSM",)),
    "KMS": ("ASSET", ("KMS_KEY",)),
    "Hardware": ("ASSET", ("HARDWARE",)),
    "NetworkDevice": ("ASSET", ("FIREWALL", "LOAD_BALANCER", "VPN")),
    "NetworkEndpoint": ("ASSET", ("NETWORK_ENDPOINT",)),
    "Vendor": ("ASSET", ("VENDOR",)),
    "Product": ("ASSET", ("PRODUCT",)),
    "Firmware": ("ASSET", ("FIRMWARE",)),
    "Evidence": ("EVIDENCE", EVIDENCE_TYPES),
}


def graph_label_coverage() -> dict[str, Any]:
    """Which of the specification's graph labels this build can emit, and as what."""
    known = {
        "ASSET": set(ASSET_TYPES),
        "PLACEMENT": set(PLACEMENT_LABELS),
        "EVIDENCE": set(EVIDENCE_TYPES),
    }
    rows = []
    for spec_label, (family, emitted) in SPEC_GRAPH_LABELS.items():
        missing = [label for label in emitted if label not in known[family]]
        rows.append(
            {
                "spec_label": spec_label,
                "family": family,
                "emitted_as": list(emitted),
                "available": not missing,
                "missing": missing,
            }
        )
    return {
        "labels": rows,
        "specified": len(rows),
        "available": sum(1 for row in rows if row["available"]),
        "note": (
            "a placement level becomes a node only where evidence asserts it, so an "
            "available label is a shape the export can produce, not a promise that this "
            "estate has one"
        ),
    }


def graph_export(graph: EstateGraph) -> dict[str, Any]:
    """Typed nodes and edges for loading into a graph database.

    The spec (§20–§21) is explicit that a graph store is a *projection* of the
    canonical records, never the source of truth. This export is the boundary
    where that stays true: it is deterministic, it carries the evidence ids on
    every edge, and re-importing it cannot mint a fact that the evidence does not
    already support.
    """
    nodes = []
    for asset in graph.assets():
        nodes.append(
            {
                "id": asset["asset_id"],
                "labels": ["Asset", asset["type"]],
                "properties": {
                    "asset_id": asset["asset_id"],
                    "type": asset["type"],
                    "name": asset["name"],
                    "environment": asset.get("environment"),
                    "owner": asset.get("owner"),
                    "location": asset.get("location"),
                    "status": asset.get("status"),
                    "identity": asset.get("identity") or {},
                    "attributes": asset.get("attributes") or {},
                    "evidence_count": len(asset.get("evidence_refs") or []),
                },
            }
        )

    relationships = []
    for edge in graph.relationships():
        relationships.append(
            {
                "type": edge["predicate"].upper(),
                "from": edge["subject"],
                "to": edge["object"],
                "properties": {
                    "basis": edge.get("basis"),
                    "confidence": edge.get("confidence"),
                    "evidence_ids": list(edge.get("evidence_ids") or []),
                    "attributes": edge.get("attributes") or {},
                },
            }
        )

    unresolved = []
    for edge in graph.unresolved_relationships():
        unresolved.append(
            {
                "type": "UNRESOLVED",
                "from": edge.get("subject"),
                "to": edge.get("object"),
                "properties": {
                    "attempted_predicate": edge.get("predicate"),
                    "basis": edge.get("basis"),
                    "reason": edge.get("reason"),
                },
            }
        )

    evidence = [
        {
            "id": record["evidence_id"],
            "labels": ["Evidence", record["evidence_type"]],
            "properties": {
                "target": record["target"],
                "evidence_type": record["evidence_type"],
                "confidence": record["confidence"],
                "layer": record["layer"],
                "source": record.get("source"),
                "collector": record.get("collector"),
                "observed_at": record.get("observed_at"),
                "facts": record.get("facts") or {},
            },
        }
        for record in graph.evidence()
    ]
    supports = [
        {
            "type": "SUPPORTS",
            "from": record["evidence_id"],
            "to": record["target"],
            # every edge cites the evidence behind it, including this one — an
            # export where some edges lack provenance invites a graph store that
            # cannot answer "why is this here"
            "properties": {
                "evidence_type": record["evidence_type"],
                "evidence_ids": [record["evidence_id"]],
            },
        }
        for record in graph.evidence()
    ]

    placement_nodes, placement_edges = _placement_nodes(graph)

    return {
        "schema": GRAPH_EXPORT_SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "generated_at": _now(),
        "nodes": nodes + evidence + placement_nodes,
        "relationships": relationships + supports + placement_edges,
        "unresolved": unresolved,
        "label_coverage": {
            row["spec_label"]: row["emitted_as"] for row in graph_label_coverage()["labels"]
        },
        "counts": {
            "nodes": len(nodes) + len(evidence) + len(placement_nodes),
            "asset_nodes": len(nodes),
            "evidence_nodes": len(evidence),
            "placement_nodes": len(placement_nodes),
            "relationships": len(relationships),
            "supports": len(supports),
            "placement_edges": len(placement_edges),
            "unresolved": len(unresolved),
        },
        "load_notes": {
            "node_identity": (
                "asset nodes are keyed by the deterministic asset_id; evidence nodes by evidence_id; "
                "placement nodes by (level, asserted name) — never by position in a tree"
            ),
            "placement_levels_are_asserted_only": (
                "a level with no asserting evidence has no node. The graph never fills the chart in "
                "from the level below it"
            ),
            "edge_identity": "an edge is (type, from, to) plus its basis — never a bare foreign key",
            "unresolved_edges_ship_separately": True,
            "not_source_of_truth": (
                "this export is a projection of the canonical evidence records. If a graph store and "
                "this export disagree, the evidence wins and the store is rebuilt"
            ),
        },
    }


def overview(graph: EstateGraph) -> dict[str, Any]:
    """§24 — the estate screen: what the twin holds, in one read."""
    placement = placement_model(graph)
    return {
        "schema": TWIN_SCHEMA,
        "model": "cryptoscan.estate-twin-overview/1",
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "levels": list(ESTATE_LEVELS),
        "asset_types": sorted(ASSET_TYPES),
        "summary": graph.summary(),
        "placement": {
            "environments": placement["environments"],
            "unplaced_count": placement["unplaced_count"],
            "business_systems": placement["business_systems"],
        },
        "completeness": completeness(graph),
        "note": (
            "the twin is one correlated model: the six BOMs, the coverage matrix and the completeness "
            "report are all views of this snapshot"
        ),
    }


__all__ = [
    "COMPARE_SCHEMA",
    "CRYPTO_GRAPH_SCHEMA",
    "CRYPTO_PLANES",
    "GRAPH_EXPORT_SCHEMA",
    "COMPARE_VERDICTS",
    "COMPLETENESS_SCHEMA",
    "ESTATE_LEVELS",
    "IMPACT_SCHEMA",
    "CASCADE_KINDS",
    "CASCADE_RULES",
    "CASCADE_SCHEMA",
    "SCENARIO_INPUTS",
    "SCENARIO_KINDS",
    "SIMULATION_KINDS",
    "SIMULATION_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "SPEC_GRAPH_LABELS",
    "STRENGTH_ORDER",
    "TWIN_SCHEMA",
    "cascade",
    "cascade_preview",
    "compare",
    "completeness",
    "crypto_graph",
    "graph_export",
    "graph_label_coverage",
    "graph_from_snapshot",
    "impact",
    "investigate",
    "overview",
    "placement_model",
    "search",
    "simulate",
    "snapshot",
    "why",
]
