"""Crypto dependency map: system → software component → library → algorithm,
plus system → system dependencies and a selectable cascade simulation.

Every edge is derived from a stored record and carries the record that
establishes it:

* system → component   — a ``system_assets`` link (asset owned by the system)
* component → algorithm — a ``crypto_assets`` row (algorithm at that location)
* component → library   — the asset's recorded ``libraries`` provenance
* system → system       — a ``system_dependencies`` row (consumer → provider)

Nothing is inferred from names or proximity: an asset without an ownership
link is reported as *unattributed*, not guessed onto a system, and a
dependency edge that is not ACTIVE (stale, expired, tombstoned) is shown but
never propagates a cascade.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from typing import Any, Iterable

from sqlalchemy.orm import Session

from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from shared_models.algorithm_registry import parse_algorithm
from shared_models.dependency_semantics import MAX_SYSTEM_HOPS, POLICY_VERSION, propagates
from shared_models.relationship_lifecycle import clock, effective_state, lifecycle_payload
from shared_models.traversal_evidence import system_dependency_metadata

UNATTRIBUTED = "unattributed"

#: worst-first; a component/system inherits the worst risk it touches
RISK_ORDER = ("disallowed", "deprecated", "quantum_vulnerable", "unknown", "acceptable", "quantum_safe")
RISK_LABEL = {
    "disallowed": "Disallowed — broken or below minimum strength",
    "deprecated": "Deprecated / restricted — scheduled for removal",
    "quantum_vulnerable": "Quantum-vulnerable — broken by Shor's algorithm",
    "unknown": "Not classified by the algorithm registry",
    "acceptable": "Acceptable today",
    "quantum_safe": "Post-quantum algorithm",
}

_ENDPOINT_RE = re.compile(r"^(?:tls://)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+):(\d{1,5})$")
_SOURCE_EXT = {".java", ".go", ".py", ".cpp", ".cc", ".c", ".h", ".cbl", ".cob", ".scala", ".kt",
               ".js", ".ts", ".rb", ".rs", ".cs", ".php", ".swift"}
_KEYSTORE_EXT = {".p12", ".pfx", ".jks", ".pem", ".key", ".crt", ".der", ".keystore"}


# ── classification ──────────────────────────────────────────────────────────

def algorithm_identity(algorithm: str | None, key_size: int | None) -> dict[str, Any] | None:
    """Canonical algorithm node for an asset's (algorithm, key size).

    The declared key size wins over registry inference (a 3DES-112 keying
    option is not 3DES-168). Status and quantum impact come from the shared
    algorithm registry so the map agrees with every other BOM view.
    """
    raw = (algorithm or "").strip()
    if not raw or raw.upper() == "MARKER":
        return None
    probe = raw
    ephemeral_dh = raw.upper().startswith("DHE") and not raw.upper().startswith("DHE-RSA")
    if ephemeral_dh:
        probe = "DH" + raw[3:]  # finite-field ephemeral DH is classified as DH
    size = int(key_size) if isinstance(key_size, int) or (isinstance(key_size, str) and key_size.isdigit()) else None
    has_size_suffix = bool(re.search(r"-\d{2,5}$", probe))
    info = parse_algorithm(probe)
    if size and not has_size_suffix:
        # the size-qualified form carries key-strength policy (RSA-1024 is
        # disallowed, RSA-2048 is not) — use it whenever the registry knows it
        sized = parse_algorithm(f"{probe}-{size}")
        if sized.recognized and str(sized.status).upper() != "UNKNOWN":
            info = sized
    canonical = info.canonical or raw
    if ephemeral_dh and canonical.upper().startswith("DH"):
        canonical = "DHE" + canonical[2:]  # name what the asset recorded
    label = canonical
    if size and not re.search(r"\d{2,5}$", canonical) and info.family not in {"hash", "mac", "unknown"}:
        label = f"{canonical}-{size}"
    elif size and info.family == "unknown" and not has_size_suffix:
        label = f"{raw}-{size}"
    family_lower = str(info.family or "").lower()
    status = str(info.status or "UNKNOWN").upper()
    if status == "DISALLOWED":
        risk = "disallowed"
    elif status in {"DEPRECATED", "RESTRICTED"}:
        risk = "deprecated"
    elif info.quantum_impact == "shor":
        risk = "quantum_vulnerable"
    elif "pqc" in family_lower:
        risk = "quantum_safe"
    elif status == "ALLOWED":
        risk = "acceptable"
    else:
        risk = "unknown"
    return {
        "id": "algorithm:" + label.lower(),
        "label": label,
        "canonical": canonical,
        "family": info.family,
        "status": status,
        "quantum_impact": info.quantum_impact,
        "key_size": size,
        "risk": risk,
        "risk_label": RISK_LABEL[risk],
    }


def worst_risk(risks: Iterable[str]) -> str | None:
    present = set(risks)
    for risk in RISK_ORDER:
        if risk in present:
            return risk
    return None


def component_identity(file_path: str | None) -> dict[str, Any]:
    """The software component an asset lives in: a source file, a config or
    keystore file, or a live network endpoint (``tls://host:port`` cipher
    stack and ``host:port`` served certificate collapse into one endpoint)."""
    path = (file_path or "").strip() or "(no location recorded)"
    match = _ENDPOINT_RE.match(path)
    if match and (path.startswith("tls://") or "/" not in path):
        endpoint = f"{match.group(1)}:{match.group(2)}"
        return {"id": "component:ep:" + endpoint, "label": endpoint, "kind": "tls_endpoint",
                "location": endpoint}
    name = path.rsplit("/", 1)[-1]
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    kind = "source" if ext in _SOURCE_EXT else "keystore" if ext in _KEYSTORE_EXT else "config"
    digest = hashlib.sha1(path.encode("utf-8")).hexdigest()[:12]
    return {"id": f"component:{digest}", "label": name, "kind": kind, "location": path}


def _library_identity(lib: Any) -> dict[str, Any] | None:
    if isinstance(lib, dict):
        name = str(lib.get("name") or "").strip()
        version = str(lib.get("version") or "").strip()
    else:
        name, version = str(lib or "").strip(), ""
    if not name:
        return None
    label = f"{name} {version}".strip()
    return {"id": "library:" + label.lower().replace(" ", "@"), "label": label, "name": name,
            "version": version or None}


# ── map ─────────────────────────────────────────────────────────────────────

def _system_edges(rows: list[SystemDependency], system_ids: set[str], *, now) -> list[dict[str, Any]]:
    edges = []
    for row in rows:
        if row.parent_id not in system_ids or row.child_id not in system_ids:
            continue
        relation = (row.relation or "CALLS").upper()
        state = effective_state(lifecycle_payload(row), now=now)
        meta = system_dependency_metadata(row)
        edges.append({
            "id": row.id,
            "from": f"system:{row.parent_id}",
            "to": f"system:{row.child_id}",
            "relation": relation,
            "lifecycle_state": state,
            "propagates": bool(propagates(relation) and state == "ACTIVE"),
            "provenance": meta.get("provenance"),
            "source": row.source,
            "created_by": row.created_by,
            "evidence_ref": row.evidence_ref,
            "confidence": row.confidence,
            "operational_dependency": row.operational_dependency,
            "last_verified": meta.get("last_verified"),
        })
    edges.sort(key=lambda e: (e["from"], e["to"]))
    return edges


def build_dependency_map(db: Session) -> dict[str, Any]:
    now = clock()
    systems = db.query(System).all()
    system_by_id = {s.id: s for s in systems}
    links = db.query(SystemAsset).all()
    owners_of: dict[str, set[str]] = defaultdict(set)
    for link in links:
        if link.system_id in system_by_id:
            owners_of[link.asset_id].add(link.system_id)

    components: dict[str, dict[str, Any]] = {}
    algorithms: dict[str, dict[str, Any]] = {}
    libraries: dict[str, dict[str, Any]] = {}
    uses: dict[tuple[str, str], dict[str, Any]] = {}
    contains: dict[tuple[str, str], dict[str, Any]] = {}
    links_lib: dict[tuple[str, str], dict[str, Any]] = {}
    provides: dict[tuple[str, str], dict[str, Any]] = {}
    unattributed_assets = 0
    asset_total = 0

    for asset in db.query(CryptoAsset).all():
        algo = algorithm_identity(asset.algorithm, asset.key_size)
        if algo is None:
            continue
        asset_total += 1
        comp = component_identity(asset.file_path)
        owners = sorted(owners_of.get(asset.id) or [])
        if not owners:
            unattributed_assets += 1
            owners = [UNATTRIBUTED]
        node = components.setdefault(comp["id"], {**comp, "system_ids": set(), "algorithm_ids": set(),
                                                   "asset_count": 0, "languages": set()})
        node["asset_count"] += 1
        node["algorithm_ids"].add(algo["id"])
        if asset.source_language:
            node["languages"].add(str(asset.source_language))
        anode = algorithms.setdefault(algo["id"], {**algo, "asset_count": 0, "component_ids": set(),
                                                   "system_ids": set(), "library_ids": set(),
                                                   "purposes": set(), "modes": set()})
        anode["asset_count"] += 1
        anode["component_ids"].add(comp["id"])
        if asset.purpose:
            anode["purposes"].add(str(asset.purpose))
        if asset.mode:
            anode["modes"].add(str(asset.mode))
        location = {
            "asset_id": asset.id,
            "file_path": asset.file_path,
            "line_number": asset.line_number,
            "purpose": asset.purpose,
            "mode": asset.mode,
            "key_size": asset.key_size,
            "confidence": asset.confidence,
            "is_hardcoded_key": bool(asset.is_hardcoded_key),
            "scanner_ids": list(asset.scanner_ids or []),
        }
        libs = [lib for lib in (_library_identity(x) for x in (asset.libraries or [])) if lib]
        edge = uses.setdefault((comp["id"], algo["id"]), {
            "from": comp["id"], "to": algo["id"], "relation": "USES",
            "basis": "crypto_assets row (algorithm recorded at this location)",
            "locations": [], "library_ids": set()})
        edge["locations"].append(location)
        for lib in libs:
            libraries.setdefault(lib["id"], {**lib, "component_ids": set(), "algorithm_ids": set(),
                                             "system_ids": set()})
            libraries[lib["id"]]["component_ids"].add(comp["id"])
            libraries[lib["id"]]["algorithm_ids"].add(algo["id"])
            edge["library_ids"].add(lib["id"])
            anode["library_ids"].add(lib["id"])
            links_lib.setdefault((comp["id"], lib["id"]), {
                "from": comp["id"], "to": lib["id"], "relation": "LINKS",
                "basis": "library recorded on the crypto asset", "asset_ids": []})["asset_ids"].append(asset.id)
            provides.setdefault((lib["id"], algo["id"]), {
                "from": lib["id"], "to": algo["id"], "relation": "PROVIDES",
                "basis": "algorithm resolved through this library", "asset_ids": []})["asset_ids"].append(asset.id)
        for sid in owners:
            node["system_ids"].add(sid)
            anode["system_ids"].add(sid)
            for lib in libs:
                libraries[lib["id"]]["system_ids"].add(sid)
            contains.setdefault((f"system:{sid}", comp["id"]), {
                "from": f"system:{sid}", "to": comp["id"], "relation": "CONTAINS",
                "basis": ("system_assets link" if sid != UNATTRIBUTED
                          else "no system owns this asset — not guessed"),
                "asset_ids": []})["asset_ids"].append(asset.id)

    system_nodes = []
    system_ids = set(system_by_id)
    sys_algos: dict[str, set[str]] = defaultdict(set)
    for comp in components.values():
        for sid in comp["system_ids"]:
            sys_algos[sid] |= comp["algorithm_ids"]
    for s in sorted(systems, key=lambda s: (s.name or "").lower()):
        algo_ids = sys_algos.get(s.id, set())
        system_nodes.append({
            "id": f"system:{s.id}", "system_id": s.id, "label": s.name, "kind": "system",
            "criticality": s.criticality, "business_unit": s.business_unit,
            "owner": s.technical_owner or s.owner, "environment": s.environment,
            "algorithm_ids": sorted(algo_ids),
            "risk": worst_risk(algorithms[a]["risk"] for a in algo_ids if a in algorithms),
            "component_count": sum(1 for c in components.values() if s.id in c["system_ids"]),
        })
    if unattributed_assets:
        algo_ids = sys_algos.get(UNATTRIBUTED, set())
        system_nodes.append({
            "id": f"system:{UNATTRIBUTED}", "system_id": UNATTRIBUTED,
            "label": "Unattributed (no owning system)", "kind": "unattributed",
            "criticality": None, "business_unit": None, "owner": None, "environment": None,
            "algorithm_ids": sorted(algo_ids),
            "risk": worst_risk(algorithms[a]["risk"] for a in algo_ids if a in algorithms),
            "component_count": sum(1 for c in components.values() if UNATTRIBUTED in c["system_ids"]),
        })

    def _finish(node: dict[str, Any]) -> dict[str, Any]:
        out = {}
        for key, value in node.items():
            if isinstance(value, set):
                out[key] = sorted(value)
            else:
                out[key] = value
        return out

    for comp in components.values():
        comp["risk"] = worst_risk(algorithms[a]["risk"] for a in comp["algorithm_ids"])
    system_edges = _system_edges(db.query(SystemDependency).all(), system_ids, now=now)
    algo_list = sorted((_finish(a) for a in algorithms.values()),
                       key=lambda a: (RISK_ORDER.index(a["risk"]), a["label"].lower()))
    uses_list = []
    for edge in uses.values():
        edge = _finish(edge)
        edge["locations"].sort(key=lambda loc: (str(loc["file_path"]), loc["line_number"] or 0))
        uses_list.append(edge)
    return {
        "policy": {"version": POLICY_VERSION, "direction": "consumer_to_provider",
                   "meaning": "system A → system B means A depends on (calls / consumes) B"},
        "generated_at": now.isoformat(),
        "systems": system_nodes,
        "components": sorted((_finish(c) for c in components.values()),
                             key=lambda c: (c["kind"] != "tls_endpoint", c["location"].lower())),
        "libraries": sorted((_finish(lib) for lib in libraries.values()), key=lambda lib: lib["label"].lower()),
        "algorithms": algo_list,
        "edges": {
            "contains": sorted((_finish(e) for e in contains.values()), key=lambda e: (e["from"], e["to"])),
            "uses": sorted(uses_list, key=lambda e: (e["from"], e["to"])),
            "links": sorted((_finish(e) for e in links_lib.values()), key=lambda e: (e["from"], e["to"])),
            "provides": sorted((_finish(e) for e in provides.values()), key=lambda e: (e["from"], e["to"])),
            "depends_on": system_edges,
        },
        "coverage": {
            "assets": asset_total,
            "attributed_assets": asset_total - unattributed_assets,
            "unattributed_assets": unattributed_assets,
            "systems": len(systems),
            "systems_with_crypto": sum(1 for s in system_nodes if s["kind"] == "system" and s["algorithm_ids"]),
            "dependency_edges": len(system_edges),
            "propagating_edges": sum(1 for e in system_edges if e["propagates"]),
        },
    }


# ── cascade ─────────────────────────────────────────────────────────────────

def simulate_cascade(dep_map: dict[str, Any], *, system_ids: Iterable[str] = (),
                     algorithm_ids: Iterable[str] = (), direction: str = "dependents",
                     hops: int = 6) -> dict[str, Any]:
    """Which systems a change/compromise at the selected systems or
    algorithms reaches over ACTIVE propagating dependency edges.

    ``dependents`` walks consumer edges backwards (who calls the seed and so
    breaks when it breaks); ``providers`` walks forwards (what the seed relies
    on); ``both`` unions the two. Each reached system carries its shortest
    witness path and the exact edges on it.
    """
    hops = max(1, min(MAX_SYSTEM_HOPS, int(hops)))
    if direction not in {"dependents", "providers", "both"}:
        raise ValueError("direction must be dependents, providers or both")
    nodes = {s["id"]: s for s in dep_map["systems"]}
    algos = {a["id"]: a for a in dep_map["algorithms"]}
    seeds: dict[str, list[str]] = defaultdict(list)
    unknown: list[str] = []
    for raw in system_ids:
        sid = raw if str(raw).startswith("system:") else f"system:{raw}"
        if sid in nodes:
            seeds[sid].append("selected")
        else:
            unknown.append(str(raw))
    algo_seed_detail = []
    for raw in algorithm_ids:
        aid = raw if str(raw).startswith("algorithm:") else f"algorithm:{str(raw).lower()}"
        algo = algos.get(aid)
        if not algo:
            unknown.append(str(raw))
            continue
        users = [sid for sid in algo["system_ids"] if f"system:{sid}" in nodes]
        locations = [loc for e in dep_map["edges"]["uses"] if e["to"] == aid for loc in e["locations"]]
        algo_seed_detail.append({"algorithm": algo["label"], "id": aid, "risk": algo["risk"],
                                 "systems": [nodes[f"system:{sid}"]["label"] for sid in users],
                                 "locations": len(locations)})
        for sid in users:
            seeds[f"system:{sid}"].append(f"uses {algo['label']}")

    active = [e for e in dep_map["edges"]["depends_on"] if e["propagates"]]
    skipped = [e for e in dep_map["edges"]["depends_on"] if not e["propagates"]]
    forward: dict[str, list[dict[str, Any]]] = defaultdict(list)
    backward: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in active:
        forward[e["from"]].append(e)
        backward[e["to"]].append(e)

    def walk(mode: str) -> dict[str, dict[str, Any]]:
        reached: dict[str, dict[str, Any]] = {}
        dist = {sid: 0 for sid in seeds}
        parent: dict[str, tuple[str, dict[str, Any]]] = {}
        queue = deque(sorted(seeds))
        while queue:
            cur = queue.popleft()
            if dist[cur] >= hops:
                continue
            adjacency = backward if mode == "dependents" else forward
            for edge in sorted(adjacency.get(cur, []), key=lambda e: (e["from"], e["to"])):
                nxt = edge["from"] if mode == "dependents" else edge["to"]
                if nxt in dist:
                    continue
                dist[nxt] = dist[cur] + 1
                parent[nxt] = (cur, edge)
                queue.append(nxt)
        for sid, depth in dist.items():
            if depth == 0:
                continue
            path, path_edges, node = [sid], [], sid
            while node in parent:
                prev, edge = parent[node]
                path.append(prev)
                path_edges.append(edge)
                node = prev
            path.reverse()
            path_edges.reverse()
            # chain oriented consumer → provider, matching the edge arrows
            chain = list(reversed(path)) if mode == "dependents" else path
            reached[sid] = {"hops": depth, "path": path, "path_edges": path_edges, "direction": mode,
                            "chain": chain}
        return reached

    results: dict[str, dict[str, Any]] = {}
    for mode in (["dependents", "providers"] if direction == "both" else [direction]):
        for sid, row in walk(mode).items():
            if sid in seeds:
                continue
            prev = results.get(sid)
            if prev is None or row["hops"] < prev["hops"]:
                results[sid] = row

    def _system_row(sid: str, extra: dict[str, Any]) -> dict[str, Any]:
        node = nodes[sid]
        exposure = [algos[a] for a in node["algorithm_ids"] if a in algos]
        return {
            "id": sid, "system_id": node["system_id"], "name": node["label"],
            "criticality": node.get("criticality"), "risk": node.get("risk"),
            "algorithms": [{"id": a["id"], "label": a["label"], "risk": a["risk"]} for a in exposure],
            "weak_algorithms": [a["label"] for a in exposure
                                if a["risk"] in {"disallowed", "deprecated", "quantum_vulnerable"}],
            **extra,
        }

    impacted = [
        _system_row(sid, {**row, "path_names": [nodes[p]["label"] for p in row["path"]],
                          "chain_names": [nodes[p]["label"] for p in row["chain"]]})
        for sid, row in results.items()
    ]
    impacted.sort(key=lambda r: (r["hops"], (r["name"] or "").lower()))
    by_crit: dict[str, int] = defaultdict(int)
    for row in impacted:
        by_crit[str(row.get("criticality") or "UNSET")] += 1
    return {
        "direction": direction,
        "hops": hops,
        "seeds": [_system_row(sid, {"reasons": reasons}) for sid, reasons in sorted(seeds.items())],
        "algorithm_seeds": algo_seed_detail,
        "impacted": impacted,
        "unknown_selections": unknown,
        "summary": {
            "seed_systems": len(seeds),
            "impacted_systems": len(impacted),
            "max_depth": max((r["hops"] for r in impacted), default=0),
            "by_criticality": dict(by_crit),
            "edges_considered": len(active),
            "edges_not_propagating": len(skipped),
        },
        "not_propagating": [{"from": e["from"], "to": e["to"], "relation": e["relation"],
                             "lifecycle_state": e["lifecycle_state"]} for e in skipped],
        "semantics": ("dependents = systems that consume the seed (break when it breaks); "
                      "providers = systems the seed relies on; only ACTIVE CALLS/DEPENDS_ON/IMPORTS "
                      "edges propagate — modeled exposure, not a runtime failure simulation"),
    }
