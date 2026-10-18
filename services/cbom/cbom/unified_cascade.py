"""Cross-BOM cascade — one question answered across every BOM layer.

An operator asking "what breaks if this changes?" should not need to know
that certificates live in the NBOM, algorithms in the CBOM, systems in the
dependency graph and vendors in the VBOM. :func:`unified_cascade` takes one
target — an algorithm, certificate, endpoint, system, device, vendor or
library — and fans the blast radius out across all of them in a single,
deterministic, read-only answer.

It operates on the same plain-dict estate snapshot the digital twin uses
(live states, systems, certificates, vendors, system↔vendor links, evidence,
dependency edges, wire-observed endpoints, hardware fleet), so the cascade
and the twin can never disagree about what the estate looks like.

Everything the engine cannot know is carried as an explicit honest unknown
(``honest_unknowns``), following the contract the twin engine established:
never estimate, never silently omit.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping

from shared_models.process_impact import classify_systems, project_processes
from cbom.target_resolution import resolve_target, fingerprint
from cbom.cascade_evidence import cascade_evidence
from cbom.software_cascade import software_context
from shared_models.relationship_lifecycle import current, possible, summary as lifecycle_summary
from shared_models.dependency_semantics import MAX_SYSTEM_HOPS, edge_relation, policy_metadata, propagates, system_id

#: Public supported-kind list. Resolution tiers are defined in target_resolution;
#: this display order does not authorize broad/first-row protected-kind selection.
TARGET_KINDS = (
    "package",      # exact versioned PURL from explicitly bound package SBOM
    "artifact",     # registered immutable sha256 digest or artifact id
    "certificate",  # fingerprint sha256 or subject
    "endpoint",     # host or host:port seen on the wire / registered
    "system",       # system id or name
    "vendor",       # exact vendor id or unique whole registry name
    "device",       # hardware fleet asset id / manufacturer / model
    "library",      # library named in the twin's asset libraries
    "process",      # business process (id or name)
    "algorithm",    # algorithm family (RSA, ML-KEM, TLS_RSA_WITH_...)
)

#: Propagation depth bound. Mirrors the graph engine's blast-radius cap
#: (``CALLS*1..12``); deeper traversals cost more than they reveal.
MAX_DEPTH_LIMIT = MAX_SYSTEM_HOPS

_SCHEMA = "cryptoscan.unified-cascade/1"
SYSTEM_SCOPE_SCHEMA = "cryptoscan.cascade-system-scope/1"


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _match(haystack: Any, needle: str) -> bool:
    return bool(needle) and needle in _norm(haystack)


def _cipher_mentions(cipher_suite: Any, algorithm: str) -> bool:
    """Does a TLS cipher suite reference this algorithm's family?

    Cipher suites name families, not parameterized algorithms
    (``TLS_RSA_WITH_AES_128_GCM_SHA256`` mentions RSA, not RSA-2048), so the
    check is on word-boundary tokens: any alphabetic token of the algorithm
    appearing as a delimited word in the suite name counts.
    """
    cipher = _norm(cipher_suite)
    if not cipher:
        return False
    padded = f"_{cipher}_"
    return any(f"_{token}_" in padded
               for token in re.findall(r"[A-Za-z]{2,}", algorithm))


def _processes_for(snapshot: Mapping[str, Any],
                   system_ids: list[str]) -> dict[str, Any]:
    """Business processes supported by these systems (real links, deduped)."""
    registry = snapshot.get("business_processes") or {}
    seen: set[str] = set()
    processes: list[dict[str, Any]] = []
    for sid in system_ids:
        for process in registry.get(sid) or []:
            key = str(process.get("id"))
            if key in seen:
                continue
            seen.add(key)
            processes.append({"id": process.get("id"), "name": process.get("name")})
    return {"processes": processes}


def _systems_for_assets(snapshot: Mapping[str, Any],
                        asset_ids: list[str]) -> list[str]:
    """Systems running these assets (real SystemAsset links via the twin)."""
    wanted = {str(a) for a in asset_ids}
    return sorted({str(sid) for asset in snapshot.get("assets") or []
                   if str(asset.get("asset_id")) in wanted
                   for sid in (asset.get("system_ids") or [])})


def _dependents_of(snapshot: Mapping[str, Any], systems: list[str],
                   max_depth: int) -> dict[str, list[str]]:
    if not systems:
        return {}
    return _bfs(list(snapshot.get("dependencies") or []), set(systems),
                reverse=True, max_depth=max_depth)


def _downstream_of(snapshot: Mapping[str, Any], systems: list[str],
                   max_depth: int) -> dict[str, list[str]]:
    if not systems:
        return {}
    return _bfs(list(snapshot.get("dependencies") or []), set(systems),
                reverse=False, max_depth=max_depth)


def _bfs(edges: list[Mapping[str, Any]], seeds: set[str], *,
         reverse: bool, max_depth: int) -> dict[str, list[str]]:
    """Depth-bounded BFS over {source,target} edges.

    ``reverse=True`` walks dependents: who (transitively) calls a seed.
    Returns nodes by depth (1 = direct), seeds excluded.
    """
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        src, dst = str(edge.get("source") or ""), str(edge.get("target") or "")
        if not src or not dst:
            continue
        if reverse:
            adjacency.setdefault(dst, set()).add(src)
        else:
            adjacency.setdefault(src, set()).add(dst)
    found: dict[str, list[str]] = {}
    seen: set[str] = set(seeds)
    frontier = set(seeds)
    for depth in range(1, max_depth + 1):
        nxt: set[str] = set()
        for node in frontier:
            for neighbour in adjacency.get(node, ()):
                if neighbour in seen:
                    continue
                seen.add(neighbour)
                nxt.add(neighbour)
        if not nxt:
            break
        found[str(depth)] = sorted(nxt)  # str keys: JSON-stable end to end
        frontier = nxt
    return found


def _identify_legacy(snapshot: Mapping[str, Any], target: str,
                    kind: str | None = None) -> dict[str, Any] | None:
    """Detect what the target refers to. Returns ``{kind, matched}`` or None.

    With ``kind`` given, only that interpretation is tried; without it, kinds
    are tried most-specific-first (a sha256 fingerprint is never a vendor).
    """
    wanted = _norm(target)
    if not wanted:
        return None

    def _endpoint() -> dict[str, Any] | None:
        host_port = wanted if ":" in wanted else None
        for endpoint in snapshot.get("network_endpoints") or []:
            candidate = _norm(f"{endpoint.get('host')}:{endpoint.get('port')}")
            host = _norm(endpoint.get("host"))
            if (host_port and candidate == host_port) or (not host_port and host and host == wanted):
                return {"kind": "endpoint", "matched": dict(endpoint)}
        return None

    def _system() -> dict[str, Any] | None:
        for system in snapshot.get("systems") or []:
            if _norm(system.get("id")) == wanted or _norm(system.get("name")) == wanted:
                return {"kind": "system", "matched": dict(system)}
        return None

    def _device() -> dict[str, Any] | None:
        for device in snapshot.get("hardware") or []:
            hsm = device.get("hsm") if isinstance(device.get("hsm"), Mapping) else {}
            if (wanted in (_norm(device.get("asset_id")), )
                    or _match(device.get("manufacturer"), wanted)
                    or _match(device.get("model"), wanted)
                    or _match(hsm.get("manufacturer"), wanted)
                    or _match(hsm.get("model"), wanted)):
                return {"kind": "device", "matched": dict(device)}
        return None

    def _library() -> dict[str, Any] | None:
        for asset in snapshot.get("assets") or []:
            libraries = asset.get("libraries") or {}
            names = list(libraries.keys()) if isinstance(libraries, Mapping) else [
                str(x) for x in libraries]
            for name in names:
                if _match(name, wanted):
                    # matched name as the estate spells it — the cascade and
                    # the catalog lookup need the real key, not the query text
                    return {"kind": "library", "matched": {"library": name}}
        return None

    def _process() -> dict[str, Any] | None:
        registry = snapshot.get("business_processes") or {}
        for processes in registry.values():
            for process in processes:
                if wanted in (_norm(process.get("id")), _norm(process.get("name"))):
                    return {"kind": "process", "matched": dict(process)}
        return None

    def _algorithm() -> dict[str, Any] | None:
        for record in snapshot.get("evidence") or []:
            if _match(record.get("algorithm"), wanted):
                return {"kind": "algorithm", "matched": {"algorithm": record.get("algorithm")}}
        for asset in snapshot.get("assets") or []:
            algorithms = asset.get("algorithms") or {}
            names = list(algorithms.keys()) if isinstance(algorithms, Mapping) else []
            if any(_match(name, wanted) for name in names):
                return {"kind": "algorithm", "matched": {"algorithm": target}}
        return None

    detectors = {
        "endpoint": _endpoint, "system": _system,
        "device": _device, "library": _library,
        "process": _process, "algorithm": _algorithm,
    }
    if kind is not None:
        normalized_kind = _norm(kind)
        if normalized_kind not in detectors:
            raise ValueError(
                f"unknown target kind {kind!r}; available: {list(detectors)}")
        return detectors[normalized_kind]()
    for detector in detectors.values():
        found = detector()
        if found is not None:
            return found
    return None


def identify_target(snapshot: Mapping[str, Any], target: str, kind: str | None = None, *, allow_name_search=False):
    """Compatibility lookup: unresolved choices never return an arbitrary row."""
    return resolve_target(snapshot, target, kind, allow_name_search=allow_name_search, legacy_detector=_identify_legacy)[1]


def _cascade_algorithm(snapshot: Mapping[str, Any], wanted: str,
                        max_depth: int = 6) -> dict[str, Any]:
    evidence = [e for e in snapshot.get("evidence") or []
                if _match(e.get("algorithm"), wanted)]
    seen_ids: set[Any] = set()
    unique: list[Mapping[str, Any]] = []
    for record in evidence:
        if record.get("id") in seen_ids:
            continue
        seen_ids.add(record.get("id"))
        unique.append(record)
    # systems come from EVERY matching row, before the id dedup: the twin
    # emits one row per (record, system) pair, so an evidence record shared
    # by two systems' assets appears twice with the same id — deduping first
    # silently dropped the second system from the blast radius
    systems = sorted({str(e.get("system_id")) for e in evidence if e.get("system_id")}
                     | set(_systems_for_assets(
                         snapshot, [str(a.get("asset_id")) for a in
                                    [a for a in snapshot.get("assets") or []
                                     if any(_match(name, wanted)
                                            for name in (a.get("algorithms") or {}))]])))
    assets = [a for a in snapshot.get("assets") or []
              if any(_match(name, wanted) for name in (a.get("algorithms") or {}))]
    libraries = sorted({
        str(name)
        for asset in assets
        for name in ((asset.get("libraries") or {})
                     if isinstance(asset.get("libraries"), Mapping) else {})
    })
    endpoints = [e for e in snapshot.get("network_endpoints") or []
                 if _cipher_mentions(e.get("cipher_suite"), wanted)]
    return {
        "code": {
            "evidence_ids": [str(e.get("id")) for e in unique],
            "systems": systems,
            "matched_asset_ids": [str(a.get("asset_id")) for a in assets],
            "files": sorted({str(e.get("file_path")) for e in unique if e.get("file_path")}),
        },
        "network": {
            "endpoints": [f"{e.get('host')}:{e.get('port')}" for e in endpoints],
        },
        "system": {
            "dependents_by_depth": _dependents_of(snapshot, systems, max_depth),
            "downstream_by_depth": {},
        },
        "process": _processes_for(snapshot, systems),
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": [], "systems": []},
        "_assets": [str(a.get("asset_id")) for a in assets],
        "_libraries": libraries,
    }


def _cascade_certificate(snapshot: Mapping[str, Any], matched: Mapping[str, Any],
                         max_depth: int = 6) -> dict[str, Any]:
    subject = _norm(matched.get("subject"))
    selected_fp = fingerprint(matched.get("fingerprint_sha256"))
    def endpoint_fp(endpoint):
        return fingerprint(endpoint.get("certificate_fingerprint_sha256") or (endpoint.get("certificate") or {}).get("fingerprint_sha256"))
    all_endpoints = snapshot.get("network_endpoints") or []
    endpoints = [e for e in all_endpoints if selected_fp and endpoint_fp(e) == selected_fp]
    subject_only = [e for e in all_endpoints if subject and _norm(e.get("certificate_subject") or (e.get("certificate") or {}).get("subject")) == subject and not endpoint_fp(e)]
    different_fp = [e for e in all_endpoints if subject and _norm(e.get("certificate_subject") or (e.get("certificate") or {}).get("subject")) == subject and endpoint_fp(e) and endpoint_fp(e) != selected_fp]
    usage_systems = {str(sid) for fp, sids in (snapshot.get("certificate_usages") or {}).items()
                     if selected_fp and fingerprint(fp) == selected_fp for sid in sids}
    owning = {str(e.get("system_id")) for e in endpoints if e.get("system_id")}
    systems = sorted(usage_systems | owning)
    return {
        "code": {"evidence_ids": [], "systems": [], "files": []},
        "network": {
            "certificate_join": {"method": "exact_leaf_fingerprint", "fingerprint_sha256": selected_fp,
                "subject_only_endpoint_count": len(subject_only), "different_fingerprint_same_subject_count": len(different_fp),
                "subject_only_endpoints": [f"{e.get('host')}:{e.get('port')}" for e in subject_only[:200]],
                "subject_only_endpoints_truncated": len(subject_only) > 200,
                "note": "Subject equality is not certificate identity. Subject-only endpoints do not seed system exposure."},
            "endpoints": [f"{e.get('host')}:{e.get('port')}" for e in endpoints],
            "tls_versions": sorted({str(e.get("version")) for e in endpoints if e.get("version")}),
        },
        "system": {
            # everyone who depends on the systems that run this certificate
            "dependents_by_depth": _dependents_of(snapshot, systems, max_depth),
            "downstream_by_depth": _downstream_of(snapshot, systems, max_depth),
            "systems": systems,
        },
        "process": _processes_for(snapshot, systems),
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": [], "systems": []},
        "_certificate": {
            "not_after": matched.get("not_after"),
            "renewal_status": matched.get("renewal_status"),
            "expiry_status": matched.get("expiry_status"),
        },
    }


def _cascade_system(snapshot: Mapping[str, Any], system: Mapping[str, Any],
                    max_depth: int = 6) -> dict[str, Any]:
    system_id = str(system.get("id"))
    evidence = [e for e in snapshot.get("evidence") or []
                if str(e.get("system_id")) == system_id]
    endpoints = [e for e in snapshot.get("network_endpoints") or []
                 if str(e.get("system_id")) == system_id]
    edges = list(snapshot.get("dependencies") or [])
    vendor_ids = set(system.get("vendor_ids") or [])
    vendors = sorted({str(v.get("name")) for v in snapshot.get("vendors") or []
                      if v.get("id") in vendor_ids})
    return {
        "code": {
            "evidence_ids": [str(e.get("id")) for e in evidence],
            "systems": [system_id],
            "algorithms": sorted({str(e.get("algorithm")) for e in evidence if e.get("algorithm")}),
        },
        "network": {
            "endpoints": [f"{e.get('host')}:{e.get('port')}" for e in endpoints],
        },
        "system": {
            "dependents_by_depth": _bfs(edges, {system_id}, reverse=True, max_depth=max_depth),
            "downstream_by_depth": _bfs(edges, {system_id}, reverse=False, max_depth=max_depth),
        },
        "process": _processes_for(snapshot, [system_id]),
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": vendors, "systems": []},
    }


def _cascade_vendor(snapshot: Mapping[str, Any], matched: Mapping[str, Any],
                     max_depth: int = 6) -> dict[str, Any]:
    vendor_id = matched.get("id")
    name = _norm(matched.get("name"))
    linked = [sv.get("system_id") for sv in snapshot.get("system_vendors") or []
              if sv.get("vendor_id") == vendor_id]
    # canonical system IDs — every other cascade kind reports IDs, and a
    # consumer that cannot join the answer back to systems cannot act on it
    systems = sorted({str(s) for s in linked if s})
    devices = [hw for hw in snapshot.get("hardware") or []
               if _match(hw.get("manufacturer"), name)
               or _match((hw.get("hsm") or {}).get("manufacturer"), name)]
    device_ids = sorted({str(d.get("asset_id")) for d in devices})
    assets = [a for a in snapshot.get("assets") or []
              if any(_match(lib, name) for lib in (
                  (a.get("libraries") or {}) if isinstance(a.get("libraries"), Mapping) else {}))]
    # VBOM: what this vendor's products implement, as discovered — never
    # marketing claims. PQC readiness is the scanner's verdict per use case.
    crypto_inventory = list((snapshot.get("vendor_crypto") or {}).get(vendor_id) or [])
    # sub-tier supply chain: declared vendor-of-vendor edges, walked
    # transitively (depth-bounded) so a chip vendor under an HSM vendor shows
    # up when the relationship has been declared — never inferred
    vendor_edges = [{"source": str(e.get("parent")), "target": str(e.get("child"))}
                    for e in snapshot.get("vendor_dependencies") or []]
    sub_tier = _bfs(vendor_edges, {str(vendor_id)},
                    reverse=False, max_depth=3) if vendor_edges else {}
    return {
        "code": {"evidence_ids": [], "systems": [], "files": [],
                 "assets_using_vendor_libraries": [str(a.get("asset_id")) for a in assets]},
        "network": {"endpoints": []},
        "system": {
            "dependents_by_depth": _bfs(
                list(snapshot.get("dependencies") or []), set(systems),
                reverse=True, max_depth=max_depth),
            "downstream_by_depth": _downstream_of(
                snapshot, systems, max_depth),
            "systems": systems,
        },
        "process": _processes_for(snapshot, systems),
        "hardware": {"devices": device_ids, "inventory_only": True},
        "vendor": {
            "vendors": [str(matched.get("name"))],
            "criticality": matched.get("criticality"),
            "sub_tier_vendors_by_depth": sub_tier,
            "crypto_inventory": crypto_inventory,
            "pqc_ready_use_cases": sorted({
                str(row.get("crypto_use_case")) for row in crypto_inventory
                if row.get("pqc_ready")}),
            "pqc_not_ready_use_cases": sorted({
                str(row.get("crypto_use_case")) for row in crypto_inventory
                if row.get("crypto_use_case") and not row.get("pqc_ready")}),
        },
    }


def _cascade_device(snapshot: Mapping[str, Any], matched: Mapping[str, Any],
                    max_depth: int = 6) -> dict[str, Any]:
    hsm = matched.get("hsm") if isinstance(matched.get("hsm"), Mapping) else {}
    device_id = str(matched.get("asset_id"))
    # declared crypto↔hardware linkage: which crypto assets this device
    # serves, and therefore which systems depend on it. Without a declared
    # link the cascade stays inventory-only and says so.
    linked_assets = list((snapshot.get("crypto_hardware") or {}).get(device_id) or [])
    systems = _systems_for_assets(snapshot, linked_assets)
    linked = bool(linked_assets)
    return {
        "code": {"evidence_ids": [], "systems": systems, "files": [],
                 "assets": [str(a) for a in linked_assets]},
        "network": {"endpoints": []},
        "system": {
            "dependents_by_depth": _dependents_of(snapshot, systems, max_depth),
            "downstream_by_depth": {},
            "systems": systems,
        },
        "process": _processes_for(snapshot, systems),
        "hardware": {
            "devices": [device_id],
            "manufacturer": matched.get("manufacturer") or hsm.get("manufacturer"),
            "model": matched.get("model") or hsm.get("model"),
            "firmware": hsm.get("firmware") or (
                matched.get("firmware") or {}).get("version")
            if isinstance(matched.get("firmware"), Mapping) else matched.get("firmware"),
            "pqc_capability": str(hsm.get("pqc_capability") or "").upper() or None,
            "inventory_only": not linked,
        },
        "vendor": {"vendors": [], "systems": []},
    }


def _cascade_endpoint(snapshot: Mapping[str, Any], matched: Mapping[str, Any],
                      max_depth: int = 6) -> dict[str, Any]:
    owner = [str(matched["system_id"])] if matched.get("system_id") else []
    return {
        "code": {"evidence_ids": [], "systems": [], "files": []},
        "network": {
            "endpoints": [f"{matched.get('host')}:{matched.get('port')}"],
            "tls_versions": [matched.get("version")] if matched.get("version") else [],
            "cipher_suites": [matched.get("cipher_suite")] if matched.get("cipher_suite") else [],
            "observed": bool(matched.get("observed", True)),
        },
        "system": {
            "dependents_by_depth": _dependents_of(snapshot, owner, max_depth),
            "downstream_by_depth": _downstream_of(snapshot, owner, max_depth),
            "systems": owner,
        },
        "process": _processes_for(snapshot, owner),
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": [], "systems": []},
    }


def _cascade_library(snapshot: Mapping[str, Any],
                     matched: Mapping[str, Any],
                     max_depth: int = 6) -> dict[str, Any]:
    name = str(matched.get("library") or "")
    assets = [a for a in snapshot.get("assets") or []
              if name in ((a.get("libraries") or {})
                          if isinstance(a.get("libraries"), Mapping) else {})]
    asset_ids = [str(a.get("asset_id")) for a in assets]
    systems = _systems_for_assets(snapshot, asset_ids)
    observed = sorted({
        str(alg) for a in assets
        for alg in ((a.get("algorithms") or {})
                    if isinstance(a.get("algorithms"), Mapping) else {})
    })
    # the fingerprint catalog is the second source of truth: what the library
    # implements per ADR-007, independent of what this estate has observed
    catalog = (snapshot.get("library_catalog") or {}).get(name)
    return {
        "code": {
            "evidence_ids": [], "systems": systems,
            "assets": asset_ids,
            "algorithms": observed,
        },
        "network": {"endpoints": []},
        "system": {
            "dependents_by_depth": _dependents_of(snapshot, systems, max_depth),
            "downstream_by_depth": {},
            "systems": systems,
        },
        "process": _processes_for(snapshot, systems),
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": [catalog.get("vendor")] if catalog and catalog.get("vendor") else []},
        "library": {
            "name": name,
            "catalog_algorithms": (catalog or {}).get("algorithms") or [],
            "deprecated": (catalog or {}).get("deprecated", False),
            "catalog_vendor": (catalog or {}).get("vendor"),
            "observed_algorithms": observed,
            "in_catalog": catalog is not None,
        },
    }


def _cascade_process(snapshot: Mapping[str, Any],
                     matched: Mapping[str, Any], max_depth: int = 6) -> dict[str, Any]:
    """Recorded support-system scope for a selected business process.

    Support declarations do not establish that systems stop with a process.
    Registered consumers are modeled exposure, not confirmed failures. Reverse
    reachability is retained for review. Crypto, endpoints and vendors of the
    supporting systems are named so the answer
    spans every BOM layer like every other cascade kind.
    """
    process_id = str(matched.get("id"))
    registry = snapshot.get("business_processes") or {}
    systems = sorted(sid for sid, processes in registry.items()
                     if any(str(p.get("id")) == process_id for p in processes))
    evidence = [e for e in snapshot.get("evidence") or []
                if str(e.get("system_id")) in systems]
    endpoints = [e for e in snapshot.get("network_endpoints") or []
                 if str(e.get("system_id")) in systems]
    edges = list(snapshot.get("dependencies") or [])
    dependents = _bfs(edges, set(systems), reverse=True, max_depth=max_depth)
    vendor_ids = set()
    for system in snapshot.get("systems") or []:
        if str(system.get("id")) in systems:
            vendor_ids.update(system.get("vendor_ids") or [])
    vendors = sorted({str(v.get("name")) for v in snapshot.get("vendors") or []
                      if v.get("id") in vendor_ids})
    return {
        "code": {
            "evidence_ids": [str(e.get("id")) for e in evidence],
            "systems": systems,
            "algorithms": sorted({str(e.get("algorithm")) for e in evidence
                                  if e.get("algorithm")}),
        },
        "network": {
            "endpoints": [f"{e.get('host')}:{e.get('port')}" for e in endpoints],
        },
        "system": {
            "dependents_by_depth": dependents,
            "downstream_by_depth": {},
            "systems": systems,
        },
        "process": {"processes": [{"id": matched.get("id"),
                                   "name": matched.get("name")}]},
        "hardware": {"devices": [], "inventory_only": True},
        "vendor": {"vendors": vendors, "systems": []},
    }



def _classify_system_scope(layers: Mapping[str, Any]) -> dict[str, Any]:
    """Disjoint review buckets; reachability is not an availability verdict.

    Seeds win over reverse consumers, which win over forward-only context.
    The original directional walks remain in layers (including cyclic overlap).
    Keep this additive: affected_systems remains the legacy full review union.
    """
    system = layers.get("system") or {}
    direct = (set((layers.get("code") or {}).get("systems") or [])
              | set(system.get("systems") or [])
              | set((layers.get("vendor") or {}).get("systems") or []))
    reverse = {s for group in (system.get("dependents_by_depth") or {}).values()
               for s in group}
    forward = {s for group in (system.get("downstream_by_depth") or {}).values()
               for s in group}
    return classify_systems(direct, reverse, forward)


def summarize_system_scope(result: Mapping[str, Any]) -> dict[str, Any] | None:
    """Bounded summary for history/events/watches; never reconstruct old runs.

    Full memberships live in the stored run. Copy counts only, so history
    doesn't multiply a large estate's system IDs across every summary row.
    """
    scope = (result.get("impact") or {}).get("system_classification") or {}
    if scope.get("schema") != SYSTEM_SCOPE_SCHEMA:
        return None
    return {
        "schema": SYSTEM_SCOPE_SCHEMA,
        **{key: {"count": scope[key]["count"]}
           for key in ("direct_exposure", "dependent_consumers", "supporting_context")},
        "exposure_system_count": scope["exposure_system_count"],
        "review_system_count": scope["review_system_count"],
    }


def unified_cascade(snapshot: Mapping[str, Any], *, target: str,
                    kind: str | None = None, max_depth: int = 6,
                    now: datetime, allow_name_search: bool = False) -> dict[str, Any]:
    """The blast radius of changing ``target``, across every BOM layer.

    Pure function of the snapshot: deterministic, read-only, ``now`` always a
    parameter. Raises ``ValueError`` for bad input so the API can answer 400.
    """
    target_text = str(target or "").strip()
    if not target_text:
        raise ValueError("target is required")
    depth = int(max_depth)
    if not 1 <= depth <= MAX_DEPTH_LIMIT:
        raise ValueError(f"max_depth must be 1..{MAX_DEPTH_LIMIT}")

    # Copy, never mutate a stored twin snapshot during replay. IDs from graph
    # snapshots may carry the system: prefix; non-system edges cannot bridge
    # the system graph. Empty/unknown relation behavior is versioned explicitly.
    snapshot = dict(snapshot)
    known = {system_id(row.get("id")) for row in snapshot.get("systems") or []}
    dependencies = []
    potential_dependencies = []
    original_dependencies = list(snapshot.get("dependencies") or [])
    for edge in snapshot.get("dependencies") or []:
        src, dst = system_id(edge.get("source")), system_id(edge.get("target"))
        if (src and dst and (src in known and dst in known)
                and propagates(edge_relation(edge))):
            normalized = {**edge, "source": src, "target": dst, "type": edge_relation(edge)}
            if current(edge, now=now):
                dependencies.append(normalized)
            if possible(edge, now=now):
                potential_dependencies.append(normalized)
    snapshot["dependencies"] = dependencies

    resolution, identified = resolve_target(snapshot, target_text, kind, allow_name_search=allow_name_search, legacy_detector=_identify_legacy)
    if identified is None:
        return {
            "schema": _SCHEMA,
            "relationship_policy": policy_metadata(),
            "as_of": now.isoformat(),
            "deterministic": True,
            "mutates_nothing": True,
            "target": {"input": target_text, "kind": kind or "unknown", "matched": None},
            "verdict": "NOT_FOUND" if resolution["status"] == "NOT_FOUND" else "UNRESOLVED",
            "target_resolution": resolution, "analysis_performed": False,
            "traversal_evidence": cascade_evidence(snapshot, _classify_system_scope({}), {}, {}, None, now=now, depth=depth, uncertain_systems=[], possible_direct=[]),
            "layers": {},
            "impact": {"affected_system_count": 0, "affected_systems": [],
                       "system_classification": _classify_system_scope({})},
            "honest_unknowns": [
                resolution["reason"] or "Target not resolved.",
                "No impact analysis performed. Empty compatibility fields are not measured zero exposure; candidates are limited to loaded authorized inventory.",
                *(["software supply-chain input was truncated; a missing package/artifact match is not proof of absence"]
                  if (snapshot.get("software_supply_chain_coverage") or {}).get("truncated") else []),
            ],
        }

    cascade_kind, matched = identified["kind"], identified["matched"]
    if cascade_kind in {"package", "artifact"}:
        software = software_context(snapshot, purl=matched.get("purl") if cascade_kind == "package" else None,
                                    artifact_id=matched.get("id") if cascade_kind == "artifact" else None, now=now)
        systems = software["systems"]
        layers = {
            "code": {"evidence_ids": [], "systems": [], "files": []},
            "system": {"systems": systems,
                       "dependents_by_depth": _dependents_of(snapshot, systems, depth),
                       "downstream_by_depth": _bfs(list(snapshot.get("dependencies") or []), set(systems),
                                                   reverse=False, max_depth=depth)},
            "network": {"endpoints": []}, "hardware": {"devices": []},
            "vendor": {"vendors": [], "systems": []},
            "process": _processes_for(snapshot, systems), "software": software,
        }
    elif cascade_kind == "algorithm":
        layers = _cascade_algorithm(snapshot, _norm(target_text), max_depth=depth)
    elif cascade_kind == "certificate":
        layers = _cascade_certificate(snapshot, matched, max_depth=depth)
    elif cascade_kind == "system":
        layers = _cascade_system(snapshot, matched, max_depth=depth)
    elif cascade_kind == "vendor":
        layers = _cascade_vendor(snapshot, matched, max_depth=depth)
    elif cascade_kind == "device":
        layers = _cascade_device(snapshot, matched, max_depth=depth)
    elif cascade_kind == "endpoint":
        layers = _cascade_endpoint(snapshot, matched, max_depth=depth)
    elif cascade_kind == "process":
        layers = _cascade_process(snapshot, matched, max_depth=depth)
    else:
        layers = _cascade_library(snapshot, matched, max_depth=depth)

    if cascade_kind == "system":
        layers["software"] = software_context(snapshot, system_id=str(matched.get("id")), now=now)

    # Private keys (``_``-prefixed) are folded into impact, not leaked as layers.
    extra_assets = layers.pop("_assets", [])
    libraries = layers.pop("_libraries", [])
    certificate = layers.pop("_certificate", None)

    dependents = layers["system"].get("dependents_by_depth") or {}
    downstream = layers["system"].get("downstream_by_depth") or {}
    classification = _classify_system_scope(layers)
    # Compatibility alias: historically "affected" included supporting context.
    # New callers must use the explicitly named classification, not treat the
    # legacy review union as a confirmed failure/consumer count.
    affected_systems = classification["review_systems"]
    seeds = set(classification["direct_exposure"]["systems"])
    possible_direct = set((layers.get("software") or {}).get("uncertain_systems") or [])
    potential_consumers = _bfs(potential_dependencies, seeds | possible_direct, reverse=True, max_depth=depth)
    potential_context = _bfs(potential_dependencies, seeds | possible_direct, reverse=False, max_depth=depth)
    potential_systems = possible_direct | {sid for values in [*potential_consumers.values(), *potential_context.values()] for sid in values}
    # Some target adapters intentionally omit forward-only active context.
    # Such ordinary active paths must not be mislabeled lifecycle uncertainty.
    active_walks = [*_bfs(dependencies, seeds, reverse=True, max_depth=depth).values(),
                    *_bfs(dependencies, seeds, reverse=False, max_depth=depth).values()]
    actively_reachable = seeds | {sid for values in active_walks for sid in values}
    uncertain_systems = sorted(potential_systems - set(affected_systems) - actively_reachable)
    lifecycle = lifecycle_summary([{**e, "record_kind": "system_dependency"} for e in original_dependencies] +
        [b for b in (layers.get("software") or {}).get("sbom_bindings") or []] +
        [d for d in (layers.get("software") or {}).get("deployments") or []], now=now)
    lifecycle["summary_scope"] = "all snapshot dependencies and matched software assertions"
    explanation_snapshot = {**snapshot, "dependencies": original_dependencies}
    explanation = cascade_evidence(explanation_snapshot, classification, layers, matched, cascade_kind,
        now=now, depth=depth, uncertain_systems=uncertain_systems, possible_direct=possible_direct)

    process_impact = project_processes(snapshot.get("business_processes") or {}, classification,
        now=now, uncertain_systems=uncertain_systems, witnesses=explanation, source_coverage=snapshot.get("business_process_coverage"))
    affected_processes = process_impact["review_processes"]
    layers["process"] = {"processes": affected_processes, "scope": "all classified review systems"}
    # migration waves of the affected systems (twin carries the wave per
    # system, derived from its readiness category) — "what breaks" plus
    # "when the migration plan can fix it"
    waves: dict[str, list[str]] = {}
    system_wave = {str(s.get("id")): s.get("migration_wave")
                   for s in snapshot.get("systems") or []}
    for sid in affected_systems:
        wave = system_wave.get(sid)
        if wave is not None:
            waves.setdefault(str(wave), []).append(sid)

    propagated = max(
        [int(d) for d in dependents] + [int(d) for d in downstream] + [0])

    verdict = "AFFECTED" if (
        affected_systems
        or affected_processes
        or layers["code"].get("evidence_ids")
        or layers["code"].get("assets")
        or layers["network"].get("endpoints")
        or layers["hardware"].get("devices")
        or extra_assets
    ) else "INSUFFICIENT_DATA"

    unknowns = [
        "network evidence is only as fresh as the last authorized scan",
        "code-layer evidence is capped (20k records); an estate larger than "
        "that undercounts this cascade",
        "system propagation walks registered dependency edges only — edges "
        "nobody registered do not exist here",
    ]
    if cascade_kind == "certificate":
        binding = layers["network"]["certificate_join"]
        if binding["subject_only_endpoint_count"]:
            unknowns.append("same-subject endpoints without a usable leaf fingerprint were not bound to this certificate; owner coverage remains incomplete")
        if not layers["network"]["endpoints"] and not layers["system"]["systems"]:
            unknowns.append("selected certificate has no loaded exact endpoint or usage binding; consumers remain unknown, not safe")
    if cascade_kind in {"package", "artifact"}:
        unknowns.extend([
            "SBOM membership is not proof of executable reachability or runtime use",
            "artifact identity, SBOM-to-release linkage and deployment are separate evidence assertions",
            "SBOM content was checked when bound; this cascade uses pinned components and does not reverify live stored bytes",
            "deployment bindings remain declarations even when recently confirmed by a source collection",
        ])
        if layers["software"]["unbound_artifact_ids"]:
            unknowns.append("one or more matched release artifacts have no valid explicit deployment binding; consumers remain unknown")
        if (layers["software"].get("coverage") or {}).get("truncated"):
            unknowns.append("software supply-chain input was truncated; absent matches or links are not proof of absence")
    if cascade_kind == "device":
        if (layers["hardware"] or {}).get("inventory_only"):
            unknowns.append(
                "no declared crypto-to-hardware linkage for this device: its "
                "dependents cannot be named, only the device facts are certain "
                "(declare one via POST /graph/hardware-links)")
    elif cascade_kind == "vendor":
        if not (layers["vendor"] or {}).get("sub_tier_vendors_by_depth"):
            unknowns.append(
                "no declared vendor-of-vendor edges for this vendor: transitive "
                "supply-chain exposure is unmodelled (declare via POST /graph/vendor-edges)")

    if lifecycle["excluded_count"]:
        unknowns.append("non-current relationship evidence was retained but excluded from active traversal; lower counts are not proof of remediation")
    if lifecycle["unbounded_active_count"]:
        unknowns.append("some eligible relationships have no validity deadline; legacy/unbounded eligibility is not verified freshness")

    return {
        "schema": _SCHEMA,
        "relationship_policy": policy_metadata(),
        "relationship_lifecycle": lifecycle,
        "target_resolution": resolution, "analysis_performed": True,
        "traversal_evidence": explanation,
        "as_of": now.isoformat(),
        "deterministic": True,
        "mutates_nothing": True,
        "target": {"input": target_text, "kind": cascade_kind, "matched": matched},
        "verdict": verdict,
        "layers": layers,
        "impact": {
            "affected_systems": affected_systems,
            "affected_system_count": len(affected_systems),
            "system_classification": classification,
            "lifecycle_uncertainty": {"possible_additional_systems": uncertain_systems,
                "count": len(uncertain_systems), "possible_direct_systems": sorted(possible_direct),
                "possible_dependents_by_depth": potential_consumers, "possible_downstream_by_depth": potential_context,
                "note": "Potential reachability through nonterminal uncertain evidence; not active exposure or proven failure."},
            "affected_processes": affected_processes,
            "process_impact": process_impact,
            "migration_waves": {wave: sorted(sids)
                                for wave, sids in sorted(waves.items())},
            "twin_assets": extra_assets,
            "libraries": libraries,
            "certificate": certificate,
            "max_propagation_depth": propagated,
        },
        "honest_unknowns": unknowns,
    }
