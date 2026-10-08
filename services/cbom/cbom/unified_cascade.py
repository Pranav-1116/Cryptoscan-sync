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

#: What a cascade target can be. Order matters for auto-detection when no
#: explicit kind is given: most specific (fingerprints, host:port) first.
TARGET_KINDS = (
    "certificate",  # fingerprint sha256 or subject
    "endpoint",     # host or host:port seen on the wire / registered
    "system",       # system id or name
    "vendor",       # vendor registry name
    "device",       # hardware fleet asset id / manufacturer / model
    "library",      # library named in the twin's asset libraries
    "process",      # business process (id or name)
    "algorithm",    # algorithm family (RSA, ML-KEM, TLS_RSA_WITH_...)
)

#: Propagation depth bound. Mirrors the graph engine's blast-radius cap
#: (``CALLS*1..12``); deeper traversals cost more than they reveal.
MAX_DEPTH_LIMIT = 12

_SCHEMA = "cryptoscan.unified-cascade/1"


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
         reverse: bool, max_depth: int) -> dict[int, list[str]]:
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


def identify_target(snapshot: Mapping[str, Any], target: str,
                    kind: str | None = None) -> dict[str, Any] | None:
    """Detect what the target refers to. Returns ``{kind, matched}`` or None.

    With ``kind`` given, only that interpretation is tried; without it, kinds
    are tried most-specific-first (a sha256 fingerprint is never a vendor).
    """
    wanted = _norm(target)
    if not wanted:
        return None

    def _certificate() -> dict[str, Any] | None:
        """Fingerprint is exact and unambiguous; subject matching must not
        steal a system's name (``CN=payment-api`` contains ``payment-api``),
        so bare-subject containment only runs as a last resort below."""
        for cert in snapshot.get("certificates") or []:
            if _norm(cert.get("fingerprint_sha256")) == wanted:
                return {"kind": "certificate", "matched": dict(cert)}
            if _norm(cert.get("subject")) == wanted:
                return {"kind": "certificate", "matched": dict(cert)}
        return None

    def _certificate_by_subject() -> dict[str, Any] | None:
        for cert in snapshot.get("certificates") or []:
            if _match(cert.get("subject"), wanted):
                return {"kind": "certificate", "matched": dict(cert)}
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

    def _vendor() -> dict[str, Any] | None:
        for vendor in snapshot.get("vendors") or []:
            if _match(vendor.get("name"), wanted):
                return {"kind": "vendor", "matched": dict(vendor)}
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
        "certificate": _certificate, "endpoint": _endpoint, "system": _system,
        "vendor": _vendor, "device": _device, "library": _library,
        "process": _process, "algorithm": _algorithm,
    }
    if kind is not None:
        normalized_kind = _norm(kind)
        if normalized_kind == "certificate":
            # an explicit certificate hint means subject containment is
            # intended too, not just exact subject/fingerprint
            return _certificate() or _certificate_by_subject()
        if normalized_kind not in detectors:
            raise ValueError(
                f"unknown target kind {kind!r}; available: {list(detectors)}")
        return detectors[normalized_kind]()
    for detector in detectors.values():
        found = detector()
        if found is not None:
            return found
    # nothing exact matched — a certificate subject substring is the last
    # interpretation worth trying ("payment-api" → CN=payment-api)
    return _certificate_by_subject()


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
    systems = sorted({str(e.get("system_id")) for e in unique if e.get("system_id")}
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
    fingerprint = matched.get("fingerprint_sha256")
    endpoints = [e for e in snapshot.get("network_endpoints") or []
                 if _match((e.get("certificate") or {}).get("subject"), subject)
                 or _match(e.get("certificate_subject"), subject)]
    # real usage links (CertificateUsage rows) name the systems that run the
    # certificate; endpoint owners add whoever serves it on the wire
    usage_systems = sorted(set(
        (snapshot.get("certificate_usages") or {}).get(fingerprint) or []))
    owning = {str(e.get("system_id")) for e in endpoints if e.get("system_id")}
    systems = sorted(set(usage_systems) | owning)
    return {
        "code": {"evidence_ids": [], "systems": [], "files": []},
        "network": {
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
    system_names = sorted({str(s.get("name")) for s in snapshot.get("systems") or []
                           if s.get("id") in linked})
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
                list(snapshot.get("dependencies") or []), set(linked),
                reverse=True, max_depth=max_depth),
            "downstream_by_depth": _downstream_of(
                snapshot, [str(s) for s in linked if s], max_depth),
            "systems": system_names,
        },
        "process": _processes_for(snapshot, [str(s) for s in linked if s]),
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
    """What breaks if this business process stops.

    The systems that support the process stop with it; whoever depends on
    those systems (registered edges, walked backwards) stops too. Crypto,
    endpoints and vendors of the supporting systems are named so the answer
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


def unified_cascade(snapshot: Mapping[str, Any], *, target: str,
                    kind: str | None = None, max_depth: int = 6,
                    now: datetime) -> dict[str, Any]:
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

    identified = identify_target(snapshot, target_text, kind)
    if identified is None:
        return {
            "schema": _SCHEMA,
            "as_of": now.isoformat(),
            "deterministic": True,
            "mutates_nothing": True,
            "target": {"input": target_text, "kind": kind or "unknown", "matched": None},
            "verdict": "NOT_FOUND",
            "layers": {},
            "impact": {"affected_system_count": 0},
            "honest_unknowns": [
                "the target matches nothing in the twin: no certificate, "
                "endpoint, system, vendor, device, library or algorithm",
            ],
        }

    cascade_kind, matched = identified["kind"], identified["matched"]
    if cascade_kind == "algorithm":
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

    # Private keys (``_``-prefixed) are folded into impact, not leaked as layers.
    extra_assets = layers.pop("_assets", [])
    libraries = layers.pop("_libraries", [])
    certificate = layers.pop("_certificate", None)

    dependents = layers["system"].get("dependents_by_depth") or {}
    downstream = layers["system"].get("downstream_by_depth") or {}
    code_systems = layers["code"].get("systems") or []
    vendor_systems = layers["vendor"].get("systems") or layers["system"].get("systems") or []
    affected_systems = sorted(
        {s for by_depth in dependents.values() for s in by_depth}
        | {s for by_depth in downstream.values() for s in by_depth}
        | set(code_systems) | set(vendor_systems))
    affected_processes = [
        {"id": p.get("id"), "name": p.get("name")}
        for p in (layers.get("process") or {}).get("processes") or []
    ]
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

    return {
        "schema": _SCHEMA,
        "as_of": now.isoformat(),
        "deterministic": True,
        "mutates_nothing": True,
        "target": {"input": target_text, "kind": cascade_kind, "matched": matched},
        "verdict": verdict,
        "layers": layers,
        "impact": {
            "affected_systems": affected_systems,
            "affected_system_count": len(affected_systems),
            "affected_processes": affected_processes,
            "migration_waves": {wave: sorted(sids)
                                for wave, sids in sorted(waves.items())},
            "twin_assets": extra_assets,
            "libraries": libraries,
            "certificate": certificate,
            "max_propagation_depth": propagated,
        },
        "honest_unknowns": unknowns,
    }
