"""Cryptographic Digital Twin — deterministic scenario engine and fidelity.

The twin is the live crypto estate replica (``crypto_live_states`` + the
``crypto_live_events`` journal). This module answers the two questions a
bank asks of a twin:

1. **"What happens if …?"** — :data:`SCENARIOS`, ten deterministic scenario
   types over an estate snapshot. Every scenario is a pure function of the
   snapshot and its inputs: no randomness, no AI, no wall-clock reads
   (``now`` is always a parameter), and nothing is ever mutated, applied or
   deployed. Results carry explicit ``honest_unknowns`` rather than guesses,
   following the what-if contract the console already established.

2. **"Does the twin match reality?"** — :func:`twin_fidelity`, which measures
   what can be measured from the twin itself (staleness, coverage, journal
   lag, quantum mix) and names, as honest unknowns, the parts that need a
   fresh scan to compute (reconciliation diff). :func:`reconcile` computes
   the half that is computable today: the diff between the twin's algorithm
   inventory and the last ingested evidence.

All three operate on a plain-dict ``EstateSnapshot`` so the engine stays
unit-testable without a database; the API router adapts ORM rows into the
snapshot shape. Field-by-field, the snapshot is:

``assets``       one per ``crypto_live_states`` row (the twin's core),
                 plus ``last_event_at``/``event_count`` from the journal.
``systems``      estate systems with ``vendor_ids`` pre-joined.
``certificates`` certificate rows (fingerprint, not_after, key size…).
``vendors``      vendor registry rows.
``evidence``     a bounded projection of evidence records (algorithm,
                 key_size, is_hardcoded_key, file_path).
``dependencies`` graph edges ``{"source", "target", "type"}`` — from the
                 relational dependency table, or the latest versioned graph
                 snapshot when that table is empty.
``network_endpoints`` endpoints observed by stored network scans (newest
                 run wins per endpoint, same derivation as the NBOM), plus
                 registered scan targets that no run has observed yet as
                 version-less placeholders.
``hardware``     hardware fleet rows from the live hardware engine
                 (manufacturer, model, firmware, HSM observations with
                 declared PQC capability). Vendor management APIs are the
                 operator's to connect; whatever they feed lands here.

Missing sections are always legal: scenarios report what the missing data
prevents as honest unknowns instead of inventing it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from agility.simulation import ACTIONS, calculate_agility_score
from agility.migration_simulation import simulate_migration

#: Scenario identifiers, stable for API clients. Ten types — the count the
#: README claims; this module is what makes that claim true.
SCENARIO_IDS = (
    "algorithm_migration",
    "certificate_expiry",
    "key_rotation",
    "hsm_outage",
    "vendor_compromise",
    "protocol_deprecation",
    "compliance_change",
    "attack_path",
    "pqc_migration",
    "drift_regression",
)

#: Quantum-vulnerable algorithm families (deterministic classification; the
#: per-asset verdicts in the twin's ``quantum_status`` take precedence when
#: present).
_QUANTUM_VULNERABLE = ("rsa", "ecdsa", "ecdh", "dh", "ed25519", "x25519", "dsa")


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _algo_family(name: Any) -> str:
    return str(name or "").strip().lower()


def _unique_evidence(rows: Any) -> list[dict[str, Any]]:
    """Deduplicate evidence rows by id, keeping first sight.

    The API adapter ships one row per (record, linked system) so per-system
    scenarios can attribute correctly; a record linked to two systems is
    still one record, and estate-wide counts must not double-count it.
    """
    seen: set[Any] = set()
    out: list[dict[str, Any]] = []
    for row in rows or []:
        key = row.get("id") if isinstance(row, Mapping) else row
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row) if isinstance(row, Mapping) else {"id": row})
    return out


def _algo_matches(name: Any, wanted: str) -> bool:
    """Deterministic containment match: 'rsa' matches 'RSA-2048', 'rsa-3072'."""
    family = _algo_family(name)
    want = _algo_family(wanted)
    return bool(want) and want in family


def _assets_using(assets: list[dict], wanted: str) -> list[dict]:
    out = []
    for asset in assets:
        algorithms = asset.get("algorithms") or {}
        if isinstance(algorithms, dict):
            names = list(algorithms.keys())
            counts = list(algorithms.values())
        elif isinstance(algorithms, list):
            names = [a if isinstance(a, str) else (a or {}).get("name", "") for a in algorithms]
            counts = names
        else:
            names, counts = [], []
        if any(_algo_matches(n, wanted) for n in names if isinstance(n, str)) or any(
            _algo_matches(c, wanted) for c in counts if isinstance(c, str)
        ):
            out.append(asset)
    return out


def _result(scenario: str, inputs: dict, *, affected: dict, impact: dict,
            unknowns: list[str], verdict: str = "COMPUTED") -> dict:
    return {
        "scenario": scenario,
        "deterministic": True,
        "mutates_nothing": True,
        "inputs": inputs,
        "verdict": verdict,
        "affected": affected,
        "impact": impact,
        "honest_unknowns": unknowns,
    }


# ----------------------------------------------------------------- scenarios

def scenario_algorithm_migration(snapshot: Mapping[str, Any], *, now: datetime,
                                 from_algo: str, to_algo: str, systems: Any = None) -> dict:
    """Estate-wide arbitrary algorithm migration: who uses ``from_algo`` today —
    and, under ``migration``, the full migration answer read against the twin's
    hardware, software, connected systems and vendors (how to migrate, what can
    go wrong, who else is affected, parallel or direct). ``systems`` optionally
    narrows that answer to named systems (ids or names, comma-separated)."""
    from_algo, to_algo = str(from_algo or "").strip(), str(to_algo or "").strip()
    if not from_algo or not to_algo:
        raise ValueError("from_algo and to_algo are required")
    assets = _assets_using(list(snapshot.get("assets") or []), from_algo)
    evidence = [
        e for e in (snapshot.get("evidence") or [])
        if _algo_matches(e.get("algorithm") or e.get("normalized_algorithm"), from_algo)
    ]
    certs = [
        c for c in (snapshot.get("certificates") or [])
        if _algo_matches(c.get("public_key_algorithm"), from_algo)
    ]
    # Library support: does any twin asset already run the target?
    target_assets = _assets_using(list(snapshot.get("assets") or []), to_algo)
    target_libs = sorted({
        lib for a in target_assets
        for lib in (a.get("libraries") or {}) if isinstance(lib, str)
    })
    migration = simulate_migration(snapshot, from_algo=from_algo, to_algo=to_algo,
                                   systems=systems, now=now)
    result = _result(
        "algorithm_migration", {"from": from_algo, "to": to_algo,
                                **({"systems": systems} if systems else {})},
        affected={
            "assets": [a.get("asset_id") for a in assets],
            "evidence_records": len(evidence),
            "certificates": [c.get("fingerprint_sha256") for c in certs],
            "asset_count": len(assets),
        },
        impact={
            "target_already_in_use_by": [a.get("asset_id") for a in target_assets],
            "libraries_observed_with_target": target_libs,
            "key_sizes_in_play": sorted({
                int(e["key_size"]) for e in evidence
                if isinstance(e.get("key_size"), int)
            }),
        },
        unknowns=[
            "runtime/protocol negotiation is not modelled: an asset can use "
            f"{from_algo} at runtime without a matching evidence record",
            "hardware and HSM support for the target is read from recorded "
            "capability lists and declared PQC capability — not tested on the device",
            "library *versions* matter for migration feasibility; the twin "
            "records library names only",
        ])
    result["migration"] = migration
    return result


def scenario_certificate_expiry(snapshot: Mapping[str, Any], *, now: datetime,
                                horizon_days: int = 90) -> dict:
    """Certificates that expire within ``horizon_days`` — the renewal wave."""
    # A horizon beyond ~100 years is not a planning window; timedelta would
    # silently overflow on astronomical values and 500 the API.
    horizon_days = int(horizon_days)
    if abs(horizon_days) > 36500:
        raise ValueError("horizon_days out of range (±36500)")
    horizon = timedelta(days=horizon_days)
    expired, expiring, no_date, backlog = [], [], [], []
    for cert in snapshot.get("certificates") or []:
        not_after = _parse(cert.get("not_after"))
        if not_after is None:
            no_date.append(cert.get("fingerprint_sha256"))
            continue
        if not_after <= now:
            expired.append(cert)
        elif not_after <= now + horizon:
            expiring.append(cert)
        if str(cert.get("renewal_status") or "NONE").upper() not in ("DONE",):
            backlog.append(cert.get("fingerprint_sha256"))
    def _iss(c):  # issuer rollup
        return str(c.get("issuer") or "unknown")
    issuers: dict[str, int] = {}
    for cert in expired + expiring:
        issuers[_iss(cert)] = issuers.get(_iss(cert), 0) + 1
    return _result(
        "certificate_expiry", {"horizon_days": int(horizon_days), "as_of": now.isoformat()},
        affected={
            "expired": [c.get("fingerprint_sha256") for c in expired],
            "expiring_in_horizon": [c.get("fingerprint_sha256") for c in expiring],
            "renewal_backlog_not_done": backlog,
        },
        impact={
            "counts": {"expired": len(expired), "expiring": len(expiring),
                       "no_expiry_date": len(no_date), "backlog": len(backlog)},
            "by_issuer": dict(sorted(issuers.items())),
            "next_expiry": min(
                (c.get("not_after") for c in expiring), default=None),
        },
        unknowns=[
            "certificate-to-system linkage is not always recorded; affected "
            "services may be undercounted",
            "revocation status is snapshot data, not a live check",
        ] if no_date or True else [])


def scenario_key_rotation(snapshot: Mapping[str, Any], *, now: datetime,
                          algorithm: str = "") -> dict:
    """Rotate keys of one family (or all): what blocks a clean rotation."""
    algo = str(algorithm or "").strip()
    rows = _unique_evidence([
        e for e in (snapshot.get("evidence") or [])
        if not algo or _algo_matches(e.get("algorithm") or e.get("normalized_algorithm"), algo)
    ])
    hardcoded = _unique_evidence([e for e in rows if e.get("is_hardcoded_key")])
    sizes: dict[str, int] = {}
    for e in rows:
        if isinstance(e.get("key_size"), int):
            sizes[str(e.get("algorithm") or algo or "unknown")] = e["key_size"]
    return _result(
        "key_rotation", {"algorithm": algo or "all"},
        affected={
            "evidence_records": len(rows),
            "hardcoded_keys": [e.get("id") for e in hardcoded],
            "key_material_sites": [e.get("file_path") for e in hardcoded if e.get("file_path")],
        },
        impact={
            "blockers": {
                "hardcoded_key_count": len(hardcoded),
                "requires_code_change": len(hardcoded),
            },
            "key_sizes": sizes,
        },
        unknowns=[
            "key material that never appeared in scanned sources (HSM/KMS-held, "
            "generated at runtime) is invisible to source evidence",
            "rotation assumes the inventory of keys is complete; unscanned "
            "repositories are not represented",
        ])


def _hsm_devices(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """HSM entries from the hardware fleet section (live hardware engine).

    An entry counts when the row says it is an HSM (device_type) or carries
    an HSM observation (the ``hsm`` dict the scanner produces).
    """
    out: list[dict[str, Any]] = []
    for hw in snapshot.get("hardware") or []:
        hsm = hw.get("hsm") if isinstance(hw.get("hsm"), Mapping) else {}
        device_type = str(hw.get("device_type") or hsm.get("device_type") or "").lower()
        if device_type != "hsm" and not hsm:
            continue
        out.append({
            "asset_id": hw.get("asset_id"),
            "manufacturer": hw.get("manufacturer") or hsm.get("manufacturer"),
            "model": hw.get("model") or hsm.get("model"),
            "firmware": (hw.get("firmware") or {}).get("version")
            if isinstance(hw.get("firmware"), Mapping) else hsm.get("firmware"),
            "pqc_capability": str(hsm.get("pqc_capability") or "").upper() or None,
            "last_seen": hw.get("last_seen"),
        })
    return out


def _hardware_pqc_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """PQC capability of the HSM fleet, as declared to the hardware engine."""
    devices = _hsm_devices(snapshot)
    capable, not_capable, unknown = [], [], []
    for device in devices:
        verdict = str(device.get("pqc_capability") or "").upper()
        if not verdict or verdict == "UNKNOWN":
            unknown.append(device["asset_id"])
        elif "NOT" in verdict:
            not_capable.append(device["asset_id"])
        elif "HYBRID" in verdict or "READY" in verdict or "SUPPORTED" in verdict:
            capable.append(device["asset_id"])
        else:
            unknown.append(device["asset_id"])
    return {
        "hsms": len(devices),
        "pqc_capable": len(capable),
        "pqc_not_capable": len(not_capable),
        "pqc_unknown": len(unknown),
        "not_capable_devices": sorted(d for d in not_capable if d),
    }


def scenario_hsm_outage(snapshot: Mapping[str, Any], *, now: datetime) -> dict:
    """One HSM/partner becomes unavailable: who loses what capability."""
    dependent, signals = [], {}
    for asset in snapshot.get("assets") or []:
        usage = asset.get("usage") or {}
        capabilities = asset.get("capabilities") or {}
        hits = []
        for container, label in ((usage, "usage"), (capabilities, "capabilities")):
            if not isinstance(container, Mapping):
                continue
            for key, value in container.items():
                text = f"{key} {value if isinstance(value, str) else ''}".lower()
                if any(word in text for word in ("hsm", "kms", "cloudhsm", "keyvault",
                                                  "vault", "token", "payshield")):
                    hits.append(f"{label}.{key}")
        if hits:
            dependent.append(asset.get("asset_id"))
            signals[str(asset.get("asset_id"))] = sorted(set(hits))
    # The actual fleet that would be down — from the live hardware engine,
    # not inferred from keywords.
    fleet = _hsm_devices(snapshot)
    return _result(
        "hsm_outage", {"as_of": now.isoformat()},
        affected={
            "assets": dependent,
            "asset_count": len(dependent),
            "hardware_hsms": fleet,
            "hardware_hsm_count": len(fleet),
        },
        impact={
            "dependency_signals": signals,
            "operations_at_risk": ["signing", "key generation", "tokenisation"]
            if dependent or fleet else [],
            "hsm_fleet": [
                f"{d.get('manufacturer') or 'unknown'} {d.get('model') or ''}".strip()
                for d in fleet
            ],
        },
        unknowns=[
            "fallback and HA topology is not modelled: an asset with a KMS "
            "signal may have a working local fallback",
            "vendor-specific outage behaviour (rate limiting, caching) is not "
            "represented in the twin",
            "which crypto assets depend on which physical HSM is not modelled "
            "in the twin; the device list is the fleet, not the blast radius",
        ])


def scenario_vendor_compromise(snapshot: Mapping[str, Any], *, now: datetime,
                               vendor: str) -> dict:
    """A supply-chain vendor is compromised: the blast radius."""
    wanted = str(vendor or "").strip().lower()
    if not wanted:
        raise ValueError("vendor is required")
    vendors = snapshot.get("vendors") or []
    match = next((v for v in vendors if wanted in str(v.get("name") or "").lower()), None)
    vendor_id = (match or {}).get("id") or wanted
    linked_systems = [
        sv.get("system_id") for sv in (snapshot.get("system_vendors") or [])
        if sv.get("vendor_id") == vendor_id or wanted in str(sv.get("vendor_id") or "").lower()
    ]
    # Assets whose libraries mention the vendor name.
    asset_hits = []
    for asset in snapshot.get("assets") or []:
        libs = asset.get("libraries") or {}
        names = list(libs.keys()) if isinstance(libs, dict) else [str(x) for x in libs]
        if any(wanted in str(n).lower() for n in names):
            asset_hits.append(asset.get("asset_id"))
    system_names = sorted({
        str(s.get("name")) for s in (snapshot.get("systems") or [])
        if s.get("id") in linked_systems
    })
    return _result(
        "vendor_compromise", {"vendor": vendor, "matched_vendor": (match or {}).get("name")},
        affected={
            "systems": system_names,
            "assets_using_vendor_libraries": asset_hits,
            "criticality": (match or {}).get("criticality"),
        },
        impact={
            "dependency_type": sorted({
                str(sv.get("dependency_type")) for sv in (snapshot.get("system_vendors") or [])
                if sv.get("vendor_id") == vendor_id
            } - {"None"}),
        },
        unknowns=[
            "library names in the twin are not vendor-resolved; a vendored "
            "library under a different name is not counted",
            "transitive (vendor-of-vendor) exposure is not modelled",
        ] if match is None else [
            "transitive (vendor-of-vendor) exposure is not modelled",
        ])


def scenario_protocol_deprecation(snapshot: Mapping[str, Any], *, now: datetime,
                                  protocol: str = "TLS", min_version: str = "1.2") -> dict:
    """A protocol floor rises (e.g. TLS < 1.2 banned): what breaks."""
    proto, floor = str(protocol or "TLS").strip().lower(), str(min_version or "").strip()
    try:
        floor_num = float(floor)
    except ValueError:
        raise ValueError("min_version must be numeric, e.g. 1.2") from None

    def _below(version: Any) -> bool:
        # Wire formats spell versions "TLSv1.0", "tlsv1.1", "TLS 1.2";
        # the engine reads the first numeric version token. An endpoint with
        # no version (unprobed target) is never "below" — it is unknown.
        match = re.search(r"\d+(?:\.\d+)?", str(version or ""))
        if not match:
            return False
        try:
            return float(match.group(0)) < floor_num
        except ValueError:
            return False

    endpoints = [
        e for e in (snapshot.get("network_endpoints") or [])
        if proto in str(e.get("protocol") or "").lower() and _below(e.get("version") or e.get("tls_version"))
    ]
    assets = []
    for asset in snapshot.get("assets") or []:
        protocols = asset.get("protocols") or {}
        if not isinstance(protocols, Mapping):
            continue
        for key, value in protocols.items():
            if proto in str(key).lower() and (_below(key) or _below(value)):
                assets.append(asset.get("asset_id"))
                break
    return _result(
        "protocol_deprecation", {"protocol": protocol, "min_version": min_version},
        affected={
            "endpoints": [f"{e.get('host')}:{e.get('port')}" for e in endpoints],
            "assets": assets,
        },
        impact={"endpoint_count": len(endpoints), "asset_count": len(assets)},
        unknowns=[
            "endpoints observed only when a network scan ran against them; "
            "unprobed segments are absent",
            "clients that negotiate the old protocol but were never scanned "
            "are not represented",
        ])


def scenario_compliance_change(snapshot: Mapping[str, Any], *, now: datetime,
                               min_key_bits: int = 3072,
                               disallow_hashes: tuple[str, ...] = ("md5", "sha1")) -> dict:
    """Policy tightens: which current findings would flip to violations."""
    min_bits = int(min_key_bits)
    weak_size, weak_hash = [], []
    for e in _unique_evidence(snapshot.get("evidence") or []):
        if isinstance(e.get("key_size"), int) and 0 < e["key_size"] < min_bits:
            weak_size.append(e)
        algo = _algo_family(e.get("algorithm") or e.get("normalized_algorithm"))
        if any(h in algo for h in disallow_hashes):
            weak_hash.append(e)
    return _result(
        "compliance_change", {"min_key_bits": min_bits, "disallow_hashes": list(disallow_hashes)},
        affected={
            "newly_failing_key_size": [e.get("id") for e in weak_size],
            "newly_failing_hash": [e.get("id") for e in weak_hash],
        },
        impact={
            "counts": {"key_size": len(weak_size), "hash": len(weak_hash)},
            "current_key_sizes": sorted({
                e["key_size"] for e in snapshot.get("evidence") or []
                if isinstance(e.get("key_size"), int)
            }),
        },
        unknowns=[
            "this projection applies the two supplied rules only; the full "
            "policy engine must re-run for an authoritative verdict",
        ])


def scenario_attack_path(snapshot: Mapping[str, Any], *, now: datetime,
                         seed_asset: str, max_depth: int = 10) -> dict:
    """Compromise propagates from one asset through dependency edges (BFS)."""
    seed = str(seed_asset or "").strip()
    if not seed:
        raise ValueError("seed_asset is required")
    edges = (snapshot.get("dependencies") or [])
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        src, dst = str(edge.get("source") or ""), str(edge.get("target") or "")
        if src and dst:
            adjacency.setdefault(src, []).append(dst)
    frontier, seen = [seed], {seed}
    depth = 0
    by_depth: dict[int, list[str]] = {}
    while frontier and depth < int(max_depth):
        depth += 1
        nxt = []
        for node in frontier:
            for neighbour in sorted(adjacency.get(node, [])):
                if neighbour not in seen:
                    seen.add(neighbour)
                    nxt.append(neighbour)
        if nxt:
            by_depth[depth] = sorted(nxt)
        frontier = nxt
    return _result(
        "attack_path", {"seed_asset": seed, "max_depth": int(max_depth)},
        affected={"reachable_assets": sorted(seen - {seed}), "by_depth": by_depth},
        impact={"reachable_count": len(seen) - 1, "max_depth_reached": depth if by_depth else 0},
        unknowns=[
            "propagation follows recorded dependency edges only; unmodelled "
            "trust relationships (shared credentials, network reachability) "
            "are not edges",
        ] if edges else [
            "no dependency edges in the twin — propagation cannot be computed; "
            "materialise the dependency graph first",
        ],
        verdict="COMPUTED" if edges else "INSUFFICIENT_DATA")


def scenario_pqc_migration(snapshot: Mapping[str, Any], *, now: datetime) -> dict:
    """Estate-wide quantum-readiness: who is vulnerable, who is unknown."""
    buckets: dict[str, list[str]] = {"vulnerable": [], "ready": [], "unknown": []}
    vulnerable_algos: dict[str, int] = {}
    for asset in snapshot.get("assets") or []:
        status = asset.get("quantum_status") or {}
        verdict = (
            status.get("status") or status.get("verdict")
            if isinstance(status, Mapping) else str(status or "")
        )
        verdict = str(verdict or "").lower()
        if "vulnerab" in verdict or "at_risk" in verdict:
            buckets["vulnerable"].append(asset.get("asset_id"))
        elif "ready" in verdict or "pq" in verdict:
            buckets["ready"].append(asset.get("asset_id"))
        else:
            # Fall back to the algorithm families the twin recorded.
            algos = asset.get("algorithms") or {}
            names = list(algos.keys()) if isinstance(algos, dict) else []
            hits = [n for n in names if any(v in _algo_family(n) for v in _QUANTUM_VULNERABLE)]
            if hits:
                buckets["vulnerable"].append(asset.get("asset_id"))
                for hit in hits:
                    vulnerable_algos[str(hit)] = vulnerable_algos.get(str(hit), 0) + 1
            elif names:
                buckets["ready"].append(asset.get("asset_id"))
            else:
                buckets["unknown"].append(asset.get("asset_id"))

    # The hardware fleet grounds the migration in devices that must be
    # firmware-upgraded or replaced — from the live hardware engine, not
    # from vendor marketing claims.
    hardware_pqc = _hardware_pqc_summary(snapshot)
    return _result(
        "pqc_migration", {"as_of": now.isoformat()},
        affected=buckets,
        impact={
            "counts": {k: len(v) for k, v in buckets.items()},
            "vulnerable_algorithm_families": dict(sorted(vulnerable_algos.items())),
            "hardware": hardware_pqc,
        },
        unknowns=[
            "quantum classification falls back to algorithm names when the "
            "twin has no per-asset verdict; protocol-level exposure "
            "(e.g. TLS key exchange) may differ",
            *(
                ["hardware PQC capability is as declared by agents/management "
                  "APIs, not independently verified against the vendor's "
                  "certification matrix"]
                if hardware_pqc["hsms"] else []
            ),
        ])


def scenario_drift_regression(snapshot: Mapping[str, Any], *, now: datetime,
                              system_id: str, actions: list[str]) -> dict:
    """Re-score one system after hypothetical agility improvements."""
    system = next((s for s in snapshot.get("systems") or []
                   if s.get("id") == system_id or s.get("name") == system_id), None)
    if system is None:
        raise ValueError(f"system {system_id!r} not found in the estate snapshot")
    evidence = [
        e for e in (snapshot.get("evidence") or [])
        if e.get("system_id") == system.get("id") or system.get("id") is None
    ]
    current = calculate_agility_score(evidence, system)
    rows = [dict(e) for e in evidence]
    world = dict(system)
    assumptions: list[str] = []
    for action in actions or []:
        handler = ACTIONS.get(str(action))
        if handler is None:
            raise ValueError(f"unknown action {action!r}; available: {sorted(ACTIONS)}")
        assumptions.append(handler(rows, world))
    projected = calculate_agility_score(rows, world)
    return _result(
        "drift_regression", {"system_id": system_id, "actions": list(actions or [])},
        affected={"system": system.get("name")},
        impact={
            "current": {"agility_score": current["agility_score"], "category": current["category"]},
            "projected": {"agility_score": projected["agility_score"], "category": projected["category"]},
            "assumptions": assumptions,
        },
        unknowns=[
            "the projection re-runs the production scoring formula on a "
            "transformed copy; it commits nothing and cannot predict "
            "operational regressions the score does not capture",
        ])


#: The registry. Keys are the stable scenario ids; each entry documents its
#: inputs so the console can render a launcher without hard-coding types.
SCENARIOS: dict[str, dict[str, Any]] = {
    "algorithm_migration": {
        "name": "Algorithm migration",
        "description": ("Estate-wide impact of migrating one algorithm family to another, "
                        "checked against hardware, software, connected systems and vendors: "
                        "how to migrate, what can go wrong, and parallel or direct."),
        "inputs": {"from_algo": "text", "to_algo": "text", "systems": "text"},
        "run": scenario_algorithm_migration,
    },
    "certificate_expiry": {
        "name": "Certificate expiry wave",
        "description": "Certificates expiring within a horizon, and the renewal backlog.",
        "inputs": {"horizon_days": "number"},
        "run": scenario_certificate_expiry,
    },
    "key_rotation": {
        "name": "Key rotation",
        "description": "What blocks rotating keys of one family — hardcoded key sites first.",
        "inputs": {"algorithm": "text"},
        "run": scenario_key_rotation,
    },
    "hsm_outage": {
        "name": "HSM / KMS outage",
        "description": "Which assets lose which capabilities if the key custodian is unavailable — grounded in the hardware fleet the live engine knows.",
        "inputs": {},
        "run": scenario_hsm_outage,
    },
    "vendor_compromise": {
        "name": "Vendor compromise",
        "description": "Supply-chain blast radius for one vendor: linked systems and library users.",
        "inputs": {"vendor": "text"},
        "run": scenario_vendor_compromise,
    },
    "protocol_deprecation": {
        "name": "Protocol deprecation",
        "description": "What breaks when a protocol floor rises (e.g. TLS < 1.2 banned).",
        "inputs": {"protocol": "text", "min_version": "text"},
        "run": scenario_protocol_deprecation,
    },
    "compliance_change": {
        "name": "Compliance change",
        "description": "Which current findings would violate a tightened policy.",
        "inputs": {"min_key_bits": "number"},
        "run": scenario_compliance_change,
    },
    "attack_path": {
        "name": "Attack path",
        "description": "How compromise propagates from one asset through dependency edges.",
        "inputs": {"seed_asset": "text", "max_depth": "number"},
        "run": scenario_attack_path,
    },
    "pqc_migration": {
        "name": "PQC migration posture",
        "description": "Quantum-readiness of every twin asset: vulnerable, ready, unknown.",
        "inputs": {},
        "run": scenario_pqc_migration,
    },
    "drift_regression": {
        "name": "Agility drift regression",
        "description": "Re-score a system after hypothetical improvements, through the real formula.",
        "inputs": {"system_id": "text", "actions": "list"},
        "run": scenario_drift_regression,
    },
}


def run_scenario(scenario: str, snapshot: Mapping[str, Any], *, now: datetime,
                 params: Mapping[str, Any] | None = None) -> dict:
    """Dispatch one scenario by id. Raises ``ValueError`` on bad input."""
    entry = SCENARIOS.get(str(scenario))
    if entry is None:
        raise ValueError(f"unknown scenario {scenario!r}; available: {sorted(SCENARIOS)}")
    params = dict(params or {})
    unknown = set(params) - set(entry["inputs"])
    if unknown:
        raise ValueError(f"unknown input(s) for {scenario}: {sorted(unknown)}")
    try:
        return entry["run"](snapshot, now=now, **params)
    except TypeError as exc:
        # A missing required input must surface as the same ValueError the
        # API layer maps to HTTP 400, not as an internal TypeError.
        raise ValueError(f"{scenario}: {exc}") from exc


# ------------------------------------------------------------------ fidelity

def twin_fidelity(snapshot: Mapping[str, Any], *, now: datetime,
                  stale_after_seconds: int = 86400) -> dict:
    """Measure how well the twin tracks the estate — without inventing a diff.

    Computes what the twin itself can prove (coverage, staleness, journal
    activity, quantum mix) and declares the reconciliation diff — the one
    fidelity question that needs fresh observation — as an explicit honest
    unknown with the command that answers it.
    """
    assets = list(snapshot.get("assets") or [])
    systems = list(snapshot.get("systems") or [])
    ages: list[float] = []
    stale = 0
    for asset in assets:
        last = _parse(asset.get("last_event_at"))
        if last is None:
            stale += 1
            continue
        age = max(0.0, (now - last).total_seconds())
        ages.append(age)
        if age > stale_after_seconds:
            stale += 1
    ages.sort()

    def _pct(q: float) -> float:
        if not ages:
            return 0.0
        idx = min(len(ages) - 1, int(q * len(ages)))
        return round(ages[idx], 1)

    system_ids = {s.get("id") for s in systems}
    asset_ids = {a.get("asset_id") for a in assets}
    events = sum(int(a.get("event_count") or 0) for a in assets)
    covered_systems = len(system_ids & asset_ids)
    endpoints = list(snapshot.get("network_endpoints") or [])
    endpoints_observed = sum(1 for e in endpoints if e.get("observed", True))
    hardware = list(snapshot.get("hardware") or [])
    return {
        "schema": "cryptoscan.twin-fidelity/1",
        "as_of": now.isoformat(),
        "deterministic": True,
        "twin": {
            "hardware_assets": len(hardware),
            "assets": len(assets),
            "systems_known": len(systems),
            "systems_with_twin_state": covered_systems,
            "journal_events": events,
            "cbom_versions": {
                "max": max((int(a.get("cbom_version") or 1) for a in assets), default=0),
            },
        },
        "coverage": {
            "systems_covered_pct": round(100.0 * covered_systems / len(system_ids), 1)
            if system_ids else None,
            "assets_without_journal_activity": sum(
                1 for a in assets if not int(a.get("event_count") or 0)),
            "network_endpoints": len(endpoints),
            "network_endpoints_observed": endpoints_observed,
            "network_observed_pct": round(
                100.0 * endpoints_observed / len(endpoints), 1)
            if endpoints else None,
        },
        "staleness": {
            "stale_after_seconds": stale_after_seconds,
            "assets_stale": stale,
            "assets_fresh": len(assets) - stale,
            "age_seconds_p50": _pct(0.5),
            "age_seconds_max": round(ages[-1], 1) if ages else None,
        },
        "honest_unknowns": [
            "reconciliation against reality needs a fresh scan: trigger a scan "
            "of the estate and compare new evidence against the twin — this "
            "metric cannot be computed from the twin alone",
            "coverage counts systems registered in the inventory; systems "
            "nobody registered are invisible to both the estate and this "
            "number",
            *(
                [f"{len(endpoints) - endpoints_observed} of {len(endpoints)} "
                  "network endpoints were never observed by a scan: their "
                  "protocol posture is unknown, not healthy"]
                if endpoints and endpoints_observed < len(endpoints) else []
            ),
        ],
    }


def reconcile(snapshot: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Diff the twin's algorithm inventory against its own evidence store.

    This is the twin-vs-sources half of reconciliation: the algorithm
    families the twin claims (aggregated over its assets) against the
    families present in the last ingested evidence records. It catches the
    twin lagging its own inputs — an algorithm scanners keep finding that no
    twin asset reflects, or a twin claim nothing currently backs.

    It is deliberately *not* a claim of matching reality: evidence is only
    as fresh as the last scan, and the twin's asset ids and the evidence's
    system linkage are different id spaces, so the diff is portfolio-level.
    Identifiers are matched exactly as recorded (lowercased): ``rsa-2048``
    and ``rsa-3072`` are different entries by design — a key-size change is
    a real divergence. Both limits are stated as honest unknowns.
    """
    twin_families: dict[str, int] = {}
    for asset in snapshot.get("assets") or []:
        algos = asset.get("algorithms") or {}
        names = algos.keys() if isinstance(algos, Mapping) else []
        for name in names:
            family = _algo_family(name)
            if family:
                twin_families[family] = twin_families.get(family, 0) + 1

    # Prefer exact pre-aggregated counts when the adapter provides them: the
    # GROUP BY covers the whole evidence table, so a capped evidence-row list
    # on a very large estate cannot silently shrink this diff.
    counted = snapshot.get("evidence_algorithm_counts")
    if isinstance(counted, Mapping) and counted:
        evidence_families = {
            _algo_family(name): int(n or 0)
            for name, n in counted.items() if _algo_family(name)
        }
    else:
        evidence_families = {}
        for record in snapshot.get("evidence") or []:
            family = _algo_family(record.get("algorithm") or record.get("normalized_algorithm"))
            if family:
                evidence_families[family] = evidence_families.get(family, 0) + 1

    in_both = sorted(set(twin_families) & set(evidence_families))
    twin_only = sorted(set(twin_families) - set(evidence_families))
    evidence_only = sorted(set(evidence_families) - set(twin_families))

    if not twin_families or not evidence_families:
        # One side empty means there is nothing to compare — never verdict
        # "lags" off an absence.
        verdict = "INSUFFICIENT_DATA"
    elif not evidence_only and not twin_only:
        verdict = "IN_SYNC"
    elif evidence_only and not twin_only:
        # Scanners see families the twin has not absorbed yet.
        verdict = "TWIN_LAGS_EVIDENCE"
    elif twin_only and not evidence_only:
        # The twin claims families no current evidence backs.
        verdict = "EVIDENCE_LAGS_TWIN"
    else:
        verdict = "DIVERGED"

    return {
        "schema": "cryptoscan.twin-reconciliation/1",
        "as_of": now.isoformat(),
        "deterministic": True,
        "verdict": verdict,
        "twin_algorithm_families": dict(sorted(twin_families.items())),
        "evidence_algorithm_families": dict(sorted(evidence_families.items())),
        "families_in_both": in_both,
        "families_only_in_twin": twin_only,
        "families_only_in_evidence": evidence_only,
        "honest_unknowns": [
            "this diff compares the twin against the last *ingested* "
            "evidence, not against reality: only a fresh scan of the estate "
            "can prove the twin matches production",
            "twin asset ids and evidence system linkage are different id "
            "spaces; this diff is portfolio-level and cannot attribute a "
            "divergence to one system",
            *(
                ["evidence store is empty: nothing to reconcile against — "
                  "run a scan first"]
                if not evidence_families else []
            ),
            *(
                ["twin has no algorithm inventory: no live state has been "
                  "ingested for any asset"]
                if not twin_families else []
            ),
        ],
    }
