"""The Digital Twin read through its six BOMs, with a migration laid over it.

One page answers three questions about a bank estate, all from the same evidence graph:

1. **What is in the twin** — every component of the CBOM, NBOM, SBOM, HBOM, VBOM and the
   technology BOM, with the business systems each one belongs to.
2. **What breaks if we migrate** ``from_algo`` → ``to_algo`` — each component gets a status
   (AFFECTED, AT_RISK, UNKNOWN, READY, NOT_AFFECTED) with the cause and the action, and the
   migration engine's problems are filed under the BOM layer they come from.
3. **What the connections do to it** — for every system-to-system connection, which side
   changes, what happens to the other side, the components both sides share (an HSM, a
   CA, a vendor, a library), and how far the change ripples through the dependency chain.

Rules carried over from the twin and the projections, never relaxed here:

* a component belongs to a system only through an evidenced edge (``system_members``);
* SBOM presence is not use — a package that is merely installed is NOT_AFFECTED;
* CBOM layers never merge — each artefact is judged on its own layer and usage state;
* a capability-only artefact (``SUPPORTED``) has nothing to cut over: it is AT_RISK until
  it is switched off, never AFFECTED;
* VBOM entries are declared, not observed, and the answer says so;
* a missing capability is UNKNOWN, never "fine".

Pure: reads the BOM set, the migration twin and the relationships; writes nothing.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Any, Iterable, Mapping

from agility.migration_simulation import (
    _matches,
    _supports,
    _version_rank,
    algorithm_profile,
    simulate_migration,
)

SCHEMA = "cryptoscan.twin-bom-impact/1"

#: the order the page shows them in: crypto first, then where it travels, runs and comes from
BOM_ORDER: tuple[str, ...] = ("CBOM", "NBOM", "SBOM", "HBOM", "VBOM", "TECHBOM")
BOM_LABEL = {
    "CBOM": "Cryptography",
    "NBOM": "Network",
    "SBOM": "Software",
    "HBOM": "Hardware",
    "VBOM": "Vendors",
    "TECHBOM": "Technology",
}

#: the BOM layer a migration problem belongs to
CODE_BOM = {
    "TARGET_ROLE_MISMATCH": "CBOM",
    "TARGET_COVERS_PART": "CBOM",
    "HARDCODED_KEYS": "CBOM",
    "CERTIFICATES_TO_REISSUE": "CBOM",
    "STORED_DATA": "CBOM",
    "EXISTING_SIGNATURES": "CBOM",
    "TLS_VERSION_TOO_OLD": "NBOM",
    "HANDSHAKE_SIZE": "NBOM",
    "ENDPOINT_CLIENTS_UNSEEN": "NBOM",
    "LIBRARY_LACKS_TARGET": "SBOM",
    "LIBRARY_DEPRECATED": "SBOM",
    "HARDWARE_CANNOT_RUN_TARGET": "HBOM",
    "HARDWARE_CAPABILITY_UNKNOWN": "HBOM",
    "VENDOR_NOT_READY": "VBOM",
    "VENDOR_RELEASE_NOT_READY": "VBOM",
    "VENDOR_CAPABILITY_UNKNOWN": "VBOM",
    "VENDOR_SUB_TIER": "VBOM",
    "VENDOR_NO_SUPPORT_CONTRACT": "VBOM",
    "PEER_OUTSIDE_CHANGE": "TECHBOM",
}

STATUSES: tuple[str, ...] = ("AFFECTED", "AT_RISK", "UNKNOWN", "READY", "NOT_AFFECTED")
_STATUS_RANK = {status: rank for rank, status in enumerate(STATUSES)}
_SEVERITY_RANK = {"BLOCKER": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

#: rows listed per BOM; the counts always cover every component
MAX_COMPONENTS = 400
#: hops the ripple walks along system connections
MAX_RIPPLE_HOPS = 4

#: types that run the changed software and are redeployed with it
_RUNS_THE_CHANGE = frozenset({"HOST", "APPLICATION", "SERVICE", "CONTAINER", "POD", "DATABASE",
                              "LOAD_BALANCER", "API_GATEWAY", "MESSAGE_BROKER", "IMAGE"})
_PLATFORM = frozenset({"HARDWARE", "FIRMWARE"})
#: what a shared component is called on the connection view
#: (only things that carry or decide crypto — a shared package or server is not listed)
_SHARED_KIND = {
    "HSM": "HSM", "KMS_KEY": "KMS key", "CA": "certificate authority", "CERTIFICATE": "certificate",
    "LIBRARY": "crypto library", "NETWORK_ENDPOINT": "network endpoint", "LOAD_BALANCER": "load balancer",
    "API_GATEWAY": "API gateway", "MESSAGE_BROKER": "message broker", "DATABASE": "database",
    "VENDOR": "vendor",
}
_SHARED_ORDER = {kind: rank for rank, kind in enumerate(_SHARED_KIND)}
#: shared components listed per connection
MAX_SHARED = 12


def _attrs(component: Mapping[str, Any]) -> dict[str, Any]:
    return dict(component.get("attributes") or {})


def _identity(component: Mapping[str, Any]) -> dict[str, Any]:
    return dict(component.get("identity") or {})


def _join(parts: Iterable[Any]) -> str:
    return " · ".join(str(p) for p in parts if p not in (None, "", [], {}))


def _names(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [str(k) for k in value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)] if value else []


def _bom_of(code: str) -> str:
    return CODE_BOM.get(code, "TECHBOM")


def _issue(finding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "code": finding.get("code"), "severity": finding.get("severity"),
        "title": finding.get("title"), "cause": finding.get("detail"),
        "effect": finding.get("if_ignored"), "action": finding.get("mitigation"),
        "who_acts": finding.get("who_acts"), "system": finding.get("system"),
        "subject": finding.get("subject"), "basis": finding.get("basis"),
        "systems": [str(finding["system"])] if finding.get("system") else [],
    }


def _grouped(issues: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per problem: the same library lacking the target in six systems is one issue
    naming six systems, not six rows."""
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for issue in issues:
        key = (issue.get("code"), issue.get("title"), issue.get("subject"), issue.get("severity"))
        if key not in merged:
            merged[key] = {**issue, "systems": list(issue.get("systems") or [])}
            continue
        row = merged[key]
        for system in issue.get("systems") or []:
            if system not in row["systems"]:
                row["systems"].append(system)
        if row.get("system") != issue.get("system"):
            row["system"] = None
    for row in merged.values():
        row["systems"].sort()
    return list(merged.values())


def simulate_bom_impact(bom_set: Mapping[str, Any], twin: Mapping[str, Any],
                        relationships: Iterable[Mapping[str, Any]], *,
                        from_algo: str | None = None, to_algo: str | None = None,
                        systems: Any = None, now: datetime | None = None) -> dict[str, Any]:
    """Every BOM of the twin, and — when an algorithm change is given — what it does to each.

    ``bom_set`` is ``EstateGraph.project_all()``; ``twin`` is ``twin_from_estate(...)`` over
    the same graph; ``relationships`` is ``graph.relationships()``. Without ``from_algo`` and
    ``to_algo`` the answer is the twin's inventory and connections with no statuses.
    """
    source = str(from_algo or "").strip()
    target = str(to_algo or "").strip()
    if bool(source) != bool(target):
        raise ValueError("give both from_algo and to_algo, or neither")
    simulating = bool(source)
    edges = [dict(e) for e in relationships]
    boms = dict((bom_set or {}).get("boms") or {})

    # ---- the twin: systems, membership, lookups ------------------------------------- #
    twin_systems = list(twin.get("systems") or [])
    system_name = {str(s["id"]): str(s.get("name") or s["id"]) for s in twin_systems}
    system_members = {str(k): set(v) for k, v in (twin.get("system_members") or {}).items()}
    member_of: dict[str, set[str]] = {}
    for sid, members in system_members.items():
        for node_id in members:
            member_of.setdefault(str(node_id), set()).add(sid)
    for sid in system_name:
        member_of.setdefault(sid, set()).add(sid)
    for asset in twin.get("assets") or []:
        for sid in asset.get("system_ids") or []:
            member_of.setdefault(str(asset["asset_id"]), set()).add(str(sid))

    twin_asset = {str(a["asset_id"]): a for a in twin.get("assets") or []}
    cert_by_asset = {str(c.get("asset_id")): c for c in twin.get("certificates") or [] if c.get("asset_id")}
    endpoint_by_asset = {str(e.get("asset_id")): e for e in twin.get("network_endpoints") or []
                         if e.get("asset_id")}
    vendor_by_name = {str(v.get("name") or "").lower(): v for v in twin.get("vendors") or []}
    vendor_by_id = {str(v.get("id")): v for v in twin.get("vendors") or []}
    platform_of: dict[str, set[str]] = {}
    for sid, hardware in (twin.get("platform_hardware") or {}).items():
        for hw in hardware or []:
            platform_of.setdefault(str(hw.get("asset_id")), set()).add(str(sid))
    dependencies = [d for d in twin.get("dependencies") or []
                    if str(d.get("source")) != str(d.get("target"))]
    neighbours: dict[str, set[str]] = {}
    for dep in dependencies:
        a, b = str(dep["source"]), str(dep["target"])
        neighbours.setdefault(a, set()).add(b)
        neighbours.setdefault(b, set()).add(a)
    outgoing: dict[str, list[dict[str, Any]]] = {}
    incoming: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        outgoing.setdefault(str(edge.get("subject")), []).append(edge)
        incoming.setdefault(str(edge.get("object")), []).append(edge)

    def names_of(sids: Iterable[str]) -> list[str]:
        return sorted(system_name.get(s, s) for s in sids)

    # ---- the migration ---------------------------------------------------------------- #
    migration: dict[str, Any] | None = None
    change: set[str] = set()
    strategy_of: dict[str, str] = {}
    why_of: dict[str, list[str]] = {}
    lib_support: dict[str, dict[str, Any]] = {}
    hw_support: dict[str, dict[str, Any]] = {}
    vendor_readiness: dict[str, dict[str, Any]] = {}
    uses_target_sys: set[str] = set()
    target_profile = algorithm_profile(target) if simulating else {}
    if simulating:
        migration = simulate_migration(twin, from_algo=source, to_algo=target, systems=systems, now=now)
        for report in migration.get("systems") or []:
            sid = str(report.get("system_id"))
            change.add(sid)
            strategy_of[sid] = str(report.get("strategy"))
            why_of[sid] = list(report.get("why_in_change") or [])
            details = report.get("twin") or {}
            for lib in (details.get("software") or {}).get("libraries") or []:
                lib_support.setdefault(str(lib.get("name")), lib)
            for device in details.get("hardware") or []:
                hw_support.setdefault(str(device.get("asset_id")), device)
        for vendor in migration.get("vendor_impact") or []:
            vendor_readiness[str(vendor.get("vendor_id"))] = vendor
            vendor_readiness.setdefault("name:" + str(vendor.get("name") or "").lower(), vendor)
        for entry in migration.get("connected_impact") or []:
            if entry.get("uses_target"):
                uses_target_sys.add(str(entry.get("system_id")))

    # which assets hold the old algorithm, from the CBOM artefacts and the twin's crypto assets
    holds: dict[str, list[str]] = {}
    if simulating:
        for artifact in (boms.get("CBOM") or {}).get("components") or []:
            if artifact.get("type") == "CRYPTO_ARTIFACT" and _matches(artifact.get("algorithm"), source) \
                    and artifact.get("usage_state") != "SUPPORTED":
                holds.setdefault(str(artifact.get("asset_id")), []).append(str(artifact.get("algorithm")))
        for asset_id, asset in twin_asset.items():
            for name in _names(asset.get("algorithms")):
                if _matches(name, source):
                    holds.setdefault(asset_id, []).append(name)
        holds = {k: sorted(set(v)) for k, v in holds.items()}

    def cert_alg_hits(asset_id: str) -> tuple[bool, bool]:
        cert = cert_by_asset.get(asset_id) or {}
        key_alg = cert.get("public_key_algorithm")
        sig_alg = cert.get("signature_algorithm")
        return (_matches(key_alg, source) or _matches(_join(holds.get(asset_id, [])), source),
                _matches(sig_alg, source))

    affected_certs: set[str] = set()
    if simulating:
        for asset_id in set(cert_by_asset) | {a for a, t in twin_asset.items() if t.get("type") == "CERTIFICATE"}:
            key_hit, sig_hit = cert_alg_hits(asset_id)
            if key_hit or sig_hit:
                affected_certs.add(asset_id)

    # ---- per-component status --------------------------------------------------------- #
    def verdict(status: str, impact: str, action: str | None = None) -> dict[str, Any]:
        return {"status": status, "impact": impact, "action": action}

    def classify_artifact(c: Mapping[str, Any]) -> dict[str, Any]:
        alg = c.get("algorithm")
        state = str(c.get("usage_state") or "")
        layer = str(c.get("layer") or "").replace("_", " ").lower()
        where = c.get("asset_name") or c.get("asset_id")
        if _matches(alg, source):
            if state == "SUPPORTED":
                return verdict("AT_RISK",
                               f"{alg} is only enabled as a capability on {where} ({layer}); "
                               "no traffic has to move, but it stays available to a downgrade",
                               f"switch {source} off here once every peer uses {target}")
            roles = set(algorithm_profile(alg)["roles"])
            how = (f"reissue or re-sign with {target}" if "signature" in roles and
                   "signature" in target_profile.get("roles", []) else
                   f"offer {target} beside {alg} (hybrid), then remove {alg}"
                   if "key_establishment" in roles else f"replace {alg} with {target}")
            return verdict("AFFECTED",
                           f"{alg} is {state.lower() or 'in use'} at the {layer} layer of {where}; "
                           f"this use must move to {target}", how)
        if _matches(alg, target):
            return verdict("READY", f"{where} already uses {target} at the {layer} layer")
        return verdict("NOT_AFFECTED", f"{alg or 'this artefact'} is not {source}")

    def classify(c: Mapping[str, Any]) -> dict[str, Any]:
        aid = str(c.get("asset_id"))
        typ = str(c.get("type"))
        sids = member_of.get(aid, set())
        moving = sids & change
        held = holds.get(aid, [])
        in_names = ", ".join(names_of(moving)) if moving else None

        if typ == "SYSTEM":
            if aid in change:
                return verdict("AFFECTED",
                               f"holds {source}: " + "; ".join(why_of.get(aid) or ["in the change set"]),
                               {"PARALLEL": f"run {source} and {target} side by side, then retire {source}",
                                "DIRECT": f"switch straight to {target}",
                                "BLOCKED": "resolve the blockers first — see the issues"}.get(
                                   strategy_of.get(aid, ""), None))
            linked = neighbours.get(aid, set()) & change
            if linked:
                return verdict("AT_RISK",
                               f"does not hold {source} itself, but is connected to "
                               f"{', '.join(names_of(linked))}, which changes",
                               "confirm the connection accepts " + target)
            return verdict("NOT_AFFECTED", f"holds no {source} and is not connected to a system that changes")

        if typ == "VENDOR":
            name = str(_attrs(c).get("vendor") or _identity(c).get("name") or c.get("name") or "").lower()
            vendor = vendor_readiness.get("vendor:" + name) or vendor_readiness.get("name:" + name)
            if vendor is None:
                return verdict("NOT_AFFECTED", "supplies nothing a changing system uses for this algorithm")
            readiness = vendor.get("readiness")
            status = {"NOT_READY": "AFFECTED", "RELEASE_NOT_READY": "AFFECTED", "READY": "READY"}.get(
                readiness, "UNKNOWN")
            return verdict(status,
                           f"{str(readiness).replace('_', ' ').lower()} for {target} — supplies "
                           f"{', '.join(vendor.get('dependency_types') or []) or 'components'} to "
                           f"{', '.join(vendor.get('systems') or [])} (declared, not observed)",
                           vendor.get("needs_to"))

        if typ == "CERTIFICATE":
            key_hit, sig_hit = cert_alg_hits(aid)
            cert = cert_by_asset.get(aid) or {}
            if key_hit or sig_hit:
                what = []
                if key_hit:
                    what.append(f"its key is {cert.get('public_key_algorithm') or source}"
                                + (f"-{cert['public_key_bits']}" if cert.get("public_key_bits") else ""))
                if sig_hit:
                    what.append(f"it is signed with {cert.get('signature_algorithm')}")
                expiry = cert.get("days_until_expiry")
                return verdict("AFFECTED",
                               "; ".join(what) + (f"; expires in {expiry} days" if expiry is not None else ""),
                               f"reissue with a {target} key once relying parties trust the new chain")
            if _matches(cert.get("public_key_algorithm"), target):
                return verdict("READY", f"already carries a {target} key")
            return verdict("NOT_AFFECTED", f"carries no {source}")

        if typ == "CA":
            issued = sorted(str(e["subject"]) for e in incoming.get(aid, [])
                            if e.get("predicate") == "issued_by" and str(e["subject"]) in affected_certs)
            if issued:
                return verdict("AFFECTED",
                               f"issued {len(issued)} certificate(s) that must be reissued with {target}; "
                               f"whether this CA can issue {target} certificates is not recorded",
                               f"stand up (or confirm) a {target}-capable issuing chain before reissuing")
            return verdict("NOT_AFFECTED", f"issued no certificate that carries {source}")

        if aid in hw_support:
            device = hw_support[aid]
            support = device.get("target_support")
            if support == "NOT_SUPPORTED":
                return verdict("AFFECTED", f"holds the keys and cannot run {target}: {device.get('basis')}",
                               "upgrade the firmware or replace the device before the cut-over")
            if support in ("SUPPORTED", "SUPPORTED_DECLARED"):
                return verdict("READY", f"can run {target}: {device.get('basis')}")
            return verdict("UNKNOWN",
                           f"{'holds affected keys; ' if device.get('holds_affected_keys') else ''}"
                           f"its {target} support is unknown — {device.get('basis')}",
                           f"ask the vendor for the firmware that supports {target}")

        if typ == "LIBRARY":
            lib = lib_support.get(str(c.get("name")))
            if lib is None and moving:
                caps = [str(x) for x in (twin.get("library_catalog") or {}).get(str(c.get("name")), {}).get(
                    "algorithms") or []]
                lib = {"target_support": "SUPPORTED" if _supports(caps, target) else
                       ("NOT_SUPPORTED" if caps else "UNKNOWN"),
                       "basis": ("implements " + ", ".join(caps[:6])) if caps else "no capability list recorded"}
            if lib is not None:
                support = lib.get("target_support")
                if support == "NOT_SUPPORTED":
                    return verdict("AFFECTED", f"does not implement {target} ({lib.get('basis')})",
                                   f"upgrade to a release that implements {target} and rebuild what links it")
                if support == "SUPPORTED":
                    return verdict("READY", f"implements {target}")
                return verdict("UNKNOWN", f"whether it implements {target} is unknown ({lib.get('basis')})",
                               "confirm the library's capability")
            return verdict("NOT_AFFECTED", "not used by a system that changes")

        if typ == "NETWORK_ENDPOINT":
            ep = endpoint_by_asset.get(aid) or {}
            reasons = []
            if _matches(ep.get("cipher_suite"), source) or held:
                reasons.append(f"negotiates {ep.get('cipher_suite') or ', '.join(held)}")
            presented = [str(e["object"]) for e in outgoing.get(aid, [])
                         if e.get("predicate") == "uses_certificate" and str(e["object"]) in affected_certs]
            if presented:
                reasons.append(f"presents {len(presented)} certificate(s) that carry {source}")
            rank = _version_rank(ep.get("version"))
            if (target_profile.get("pqc") and "key_establishment" in target_profile.get("roles", [])
                    and rank is not None and rank < 1.3 and (moving or reasons)):
                reasons.append(f"negotiates {ep.get('version')}, and {target} key exchange needs TLS 1.3")
            if reasons:
                return verdict("AFFECTED", "; ".join(reasons) + " — every client that connects here must accept "
                               f"{target}, and those clients are not in the twin",
                               f"serve {source} and {target} together on this endpoint until its clients move")
            return verdict("NOT_AFFECTED", f"carries no {source}")

        if held:
            return verdict("AFFECTED", f"holds {', '.join(held)}", f"move to {target}")
        if typ in _PLATFORM and (platform_of.get(aid, set()) & change or moving):
            return verdict("NOT_AFFECTED",
                           f"platform of {in_names or ', '.join(names_of(platform_of.get(aid, set()) & change))}: "
                           f"{target} runs in software on it, so it is not a blocker")
        if moving and typ in _RUNS_THE_CHANGE:
            return verdict("AT_RISK", f"part of {in_names}, which moves to {target}",
                           "redeploy with the new crypto configuration and re-test")
        if moving and typ == "PACKAGE":
            return verdict("NOT_AFFECTED", f"installed in {in_names}; presence is not crypto use, and no "
                                           f"{source} use is recorded for it")
        if moving:
            return verdict("NOT_AFFECTED", f"{in_names} changes, but this component carries no {source}")
        return verdict("NOT_AFFECTED", f"holds no {source}" + (" and its systems do not change" if sids else ""))

    # ---- details shown per component ------------------------------------------------ #
    def detail(c: Mapping[str, Any]) -> str:
        typ = str(c.get("type"))
        attrs, ident = _attrs(c), _identity(c)
        aid = str(c.get("asset_id"))
        if typ == "CRYPTO_ARTIFACT":
            size = f"-{c['key_size']}" if c.get("key_size") else ""
            return _join([f"{c.get('algorithm') or '?'}{size}", c.get("role"), c.get("protocol"),
                          str(c.get("layer") or "").replace("_", " ").lower() or None, c.get("usage_state")])
        if typ == "CERTIFICATE":
            cert = cert_by_asset.get(aid) or {}
            key = cert.get("public_key_algorithm") or attrs.get("public_key_algorithm")
            bits = cert.get("public_key_bits") or attrs.get("public_key_bits")
            return _join([f"{key}-{bits}" if key and bits else key,
                          f"signed {cert.get('signature_algorithm')}" if cert.get("signature_algorithm") else None,
                          f"expires in {cert['days_until_expiry']} d" if cert.get("days_until_expiry") is not None else None,
                          cert.get("issuer")])
        if typ == "NETWORK_ENDPOINT":
            ep = endpoint_by_asset.get(aid) or {}
            where = f"{ep.get('host') or ident.get('host')}:{ep.get('port') or ident.get('port')}"
            return _join([where, ep.get("version") or ident.get("protocol"), ep.get("cipher_suite")])
        if typ == "VENDOR":
            vendor = vendor_by_name.get(str(attrs.get("vendor") or ident.get("name") or "").lower()) or {}
            return _join([attrs.get("product") or ident.get("product"),
                          f"contract {str(vendor.get('contract_state') or attrs.get('contract_state') or '').replace('_', ' ').lower()}"
                          if (vendor.get("contract_state") or attrs.get("contract_state")) else None])
        if typ == "SYSTEM":
            return _join([attrs.get("owner") or c.get("owner"), attrs.get("criticality"),
                          attrs.get("business_service")])
        if typ in ("HARDWARE", "FIRMWARE", "HSM"):
            return _join([attrs.get("manufacturer") or ident.get("vendor"), attrs.get("model"),
                          attrs.get("firmware") or attrs.get("version") or ident.get("version")])
        if typ in ("LIBRARY", "PACKAGE", "IMAGE"):
            return _join([attrs.get("version") or ident.get("version"), ident.get("ecosystem") or attrs.get("family")])
        if typ == "CA":
            return _join([attrs.get("subject") or ident.get("subject") or ident.get("name"),
                          attrs.get("key_algorithm") or attrs.get("public_key_algorithm")])
        if typ == "HOST":
            return _join([attrs.get("os") or attrs.get("os_name") or ident.get("hostname"),
                          ", ".join(str(x) for x in attrs.get("addresses") or []) or ident.get("ip")])
        where = (f"{ident['host']}:{ident['port']}" if ident.get("host") and ident.get("port")
                 else ident.get("host"))
        return _join([where, attrs.get("engine") or ident.get("engine"), attrs.get("version"),
                      c.get("environment")])

    # ---- the six BOMs ------------------------------------------------------------- #
    issues_by_bom: dict[str, list[dict[str, Any]]] = {bom: [] for bom in BOM_ORDER}
    if migration is not None:
        for finding in migration.get("problems") or []:
            issues_by_bom[_bom_of(str(finding.get("code")))].append(_issue(finding))

    #: asset id → (type, name), from every BOM and the twin
    asset_info: dict[str, tuple[str, Any]] = {
        aid: (str(a.get("type") or ""), a.get("name")) for aid, a in twin_asset.items()}
    for projection in boms.values():
        for component in projection.get("components") or []:
            if component.get("type") != "CRYPTO_ARTIFACT" and component.get("asset_id"):
                asset_info[str(component["asset_id"])] = (str(component.get("type") or ""),
                                                          component.get("name"))

    component_status: dict[str, str] = {}
    bom_rows: dict[str, dict[str, Any]] = {}
    per_system_counts: dict[str, dict[str, dict[str, int]]] = {sid: {} for sid in system_name}
    for bom in BOM_ORDER:
        projection = boms.get(bom) or {}
        rows = []
        for component in projection.get("components") or []:
            is_artifact = component.get("type") == "CRYPTO_ARTIFACT"
            aid = str(component.get("asset_id"))
            sids = sorted(member_of.get(aid, set()))
            row = {
                "ref": str(component.get("artifact_id") or aid),
                "asset_id": aid,
                "name": str(component.get("asset_name") if is_artifact else component.get("name") or aid),
                "type": component.get("asset_type") if is_artifact else component.get("type"),
                "kind": "crypto" if is_artifact else "asset",
                "detail": detail(component),
                "systems": names_of(sids),
                "status": None, "impact": None, "action": None,
            }
            if simulating:
                row.update(classify_artifact(component) if is_artifact else classify(component))
                previous = component_status.get(aid)
                if previous is None or _STATUS_RANK[row["status"]] < _STATUS_RANK[previous]:
                    component_status[aid] = row["status"]
            for sid in sids:
                counts = per_system_counts.setdefault(sid, {}).setdefault(bom, {"components": 0, "affected": 0})
                counts["components"] += 1
                if row["status"] == "AFFECTED":
                    counts["affected"] += 1
            rows.append(row)
        rows.sort(key=lambda r: (_STATUS_RANK.get(r["status"], 9), not r["systems"], str(r["type"]), r["name"]))
        status_counts = {status: sum(1 for r in rows if r["status"] == status) for status in STATUSES} \
            if simulating else None
        if simulating and bom == "NBOM":
            exposed = [r for r in rows if r["status"] == "AFFECTED" and r["type"] == "NETWORK_ENDPOINT"]
            if exposed:
                issues_by_bom["NBOM"].append({
                    "code": "ENDPOINT_CLIENTS_UNSEEN", "severity": "MEDIUM",
                    "title": f"{len(exposed)} endpoint(s) carry {source} to clients the twin cannot see",
                    "cause": "the clients of a network endpoint (branches, partners, customers' apps) are not "
                             f"assets in the twin, so their {target} support cannot be checked",
                    "effect": f"a client that cannot negotiate {target} loses the connection when {source} "
                              "is switched off",
                    "action": f"serve {source} and {target} together and watch which clients still pick {source}",
                    "who_acts": "the endpoint owners", "system": None,
                    "subject": ", ".join(r["name"] for r in exposed[:5]), "basis": "NBOM"})
        issues = sorted(_grouped(issues_by_bom[bom]), key=lambda i: (_SEVERITY_RANK.get(str(i["severity"]), 9),
                                                           str(i["title"])))
        extra: dict[str, Any] = {}
        if bom == "VBOM":
            extra = {"declared_capabilities": list(projection.get("declared_capabilities") or [])[:200],
                     "contracts": list(projection.get("contracts") or [])[:200]}
        if bom == "CBOM":
            extra = {"by_layer": projection.get("by_layer") or {},
                     "by_usage_state": projection.get("by_usage_state") or {}}
        bom_rows[bom] = {
            "bom": bom, "label": BOM_LABEL[bom],
            "question": projection.get("question"), "boundary": projection.get("boundary"),
            "total": len(rows), "relationships": len(projection.get("relationships") or []),
            "by_type": (projection.get("counts") or {}).get("by_type") or {},
            "status_counts": status_counts, "issues": issues,
            "components": rows[:MAX_COMPONENTS], "truncated": len(rows) > MAX_COMPONENTS,
            **extra,
        }

    # ---- connections between systems ------------------------------------------------ #
    def shared_between(a: str, b: str) -> list[dict[str, Any]]:
        out = []
        for node_id in sorted(system_members.get(a, set()) & system_members.get(b, set())):
            comp_type, name = asset_info.get(node_id, ("", None))
            if comp_type not in _SHARED_KIND:
                continue
            if comp_type == "VENDOR" and not any(
                    str(name or "").lower().startswith(v) for v in vendor_by_name if v):
                continue  # a hardware maker is platform, not a party to the change
            out.append({"asset_id": node_id, "name": name or node_id, "type": comp_type,
                        "kind": _SHARED_KIND[comp_type], "status": component_status.get(node_id)})
        out.sort(key=lambda s: (_STATUS_RANK.get(s["status"] or "", 9), _SHARED_ORDER[s["type"]], str(s["name"])))
        return out[:MAX_SHARED]

    def endpoints_of(sid: str) -> list[str]:
        return sorted(_join([f"{e.get('host')}:{e.get('port')}", e.get("version"), e.get("cipher_suite")])
                      for e in twin.get("network_endpoints") or [] if str(e.get("system_id")) == sid)[:5]

    connections = []
    for dep in dependencies:
        a, b = str(dep["source"]), str(dep["target"])
        an, bn = system_name.get(a, a), system_name.get(b, b)
        shared = shared_between(a, b)
        row: dict[str, Any] = {
            "caller_id": a, "caller": an, "provider_id": b, "provider": bn,
            "relation": dep.get("type"), "provenance": dep.get("provenance"), "via": dep.get("via"),
            "provider_endpoints": endpoints_of(b), "shared": shared,
            "caller_in_change": a in change, "provider_in_change": b in change,
            "status": None, "severity": None, "effect_on_caller": None, "effect_on_provider": None,
            "action": None, "issues": [],
        }
        if simulating:
            changed_shared = [s for s in shared if s["status"] in ("AFFECTED", "UNKNOWN")]
            if a in change and b in change:
                row.update(status="BOTH_CHANGE", severity="MEDIUM",
                           effect_on_caller=f"{an} moves to {target} too; if {bn} switches first and {an} lags, "
                                            f"{an}'s calls to {bn} fail during the gap",
                           effect_on_provider=f"{bn} must keep accepting {source} until {an} has moved",
                           action=f"upgrade {bn} (the provider) first with both algorithms on, then {an}, "
                                  f"then retire {source} on the connection")
            elif a in change:
                ready = b in uses_target_sys
                row.update(status="CALLER_CHANGES", severity="MEDIUM" if ready else "HIGH",
                           effect_on_caller=f"{an} will offer {target}; if it stops offering {source}, its calls "
                                            f"to {bn} fail unless {bn} accepts {target}",
                           effect_on_provider=(f"{bn} already uses {target} elsewhere, but this connection is not "
                                               "confirmed to negotiate it" if ready else
                                               f"{bn} is not part of this change and has no evidence of {target} "
                                               f"support — it keeps expecting {source}"),
                           action=f"keep {source} enabled on {an}'s connection to {bn} until {bn} confirms {target}")
            elif b in change:
                row.update(status="PROVIDER_CHANGES", severity="HIGH",
                           effect_on_caller=f"once {bn} serves {target} (new keys, certificates or key exchange), "
                                            f"{an} must accept it — if it cannot, every call from {an} to {bn} fails",
                           effect_on_provider=f"{bn} has to run {source} and {target} side by side while {an} "
                                              "still calls it the old way",
                           action=f"run {bn} in parallel ({source} + {target}) until {an} is upgraded and tested")
            elif changed_shared:
                row.update(status="SHARED_COMPONENT", severity="MEDIUM",
                           effect_on_caller=f"{an} does not change, but shares "
                                            f"{', '.join(s['kind'] + ' ' + str(s['name']) for s in changed_shared[:3])} "
                                            f"with {bn}; changing it changes it for both",
                           effect_on_provider=f"{bn} shares the same component(s); plan the change once for both",
                           action="schedule the shared component's change with both owners")
            else:
                row.update(status="NOT_AFFECTED", severity="INFO",
                           effect_on_caller=f"neither {an} nor {bn} is in this change; the connection is untouched",
                           effect_on_provider=None, action=None)
            if changed_shared and row["status"] != "SHARED_COMPONENT":
                row["effect_on_caller"] += (f"; they also share "
                                            f"{', '.join(s['kind'] + ' ' + str(s['name']) for s in changed_shared[:3])}, "
                                            "which changes for both")
            row["issues"] = [i for i in issues_by_bom["TECHBOM"]
                             if {str(i.get("system")), str(i.get("subject"))} == {an, bn}]
        connections.append(row)
    connections.sort(key=lambda c: (_SEVERITY_RANK.get(str(c["severity"]), 9), c["caller"], c["provider"]))

    # ---- ripple: how far the change travels through the connections ------------------ #
    ripple = []
    if simulating and change:
        seen = {sid: (0, [system_name.get(sid, sid)]) for sid in change}
        queue = deque(sorted(change))
        while queue:
            current = queue.popleft()
            hops, path = seen[current]
            if hops >= MAX_RIPPLE_HOPS:
                continue
            for nxt in sorted(neighbours.get(current, set())):
                if nxt not in seen:
                    seen[nxt] = (hops + 1, path + [system_name.get(nxt, nxt)])
                    queue.append(nxt)
        for sid, (hops, path) in seen.items():
            if sid in change:
                continue
            ripple.append({
                "system_id": sid, "name": system_name.get(sid, sid), "hops": hops,
                "path": path,
                "effect": ("directly connected to a system that changes — its connection must accept "
                           f"{target} or keep {source}") if hops == 1 else
                          (f"{hops} hops away: not changed itself, but it depends on a chain that does — "
                           "an outage on the way reaches it"),
            })
        ripple.sort(key=lambda r: (r["hops"], r["name"]))

    # ---- systems ---------------------------------------------------------------- #
    system_rows = []
    for system in twin_systems:
        sid = str(system["id"])
        callers = sorted(system_name.get(str(d["source"]), str(d["source"])) for d in dependencies
                         if str(d["target"]) == sid)
        calls = sorted(system_name.get(str(d["target"]), str(d["target"])) for d in dependencies
                       if str(d["source"]) == sid)
        system_rows.append({
            "id": sid, "name": system_name[sid], "owner": system.get("owner"),
            "criticality": system.get("criticality"), "business_service": system.get("business_service"),
            "environment": system.get("environment"), "hosts": system.get("hosts") or [],
            "vendors": [vendor_by_id.get(v, {}).get("name") or v for v in system.get("vendor_ids") or []],
            "calls": calls, "called_by": callers,
            "bom_counts": {bom: (per_system_counts.get(sid) or {}).get(bom, {"components": 0, "affected": 0})
                           for bom in BOM_ORDER},
            "in_change": sid in change if simulating else None,
            "strategy": strategy_of.get(sid) if simulating else None,
            "why_in_change": why_of.get(sid, []) if simulating else [],
        })
    system_rows.sort(key=lambda s: (not s["in_change"] if simulating else False, s["name"]))

    unowned = sum(1 for bom in BOM_ORDER for r in bom_rows[bom]["components"] if not r["systems"])
    unknowns = list((migration or {}).get("unknowns") or [])
    unknowns.append("VBOM capabilities and contracts are what vendors and the register declare — "
                    "not observed on the estate")
    if unowned:
        unknowns.append(f"{unowned} listed component(s) belong to no system through an evidenced edge, so "
                        "no connection effect can be traced for them")
    if not dependencies:
        unknowns.append("no system-to-system connection is recorded — connected-system effects cannot be shown")

    return {
        "schema": SCHEMA,
        "estate": twin.get("estate"),
        "projection_id": (bom_set or {}).get("projection_id") or twin.get("projection_id"),
        "change": {"from_algo": source, "to_algo": target} if simulating else None,
        "strategy": (migration or {}).get("strategy"),
        "headline": (migration or {}).get("headline"),
        "problem_counts": (migration or {}).get("problem_counts"),
        "plan": (migration or {}).get("plan") or [],
        "totals": {
            "systems": len(system_rows), "connections": len(connections),
            "components": {bom: bom_rows[bom]["total"] for bom in BOM_ORDER},
            "affected": {bom: (bom_rows[bom]["status_counts"] or {}).get("AFFECTED", 0) for bom in BOM_ORDER}
            if simulating else None,
            "systems_in_change": len(change) if simulating else None,
        },
        "systems": system_rows,
        "boms": [bom_rows[bom] for bom in BOM_ORDER],
        "connections": connections,
        "ripple": ripple,
        "unknowns": sorted(set(unknowns)),
        "statuses": list(STATUSES),
        "mutates_nothing": True,
    }
