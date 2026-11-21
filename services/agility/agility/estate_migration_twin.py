"""The live estate graph, read as the migration simulation's twin.

``migration_simulation.simulate_migration`` reads one dict shape: the Digital Twin
snapshot (systems, crypto assets, hardware, vendors, dependencies, endpoints,
certificates). That snapshot is built from the platform's relational tables. A bank whose
estate arrives through agents — the Meridian sandbox, where one Cryptava agent per server
pushes a signed observation — has all of that in the **estate graph** instead: SYSTEM
nodes from the bank-approved mapping, hosts, services, packages, libraries, listening
endpoints with their negotiated TLS, certificates, the platform hardware a host runs on,
an HSM a host uses, the vendors behind each of them and the contracts from the asset
register.

This module translates one into the other, using **only evidenced edges**:

* **Membership** of a system is the closure over ``part_of`` / ``runs_on`` /
  ``hosted_on`` edges that end at the SYSTEM node (host → system, service → host,
  package → host, library → package, endpoint → host, database → host, certificate file
  → host), plus what a member ``exposes`` / ``terminates_tls_for``.
* **What a system uses** is one forward step from a member: ``uses_certificate``,
  ``uses_hsm``, ``uses_kms``, ``uses_key``, ``uses_crypto_library``, ``hosted_on`` (the
  platform hardware), ``provided_by`` (vendors) — and from those, ``issued_by`` (the CA)
  and the vendor that provides it.
* **Connections** between systems come from ``depends_on`` edges (declared by the bank's
  CMDB mapping or a deployment config) and from ``connects_to`` an outbound peer whose
  address is exactly the IP address of another system's host. A peer that matches no
  system stays an unregistered peer — never assigned by name resemblance.
* **Algorithms in use** come from evidence that states an ``algorithm`` (a negotiated
  cipher suite, a certificate key, an SSH host key) and from the key slots an HSM reports.
  A *capability list* (``supported_algorithms``) is never use: it feeds the library
  catalog and the hardware capability check instead.

A general-purpose server is listed as the system's platform, not as a key-holding
device: its CPU runs the target in software, and treating "no ML-KEM in the CPU flags" as
"cannot run ML-KEM" would invent a blocker. Only an HSM is checked as a device that holds
the keys.

Pure: reads plain dicts (``graph.assets()``, ``graph.relationships()``,
``graph.evidence()``) and writes nothing.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.estate-migration-twin/1"

#: subject → object edges along which the subject belongs to whatever the object belongs to
MEMBER_PREDICATES = frozenset({"part_of", "runs_on", "hosted_on"})
#: a member that exposes an endpoint makes the endpoint a member as well
EXPOSE_PREDICATES = frozenset({"exposes", "terminates_tls_for"})
#: one forward step from a member: things the system uses but does not contain
USE_PREDICATES = frozenset({"uses_certificate", "uses_hsm", "uses_kms", "uses_key",
                            "uses_crypto_library", "uses"})
#: member types that never pull further members in (they are shared infrastructure)
_NO_BACKWARD = frozenset({"SYSTEM", "VENDOR", "HARDWARE", "FIRMWARE", "HSM", "CA"})
#: asset types that carry crypto worth listing as a system's crypto asset
_CRYPTO_TYPES = frozenset({"CERTIFICATE", "KEY_METADATA", "LIBRARY", "HSM", "KMS_KEY",
                           "NETWORK_ENDPOINT", "CRYPTO_ASSET"})
#: evidence types that state a capability or a declaration, never use
_NOT_USE_EVIDENCE = frozenset({"VENDOR_DECLARED", "INFERRED", "UNKNOWN"})
_PLATFORM_HW_TYPES = frozenset({"HARDWARE"})

#: what the vendor supplies, from the type of the thing it provides
_SUPPLIES = {
    "HOST": "operating system", "LIBRARY": "crypto library", "PACKAGE": "software package",
    "HARDWARE": "hardware", "FIRMWARE": "firmware", "CA": "certificate authority",
    "CERTIFICATE": "certificate", "HSM": "HSM", "DATABASE": "database", "SERVICE": "software",
    "IMAGE": "container image", "CONTAINER": "container runtime",
}


def _attrs(asset: Mapping[str, Any]) -> dict[str, Any]:
    return dict(asset.get("attributes") or {})


def _identity(asset: Mapping[str, Any]) -> dict[str, Any]:
    return dict(asset.get("identity") or {})


def _days_until(value: Any, now: datetime) -> int | None:
    if not value:
        return None
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int((when - now).total_seconds() // 86400)


def _criticality(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in {"tier-0", "tier0", "tier 0", "critical", "mission-critical", "p0"}:
        return "critical"
    if text in {"tier-1", "tier1", "tier 1", "high", "p1"}:
        return "high"
    if text in {"tier-2", "tier2", "tier 2", "medium", "p2"}:
        return "medium"
    if text in {"tier-3", "tier3", "tier 3", "low", "p3"}:
        return "low"
    return text


def _host_addresses(asset: Mapping[str, Any]) -> set[str]:
    ident, attrs = _identity(asset), _attrs(asset)
    found = {str(ident.get("ip_address") or "").strip()}
    for value in attrs.get("ip_addresses") or []:
        found.add(str(value).strip())
    if attrs.get("primary_ip"):
        found.add(str(attrs["primary_ip"]).strip())
    return {item for item in found if item and item not in {"127.0.0.1", "::1", "0.0.0.0", "::"}}


def twin_from_estate(assets: Iterable[Mapping[str, Any]],
                     relationships: Iterable[Mapping[str, Any]],
                     evidence: Iterable[Mapping[str, Any]],
                     *, estate: str | None = None, projection_id: str | None = None,
                     now: datetime | None = None) -> dict[str, Any]:
    """The migration-simulation snapshot for one estate graph. Pure."""
    now = now or datetime.now(timezone.utc)
    nodes: dict[str, dict[str, Any]] = {str(a["asset_id"]): dict(a) for a in assets if a.get("asset_id")}
    edges = [dict(r) for r in relationships
             if str(r.get("subject")) in nodes and str(r.get("object")) in nodes]
    facts_by_target: dict[str, list[dict[str, Any]]] = {}
    for record in evidence:
        target = str(record.get("target") or "")
        if target in nodes:
            facts_by_target.setdefault(target, []).append(dict(record))

    incoming: dict[str, list[dict[str, Any]]] = {}
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        outgoing.setdefault(str(edge["subject"]), []).append(edge)
        incoming.setdefault(str(edge["object"]), []).append(edge)

    def kind(node_id: str) -> str:
        return str(nodes.get(node_id, {}).get("type") or "UNKNOWN")

    # ---- systems and their members ------------------------------------------------ #
    system_ids = sorted(node_id for node_id, node in nodes.items() if node.get("type") == "SYSTEM")
    members: dict[str, set[str]] = {}
    for sid in system_ids:
        seen: set[str] = {sid}
        queue: deque[str] = deque([sid])
        while queue:
            current = queue.popleft()
            if current != sid and kind(current) in _NO_BACKWARD:
                continue
            for edge in incoming.get(current, []):
                if edge.get("predicate") not in MEMBER_PREDICATES:
                    continue
                subject = str(edge["subject"])
                if subject in seen or kind(subject) == "SYSTEM":
                    continue
                seen.add(subject)
                queue.append(subject)
            for edge in outgoing.get(current, []):
                if current == sid or edge.get("predicate") not in EXPOSE_PREDICATES:
                    continue
                obj = str(edge["object"])
                if obj not in seen and kind(obj) == "NETWORK_ENDPOINT":
                    seen.add(obj)
                    queue.append(obj)
        seen.discard(sid)
        members[sid] = seen

    node_systems: dict[str, set[str]] = {}
    for sid, ids in members.items():
        for node_id in ids:
            node_systems.setdefault(node_id, set()).add(sid)

    # one forward step: what each system uses, and the platform it runs on
    uses: dict[str, set[str]] = {sid: set() for sid in system_ids}
    platform: dict[str, set[str]] = {sid: set() for sid in system_ids}
    hsm_users: dict[str, set[str]] = {}
    for sid in system_ids:
        for node_id in members[sid]:
            for edge in outgoing.get(node_id, []):
                obj, predicate = str(edge["object"]), str(edge.get("predicate"))
                if obj in members[sid]:
                    continue
                if predicate in USE_PREDICATES:
                    uses[sid].add(obj)
                    if kind(obj) == "HSM":
                        hsm_users.setdefault(obj, set()).add(sid)
                elif predicate == "hosted_on" and kind(obj) in _PLATFORM_HW_TYPES:
                    platform[sid].add(obj)
                elif predicate == "hosted_on" and kind(obj) == "HSM":
                    uses[sid].add(obj)
                    hsm_users.setdefault(obj, set()).add(sid)
    for sid in system_ids:
        for node_id in list(uses[sid]):
            node_systems.setdefault(node_id, set()).add(sid)

    # ---- algorithms in use, per node ------------------------------------------------ #
    def algorithms_of(node_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in facts_by_target.get(node_id, []):
            if str(record.get("evidence_type") or "").upper() in _NOT_USE_EVIDENCE:
                continue
            facts = record.get("facts") or {}
            name = facts.get("algorithm")
            if name and str(facts.get("role") or "") != "capability":
                counts[str(name)] = counts.get(str(name), 0) + 1
            for slot in facts.get("key_slots") or []:
                if isinstance(slot, Mapping) and slot.get("algorithm"):
                    counts[str(slot["algorithm"])] = counts.get(str(slot["algorithm"]), 0) + 1
        return counts

    def capabilities_of(node_id: str) -> list[str]:
        out: list[str] = []
        for record in facts_by_target.get(node_id, []):
            facts = record.get("facts") or {}
            for field in ("supported_algorithms", "mechanisms", "supported_mechanisms"):
                for item in facts.get(field) or []:
                    text = str(item).strip()
                    if text and text not in out:
                        out.append(text)
        return out

    def first_fact(node_id: str, *keys: str) -> Any:
        for record in facts_by_target.get(node_id, []):
            facts = record.get("facts") or {}
            for key in keys:
                if facts.get(key) not in (None, "", [], {}):
                    return facts[key]
        return None

    # ---- crypto assets ------------------------------------------------------------- #
    library_catalog: dict[str, dict[str, Any]] = {}
    twin_assets: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    vendor_of: dict[str, list[str]] = {}
    for edge in edges:
        if edge.get("predicate") == "provided_by" and kind(str(edge["object"])) == "VENDOR":
            vendor_of.setdefault(str(edge["subject"]), []).append(str(edge["object"]))

    def vendor_name(vendor_node: str) -> str:
        node = nodes.get(vendor_node, {})
        return str(_attrs(node).get("vendor") or _identity(node).get("name") or node.get("name") or vendor_node)

    crypto_nodes = sorted(
        node_id for node_id, node in nodes.items()
        if node.get("type") in _CRYPTO_TYPES or algorithms_of(node_id))
    for node_id in crypto_nodes:
        node = nodes[node_id]
        algorithms = algorithms_of(node_id)
        attrs, ident = _attrs(node), _identity(node)
        libraries: dict[str, Any] = {}
        if node.get("type") == "LIBRARY":
            lib_name = str(node.get("name") or ident.get("name") or node_id)
            version = attrs.get("version") or ident.get("version")
            libraries[lib_name] = str(version) if version not in (None, "", "unknown") else None
            providers = [vendor_name(v) for v in vendor_of.get(node_id, [])]
            library_catalog.setdefault(lib_name, {
                "algorithms": capabilities_of(node_id),
                "deprecated": False,
                "vendor": providers[0] if providers else None,
                "family": attrs.get("family"),
                "pqc_native": first_fact(node_id, "pqc_native"),
            })
        if node.get("type") in ("NETWORK_ENDPOINT", "LIBRARY") and not algorithms and not node_systems.get(node_id):
            continue
        twin_assets.append({
            "asset_id": node_id, "name": node.get("name"), "type": node.get("type"),
            "algorithms": algorithms, "libraries": libraries,
            "system_ids": sorted(node_systems.get(node_id, set())),
            "usage": {str(r.get("facts", {}).get("role")): True
                      for r in facts_by_target.get(node_id, []) if (r.get("facts") or {}).get("role")},
        })
        for record in facts_by_target.get(node_id, []):
            if str(record.get("evidence_type") or "").upper() in _NOT_USE_EVIDENCE:
                continue
            facts = record.get("facts") or {}
            names = [str(facts["algorithm"])] if facts.get("algorithm") else []
            names += [str(s["algorithm"]) for s in facts.get("key_slots") or []
                      if isinstance(s, Mapping) and s.get("algorithm")]
            owners = sorted(node_systems.get(node_id, set())) or [None]
            for algorithm in names:
                for owner in owners:
                    evidence_rows.append({
                        "evidence_id": record.get("evidence_id"), "algorithm": algorithm,
                        "system_id": owner, "asset_id": node_id,
                        "evidence_type": record.get("evidence_type"),
                        "file_path": facts.get("path") or facts.get("observed_at_location"),
                        "is_hardcoded_key": bool(facts.get("hardcoded") or facts.get("is_hardcoded_key")),
                    })

    # ---- hardware: HSMs (key holders) and the platform servers ------------------------ #
    hardware: list[dict[str, Any]] = []
    crypto_hardware: dict[str, list[str]] = {}
    for hsm_id in sorted(hsm_users):
        node = nodes[hsm_id]
        attrs, ident = _attrs(node), _identity(node)
        compliance = first_fact(hsm_id, "compliance") or {}
        hardware.append({
            "asset_id": hsm_id, "device_type": "hsm", "name": node.get("name"),
            "manufacturer": ident.get("vendor") or attrs.get("vendor"),
            "model": node.get("name"), "firmware": attrs.get("firmware") or first_fact(hsm_id, "firmware"),
            "crypto_capabilities": {"supported_algorithms": capabilities_of(hsm_id)},
            "hsm": {k: v for k, v in {
                "firmware": attrs.get("firmware") or first_fact(hsm_id, "firmware"),
                "fips_mode": attrs.get("fips_mode", compliance.get("fips_mode") if isinstance(compliance, Mapping) else None),
                "pqc_capability": attrs.get("pqc_capability") or first_fact(hsm_id, "pqc_capability"),
                "partition": ident.get("partition"),
            }.items() if v is not None},
        })
        crypto_hardware[hsm_id] = [hsm_id]

    platform_hardware: dict[str, list[dict[str, Any]]] = {}
    for sid in system_ids:
        rows = []
        for hw_id in sorted(platform[sid]):
            node = nodes[hw_id]
            attrs, ident = _attrs(node), _identity(node)
            rows.append({
                "asset_id": hw_id, "name": node.get("name"),
                "manufacturer": attrs.get("manufacturer") or attrs.get("vendor") or ident.get("vendor"),
                "model": attrs.get("model") or ident.get("model") or node.get("name"),
                "virtual": attrs.get("virtualization") or attrs.get("platform"),
                "vendors": sorted({vendor_name(v) for v in vendor_of.get(hw_id, [])}),
            })
        if rows:
            platform_hardware[sid] = rows

    # ---- vendors -------------------------------------------------------------------- #
    vendors: dict[str, dict[str, Any]] = {}
    vendor_crypto: dict[str, list[dict[str, Any]]] = {}
    system_vendors: dict[tuple[str, str], set[str]] = {}

    def vendor_key(vendor_node: str) -> str:
        return "vendor:" + vendor_name(vendor_node).lower()

    for subject, vendor_nodes in vendor_of.items():
        # the server, its CPU, NICs and firmware are the platform: their makers do not take
        # part in an algorithm change (an HSM does, and is not HARDWARE)
        if kind(subject) in ("HARDWARE", "FIRMWARE"):
            continue
        owners: set[str] = set(node_systems.get(subject, set()))
        # a CA reached through a certificate the system uses
        if kind(subject) == "CA":
            for edge in incoming.get(subject, []):
                if edge.get("predicate") == "issued_by":
                    owners |= node_systems.get(str(edge["subject"]), set())
        for vendor_node in vendor_nodes:
            key = vendor_key(vendor_node)
            node = nodes[vendor_node]
            attrs = _attrs(node)
            entry = vendors.setdefault(key, {
                "id": key, "name": vendor_name(vendor_node), "vendor_type": None,
                "products": [], "contract_state": None, "contract_end": None, "support_level": None,
            })
            product = str(attrs.get("product") or _identity(node).get("product") or node.get("name") or "")
            if product and product not in entry["products"]:
                entry["products"].append(product)
            for field in ("contract_state", "contract_end", "support_level"):
                if attrs.get(field) and not entry.get(field):
                    entry[field] = attrs[field]
            for record in facts_by_target.get(vendor_node, []):
                facts = record.get("facts") or {}
                if str(record.get("evidence_type") or "").upper() == "VENDOR_DECLARED":
                    pqc = facts.get("pqc_ready")
                    row = {
                        "algorithm": facts.get("algorithm"), "key_size": facts.get("key_size"),
                        "pqc_ready": bool(pqc), "pqc_ready_declared": pqc is not None,
                        "crypto_use_case": facts.get("use_case") or product or None,
                        "product": product, "version": facts.get("version"),
                        "support_lifecycle": facts.get("support_lifecycle"),
                    }
                    if row not in vendor_crypto.setdefault(key, []):
                        vendor_crypto[key].append(row)
                elif str(record.get("evidence_type") or "").upper() == "IMPORTED" and facts.get("contract_state"):
                    entry["contract_state"] = entry.get("contract_state") or facts.get("contract_state")
            for sid in owners:
                system_vendors.setdefault((sid, key), set()).add(_SUPPLIES.get(kind(subject), "supplier"))
    # a vendor with declaration rows that carry no crypto fact at all is not an inventory
    vendor_crypto = {key: [r for r in rows if r["algorithm"] or r["pqc_ready_declared"]]
                     for key, rows in vendor_crypto.items()}
    vendor_crypto = {key: rows for key, rows in vendor_crypto.items() if rows}

    # ---- network endpoints and certificates ----------------------------------------- #
    network_endpoints: list[dict[str, Any]] = []
    for sid in system_ids:
        for node_id in sorted(members[sid]):
            node = nodes[node_id]
            if node.get("type") != "NETWORK_ENDPOINT":
                continue
            ident, attrs = _identity(node), _attrs(node)
            if attrs.get("loopback_only"):
                continue
            handshake = next((r.get("facts") or {} for r in facts_by_target.get(node_id, [])
                              if (r.get("facts") or {}).get("role") == "negotiated-cipher-suite"
                              or ((r.get("facts") or {}).get("protocol") and (r.get("facts") or {}).get("algorithm"))),
                             None)
            host = ident.get("host")
            if host in (None, "", "0.0.0.0", "::", "*"):
                host_names = [nodes[h].get("name") for h in members[sid] if kind(h) == "HOST"]
                host = host_names[0] if host_names else node.get("name")
            network_endpoints.append({
                "system_id": sid, "asset_id": node_id, "host": host, "port": ident.get("port"),
                "protocol": ident.get("protocol") or attrs.get("transport"),
                "version": (handshake or {}).get("protocol"),
                "cipher_suite": (handshake or {}).get("algorithm"),
                "observed": handshake is not None,
                "app_protocol": attrs.get("app_protocol"),
            })

    certificates: dict[str, dict[str, Any]] = {}
    certificate_usages: dict[str, set[str]] = {}
    for node_id, node in nodes.items():
        if node.get("type") != "CERTIFICATE":
            continue
        ident, attrs = _identity(node), _attrs(node)
        fingerprint = str(ident.get("fingerprint_sha256") or node_id)
        not_after = attrs.get("not_after") or first_fact(node_id, "not_after")
        issuer = attrs.get("issuer") or first_fact(node_id, "issuer")
        public_key = attrs.get("public_key_algorithm") or next(
            ((r.get("facts") or {}).get("algorithm") for r in facts_by_target.get(node_id, [])
             if (r.get("facts") or {}).get("role") == "certificate-public-key"), None)
        certificates[fingerprint] = {
            "fingerprint_sha256": fingerprint, "asset_id": node_id,
            "subject": attrs.get("subject") or node.get("name"), "issuer": issuer,
            "public_key_algorithm": public_key,
            "public_key_bits": attrs.get("public_key_bits") or first_fact(node_id, "key_size"),
            "signature_algorithm": attrs.get("signature_algorithm"),
            "not_after": not_after, "days_until_expiry": _days_until(not_after, now),
        }
        owners = node_systems.get(node_id, set())
        if owners:
            certificate_usages[fingerprint] = set(owners)

    # ---- connections between systems ------------------------------------------------- #
    address_owner: dict[str, set[str]] = {}
    for sid in system_ids:
        for node_id in members[sid]:
            if kind(node_id) == "HOST":
                for address in _host_addresses(nodes[node_id]):
                    address_owner.setdefault(address, set()).add(sid)
    dependencies: dict[tuple[str, str, str], dict[str, Any]] = {}

    def link(src: str, dst: str, relation: str, provenance: str, via: str | None) -> None:
        if src == dst:
            return
        key = (src, dst, relation)
        if key not in dependencies:
            dependencies[key] = {"source": src, "target": dst, "type": relation,
                                 "provenance": provenance, "via": via}

    for edge in edges:
        predicate = str(edge.get("predicate"))
        subject, obj = str(edge["subject"]), str(edge["object"])
        if predicate == "depends_on":
            src_systems = {subject} if kind(subject) == "SYSTEM" else node_systems.get(subject, set())
            dst_systems = {obj} if kind(obj) == "SYSTEM" else node_systems.get(obj, set())
            for src in src_systems:
                for dst in dst_systems:
                    link(src, dst, "depends_on", str(edge.get("basis") or "DECLARED"),
                         nodes[obj].get("name") if kind(obj) != "SYSTEM" else None)
        elif predicate == "connects_to" and kind(obj) == "NETWORK_ENDPOINT":
            peer_host = str(_identity(nodes[obj]).get("host") or "")
            for src in node_systems.get(subject, set()):
                for dst in address_owner.get(peer_host, set()):
                    link(src, dst, "connects_to", str(edge.get("basis") or "NETWORK_OBSERVATION"),
                         f"{peer_host}:{_identity(nodes[obj]).get('port')}")

    # ---- everything a system is built from (the per-system BOM scope) ----------------- #
    # members + what they use + the platform server and its parts + the CA behind a member
    # certificate + the vendors of all of it. Used to slice the six BOMs per system; still
    # only evidenced edges, never a name match.
    system_members: dict[str, list[str]] = {}
    for sid in system_ids:
        scope: set[str] = set(members[sid]) | uses[sid] | platform[sid]
        frontier = list(platform[sid])
        for _ in range(2):  # the server's CPU/NIC/TPM/disks, and a disk's firmware
            nxt = []
            for hw in frontier:
                for edge in incoming.get(hw, []):
                    sub = str(edge["subject"])
                    if edge.get("predicate") == "part_of" and kind(sub) in ("HARDWARE", "FIRMWARE") \
                            and sub not in scope:
                        scope.add(sub)
                        nxt.append(sub)
            frontier = nxt
        for node_id in list(scope):
            for edge in outgoing.get(node_id, []):
                obj = str(edge["object"])
                if edge.get("predicate") == "issued_by" and kind(obj) == "CA":
                    scope.add(obj)
                elif edge.get("predicate") == "connects_to" and kind(obj) == "NETWORK_ENDPOINT" \
                        and node_id in members[sid]:
                    scope.add(obj)
        for node_id in list(scope):
            scope.update(vendor_of.get(node_id, []))
        scope.discard(sid)
        system_members[sid] = sorted(scope)

    # ---- systems -------------------------------------------------------------------- #
    systems = []
    for sid in system_ids:
        node = nodes[sid]
        attrs = _attrs(node)
        hosts = sorted(str(nodes[h].get("name")) for h in members[sid] if kind(h) == "HOST")
        systems.append({
            "id": sid, "name": node.get("name"), "owner": attrs.get("owner") or node.get("owner"),
            "criticality": _criticality(attrs.get("criticality")),
            "business_service": attrs.get("business_service"),
            "environment": node.get("environment"),
            "hosts": hosts,
            "vendor_ids": sorted({key for (s, key) in system_vendors if s == sid}),
            "coverage_status": "COMPLETE" if hosts else "PARTIAL",
        })

    unowned = sorted(node_id for node_id in crypto_nodes
                     if algorithms_of(node_id) and not node_systems.get(node_id))
    return {
        "schema": SCHEMA,
        "source": "ESTATE_GRAPH",
        "estate": estate,
        "projection_id": projection_id,
        "systems": systems,
        "assets": twin_assets,
        "evidence": evidence_rows,
        "hardware": hardware,
        "crypto_hardware": crypto_hardware,
        "platform_hardware": platform_hardware,
        "vendors": sorted(vendors.values(), key=lambda v: v["name"].lower()),
        "system_vendors": [{"system_id": sid, "vendor_id": key,
                            "dependency_type": ", ".join(sorted(kinds))}
                           for (sid, key), kinds in sorted(system_vendors.items())],
        "vendor_crypto": vendor_crypto,
        "vendor_dependencies": [],
        "dependencies": sorted(dependencies.values(), key=lambda d: (d["source"], d["target"], d["type"])),
        "network_endpoints": network_endpoints,
        "system_members": system_members,
        "certificates": sorted(certificates.values(), key=lambda c: c["fingerprint_sha256"]),
        "certificate_usages": {fp: sorted(ids) for fp, ids in sorted(certificate_usages.items())},
        "business_processes": {},
        "library_catalog": library_catalog,
        "software_deployments": [],
        "source_coverage": {"collections": {}},
        "graph_counts": {
            "assets": len(nodes), "relationships": len(edges),
            "evidence": sum(len(v) for v in facts_by_target.values()),
            "systems": len(system_ids), "unowned_crypto_assets": len(unowned),
        },
    }


def migration_context(twin: Mapping[str, Any]) -> dict[str, Any]:
    """What the migration form can offer: systems with what each holds, algorithms in use."""
    per_system: dict[str, dict[str, int]] = {}
    totals: dict[str, dict[str, Any]] = {}
    unowned: dict[str, int] = {}
    for row in twin.get("evidence") or []:
        algorithm = str(row.get("algorithm") or "")
        if not algorithm:
            continue
        sid = row.get("system_id")
        entry = totals.setdefault(algorithm, {"algorithm": algorithm, "evidence": 0, "systems": set()})
        entry["evidence"] += 1
        if sid:
            entry["systems"].add(str(sid))
            per_system.setdefault(str(sid), {})
            per_system[str(sid)][algorithm] = per_system[str(sid)].get(algorithm, 0) + 1
        else:
            unowned[algorithm] = unowned.get(algorithm, 0) + 1
    names = {str(s["id"]): s.get("name") for s in twin.get("systems") or []}
    systems = []
    for system in twin.get("systems") or []:
        sid = str(system["id"])
        assets = [a for a in twin.get("assets") or [] if sid in (a.get("system_ids") or [])]
        systems.append({
            "system_id": sid, "name": system.get("name"), "owner": system.get("owner"),
            "criticality": system.get("criticality"), "hosts": system.get("hosts") or [],
            "crypto_assets": len(assets),
            "certificates": sum(1 for a in assets if a.get("type") == "CERTIFICATE"),
            "libraries": sum(1 for a in assets if a.get("type") == "LIBRARY"),
            "endpoints": sum(1 for e in twin.get("network_endpoints") or [] if str(e.get("system_id")) == sid),
            "hsms": sum(1 for hw_id, ids in (twin.get("crypto_hardware") or {}).items()
                        if any(sid in (a.get("system_ids") or []) for a in twin.get("assets") or []
                               if a.get("asset_id") in ids)),
            "servers": len((twin.get("platform_hardware") or {}).get(sid) or []),
            "vendors": len(system.get("vendor_ids") or []),
            "algorithms": dict(sorted(per_system.get(sid, {}).items(), key=lambda kv: (-kv[1], kv[0]))),
        })
    algorithms = sorted(
        ({"algorithm": a["algorithm"], "evidence": a["evidence"],
          "systems": sorted(names.get(s) or s for s in a["systems"])} for a in totals.values()),
        key=lambda a: (-len(a["systems"]), -a["evidence"], a["algorithm"].lower()))
    return {
        "systems": systems,
        "algorithms": algorithms,
        "unowned_algorithms": dict(sorted(unowned.items(), key=lambda kv: (-kv[1], kv[0]))),
        "dependencies": [{"from": names.get(str(d["source"])) or d["source"],
                          "to": names.get(str(d["target"])) or d["target"],
                          "type": d.get("type"), "provenance": d.get("provenance")}
                         for d in twin.get("dependencies") or []],
        "counts": dict(twin.get("graph_counts") or {}),
    }


__all__ = ["SCHEMA", "twin_from_estate", "migration_context"]
