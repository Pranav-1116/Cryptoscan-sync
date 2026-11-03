"""From the stored inventory to a TechBOM estate, with provenance carried and never invented.

:mod:`cbom.techbom` refuses to join two assets because they were seen together, and
:mod:`cbom.techbom_queries` answers questions on that graph. Both have so far been fed a
fixture. This module is the bridge to the real thing: it takes the inventory the platform
already gathers (systems, crypto assets, hardware, vendors, certificates, dependency edges
and the scan's software rows) and produces a `cryptoscan.techbom-estate/1` document that
``build()`` accepts.

The hard part is not mapping field names. It is that a **stored row is not an
observation**. A `CryptoAsset` row is the residue of a scan that happened earlier, read back
through a database; calling that `OBSERVED` would be the relationship-poisoning mistake this
whole build exists to prevent. So the adapter maps each row to the weakest basis its own
provenance supports and refuses the row when it has none:

============================  =========================  ==================
inventory row                 basis                      class
============================  =========================  ==================
`System` / registration edge  `operator-registration`    `IMPORTED`
`SystemDependency` manual     `operator-registration`    `IMPORTED`
`SystemDependency` imported   `cmdb-import`              `IMPORTED`
`SystemDependency` discovered `agent-inventory`           `CONFIGURED`
software row, code import     `code-analysis`            `CONFIGURED`
software row, manifest only   `sbom-import`              `IMPORTED`
crypto asset                  its own `source_basis`     `IMPORTED`
hardware / HSM observation    `cmdb-import`              `IMPORTED`
vendor row                    `vendor-datasheet`         `VENDOR_DECLARED`
============================  =========================  ==================

Three consequences worth stating, because they are the point:

* **nothing here is ever `OBSERVED`.** `OBSERVED` belongs to a packet capture, a runtime
  probe or a process trace — things this adapter does not have. If a future collector hands
  over its own evidence, it can say `OBSERVED` itself; the store cannot say it on the
  collector's behalf.
* **a dependency edge with no provenance is refused, by name.** `SystemDependency.source`
  is `manual|discovered|imported`; an empty or unrecognised value is not a basis, and the
  edge is reported in ``skipped`` rather than drawn as if somebody had verified it.
* **a certificate row is a certificate, not a key and not an algorithm.** The stored shape
  carries a fingerprint and a subject. The adapter creates the `CERTIFICATE` asset and
  stops: no `PUBLIC_KEY`, no `USES_ALGORITHM`, because inventing them would be exactly the
  "certificate ≠ application crypto" shortcut the review forbids.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cbom.techbom import ASSET_TYPES, ESTATE_SCHEMA, _norm

#: the asset kind a hardware row becomes, by the fields it carries
DEVICE_KINDS: dict[str, str] = {
    "HSM": "HSM",
    "TPM": "TPM",
    "HOST": "HOST",
    "SERVER": "PHYSICAL_SERVER",
    "PHYSICAL_SERVER": "PHYSICAL_SERVER",
    "VM": "VM",
    "FIRMWARE": "FIRMWARE",
    "NETWORK": "HOST",
    "APPLIANCE": "PHYSICAL_SERVER",
}

#: `SystemDependency.source` → the basis it supports
DEPENDENCY_BASIS: dict[str, str] = {
    "discovered": "agent-inventory",
    "imported": "cmdb-import",
    "manual": "operator-registration",
}

#: software row `origin` → the basis it supports
ORIGIN_BASIS: dict[str, str] = {
    "CODE_IMPORT": "code-analysis",
    "CODE_AND_MANIFEST": "code-analysis",
    "MANIFEST_DECLARED": "sbom-import",
}

#: a source_basis the store may already carry, mapped to a basis this model knows
STORED_BASIS: dict[str, str] = {
    "import": "cmdb-import",
    "imported": "cmdb-import",
    "legacy_import": "cmdb-import",
    "scan": "sbom-import",
    "sbom": "sbom-import",
    "agent": "agent-inventory",
    "api": "api-poll",
    "vendor": "vendor-datasheet",
}


def _skipped(kind: str, subject: Any, reason: str) -> dict[str, Any]:
    return {"kind": kind, "subject": subject, "reason": reason}


def _evidence(*candidates: Any) -> list[str]:
    out: list[str] = []
    for value in candidates:
        if isinstance(value, (list, tuple, set)):
            out.extend(_norm(item) for item in value if _norm(item))
        elif _norm(value):
            out.append(_norm(value))
    seen: list[str] = []
    for value in out:
        if value not in seen:
            seen.append(value)
    return seen


def _row_basis(row: Mapping[str, Any], *, default: str) -> str | None:
    """The basis a stored row's own provenance supports, or ``None`` for none."""
    declared = _norm(row.get("source_basis") or row.get("basis")).lower()
    if declared:
        if declared in STORED_BASIS:
            return STORED_BASIS[declared]
        return None
    return default


# --------------------------------------------------------------------------- #
# the adapter
# --------------------------------------------------------------------------- #

def from_inventory(inventory: Mapping[str, Any] | None, *, environment: Any = None,
                   estate_id: Any = None, expected: Mapping[str, int] | None = None,
                   gaps: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """One gathered inventory → an estate document plus what could not be placed."""
    inv = inventory if isinstance(inventory, Mapping) else {}
    environment_text = (_norm(environment) or _norm(inv.get("environment"))
                        or "PRODUCTION").upper()
    estate_id_text = _norm(estate_id) or "estate:" + environment_text.lower()
    scan = inv.get("scan") if isinstance(inv.get("scan"), Mapping) else {}
    scan_id = _norm(scan.get("software", {}).get("scan_id")) if isinstance(
        scan.get("software"), Mapping) else ""
    assets: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(kind: str, name: str, *, evidence_ids: list[str], version: Any = None,
            owner: Any = None, location: Any = None, status: Any = "ACTIVE",
            **attributes: Any) -> str | None:
        key = f"{kind}:{_norm(name).lower()}:{environment_text.lower()}"
        if not _norm(name):
            skipped.append(_skipped(kind, name, "the row has no name, so it has no identity"))
            return None
        if kind not in ASSET_TYPES:
            skipped.append(_skipped(kind, name, f"{kind} is not a technology asset type"))
            return None
        if key in seen:
            return key  # one row per identity; a repeat is the same asset, not a conflict
        if not evidence_ids:
            skipped.append(_skipped(
                kind, name,
                "no evidence reference on the row: an asset with no evidence id is a claim"))
            return None
        seen.add(key)
        assets.append({"kind": kind, "name": _norm(name), "version": _norm(version)
                       or None, "owner": _norm(owner) or None,
                       "location": _norm(location) or None, "status": _norm(status)
                       or "ACTIVE", "evidence_ids": evidence_ids,
                       "attributes": {key_: value for key_, value in attributes.items()
                                      if value not in (None, "", [], {})}})
        return key

    def chain(source: str | None, relation: str, target: str | None, *, basis: str,
              evidence_ids: list[str], note: Any = None) -> None:
        if not source or not target or source == target:
            return
        claims.append({"from": source, "relation": relation, "to": target,
                       "basis": basis, "evidence_ids": evidence_ids or ["estate-row"],
                       "note": _norm(note) or None})

    # ---- systems ---------------------------------------------------------- #
    systems: dict[str, str] = {}
    for row in inv.get("applications") or []:
        if not isinstance(row, Mapping):
            continue
        identifier = _norm(row.get("id"))
        key = add("BUSINESS_SYSTEM", row.get("name"),
                  evidence_ids=_evidence(identifier and f"system:{identifier}"),
                  version=row.get("version"), owner=row.get("owner"),
                  location=row.get("environment"), criticality=row.get("criticality"),
                  business_unit=row.get("business_unit"),
                  scan_target=row.get("scan_target") or row.get("target"),
                  supplier=row.get("supplier"))
        if key and identifier:
            systems[identifier] = key

    # ---- registrations, resolved once the assets have identities ----------- #
    registrations: list[Mapping[str, Any]] = [row for row in
                                              (inv.get("system_assets") or [])
                                              if isinstance(row, Mapping)]

    # ---- crypto assets ---------------------------------------------------- #
    crypto_keys: dict[str, str] = {}
    for row in inv.get("crypto") or []:
        if not isinstance(row, Mapping):
            continue
        basis = _row_basis(row, default="cmdb-import")
        algorithm = _norm(row.get("algorithm"))
        key_size = row.get("key_size")
        label = f"{algorithm}-{key_size}" if algorithm and key_size else algorithm
        if not basis:
            skipped.append(_skipped(
                "CRYPTO_ASSET", label or row.get("id"),
                f"its source_basis {row.get('source_basis')!r} is not one this model can "
                "classify, so it cannot be placed with a confidence"))
            continue
        identifier = _norm(row.get("id"))
        evidence = _evidence(f"crypto:{identifier}" if identifier else None,
                            row.get("evidence_ref"), row.get("evidence_links"))
        key = add("CRYPTO_ASSET", label, evidence_ids=evidence,
                  status="ACTIVE",
                  evidence_type=("RUNTIME_OBSERVED"
                                 if _norm(row.get("evidence_type")).upper()
                                 == "RUNTIME_OBSERVED" else "STATIC_OBSERVED"),
                  purpose=row.get("purpose"), mode=row.get("mode"),
                  file_path=row.get("file_path"),
                  confidence=row.get("confidence"))
        if not key:
            continue
        if identifier:
            crypto_keys[identifier] = key
        library = _norm(row.get("library"))
        if library:
            library_key = add("CRYPTO_LIBRARY", library, evidence_ids=evidence,
                              version=None)
            chain(library_key, "PROVIDES_ALGORITHM", key, basis=basis,
                  evidence_ids=evidence, note="the library row the asset was found through")
        host = _norm(row.get("asset"))
        if host:
            host_key = add("HOST", host, evidence_ids=evidence)
            chain(key, "FOUND_ON", host_key, basis=basis, evidence_ids=evidence)
        application = _norm(row.get("application"))
        if application:
            app_key = add("APPLICATION", application, evidence_ids=evidence)
            chain(key, "FOUND_ON", app_key, basis=basis, evidence_ids=evidence)

    for row in registrations:
        system_key = systems.get(_norm(row.get("system_id")))
        identifier = _norm(row.get("asset_id"))
        crypto_key = crypto_keys.get(identifier)
        if not system_key or not crypto_key:
            skipped.append(_skipped(
                "REGISTRATION", f"{row.get('system_id')} → {identifier}",
                "the registration names a system or an asset this inventory does not "
                "hold, and an edge to an undeclared node is refused"))
            continue
        claims.append({
            "from": system_key, "relation": "OWNS", "to": crypto_key,
            "basis": "operator-registration",
            "evidence_ids": _evidence(f"system-asset:{row.get('id') or identifier}"),
            "note": "a registered link between a system and an asset, not a measurement"})

    # ---- hardware, HSM, TPM ---------------------------------------------- #
    for row in inv.get("hardware") or []:
        if not isinstance(row, Mapping):
            continue
        device = _norm(row.get("device_type")).upper()
        kind = "HSM" if row.get("hsm") else (
            "TPM" if row.get("tpm") else DEVICE_KINDS.get(device, "HOST"))
        name = _norm(row.get("asset_id")) or _norm(row.get("id"))
        if not name:
            skipped.append(_skipped(
                kind, row.get("model") or row.get("manufacturer"),
                "a hardware row with neither asset_id nor id cannot be referenced by an "
                "edge, so it is skipped rather than given an invented identity"))
            continue
        basis = "cmdb-import"
        evidence = _evidence(f"hardware:{name}", row.get("evidence_history"))
        capabilities = row.get("crypto_capabilities")
        if isinstance(capabilities, str):
            capabilities = [part.strip() for part in capabilities.split(",") if part.strip()]
        key = add(kind, name, evidence_ids=evidence, version=row.get("firmware"),
                  location=row.get("location") or row.get("asset"),
                  model=row.get("model"), manufacturer=row.get("manufacturer"),
                  serial_reference=row.get("serial_reference"),
                  risk_level=row.get("risk_level"), supports=capabilities)
        if not key:
            continue
        system_reference = _norm(row.get("asset"))
        if system_reference in systems:
            claims.append({
                "from": systems[system_reference], "relation": "OWNS", "to": key,
                "basis": "operator-registration",
                "evidence_ids": _evidence(f"hardware:{name}"),
                "note": "the hardware row names this system as its owner"})
        firmware = _norm(row.get("firmware") or row.get("firmware_version"))
        if firmware:
            firmware_key = add("FIRMWARE", f"{name} firmware {firmware}",
                               evidence_ids=evidence, version=firmware,
                               supports=capabilities)
            chain(key, "RUNS_FIRMWARE", firmware_key, basis=basis, evidence_ids=evidence)
        manufacturer = _norm(row.get("manufacturer"))
        if manufacturer:
            vendor_key = add("VENDOR", manufacturer, evidence_ids=evidence)
            chain(key, "SUPPLIED_BY", vendor_key, basis="vendor-datasheet",
                  evidence_ids=evidence,
                  note="the manufacturer field is a vendor declaration, not a delivery "
                       "record")

    # ---- vendors ---------------------------------------------------------- #
    for row in inv.get("vendors") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        if not name:
            skipped.append(_skipped("VENDOR", row, "a vendor row with no name"))
            continue
        evidence = _evidence(f"vendor:{name.lower()}", row.get("evidence_ref"))
        vendor_key = add("VENDOR", name, evidence_ids=evidence,
                         lifecycle=row.get("lifecycle"), risk_level=row.get("risk_level"),
                         crypto_capability=row.get("crypto_capability"))
        product = _norm(row.get("product")) or _norm(row.get("model"))
        if product:
            version = _norm(row.get("version"))
            product_key = add("VENDOR_PRODUCT", f"{name} {product}", evidence_ids=evidence,
                              version=None if version else (row.get("version") or None),
                              lifecycle=row.get("lifecycle"),
                              eol_date=row.get("eol_date"), eos_date=row.get("eos_date"),
                              support_status=row.get("support_status"))
            chain(product_key, "SUPPLIED_BY", vendor_key, basis="vendor-datasheet",
                  evidence_ids=evidence)
            # A versioned vendor row is two facts, not one: the product the vendor sells and
            # the release the claim is about. Recording the version on the product alone
            # loses the level the applicability question is asked at, so the release is a
            # node of its own and the product *releases* it.
            if product_key and version:
                release_key = add("PRODUCT_VERSION", f"{product}@{version}",
                                  evidence_ids=evidence, version=version,
                                  lifecycle=row.get("lifecycle"),
                                  eol_date=row.get("eol_date"),
                                  eos_date=row.get("eos_date"),
                                  support_status=row.get("support_status"),
                                  release_date=row.get("release_date"))
                chain(product_key, "RELEASES", release_key, basis="vendor-datasheet",
                      evidence_ids=evidence,
                      note="the vendor row carries the version, so it names a release")

    # ---- certificates ----------------------------------------------------- #
    for row in inv.get("certificates") or []:
        if not isinstance(row, Mapping):
            continue
        fingerprint = _norm(row.get("fingerprint"))
        subject = _norm(row.get("subject"))
        name = subject or fingerprint
        if not name:
            skipped.append(_skipped("CERTIFICATE", row,
                                    "a certificate row with neither subject nor fingerprint"))
            continue
        add("CERTIFICATE", name, evidence_ids=_evidence(
            fingerprint and f"cert:{fingerprint}", row.get("evidence_ref")),
            fingerprint_sha256=fingerprint, subject=subject,
            not_after=row.get("not_after"))

    # ---- software rows and their edges ----------------------------------- #
    software = inv.get("software") if isinstance(inv.get("software"), list) else []
    coordinates: dict[str, str] = {}
    for row in software:
        if not isinstance(row, Mapping):
            continue
        coordinate = _norm(row.get("coordinate")) or _norm(row.get("name"))
        origin = _norm(row.get("origin")).upper()
        basis = ORIGIN_BASIS.get(origin)
        if not basis:
            skipped.append(_skipped(
                "PACKAGE", coordinate or row.get("name"),
                f"its origin {origin or '(none)'} does not say whether the code imports it "
                "or only a manifest declares it, so its class cannot be set"))
            continue
        kind = "CRYPTO_LIBRARY" if _norm(row.get("component_type")).lower() == "library" \
            else "PACKAGE"
        evidence = _evidence(coordinate and f"software:{coordinate}",
                            row.get("declared_in"), scan_id and f"scan:{scan_id}")
        key = add(kind, coordinate or row.get("name"), evidence_ids=evidence,
                  version=row.get("version"), package=row.get("name"),
                  ecosystem=row.get("ecosystem"), origin=origin,
                  crypto_bearing=row.get("crypto_bearing"),
                  declared_in=row.get("declared_in"),
                  algorithms=row.get("algorithms"))
        if key:
            coordinates[coordinate.lower()] = key
            coordinates[_norm(row.get("name")).lower()] = key
    for edge in inv.get("dependencies") or []:
        if isinstance(edge, Mapping):
            source, target, why = (edge.get("source"), edge.get("target"),
                                   edge.get("type") or edge.get("predicate"))
        elif isinstance(edge, (list, tuple)) and len(edge) >= 2:
            source, target = edge[0], edge[1]
            why = edge[2] if len(edge) > 2 else ""
        else:
            continue
        source_text, target_text = _norm(source), _norm(target)
        why_text = _norm(why).lower()
        if source_text in systems and target_text in systems:
            claims.append({
                "from": systems[source_text], "relation": "DEPENDS_ON",
                "to": systems[target_text], "basis": "cmdb-import",
                "evidence_ids": [f"dependency:{source_text}:{target_text}"],
                "note": "a system dependency row; its own source column decides the "
                        "class when it is present"})
            continue
        source_key = coordinates.get(source_text.lower())
        target_key = coordinates.get(target_text.lower())
        if source_key and target_key:
            relation = "SHIPS" if why_text in ("contains", "contains_package") else \
                "DEPENDS_ON"
            basis = "sbom-import" if not scan_id else "scan-manifest"
            claims.append({
                "from": source_key, "relation": relation, "to": target_key,
                "basis": basis,
                "evidence_ids": _evidence(scan_id and f"scan:{scan_id}",
                                          f"edge:{source_text}->{target_text}"),
                "note": f"software edge of type {why_text or 'unstated'}"})
            continue
        skipped.append(_skipped(
            "DEPENDENCY", f"{source_text} → {target_text}",
            "one end of the edge is not an asset in this estate, and an edge to an "
            "undeclared node is refused rather than invented"))

    # ---- dependency rows with their own provenance ------------------------ #
    for row in inv.get("system_dependencies") or []:
        if not isinstance(row, Mapping):
            continue
        declared = _norm(row.get("source")).lower()
        basis = DEPENDENCY_BASIS.get(declared)
        parent_id, child_id = _norm(row.get("parent_id")), _norm(row.get("child_id"))
        subject = f"{parent_id} → {child_id}"
        if not basis:
            skipped.append(_skipped(
                "DEPENDENCY", subject,
                f"its provenance column says {declared or '(empty)'}, which is not one of "
                "manual, discovered or imported: the edge cannot be given a class"))
            continue
        if parent_id not in systems or child_id not in systems:
            skipped.append(_skipped(
                "DEPENDENCY", subject,
                "the dependency row names a system this inventory does not hold; an edge "
                "to an undeclared system is refused rather than invented"))
            continue
        claims.append({
            "from": systems[parent_id], "relation": "DEPENDS_ON",
            "to": systems[child_id], "basis": basis,
            "evidence_ids": _evidence(row.get("evidence_ref"),
                                      f"dependency:{subject}"),
            "source_system": declared,
            "note": row.get("confidence_meaning") or None})

    estate = {
        "schema": ESTATE_SCHEMA,
        "estate_id": estate_id_text,
        "environment": environment_text,
        "expected": dict(expected or {}),
        "gaps": [dict(row) for row in (gaps or [])],
        "assets": assets,
        "claims": claims,
        "source": {
            "kind": "INVENTORY",
            "scan_id": scan_id or None,
            "note": ("read from the stored inventory: every asset and edge here is the "
                     "residue of a collection that already happened, so none of it is "
                     "OBSERVED on this read"),
        },
    }
    return {
        "schema": ESTATE_SCHEMA,
        "estate": estate,
        "assets": len(assets),
        "claims": len(claims),
        "skipped": skipped,
        "statement": (
            f"{len(assets)} asset(s) and {len(claims)} claim(s) read from the inventory"
            + (f"; {len(skipped)} row(s) skipped with a reason" if skipped else "")
            + "; every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a "
              "stored row is not an observation"),
        "not_proven": [
            "that a stored row is still true: a scan row records what a collector saw "
            "when it ran, and the estate may have changed since",
            "that a dependency row with provenance 'manual' is deployed: a person "
            "registering an edge is a claim, and it stays IMPORTED",
            "that a certificate's key or algorithm is known here: the stored row carries a "
            "fingerprint and a subject, and the key layer is not derived from them",
            "that the inventory is complete: coverage is a denominator plus a reason, and "
            "this adapter reports what it read rather than what should exist",
        ],
    }
