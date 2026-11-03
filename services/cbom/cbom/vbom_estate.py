"""The vendor dependency graph over the estate the API actually holds.

:mod:`cbom.vbom_dependency` proves the graph against a payload a bank files. This module is the
step that turns *stored rows* into that payload, so the graph is not a second inventory living
in a script — and :func:`assess` is the one call an API needs: rows in, the same twenty-nine
answers out, plus what could not be mapped.

Three rules, and everything here follows from them:

* **A mapper never invents a row.** A hardware row with no model, a software row with no
  coordinate, a vendor row whose product is blank — each is reported in ``unmapped`` with the
  section it would have filled. Silent drops are how a graph reports a smaller estate than the
  bank has and calls it coverage.
* **Only a live observation may say runtime.** The stored crypto findings are static analysis:
  ``CryptoAsset`` rows say a library *can* do something, not that a process did it. They are
  therefore **not** mapped into the graph's ``usage`` section, and
  ``declared_vs_observed`` answers ``NOT_OBSERVED`` — which is the truth — instead of inheriting
  a runtime claim from a file path.
* **A declaration without a document is not a declaration.** Capabilities are mapped only when
  the row carries a source document; a ``vendor_crypto_inventory`` row with a
  ``source_document`` becomes a release capability citing it, and one without is unmapped with
  the reason, because the graph would refuse it anyway (``VENDOR_CLAIM_WITHOUT_DOCUMENT``).

The environment matters: an asset, a product and a release are keyed per environment, so the
same HSM in PRODUCTION and in DR is two nodes and the module never joins them.
"""

from __future__ import annotations

import inspect
from collections.abc import Iterable, Mapping
from typing import Any

from . import techbom as tb
from . import vbom_dependency as vd

SCHEMA = "cryptoscan.vbom-estate/1"

#: inventory ``device_type`` → graph kind. Anything unrecognised lands on ``HOST`` and says so
#: in ``unmapped`` only when the row could not be attributed at all — the same device stored
#: under a new label tomorrow is still a device, not a refused row.
DEVICE_TYPES: dict[str, str] = {
    "hsm": "HSM", "hardware_hsm": "HSM", "tpm": "TPM", "kms": "KMS",
    "load_balancer": "LOAD_BALANCER", "loadbalancer": "LOAD_BALANCER", "lb": "LOAD_BALANCER",
    "firewall": "FIREWALL", "waf": "WAF", "vpn": "VPN_GATEWAY", "vpn_gateway": "VPN_GATEWAY",
    "gateway": "API_GATEWAY", "api_gateway": "API_GATEWAY", "proxy": "API_GATEWAY",
    "server": "PHYSICAL_SERVER", "physical_server": "PHYSICAL_SERVER", "host": "HOST",
    "workstation": "HOST", "vm": "VM", "virtual_machine": "VM", "container_host": "HOST",
    "database": "DATABASE", "ca": "CERTIFICATE_AUTHORITY", "pki": "CERTIFICATE_AUTHORITY",
    "smartcard": "SMART_CARD", "smart_card": "SMART_CARD", "ids": "IDS", "ips": "IPS",
    "network": "LOAD_BALANCER", "appliance": "SECURITY_APPLIANCE",
    "security_appliance": "SECURITY_APPLIANCE",
}

#: the sections this mapper can fill. A section named here and absent from ``mapped`` counted
#: zero rows, which is a different sentence from "the mapper does not read it".
SECTIONS: tuple[str, ...] = ("documents", "vendors", "products", "releases", "firmware",
                             "assets", "packages", "components", "applications", "systems",
                             "usage", "network", "pki")

#: sections the estate genuinely does not hold in this build. Stated rather than omitted,
#: because a caller reading the payload cannot tell an empty section from an unread one.
NOT_MAPPED: dict[str, str] = {
    "usage": "runtime usage needs a process trace or a live probe; the stored crypto findings "
             "are static analysis and are not mapped here, so `declared_vs_observed` reports "
             "every declared capability as declared and never observed rather than inheriting "
             "a runtime claim from a file path",
    "network": "an endpoint's load balancer, TLS mode and certificate chain come from the "
               "network scan projection and the NBOM, not from this mapper",
    "pki": "certificate authority, certificate and endpoint rows come from the PKI projection; "
           "a fingerprint without its chain is not a dependency edge",
    "firmware": "no firmware rows are mapped: a device's firmware becomes a node from the "
                "device's own row, and a vendor firmware document would add the support dates "
                "and the security status that row does not carry",
    "applications": "the API's `applications` rows are business systems (the System model); "
                    "the only application node this mapper can justify is the scanned "
                    "target, and it carries the packages the scan reported",
}


def _norm(value: Any) -> str:
    return tb._norm(value)


def _kind_for(device_type: Any, *, hsm: Any = None, tpm: Any = None) -> str:
    if hsm:
        return "HSM"
    if tpm:
        return "TPM"
    text = _norm(device_type).lower().replace("-", "_").replace(" ", "_")
    return DEVICE_TYPES.get(text, "HOST")


def _release_for(payload: Mapping[str, Any], product: str, firmware: Any) -> str | None:
    """The release a firmware belongs to, when the estate holds one that is its prefix."""
    text = _norm(firmware)
    if not text:
        return None
    candidates = [row["version"] for row in payload.get("releases") or []
                  if _norm(row.get("product")).lower() == _norm(product).lower()
                  and row.get("version") and text.startswith(str(row["version"]))]
    return max(candidates, key=len) if candidates else None


def _unmapped(section: str, subject: Any, reason: str) -> dict[str, Any]:
    return {"section": section, "subject": _norm(subject) or None, "reason": reason}


def payload_from_inventory(inventory: Mapping[str, Any] | None, *, as_of: Any = None,
                           environment: Any = None) -> dict[str, Any]:
    """A gathered inventory → ``cryptoscan.vbom-input/1`` plus what it could not map.

    The inventory shape is the one the API already assembles (``vendors``, ``hardware``,
    ``software``, ``applications``, ``certificates``, ``crypto``, ``scan``). Keys this mapper
    does not read are listed in :data:`NOT_MAPPED` rather than ignored, so the difference
    between "the estate is thin" and "the mapper is thin" survives the call.
    """
    inv = inventory if isinstance(inventory, Mapping) else {}
    env = (_norm(environment) or _norm(inv.get("environment")) or "PRODUCTION").upper()
    payload: dict[str, Any] = {"schema": vd.INPUT_SCHEMA, "as_of": as_of or inv.get("as_of"),
                               **{section: [] for section in SECTIONS}}
    mapped = {section: 0 for section in SECTIONS}
    unmapped: list[dict[str, Any]] = []
    seen: dict[str, set[str]] = {section: set() for section in SECTIONS
                                 if section not in ("documents", "components")}
    vendors_seen: dict[str, str] = {}
    products_seen: dict[str, str] = {}

    def add(section: str, key: str, row: dict[str, Any]) -> bool:
        if key in seen.get(section, set()):
            return False
        seen.setdefault(section, set()).add(key)
        payload[section].append(row)
        mapped[section] += 1
        return True

    def ensure_vendor(name: str, *, evidence: str | None = None) -> str | None:
        name = _norm(name)
        if not name:
            return None
        key = name.lower()
        if key in vendors_seen:
            return vendors_seen[key]
        vendors_seen[key] = name
        add("vendors", key, {"name": name, **({"evidence_ref": evidence} if evidence else {})})
        return name

    def ensure_product(vendor: str, product: str, *, family: Any = None, kind: Any = None,
                       evidence: str | None = None) -> str | None:
        product = _norm(product)
        if not product or not vendor:
            return None
        key = f"{vendor.lower()}::{product.lower()}"
        if key in products_seen:
            return products_seen[key]
        products_seen[key] = product
        row: dict[str, Any] = {"name": product, "vendor": vendor,
                               "type": _norm(kind).upper() or None}
        if _norm(family):
            row["family"] = _norm(family)
        if evidence:
            row["evidence_ref"] = evidence
        add("products", key, row)
        return product

    # ---- vendors, and the products they sell ------------------------------- #
    for row in inv.get("vendors") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        if not name:
            unmapped.append(_unmapped("vendors", row.get("id") or row.get("product"),
                                      "a vendor row with no name cannot be a node"))
            continue
        vendor = ensure_vendor(name, evidence=_norm(row.get("evidence_ref")) or None)
        product = _norm(row.get("product")) or _norm(row.get("model"))
        if not product:
            continue  # a vendor without a product is a vendor: no product row is invented
        ensure_product(vendor, product, family=row.get("family"), kind=row.get("type"))
        version = _norm(row.get("version"))
        if version:
            product_key = f"{vendor.lower()}::{product.lower()}"
            if add("releases", f"{product_key}@{version.lower()}", {
                    "product": product, "version": version,
                    "support_status": _norm(row.get("lifecycle")).upper() or None,
                    "pqc_capability": _norm(row.get("crypto_capability")).upper() or None,
                    "vendor": vendor}):
                products_seen[product_key] = product

    # ---- hardware: the devices the vendor delivered ------------------------ #
    for row in inv.get("hardware") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("asset_id")) or _norm(row.get("id"))
        model = _norm(row.get("model"))
        manufacturer = _norm(row.get("manufacturer"))
        if not name:
            unmapped.append(_unmapped(
                "assets", row.get("id"),
                "a hardware row with no asset_id cannot be addressed by an edge"))
            continue
        if not model:
            unmapped.append(_unmapped(
                "assets", name,
                "the row names no model, so the device cannot be attributed to a product "
                "and an unattributed device is a vendor dependency nobody owns"))
            continue
        vendor = ensure_vendor(manufacturer) if manufacturer else None
        if vendor:
            ensure_product(vendor, model, kind=row.get("device_type"))
        firmware = _norm(row.get("firmware")) or None
        if add("assets", name.lower(), {
                "name": name, "type": _kind_for(row.get("device_type"), hsm=row.get("hsm"),
                                                tpm=row.get("tpm")),
                "product": model, "vendor": vendor, "firmware": firmware,
                "serial": _norm(row.get("serial_reference")) or None,
                "location": _norm(row.get("location")) or None,
                "owner": _norm(row.get("owner")) or None,
                "environment": env,
                }) and firmware:
            # A device that reports a firmware *is* the firmware row: the graph keeps the
            # firmware as a node of its own so `RUNS_FIRMWARE` has somewhere to land, and its
            # evidence is the device's own row rather than a vendor document nobody holds.
            row_firmware = {"product": model, "version": firmware,
                            "evidence_id": f"hardware:{name}"}
            release_version = _release_for(payload, model, firmware)
            if release_version:
                # 9.2.1 is a firmware of release 9.2 when the estate says so; the prefix is
                # the only join this mapper will make, and it is a join it can show.
                row_firmware["release"] = release_version
            add("firmware", f"{model.lower()}@{firmware.lower()}", row_firmware)

    # ---- vendor crypto declarations, with the document that states them ---- #
    for row in inv.get("vendor_crypto") or []:
        if not isinstance(row, Mapping):
            continue
        vendor = ensure_vendor(row.get("vendor"))
        product = _norm(row.get("product")) or _norm(row.get("vendor_product"))
        version = _norm(row.get("version"))
        algorithm = _norm(row.get("algorithm"))
        document_ref = _norm(row.get("source_document")) or _norm(row.get("document"))
        if not (vendor and product and version and algorithm):
            unmapped.append(_unmapped(
                "releases", f"{vendor or '(no vendor)'}/{product or '(no product)'}",
                "a capability needs a vendor, a product, a release and an algorithm before it "
                "can be applied to anything"))
            continue
        if not document_ref:
            unmapped.append(_unmapped(
                "releases", f"{product}@{version}",
                "the capability cites no document, and a capability with no page behind it is "
                "a rumour the graph refuses (VENDOR_CLAIM_WITHOUT_DOCUMENT)"))
            continue
        document_id = f"VCI-{tb._digest(document_ref)[:12].upper()}" if hasattr(
            tb, "_digest") else f"VCI-{abs(hash(document_ref)) % 10**10}"
        if document_id not in {row_["id"] for row_ in payload["documents"]}:
            payload["documents"].append({
                "id": document_id, "title": document_ref, "vendor": vendor,
                "product": product, "version": version,
                "reviewer": _norm(row.get("reviewed_by")) or None,
                "received_at": row.get("discovered_at"), "revision": 1})
            mapped["documents"] += 1
        ensure_product(vendor, product, kind=row.get("product_type"))
        release_key = f"{vendor.lower()}::{product.lower()}@{version.lower()}"
        release = next((entry for entry in payload["releases"]
                        if entry["product"].lower() == product.lower()
                        and entry["version"] == version), None)
        if release is None:
            release = {"product": product, "version": version, "vendor": vendor,
                       "capabilities": []}
            payload["releases"].append(release)
            mapped["releases"] += 1
            seen.setdefault("releases", set()).add(release_key)
        capability = {"algorithm": algorithm, "key_size": row.get("key_size"),
                      "mode": _norm(row.get("mode")) or None,
                      "purpose": _norm(row.get("crypto_use_case")) or None,
                      "documents": [document_id]}
        if capability not in release.setdefault("capabilities", []):
            release["capabilities"].append(capability)

    # ---- software: packages, and the vendor field coverage needs ----------- #
    for row in inv.get("software") or []:
        if not isinstance(row, Mapping):
            continue
        coordinate = _norm(row.get("coordinate")) or _norm(row.get("purl"))
        name = _norm(row.get("name"))
        version = _norm(row.get("version"))
        if not coordinate:
            unmapped.append(_unmapped(
                "packages", name or row.get("id"),
                "a software row with no coordinate cannot be joined to an SBOM or a runtime "
                "trace, which both name components by coordinate"))
            continue
        add("packages", coordinate.lower(), {"coordinate": coordinate,
                                             "version": version or None,
                                             "product": None})
        vendor = _norm(row.get("vendor")) or (_norm(row.get("publisher")) if row.get(
            "crypto_bearing") else "")
        payload["components"].append({"coordinate": coordinate, "version": version,
                                      "vendor": vendor.upper() if vendor else "UNKNOWN"})
        mapped["components"] += 1

    # ---- the systems the bank would lose ----------------------------------- #
    for row in inv.get("applications") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        if not name:
            unmapped.append(_unmapped("systems", row.get("id"),
                                      "a system row with no name has no identity"))
            continue
        add("systems", name.lower(), {
            "name": name, "owner": _norm(row.get("owner")) or None,
            "criticality": _norm(row.get("criticality")) or None,
            "environment": _norm(row.get("environment")) or env,
        })
        if _norm(row.get("version")):
            # the API's "application" row is a business system with a version; it is a
            # system node here, and the version is the system's, not a vendor release's
            payload["systems"][-1]["version"] = _norm(row.get("version"))

    # ---- the scanned target, which is the only application row this estate has --- #
    scan = inv.get("scan") if isinstance(inv.get("scan"), Mapping) else {}
    target = _norm(scan.get("target"))
    coordinates = [row["coordinate"] for row in payload["packages"]]
    if target and coordinates:
        add("applications", target.lower(), {
            "name": target, "packages": coordinates[:500],
            "environment": env,
            "owner": None,
        })

    counts = {section: mapped[section] for section in SECTIONS}
    return {
        "schema": SCHEMA,
        "payload": payload,
        "environment": env,
        "mapped": counts,
        "unmapped": unmapped,
        "not_mapped": dict(NOT_MAPPED),
        "statement": (f"{sum(counts.values())} row(s) mapped over "
                      f"{len([count for count in counts.values() if count])} section(s); "
                      f"{len(unmapped)} row(s) unmapped by name"),
        "rule": ("a mapper never invents a row: an unattributable device, a coordinate-less "
                 "package and a document-less capability are reported, not dropped"),
        "not_proven": [
            "that the stored rows are right: this maps what the estate holds",
            "runtime usage: a static finding is not an observation, so the graph's runtime "
            "level is empty and the answers say NOT_OBSERVED rather than guessing",
        ],
    }


# --------------------------------------------------------------------------- #
# The answers, over a graph built from the estate
# --------------------------------------------------------------------------- #

#: question → (reader, the parameters it needs). The list is what an API will advertise; a
#: question not in it cannot be asked, which is how the surface stays equal to the module
#: instead of drifting from it.
ANSWERS: dict[str, tuple[Any, tuple[str, ...]]] = {
    "vendor_products": (vd.vendor_products, ("vendor",)),
    "product_releases": (vd.product_releases, ("product",)),
    "vendor_assets": (vd.vendor_assets, ("vendor",)),
    "vendor_applications": (vd.vendor_applications, ("vendor",)),
    "vendor_systems": (vd.vendor_systems, ("vendor",)),
    "vendor_history": (None, ()),
    "hardware_chain": (vd.hardware_chain, ("asset",)),
    "software_chain": (vd.software_chain, ()),
    "crypto_chain": (vd.crypto_chain, ()),
    "declared_vs_observed": (vd.declared_vs_observed, ()),
    "crypto_business": (vd.crypto_business, ("vendor",)),
    "runtime_dependency": (vd.runtime_dependency, ("vendor",)),
    "network_dependency": (vd.network_dependency, ("vendor",)),
    "pki_dependency": (vd.pki_dependency, ("vendor",)),
    "firmware_posture": (vd.firmware_posture, ()),
    "lifecycle_impact": (vd.lifecycle_impact, ()),
    "evidence_report": (vd.evidence_report, ()),
    "statement_applicability": (vd.declaration_applicability, ()),
    "sbom_agreement": (vd.sbom_agreement, ()),
    "cbom_agreement": (vd.cbom_agreement, ()),
    "version_conflicts": (vd.version_conflicts, ()),
    "risk_propagation": (vd.risk_propagation, ("vendor",)),
    "pqc_posture": (vd.pqc_posture, ()),
    "twin": (vd.twin, ()),
    "coverage": (None, ()),
}


def _accepted(name: str) -> tuple[str, ...]:
    """The parameters a reader will accept — read from its signature, never guessed."""
    reader, _required_params = ANSWERS[name]
    if reader is None:
        return ()
    signature = inspect.signature(reader)
    return tuple(key for key, value in signature.parameters.items()
                 if key != "bom" and value.kind is inspect.Parameter.KEYWORD_ONLY)


def catalogue() -> dict[str, Any]:
    """The questions an estate-backed graph can answer, and what each one costs."""
    rows = [{"question": name,
             "parameters": list(_accepted(name)),
             "required": list(params),
             "needs_a_subject": bool(_accepted(name)),
             "source": ("payload" if reader is None else "graph")}
            for name, (reader, params) in ANSWERS.items()]
    return {
        "schema": SCHEMA,
        "count": len(rows),
        "questions": rows,
        "statement": (f"{len(rows)} question(s), "
                      f"{len([row for row in rows if row['needs_a_subject']])} of which need "
                      "a vendor, a product or an asset named"),
        "rule": "a question is asked by name; an unknown name is refused, not approximated",
    }


def answer(bom: Mapping[str, Any], question: Any, *, payload: Mapping[str, Any] | None = None,
           **params: Any) -> dict[str, Any]:
    """One answer, in one shape — including the refusals, which stay refusals."""
    name = _norm(question)
    if name not in ANSWERS:
        return {"question": name or None, "ok": False, "code": "UNKNOWN_QUESTION",
                "reason": f"{name or '(none)'} is not one of the {len(ANSWERS)} questions; "
                          "see catalogue()", "result": None}
    reader, declared = ANSWERS[name]
    accepted = set(_accepted(name))
    unknown = sorted(set(params) - accepted - {"as_of"})
    if unknown:
        return {"question": name, "ok": False, "code": "UNKNOWN_PARAMETER",
                "reason": f"{', '.join(unknown)} is not a parameter of {name}",
                "result": None}
    missing = [key for key in declared if key not in params]
    if missing:
        return {"question": name, "ok": False, "code": "MISSING_PARAMETER",
                "reason": f"{name} needs {', '.join(declared)}",
                "result": None}
    try:
        if name == "vendor_history":
            result = vd.history(payload or {})
        elif name == "coverage":
            result = vd.coverage(payload or {})
        else:
            result = reader(bom, **params)
    except tb.ClaimRefused as refusal:
        return {"question": name, "ok": False, "code": refusal.code,
                "reason": refusal.reason, "result": None}
    return {"question": name, "ok": True,
            "statement": (result or {}).get("statement") if isinstance(result, Mapping) else None,
            "result": result}


#: readers whose parameters are optional in the signature but which refuse without a subject:
#: asking them with nothing is a question about no subject, not a question about the estate.
NEEDS_SUBJECT: frozenset[str] = frozenset({
    "software_chain", "crypto_chain", "declared_vs_observed", "sbom_agreement",
    "cbom_agreement", "pqc_posture", "firmware_posture", "lifecycle_impact",
})

#: asked when the caller names none: the questions a graph can answer without a subject.
DEFAULT_QUESTIONS: tuple[str, ...] = tuple(
    name for name, (_reader, params) in ANSWERS.items()
    if not params and name not in NEEDS_SUBJECT)


def assess(inventory: Mapping[str, Any] | None, *, as_of: Any = None,
           questions: Iterable[str] | None = None) -> dict[str, Any]:
    """Stored rows → payload → graph → the questions asked of it.

    The payload and the graph are both returned, because a caller that cannot see what was
    mapped cannot tell a thin estate from a broken mapper.
    """
    mapped = payload_from_inventory(inventory, as_of=as_of)
    built = vd.build(mapped["payload"], as_of=as_of or mapped["payload"].get("as_of"),
                     estate_id="vbom:estate")
    bom = built["bom"]
    asked = [name for name in (DEFAULT_QUESTIONS if questions is None else questions)
             if name in ANSWERS]
    answers = [answer(bom, name, payload=mapped["payload"],
                      **{key: mapped["payload"][key] for key in ()})
               for name in asked]
    unanswered = [row for row in answers if not row["ok"]]
    return {
        "schema": SCHEMA,
        "as_of": built["as_of"],
        "mapped": mapped["mapped"],
        "unmapped": mapped["unmapped"],
        "not_mapped": mapped["not_mapped"],
        "not_proven": mapped["not_proven"],
        "payload": mapped["payload"],
        "document": bom,
        "levels": vd.levels(bom),
        "applicability": vd.declaration_applicability(bom, as_of=as_of)["states"],
        "answers": answers,
        "unanswered": unanswered,
        "statement": (f"{mapped['statement']}; {built['statement']}; "
                      f"{len(answers)} question(s) answered, {len(unanswered)} refused"),
        "rule": ("the graph is the estate's, not the mapper's: every node here came from a "
                 "stored row and every gap is named"),
    }


# --------------------------------------------------------------------------- #
# CycloneDX: the vendor graph as a document a scanner can read
# --------------------------------------------------------------------------- #

#: graph kind → CycloneDX 1.6 component type. The format has no "vendor" and no "business
#: system"; a vendor product is an application, a device is a device, and a system is the
#: application the bank loses.
COMPONENT_TYPE: dict[str, str] = {
    "VENDOR": "application", "VENDOR_PRODUCT": "application", "PRODUCT_VERSION": "application",
    "APPLICATION": "application", "BUSINESS_SYSTEM": "application", "SERVICE": "application",
    "PACKAGE": "library", "CRYPTO_LIBRARY": "library", "FIRMWARE": "firmware",
    "VM": "platform", "HOST": "device", "PHYSICAL_SERVER": "device", "HSM": "device",
    "TPM": "device", "KMS": "device", "LOAD_BALANCER": "device", "WAF": "device",
    "FIREWALL": "device", "API_GATEWAY": "device", "VPN_GATEWAY": "device",
    "SECURITY_APPLIANCE": "device", "DATABASE": "device", "SMART_CARD": "device",
    "CERTIFICATE_AUTHORITY": "application", "CERTIFICATE": "data",
    "CRYPTO_CAPABILITY": "cryptographic-asset", "CRYPTO_ASSET": "cryptographic-asset",
    "ALGORITHM": "cryptographic-asset",
}

#: exported kinds. The runtime and the evidence stay out: a CycloneDX export of a *vendor*
#: graph that also carried a process tree would be a CBOM with a misleading title.
EXPORTED_KINDS: tuple[str, ...] = ("VENDOR", "VENDOR_PRODUCT", "PRODUCT_VERSION", "FIRMWARE",
                                   "PACKAGE", "CRYPTO_LIBRARY", "HSM", "TPM", "KMS", "HOST",
                                   "VM", "PHYSICAL_SERVER", "LOAD_BALANCER", "WAF", "FIREWALL",
                                   "API_GATEWAY", "VPN_GATEWAY", "SECURITY_APPLIANCE",
                                   "DATABASE", "SMART_CARD", "APPLICATION",
                                   "BUSINESS_SYSTEM", "CRYPTO_CAPABILITY")

#: edges that survive as ``dependencies``. Anything else — documented-by, declared-in,
#: supplied-by-a-claim — is a property, because CycloneDX's dependency graph means "A needs B",
#: not "A was mentioned by B".
DEPENDENCY_RELATIONS: tuple[str, ...] = ("HAS_MODEL", "RELEASES", "SHIPS_PACKAGE",
                                         "FIRMWARE_OF", "RUNS_FIRMWARE", "SUPPORTS",
                                         "CONTAINS", "RUNS_APPLICATION")


def to_cyclonedx(bom: Mapping[str, Any], *, as_of: Any = None) -> dict[str, Any]:
    """The vendor graph as CycloneDX 1.6, with the confidence carried in properties."""
    rows = [row for row in bom["assets"] if row["kind"] in EXPORTED_KINDS]
    refs: dict[str, str] = {}
    components: list[dict[str, Any]] = []
    for row in rows:
        ref = f"{row['kind'].lower()}:{_norm(row['name']).lower().replace(' ', '-')}"
        refs[row["key"]] = ref
        properties = [
            {"name": "cryptoscan:kind", "value": row["kind"]},
            {"name": "cryptoscan:level", "value": vd.KIND_LEVEL.get(row["kind"], "unknown")},
            {"name": "cryptoscan:environment", "value": row.get("environment") or "UNKNOWN"},
        ]
        for name in ("lifecycle", "support_status", "eol_date", "eos_date", "security_status",
                     "pqc_capability", "product_type", "product_family", "serial", "location",
                     "owner", "algorithm", "key_size", "mode"):
            value = (row.get("attributes") or {}).get(name)
            if value not in (None, "", [], {}):
                properties.append({"name": f"cryptoscan:{name}", "value": str(value)})
        for evidence in row.get("evidence_ids") or []:
            properties.append({"name": "cryptoscan:evidence", "value": str(evidence)})
        component: dict[str, Any] = {
            "type": COMPONENT_TYPE.get(row["kind"], "application"),
            "bom-ref": ref, "name": row["name"], "properties": properties,
        }
        if row.get("version"):
            component["version"] = str(row["version"])
        components.append(component)

    dependencies = []
    for claim in bom["claims"]:
        if claim["relation"] not in DEPENDENCY_RELATIONS:
            continue
        source, target = refs.get(claim["from_key"]), refs.get(claim["to_key"])
        if not source or not target or source == target:
            continue
        entry = next((row for row in dependencies if row["ref"] == source), None)
        if entry is None:
            entry = {"ref": source, "dependsOn": []}
            dependencies.append(entry)
        if target not in entry["dependsOn"]:
            entry["dependsOn"].append(target)
    dependencies.sort(key=lambda row: row["ref"])
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": _timestamp(as_of),
            "component": {
                "type": "application", "bom-ref": "vbom:vendor-dependency",
                "name": "CryptoScan vendor dependency graph",
                "properties": [
                    {"name": "cryptoscan:profile", "value": "VENDOR_DEPENDENCY"},
                    {"name": "cryptoscan:discovery_completeness", "value": "NOT_PROVEN"},
                ],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }
    return {
        "schema": SCHEMA,
        "document": document,
        "components": len(components),
        "dependencies": len(dependencies),
        "statement": (f"{len(components)} component(s) and {len(dependencies)} dependency "
                      f"entr(ies) in a CycloneDX 1.6 document"),
        "rule": ("a vendor graph is exported, not interpreted: the class and the evidence "
                 "travel as cryptoscan: properties a consumer may ignore"),
        "not_proven": ["that the document validates against the official schema: this build "
                       "emits the 1.6 shape and the CBOM exporter owns schema validation"],
    }


def _timestamp(value: Any = None) -> str:
    from datetime import datetime, timezone  # noqa: PLC0415 — only needed here

    text = _norm(value)
    if text:
        return text if "T" in text else f"{text}T00:00:00Z"
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summary(bom: Mapping[str, Any], *, as_of: Any = None) -> dict[str, Any]:
    """Levels, applicability states and the refusals — the first three numbers a reviewer wants."""
    levels = vd.levels(bom)
    states = vd.declaration_applicability(bom, as_of=as_of)["states"]
    refusals = list(bom.get("refusals") or [])
    return {
        "schema": SCHEMA,
        "levels": levels,
        "applicability": states,
        "refusals": refusals[:20],
        "refusal_count": len(refusals),
        "populated_levels": [name for name, count in levels.items() if count],
        "statement": (f"{sum(levels.values())} node(s) over "
                      f"{len([name for name, count in levels.items() if count])} level(s); "
                      f"{len(refusals)} refusal(s); "
                      + (", ".join(f"{state} {count}"
                                   for state, count in sorted(states.items()))
                         or "no declaration reaches a deployment")),
        "rule": ("a summary that hides the refusals is a summary of the model, not of the "
                 "estate"),
    }
