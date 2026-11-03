"""The VBOM dependency surface: one catalogue, one envelope, one standard document.

:mod:`cbom.vbom_dependency` answers twenty-nine questions about a vendor estate. This module
makes those answers *reachable* — from an API, from a script, from an export — without any of
the three re-implementing the graph.

Three pieces, and nothing else:

* :data:`QUESTIONS` — the catalogue. Every reader in ``vbom_dependency`` appears once, with
  the parameters it needs and the sentence it answers. A question that is not in the
  catalogue cannot be asked, which is how the surface stays in step with the module instead
  of drifting from it.
* :func:`ask` — one question, one envelope. A refusal comes back as ``{ok: false, code,
  reason}`` rather than as an exception, because an API that turns ``UNKNOWN_NODE`` into a
  500 has told the caller nothing about its own graph.
* :func:`assess` — a vendor payload (and optionally the live collector payloads from guide
  177) turned into **one** estate, one projection and a set of answers. Live collection and
  the vendor graph are the same estate: the collectors say what is deployed, the vendor
  payload says who supplies it, and the answers are the join.
* :func:`to_cyclonedx` — the vendor graph as a CycloneDX 1.6 document, validated against the
  schema already vendored for the CBOM exporter. Applicability, class and evidence travel in
  ``properties``, so the document says what it knows and how well.

The envelope is deliberately boring::

    {"schema", "question", "ok", "statement", "params", "result"}   # or
    {"schema", "question", "ok": false, "code", "reason", "params"}
"""

from __future__ import annotations

import inspect
from collections.abc import Iterable, Mapping
from typing import Any

from . import cyclonedx16 as cdx
from . import sbom_collectors as collectors
from . import techbom as tb
from . import vbom_dependency as vd

SCHEMA = "cryptoscan.vbom-surface/1"
ANSWER_SCHEMA = "cryptoscan.vbom-answer/1"
CDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"

#: question -> (reader, parameters, the sentence it answers). The parameter list is what the
#: surface will pass through and what the API will document; a parameter not listed here is
#: refused rather than silently dropped.
QUESTIONS: dict[str, dict[str, Any]] = {
    "vendor_products": {
        "reader": vd.vendor_products, "params": ("vendor",), "section": "vendor→product",
        "statement": "which products this vendor supplies, and which releases of each"},
    "product_releases": {
        "reader": vd.product_releases, "params": ("product",),
        "section": "vendor→product→version",
        "statement": "the releases of one product, with lifecycle and capabilities"},
    "declaration_applicability": {
        "reader": vd.declaration_applicability, "params": ("document", "product", "as_of"),
        "section": "version-applicability",
        "statement": "every declaration answered against every deployment of its release"},
    "verification": {
        "reader": vd.verification, "params": ("document", "product", "as_of"),
        "section": "document→deployment",
        "statement": "the five checks behind each applicability answer"},
    "applicability": {
        "reader": None, "params": ("declaration", "deployment", "as_of"),
        "section": "version-applicability",
        "statement": "one claim against one deployment, without a graph"},
    "vendor_assets": {
        "reader": vd.vendor_assets, "params": ("vendor", "as_of"), "section": "vendor→asset",
        "statement": "the assets the bank runs that a vendor supplies"},
    "hardware_chain": {
        "reader": vd.hardware_chain, "params": ("asset", "as_of"),
        "section": "vendor→hardware",
        "statement": "vendor → product → model → firmware → asset for one device"},
    "hardware_identity": {
        "reader": vd.hardware_identity, "params": ("asset",), "section": "vendor→HBOM",
        "statement": "the canonical hardware identity the HBOM also uses"},
    "software_chain": {
        "reader": vd.software_chain, "params": ("vendor", "product"),
        "section": "vendor→software",
        "statement": "vendor → product → release → package → application"},
    "crypto_chain": {
        "reader": vd.crypto_chain, "params": ("vendor", "product"), "section": "vendor→crypto",
        "statement": "declared capabilities with algorithm, key size, mode and purpose"},
    "declared_vs_observed": {
        "reader": vd.declared_vs_observed, "params": ("vendor", "product"),
        "section": "declared≠observed",
        "statement": "which declared capabilities were observed and which never were"},
    "vendor_applications": {
        "reader": vd.vendor_applications, "params": ("vendor",),
        "section": "vendor→application",
        "statement": "which applications depend on this vendor, with the path"},
    "vendor_systems": {
        "reader": vd.vendor_systems, "params": ("vendor",), "section": "vendor→business system",
        "statement": "which business systems are reachable from this vendor"},
    "crypto_business": {
        "reader": vd.crypto_business, "params": ("vendor", "algorithm"),
        "section": "vendor→crypto→system",
        "statement": "which business systems depend on this vendor for one algorithm"},
    "runtime_dependency": {
        "reader": vd.runtime_dependency, "params": ("vendor",), "section": "vendor→runtime",
        "statement": "which processes load the vendor's software and what was watched"},
    "network_dependency": {
        "reader": vd.network_dependency, "params": ("vendor",), "section": "vendor→network",
        "statement": "the network devices, endpoints and applications behind a vendor"},
    "network_identity": {
        "reader": vd.network_identity, "params": ("asset",), "section": "vendor→NBOM",
        "statement": "the endpoints and TLS mode of one vendor device"},
    "pki_dependency": {
        "reader": vd.pki_dependency, "params": ("vendor",), "section": "vendor→certificate",
        "statement": "the CA, certificates and endpoints of a PKI vendor"},
    "firmware_posture": {
        "reader": vd.firmware_posture, "params": ("firmware", "as_of"),
        "section": "vendor→firmware",
        "statement": "firmware dates, support state, security status and PQC claim"},
    "lifecycle_impact": {
        "reader": vd.lifecycle_impact, "params": ("product", "as_of"),
        "section": "vendor-lifecycle",
        "statement": "what an end-of-life product reaches, level by level"},
    "evidence_report": {
        "reader": vd.evidence_report, "params": ("as_of",), "section": "evidence-freshness",
        "statement": "how old each vendor document is and whether it still holds"},
    "sbom_agreement": {
        "reader": vd.sbom_agreement, "params": ("vendor", "product"), "section": "vendor→SBOM",
        "statement": "declared package version against the SBOM's version"},
    "cbom_agreement": {
        "reader": vd.cbom_agreement, "params": ("vendor", "product"), "section": "vendor→CBOM",
        "statement": "declared capabilities against CBOM observations"},
    "version_conflicts": {
        "reader": vd.version_conflicts, "params": (), "section": "vendor-conflict",
        "statement": "every subject with more than one version claim, layer by layer"},
    "history": {
        "reader": vd.history, "params": (), "section": "vendor-history",
        "statement": "vendor relationship changes with evidence on both sides"},
    "coverage": {
        "reader": vd.coverage, "params": (), "section": "vendor-coverage",
        "statement": "how much of the software estate has a vendor, unknown or internal"},
    "risk_propagation": {
        "reader": vd.risk_propagation, "params": ("vendor", "as_of"),
        "section": "vendor-risk",
        "statement": "the risk a vendor carries, travelled through the graph"},
    "pqc_posture": {
        "reader": vd.pqc_posture, "params": ("vendor", "product"), "section": "vendor-PQC",
        "statement": "declared, deployed and observed PQC — three answers, never ready"},
    "twin": {
        "reader": vd.twin, "params": (), "section": "vendor→twin",
        "statement": "the levels, edges and gaps the twin holds"},
}

#: the questions a caller may ask without passing a graph: they read the payload itself.
PAYLOAD_QUESTIONS: frozenset[str] = frozenset({"history", "coverage"})

#: the questions that need no parameter at all
PARAMETERLESS: frozenset[str] = frozenset({"version_conflicts", "twin"})



def _required(name: str) -> tuple[str, ...]:
    """The parameters a reader refuses to run without — read from its signature, not guessed.

    Deriving this from the function itself is the reason the catalogue cannot rot: change a
    reader's signature and the surface's required-parameter list changes with it.
    """
    entry = QUESTIONS[name]
    if name == "applicability":
        return ("declaration", "deployment")
    if not entry["reader"]:
        return ()
    params = inspect.signature(entry["reader"]).parameters
    return tuple(key for key, value in params.items()
                 if key != "bom" and value.default is inspect.Parameter.empty
                 and value.kind is inspect.Parameter.KEYWORD_ONLY)


#: public callables in :mod:`cbom.vbom_dependency` that are deliberately *not* questions, and
#: why. The catalogue test asserts this list is exactly the difference between the module's
#: public functions and the catalogue, so a new reader cannot be added and left unreachable.
NOT_QUESTIONS: dict[str, str] = {
    "build": "assembles the graph; the surface builds one per assessment",
    "from_documents": "the estate document before projection, not an answer about it",
    "levels": "the level counts — `summary` answers with these and the refusals beside them",
    "compare_versions": "one step of an applicability answer, not an answer",
    "lifecycle_of": "a lifecycle state for one row, not an estate question",
    "evidence_freshness": "one freshness answer for one document",
    "deploy_is_read": "a helper inside a declaration's deployment check",
}

#: the refusals the *surface* can emit, as opposed to the ones the readers emit. Kept short on
#: purpose: everything else is the module's vocabulary and the surface only passes it through.
SURFACE_CODES: frozenset[str] = frozenset({"UNKNOWN_QUESTION", "UNKNOWN_PARAMETER",
                                           "MISSING_PARAMETER"})

#: questions whose reader needs a *subject* — a vendor, a product, an asset — and refuses
#: without one. They are answered when the caller names a subject, not defaulted to "no".
NEEDS_SUBJECT: frozenset[str] = frozenset({
    "software_chain", "crypto_chain", "declared_vs_observed", "firmware_posture",
    "sbom_agreement", "cbom_agreement", "pqc_posture", "lifecycle_impact",
})

#: what :func:`assess` answers when the caller names no questions: every question that can be
#: asked of a graph alone. A question that needs a vendor name is asked when a vendor is
#: named, not answered with "no".
DEFAULT_QUESTIONS: tuple[str, ...] = tuple(
    name for name, _entry in QUESTIONS.items()
    if not _required(name) and name not in NEEDS_SUBJECT
)


def catalogue() -> dict[str, Any]:
    """The questions, in the order a reviewer asks them."""
    rows = [{"question": name, "section": entry["section"],
             "params": list(entry["params"]), "required": list(_required(name)),
             "statement": entry["statement"],
             "source": ("payload" if name in PAYLOAD_QUESTIONS
                        else "argument" if name == "applicability" else "projection")}
            for name, entry in QUESTIONS.items()]
    return {
        "schema": SCHEMA, "count": len(rows), "questions": rows,
        "statement": (f"{len(rows)} question(s) across "
                      f"{len({row['section'] for row in rows})} section(s)"),
        "rule": ("a question is asked through the catalogue or not at all: the surface "
                 "cannot invent a reader the module does not have"),
    }


def _run(name: str, *, bom: Mapping[str, Any], payload: Mapping[str, Any],
         params: Mapping[str, Any]) -> Any:
    entry = QUESTIONS[name]
    if name == "applicability":
        return vd.applicability(params.get("declaration") or {},
                                params.get("deployment") or {},
                                as_of=params.get("as_of"))
    if name in PAYLOAD_QUESTIONS or not QUESTIONS[name]["params"]:
        return entry["reader"](payload if name in PAYLOAD_QUESTIONS else bom)
    return entry["reader"](bom, **params)


def ask(bom: Mapping[str, Any], question: str, *, payload: Mapping[str, Any] | None = None,
        **params: Any) -> dict[str, Any]:
    """One question, one envelope — and a refusal that stays a refusal.

    A caller cannot pass a parameter the catalogue does not list, and cannot ask a question
    the catalogue does not hold. Both come back as ``ok: false`` with a code, because the
    alternative is an API that answers a slightly different question than the one asked.
    """
    name = str(question or "").strip()
    if name not in QUESTIONS:
        return {"schema": ANSWER_SCHEMA, "question": name or None, "ok": False,
                "code": "UNKNOWN_QUESTION",
                "reason": f"{name or '(none)'} is not a question this surface answers; see "
                          f"the catalogue for the {len(QUESTIONS)} it does",
                "params": {}, "result": None}
    missing = [key for key in _required(name) if key not in params]
    if missing:
        return {"schema": ANSWER_SCHEMA, "question": name, "ok": False,
                "code": "MISSING_PARAMETER",
                "reason": f"{name} needs {', '.join(_required(name))}; {', '.join(missing)} "
                          f"was not given",
                "params": dict(params), "result": None}
    unknown = sorted(set(params) - set(QUESTIONS[name]["params"]))
    if unknown:
        return {"schema": ANSWER_SCHEMA, "question": name, "ok": False,
                "code": "UNKNOWN_PARAMETER",
                "reason": f"{', '.join(unknown)} is not a parameter of {name}; it takes "
                          f"{', '.join(QUESTIONS[name]['params']) or 'none'}",
                "params": {}, "result": None}
    try:
        result = _run(name, bom=bom, payload=payload or {}, params=params)
    except tb.ClaimRefused as exc:
        return {"schema": ANSWER_SCHEMA, "question": name, "ok": False, "code": exc.code,
                "reason": exc.reason, "params": dict(params), "result": None}
    return {
        "schema": ANSWER_SCHEMA, "question": name, "ok": True,
        "section": QUESTIONS[name]["section"],
        "statement": (result or {}).get("statement") if isinstance(result, Mapping)
        else None,
        "params": dict(params), "result": result,
    }


def assess(payload: Mapping[str, Any], *, live: Iterable[Mapping[str, Any]] | None = None,
           as_of: Any = None, questions: Iterable[str] | None = None,
           given: Mapping[str, Mapping[str, Any]] | None = None,
           estate_id: str = "vbom:assessment") -> dict[str, Any]:
    """A vendor payload (and the collectors' payloads) → one graph → the answers asked for.

    ``live`` is the guide-177 side: registry manifests, a CI run, a process trace. They are
    collected first and their rows are folded into the vendor payload's own inventory, so an
    application discovered by a collector and a product registered by procurement are the
    same estate and the same answer. Nothing is merged by name — a collector names a package
    and the vendor payload names a product, and the join between them is the SBOM's.
    """
    body = dict(payload or {})
    collected: list[dict[str, Any]] = []
    if live:
        results = collectors.collect_all(live, as_of=as_of or body.get("as_of"))
        merged = collectors.collect(*results, as_of=as_of or body.get("as_of"))
        collected = results
        body = _fold_live(body, merged["inventory"])
    built = vd.build(body, as_of=as_of or body.get("as_of"), estate_id=estate_id)
    asked = list(DEFAULT_QUESTIONS if questions is None else questions)
    answers = [ask(built["bom"], name, payload=body,
                   **({"as_of": as_of or body.get("as_of")}
                      if "as_of" in QUESTIONS[name]["params"] else {}),
                   **(given or {}).get(name, {}))
               for name in asked]
    refused = [answer for answer in answers if not answer["ok"]]
    return {
        "schema": SCHEMA,
        "as_of": built["as_of"],
        "graph": {**built, "bom": None},
        "document": built["bom"],
        "live": {
            "transports": sorted({result["transport"] for result in collected}),
            "rows": sum(sum((result.get("counts") or {}).values()) for result in collected),
        },
        "answers": answers,
        "refused": refused,
        "statement": (f"{built['statement']}; {len(answers)} question(s) answered, "
                      f"{len(refused)} refused"
                      + (f" ({', '.join(answer['question'] for answer in refused)})"
                         if refused else "")),
        "rule": ("the surface answers from one estate: a live collector and a vendor "
                 "document that disagree are two rows, and the answer says so"),
    }


def _fold_live(body: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    """Live collector rows → the vendor payload's own sections.

    Only the rows the vendor graph reads are folded: packages (what is installed), usage
    (processes and operations), applications and systems (what depends on what). A vendor
    payload that already names one of them keeps its own row — procurement beats a scan for
    *who supplies*, and the scan beats procurement for *what version is running*, which is
    why the two stay in different fields.
    """
    merged = dict(body)
    packages = list(merged.get("packages") or [])
    known = {str(row.get("coordinate") or "").lower() for row in packages
             if isinstance(row, Mapping)}
    # a release's own packages are already in the estate, so a scan that names the same
    # coordinate is agreeing with the vendor payload, not adding a second copy of it.
    known |= {str(package.get("coordinate") or "").lower()
              for release in merged.get("releases") or [] if isinstance(release, Mapping)
              for package in release.get("packages") or [] if isinstance(package, Mapping)}
    for row in inventory.get("software") or []:
        coordinate = str(row.get("coordinate") or "")
        if not coordinate or coordinate.lower() in known:
            continue
        known.add(coordinate.lower())
        packages.append({"coordinate": coordinate, "version": row.get("version"),
                         "product": row.get("product"),
                         "evidence_id": row.get("evidence_ref")})
    merged["packages"] = packages

    usage = list(merged.get("usage") or [])
    seen = {(str(row.get("process") or ""), str(row.get("algorithm") or ""))
            for row in usage if isinstance(row, Mapping)}
    for row in inventory.get("crypto") or []:
        key = (str(row.get("process") or ""), str(row.get("algorithm") or ""))
        if not row.get("process") or key in seen:
            continue
        seen.add(key)
        usage.append({"application": row.get("application"), "process": row.get("process"),
                      "pid": row.get("pid"), "host": row.get("host"),
                      "algorithm": row.get("algorithm"), "key_size": row.get("key_size"),
                      "mode": row.get("mode"), "operation": row.get("operation"),
                      "observed_at": row.get("observed_at"),
                      "evidence_id": row.get("evidence_ref")})
    merged["usage"] = usage

    applications = list(merged.get("applications") or [])
    known_apps = {str(row.get("name") or "").lower() for row in applications
                  if isinstance(row, Mapping)}
    for row in inventory.get("applications") or []:
        name = str(row.get("name") or "")
        if not name or name.lower() in known_apps:
            continue
        known_apps.add(name.lower())
        applications.append({"name": name, "system": row.get("system"),
                             "owner": row.get("owner"),
                             "system_criticality": row.get("criticality")})
    merged["applications"] = applications
    return merged


# --------------------------------------------------------------------------- #
# CycloneDX: the vendor graph as a document another tool can read
# --------------------------------------------------------------------------- #

#: CycloneDX 1.6 has thirteen component types and none of them is "hardware", "service" or
#: "organization". An appliance is a ``device``, a CA is an ``application``, a vendor is not a
#: component at all — it is the ``supplier`` of the things it sells. Mapping into the format's
#: own vocabulary instead of inventing this one's is the difference between a document a
#: scanner can read and XML-shaped JSON.
_COMPONENT_TYPE: dict[str, str] = {
    "VENDOR_PRODUCT": "application", "PRODUCT_VERSION": "application",
    "APPLICATION": "application", "SERVICE": "application",
    "BUSINESS_SYSTEM": "application", "CERTIFICATE_AUTHORITY": "application",
    "PROCESS": "application",
    "CRYPTO_LIBRARY": "library", "PACKAGE": "library",
    "FIRMWARE": "firmware",
    "VM": "platform",
    "HSM": "device", "KMS": "device", "TPM": "device", "HOST": "device",
    "PHYSICAL_SERVER": "device", "SECURITY_APPLIANCE": "device",
    "CRYPTO_ACCELERATOR": "device", "LOAD_BALANCER": "device", "WAF": "device",
    "API_GATEWAY": "device", "SERVICE_MESH": "device", "VPN_GATEWAY": "device",
    "FIREWALL": "device", "IDS": "device", "IPS": "device", "DATABASE": "device",
    "SMART_CARD": "device", "KUBERNETES_NODE": "device", "CLOUD_INSTANCE": "device",
    "CERTIFICATE": "data", "NETWORK_ENDPOINT": "data", "EVIDENCE": "data",
    "CRYPTO_CAPABILITY": "cryptographic-asset", "CRYPTO_ASSET": "cryptographic-asset",
    "ALGORITHM": "cryptographic-asset", "CRYPTO_OPERATION": "cryptographic-asset",
}

#: Containment: "a product *releases* a version" is not a dependency, it is composition.
#: CycloneDX has nested components for exactly this, so a release lives inside its product and
#: a package inside the release. child relation → parent is the direction stored.
_CONTAINS: dict[str, str] = {  # relation → which end of the stored edge is the child
    "RELEASES": "to",         # product RELEASES release → release nested in product
    "FIRMWARE_OF": "from",    # firmware FIRMWARE_OF release → firmware nested in release
    "SHIPS_PACKAGE": "to",    # release SHIPS_PACKAGE package → package nested in release
}

#: Dependencies: "A needs B to work". ``forward`` means the edge already points from the
#: dependent to the provider; ``reverse`` means the stored edge points the other way (an
#: asset *serves* an application, so the application depends on the asset). Every relation
#: not listed here stays a ``cryptoscan:relation`` property: a dependency a consumer would
#: install is a promise this module will not make on the strength of a vendor datasheet.
_DEPENDS: dict[str, str] = {
    "HAS_MODEL": "forward",        # device HAS_MODEL product
    "RUNS_FIRMWARE": "forward",    # device RUNS_FIRMWARE firmware
    "SUPPLIED_BY": "forward",      # asset SUPPLIED_BY product
    "RUNS_APPLICATION": "forward",  # process RUNS_APPLICATION application
    "SERVES": "reverse",           # asset SERVES application → application needs asset
    "LOADS": "forward",            # process LOADS package
}

#: levels exported. A VBOM document about vendors, products and releases that also carried
#: the runtime and the algorithm would be a CBOM with a vendor heading; those two have their
#: own exporters.
_CDX_LEVELS: frozenset[str] = frozenset({"product", "release", "firmware", "package", "asset",
                                         "application", "system"})

#: supplier relations: a vendor row pointing at the thing it sells. These do not become
#: components — they become the component's ``supplier``.
_SUPPLIER_RELATIONS: frozenset[str] = frozenset({"SUPPLIED_BY", "PRODUCT_OF"})


def _ref(row: Mapping[str, Any]) -> str:
    return f"{row['kind'].lower()}:{str(row['name']).lower()}"


def _component_type(kind: str) -> str:
    """One mapping, checked. A kind with no CycloneDX type is ``data``, not an exception."""
    return _COMPONENT_TYPE.get(kind, "data")


#: worst-first: when one asset is reached by several declarations, the component carries the
#: state a reviewer must act on, not the one that happens to sort first.
_STATE_PRECEDENCE: tuple[str, ...] = (
    vd.VERSION_MISMATCH, vd.PRODUCT_MISMATCH, vd.EXPIRED, vd.SUPERSEDED,
    vd.DEPLOYMENT_UNVERIFIED, vd.PARTIAL_MATCH, vd.MATCHED, vd.UNKNOWN_APPLICABILITY,
)


def _applicability_by_asset(applicability: Mapping[str, Any] | None) -> dict[str, str]:
    """``asset name → worst applicability state``, from a declaration/deployment report."""
    found: dict[str, str] = {}
    for row in (applicability or {}).get("declarations") or []:
        asset = str((row.get("deployment") or {}).get("asset") or "").lower()
        state = row.get("state")
        if not asset or not state:
            continue
        current = found.get(asset)
        if current is None or (_STATE_PRECEDENCE.index(state)
                               < _STATE_PRECEDENCE.index(current)):
            found[asset] = state
    return found


def to_cyclonedx(bom: Mapping[str, Any], *, as_of: Any = None,
                 applicability: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The vendor graph as CycloneDX 1.6, with the confidence carried in properties.

    Three decisions shape the document, and each one is about not lying in a format:

    * **A vendor is not a component.** CycloneDX has no such type. It has ``supplier``, so
      that is where a vendor goes — on the product it sells.
    * **Composition is nesting.** A product *releases* versions; those versions are nested
      components of the product, firmware and packages nested in turn. Making them
      ``dependsOn`` entries would say a product cannot run without its version, which is
      not what a vendor BOM means.
    * **Only real needs become dependencies.** A device has a model, runs firmware, is
      supplied by a product. Everything else — who documented it, what declared it, who
      approved it — is a ``cryptoscan:relation`` property, because the format's
      ``dependsOn`` is an installation contract and this module's edges are evidence.

    The document is validated against the schema vendored for the CBOM exporter, so a
    regression in this projection fails here rather than in a customer's importer.
    """
    states = dict((applicability or {}).get("states") or {})
    by_asset = _applicability_by_asset(applicability)
    rows = {row["key"]: row for row in bom["assets"]}
    vendors = {row["key"]: row for row in bom["assets"] if row["kind"] == "VENDOR"}
    exported = {row["key"]: row for row in bom["assets"]
                if vd.KIND_LEVEL.get(row["kind"]) in _CDX_LEVELS}

    suppliers: dict[str, tuple[str, str]] = {}
    parent: dict[str, str] = {}
    dependencies: dict[str, set[str]] = {}
    relations: dict[str, list[str]] = {}
    for claim in bom["claims"]:
        source, target = rows.get(claim["from_key"]), rows.get(claim["to_key"])
        if source is None or target is None:
            continue
        relation = claim["relation"]
        if relation in _SUPPLIER_RELATIONS and claim["to_key"] in vendors:
            suppliers.setdefault(claim["from_key"],
                                 (vendors[claim["to_key"]]["name"], claim["basis"]))
            continue
        if claim["from_key"] not in exported:
            continue  # a vendor or a runtime row: nothing to hang this on
        if relation in _CONTAINS and claim["to_key"] in exported:
            child = (claim["to_key"] if _CONTAINS[relation] == "to"
                     else claim["from_key"])
            owner = (claim["from_key"] if child == claim["to_key"] else claim["to_key"])
            if child != owner:
                parent.setdefault(child, owner)
            continue
        if relation in _DEPENDS and claim["to_key"] in exported:
            dependent = (claim["from_key"] if _DEPENDS[relation] == "forward"
                         else claim["to_key"])
            provider = (claim["to_key"] if dependent == claim["from_key"]
                        else claim["from_key"])
            if dependent != provider:
                dependencies.setdefault(dependent, set()).add(provider)
            continue
        relations.setdefault(claim["from_key"], []).append(
            f"{relation.lower()} {_ref(target)} "
            f"({claim['confidence']} via {claim['basis']})")

    def build_component(key: str, depth: int = 0) -> dict[str, Any]:
        row = exported[key]
        properties = [
            {"name": "cryptoscan:level", "value": vd.KIND_LEVEL.get(row["kind"], "unknown")},
            {"name": "cryptoscan:kind", "value": row["kind"]},
            {"name": "cryptoscan:environment", "value": row.get("environment") or "UNKNOWN"},
        ]
        for name in ("lifecycle", "support_status", "support_level", "eol_date", "eos_date",
                     "security_status", "pqc_capability", "product_family", "product_type",
                     "serial", "location", "owner", "evidence_freshness"):
            value = (row.get("attributes") or {}).get(name)
            if value not in (None, "", [], {}):
                properties.append({"name": f"cryptoscan:{name}", "value": str(value)})
        state = ((bom.get("applicability") or {}).get(key)
                 or by_asset.get(str(row["name"]).lower()))
        if state:
            properties.append({"name": "cryptoscan:applicability", "value": str(state)})
        for evidence in row.get("evidence_ids") or []:
            properties.append({"name": "cryptoscan:evidence", "value": str(evidence)})
        for relation in sorted(relations.get(key, [])):
            properties.append({"name": "cryptoscan:relation", "value": relation})
        component: dict[str, Any] = {
            "type": _component_type(row["kind"]),
            "bom-ref": _ref(row), "name": row["name"], "properties": properties,
        }
        if row.get("version"):
            component["version"] = str(row["version"])
            properties.append({"name": "cryptoscan:version", "value": str(row["version"])})
        supplier = suppliers.get(key)
        if supplier:
            component["supplier"] = {"name": supplier[0]}
            properties.append({"name": "cryptoscan:supplier_basis", "value": supplier[1]})
        if depth < 4:
            children = sorted(child for child, owner in parent.items() if owner == key)
            nested = [build_component(child, depth + 1) for child in children
                      if child in exported]
            if nested:
                component["components"] = nested
        return component

    roots = sorted(key for key in exported if key not in parent or parent[key] not in exported)
    components = [build_component(key) for key in roots]
    dependency_entries = [{"ref": _ref(exported[key]),
                           "dependsOn": sorted({_ref(exported[need]) for need in needs
                                                if need in exported})}
                          for key, needs in sorted(dependencies.items())
                          if any(need in exported for need in needs)]

    document = {
        "$schema": CDX_SCHEMA,
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": datetime_text(as_of),
            "component": {
                "type": "application", "bom-ref": "vbom:vendor-dependency",
                "name": "CryptoScan VBOM — vendor dependency graph",
                "properties": [
                    {"name": "cryptoscan:bom", "value": "VBOM"},
                    {"name": "cryptoscan:profile",
                     "value": "VENDOR_DEPENDENCY_WITH_APPLICABILITY"},
                    {"name": "cryptoscan:applicability_states",
                     "value": ", ".join(f"{state}:{count}"
                                        for state, count in sorted(states.items())) or "none"},
                ] + [{"name": "cryptoscan:vendor", "value": vendor["name"]}
                     for vendor in sorted(vendors.values(), key=lambda row: row["name"])],
            },
        },
        "components": components,
        "dependencies": dependency_entries,
    }
    check = cdx.validate_cyclonedx16(document)
    edges = sum(len(items) for items in relations.values())
    return {
        "schema": SCHEMA, "document": document, "validation": check,
        "components": len(exported), "top_level": len(components),
        "vendors": len(vendors), "nested": len(parent),
        "dependency_refs": len(dependency_entries), "relation_properties": edges,
        "statement": (f"{len(exported)} component(s) ({len(components)} top-level, "
                      f"{len(parent)} nested), {len(dependency_entries)} dependency "
                      f"entr(ies), {edges} relation propert(ies), {len(vendors)} "
                      f"supplier(s); schema {'valid' if check['ok'] else 'INVALID'}"),
        "rule": ("a vendor is a supplier and not a component, a release is nested in its "
                 "product and not a dependency, and only a real need becomes dependsOn — "
                 "the rest travels as properties, basis included"),
    }


def datetime_text(value: Any = None) -> str:
    """An ISO-8601 UTC timestamp — the document's, not the clock's, when one was given."""
    text = tb._norm(value)
    if text:
        return text if "T" in text else f"{text}T00:00:00Z"
    from datetime import datetime, timezone  # noqa: PLC0415 — only needed here

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summary(bom: Mapping[str, Any], *, vendor: Any = None,
            refusals: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """The three numbers a caller wants first: levels, applicability, and what is unmapped.

    ``refusals`` is what the *builder* refused while assembling the estate — a row it could not
    place at all. The document keeps only the refusals its projection made, so a caller that
    has both passes both; the two are counted together and de-duplicated by code and subject.
    """
    levels = vd.levels(bom)
    states = vd.declaration_applicability(bom)["states"]
    seen: set[tuple[str, str]] = set()
    rows: list[Mapping[str, Any]] = []
    for row in [*(refusals or []), *(bom.get("refusals") or [])]:
        key = (str(row.get("code")), str(row.get("subject")))
        if row.get("code") and key not in seen:
            seen.add(key)
            rows.append(row)
    unresolved = sorted({row["subject"] for row in rows})
    return {
        "schema": SCHEMA,
        "vendor": vendor,
        "levels": levels,
        "applicability": states,
        "refusals": len(rows),
        "refusal_codes": sorted({str(row["code"]) for row in rows}),
        "unresolved": unresolved[:10],
        "statement": (f"{sum(levels.values())} node(s) across "
                      f"{len([count for count in levels.values() if count])} level(s); "
                      + (", ".join(f"{state} {count}"
                                   for state, count in sorted(states.items())) or
                         "no declaration reaches a deployment")
                      + f"; {len(rows)} refusal(s)"),
        "rule": ("a summary that hides the refusals is a summary of the model, not of the "
                 "estate"),
    }
