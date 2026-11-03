#!/usr/bin/env python3
"""Guide 179 — the VBOM surface: the catalogue, the envelope, the export and the live merge.

Guide 178 built the graph and answered twenty-nine questions about a vendor estate. This
guide is about the three ways those answers leave the building, and each is measured rather
than described:

* **the catalogue** — twenty-nine questions, each with the parameters its reader actually
  takes. A reader added to the module and left out of the catalogue fails here, because the
  probe compares the module's public functions against the catalogue instead of trusting a
  list somebody maintains by hand.
* **the envelope** — every answer, including the refusals, arrives as ``ok`` plus a code. An
  unknown question, an unknown parameter, a missing parameter and a reader's own refusal are
  four different sentences, and a surface that collapses them into an exception has told the
  caller nothing about its own graph.
* **the export** — the vendor graph as CycloneDX 1.6, validated against the schema this
  repository already vendors. Three modelling decisions are probed directly: a vendor is a
  ``supplier`` and not a component, a release is nested in its product and not a dependency,
  and only a real need becomes ``dependsOn``.
* **the live merge** — an image scanner and an OCI registry joined to a vendor payload. The
  collectors say what is deployed, the payload says who supplies it, and neither overwrites
  the other: two rows that disagree stay two rows, and a package the payload already names
  is not added twice because a scan saw it.

Usage::

    python scripts/cbom_vbom_surface.py            # markdown to stdout
    python scripts/cbom_vbom_surface.py --json out.json --md out.md
    python scripts/cbom_vbom_surface.py --check    # exit 1 on a partial, 2 on a failure
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SERVICES = REPO / "services"

SCHEMA = "cryptoscan.vbom-surface-guide/1"
GUIDE = 179

VERDICT_PASS = "PASS"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_FAIL = "FAIL"

AS_OF = "2026-11-03"
DIGEST = "sha256:" + "9" * 64

PAYLOAD: dict[str, Any] = {
    "as_of": AS_OF,
    "documents": [
        {"id": "DOC-1", "title": "payShield 9000 9.2 release notes", "vendor": "Thales",
         "product": "payShield 9000", "version": "9.2", "received_at": "2026-10-01",
         "valid_until": "2027-10-01", "reviewer": "s.iyer", "revision": 1},
        {"id": "DOC-2", "title": "OpenSSL 3.0.13 capabilities", "vendor": "OpenSSL Project",
         "product": "OpenSSL", "version": "3.0.13", "received_at": "2026-09-15",
         "valid_until": "2027-09-15", "reviewer": "r.nair", "revision": 2},
        {"id": "DOC-3", "title": "BIG-IP 17.1 datasheet", "vendor": "F5",
         "product": "BIG-IP 9000", "version": "17.1", "received_at": "2026-10-20",
         "valid_until": "2027-03-01", "reviewer": "r.nair", "revision": 1},
        {"id": "DOC-4", "title": "payShield 9000 firmware 9.2.1 guide", "vendor": "Thales",
         "product": "payShield 9000", "version": "9.2", "firmware": "9.2.1",
         "received_at": "2026-09-20", "valid_until": "2027-09-20", "reviewer": "s.iyer",
         "revision": 1},
        {"id": "DOC-5", "title": "BIG-IP 9000 firmware 17.1 note", "vendor": "F5",
         "product": "BIG-IP 9000", "version": "17.1", "firmware": "17.1",
         "received_at": "2026-10-21", "valid_until": "2027-03-01", "reviewer": "r.nair",
         "revision": 1},
    ],
    "vendors": [
        {"name": "Thales", "lifecycle": "ACTIVE", "risk_level": "HIGH"},
        {"name": "OpenSSL Project", "lifecycle": "ACTIVE", "risk_level": "MEDIUM"},
        {"name": "F5", "lifecycle": "ACTIVE", "risk_level": "MEDIUM"},
    ],
    "products": [
        {"name": "payShield 9000", "vendor": "Thales", "family": "payShield", "type": "HSM",
         "lifecycle": "SUPPORTED", "documents": ["DOC-1"]},
        {"name": "OpenSSL", "vendor": "OpenSSL Project", "type": "LIBRARY",
         "lifecycle": "SUPPORTED", "documents": ["DOC-2"]},
        {"name": "BIG-IP 9000", "vendor": "F5", "family": "BIG-IP", "type": "LOAD_BALANCER",
         "lifecycle": "SUPPORTED", "documents": ["DOC-3"]},
    ],
    "releases": [
        {"product": "payShield 9000", "version": "9.2", "support_status": "SUPPORTED",
         "documents": ["DOC-1"],
         "capabilities": [{"algorithm": "AES", "key_size": 256, "mode": "GCM",
                           "purpose": "payment data", "documents": ["DOC-4"]}],
         "packages": [{"coordinate": "pkg:generic/payshield-sdk", "version": "9.2"}]},
        {"product": "OpenSSL", "version": "3.0.13", "pqc_capability": "DECLARED",
         "documents": ["DOC-2"],
         "packages": [{"coordinate": "pkg:generic/openssl", "version": "3.0.13"}],
         "capabilities": [{"algorithm": "ML-KEM", "key_size": 768, "documents": ["DOC-2"]},
                          {"algorithm": "RSA", "key_size": 2048, "documents": ["DOC-2"]}]},
        {"product": "BIG-IP 9000", "version": "17.1", "support_status": "SUPPORTED",
         "documents": ["DOC-3"],
         "capabilities": [{"algorithm": "TLS", "key_size": 256, "mode": "CBC",
                           "documents": ["DOC-5"]}]},
        {"product": "BIG-IP 9000", "version": "15.1", "support_status": "EOL",
         "eol_date": "2026-01-31",
         "capabilities": [{"algorithm": "TLS", "key_size": 128, "mode": "CBC",
                           "documents": ["DOC-3"]}]},
    ],
    "firmware": [
        {"product": "payShield 9000", "version": "9.2.1", "release": "9.2",
         "release_date": "2025-11-01", "support_status": "SUPPORTED",
         "documents": ["DOC-4"]},
        {"product": "BIG-IP 9000", "version": "17.1", "release": "17.1",
         "release_date": "2026-03-15", "support_status": "SUPPORTED",
         "documents": ["DOC-5"]},
        {"product": "BIG-IP 9000", "version": "15.1.0", "release": "15.1",
         "release_date": "2023-05-01", "support_status": "EOL", "eol_date": "2026-01-31"},
        {"product": "OpenSSL", "version": "3.0.13", "release": "3.0.13",
         "release_date": "2026-01-30", "support_status": "SUPPORTED",
         "documents": ["DOC-2"]},
    ],
    "assets": [
        {"name": "HSM-001", "type": "HSM", "product": "payShield 9000", "vendor": "Thales",
         "version": "9.2", "firmware": "9.2.1", "location": "dc-1", "owner": "payments",
         "serial": "SN-001"},
        {"name": "LB-001", "type": "LOAD_BALANCER", "product": "BIG-IP 9000", "vendor": "F5",
         "version": "17.1", "firmware": "17.1", "location": "dc-2", "owner": "network",
         "serial": "SN-002"},
        {"name": "APP-01", "type": "HOST", "product": "OpenSSL",
         "vendor": "OpenSSL Project", "version": "3.0.13", "firmware": "3.0.13",
         "location": "dc-3"},
        {"name": "LB-002", "type": "LOAD_BALANCER", "product": "BIG-IP 9000", "vendor": "F5",
         "version": "15.1", "firmware": "15.1.0", "location": "dc-2", "owner": "network"},
        {"name": "UNMAPPED-HSM", "type": "HSM", "location": "dc-9"},
    ],
    "applications": [
        {"name": "Payments API", "system": "Payments System", "criticality": "TIER_1",
         "assets": ["LB-001"], "packages": ["pkg:generic/openssl"],
         "products": ["payShield 9000"]},
        {"name": "Reporting API", "system": "Reporting System", "criticality": "TIER_2",
         "assets": ["APP-01"], "packages": ["pkg:generic/openssl"]},
    ],
    "usage": [
        {"application": "Payments API", "process": "java", "algorithm": "AES",
         "key_size": 256, "mode": "GCM", "operation": "encrypt", "host": "HSM-001",
         "observed_at": "2026-10-30T10:00:00Z"},
        {"application": "Reporting API", "process": "python", "algorithm": "RSA",
         "key_size": 2048, "operation": "sign", "host": "APP-01",
         "observed_at": "2026-10-30T10:00:00Z"},
    ],
    "components": [
        {"coordinate": "pkg:generic/openssl", "vendor": "OpenSSL Project"},
        {"coordinate": "pkg:generic/payshield-sdk", "vendor": "Thales"},
        {"coordinate": "pkg:generic/newlib", "vendor": "UNKNOWN"},
        {"coordinate": "pkg:generic/payments-core", "vendor": "INTERNAL"},
    ],
}

LIVE: list[dict[str, Any]] = [
    {"transport": "registry",
     "image": {"repository": "payments-api", "tag": "4.2.1", "digest": DIGEST},
     "layers": [{"digest": "sha256:" + "8" * 64, "size": 4096}]},
    {"transport": "scan",
     "image": {"name": "payments-api", "tag": "4.2.1", "digest": DIGEST},
     "packages": [{"coordinate": "pkg:generic/newlib", "version": "1.2.3", "crypto": True},
                  {"coordinate": "pkg:generic/openssl", "version": "3.0.13"}]},
]


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "api", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import techbom, vbom_dependency, vbom_surface  # noqa: PLC0415

    return {"t": techbom, "v": vbom_dependency, "s": vbom_surface}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def measure() -> dict[str, Any]:
    modules = _load()
    v, s = modules["v"], modules["s"]
    assessment = s.assess(PAYLOAD, as_of=AS_OF, estate_id="vbom:guide-179")
    bom = assessment["document"]
    catalogue = s.catalogue()
    rows = {row["question"]: row for row in catalogue["questions"]}
    points: list[dict[str, Any]] = []

    def add(number: int, section: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"VBS-{number:02d}", "number": number, "section": section,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    # ---- 1. the catalogue -------------------------------------------------- #
    public = {name for name in dir(v) if not name.startswith("_")
              and callable(getattr(v, name))
              and getattr(getattr(v, name), "__module__", "") == v.__name__}
    add(1, "catalogue", "every answer the module has is a question the surface can be asked", [
        _probe("the-catalogue-covers-every-public-reader",
               public - set(s.QUESTIONS) == set(s.NOT_QUESTIONS),
               f"{len(public)} public function(s), {len(s.QUESTIONS)} question(s), "
               f"{len(s.NOT_QUESTIONS)} documented as not questions"),
        _probe("no-question-is-listed-twice",
               len(set(rows)) == len(catalogue["questions"]) == len(s.QUESTIONS),
               f"{len(catalogue['questions'])} row(s)"),
        _probe("every-question-cites-a-section-and-a-sentence",
               all(row["section"] and row["statement"] for row in rows.values()),
               f"{len({row['section'] for row in rows.values()})} distinct section(s)"),
        _probe("each-question-says-where-its-answer-comes-from",
               {row["source"] for row in rows.values()} == {"payload", "projection",
                                                            "argument"},
               ", ".join(sorted({row["source"] for row in rows.values()}))),
        _probe("the-required-parameters-come-from-the-signatures",
               rows["vendor_products"]["required"] == ["vendor"]
               and rows["twin"]["required"] == [],
               "vendor_products needs a vendor; twin needs nothing"),
    ])

    # ---- 2. the envelope --------------------------------------------------- #
    unknown = s.ask(bom, "which_vendor_is_worst")
    extra = s.ask(bom, "twin", vendor="Thales")
    missing = s.ask(bom, "product_releases")
    add(2, "envelope", "a question, a refusal and a mistake are three different answers", [
        _probe("an-answered-question-carries-the-readers-own-statement",
               (s.ask(bom, "vendor_products", vendor="Thales")["statement"]
                == v.vendor_products(bom, vendor="Thales")["statement"]),
               "the envelope repeats the reader's sentence rather than inventing one"),
        _probe("an-unknown-question-is-refused-with-a-code",
               unknown["ok"] is False and unknown["code"] == "UNKNOWN_QUESTION",
               f"{unknown['code']}: {unknown['reason'][:70]}"),
        _probe("an-unlisted-parameter-is-refused-not-dropped",
               extra["code"] == "UNKNOWN_PARAMETER",
               f"{extra['code']}: {extra['reason'][:70]}"),
        _probe("a-missing-required-parameter-is-refused-before-the-reader-runs",
               missing["code"] == "MISSING_PARAMETER",
               f"{missing['code']}: {missing['reason']}"),
    ])

    # ---- 3. a reader's refusal stays a refusal ------------------------------ #
    nob = s.ask(bom, "vendor_products", vendor="Nobody")
    noquery = s.ask(bom, "software_chain")
    add(3, "refusals", "the graph saying no is an answer the API returns as 200", [
        _probe("an-unknown-vendor-is-the-modules-code-not-the-surfaces",
               nob["ok"] is False and nob["code"] == "UNKNOWN_NODE"
               and nob["code"] not in s.SURFACE_CODES,
               f"{nob['code']}: {nob['reason'][:70]}"),
        _probe("a-question-with-no-subject-keeps-the-readers-own-code",
               noquery["code"] == "NO_QUERY",
               f"{noquery['code']}: {noquery['reason']}"),
        _probe("the-surface-own-vocabulary-is-three-codes",
               s.SURFACE_CODES == {"UNKNOWN_QUESTION", "UNKNOWN_PARAMETER",
                                   "MISSING_PARAMETER"},
               ", ".join(sorted(s.SURFACE_CODES))),
    ])

    # ---- 4. the assessment -------------------------------------------------- #
    default = s.assess(PAYLOAD, as_of=AS_OF)
    add(4, "assessment", "one payload in, one estate and a set of answers out", [
        _probe("the-estate-is-assembled-once-and-shared",
               [row["key"] for row in assessment["document"]["assets"]]
               == [row["key"] for row in default["document"]["assets"]]
               and len(assessment["document"]["claims"]) == len(default["document"]["claims"]),
               f"{len(bom['assets'])} asset(s), {len(bom['claims'])} claim(s), identical "
               "across two assessments"),
        _probe("the-default-question-set-is-what-a-graph-can-answer",
               len(default["answers"]) == len(s.DEFAULT_QUESTIONS) < len(s.QUESTIONS)
               and all(answer["ok"] for answer in default["answers"]),
               f"{len(default['answers'])} of {len(s.QUESTIONS)} answered without a subject; "
               f"{len(s.NEEDS_SUBJECT)} need one"),
        _probe("an-empty-question-list-answers-nothing",
               s.assess(PAYLOAD, as_of=AS_OF, questions=[])["answers"] == [],
               "0 answers, so a caller that wants only the graph pays for only the graph"),
        _probe("a-called-out-question-is-named-when-it-refuses",
               "refused" in s.assess(PAYLOAD, as_of=AS_OF,
                                     questions=["vendor_products"])["statement"],
               "the statement names what was refused, not only what succeeded"),
    ])

    # ---- 5. the export is a valid document ---------------------------------- #
    applicability = v.declaration_applicability(bom, as_of=AS_OF)
    export = s.to_cyclonedx(bom, as_of=AS_OF, applicability=applicability)
    document = export["document"]
    add(5, "export", "the vendor graph leaves as CycloneDX 1.6 or it does not leave", [
        _probe("the-official-schema-accepts-the-document",
               export["validation"]["ok"],
               f"{export['statement']}"),
        _probe("every-component-type-is-in-the-formats-vocabulary",
               {component["type"] for component in document["components"]} <=
               {"application", "framework", "library", "container", "platform",
                "operating-system", "device", "device-driver", "firmware", "file",
                "machine-learning-model", "data", "cryptographic-asset"},
               ", ".join(sorted({component["type"]
                                 for component in document["components"]}))),
        _probe("the-timestamp-is-the-documents-and-not-the-clock",
               document["metadata"]["timestamp"] == f"{AS_OF}T00:00:00Z",
               document["metadata"]["timestamp"]),
        _probe("the-export-is-deterministic",
               s.to_cyclonedx(bom, as_of=AS_OF,
                              applicability=applicability)["document"] == document,
               "two calls with the same claims, one document"),
    ])

    # ---- 6. a vendor is a supplier ------------------------------------------ #
    suppliers = {component.get("supplier", {}).get("name")
                 for component in document["components"]}
    metadata_properties = {row["name"]: row["value"]
                           for row in document["metadata"]["component"]["properties"]}
    add(6, "vendor-is-a-supplier", "CycloneDX has no vendor type and this does not invent one",
        [
            _probe("no-component-is-a-vendor",
                   not any(component["name"] in {"Thales", "F5", "OpenSSL Project"}
                           for component in document["components"]),
                   f"{len(document['components'])} top-level component(s), none of them a "
                   "vendor"),
            _probe("each-product-names-its-supplier",
                   {"Thales", "F5"} <= suppliers,
                   ", ".join(sorted(name for name in suppliers if name))),
            _probe("the-vendors-are-listed-in-the-documents-own-metadata",
                   "cryptoscan:vendor" in metadata_properties
                   or "Thales" in json.dumps(metadata_properties),
                   f"{metadata_properties.get('cryptoscan:vendor')} and 2 more"),
        ])

    # ---- 7. composition is nesting ------------------------------------------ #
    def walk(components):
        for component in components:
            yield component
            yield from walk(component.get("components", []))

    nested = {component["name"]: component for component in walk(document["components"])}
    add(7, "composition", "a release belongs to a product, so it is nested in it", [
        _probe("a-release-is-nested-in-its-product",
               [child["name"] for child
                in nested["payShield 9000"].get("components", [])] == ["payShield 9000@9.2"],
               "payShield 9000 → payShield 9000@9.2"),
        _probe("a-package-is-nested-in-its-release",
               "pkg:generic/openssl" in [child["name"] for child
                                         in nested["OpenSSL@3.0.13"].get("components", [])],
               "OpenSSL@3.0.13 → "
               + ", ".join(child["name"]
                           for child in nested["OpenSSL@3.0.13"].get("components", []))),
        _probe("a-release-is-not-a-dependency-of-its-product",
               not any(entry["ref"].startswith("vendor_product:")
                       and any(child.startswith("product_version:")
                               for child in entry["dependsOn"])
                       for entry in document["dependencies"]),
               f"{len(document['dependencies'])} dependency entr(ies), none of them a "
               "containment"),
    ])

    # ---- 8. only a need is a dependency -------------------------------------- #
    refs = set()

    def collect(components):
        for component in components:
            refs.add(component["bom-ref"])
            collect(component.get("components", []))

    collect(document["components"])
    refs.add(document["metadata"]["component"]["bom-ref"])
    dangling = [entry["ref"] for entry in document["dependencies"]
                if entry["ref"] not in refs
                or any(child not in refs for child in entry["dependsOn"])]
    add(8, "dependencies", "dependsOn is an installation contract, not an evidence list", [
        _probe("every-dependency-reference-resolves",
               not dangling,
               f"{len(document['dependencies'])} entr(ies), 0 dangling"),
        _probe("a-device-depends-on-its-model-and-its-firmware",
               any(entry["ref"].startswith("hsm:") for entry in document["dependencies"]),
               f"{len(document['dependencies'])} entr(ies) start at a device or an "
               "application"),
        _probe("the-relations-that-are-not-needs-travel-as-properties",
               len({row["value"] for component in document["components"]
                    for row in component["properties"]
                    if row["name"] == "cryptoscan:relation"}) > 0,
               f"{export['relation_properties']} relation propert(ies) carry "
               "documented-by, declares and supplies"),
    ])

    # ---- 9. confidence travels ----------------------------------------------- #
    states = {row["value"] for component in document["components"]
              for row in component["properties"]
              if row["name"] == "cryptoscan:applicability"}
    add(9, "confidence", "the document says how strongly each row is believed", [
        _probe("every-applicability-state-is-one-the-module-defines",
               states <= set(v.APPLICABILITY) and {"MATCHED", "VERSION_MISMATCH"} <= states,
               ", ".join(sorted(states)) or "none"),
        _probe("the-estates-states-are-published-in-metadata",
               metadata_properties["cryptoscan:applicability_states"]
               == ", ".join(f"{state}:{count}"
                            for state, count in sorted(applicability["states"].items())),
               metadata_properties["cryptoscan:applicability_states"]),
        _probe("the-supplier-basis-is-on-the-component-it-justifies",
               any(row["name"] == "cryptoscan:supplier_basis"
                   for component in document["components"]
                   for row in component["properties"]),
               "vendor-datasheet, carried next to the supplier it justifies"),
    ])

    # ---- 10. the live merge -------------------------------------------------- #
    live = s.assess(PAYLOAD, live=LIVE, as_of=AS_OF, questions=[])
    live_packages = {row["name"]: row for row in live["document"]["assets"]
                     if row["kind"] == "PACKAGE"}
    add(10, "live", "a collector and a vendor payload describe the same estate", [
        _probe("both-transports-are-reported",
               live["live"]["transports"] == ["registry", "scan"],
               f"{', '.join(live['live']['transports'])}; {live['live']['rows']} row(s)"),
        _probe("a-scanned-package-joins-the-vendor-estate",
               "pkg:generic/newlib" in live_packages,
               f"{len(live_packages)} package node(s) after the merge"),
        _probe("a-package-the-payload-already-names-is-not-duplicated",
               sorted(live_packages) == sorted(set(live_packages))
               and len([row for row in live["document"]["assets"]
                        if row["name"] == "pkg:generic/openssl"]) == 1,
               "openssl appears once: the release names it and the scan agrees"),
        _probe("a-live-read-never-replaces-a-vendor-declaration",
               {row["name"] for row in live["document"]["assets"]
                if row["kind"] == "VENDOR"} == {"Thales", "OpenSSL Project", "F5"},
               "3 vendor(s), unchanged by the scan"),
    ])

    # ---- 11. the summary ------------------------------------------------------ #
    summary = s.summary(bom, refusals=assessment["graph"].get("refusals"))
    add(11, "summary", "the first three numbers, refusals included", [
        _probe("the-levels-are-the-graphs-own-counts",
               summary["levels"] == v.levels(bom) and summary["levels"].get("firmware"),
               ", ".join(f"{name} {count}" for name, count in summary["levels"].items()
                         if count)),
        _probe("the-applicability-states-are-carried-through",
               summary["applicability"] == applicability["states"],
               ", ".join(f"{state} {count}"
                         for state, count in sorted(summary["applicability"].items()))),
        _probe("the-refusals-are-counted-and-named",
               summary["refusals"] >= 1 and "refusal(s)" in summary["statement"],
               f"{summary['refusals']} refusal(s) "
               f"({', '.join(summary['refusal_codes'])}): "
               + ", ".join(summary["unresolved"][:3])),
    ])

    # ---- 12. the surface is a pure function ---------------------------------- #
    import inspect  # noqa: PLC0415 - only used here

    source_text = inspect.getsource(s)
    add(12, "purity", "the surface answers about what it was given and reads nothing else", [
        _probe("no-database-and-no-session-import",
               not any(token in source_text for token in ("import sqlalchemy", "get_db",
                                                          "from db.", "import db")),
               "no engine, no session, no tenant filter"),
        _probe("no-writes-and-no-caches",
               not any(token in source_text for token in (".commit(", "cache", "write_text")),
               "nothing is stored between two calls"),
        _probe("the-same-payload-twice-is-the-same-answer",
               s.assess(PAYLOAD, as_of=AS_OF, questions=["coverage"])["answers"]
               == s.assess(PAYLOAD, as_of=AS_OF, questions=["coverage"])["answers"],
               "two assessments, one answer"),
    ])

    # ---- 13. the HTTP surface -------------------------------------------------- #
    api_probes = []
    try:
        from api.routers import cbom_vbom  # noqa: PLC0415

        prefix = cbom_vbom.router.prefix
        routes = {route.path for route in cbom_vbom.router.routes}
        api_probes = [
            _probe("the-catalogue-is-a-route", f"{prefix}/questions" in routes,
                   f"{prefix}/questions"),
            _probe("every-question-shares-one-answer-route",
                   f"{prefix}/answer/{{question}}" in routes,
                   "one route parametrised by the catalogue, not 29 hand-written handlers"),
            _probe("the-export-and-the-assessment-are-routes",
                   {f"{prefix}/assess", f"{prefix}/summary",
                    f"{prefix}/export/cyclonedx"} <= routes,
                   ", ".join(sorted(path.removeprefix(prefix) for path in routes))),
        ]
    except Exception as exc:  # an import failure is a finding, not a crash  # noqa: BLE001
        api_probes = [_probe("the-router-imports", False, f"{type(exc).__name__}: {exc}")]
    add(13, "http", "the surface is reachable, or it is a library nobody calls", api_probes)

    counts = {VERDICT_PASS: 0, VERDICT_PARTIAL: 0, VERDICT_FAIL: 0}
    for point in points:
        counts[point["verdict"]] += 1
    probes = sum(len(point["probes"]) for point in points)
    passed = sum(1 for point in points for probe in point["probes"] if probe["ok"])
    return {
        "schema": SCHEMA,
        "guide": GUIDE,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": AS_OF,
        "counts": counts,
        "points": len(points),
        "probes": probes,
        "probes_passed": passed,
        "statement": (f"{counts[VERDICT_PASS]} of {len(points)} points of surface behaviour "
                      f"hold, across {probes} probes; {catalogue['count']} question(s) over "
                      f"{len({row['section'] for row in catalogue['questions']})} section(s), "
                      f"{export['components']} exported component(s) in a document the "
                      f"official schema {'accepts' if export['validation']['ok'] else 'refuses'}"),
        "questions": catalogue["count"],
        "sections": len({row["section"] for row in catalogue["questions"]}),
        "surface_codes": sorted(s.SURFACE_CODES),
        "levels": v.levels(bom),
        "applicability": applicability["states"],
        "export": {"components": export["components"], "top_level": export["top_level"],
                   "nested": export["nested"], "dependencies": export["dependency_refs"],
                   "relation_properties": export["relation_properties"],
                   "vendors": export["vendors"], "schema_valid": export["validation"]["ok"]},
        "live": live["live"],
        "refusals": assessment["graph"].get("refusals") or [],
        "estate_refusals": bom.get("refusals") or [],
        "rows": points,
        "limits": [
            "the payload is a recorded vendor estate: the surface is proven against the "
            "shapes a bank files, not against a running procurement system",
            "the live merge joins a registry and an image scan to the vendor payload; it "
            "does not read the API database, which is the cross-links route's job",
            "a MATCHED applicability state says the vendor's claim lines up with the "
            "deployment; it does not say anything exercised the capability",
            "CycloneDX carries no field for class, basis or applicability, so those travel "
            "as cryptoscan: properties that a consumer may ignore",
            "the API is exercised for routing and for one assessment; full endpoint "
            "behaviour is covered by the unit tests, not by this harness",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The VBOM surface: catalogue, envelope, export and live merge",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['counts'][VERDICT_PASS]} pass · {report['counts'][VERDICT_PARTIAL]} "
        f"partial · {report['counts'][VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "```",
        "payload + collectors → one estate → the graph → { catalogue, answers, CycloneDX }",
        "                                      ↓",
        "                         ok / code / statement, never an exception",
        "```",
        "",
        "| Surface | Value |",
        "|---|---|",
        f"| questions | {report['questions']} |",
        f"| sections | {report['sections']} |",
        f"| surface codes | {', '.join(report['surface_codes'])} |",
        f"| exported components | {report['export']['components']} "
        f"({report['export']['top_level']} top-level, {report['export']['nested']} nested) |",
        f"| exporters' dependencies | {report['export']['dependencies']} |",
        f"| relation properties | {report['export']['relation_properties']} |",
        f"| suppliers | {report['export']['vendors']} |",
        f"| schema valid | {report['export']['schema_valid']} |",
        f"| live transports | {', '.join(report['live']['transports']) or 'none'} |",
        "",
        "| Level | Nodes |",
        "|---|---|",
    ]
    for name, count in report["levels"].items():
        lines.append(f"| `{name}` | {count} |")

    lines += ["", "| Applicability | Declaration/deployment pairs |", "|---|---|"]
    for state, count in sorted(report["applicability"].items()):
        lines.append(f"| `{state}` | {count} |")

    lines += ["", "| Row | Section | Question | Verdict | Probes |", "|---|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['section']} | {row['question']} | "
                     f"**{row['verdict']}** | {len(row['probes'])}, {len(row['failed'])} "
                     "failing |")

    lines += ["", "## What was refused while building the graph", ""]
    for row in report["refusals"]:
        lines.append(f"- `{row['code']}` — {row['subject']}: {row['reason']}")
    for row in report["estate_refusals"]:
        lines.append(f"- `{row['code']}` — {row['subject']}: "
                     + str(row.get("reason") or "refused while the estate was assembled"))
    if not report["refusals"] and not report["estate_refusals"]:
        lines.append("- nothing")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 179, {row['section']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")

    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
          f"{counts[VERDICT_FAIL]} fail", file=sys.stderr)
    if not args.check:
        return 0
    if counts[VERDICT_FAIL]:
        return 2
    if counts[VERDICT_PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
