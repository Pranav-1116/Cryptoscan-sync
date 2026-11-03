#!/usr/bin/env python3
"""Guide 180 — the vendor dependency graph over the estate the platform actually holds.

Guide 178 proved the graph against a recorded payload. This guide proves the step that makes
it a product rather than a script: **stored rows → payload → graph → answers → an API route and
a CycloneDX document**, with the mapping rules that decide what may and may not become a node.

Four rules are probed, not described:

* **a mapper invents nothing** — a device with no model, a package with no coordinate and a
  capability with no document each appear in ``unmapped`` with a reason, instead of quietly
  shrinking the estate;
* **a static finding is not an observation** — the stored ``CryptoAsset`` rows are analysis of
  files, so the runtime section stays empty and ``declared_vs_observed`` answers
  ``NOT_OBSERVED`` rather than inheriting a runtime claim from a file path;
* **a capability needs a page** — a vendor declaration becomes a release capability only when
  the row carries its source document, because the graph refuses a claim it cannot cite;
* **applicability is only as good as the fields the estate keeps** — the inventory knows a
  device's firmware, not its product release, so the answer is ``UNKNOWN`` with
  ``version: NOT_COMPARABLE`` and the missing field named, which is a finding rather than a
  silent ``MATCHED``.

Usage::

    python scripts/cbom_vbom_estate.py            # markdown to stdout
    python scripts/cbom_vbom_estate.py --json out.json --md out.md
    python scripts/cbom_vbom_estate.py --check    # exit 1 on a partial, 2 on a failure
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

SCHEMA = "cryptoscan.vbom-estate-guide/1"
GUIDE = 180

VERDICT_PASS = "PASS"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_FAIL = "FAIL"

AS_OF = "2026-11-03"

INVENTORY: dict[str, Any] = {
    "vendors": [
        {"name": "Thales", "product": "payShield 9000", "model": "payShield 9000",
         "version": "9.2", "lifecycle": "SUPPORTED", "risk_level": "HIGH",
         "crypto_capability": "PQC_READY"},
        {"name": "F5", "product": "BIG-IP 9000", "version": "17.1", "lifecycle": "SUPPORTED",
         "risk_level": "MEDIUM"},
        {"name": "DigiCert", "product": "PKI Platform", "version": "5.0",
         "lifecycle": "ACTIVE", "risk_level": "LOW"},
        {"name": "Acme Legacy", "product": "Acme Datacrypt", "version": "4.2",
         "lifecycle": "EOL", "risk_level": "LOW"},
    ],
    "vendor_crypto": [
        {"id": "vc-1", "vendor": "Thales", "product": "payShield 9000", "version": "9.2",
         "algorithm": "AES", "key_size": 256, "mode": "GCM",
         "crypto_use_case": "card data at rest", "source_document": "payShield 9.2 policy",
         "confidence": "HIGH", "discovered_at": "2026-09-01"},
        {"id": "vc-2", "vendor": "Thales", "product": "payShield 9000", "version": "9.2",
         "algorithm": "ML-KEM", "key_size": 768, "source_document": "payShield 9.2 policy",
         "confidence": "MEDIUM", "discovered_at": "2026-09-01"},
        {"id": "vc-3", "vendor": "Acme Legacy", "product": "Acme Datacrypt", "version": "4.2",
         "algorithm": "RSA", "key_size": 2048, "source_document": "",
         "confidence": "LOW", "discovered_at": "2026-08-01"},
    ],
    "hardware": [
        {"id": "h-1", "asset_id": "HSM-001", "manufacturer": "Thales",
         "model": "payShield 9000", "device_type": "hsm", "firmware": "9.2.1",
         "serial_reference": "SN-001", "location": "dc-1", "hsm": True},
        {"id": "h-2", "asset_id": "HSM-002", "manufacturer": "Thales",
         "model": "payShield 9000", "device_type": "hsm", "firmware": "8.4.2",
         "location": "dc-1", "hsm": True},
        {"id": "h-3", "asset_id": "LB-001", "manufacturer": "F5", "model": "BIG-IP 9000",
         "device_type": "load_balancer", "firmware": "17.1", "serial_reference": "SN-002"},
        {"id": "h-4", "asset_id": "CA-01", "manufacturer": "DigiCert", "model": "PKI Platform",
         "device_type": "ca", "firmware": "5.0"},
        {"id": "h-5", "asset_id": "SRV-01", "manufacturer": "Dell", "model": "R760",
         "device_type": "server", "firmware": "2.1.0"},
        {"id": "h-6", "asset_id": "MYSTERY-01", "device_type": "hsm"},
    ],
    "software": [
        {"coordinate": "pkg:pypi/cryptography@42.0", "name": "cryptography",
         "version": "42.0", "vendor": "OpenSSL Project", "crypto_bearing": True},
        {"coordinate": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0",
         "vendor": ""},
        {"coordinate": "pkg:pypi/internal-banking@2.0", "name": "internal-banking",
         "version": "2.0", "vendor": "INTERNAL"},
        {"name": "no-coordinate", "version": "1.0"},
    ],
    "applications": [
        {"id": "s-1", "name": "Payments System", "owner": "ops", "criticality": "TIER_1",
         "environment": "PRODUCTION"},
        {"id": "s-2", "name": "Reporting System", "owner": "bi", "criticality": "TIER_2",
         "environment": "PRODUCTION"},
    ],
    "crypto": [
        {"algorithm": "RSA", "key_size": 2048, "purpose": "signing", "file_path": "a.py",
         "confidence": "HIGH"},
    ],
    "certificates": [{"fingerprint": "aa:bb", "subject": "payments.bank.example"}],
    "scan": {"target": "payments-api", "state": "COMPLETE"},
}


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "api", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import techbom, vbom_dependency, vbom_estate  # noqa: PLC0415

    return {"t": techbom, "v": vbom_dependency, "e": vbom_estate}


def _declared_vs_observed(module: Any, bom: dict[str, Any]) -> dict[str, Any]:
    """The declared-vs-observed answer for the HSM vendor's product, or an empty answer."""
    answer = module.answer(bom, "declared_vs_observed", product="payShield 9000")
    return answer["result"] if answer["ok"] else {"observed_count": None,
                                                 "declared_count": None}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def measure() -> dict[str, Any]:
    modules = _load()
    v, e = modules["v"], modules["e"]
    mapped = e.payload_from_inventory(INVENTORY, as_of=AS_OF)
    payload = mapped["payload"]
    assessed = e.assess(INVENTORY, as_of=AS_OF)
    bom = assessed["document"]
    points: list[dict[str, Any]] = []

    def add(number: int, section: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"VBE-{number:02d}", "number": number, "section": section,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    # ---- 1. the mapper ------------------------------------------------------ #
    add(1, "mapping", "stored rows become one payload, and the count says which", [
        _probe("the-payload-declares-the-graphs-input-schema",
               payload["schema"] == v.INPUT_SCHEMA,
               payload["schema"]),
        _probe("every-section-has-a-count-including-the-empty-ones",
               set(mapped["mapped"]) == set(e.SECTIONS)
               and sum(mapped["mapped"].values()) > 20,
               ", ".join(f"{name} {count}" for name, count in mapped["mapped"].items()
                         if count)),
        _probe("the-environment-is-stated-not-assumed",
               mapped["environment"] == "PRODUCTION",
               f"{mapped['environment']} (the default when no row says otherwise)"),
    ])

    # ---- 2. vendor → product → release -------------------------------------- #
    releases = {(row["product"], row["version"]) for row in payload["releases"]}
    thales_release = next(row for row in payload["releases"]
                          if row["product"] == "payShield 9000")
    add(2, "vendor→product→version", "a versioned vendor row names a release", [
        _probe("every-versioned-vendor-row-lands-on-a-release",
               {("payShield 9000", "9.2"), ("BIG-IP 9000", "17.1")} <= releases,
               f"{len(releases)} release(s): "
               + ", ".join(f"{product}@{version}" for product, version in sorted(releases))),
        _probe("the-lifecycle-and-pqc-field-travel-with-it",
               thales_release["support_status"] == "SUPPORTED"
               and thales_release["pqc_capability"] == "PQC_READY",
               f"{thales_release['support_status']} / {thales_release['pqc_capability']}"),
        _probe("a-vendor-with-no-product-still-becomes-a-vendor",
               "Dell" in {row["name"] for row in payload["vendors"]},
               "Dell is a vendor from a device row; no product row was invented for it"),
    ])

    # ---- 3. the devices ------------------------------------------------------ #
    assets = {row["name"]: row for row in payload["assets"]}
    add(3, "vendor→asset", "a device keeps the identity, the firmware and the place it is", [
        _probe("the-flags-and-type-choose-the-kind",
               assets["HSM-001"]["type"] == "HSM"
               and assets["LB-001"]["type"] == "LOAD_BALANCER"
               and assets["CA-01"]["type"] == "CERTIFICATE_AUTHORITY"
               and assets["SRV-01"]["type"] == "PHYSICAL_SERVER",
               ", ".join(f"{name}={row['type']}" for name, row in sorted(assets.items()))),
        _probe("firmware-serial-and-location-survive-the-mapping",
               assets["HSM-001"]["firmware"] == "9.2.1"
               and assets["HSM-001"]["serial"] == "SN-001"
               and assets["HSM-001"]["location"] == "dc-1",
               f"{assets['HSM-001']['firmware']}, {assets['HSM-001']['serial']}, "
               f"{assets['HSM-001']['location']}"),
        _probe("a-device-with-no-model-is-unmapped-by-name",
               "MYSTERY-01" not in assets
               and any(row["subject"] == "MYSTERY-01" for row in mapped["unmapped"]),
               next(row["reason"] for row in mapped["unmapped"]
                    if row["subject"] == "MYSTERY-01")[:80]),
    ])

    # ---- 4. declarations need documents -------------------------------------- #
    documents = payload["documents"]
    cited = [capability for release in payload["releases"]
             for capability in release.get("capabilities") or []]
    add(4, "declared-capability", "a capability is imported with the page that states it", [
        _probe("a-declaration-becomes-a-release-capability",
               len(cited) == 2 and {row["algorithm"] for row in cited} == {"AES", "ML-KEM"},
               ", ".join(row["algorithm"] for row in cited)),
        _probe("the-document-is-created-once-and-cited-by-id",
               len(documents) == 1
               and all(row["documents"] == [documents[0]["id"]] for row in cited),
               f"{documents[0]['id']} ← {documents[0]['title']}"),
        _probe("a-capability-with-no-document-is-unmapped-not-imported",
               not any(row["algorithm"] == "RSA" for row in cited)
               and any("VENDOR_CLAIM_WITHOUT_DOCUMENT" in row["reason"]
                       for row in mapped["unmapped"]),
               "Acme Datacrypt RSA-2048 refused: the row cites no document"),
    ])

    # ---- 5. no runtime claim from a static finding --------------------------- #
    usage = payload["usage"]
    static_findings = INVENTORY["crypto"]
    add(5, "declared≠observed", "a static finding is not an observation", [
        _probe("the-stored-crypto-findings-do-not-become-runtime-usage",
               usage == [] and len(static_findings) > 0,
               f"{len(static_findings)} stored finding(s), 0 usage row(s)"),
        _probe("the-reason-is-in-the-response",
               "static analysis" in mapped["not_mapped"]["usage"],
               mapped["not_mapped"]["usage"][:90]),
        _probe("declared-vs-observed-keeps-the-two-apart",
               _declared_vs_observed(e, bom)["observed_count"] == 0
               and _declared_vs_observed(e, bom)["declared_count"] == 2,
               "2 capabilities declared, 0 observed: the vendor's page is not a runtime "
               "observation"),
    ])

    # ---- 6. systems and the scanned target ---------------------------------- #
    add(6, "vendor→system", "the rows say what the bank runs and what it would lose", [
        _probe("a-system-row-becomes-a-business-system",
               {row["name"] for row in payload["systems"]} == {"Payments System",
                                                              "Reporting System"},
               ", ".join(row["name"] for row in payload["systems"])),
        _probe("the-scanned-target-is-the-only-application-claimed",
               [row["name"] for row in payload["applications"]] == ["payments-api"]
               and len(payload["applications"][0]["packages"]) == 3,
               "payments-api carries the three packages the scan reported"),
        _probe("a-package-with-no-coordinate-is-unmapped",
               any(row["subject"] == "no-coordinate" for row in mapped["unmapped"]),
               "no-coordinate: a row that cannot be joined to an SBOM or a trace"),
    ])

    # ---- 7. the graph -------------------------------------------------------- #
    levels = assessed["levels"]
    add(7, "the-graph", "the levels the estate supports, and nothing above them", [
        _probe("the-levels-are-populated-up-to-what-the-rows-support",
               levels["vendor"] >= 5 and levels["release"] >= 4 and levels["asset"] == 5
               and levels["system"] == 2,
               ", ".join(f"{name} {count}" for name, count in levels.items() if count)),
        _probe("the-runtime-level-stays-empty-because-nothing-was-observed",
               levels["runtime"] == 0,
               "0 runtime node(s): a static finding is not a process"),
        _probe("the-graph-refuses-nothing-the-mapper-had-already-rejected",
               not any(str(row.get("subject")).startswith(("MYSTERY", "no-coordinate"))
                       for row in bom.get("refusals") or []),
               f"{len(bom.get('refusals') or [])} graph refusal(s), none of them a row the "
               "mapper had already reported"),
    ])

    # ---- 8. the answers ------------------------------------------------------ #
    catalogue = e.catalogue()
    default = assessed["answers"]
    add(8, "answers", "every question has one shape, refusals included", [
        _probe("the-catalogue-and-the-module-agree",
               catalogue["count"] == len(e.ANSWERS)
               and all(getattr(reader, "__module__", "") == v.__name__
                       for reader, _params in e.ANSWERS.values() if reader),
               f"{catalogue['count']} question(s), "
               f"{len([row for row in catalogue['questions'] if row['needs_a_subject']])} "
               "of which need a subject"),
        _probe("the-default-assessment-answers-without-a-subject",
               bool(default) and all(row["ok"] for row in default),
               ", ".join(row["question"] for row in default)),
        _probe("an-unknown-question-is-refused-with-a-code",
               e.answer(bom, "which_vendor_is_worst")["code"] == "UNKNOWN_QUESTION",
               "UNKNOWN_QUESTION"),
        _probe("a-missing-subject-is-refused-before-the-reader-runs",
               e.answer(bom, "vendor_products")["code"] == "MISSING_PARAMETER",
               "MISSING_PARAMETER"),
        _probe("a-readers-refusal-keeps-the-readers-code",
               e.answer(bom, "vendor_products", vendor="Nobody")["code"] == "UNKNOWN_NODE",
               "UNKNOWN_NODE, passed through rather than renamed"),
    ])

    # ---- 9. coverage --------------------------------------------------------- #
    coverage = e.answer(bom, "coverage", payload=payload)["result"]
    add(9, "coverage", "how much of the software estate has a vendor", [
        _probe("three-answers-not-one",
               coverage["total"] == 3
               and (coverage["identified"], coverage["unknown"], coverage["internal"])
               == (1, 1, 1),
               f"{coverage['identified']} identified, {coverage['unknown']} unknown, "
               f"{coverage['internal']} internal of {coverage['total']}"),
        _probe("an-unknown-vendor-is-a-mapping-gap-and-an-internal-one-is-not",
               coverage["coverage_percent"] == 33.3
               and coverage["accounted_percent"] == 66.7,
               f"{coverage['coverage_percent']}% identified, "
               f"{coverage['accounted_percent']}% accounted for"),
    ])

    # ---- 10. applicability is as good as the fields -------------------------- #
    applicability = v.declaration_applicability(bom, as_of=AS_OF)
    pairs = applicability["declarations"]
    add(10, "applicability", "the answer names the field the estate does not keep", [
        _probe("a-declaration-reaches-a-deployment",
               bool(pairs),
               f"{len(pairs)} declaration/deployment pair(s): "
               + ", ".join(f"{state} {count}"
                           for state, count in sorted(applicability["states"].items()))),
        _probe("the-missing-field-is-named-not-assumed",
               any(row["checks"]["version"] == "NOT_COMPARABLE" for row in pairs),
               "version: NOT_COMPARABLE — the inventory knows a device's firmware, not its "
               "product release"),
        _probe("no-pair-claims-MATCHED-on-a-field-nobody-kept",
               not any(row["state"] == v.MATCHED and row["checks"]["version"] != "PASS"
                       for row in pairs),
               "MATCHED requires a version comparison that passed"),
    ])

    # ---- 11. the summary ------------------------------------------------------ #
    summary = e.summary(bom, as_of=AS_OF)
    add(11, "summary", "the first three numbers a reviewer wants", [
        _probe("the-levels-are-the-graphs-own",
               summary["levels"] == levels,
               f"{sum(levels.values())} node(s) over {len(summary['populated_levels'])} "
               "level(s)"),
        _probe("the-applicability-states-are-carried-through",
               summary["applicability"] == applicability["states"],
               ", ".join(f"{state} {count}"
                         for state, count in sorted(summary["applicability"].items()))
               or "none"),
        _probe("the-refusals-are-counted-even-when-there-are-none",
               "refusal(s)" in summary["statement"],
               summary["statement"][:100]),
    ])

    # ---- 12. the export -------------------------------------------------------- #
    export = e.to_cyclonedx(bom, as_of=AS_OF)
    document = export["document"]
    refs = {row["bom-ref"] for row in document["components"]}
    add(12, "export", "the graph leaves as a CycloneDX document", [
        _probe("only-the-vendor-side-is-exported",
               {row["properties"][0]["value"] for row in document["components"]} <=
               set(e.EXPORTED_KINDS)
               and not any(row["type"] == "cryptographic-asset"
                           for row in document["components"]
                           if any(prop["value"] == "CRYPTO_ASSET"
                                  for prop in row["properties"])),
               f"{export['components']} component(s), kinds within the export list"),
        _probe("every-dependency-reference-resolves",
               all(entry["ref"] in refs
                   and set(entry["dependsOn"]) <= refs
                   for entry in document["dependencies"]),
               f"{export['dependencies']} dependency entr(ies), 0 dangling"),
        _probe("the-timestamp-is-the-documents-not-the-clock",
               document["metadata"]["timestamp"] == f"{AS_OF}T00:00:00Z",
               document["metadata"]["timestamp"]),
        _probe("the-export-is-deterministic",
               e.to_cyclonedx(bom, as_of=AS_OF)["document"] == document,
               "two calls, one document"),
    ])

    # ---- 13. the API ----------------------------------------------------------- #
    api_probes: list[dict[str, Any]] = []
    try:
        from api.routers import vbom  # noqa: PLC0415

        paths = {route.path for route in vbom.router.routes}
        api_probes = [
            _probe("the-graph-is-a-route",
                   f"{vbom.router.prefix}/dependency" in paths,
                   f"GET {vbom.router.prefix}/dependency"),
            _probe("the-catalogue-is-a-route",
                   f"{vbom.router.prefix}/dependency/questions" in paths,
                   f"GET {vbom.router.prefix}/dependency/questions"),
            _probe("a-vendor-and-an-asset-are-addressable",
                   {f"{vbom.router.prefix}/dependency/vendors/{{vendor}}",
                    f"{vbom.router.prefix}/dependency/assets/{{asset}}"} <= paths,
                   ", ".join(sorted(path.removeprefix(vbom.router.prefix) for path in paths))),
            _probe("the-export-is-a-route",
                   f"{vbom.router.prefix}/dependency/export" in paths,
                   f"GET {vbom.router.prefix}/dependency/export"),
        ]
    except Exception as exc:  # noqa: BLE001 — an import failure is a finding
        api_probes = [_probe("the-router-imports", False, f"{type(exc).__name__}: {exc}")]
    add(13, "http", "the graph is reachable, or it is a library nobody calls", api_probes)

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
        "statement": (f"{counts[VERDICT_PASS]} of {len(points)} points of estate mapping hold, "
                      f"across {probes} probes; {sum(mapped['mapped'].values())} row(s) mapped "
                      f"over {len([count for count in mapped['mapped'].values() if count])} "
                      f"section(s), {len(mapped['unmapped'])} unmapped by name, "
                      f"{sum(levels.values())} node(s) in the graph"),
        "mapped": mapped["mapped"],
        "unmapped": mapped["unmapped"],
        "not_mapped": mapped["not_mapped"],
        "levels": levels,
        "applicability": applicability["states"],
        "coverage": {key: coverage[key] for key in ("total", "identified", "unknown",
                                                    "internal", "coverage_percent",
                                                    "accounted_percent")},
        "export": {"components": export["components"], "dependencies": export["dependencies"]},
        "questions": catalogue["count"],
        "refusals": bom.get("refusals") or [],
        "rows": points,
        "limits": [
            "the inventory is a fixture in this shape, not a live database: the mapper's "
            "contract is the dict the API assembles, and the API tests exercise it against "
            "SQLite",
            "runtime usage is not mapped: a static finding is not an observation, so the "
            "runtime level is empty on a purely stored estate",
            "applicability stops at UNKNOWN where the estate keeps firmware but not the "
            "product release — that is a finding about the estate, not about the graph",
            "the network and PKI projections are not read by this mapper; their sections are "
            "named in not_mapped rather than left empty",
            "the CycloneDX export is shape-correct but not schema-validated here: the CBOM "
            "exporter owns validation",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The vendor dependency graph over the live estate",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['counts'][VERDICT_PASS]} pass · {report['counts'][VERDICT_PARTIAL]} "
        f"partial · {report['counts'][VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "```",
        "stored rows → payload → graph → { answers, summary, CycloneDX, HTTP }",
        "                   ↓",
        "        unmapped rows, by name and by reason",
        "```",
        "",
        "| Section | Rows mapped |",
        "|---|---|",
    ]
    for name, count in report["mapped"].items():
        lines.append(f"| `{name}` | {count} |")

    lines += ["", "| Level | Nodes |", "|---|---|"]
    for name, count in report["levels"].items():
        lines.append(f"| `{name}` | {count} |")

    lines += ["", "| Applicability | Pair(s) |", "|---|---|"]
    for state, count in sorted(report["applicability"].items()):
        lines.append(f"| `{state}` | {count} |")

    lines += [
        "", "| Coverage | Value |", "|---|---|",
        f"| components | {report['coverage']['total']} |",
        f"| vendor identified | {report['coverage']['identified']} "
        f"({report['coverage']['coverage_percent']}%) |",
        f"| vendor unknown | {report['coverage']['unknown']} |",
        f"| internal | {report['coverage']['internal']} |",
        f"| accounted for | {report['coverage']['accounted_percent']}% |",
        "", "| Row | Section | Question | Verdict | Probes |", "|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['section']} | {row['question']} | "
                     f"**{row['verdict']}** | {len(row['probes'])}, {len(row['failed'])} "
                     "failing |")

    lines += ["", "## Rows the mapper refused to place", ""]
    for row in report["unmapped"]:
        lines.append(f"- `{row['section']}` — {row['subject']}: {row['reason']}")
    if not report["unmapped"]:
        lines.append("- nothing")
    for row in report["refusals"]:
        lines.append(f"- `{row['code']}` — {row['subject']}: {row['reason']}")

    lines += ["", "## Sections this mapper does not read", ""]
    for name, reason in report["not_mapped"].items():
        lines.append(f"- `{name}` — {reason}")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 180, {row['section']})", ""]
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
