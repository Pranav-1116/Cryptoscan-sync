#!/usr/bin/env python3
"""Guide 166 — the stored inventory becomes a TechBOM, and never an observation.

Guides 164 and 165 built the graph and its answers on a fixture. This guide closes the gap
that mattered: ``cbom.techbom_estate`` reads the inventory the platform actually gathers —
systems, registrations, crypto assets, hardware, vendors, certificates, dependency rows and
the scan's software rows — and produces the estate ``build()`` accepts.

The measurement is mostly about what the adapter **refuses**, because that is where a live
adapter usually goes wrong:

* a **stored row is not an observation** — nothing read back through the database can be
  `OBSERVED`, and the class comes from the row's own provenance;
* a **dependency row with no provenance** (`SystemDependency.source` empty or unknown) is
  refused by name, because an edge nobody vouched for is exactly the relationship
  poisoning the review warns about;
* a **certificate row stops at the certificate** — no key and no algorithm, because the
  stored shape does not carry them and inventing them is the shortcut that makes a
  certificate look like an application's cryptography;
* an **unclassifiable `source_basis`** refuses the asset rather than guessing a class.

It also measures what the live estate can then answer, which is the point of the whole
build: a roll-up, and a blocker list, over rows that really exist.

`GET /technology-bom/graph` is the same adapter over the database: it gathers the inventory,
returns the built graph with its refusals and coverage, and computes a roll-up (`?system=`)
or an impact answer (`?query=`) on live rows — typed, so the route cannot quietly change
shape under a consumer.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-techbom-live-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EXPECTED = {"BUSINESS_SYSTEM": 3, "HSM": 2, "CERTIFICATE": 2, "PACKAGE": 40}
GAPS = [
    {"kind": "HSM", "reason": "1 HSM collector unavailable (vendor API offline)"},
    {"kind": "PACKAGE", "reason": "the batch application's manifest was not collected"},
]


def _inventory() -> dict[str, Any]:
    """An inventory shaped exactly like `_gather_inventory` produces."""
    return {
        "applications": [
            {"id": "SYS-1", "name": "Payments", "version": "2026.11.02",
             "owner": "Payments Platform", "environment": "prod",
             "criticality": "CRITICAL", "supplier": "Payments Platform"},
            {"id": "SYS-2", "name": "Cards", "version": "2026.10.14",
             "owner": "Cards Platform", "environment": "prod", "criticality": "HIGH"},
            {"id": "SYS-3", "name": "Payments Batch", "version": "2026.09.01",
             "owner": "Payments Platform", "environment": "prod", "criticality": "HIGH"},
        ],
        "system_assets": [
            {"id": "SA-1", "system_id": "SYS-1", "asset_id": "CA-1"},
            {"id": "SA-2", "system_id": "SYS-1", "asset_id": "CA-2"},
            {"id": "SA-3", "system_id": "SYS-2", "asset_id": "CA-3"},
            {"id": "SA-4", "system_id": "SYS-99", "asset_id": "CA-1"},
        ],
        "crypto": [
            {"id": "CA-1", "algorithm": "AES", "key_size": 256, "purpose": "encryption",
             "mode": "GCM", "asset": "db-01", "file_path": "/etc/payments/tls.conf",
             "confidence": "MEDIUM", "library": "OpenSSL 3.0.13",
             "evidence_links": ["EV-CBOM-1"]},
            {"id": "CA-2", "algorithm": "RSA", "key_size": 2048, "purpose": "signature",
             "asset": "db-01", "confidence": "MEDIUM", "library": "OpenSSL 3.0.13",
             "evidence_links": ["EV-CBOM-2"]},
            {"id": "CA-3", "algorithm": "3DES", "key_size": 168, "asset": "cards-01",
             "confidence": "LOW", "source_basis": "legacy_import",
             "evidence_links": ["EV-CBOM-3"]},
            {"id": "CA-4", "algorithm": "ECDSA", "key_size": 256, "asset": "hsm-01",
             "source_basis": "unstated-instrument", "confidence": "LOW"},
        ],
        "hardware": [
            {"asset_id": "HSM-01", "manufacturer": "Vendor X", "model": "HSM-9000",
             "device_type": "hsm", "serial_reference": "SN-4471", "firmware": "8.4",
             "hsm": {"model": "HSM-9000", "vendor": "Vendor X"},
             "crypto_capabilities": ["RSA-2048", "AES-256"],
             "evidence_history": ["EV-HBOM-1"],
             "source": "estate observation (HARDWARE/HSM assets)", "asset": "SYS-1"},
            {"id": "SRV-12", "manufacturer": "Dell", "model": "R760",
             "device_type": "server", "tpm": True, "firmware": "2.1"},
            {"model": "unknown-appliance", "device_type": "appliance"},
        ],
        "vendors": [
            {"name": "Vendor X", "product": "HSM-9000", "model": "HSM-9000",
             "lifecycle": "supported", "risk_level": "LOW",
             "source": "estate observation (VENDOR assets)"},
        ],
        "certificates": [
            {"fingerprint": "ab" * 32, "subject": "CN=payments.bank.example"},
            {"fingerprint": "cd" * 32, "subject": "CN=cards.bank.example"},
        ],
        "system_dependencies": [
            {"id": "SD-1", "parent_id": "SYS-1", "child_id": "SYS-2",
             "source": "discovered", "evidence_ref": "EV-DEP-1",
             "confidence": 0.9, "confidence_meaning": "observed traffic between them"},
            {"id": "SD-2", "parent_id": "SYS-3", "child_id": "SYS-1",
             "source": "manual", "evidence_ref": "EV-DEP-2"},
            {"id": "SD-3", "parent_id": "SYS-2", "child_id": "SYS-1", "source": ""},
            {"id": "SD-4", "parent_id": "SYS-3", "child_id": "SYS-404",
             "source": "imported"},
        ],
        "software": [
            {"component_type": "library", "name": "OpenSSL",
             "coordinate": "library/OpenSSL", "origin": "CODE_AND_MANIFEST",
             "version": "3.0.13", "algorithms": ["AES-256-GCM", "RSA-2048"]},
            {"component_type": "package", "name": "left-pad",
             "coordinate": "pkg:npm/left-pad@1.0", "origin": "MANIFEST_DECLARED",
             "version": "1.0", "declared_in": "package.json"},
            {"component_type": "package", "name": "mystery", "coordinate": "pkg/npm/mystery",
             "origin": "", "version": "0.1"},
        ],
        "dependencies": [
            ["pkg:npm/left-pad@1.0", "library/OpenSSL", "depends_on"],
            ["pkg/npm/mystery", "library/OpenSSL", "depends_on"],
            ["pkg:npm/gone@2.0", "library/OpenSSL", "depends_on"],
        ],
        "scan": {"software": {"schema": "cryptoscan.software-inventory/1",
                              "state": "OBSERVED", "scan_id": "SCAN-9281",
                              "counts": {"components": 3}}},
    }


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import techbom, techbom_estate, techbom_queries  # noqa: PLC0415

    return {"t": techbom, "te": techbom_estate, "q": techbom_queries}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _body(modules: dict[str, Any], inventory: dict[str, Any] | None = None):
    te = modules["te"]
    return te.from_inventory(inventory if inventory is not None else _inventory(),
                             environment="PRODUCTION", expected=EXPECTED, gaps=GAPS)


def row_shape(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    body = _body(modules)
    bom = t.build(body["estate"])
    probes = [
        _probe("the-inventory-becomes-an-estate-the-builder-accepts",
               body["estate"]["schema"] == t.ESTATE_SCHEMA
               and bom["schema"] == t.SCHEMA and bom["refusals"] == [],
               body["statement"]),
        _probe("systems-registrations-and-assets-all-arrive",
               {"BUSINESS_SYSTEM", "CRYPTO_ASSET", "CRYPTO_LIBRARY", "HOST", "HSM",
                "FIRMWARE", "VENDOR", "VENDOR_PRODUCT", "CERTIFICATE", "PACKAGE",
                "TPM"} <= {row["kind"] for row in bom["assets"]},
               f"{len(bom['assets'])} asset(s) across {len(bom['counts'])} kind(s)"),
        _probe("every-asset-and-claim-carries-an-evidence-reference",
               all(row["evidence_ids"] for row in bom["assets"])
               and all(row["evidence_ids"] for row in bom["claims"]),
               "the row id, the scan id or the evidence link it came from"),
        _probe("a-registration-links-the-system-to-what-it-holds",
               sum(1 for row in bom["claims"] if row["relation"] == "OWNS") == 4,
               "three registered assets and the HSM row's owner"),
        _probe("the-scan-that-produced-the-software-rows-is-named",
               bom["derived_from"] == "estate:production"
               and body["estate"]["source"]["scan_id"] == "SCAN-9281",
               "scan SCAN-9281 is the evidence behind the package rows"),
    ]
    return {"id": "shape",
            "question": "does the real inventory become a graph the model accepts?",
            "phase": "review tc / 3 and 6", "probes": probes}


def row_classes(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    body = _body(modules)
    bom = t.build(body["estate"])
    classes = {row["confidence"] for row in bom["claims"]}
    probes = [
        _probe("nothing-read-back-from-the-database-is-observed",
               "OBSERVED" not in classes
               and classes <= {"CONFIGURED", "IMPORTED", "VENDOR_DECLARED", "INFERRED"},
               ", ".join(sorted(classes))),
        _probe("a-discovered-dependency-is-configured",
               any(row["basis"] == "agent-inventory"
                   and row["confidence"] == "CONFIGURED" for row in bom["claims"]),
               "SystemDependency.source = discovered"),
        _probe("a-manual-registration-is-imported-not-trusted",
               any(row["basis"] == "operator-registration"
                   and row["confidence"] == "IMPORTED" for row in bom["claims"]),
               "a person registering an edge is a claim, and it stays IMPORTED"),
        _probe("a-vendor-row-is-vendor-declared",
               any(row["confidence"] == "VENDOR_DECLARED" for row in bom["claims"]),
               "a manufacturer field is a declaration, not a delivery record"),
        _probe("the-adapter-states-the-class-ceiling-in-words",
               "not an observation" in body["statement"],
               body["statement"].split(";")[-1].strip()),
    ]
    return {"id": "classes",
            "question": "does a stored row keep the class its provenance supports?",
            "phase": "review tc / 5, 22", "probes": probes}


def row_refusals(modules: dict[str, Any]) -> dict[str, Any]:
    body = _body(modules)
    skipped = {(row["kind"], row["subject"]): row["reason"] for row in body["skipped"]}
    probes = [
        _probe("a-dependency-row-with-no-provenance-is-refused-by-name",
               any(row["subject"] == "SYS-2 → SYS-1"
                   and "manual, discovered or imported" in row["reason"]
                   for row in body["skipped"]),
               "an edge nobody vouched for is not drawn"),
        _probe("a-dependency-naming-an-unknown-system-is-refused",
               any(row["subject"] == "SYS-3 → SYS-404" and "undeclared" in row["reason"]
                   for row in body["skipped"]),
               "SYS-404 does not exist, so the edge would be invented"),
        _probe("a-registration-naming-an-unknown-system-is-refused",
               any(row["kind"] == "REGISTRATION" for row in body["skipped"]),
               "SA-4 points at SYS-99, which the inventory does not hold"),
        _probe("an-unclassifiable-source-basis-refuses-the-asset",
               any(row["subject"] == "ECDSA-256"
                   and "cannot be placed with a confidence" in row["reason"]
                   for row in body["skipped"]),
               "a source_basis this model does not know is not a class"),
        _probe("a-software-row-with-an-unstated-origin-is-refused",
               any(row["subject"] == "pkg/npm/mystery" for row in body["skipped"])
               and any("not an asset in this estate" in reason
                       for (kind, _), reason in skipped.items() if kind == "DEPENDENCY"),
               f"{len(body['skipped'])} row(s) skipped, each with the reason"),
        _probe("a-hardware-row-with-no-identity-is-refused-rather-than-named",
               any("invented identity" in row["reason"] for row in body["skipped"]),
               next((row["reason"] for row in body["skipped"]
                     if "invented identity" in row["reason"]),
                    "no identity-less hardware row")),
        _probe("nothing-was-dropped-silently",
               all(row.get("reason") for row in body["skipped"])
               and len(body["skipped"]) >= 6,
               f"{len(body['skipped'])} refusal(s), all reported"),
    ]
    return {"id": "refusals",
            "question": "are the rows that cannot be placed refused, with the reason?",
            "phase": "review tc / 22", "probes": probes}


def row_certificate(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    body = _body(modules)
    bom = t.build(body["estate"])
    kinds = {row["kind"] for row in bom["assets"]}
    probes = [
        _probe("a-certificate-row-becomes-a-certificate-and-stops",
               "CERTIFICATE" in kinds and "PUBLIC_KEY" not in kinds
               and "ALGORITHM" not in kinds,
               "the stored shape carries a fingerprint and a subject, not a key"),
        _probe("the-certificate-keeps-its-fingerprint-as-evidence",
               any(row["attributes"].get("fingerprint_sha256") for row in bom["assets"]
                   if row["kind"] == "CERTIFICATE"),
               "cert:abab… is the evidence id"),
        _probe("the-adapter-says-why-the-key-layer-is-missing",
               any("key layer is not derived" in line
                   for line in body["not_proven"]),
               "a certificate is not the application's cryptography"),
    ]
    return {"id": "certificate",
            "question": "does a certificate stay a certificate?",
            "phase": "review tc / 9, 13", "probes": probes}


def row_answers(modules: dict[str, Any]) -> dict[str, Any]:
    q, t = modules["q"], modules["t"]
    bom = t.build(_body(modules)["estate"])
    rollup = q.rollup(bom, system="Payments")["systems"][0]
    impact = q.impact(bom, query="RSA-2048", required_algorithms=["ML-KEM-768"])
    probes = [
        _probe("a-roll-up-works-on-live-rows-and-splits_the_classes",
               rollup["counts"]["CRYPTO_ASSET"] >= 2
               and rollup["by_confidence"]["DECLARED"] == rollup["declared_only_assets"]
               and "declared only" in rollup["statement"],
               rollup["statement"][:120]),
        _probe("an-hsm-that-does-not-list-a-required-algorithm-is-a-blocker",
               "HSM_PQC_UNSUPPORTED" in {row["code"] for row in impact["pqc_blockers"]},
               ", ".join(sorted(impact["blocker_counts"])) or "none"),
        _probe("a-blocker-names-the-device-and-who-acts",
               all(row["asset"] and row["who_acts"] for row in impact["pqc_blockers"]),
               f"{len(impact['pqc_blockers'])} blocker(s), each with an owner of the work"),
        _probe("completeness-uses-the-denominator-the-caller-supplied",
               bom["completeness"]["overall"] == "PARTIAL"
               and {gap["kind"] for gap in bom["completeness"]["gaps"]}
               == {"HSM", "PACKAGE"},
               bom["completeness"]["statement"]),
        _probe("impact-still-refuses-to-call-exposure-breakage",
               any("reachability is exposure" in line for line in impact["not_proven"]),
               "the owner's assessment sits above the graph"),
    ]
    return {"id": "answers",
            "question": "do the guide-165 answers work on a live inventory?",
            "phase": "review tc / 8, 19, 20", "probes": probes}


def row_empty(modules: dict[str, Any]) -> dict[str, Any]:
    t, te, q = modules["t"], modules["te"], modules["q"]
    empty = te.from_inventory({}, environment="PRODUCTION")
    bom = t.build(empty["estate"])
    probes = [
        _probe("an-empty-inventory-is-an-empty-estate-not-an-error",
               empty["assets"] == 0 and empty["claims"] == 0 and bom["assets"] == [],
               empty["statement"]),
        _probe("an-empty-estate-is-unmeasured-rather-than-complete",
               bom["completeness"]["overall"] == "UNMEASURED",
               bom["completeness"]["statement"]),
        _probe("a-roll-up-over-nothing-says-there-is-no-system",
               "no business system" in q.rollup(bom)["statement"],
               q.rollup(bom)["statement"]),
        _probe("a-none-inventory-is-treated-as-empty-rather-than-a-crash",
               te.from_inventory(None)["assets"] == 0,
               "a missing inventory reads as nothing collected"),
    ]
    return {"id": "empty",
            "question": "does an uncollected estate stay empty and say so?",
            "phase": "review tc / 16", "probes": probes}


ROWS = (row_shape, row_classes, row_refusals, row_certificate, row_answers, row_empty)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = VERDICT_PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = VERDICT_PARTIAL
        else:
            verdict = VERDICT_FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    t, q = modules["t"], modules["q"]
    body = _body(modules)
    bom = t.build(body["estate"])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "estate": body["estate"],
        "skipped": body["skipped"],
        "statement": body["statement"],
        "bom": bom,
        "summary": t.summary(bom),
        "rollup": q.rollup(bom),
        "impact": q.impact(bom, query="RSA-2048", required_algorithms=["ML-KEM-768"]),
        "rows": rows,
        "limits": [
            "the inventory is a fixture shaped like `_gather_inventory`, not a bank's "
            "database: the shapes are real, the rows are not",
            "a stored row records what a collector saw when it ran; the estate may have "
            "changed since, and nothing here re-probes",
            "the class ceiling is a property of the store, not of the collector: a future "
            "collector that hands over its own evidence can say OBSERVED itself",
            "a certificate row carries a fingerprint and a subject, so the key and "
            "algorithm layers stay empty until something reads them",
            "completeness is only as honest as the denominator, which this adapter "
            "receives rather than derives",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    bom = report["bom"]
    summary = report["summary"]
    rollup = report["rollup"]["systems"][0] if report["rollup"]["systems"] else None
    impact = report["impact"]
    lines = [
        "# The stored inventory becomes a TechBOM",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Guides 164 and 165 built the graph and its answers. This is the adapter from the",
        "inventory the platform already gathers, and the interesting part is what it",
        "refuses.",
        "",
        "```",
        "inventory row                  basis                    class",
        "System / registration          operator-registration    IMPORTED",
        "SystemDependency manual        operator-registration    IMPORTED",
        "SystemDependency imported      cmdb-import              IMPORTED",
        "SystemDependency discovered    agent-inventory          CONFIGURED",
        "software row, code import      code-analysis            CONFIGURED",
        "software row, manifest only    sbom-import              IMPORTED",
        "hardware / HSM observation     cmdb-import              IMPORTED",
        "vendor row                     vendor-datasheet         VENDOR_DECLARED",
        "```",
        "",
        "Nothing read back through the database is `OBSERVED`: that class belongs to a",
        "capture, a probe or a trace, and the store cannot claim it on a collector's behalf.",
        "",
        f"{report['statement']}",
        "",
        "| kind | assets |",
        "|---|---|",
        *[f"| `{kind}` | {count} |" for kind, count in sorted(bom["counts"].items())],
        "",
        "| confidence | relationships |",
        "|---|---|",
        *[f"| `{name}` | {count} |" for name, count in summary["by_confidence"].items()],
        "",
        "## Rows that could not be placed",
        "",
        "| kind | subject | reason |",
        "|---|---|---|",
        *[f"| `{row['kind']}` | {row['subject']} | {row['reason']} |"
          for row in report["skipped"]],
    ]
    if rollup:
        lines += ["", f"**Roll-up** — {rollup['statement']}"]
    lines += [
        "",
        f"**Impact (RSA-2048, required ML-KEM-768)** — {impact['statement']}",
        "",
        "| blocker | asset | who acts |",
        "|---|---|---|",
        *[f"| `{row['code']}` | {row['asset']} | {row['who_acts']} |"
          for row in impact["pqc_blockers"]],
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* ({row['phase']})", ""]
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
