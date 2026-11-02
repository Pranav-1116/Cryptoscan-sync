#!/usr/bin/env python3
"""Guide 142 — promotion: from "this library can do AES" to "this is an asset".

The review's item 6 is the one that decides whether a CBOM can be trusted: a
library named ``openssl`` must not mint ``AES-128 USED``, ``AES-256 USED``,
``RSA-2048 USED`` and ``ECDSA-P256 USED`` because OpenSSL *supports* them. The
chain it asks for instead is capability -> candidate -> evidence promotes.

``cbom.promotion`` implements that chain and makes the boundary explicit:

* a candidate becomes a **CBOM asset** only when an observing class (static,
  configuration, runtime, network) reports the algorithm;
* everything else stays a **candidate**, returned with the classes that would
  promote it and deliberately absent from the document;
* a component with no evidence id is **refused** — its capabilities cannot be
  attributed to a document;
* each promoted asset carries a level (CAPABILITY < STATIC/CONFIGURED <
  RUNTIME/NETWORK < VERIFIED) and the evidence ids that earned it, in
  ``cryptoscan:`` properties rather than in the standard's fields.
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
SCHEMA = "cryptoscan.cbom-usage-promotion-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

OPENSSL = {"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
           "algorithms": ["AES-128-GCM", "AES-256-GCM", "RSA-2048", "ECDSA-P256"]}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "governance"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import promotion  # noqa: PLC0415

    return {"promo": promotion}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _event(klass: str, algorithm: str = "AES-256-GCM", evidence_id: str = "E-1") -> dict:
    return {"class": klass, "evidence_id": evidence_id, "algorithm": algorithm,
            "layer": {"STATIC_OBSERVED": "static", "RUNTIME_OBSERVED": "runtime",
                      "NETWORK_OBSERVED": "network", "CONFIGURED": "config",
                      "IMPORTED": "sbom"}[klass]}


def row_ladder(modules: dict[str, Any]) -> dict[str, Any]:
    promo = modules["promo"]
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "a-capability-is-the-bottom-of-the-ladder",
        promo.promotion_level(["IMPORTED"]) == "CAPABILITY"
        and promo.promotion_level(["VENDOR_DECLARED"]) == "CAPABILITY",
        "IMPORTED and VENDOR_DECLARED both earn CAPABILITY and no more"))

    probes.append(_probe(
        "static-and-configured-sit-above-capability",
        promo.promotion_level(["STATIC_OBSERVED"]) == "STATIC"
        and promo.promotion_level(["CONFIGURED"]) == "CONFIGURED"
        and promo.LEVEL_RANK["STATIC"] > promo.LEVEL_RANK["CAPABILITY"],
        "the code or the configuration was seen to select it"))

    probes.append(_probe(
        "runtime-and-network-together-are-verified",
        promo.promotion_level(["RUNTIME_OBSERVED", "NETWORK_OBSERVED"]) == "VERIFIED"
        and promo.promotion_level(["RUNTIME_OBSERVED"]) == "RUNTIME",
        "two independent mechanisms, not one louder one"))

    probes.append(_probe(
        "the-strongest-class-decides-the-level",
        promo.promotion_level(["IMPORTED", "STATIC_OBSERVED", "RUNTIME_OBSERVED"]) == "RUNTIME",
        "the ladder is a max, not an average"))

    probes.append(_probe(
        "no-evidence-is-no-level",
        promo.promotion_level([]) == "NONE",
        "an asset with no evidence is not promoted at any level"))

    return {"id": "ladder",
            "question": "does a promotion level mean what it says?",
            "phase": "review 13 / 17", "probes": probes}


def row_capability_is_not_an_asset(modules: dict[str, Any]) -> dict[str, Any]:
    promo = modules["promo"]
    probes: list[dict[str, Any]] = []

    empty = promo.promote([OPENSSL], [])
    probes.append(_probe(
        "a-library-with-no-observations-promotes-nothing",
        empty["assets"] == [] and len(empty["candidates"]) == 4
        and "a capability is not an invocation" in empty["statement"],
        empty["statement"]))

    one = promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "AES-256-GCM", "RUNTIME-1")])
    probes.append(_probe(
        "only-the-observed-algorithm-is-promoted",
        [asset["algorithm"] for asset in one["assets"]] == ["AES-256-GCM"]
        and {row["algorithm"] for row in one["candidates"]} == {
            "AES-128-GCM", "RSA-2048", "ECDSA-P256"},
        one["statement"]))

    probes.append(_probe(
        "an-imported-event-cannot-promote",
        promo.promote([OPENSSL], [_event("IMPORTED", "AES-256-GCM", "SBOM-1")])["assets"] == [],
        "the document that declared the capability is not evidence of use"))

    probes.append(_probe(
        "a-component-with-no-evidence-id-is-refused",
        promo.promote([{**OPENSSL, "evidence_id": None}], [])["refused"] != [],
        promo.promote([{**OPENSSL, "evidence_id": None}], [])["refused"][0]["reason"]))

    probes.append(_probe(
        "evidence-for-another-algorithm-promotes-nothing-else",
        [asset["algorithm"] for asset in
         promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "RSA-2048", "R-1")])["assets"]]
        == ["RSA-2048"],
        "the matching is by algorithm, not by component"))

    probes.append(_probe(
        "a-refused-event-does-not-promote",
        promo.promote([OPENSSL], [{"class": "RUNTIME_OBSERVED",
                                   "algorithm": "AES-256-GCM"}])["assets"] == [],
        "a runtime claim with no evidence id promotes nothing"))

    return {"id": "capability_is_not_an_asset",
            "question": "does an SBOM still mint assets it cannot prove?",
            "phase": "review 6 / 13 / 21", "probes": probes}


def row_the_document(modules: dict[str, Any]) -> dict[str, Any]:
    promo = modules["promo"]
    body = promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "AES-256-GCM", "RUNTIME-1"),
                                     _event("STATIC_OBSERVED", "ECDSA-P256", "S-1")],
                         primitives={"AES-256-GCM": "aead"})
    document = promo.to_cbom(body, name="payments-api")
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "only-promoted-assets-are-components",
        {component["name"] for component in document["components"]}
        == {"AES-256-GCM", "ECDSA-P256"} and len(body["candidates"]) == 2,
        f"{len(document['components'])} component(s), {len(body['candidates'])} candidate(s)"))

    properties = {row["name"]: row["value"] for row in document["metadata"]["properties"]}
    probes.append(_probe(
        "candidates-are-counted-in-metadata-not-written-as-components",
        properties["cryptoscan:candidates_excluded"] == "2"
        and properties["cryptoscan:promoted_assets"] == "2",
        json.dumps(properties, sort_keys=True)))

    component = next(row for row in document["components"] if row["name"] == "AES-256-GCM")
    probes.append(_probe(
        "a-promoted-asset-is-a-cyclonedx-cryptographic-asset",
        component["type"] == "cryptographic-asset"
        and component["cryptoProperties"]["assetType"] == "algorithm"
        and component["cryptoProperties"]["primitive"] == "aead",
        component["bom-ref"]))

    probes.append(_probe(
        "platform-claims-live-in-properties-not-standard-fields",
        set(component["cryptoProperties"]) <= {"assetType", "oid", "primitive",
                                               "algorithmProperties"}
        and all(row["name"].startswith("cryptoscan:") for row in component["properties"]),
        ", ".join(sorted({row["name"] for row in component["properties"]}))))

    evidence_ids = [row["value"] for row in component["properties"]
                    if row["name"] == "cryptoscan:evidence_id"]
    probes.append(_probe(
        "the-evidence-that-earned-the-asset-travels-with-it",
        evidence_ids == ["RUNTIME-1"], json.dumps(evidence_ids)))

    inventory = promo.asset_inventory(body)
    probes.append(_probe(
        "the-inventory-says-what-the-document-may-be-read-as",
        inventory["algorithms"] == {"AES-256-GCM": ["RUNTIME"], "ECDSA-P256": ["STATIC"]}
        and "not in it" in inventory["statement"],
        inventory["statement"]))

    return {"id": "the_document",
            "question": "is the produced CBOM a claim or a capability list?",
            "phase": "review 6 / 20", "probes": probes}


def row_api_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probes: list[dict[str, Any]] = [
        _probe("the-promote-route-exists-and-is-typed",
               '@router.post("/promote"' in router
               and "response_model=CbomPromoteResponse" in router,
               "POST /cbom/promote"),
        _probe("the-route-returns-document-inventory-and-refusals",
               "promo.asset_inventory(promoted)" in router
               and '"document": promo.to_cbom(' in router,
               "promotion + inventory + document in one answer"),
        _probe("the-route-uses-the-promotion-module",
               "from cbom import promotion as promo" in router,
               "one implementation, not a copy in the router"),
    ]
    return {"id": "api_exposure",
            "question": "can an operator produce a defensible CBOM?",
            "phase": "review 6", "probes": probes}


ROWS = (row_ladder, row_capability_is_not_an_asset, row_the_document, row_api_exposure)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "rows": rows,
        "limits": [
            "promotion is only as good as the collector that reported the observation. The "
            "document says VERIFIED when runtime and network agreed; it cannot say whether both "
            "collectors were looking at the same deployment",
            "the algorithm list a component declares is the caller's. This module refuses an "
            "unattributable component, but it cannot verify that openssl really supports every "
            "algorithm the SBOM claims",
            "a candidate that is never promoted stays a candidate forever. That is honest and "
            "also a blind spot: an algorithm used in a path no collector watches is invisible "
            "in the document rather than present-but-unproven",
            "the produced document is CycloneDX 1.5 and is not validated against the 1.6 schema "
            "here; the platform's own properties are namespaced, but a strict consumer may still "
            "reject them",
            "level is per algorithm, not per call site: two applications sharing one algorithm "
            "produce two assets with the same name unless the caller separates them by component",
            "promotion does not decide migration or risk. A VERIFIED weak algorithm is still "
            "weak; that judgement belongs to the assessment and PQC engines, not to this ladder",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# From \"this library can do AES\" to \"this is an asset\"",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's item 6: a library that supports AES must not mint `AES-256 USED`. "
        "`cbom.promotion` implements the chain the review asks for — capability → candidate → "
        "evidence promotes — and makes the boundary visible in the document:",
        "",
        "1. **A candidate is not an asset.** Only an observing class promotes one; everything "
        "else is returned as a candidate and deliberately kept out of the CBOM.",
        "2. **Each asset says how strong its evidence is.** `CAPABILITY` < `STATIC`/`CONFIGURED` "
        "< `RUNTIME`/`NETWORK` < `VERIFIED` (both independent mechanisms agreed).",
        "3. **The document stays CycloneDX.** Standard fields carry the algorithm; every "
        "platform claim is a `cryptoscan:` property, with the evidence ids attached.",
        "4. **An unattributable component is refused**, not promoted quietly.",
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
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    if not args.check:
        return 0
    if counts[FAIL]:
        return 2
    if counts[PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
