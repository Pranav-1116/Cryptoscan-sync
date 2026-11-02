#!/usr/bin/env python3
"""Guide 139 — what a CBOM asset may claim, and what the evidence proves.

The review that prompted this says the CBOM's biggest weakness is *usage proof*:
the platform can go from source to a crypto finding to a CBOM, but a
``AES-256-GCM / confidence: HIGH`` line collapses eight different claims into one.
This artifact measures the module that separates them:

1. **Evidence classes** — the review's nine values, with a declared class unable
   to call itself an observation and an observation unable to exist without an
   evidence id.
2. **Usage profile** — capability, per-layer observation (static, config, runtime,
   network), the evidence ids, and a confidence computed by a stated ladder:
   imported is ``LOW``, static ``MEDIUM``, runtime or network ``HIGH``, runtime
   *and* network ``VERY_HIGH``.
3. **No false attribution** — a crypto-capable library yields candidate
   algorithms, never ``USED`` assets.
4. **Conflicts** — every source's claim kept side by side; two observing sources
   that disagree produce a conflict and no single asserted value.
5. **TLS, certificates, keys, HSM** — one relationship per hop, certificates as
   their own category that proves no application operation, key metadata with no
   material, and HSM capability ≠ configured key ≠ recorded operation.
6. **Coverage and API** — a partial estate cannot be quoted as a total, and the
   four routes are typed.
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
SCHEMA = "cryptoscan.cbom-usage-proof-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

AES = {"algorithm": "AES-256-GCM", "parameters": {"key_size": 256, "mode": "GCM"},
       "purpose": "TLS"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "container_scanner"), str(SERVICES / "governance"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import usage_evidence  # noqa: PLC0415

    return {"ue": usage_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _event(klass: str, evidence_id: str = "EVID-1", algorithm: str = "AES-256-GCM",
           **extra: Any) -> dict[str, Any]:
    return {"class": klass, "evidence_id": evidence_id, "algorithm": algorithm, **extra}


# --------------------------------------------------------------------------- #
# 1. the vocabulary and its refusals
# --------------------------------------------------------------------------- #


def row_evidence_classes(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "the-nine-classes-are-the-vocabulary",
        ue.EVIDENCE_CLASSES == ("OBSERVED", "STATIC_OBSERVED", "RUNTIME_OBSERVED",
                               "NETWORK_OBSERVED", "CONFIGURED", "IMPORTED",
                               "VENDOR_DECLARED", "INFERRED", "UNKNOWN"),
        ", ".join(ue.EVIDENCE_CLASSES)))

    try:
        ue.normalize_event({"class": "PROBABLY", "evidence_id": "E-1"})
        refused_class = False
    except ue.EvidenceRefused:
        refused_class = True
    probes.append(_probe("an-invented-class-is-refused-not-mapped",
                         refused_class,
                         "only the closed vocabulary is accepted"))

    try:
        ue.normalize_event({"class": "RUNTIME_OBSERVED"})
        refused_evidence = False
    except ue.EvidenceRefused:
        refused_evidence = True
    probes.append(_probe("an-observation-without-an-evidence-id-is-refused",
                         refused_evidence,
                         "an observation nobody can point at is not evidence"))

    downgraded = ue.normalize_event({"class": "IMPORTED", "layer": "runtime",
                                     "evidence_id": "E-1"})
    probes.append(_probe(
        "an-imported-fact-cannot-promote-itself-to-runtime",
        downgraded["class"] == "IMPORTED" and downgraded["observed"] is False
        and downgraded["downgrades"],
        downgraded["downgrades"][0] if downgraded["downgrades"] else "no downgrade recorded"))

    probes.append(_probe(
        "a-layer-implies-its-class",
        ue.normalize_event({"layer": "runtime", "evidence_id": "E-1"})["class"]
        == "RUNTIME_OBSERVED"
        and ue.normalize_event({"layer": "sbom", "evidence_id": "E-1"})["class"] == "IMPORTED",
        "runtime -> RUNTIME_OBSERVED, sbom -> IMPORTED"))

    return {"id": "evidence_classes",
            "question": "does every claim carry a class, and can a class lie?",
            "phase": "review 5 / 21", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. the profile and its confidence ladder
# --------------------------------------------------------------------------- #


def row_usage_profile(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    probes: list[dict[str, Any]] = []

    imported = ue.usage_profile(AES, [_event("IMPORTED", "SBOM-1")])
    probes.append(_probe(
        "sbom-capability-is-low-confidence-and-not-usage",
        imported["usage"] == "CANDIDATE_ONLY" and imported["confidence"] == "LOW"
        and imported["layers"]["runtime"]["observed"] is False,
        imported["statement"]))

    static = ue.usage_profile(AES, [_event("STATIC_OBSERVED", "STATIC-1")])
    probes.append(_probe(
        "a-static-observation-is-medium-and-observed",
        (static["usage"], static["confidence"]) == ("OBSERVED", "MEDIUM"),
        static["confidence_reason"]))

    runtime = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", "RUNTIME-92821")])
    probes.append(_probe(
        "a-runtime-observation-is-high-and-carries-its-evidence",
        runtime["confidence"] == "HIGH"
        and runtime["layers"]["runtime"]["evidence"] == ["RUNTIME-92821"],
        runtime["confidence_reason"]))

    both = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", "RUNTIME-1"),
                                  _event("NETWORK_OBSERVED", "NET-9281")])
    probes.append(_probe(
        "runtime-and-network-together-are-very-high",
        both["confidence"] == "VERY_HIGH"
        and "independent collection mechanisms" in both["confidence_reason"],
        both["confidence_reason"]))

    all_layers = ue.usage_profile(AES, [
        _event("STATIC_OBSERVED", "S-1"), _event("CONFIGURED", "C-1"),
        _event("RUNTIME_OBSERVED", "R-1"), _event("NETWORK_OBSERVED", "N-1")])
    probes.append(_probe(
        "the-reviews-four-layer-view-is-produced",
        {name: row["observed"] for name, row in all_layers["layers"].items()}
        == {"static": True, "config": True, "runtime": True, "network": True}
        and all_layers["confidence"] == "VERY_HIGH",
        json.dumps({name: row["observed"] for name, row in all_layers["layers"].items()})))

    elsewhere = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", "R-9", algorithm="RSA-2048")])
    probes.append(_probe(
        "evidence-about-another-algorithm-does-not-count",
        elsewhere["usage"] == "NOT_OBSERVED" and elsewhere["evidence_ids"] == [],
        "a runtime RSA observation says nothing about AES-256-GCM"))

    empty = ue.usage_profile(AES, [])
    probes.append(_probe(
        "no-evidence-is-unknown-not-observed-as-clean",
        empty["confidence"] == "UNKNOWN" and empty["usage"] == "NOT_OBSERVED",
        empty["confidence_reason"]))

    try:
        ue.usage_profile({}, [])
        refused_asset = False
    except ue.EvidenceRefused:
        refused_asset = True
    probes.append(_probe("a-profile-of-nothing-is-refused", refused_asset,
                         "an asset needs an algorithm"))

    return {"id": "usage_profile",
            "question": "can an asset say which layer observed it, and why the confidence?",
            "phase": "review 4 / 17", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. no false attribution
# --------------------------------------------------------------------------- #


def row_no_false_attribution(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    probes: list[dict[str, Any]] = []

    candidates = ue.capability_candidates(
        "openssl", ["AES-128", "AES-256", "RSA-2048", "ECDSA-P256", "SHA-256"],
        evidence_id="SBOM-1")
    probes.append(_probe(
        "a-librarys-support-list-becomes-candidates-not-assets",
        len(candidates["candidates"]) == 5
        and {row["usage"] for row in candidates["candidates"]} == {"CANDIDATE_ONLY"}
        and {row["confidence"] for row in candidates["candidates"]} == {"LOW"},
        candidates["statement"]))

    probes.append(_probe(
        "a-candidate-carries-the-evidence-that-would-promote-it",
        candidates["promotable_by"] == ["STATIC_OBSERVED", "RUNTIME_OBSERVED",
                                        "NETWORK_OBSERVED"]
        and candidates["candidates"][0]["evidence"][0]["class"] == "IMPORTED",
        ", ".join(candidates["promotable_by"])))

    promoted = ue.usage_profile(AES, [_event("IMPORTED", "SBOM-1"),
                                      _event("RUNTIME_OBSERVED", "RUNTIME-1")])
    probes.append(_probe(
        "only-new-evidence-promotes-a-candidate-to-usage",
        promoted["usage"] == "OBSERVED" and promoted["confidence"] == "HIGH",
        "the same asset with a runtime observation is usage; the candidate was not used as "
        "evidence"))

    return {"id": "no_false_attribution",
            "question": "does an SBOM mint crypto assets it cannot prove?",
            "phase": "review 6 / 21", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. conflicts
# --------------------------------------------------------------------------- #


def row_conflicts(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    claims = [
        {"field": "version", "fact": "3.0.13", "source": "sbom"},
        {"field": "version", "fact": "3.0.13", "source": "container", "evidence_id": "C-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime", "evidence_id": "R-1"},
        {"field": "version", "fact": "3.0.13", "source": "vendor", "evidence_id": "V-1"},
    ]
    report = ue.reconcile(claims)
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "every-source-is-kept-including-the-declarations",
        [row["class"] for row in report["rows"]]
        == ["IMPORTED", "OBSERVED", "RUNTIME_OBSERVED", "VENDOR_DECLARED"],
        ", ".join(row["class"] for row in report["rows"])))

    conflict = report["conflicts"][0] if report["conflicts"] else {}
    probes.append(_probe(
        "disagreeing-observers-produce-a-named-conflict",
        conflict.get("kind") == "VERSION_CONFLICT"
        and conflict.get("values") == {"container": "3.0.13", "runtime": "3.0.11"},
        conflict.get("statement", "no conflict found")))

    probes.append(_probe(
        "a-conflicted-field-asserts-no-value",
        report["resolved"][0]["value"] is None
        and "no single value is asserted" in report["resolved"][0]["statement"],
        report["resolved"][0]["statement"]))

    agreeing = ue.reconcile([
        {"field": "version", "fact": "3.0.13", "source": "container", "evidence_id": "C-1"},
        {"field": "version", "fact": "3.0.13", "source": "runtime", "evidence_id": "R-1"},
    ])
    probes.append(_probe(
        "agreeing-observers-resolve-to-the-strongest-claim",
        agreeing["conflicts"] == [] and agreeing["resolved"][0]["value"] == "3.0.13"
        and agreeing["resolved"][0]["basis"] == "RUNTIME_OBSERVED",
        agreeing["resolved"][0]["statement"]))

    declared_only = ue.reconcile([
        {"field": "version", "fact": "3.0.11", "source": "sbom"},
        {"field": "version", "fact": "3.0.13", "source": "runtime", "evidence_id": "R-1"},
    ])
    probes.append(_probe(
        "an-imported-claim-does-not-conflict-with-an-observation",
        declared_only["conflicts"] == [] and declared_only["resolved"][0]["value"] == "3.0.13",
        "a declaration is not a second observation"))

    return {"id": "conflicts",
            "question": "does the CBOM collapse disagreeing sources into one version?",
            "phase": "review 16", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. TLS, certificates, keys, HSM
# --------------------------------------------------------------------------- #


def row_tls_certificates_keys(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    probes: list[dict[str, Any]] = []

    path = ue.tls_paths([
        {"from": "client", "to": "lb", "endpoint": "payments.bank.example:443",
         "observed_on": "External LB", "tls_version": "TLS1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"},
        {"from": "lb", "to": "gw", "endpoint": "10.0.0.5:443", "observed_on": "API Gateway",
         "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
         "evidence_id": "NET-2"},
        {"from": "gw", "to": "api", "endpoint": "10.0.2.9:8443", "observed_on": "Payments API",
         "tls_version": "TLS1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
         "evidence_id": "NET-3"},
    ])
    probes.append(_probe(
        "a-tls-chain-is-three-relationships-not-one-attribute",
        len(path["paths"]) == 3
        and [row["tls_version"] for row in path["paths"]] == ["TLS1.3", "TLS1.2", "TLS1.3"]
        and len({row["attributed_to"] for row in path["paths"]}) == 3,
        path["statement"]))

    probes.append(_probe(
        "each-hop-is-attributed-to-the-endpoint-that-terminated-it",
        all(row["attributed_to"] == row["endpoint"] for row in path["paths"])
        and "not to the application behind it" in path["statement"],
        "attribution is to the observed endpoint"))

    probes.append(_probe(
        "a-hop-without-evidence-or-endpoint-is-refused",
        ue.tls_paths([{"from": "a", "to": "b", "evidence_id": "NET-1"}])["paths"] == []
        and ue.tls_paths([{"endpoint": "x:443"}])["refused"] != [],
        "an unobserved hop is not a relationship"))

    certificate = ue.certificate_evidence({
        "certificate_ref": "cert-9281", "public_key_algorithm": "ECDSA", "curve": "P-256",
        "signature_algorithm": "ECDSA-SHA256", "san": ["payments.bank.example"],
        "endpoint": "payments.bank.example:443", "observed_on": "External LB",
        "evidence_id": "CERT-1"})
    probes.append(_probe(
        "a-certificate-is-its-own-category-and-proves-no-operation",
        certificate["certificate"]["category"] == "CERTIFICATE"
        and certificate["application_operation_proven"] is False
        and "does not prove" in certificate["statement"],
        certificate["statement"]))

    key = ue.key_metadata({"key_ref": "HSM://partition-01/key/PAY-SIGN-001",
                           "algorithm": "RSA", "key_size": 2048, "purpose": "signature",
                           "provider": "hsm", "evidence_id": "HSM-EVID-001"})
    probes.append(_probe(
        "key-metadata-is-a-reference-and-never-material",
        key["private_material"] == "NOT STORED" and key["purpose"] == "SIGNATURE",
        f"{key['key_ref']}, private_material={key['private_material']}"))

    try:
        ue.key_metadata({"key_ref": "k1", "private_key_pem": "-----BEGIN PRIVATE KEY-----"})
        refused_secret = False
    except ue.EvidenceRefused:
        refused_secret = True
    probes.append(_probe("a-private-key-in-a-cbom-is-an-error", refused_secret,
                         "the record is refused, not sanitised"))

    capability = ue.hsm_evidence("CAPABILITY")
    configured = ue.hsm_evidence("CONFIGURED_KEY", evidence_id="HSM-EVID-002")
    operation = ue.hsm_evidence("OPERATION", evidence_id="HSM-EVID-003", operation="sign")
    probes.append(_probe(
        "hsm-capability-configured-key-and-operation-are-three-answers",
        (capability["class"], capability["observed"]) == ("VENDOR_DECLARED", False)
        and (configured["class"], configured["observed"]) == ("CONFIGURED", True)
        and (operation["class"], operation["observed"]) == ("RUNTIME_OBSERVED", True),
        "VENDOR_DECLARED -> CONFIGURED -> RUNTIME_OBSERVED as evidence accumulates"))

    try:
        ue.hsm_evidence("OPERATION")
        refused_hsm = False
    except ue.EvidenceRefused:
        refused_hsm = True
    probes.append(_probe("an-hsm-operation-without-evidence-is-refused", refused_hsm,
                         "the only evidence of an operation is a record of it"))

    return {"id": "tls_certificates_keys",
            "question": "is termination, certificate crypto and HSM use kept apart?",
            "phase": "review 8-13 / 21", "probes": probes}


# --------------------------------------------------------------------------- #
# 6. coverage and API
# --------------------------------------------------------------------------- #


def row_coverage_and_api(modules: dict[str, Any]) -> dict[str, Any]:
    ue = modules["ue"]
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    main = (SERVICES / "api" / "api" / "main.py").read_text(encoding="utf-8")
    probes: list[dict[str, Any]] = []

    partial = ue.coverage(100, 62, 12)
    probes.append(_probe(
        "a-partial-estate-cannot-quote-its-count-as-a-total",
        partial["completeness"] == "PARTIAL" and partial["quotable_as_total"] is False
        and partial["coverage_pct"] == 62.0,
        partial["statement"]))

    probes.append(_probe(
        "the-statement-says-discovered-not-exists",
        "not what exists" in partial["statement"]
        and partial["statement"].startswith("12 crypto asset(s) discovered"),
        "the count is annotated with its coverage"))

    probes.append(_probe(
        "only-a-complete-inventory-is-a-total",
        ue.coverage(100, 100, 12)["quotable_as_total"] is True
        and ue.coverage(100, 0, 0)["completeness"] == "NONE"
        and ue.coverage(0, 0, 0)["completeness"] == "UNKNOWN",
        "COMPLETE is the only quotable state; NONE and UNKNOWN are named"))

    probes.append(_probe(
        "the-four-routes-exist-and-are-mounted",
        '@router.post("/usage"' in router and "response_model=CbomUsageResponse" in router
        and '@router.post("/reconcile"' in router
        and "response_model=CbomReconcileResponse" in router
        and '@router.post("/tls-paths"' in router
        and '@router.post("/hsm-evidence"' in router
        and "app.include_router(cbom_usage.router, prefix=prefix)" in main,
        "POST /cbom/{usage,reconcile,tls-paths,hsm-evidence}"))

    probes.append(_probe(
        "the-schema-key-survives-the-response-model",
        'schema_: str = Field(alias="schema")' in router,
        "the report's `schema` key is kept by the typed model"))

    return {"id": "coverage_and_api",
            "question": "does the CBOM state how much of the estate it speaks for?",
            "phase": "review 18 / 19", "probes": probes}


ROWS = (row_evidence_classes, row_usage_profile, row_no_false_attribution, row_conflicts,
        row_tls_certificates_keys, row_coverage_and_api)


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
            "the module classifies evidence, it does not collect it. A caller that labels a "
            "vendor's PDF as RUNTIME_OBSERVED with an invented evidence id defeats it, which is "
            "why the collecting layer must own the class rather than the request body",
            "confidence is a ladder over classes present, not a probability: two agreeing "
            "observations are VERY_HIGH because the mechanisms are independent, not because the "
            "answer has been tested against ground truth",
            "runtime and network evidence do not yet have first-class collectors feeding this "
            "profile. The contract, the ladder and the API exist so that they can, and until "
            "they do every asset's runtime and network rows are genuinely NOT_OBSERVED",
            "a TLS hop is attributed to the endpoint that terminated it. Nothing here proves the "
            "traffic before and after a terminator is the same connection, which is why the hops "
            "stay separate rather than being joined into a path with one verdict",
            "certificate parsing is the collector's job: this record keeps the fields it is "
            "given, and an incomplete certificate is reported as incomplete rather than read as "
            "a weaker certificate",
            "PQC status is deliberately absent. CBOM says what crypto exists; migration priority, "
            "quantum risk and the assessment itself belong to the assessment engine, which "
            "already has its own vocabulary",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# What a CBOM asset may claim",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's central point is that `AES-256-GCM / confidence HIGH` is eight claims "
        "wearing one line. This artifact measures the code that pulls them apart:",
        "",
        "1. **Capability is not usage.** A library that supports an algorithm yields candidates, "
        "never assets, and a declared fact can never promote itself to an observation.",
        "2. **The layer is named.** static, config, runtime and network are reported per asset "
        "with the evidence ids that support each, and confidence follows a stated ladder — "
        "imported `LOW`, static `MEDIUM`, runtime or network `HIGH`, runtime *and* network "
        "`VERY_HIGH`.",
        "3. **Disagreement is the finding.** Two observing sources that disagree produce a "
        "conflict and no asserted value; the imported claim is kept and labelled.",
        "4. **Termination, certificates and HSM are their own answers.** A TLS chain is one "
        "relationship per hop; a certificate proves nothing about the application's operations; "
        "HSM capability, configured key and recorded operation are three steps.",
        "5. **A partial estate cannot be quoted as a total.** `12 discovered, 62/100 inspected "
        "(62%), PARTIAL` — and only `COMPLETE` makes the count a total.",
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
