#!/usr/bin/env python3
"""Guide 164 — TechBOM is a projection of evidenced relationships, not five BOMs in a zip.

The review's TechBOM section is one long argument against a specific failure: taking the
SBOM, CBOM, HBOM, NBOM and VBOM and concatenating them. What makes the result a TechBOM
is that a **relationship is a claim with a basis**, and this guide measures the four rules
that keep that true:

1. co-occurrence is not a relationship — "Payments API" and "HSM-01" in one scan is not
   ``USES_HSM``, and the model refuses the basis by name;
2. an edge may never be stronger than its evidence — a vendor datasheet stays
   ``VENDOR_DECLARED`` however the caller labels it;
3. the layers do not stand in for each other — a certificate presented by an endpoint
   says nothing about the application's crypto library, and that is a type rule;
4. a TechBOM is a projection — ``build()`` takes the canonical estate and the model
   refuses to accept a TechBOM as its own input.

It also measures what the review asks a TechBOM to *answer*: completeness with a
denominator, cross-BOM reconciliation that keeps a conflict, blast radius over proven
paths only, and a version change that is named as one.
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
SCHEMA = "cryptoscan.cbom-techbom-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import techbom  # noqa: PLC0415

    return {"t": techbom}


def _asset(t, kind, name, **kwargs):
    kwargs.setdefault("evidence_ids", [f"EVD-{name}"])
    return {"kind": kind, "name": name, **kwargs}


def _claim(source, relation, target, basis, **kwargs):
    return {"from": source, "relation": relation, "to": target, "basis": basis,
            "evidence_ids": kwargs.pop("evidence_ids", ["EVD-1"]), **kwargs}


def _estate(t) -> dict[str, Any]:
    """The Payments system, as the review describes it: one system, real assets, real edges."""
    return {
        "schema": t.ESTATE_SCHEMA,
        "estate_id": "EST-2026-11-03",
        "environment": "PRODUCTION",
        "expected": {"BUSINESS_SYSTEM": 1, "APPLICATION": 2, "SERVICE": 1,
                     "CONTAINER": 2, "PACKAGE": 3, "CRYPTO_ASSET": 4, "CERTIFICATE": 2,
                     "HSM": 2, "VENDOR": 1, "NETWORK_ENDPOINT": 1, "LOAD_BALANCER": 1},
        "gaps": [
            {"kind": "HSM", "reason": "1 HSM collector unavailable (vendor API offline)"},
            {"kind": "PACKAGE", "reason": "payments-batch container not reachable; its "
                                          "manifest was not collected"},
        ],
        "assets": [
            _asset(t, "BUSINESS_SYSTEM", "Payments", owner="Payments Platform",
                   evidence_ids=["EVD-MGMT-1"]),
            _asset(t, "APPLICATION", "Payments API", version="2026.11.02",
                   owner="Payments Platform", evidence_ids=["EVD-CMDB-1", "EVD-TRACE-1"]),
            _asset(t, "APPLICATION", "Payments Batch", version="2026.10.01",
                   owner="Payments Platform", evidence_ids=["EVD-CMDB-1"]),
            _asset(t, "SERVICE", "payments-api", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "CONTAINER", "payments-api-7f9", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "IMAGE", "registry/payments-api:2026.11.02", version="sha256:ABC",
                   evidence_ids=["EVD-K8S-1"]),
            _asset(t, "PACKAGE", "openssl", version="3.0.13", evidence_ids=["EVD-SBOM-1"]),
            _asset(t, "CRYPTO_LIBRARY", "OpenSSL 3.0.13", version="3.0.13",
                   evidence_ids=["EVD-TRACE-1"]),
            _asset(t, "CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED",
                   evidence_ids=["EVD-TRACE-1"]),
            _asset(t, "CRYPTO_ASSET", "RSA-2048", evidence_type="STATIC_OBSERVED",
                   evidence_ids=["EVD-SBOM-2"]),
            _asset(t, "CRYPTO_ASSET", "ECDSA P-256",
                   evidence_type="CERTIFICATE_OBSERVED", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "NETWORK_ENDPOINT", "payments.bank.example:443",
                   evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "LOAD_BALANCER", "External-LB-01", location="DMZ",
                   evidence_ids=["EVD-FW-1"]),
            _asset(t, "API_GATEWAY", "payments-gw", evidence_ids=["EVD-FW-1"]),
            _asset(t, "CERTIFICATE", "CERT-9281", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "PUBLIC_KEY", "CERT-9281-key", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "ALGORITHM", "ECDSA P-256 (ecdsa-with-SHA256)",
                   evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "CERTIFICATE_AUTHORITY", "BANK-ICA-01", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "HSM", "HSM-01", location="DC1", evidence_ids=["EVD-HSM-1"]),
            _asset(t, "KEY_REFERENCE", "key/payments/rsa-2048", evidence_ids=["EVD-HSM-1"]),
            _asset(t, "FIRMWARE", "HSM fw 8.4", version="8.4", evidence_ids=["EVD-VENDOR-1"]),
            _asset(t, "VENDOR_PRODUCT", "HSM-9000", version="8.4",
                   evidence_ids=["EVD-VENDOR-1"]),
            _asset(t, "VENDOR", "Vendor X", evidence_ids=["EVD-VENDOR-1"]),
            _asset(t, "HOST", "worker-3", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "VM", "vm-worker-3", evidence_ids=["EVD-VIRT-1"]),
            _asset(t, "PHYSICAL_SERVER", "srv-12", evidence_ids=["EVD-VIRT-1"]),
            _asset(t, "TPM", "srv-12-tpm", evidence_ids=["EVD-TPM-1"]),
            _asset(t, "SOURCE", "git:abc123", evidence_ids=["EVD-CI-1"]),
            _asset(t, "BUILD", "BUILD-9281", evidence_ids=["EVD-CI-1"]),
            _asset(t, "ARTIFACT", "payments-api.jar", evidence_ids=["EVD-CI-1"]),
            _asset(t, "SBOM", "SBOM-9281", evidence_ids=["EVD-SBOM-1"]),
            _asset(t, "DEPLOYMENT", "payments-prod", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "POD", "payments-api-7f9-x2", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "PROCESS", "pid 9211", evidence_ids=["EVD-TRACE-1"]),
        ],
        "claims": [
            _claim("Payments", "CONTAINS", "Payments API", "cmdb-import"),
            _claim("Payments", "CONTAINS", "Payments Batch", "cmdb-import"),
            _claim("Payments API", "PROVIDES", "payments-api", "config-parse"),
            _claim("payments-api", "RUNS", "payments-api-7f9", "api-poll"),
            _claim("payments-api-7f9", "FROM_IMAGE", "registry/payments-api:2026.11.02",
                   "api-poll"),
            _claim("registry/payments-api:2026.11.02", "SHIPS", "openssl",
                   "sbom-import"),
            _claim("openssl", "LINKS", "OpenSSL 3.0.13", "sbom-import"),
            _claim("Payments API", "USES_CRYPTO", "AES-256-GCM", "runtime-probe"),
            _claim("Payments API", "USES_CRYPTO", "RSA-2048", "sbom-import"),
            _claim("Payments API", "EXPOSES", "payments.bank.example:443", "config-parse"),
            _claim("payments.bank.example:443", "FRONTED_BY", "External-LB-01", "api-poll"),
            _claim("External-LB-01", "FORWARDS_TO", "payments-gw", "config-parse"),
            _claim("payments-gw", "ROUTES_TO", "Payments API", "config-parse"),
            _claim("payments.bank.example:443", "PRESENTS", "CERT-9281",
                   "packet-capture"),
            _claim("CERT-9281", "CONTAINS_KEY", "CERT-9281-key", "packet-capture"),
            _claim("CERT-9281-key", "USES_ALGORITHM", "ALGORITHM:ECDSA P-256 (ecdsa-with-SHA256):production", "packet-capture"),
            _claim("CERT-9281", "ISSUED_BY", "BANK-ICA-01", "packet-capture"),
            _claim("Payments API", "USES_HSM", "HSM-01", "config-parse"),
            _claim("HSM-01", "HOLDS_KEY", "key/payments/rsa-2048", "api-poll"),
            _claim("HSM-01", "RUNS_FIRMWARE", "HSM fw 8.4", "vendor-datasheet"),
            _claim("HSM fw 8.4", "SUPPLIED_BY", "Vendor X", "vendor-datasheet"),
            _claim("HSM-9000", "SUPPLIED_BY", "Vendor X", "vendor-datasheet"),
            _claim("payments-api-7f9", "SCHEDULED_ON", "worker-3", "api-poll"),
            _claim("worker-3", "HOSTED_ON", "vm-worker-3", "api-poll"),
            _claim("vm-worker-3", "RUNS_ON", "srv-12", "api-poll"),
            _claim("srv-12", "CARRIES", "srv-12-tpm", "agent-inventory"),
            _claim("git:abc123", "BUILT_INTO", "BUILD-9281", "api-poll"),
            _claim("BUILD-9281", "PRODUCES", "payments-api.jar", "api-poll"),
            _claim("payments-api.jar", "DESCRIBED_BY", "SBOM-9281", "sbom-import"),
            _claim("payments-api.jar", "PACKAGED_AS",
                   "registry/payments-api:2026.11.02", "api-poll"),
            _claim("registry/payments-api:2026.11.02", "DEPLOYED_AS", "payments-prod",
                   "api-poll"),
            _claim("payments-prod", "SCHEDULES", "payments-api-7f9-x2", "api-poll"),
            _claim("payments-api-7f9-x2", "RUNS_PROCESS", "pid 9211", "process-trace"),
            _claim("pid 9211", "LOADS", "OpenSSL 3.0.13", "process-trace"),
        ],
    }


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refused(call, code: str) -> bool:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 — the code, not the class, is what matters
        return getattr(exc, "code", None) == code
    return False


def row_assets(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom = t.build(_estate(t))
    app = bom["by_key"]["APPLICATION:payments api:production"]
    probes = [
        _probe("an-asset-carries-a-stable-key-a-readable-id-and-its-evidence",
               app["key"].startswith("APPLICATION:") and app["id"] == "TECH-APP-001"
               and app["evidence_ids"] and app["digest"],
               f"{app['id']} · {app['key']} · {len(app['evidence_ids'])} evidence id(s)"),
        _probe("the-estate-produces-every-layer-of-the-model",
               {"BUSINESS_SYSTEM", "APPLICATION", "CONTAINER", "PACKAGE",
                "CRYPTO_LIBRARY", "CRYPTO_ASSET", "NETWORK_ENDPOINT", "CERTIFICATE",
                "HSM", "VENDOR", "PROCESS", "TPM"} <= set(bom["counts"]),
               f"{len(bom['assets'])} assets across {len(bom['counts'])} kinds"),
        _probe("an-asset-with-no-evidence-is-refused",
               _refused(lambda: t.asset("APPLICATION", "Ghost"), "ASSET_WITHOUT_EVIDENCE"),
               "an asset with no evidence id is a claim, not an asset"),
        _probe("two-assets-with-the-same-identity-are-refused-not-merged",
               t.build({**_estate(t), "assets": [
                   _asset(t, "APPLICATION", "Payments API"),
                   _asset(t, "APPLICATION", "payments api", owner="another team")]})
               ["refusals"][0]["code"] == "DUPLICATE_ASSET",
               "the first description is kept and the second refused"),
        _probe("ids-are-deterministic-for-one-estate-and-not-durable",
               [row["id"] for row in t.build(_estate(t))["assets"]]
               == [row["id"] for row in bom["assets"]]
               and bom["not_proven"][-1].startswith("that ids are permanent"),
               "same estate, same ids; anything durable keys on `key`"),
    ]
    return {"id": "assets",
            "question": "is there an explicit asset model with identity that survives?",
            "phase": "review techbom / 6", "probes": probes}


def row_claims(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom = t.build(_estate(t))
    probes = [
        _probe("every-relationship-carries-a-basis-a-class-and-an-evidence-id",
               all(row["basis"] and row["confidence"] in t.CONFIDENCE
                   and row["evidence_ids"] and row["chain"] for row in bom["claims"]),
               f"{len(bom['claims'])} claim(s), each with its basis printed"),
        _probe("co-occurrence-is-refused-by-name",
               _refused(lambda: t.claim("Payments API", "USES_HSM", "HSM-01",
                                        basis="co-occurrence", evidence_ids=["E"]),
                        "CO_OCCURRENCE_NOT_EVIDENCE"),
               "two assets in one scan is proximity, not a relationship"),
        _probe("the-other-proximity-bases-are-refused-too",
               all(_refused(lambda basis=basis: t.claim(
                   "Payments API", "USES_HSM", "HSM-01", basis=basis,
                   evidence_ids=["E"]), "CO_OCCURRENCE_NOT_EVIDENCE")
                   for basis in ("same-scan", "proximity", "name-similarity",
                                 "assumption")),
               "same-scan · proximity · name-similarity · assumption"),
        _probe("an-edge-may-not-be-stronger-than-its-evidence",
               _refused(lambda: t.claim("Payments API", "USES_HSM", "HSM-01",
                                        basis="vendor-datasheet", confidence="OBSERVED",
                                        evidence_ids=["E"]),
                        "CLAIM_STRONGER_THAN_EVIDENCE")
               and any(row["confidence"] == "VENDOR_DECLARED"
                       for row in bom["claims"]),
               "a vendor datasheet stays VENDOR_DECLARED however it is labelled"),
        _probe("an-inference-must-name-its-rule-so-it-can-be-argued-with",
               _refused(lambda: t.claim("Payments API", "USES_HSM", "HSM-01",
                                        basis="name-match", evidence_ids=["E"]),
                        "INFERENCE_WITHOUT_RULE"),
               "an unnamed inference is an assumption with better manners"),
    ]
    return {"id": "claims",
            "question": "is a relationship a claim with a basis, or a proximity guess?",
            "phase": "review techbom / 5 and 22", "probes": probes}


def row_boundaries(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    probes = [
        _probe("a-certificate-does-not-prove-the-application-s-crypto",
               t.check_types("USES_ALGORITHM", "APPLICATION", "ALGORITHM")[0] is False,
               "the algorithm is reached through the key that carries it"),
        _probe("a-network-hop-does-not-reach-into-application-internals",
               t.check_types("SCHEDULED_ON", "NETWORK_ENDPOINT", "HOST")[0] is False
               and t.check_types("SCHEDULED_ON", "CONTAINER", "HOST")[0] is True,
               "a container is scheduled on a host; an endpoint is not"),
        _probe("a-runtime-crypto-use-may-not-be-evidenced-by-a-manifest",
               _first_refusal(t, {
                   "assets": [_asset(t, "APPLICATION", "Payments API"),
                              _asset(t, "CRYPTO_ASSET", "AES-256-GCM",
                                     evidence_type="RUNTIME_OBSERVED")],
                   "claims": [_claim("Payments API", "USES_CRYPTO", "AES-256-GCM",
                                     "sbom-import")]}) == "EVIDENCE_CLASS_MISMATCH",
               "RUNTIME_OBSERVED, STATIC_OBSERVED and CERTIFICATE_OBSERVED stay apart"),
        _probe("an-edge-to-an-undeclared-node-is-refused-not-invented",
               _first_refusal(t, {
                   "assets": [_asset(t, "APPLICATION", "Payments API")],
                   "claims": [_claim("Payments API", "USES_HSM", "HSM-99",
                                     "config-parse")]}) == "UNKNOWN_REF",
               "an edge may only join assets the estate declares"),
        _probe("the-seven-chains-are-modelled-and-distinguishable",
               set(t.build(_estate(t))["claim_counts"]) == {
                   "SOFTWARE", "NETWORK", "CERTIFICATE", "KEYS", "HARDWARE", "VENDOR",
                   "RUNTIME"},
               ", ".join(sorted(t.build(_estate(t))["claim_counts"]))),
    ]
    return {"id": "boundaries",
            "question": "do the layers stay apart instead of standing in for each other?",
            "phase": "review techbom / 9, 10, 12, 13, 22", "probes": probes}


def _first_refusal(t, parts: dict[str, Any]) -> str | None:
    """The code of the first claim the estate refuses, or None if it accepted one."""
    bom = t.build({"schema": t.ESTATE_SCHEMA, **parts})
    return bom["refusals"][0]["code"] if bom["refusals"] else None


def row_completeness(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom = t.build(_estate(t))
    block = bom["completeness"]
    hsm = next(row for row in block["rows"] if row["kind"] == "HSM")
    probes = [
        _probe("the-overall-verdict-is-partial-and-says-so",
               block["overall"] == "PARTIAL" and "PARTIAL" in block["statement"],
               block["statement"]),
        _probe("every-kind-is-measured-against-a-denominator",
               hsm == {"kind": "HSM", "observed": 1, "expected": 2, "coverage": 0.5,
                       "verdict": "PARTIAL"},
               "HSM 1 / 2, coverage 0.50"),
        _probe("each-gap-carries-the-reason-a-person-would-ask-for",
               {gap["kind"] for gap in block["gaps"]} == {"HSM", "PACKAGE"}
               and all(gap["reason"] for gap in block["gaps"]),
               " · ".join(gap["reason"] for gap in block["gaps"])),
        _probe("a-kind-with-no-denominator-is-unmeasured-not-complete",
               t.completeness([{"kind": "TPM"}, {"kind": "KMS"}], {})["overall"]
               == "UNMEASURED",
               "a count nobody can divide by is not coverage"),
        _probe("an-asset-count-is-never-printed-without-its-relationships-and-verdict",
               "relationship(s)" in bom["statement"]
               and "across" in bom["statement"] and block["rationale"],
               bom["statement"]),
    ]
    return {"id": "completeness",
            "question": "is coverage explicit, with a denominator and a reason per gap?",
            "phase": "review techbom / 16", "probes": probes}


def row_reconciliation(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    body = t.reconcile([
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.11",
         "source": "runtime", "basis": "process-trace"},
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
         "source": "sbom", "basis": "sbom-import"},
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
         "source": "vendor declaration", "basis": "vendor-datasheet"},
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
         "source": "container", "basis": "api-poll"},
        {"subject": "Payments API", "attribute": "runtime", "value": "OpenJDK 21",
         "source": "cmdb", "basis": "cmdb-import"},
        {"subject": "Payments API", "attribute": "runtime", "value": "OpenJDK 21",
         "source": "runtime", "basis": "process-trace"},
    ])
    conflict = body["conflicts"][0]
    agree = next(row for row in body["findings"] if row["attribute"] == "runtime")
    probes = [
        _probe("four-sources-three-agreeing-is-still-a-conflict",
               conflict["status"] == "CONFLICT" and conflict["values"]
               == ["3.0.11", "3.0.13"] and conflict["sources"] == 4,
               conflict["statement"]),
        _probe("the-conflict-is-left-unresolved-instead-of-picking-a-winner",
               conflict["resolution"] == "UNRESOLVED"
               and conflict["strongest"] == "OBSERVED",
               "observed 3.0.11 · artifact 3.0.13 · vendor 3.0.13 · resolution UNRESOLVED"),
        _probe("agreement-is-reported-and-not-called-verification",
               agree["status"] == "AGREE"
               and "agreement is not verification" in agree["statement"],
               agree["statement"]),
        _probe("a-proximity-source-cannot-settle-an-attribute",
               t.reconcile([{"subject": "A", "attribute": "v", "value": "1",
                             "source": "scan", "basis": "same-scan"}])["findings"][0]
               ["observations"][0]["confidence"] == "UNKNOWN",
               "a scan-time co-occurrence is not a statement about the attribute"),
        _probe("the-report-says-what-it-cannot-decide",
               any("which of two conflicting values is deployed"
                   in line for line in body["not_proven"]),
               f"{len(body['not_proven'])} stated limit(s)"),
    ]
    return {"id": "reconciliation",
            "question": "does a disagreement survive into the report instead of being lost?",
            "phase": "review techbom / 18", "probes": probes}


def row_radius_and_time(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom = t.build(_estate(t))
    radius = t.blast_radius(bom, query="ECDSA P-256")
    hsm = t.blast_radius(bom, query="HSM-01")
    changed = _estate(t)
    changed["assets"] = [
        {**row, "version": "3.0.11"} if row["name"] == "openssl" else row
        for row in changed["assets"]]
    drift = t.diff(bom, t.build(changed))
    version = [row for row in drift["events"]
               if row["change"] == "TECHNOLOGY_VERSION_CHANGED"][0]
    probes = [
        _probe("a-blast-radius-is-proven-for-applications-and-declared-above-them",
               "TECH-APP-001" in {row["id"] for row in radius["reachable"]}
               and radius["systems"] == []
               and "TECH-SYS-001" in radius["possible"],
               "the application is proven by config and capture; "
               "the business system above it is only an import"),
        _probe("reachability-is-not-the-same-as-impact",
               radius["reachable"] and "reachability is exposure" in " ".join(
                   radius["not_proven"]),
               f"{len(radius['reachable'])} dependent(s), each with its hop count"),
        _probe("a-migration-blocker-is-named-where-it-sits",
               hsm["pqc_blockers"][0]["kind"] == "HSM"
               and hsm["pqc_blockers"][0]["asset"] == "TECH-HSM-001",
               hsm["pqc_blockers"][0]["detail"]),
        _probe("a-declared-edge-is-not-counted-as-a-proven-dependency-path",
               t.blast_radius(bom, query="Vendor X")["reachable"] == []
               or all(row["proven"] is False
                      for row in t.blast_radius(bom, query="Vendor X")["reachable"]),
               "VENDOR_DECLARED paths land in `possible`, not in `reachable`"),
        _probe("a-version-change-is-a-named-event-with-both-values",
               version["detail"] == "openssl: 3.0.13 → 3.0.11"
               and version["category"] == "SBOM_CHANGED",
               version["detail"]),
    ]
    return {"id": "radius_and_time",
            "question": "can the bom answer what breaks, and what changed?",
            "phase": "review techbom / 15, 19, 20", "probes": probes}


def row_projection(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom = t.build(_estate(t))
    probes = [
        _probe("the-document-declares-itself-a-projection",
               bom["projection"] is True
               and bom["source_of_truth"] == "CANONICAL_ESTATE",
               "evidence → canonical estate → TechBOM, never the other way round"),
        _probe("a-techbom-cannot-be-fed-back-in-as-its-own-source",
               _raises(lambda: t.from_document(bom), "not a source")
               and _raises(lambda: t.build(bom), "techbom-estate"),
               "no second source of truth, by construction"),
        _probe("the-summary-reports-confidence-not-just-a-count",
               t.summary(bom)["by_confidence"]["VENDOR_DECLARED"] == 3
               and t.summary(bom)["relationships"] == len(bom["claims"]),
               json.dumps(t.summary(bom)["by_confidence"])),
        _probe("a-bom-that-loses-its-evidence-is-refused-at-the-asset",
               _refused(lambda: t.asset("HSM", "HSM-02", location="DC2"),
                        "ASSET_WITHOUT_EVIDENCE"),
               "the asset model is not the place a fact arrives unbacked"),
        _probe("the-report-states-what-it-does-not-prove",
               any("declared edge is deployed" in line for line in bom["not_proven"])
               and any("completeness" in line for line in bom["not_proven"]),
               f"{len(bom['not_proven'])} stated limit(s)"),
    ]
    return {"id": "projection",
            "question": "is TechBOM a projection, and does it know what it cannot say?",
            "phase": "review techbom / 17", "probes": probes}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


ROWS = (row_assets, row_claims, row_boundaries, row_completeness, row_reconciliation,
        row_radius_and_time, row_projection)


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
    t = modules["t"]
    bom = t.build(_estate(t))
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "kinds": list(t.ASSET_TYPES),
        "relations": {name: {"chain": spec["chain"], "from": list(spec["from"]),
                            "to": list(spec["to"])}
                      for name, spec in sorted(t.RELATIONS.items())},
        "bases": dict(t.BASES),
        "not_a_basis": dict(t.NOT_A_BASIS),
        "confidence": dict(t.CONFIDENCE),
        "bom": bom,
        "summary": t.summary(bom),
        "radius": t.blast_radius(bom, query="ECDSA P-256"),
        "reconciliation": t.reconcile([
            {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.11",
             "source": "runtime", "basis": "process-trace"},
            {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
             "source": "sbom", "basis": "sbom-import"},
            {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
             "source": "vendor declaration", "basis": "vendor-datasheet"}]),
        "rows": rows,
        "limits": [
            "the estate is a fixture, not a bank: every asset and edge here is the shape "
            "of the argument, and none of it is an observation of a real network",
            "an edge is in the graph because a source asserted it. A relationship nobody "
            "recorded is missing, and this model does not infer it from proximity",
            "completeness is only as honest as its denominator, which comes from "
            "authorisation and the scan plan, not from this module",
            "a blast radius is exposure, not impact: whether a dependent system actually "
            "breaks is the owner's assessment",
            "reconciliation preserves a conflict and cannot resolve it — resolution needs "
            "a probe at the place the value matters",
            "readable ids renumber when the estate changes, so only `key` may be used as "
            "a durable reference",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    bom = report["bom"]
    summary = report["summary"]
    block = bom["completeness"]
    lines = [
        "# TechBOM is a projection of evidenced relationships",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "A TechBOM is not `SBOM + CBOM + HBOM + NBOM + VBOM` in one file. It is a graph "
        "of typed assets whose every edge is a claim carrying a basis, a confidence "
        "class and an evidence id.",
        "",
        "```",
        "EVIDENCE  →  CANONICAL ESTATE  →  TECHBOM (a projection)",
        "",
        "BUSINESS_SYSTEM → APPLICATION → SERVICE → CONTAINER → IMAGE",
        "                            → PACKAGE → CRYPTO_LIBRARY → CRYPTO_ASSET",
        "APPLICATION → NETWORK_ENDPOINT → LOAD_BALANCER → API_GATEWAY → APPLICATION",
        "ENDPOINT → CERTIFICATE → PUBLIC_KEY → ALGORITHM → CERTIFICATE_AUTHORITY → HSM",
        "APPLICATION → HSM → KEY_REFERENCE",
        "APPLICATION → VENDOR_PRODUCT → VENDOR",
        "SOURCE → BUILD → ARTIFACT → SBOM → IMAGE → DEPLOYMENT → POD → PROCESS",
        "```",
        "",
        bom["statement"],
        "",
        f"Completeness: **{block['overall']}** — {block['statement']}",
        "",
        "| kind | observed | expected | verdict |",
        "|---|---|---|---|",
    ]
    for row in block["rows"]:
        expected = "—" if row["expected"] is None else row["expected"]
        lines.append(f"| `{row['kind']}` | {row['observed']} | {expected} | "
                     f"{row['verdict']} |")
    lines += [
        "",
        "Gaps stated by the source:",
        "",
        *[f"- `{gap['kind']}` — {gap['reason']}" for gap in block["gaps"]],
        "",
        "| chain | relationships |",
        "|---|---|",
        *[f"| `{chain}` | {count} |" for chain, count in summary["by_chain"].items()],
        "",
        "| confidence | relationships |",
        "|---|---|",
        *[f"| `{name}` | {count} |" for name, count in summary["by_confidence"].items()],
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
