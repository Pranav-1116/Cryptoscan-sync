#!/usr/bin/env python3
"""Guide 165 — the questions a TechBOM has to answer, asked of the graph.

Guide 164 built the graph and its guard rails: assets are identities, edges are claims with
a basis, and nothing is joined because it was seen together. A graph is only worth that
discipline if it can answer the questions an estate actually asks, so this guide measures
the answers — and measures that each answer inherits the graph's rules:

1. **roll-up** — a business system's technology counted by kind, proven only, with the
   declared remainder reported separately;
2. **request path** — the hops a request travels and the crypto each one negotiates, with
   an unrecorded hop marked `NOT_RECORDED` instead of drawn clean;
3. **impact** — the vocabulary an owner asks for, and typed blockers that say who acts;
4. **time** — a series of snapshots, because one snapshot is not a timeline;
5. **threat context** — an event placed in the estate it happened to, or a refusal;
6. **promotion** — `IMPORTED` becomes `OBSERVED` only with evidence the claim did not have.
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
SCHEMA = "cryptoscan.cbom-techbom-answers-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import techbom, techbom_queries  # noqa: PLC0415

    return {"t": techbom, "q": techbom_queries}


def _asset(t, kind, name, **kwargs):
    kwargs.setdefault("evidence_ids", [f"EVD-{name}"])
    return {"kind": kind, "name": name, **kwargs}


def _claim(source, relation, target, basis, **kwargs):
    return {"from": source, "relation": relation, "to": target, "basis": basis,
            "evidence_ids": kwargs.pop("evidence_ids", ["EVD-1"]), **kwargs}


def _estate(t, *, openssl: str = "3.0.13", certificate: str = "CERT-9281",
            hsm_firmware: str = "8.4") -> dict[str, Any]:
    """Payments: one business system, a request path, an HSM, a CA, a vendor, a build."""
    return {
        "schema": t.ESTATE_SCHEMA,
        "estate_id": f"EST-2026-11-03-{openssl}-{certificate}",
        "environment": "PRODUCTION",
        "expected": {"BUSINESS_SYSTEM": 1, "APPLICATION": 2, "SERVICE": 1,
                     "CONTAINER": 2, "PACKAGE": 3, "CRYPTO_ASSET": 3, "CERTIFICATE": 1,
                     "HSM": 2, "VENDOR": 1, "NETWORK_ENDPOINT": 1, "LOAD_BALANCER": 1,
                     "DATABASE": 1, "WAF": 1, "SERVICE_MESH": 1},
        "gaps": [
            {"kind": "HSM", "reason": "1 HSM collector unavailable (vendor API offline)"},
            {"kind": "PACKAGE", "reason": "payments-batch container not reachable; its "
                                          "manifest was not collected"},
        ],
        "assets": [
            _asset(t, "BUSINESS_SYSTEM", "Payments", owner="Payments Platform",
                   criticality="CRITICAL", evidence_ids=["EVD-MGMT-1"]),
            _asset(t, "APPLICATION", "Payments API", version="2026.11.02",
                   owner="Payments Platform", evidence_ids=["EVD-CMDB-1", "EVD-TRACE-1"]),
            _asset(t, "APPLICATION", "Payments Batch", version="2026.10.01",
                   owner="Payments Platform", status="LEGACY", evidence_ids=["EVD-CMDB-1"]),
            _asset(t, "SERVICE", "payments-api", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "CONTAINER", "payments-api-7f9", evidence_ids=["EVD-K8S-1"]),
            _asset(t, "IMAGE", "registry/payments-api:2026.11.02", version="sha256:ABC",
                   evidence_ids=["EVD-K8S-1"]),
            _asset(t, "PACKAGE", "openssl", version=openssl, evidence_ids=["EVD-SBOM-1"]),
            _asset(t, "CRYPTO_LIBRARY", "OpenSSL 3.0.13", version="3.0.13",
                   evidence_ids=["EVD-TRACE-1"]),
            _asset(t, "CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED",
                   evidence_ids=["EVD-TRACE-1"]),
            _asset(t, "CRYPTO_ASSET", "RSA-2048", evidence_type="STATIC_OBSERVED",
                   evidence_ids=["EVD-SBOM-2"]),
            _asset(t, "NETWORK_ENDPOINT", "payments.bank.example:443",
                   tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                   sni="payments.bank.example", alpn="h2", mtls=True,
                   evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "WAF", "waf-01", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "LOAD_BALANCER", "External-LB-01", location="DMZ",
                   tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                   evidence_ids=["EVD-FW-1"]),
            _asset(t, "API_GATEWAY", "payments-gw", tls_version="TLSv1.3",
                   evidence_ids=["EVD-FW-1"]),
            _asset(t, "SERVICE_MESH", "payments-mesh", mtls=True,
                   evidence_ids=["EVD-K8S-1"]),
            _asset(t, "DATABASE", "payments-db", tls_version="TLSv1.2",
                   evidence_ids=["EVD-DB-1"]),
            _asset(t, "CERTIFICATE", certificate, not_after="2028-04-01T00:00:00Z",
                   evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "PUBLIC_KEY", f"{certificate}-key", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "ALGORITHM", "ECDSA P-256", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "CERTIFICATE_AUTHORITY", "BANK-ICA-01", evidence_ids=["EVD-PCAP-1"]),
            _asset(t, "HSM", "HSM-01", location="DC1", evidence_ids=["EVD-HSM-1"]),
            _asset(t, "KEY_REFERENCE", "key/payments/rsa-2048", evidence_ids=["EVD-HSM-1"]),
            _asset(t, "FIRMWARE", f"HSM fw {hsm_firmware}", version=hsm_firmware,
                   supports=["RSA-2048", "AES-256"], evidence_ids=["EVD-VENDOR-1"]),
            _asset(t, "VENDOR_PRODUCT", "HSM-9000", version=hsm_firmware,
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
            _claim("Payments", "CONTAINS", "Payments API", "agent-inventory"),
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
            _claim("Payments API", "EXPOSES", "payments.bank.example:443",
                   "config-parse"),
            _claim("Payments API", "USES_HSM", "HSM-01", "config-parse"),
            _claim("Payments API", "STORES_IN", "payments-db", "config-parse"),
            _claim("payments.bank.example:443", "PROTECTED_BY", "waf-01", "config-parse"),
            _claim("waf-01", "FORWARDS_TO", "External-LB-01", "config-parse"),
            _claim("External-LB-01", "FORWARDS_TO", "payments-gw", "config-parse"),
            _claim("payments-gw", "FORWARDS_TO", "payments-mesh", "config-parse"),
            _claim("payments-mesh", "ROUTES_TO", "Payments API", "config-parse"),
            _claim("payments.bank.example:443", "PRESENTS", certificate,
                   "packet-capture"),
            _claim(certificate, "CONTAINS_KEY", f"{certificate}-key",
                   "packet-capture"),
            _claim(f"{certificate}-key", "USES_ALGORITHM", "ECDSA P-256",
                   "packet-capture"),
            _claim(certificate, "ISSUED_BY", "BANK-ICA-01", "packet-capture"),
            _claim("BANK-ICA-01", "KEY_HELD_BY", "HSM-01", "vendor-datasheet"),
            _claim("HSM-01", "RUNS_FIRMWARE", f"HSM fw {hsm_firmware}", "api-poll"),
            _claim("HSM-01", "HAS_MODEL", "HSM-9000", "vendor-datasheet"),
            _claim("HSM-01", "HOLDS_KEY", "key/payments/rsa-2048", "api-poll"),
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
    except Exception as exc:  # noqa: BLE001 — the code is the contract, not the class
        return getattr(exc, "code", None) == code
    return False


def _bom(modules: dict[str, Any], **kwargs):
    return modules["t"].build(_estate(modules["t"], **kwargs))


# --------------------------------------------------------------------------- #
# rows
# --------------------------------------------------------------------------- #

def row_rollup(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    profile = q.rollup(bom, system="Payments")["systems"][0]
    probes = [
        _probe("a-business-system-roll-up-counts-technology-by-kind",
               profile["counts"]["APPLICATION"] == 2
               and profile["counts"]["CERTIFICATE"] == 1
               and profile["counts"]["HSM"] == 1
               and profile["counts"]["NETWORK_ENDPOINT"] == 1,
               profile["statement"]),
        _probe("the-roll-up-carries-the-criticality-and-the-owner",
               profile["criticality"] == "CRITICAL"
               and profile["owner"] == "Payments Platform",
               "Payments · CRITICAL · Payments Platform"),
        _probe("a-declared-hop-is-counted-and-labelled-rather-than-hidden-or-flattened",
               profile["declared_only"]["APPLICATION"] == 1
               and profile["counts"]["APPLICATION"] == 2
               and profile["by_confidence"]["DECLARED"] == profile["declared_only_assets"]
               and "declared only" in profile["statement"],
               "Payments Batch arrives by CMDB import: in the count, out of the proven "
               "number, and named in the split"),
        _probe("a-roll-up-refuses-something-that-is-not-a-business-system",
               _raises(lambda: q.rollup(bom, system="Payments API"),
                       "not a business system"),
               "a scan target is not a business system"),
        _probe("the-portfolio-roll-up-lists-every-system-with-its-size",
               q.rollup(bom)["statement"].startswith("1 business system(s)")
               and q.rollup(bom)["systems"][0]["system"] == "TECH-SYS-001",
               q.rollup(bom)["statement"]),
    ]
    return {"id": "rollup",
            "question": "does a business system know the technology it actually holds?",
            "phase": "review tc / 7 and 8", "probes": probes}


def row_path(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    body = q.path(bom, source="payments.bank.example:443", target="Payments API")
    route = body["paths"][0]
    hops = {hop["name"]: hop for hop in route["hops"]}
    probes = [
        _probe("a-request-path-is-a-sequence-of-technology-not-a-list-of-endpoints",
               [hop["name"] for hop in route["hops"]] == [
                   "payments.bank.example:443", "waf-01", "External-LB-01",
                   "payments-gw", "payments-mesh", "Payments API"],
               route["statement"]),
        _probe("each-hop-carries-the-crypto-it-negotiates",
               hops["payments.bank.example:443"]["crypto"]["tls_version"] == "TLSv1.3"
               and hops["External-LB-01"]["crypto"]["tls_version"] == "TLSv1.2"
               and hops["payments-mesh"]["crypto"]["mtls"] is True,
               "TLS 1.3 at the edge, TLS 1.2 at the balancer, mTLS in the mesh"),
        _probe("a-hop-with-no-crypto-recorded-is-marked-not-drawn-clean",
               hops["waf-01"]["note"] == "NOT_RECORDED"
               and hops["waf-01"]["crypto_recorded"] is False,
               f"crypto recorded on {route['crypto_recorded']} hops"),
        _probe("the-hop-that-presents-a-certificate-names-it",
               hops["payments.bank.example:443"]["certificate"] == "TECH-CERT-001",
               "endpoint → CERT-9281"),
        _probe("a-path-refuses-an-asset-the-bom-does-not-hold",
               _raises(lambda: q.path(bom, source="nowhere.example:443"),
                       "not in this TechBOM"),
               "a path is drawn from the graph or not at all"),
    ]
    return {"id": "path",
            "question": "what technology path does a request travel through?",
            "phase": "review tc / 11", "probes": probes}


def row_impact(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    body = q.impact(bom, query="AES-256-GCM",
                    required_algorithms=["ML-KEM-768", "ML-DSA-65"],
                    deadline="2027-01-01")
    declared = q.impact(bom, query="RSA-2048")
    probes = [
        _probe("impact-answers-in-the-vocabulary-an-owner-asks-for",
               body["counts"]["APPLICATION"] == 1
               and body["counts"]["BUSINESS_SYSTEM"] == 1
               and body["counts"]["NETWORK_ENDPOINT"] == 1
               and body["critical_systems"] == ["TECH-SYS-001"]
               and body["primary_system"] == "TECH-SYS-001",
               body["statement"]),
        _probe("impact-counts-only-what-the-graph-proves-and-lists-the-rest",
               "APPLICATION" not in declared["counts"]
               and declared["declared_only"]
               and declared["systems"] == [],
               "RSA-2048 reaches the estate through a manifest row, so nothing above it "
               "is proven"),
        _probe("a-blocker-names-who-has-to-act",
               {row["code"] for row in body["pqc_blockers"]}
               >= {"HSM_PQC_CAPABILITY_UNKNOWN", "FIRMWARE_UPGRADE_REQUIRED"}
               and all(row["who_acts"] for row in body["pqc_blockers"]),
               " · ".join(sorted(body["blocker_counts"]))),
        _probe("a-migration-site-is-found-through-the-application-that-uses-it",
               body["migration_sites"]
               and "TECH-HSM-001" in body["migration_sites"]
               and "TECH-FW-001" in body["migration_sites"],
               ", ".join(body["migration_sites"])),
        _probe("an-application-whose-crypto-is-unknown-is-a-blocker-of-its-own",
               "LEGACY_APPLICATION_UNKNOWN" in {
                   row["code"]
                   for row in q.impact(bom, query="Payments Batch")["pqc_blockers"]},
               "a migration cannot plan around an application nobody has read"),
    ]
    return {"id": "impact",
            "question": "what breaks, who has to change, and what is only declared?",
            "phase": "review tc / 12, 19 and 20", "probes": probes}


def row_time(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    series = [_bom(modules, openssl="3.0.13"),
              _bom(modules, openssl="3.0.11"),
              _bom(modules, openssl="3.0.11", certificate="CERT-9821")]
    body = q.timeline(series)
    single = q.timeline(series[:1])
    version = next(row for row in body["changes"]
                   if row["change"] == "TECHNOLOGY_VERSION_CHANGED")
    probes = [
        _probe("one-snapshot-is-a-state-and-says-so",
               single["measurable"] is False and single["changes"] == [],
               single["statement"]),
        _probe("a-timeline-names-each-change-in-its-own-category",
               body["measurable"] is True
               and body["by_category"]["CERTIFICATE_CHANGED"] >= 1
               and body["by_category"]["SBOM_CHANGED"] >= 1,
               body["statement"]),
        _probe("a-version-change-carries-both-values-and-its-step",
               version["detail"] == "openssl: 3.0.13 → 3.0.11"
               and version["step"] == 1,
               version["detail"]),
        _probe("the-series-shows-the-estate-size-at-each-snapshot",
               len(body["series"]) == 3 and body["series"][0]["assets"] > 0,
               json.dumps(body["series"])),
        _probe("a-timeline-refuses-a-document-that-is-not-a-snapshot",
               _raises(lambda: q.timeline([{"schema": "other/1"}]),
                       "snapshots"),
               "a foreign document is rejected, not interpolated"),
    ]
    return {"id": "time",
            "question": "can the bom say what changed, not just what is?",
            "phase": "review tc / 15", "probes": probes}


def row_context(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    event = {"kind": "TLS_DOWNGRADE", "asset": "payments.bank.example:443",
             "before": "TLSv1.3", "after": "TLSv1.2", "evidence_ids": ["EVD-EVT-1"],
             "observed_at": "2026-11-03T02:00:00Z"}
    body = q.threat_context(bom, event)
    probes = [
        _probe("an-event-becomes-a-correlated-pattern-with-the-estate-behind-it",
               body["pattern"] == "CORRELATED_PATTERN"
               and body["systems"][0]["name"] == "Payments"
               and body["technology"][0]["name"] == "Payments API",
               body["statement"]),
        _probe("the-pattern-names-the-change-not-just-the-event",
               body["change"] == {"attribute": "tls_version", "from": "TLSv1.3",
                                 "to": "TLSv1.2"},
               "TLSv1.3 → TLSv1.2 on the endpoint that presents CERT-9281"),
        _probe("the-related-assets-come-from-the-graph",
               {row["relation"] for row in body["related"]} >= {"PRESENTS", "EXPOSES"},
               ", ".join(sorted({row["relation"] for row in body["related"]}))),
        _probe("a-context-will-not-name-an-asset-the-bom-does-not-hold",
               _raises(lambda: q.threat_context(bom, {**event,
                                                     "asset": "external-lb-99"}),
                       "not in this TechBOM"),
               "a fabricated context is worse than no context"),
        _probe("an-event-with-no-evidence-is-a-rumour-and-is-refused",
               _raises(lambda: q.threat_context(bom, {**event, "evidence_ids": []}),
                       "rumour"),
               "no evidence id, no pattern"),
    ]
    return {"id": "context",
            "question": "can a live event be placed in the estate it happened to?",
            "phase": "review tc / 21", "probes": probes}


def row_promotion(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    imported = next(row for row in bom["claims"]
                    if row["confidence"] == "IMPORTED"
                    and row["relation"] == "USES_CRYPTO")
    promoted = q.verify(imported, basis="runtime-probe",
                        evidence_ids=["EVD-PROBE-9"], at="2026-11-03T03:00:00Z")
    probes = [
        _probe("an-imported-relationship-becomes-observed-only-with-new-evidence",
               promoted["confidence"] == "OBSERVED"
               and promoted["promoted_from"] == "IMPORTED"
               and "EVD-PROBE-9" in promoted["evidence_ids"],
               promoted["statement"]),
        _probe("the-previous-class-is-kept-in-the-history",
               promoted["history"][0]["confidence"] == "IMPORTED"
               and promoted["history"][1]["confidence"] == "OBSERVED",
               "the model does not rewrite what it used to believe"),
        _probe("a-promotion-needs-a-stronger-basis",
               _refused(lambda: q.verify(imported, basis="cmdb-import",
                                         evidence_ids=["EVD-PROBE-9"]),
                        "NOT_A_VERIFICATION"),
               "changing the label is not verification"),
        _probe("a-promotion-needs-evidence-the-claim-did-not-already-cite",
               _refused(lambda: q.verify(imported, basis="runtime-probe",
                                         evidence_ids=imported["evidence_ids"]),
                        "NO_NEW_EVIDENCE"),
               "a belief restated is not an observation"),
        _probe("proximity-can-never-promote-anything",
               _refused(lambda: q.verify(imported, basis="co-occurrence",
                                         evidence_ids=["EVD-PROBE-9"]),
                        "CO_OCCURRENCE_NOT_EVIDENCE"),
               "the same rule that builds the graph keeps it honest"),
    ]
    return {"id": "promotion",
            "question": "can a claim get stronger without being quietly rewritten?",
            "phase": "review tc / 22", "probes": probes}


def row_honesty(modules: dict[str, Any]) -> dict[str, Any]:
    q = modules["q"]
    bom = _bom(modules)
    probes = [
        _probe("every-answer-carries-the-limits-it-cannot-cross",
               all(body["not_proven"] for body in (
                   q.rollup(bom), q.path(bom, source="payments.bank.example:443"),
                   q.impact(bom, query="AES-256-GCM"),
                   q.threat_context(bom, {"kind": "TLS_DOWNGRADE",
                                          "asset": "payments.bank.example:443",
                                          "before": "TLSv1.3", "after": "TLSv1.2",
                                          "evidence_ids": ["EVD-EVT-1"]}))),
               "each answer states what the graph cannot support"),
        _probe("reachability-is-never-reported-as-breakage",
               any("reachability is exposure" in line
                   for line in q.impact(bom, query="AES-256-GCM")["not_proven"]),
               "an owner's impact assessment sits above the graph"),
        _probe("a-downgrade-is-not-called-an-attack",
               any("most common cause" in line
                   for line in q.threat_context(bom, {
                       "kind": "TLS_DOWNGRADE", "asset": "payments.bank.example:443",
                       "before": "TLSv1.3", "after": "TLSv1.2",
                       "evidence_ids": ["EVD-EVT-1"]})["not_proven"]),
               "a client negotiating lower is the usual explanation"),
        _probe("every-answer-refuses-a-document-that-is-not-a-techbom",
               all(_raises(lambda fn=fn: fn({"schema": "other/1", "by_key": {}}),
                           "techbom/1")
                   for fn in (q.rollup,
                              lambda doc: q.path(doc, source="x"),
                              lambda doc: q.impact(doc, query="x"))),
               "the answers cannot be asked of the wrong document"),
        _probe("the-whole-guide-runs-on-one-estate-build-not-a-copy",
               bom["statement"].startswith("36 technology asset(s)")
               and len(bom["claims"]) >= 30,
               bom["statement"]),
    ]
    return {"id": "honesty",
            "question": "does each answer stop where the evidence stops?",
            "phase": "all of review tc", "probes": probes}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


ROWS = (row_rollup, row_path, row_impact, row_time, row_context, row_promotion,
        row_honesty)


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
    q = modules["q"]
    bom = _bom(modules)
    required = ["ML-KEM-768", "ML-DSA-65"]
    event = {"kind": "TLS_DOWNGRADE", "asset": "payments.bank.example:443",
             "before": "TLSv1.3", "after": "TLSv1.2", "evidence_ids": ["EVD-EVT-1"],
             "observed_at": "2026-11-03T02:00:00Z"}
    series = [_bom(modules, openssl="3.0.13"), _bom(modules, openssl="3.0.11"),
              _bom(modules, openssl="3.0.11", certificate="CERT-9821")]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "bom": bom,
        "rollup": q.rollup(bom),
        "path": q.path(bom, source="payments.bank.example:443", target="Payments API"),
        "impact": q.impact(bom, query="AES-256-GCM", required_algorithms=required,
                           deadline="2027-01-01"),
        "declared_impact": q.impact(bom, query="RSA-2048"),
        "timeline": q.timeline(series),
        "context": q.threat_context(bom, event),
        "promotion": q.verify(
            next(row for row in bom["claims"]
                 if row["confidence"] == "IMPORTED"
                 and row["relation"] == "USES_CRYPTO"),
            basis="runtime-probe", evidence_ids=["EVD-PROBE-9"],
            at="2026-11-03T03:00:00Z"),
        "rows": rows,
        "limits": [
            "the estate is a fixture, not a bank: every asset and edge here is the shape "
            "of the argument, and none of it is an observation of a real network",
            "a roll-up is the system the graph proves, not the system on the org chart: an "
            "asset nobody connected belongs to no system here",
            "a request path is a path a source asserted. Load balancers route by rules "
            "this model does not read, and an unrecorded route is missing, not absent",
            "an impact count is exposure, not breakage, and a blocker is what the model "
            "can see on the path: a vendor roadmap is not on the path",
            "a timeline samples states. What happened between two snapshots is not in "
            "either of them",
            "a threat context is the estate an event happened to. It is not a causal "
            "chain, and a downgrade is more often a client than an attacker",
            "promotion changes a claim's class on new evidence; it does not re-derive the "
            "graph, so a promoted edge is a new claim and the old one stays in history",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    bom = report["bom"]
    rollup = report["rollup"]["systems"][0]
    route = report["path"]["paths"][0]
    impact = report["impact"]
    declared = report["declared_impact"]
    timeline = report["timeline"]
    context = report["context"]
    promotion = report["promotion"]
    lines = [
        "# The questions a TechBOM has to answer",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 164 built the graph and its guard rails. This guide asks the graph the",
        "questions an estate actually asks, and holds each answer to the same rules:",
        "proven edges only, declared edges reported separately, and a refusal instead of",
        "a guess.",
        "",
        "```",
        "roll-up     business system → technology counted by kind (proven / declared)",
        "path        endpoint → WAF → LB → gateway → mesh → application → database",
        "impact      who breaks, what has to change, and which sites block a migration",
        "timeline    snapshots → typed changes, because one snapshot is not a series",
        "context     live event → CORRELATED_PATTERN with the estate behind it",
        "promotion   IMPORTED → OBSERVED on new evidence, with the old class kept",
        "```",
        "",
        f"**{rollup['statement']}**",
        "",
        "| kind | proven | declared only |",
        "|---|---|---|",
    ]
    for kind in sorted({**rollup["counts"], **rollup["declared_only"]}):
        lines.append(f"| `{kind}` | {rollup['counts'].get(kind, 0)} | "
                     f"{rollup['declared_only'].get(kind, 0)} |")
    lines += [
        "",
        f"**Request path**: {route['statement']}",
        "",
        "| hop | role | evidence | crypto | certificate |",
        "|---|---|---|---|---|",
    ]
    for hop in route["hops"]:
        crypto = ", ".join(f"{name}={value}" for name, value in hop["crypto"].items())
        lines.append(f"| `{hop['name']}` | {hop['role']} | {hop['evidence'] or 'START'} | "
                     f"{crypto or '**NOT_RECORDED**'} | {hop['certificate'] or '—'} |")
    lines += [
        "",
        f"**Impact** — {impact['statement']}",
        "",
        f"Migration sites: {', '.join(impact['migration_sites']) or 'none'}",
        "",
        "| blocker | count | who acts |",
        "|---|---|---|",
    ]
    for code, count in impact["blocker_counts"].items():
        who = next(row["who_acts"] for row in impact["pqc_blockers"]
                   if row["code"] == code)
        lines.append(f"| `{code}` | {count} | {who} |")
    lines += [
        "",
        f"*Declared, not counted* — {declared['statement']} "
        f"({len(declared['declared_only'])} asset(s) stay declared)",
        "",
        f"**Timeline** — {timeline['statement']}",
        "",
        f"**Context** — {context['statement']}",
        "",
        f"**Promotion** — {promotion['statement']}",
        "",
        f"Fixture: {bom['statement']}",
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
