#!/usr/bin/env python3
"""Guide 144 — PQC readiness is not the CBOM, and a boolean is not a status.

The review's items 14 and 15. ``quantumVulnerable: true|false|null`` fails three
ways: it says ``false`` for AES-256 without noting Grover, it cannot express
hybrid or transitional states, and it puts a *decision* in a document that only
observed an *algorithm*.

``cbom.pqc_handoff`` is the seam. The document carries the status (a namespaced
property with its basis); the PQC engine carries the migration decision.
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
SCHEMA = "cryptoscan.cbom-pqc-handoff-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "governance"), str(SERVICES / "quantum"),
                  str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import pqc_handoff  # noqa: PLC0415

    return {"pq": pqc_handoff}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _one(pq, algorithm: str, **asset: Any) -> dict[str, Any]:
    return pq.handoff([{"algorithm": algorithm, **asset}])["rows"][0]


def row_status_vocabulary(modules: dict[str, Any]) -> dict[str, Any]:
    pq = modules["pq"]
    probes = [
        _probe("a-shor-vulnerable-key-is-quantum-sensitive",
               _one(pq, "RSA-2048", key_size=2048, purpose="TLS")["quantum_status"]
               == "QUANTUM_SENSITIVE",
               "RSA-2048: Shor breaks it, no boolean needed"),
        _probe("grover-impact-depends-on-size",
               _one(pq, "AES-128-GCM", key_size=128)["quantum_status"] == "TRANSITIONAL"
               and _one(pq, "AES-256-GCM", key_size=256)["quantum_status"] == "CLASSICAL_ONLY",
               "AES-128 is Grover-weakened; AES-256 keeps >=128 bits and is acceptable"),
        _probe("a-pqc-algorithm-is-resistant-and-a-hybrid-is-hybrid",
               _one(pq, "ML-KEM-768")["quantum_status"] == "QUANTUM_RESISTANT"
               and _one(pq, "X25519MLKEM768")["quantum_status"] == "HYBRID",
               "resistant and hybrid are different answers"),
        _probe("an-unregistered-algorithm-is-unknown-not-resistant",
               _one(pq, "ACME-CIPHER-9")["quantum_status"] == "UNKNOWN"
               and _one(pq, "ACME-CIPHER-9")["requires_review"] is True,
               "resistance is never assumed from silence"),
        _probe("no-algorithm-is-not-assessed",
               pq.quantum_status(None)["status"] == "NOT_ASSESSED",
               "an asset with no algorithm produces no quantum claim"),
        _probe("classical-breakage-is-named-on-the-same-row",
               _one(pq, "3DES")["classically_broken"] is True
               and _one(pq, "3DES")["quantum_risk"] == "CRITICAL",
               "a quantum status never hides a classical purge"),
    ]
    return {"id": "status_vocabulary",
            "question": "can a status say what a boolean could not?",
            "phase": "review 15", "probes": probes}


def row_priority_from_evidence(modules: dict[str, Any]) -> dict[str, Any]:
    pq = modules["pq"]
    capability = _one(pq, "AES-128-GCM", key_size=128, usage="CAPABILITY")
    observed = _one(pq, "AES-128-GCM", key_size=128, usage="RUNTIME")
    probes = [
        _probe("a-deployed-algorithm-outranks-a-capability",
               (capability["migration_priority"], observed["migration_priority"])
               == ("MEDIUM", "HIGH")
               and observed["priority_escalated_by"] == ["OBSERVED_USAGE:RUNTIME"],
               f"capability {capability['migration_priority']} vs runtime "
               f"{observed['migration_priority']}"),
        _probe("confidentiality-use-of-a-shor-vulnerable-key-is-immediate",
               _one(pq, "ECDH-P256", purpose="KEY_EXCHANGE")["migration_priority"] == "IMMEDIATE",
               "harvest-now-decrypt-later does not improve with waiting"),
        _probe("signature-use-is-not-an-hndl-escalation",
               "HNDL_CONFIDENTIALITY_PURPOSE"
               not in _one(pq, "ECDSA-P256", purpose="SIGNATURE")["priority_escalated_by"],
               "authenticity migration is a different register"),
        _probe("evidence-only-ever-escalates",
               [row["migration_priority"] for row in pq.handoff([
                   {"algorithm": "RSA-2048", "purpose": "TLS", "usage": "CAPABILITY"},
                   {"algorithm": "RSA-2048", "purpose": "TLS", "usage": "VERIFIED"},
               ])["rows"]] == ["IMMEDIATE", "IMMEDIATE"],
               "nothing in the handoff lowers a finding"),
        _probe("a-resistance-claim-needs-no-migration",
               _one(pq, "ML-KEM-768")["migration_priority"] == "NONE"
               and _one(pq, "ML-KEM-768")["recommended_replacement"] is None,
               "no work is invented for an algorithm already on the target"),
        _probe("the-replacement-is-specific-to-the-family",
               _one(pq, "RSA-2048", purpose="TLS")["recommended_replacement"] == "ML-KEM-768"
               and _one(pq, "SHA-1")["recommended_replacement"] == "SHA-256"
               and _one(pq, "AES-128-GCM")["recommended_replacement"] == "AES-256",
               "a hash is not replaced by a cipher, and AES-128 by AES-256"),
    ]
    return {"id": "priority_from_evidence",
            "question": "does migration priority follow risk and usage, not size of inventory?",
            "phase": "review 14 / 15", "probes": probes}


def row_the_seam(modules: dict[str, Any]) -> dict[str, Any]:
    pq = modules["pq"]
    props = {row["name"]: row["value"] for row in pq.component_properties("RSA-2048", 2048)}
    document = {"components": [
        {"bom-ref": "crypto/RSA-2048", "name": "RSA-2048",
         "cryptoProperties": {"algorithmProperties": {"algorithm": "RSA-2048"}}},
        {"bom-ref": "crypto/AES-256-GCM", "name": "AES-256-GCM",
         "cryptoProperties": {"algorithmProperties": {"algorithm": "AES-256-GCM"}},
         "properties": [{"name": "cryptoscan:usage", "value": "RUNTIME"}]},
    ]}
    body = pq.handoff_from_cbom(document)
    probes = [
        _probe("the-document-carries-a-status-with-its-basis",
               props["cryptoscan:quantum_status"] == "QUANTUM_SENSITIVE"
               and props["cryptoscan:quantum_status_basis"] == "REGISTRY_SHOR",
               json.dumps(props, sort_keys=True)),
        _probe("the-document-does-not-carry-the-boolean",
               "quantumVulnerable" not in props,
               "the non-standard field is gone from the standard block"),
        _probe("a-document-without-usage-properties-is-unobserved",
               {row["algorithm"]: row["usage"] for row in body["rows"]}["RSA-2048"] is None,
               "a plain CycloneDX CBOM says nothing about deployment"),
        _probe("usage-properties-reach-the-handoff",
               {row["algorithm"]: row["migration_priority"] for row in body["rows"]}
               ["AES-256-GCM"] == "NONE",
               "AES-256 observed in use still needs no PQC migration"),
        _probe("old-documents-are-read-not-ignored",
               pq.status_from_component({"cryptoProperties": {"quantumVulnerable": True}})
               == "QUANTUM_SENSITIVE",
               "a pre-guide-144 document still yields a status"),
        _probe("a-boolean-is-only-derived-where-it-is-defensible",
               pq.vulnerable_from_status("TRANSITIONAL") is None
               and pq.vulnerable_from_status("CLASSICAL_ONLY") is False,
               "Grover-weakened is not silently 'safe'"),
    ]
    return {"id": "the_seam",
            "question": "does the document inventory while the engine decides?",
            "phase": "review 14", "probes": probes}


def row_conformance(modules: dict[str, Any]) -> dict[str, Any]:
    generator = (SERVICES / "cbom" / "cbom" / "generator.py").read_text(encoding="utf-8")
    registry = (SERVICES / "cbom" / "cbom" / "component_registry.py").read_text(encoding="utf-8")
    exporter = (SERVICES / "api" / "api" / "routers" / "export.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-xml-serializer-no-longer-writes-the-boolean",
               '"quantumVulnerable"' not in generator,
               "CycloneDX 1.5 XML has no quantumVulnerable element"),
        _probe("the-1-5-json-builders-no-longer-write-it-either",
               'pqc_handoff.component_properties' in registry
               and 'pqc_handoff.component_properties' in exporter
               and '"quantumVulnerable": normalized.get("quantum_vulnerable")'
               not in registry
               and '"quantumVulnerable": normalized.get("quantum_vulnerable")' not in exporter,
               "both 1.5 component builders emit namespaced properties instead"),
        _probe("the-readers-resolve-both-generations",
               "pqc_handoff.vulnerable_from_component" in
               (SERVICES / "cbom" / "cbom" / "inventory.py").read_text(encoding="utf-8")
               and "pqc_handoff.vulnerable_from_component" in
               (SERVICES / "cbom" / "cbom" / "assessment.py").read_text(encoding="utf-8"),
               "ingest and assessment do not depend on the field that was removed"),
    ]
    return {"id": "conformance",
            "question": "is the change a schema fix, not only a vocabulary change?",
            "phase": "review 15", "probes": probes}


def row_api_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-handoff-route-exists-and-is-typed",
               '@router.post("/pqc-handoff"' in router
               and "response_model=CbomPqcHandoffResponse" in router,
               "POST /cbom/pqc-handoff"),
        _probe("the-route-is-role-gated",
               "require_roles(*CBOM_USAGE_READERS)" in
               router.split("def cbom_pqc_handoff", 1)[1],
               "a migration register is not anonymous"),
        _probe("the-route-uses-the-module-and-accepts-a-document",
               "from cbom import pqc_handoff as pq" in router
               and "pq.handoff_from_cbom(body.document" in router,
               "one implementation, usable straight from an uploaded CBOM"),
    ]
    return {"id": "api_exposure",
            "question": "can an operator ask what needs migrating, and why?",
            "phase": "review 14", "probes": probes}


ROWS = (row_status_vocabulary, row_priority_from_evidence, row_the_seam, row_conformance,
        row_api_exposure)


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
            "status is classified from the algorithm registry, not from the deployment. A "
            "protocol negotiated with a PQC suite still reads as the suite it names, so "
            "'the bank is hybrid on this TLS endpoint' needs the network evidence, not this "
            "module",
            "priority is a planning order, not a deadline. The platform's regulatory dates "
            "live in the quantum and banking registers; nothing here asserts one",
            "migration_status is caller-supplied and defaults to NOT_STARTED. The platform "
            "does not yet observe remediation, so a migrated asset keeps saying NOT_STARTED "
            "until an operator records it",
            "a hybrid asset is NONE priority because its classical half is covered by the "
            "PQC half. That is right for the negotiation and wrong for the component that "
            "still implements only X25519, which this seam cannot see",
            "the recommended replacement is the engine's answer for the algorithm family, "
            "not for this deployment: ML-KEM-768 may be unavailable in the HSM that holds "
            "the key, and that blocker is not modelled here",
            "the 1.6 path already refused quantumVulnerable; the 1.5 builders and the XML "
            "serializer were the ones that wrote it, and third-party documents may still "
            "carry it — the readers accept it, but its presence is a schema finding, not a "
            "credential of quality",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# PQC readiness is not the CBOM, and a boolean is not a status",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's items 14 and 15. The CBOM chain the review asks for is:",
        "",
        "```",
        "CBOM (what cryptography exists)",
        "  -> crypto inventory",
        "  -> PQC engine (what needs migration, what depends on it, what blocks it)",
        "  -> migration assessment",
        "```",
        "",
        "`quantumVulnerable: null` was the honest part of the old model — it refused to "
        "conclude. What it could never do was say **why**, or say *transitional*, or *hybrid*. "
        "`cbom.pqc_handoff` replaces it with the review's vocabulary:",
        "",
        "| Status | Means |",
        "|---|---|",
        "| `NOT_ASSESSED` | no algorithm identity; no quantum claim |",
        "| `CLASSICAL_ONLY` | no known quantum break, and not PQC |",
        "| `TRANSITIONAL` | Grover weakens the margin (AES-128, SHA-256) |",
        "| `QUANTUM_RESISTANT` | registry-recognised PQC |",
        "| `HYBRID` | classical + PQC in one construction |",
        "| `QUANTUM_SENSITIVE` | Shor breaks it |",
        "| `UNKNOWN` | unrecognised algorithm; review required |",
        "",
        "and keeps `algorithm_class`, `quantum_risk`, `migration_priority` and "
        "`migration_status` as separate fields, each with the basis that produced it.",
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
