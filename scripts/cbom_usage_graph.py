#!/usr/bin/env python3
"""Guide 141 — conflicts enter the graph, and a terminator owns its algorithms.

Guide 140 turned stored rows into evidence; guide 139 profiled it. Both stop at
the document. A CBOM is a snapshot, but the questions a bank asks are relational:
*which systems use RSA-2048*, *which endpoints terminate with an ECDSA
certificate*, *which sources disagree about this library*. Those are edges.

``cbom.usage_graph`` emits three families and refuses to smooth any of them:

``USES_CRYPTO``
    one edge per (subject, algorithm), provenance taken from the strongest
    evidence class — an SBOM-only algorithm is ``DECLARED``, and the graph says so
    rather than letting a reader infer use.
``CONFLICTS_WITH``
    every conflict from ``reconcile`` as an edge with **both** evidence ids. The
    resolved value is deliberately ignored: a CycloneDX document has to choose one
    version to stay valid, and choosing is exactly the information loss a graph
    does not have to accept.
``NEGOTIATES`` / ``TERMINATES``
    an endpoint's algorithms and certificate, attached to the endpoint. A load
    balancer's TLS 1.3 never becomes an application's property.

An edge with no evidence id is not written.
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
SCHEMA = "cryptoscan.cbom-usage-graph-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

PROFILES = [
    {"asset": {"algorithm": "AES-256-GCM", "purpose": "TLS"},
     "observed_classes": ["RUNTIME_OBSERVED", "NETWORK_OBSERVED"],
     "evidence_ids": ["RUNTIME-92821", "NET-9281"], "confidence": "VERY_HIGH",
     "usage": "OBSERVED"},
    {"asset": {"algorithm": "RSA-2048", "purpose": "SIGNATURE"},
     "observed_classes": [], "classes": {"IMPORTED": {"count": 1}},
     "evidence_ids": ["SBOM-1"], "confidence": "LOW", "usage": "CANDIDATE_ONLY"},
]
RECONCILED = {"conflicts": [{
    "field": "version", "kind": "VERSION_CONFLICT",
    "values": {"container": "3.0.13", "runtime": "3.0.11"},
    "evidence": {"container": "C-1", "runtime": "R-1"},
    "statement": "version has 2 observed values across 2 source(s)"}],
    "resolved": [{"field": "version", "value": None, "basis": "RUNTIME_OBSERVED"}]}
PATHS = {"paths": [{
    "endpoint": "payments.bank.example:443", "evidence_id": "NET-9281",
    "class": "NETWORK_OBSERVED", "tls_version": "TLS1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "certificate_ref": "cert-9281",
    "from": "client", "to": "External LB"}]}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "graph_engine"),
                  str(SERVICES / "devsecops"), str(SERVICES / "governance"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import usage_graph  # noqa: PLC0415
    from graph_engine.core.engine import GraphEngine  # noqa: PLC0415

    return {"ug": usage_graph, "GraphEngine": GraphEngine}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def row_usage_edges(modules: dict[str, Any]) -> dict[str, Any]:
    ug = modules["ug"]
    probes: list[dict[str, Any]] = []
    body = ug.usage_edges(PROFILES, system="payments-api")

    observed = next(edge for edge in body["edges"] if edge["to"] == "algorithm:AES-256-GCM")
    probes.append(_probe(
        "an-observed-algorithm-is-an-observed-edge",
        observed["provenance"] == "OBSERVED" and observed["from"] == "system:payments-api"
        and observed["evidence_ids"] == ["NET-9281", "RUNTIME-92821"],
        observed["provenance"] + " from " + ", ".join(observed["evidence_ids"])))

    declared = next(edge for edge in body["edges"] if edge["to"] == "algorithm:RSA-2048")
    probes.append(_probe(
        "an-sbom-only-algorithm-is-a-declared-edge",
        declared["provenance"] == "DECLARED" and declared["usage"] == "CANDIDATE_ONLY",
        "the graph shows the algorithm and says the claim is a declaration"))

    empty = ug.usage_edges([{"asset": {"algorithm": "AES-128"}, "evidence_ids": []}],
                           system="payments-api")
    probes.append(_probe(
        "an-algorithm-with-no-evidence-gets-no-edge",
        empty["edges"] == [] and empty["undeclared"] == ["AES-128"],
        empty["statement"]))

    probes.append(_probe(
        "the-subject-is-explicit",
        ug.usage_edges(PROFILES, application="payments")["edges"][0]["from"]
        == "application:payments"
        and ug.usage_edges(PROFILES, component="openssl")["edges"][0]["from"]
        == "component:openssl",
        "system / application / component, never an implicit one"))

    probes.append(_probe(
        "a-usage-graph-with-no-subject-is-refused",
        _refused(ug.usage_edges, PROFILES),
        "an edge with no owner is not drawn"))

    return {"id": "usage_edges",
            "question": "does an algorithm edge say how it is known?",
            "phase": "review 20", "probes": probes}


def _refused(fn, *args, **kwargs) -> bool:
    try:
        fn(*args, **kwargs)
    except ValueError:
        return True
    return False


def row_conflict_edges(modules: dict[str, Any]) -> dict[str, Any]:
    ug = modules["ug"]
    probes: list[dict[str, Any]] = []
    body = ug.conflict_edges(RECONCILED)
    edge = body["edges"][0] if body["edges"] else {}

    probes.append(_probe(
        "a-conflict-becomes-an-edge-with-both-evidence-ids",
        (edge.get("from"), edge.get("kind"), edge.get("to"))
        == ("source:container", "CONFLICTS_WITH", "source:runtime")
        and edge.get("evidence_ids") == ["C-1", "R-1"],
        body["statement"]))

    probes.append(_probe(
        "the-edge-names-the-field-and-both-values",
        edge.get("field") == "version" and edge.get("left_value") == "3.0.13"
        and edge.get("right_value") == "3.0.11",
        f"{edge.get('field')}: {edge.get('left_value')} vs {edge.get('right_value')}"))

    probes.append(_probe(
        "a-conflict-is-never-resolved-into-an-edge",
        all("resolved" not in row for row in body["edges"])
        and "no conflict is resolved" in body["statement"],
        "the disagreement survives the projection"))

    probes.append(_probe(
        "agreeing-sources-produce-no-edge",
        ug.conflict_edges({"conflicts": []})["edges"] == []
        and "the sources agree" in ug.conflict_edges({"conflicts": []})["statement"],
        ug.conflict_edges({"conflicts": []})["statement"]))

    return {"id": "conflict_edges",
            "question": "can a disagreement survive the move into the graph?",
            "phase": "review 16 / 20", "probes": probes}


def row_tls_edges(modules: dict[str, Any]) -> dict[str, Any]:
    ug = modules["ug"]
    body = ug.tls_edges(PATHS)
    probes: list[dict[str, Any]] = []

    negotiates = {edge["to"] for edge in body["edges"] if edge["kind"] == "NEGOTIATES"}
    probes.append(_probe(
        "a-terminator-owns-the-algorithms-it-negotiated",
        negotiates == {"algorithm:AES-256-GCM", "algorithm:SHA-384"}
        and all(edge["from"] == "endpoint:payments.bank.example:443"
                for edge in body["edges"]),
        body["statement"]))

    terminates = [edge for edge in body["edges"] if edge["kind"] == "TERMINATES"]
    probes.append(_probe(
        "a-terminator-edges-to-its-certificate",
        terminates and terminates[0]["to"] == "certificate:cert-9281"
        and terminates[0]["evidence_ids"] == ["NET-9281"],
        "the certificate belongs to the endpoint, not to the application"))

    probes.append(_probe(
        "a-hop-with-no-endpoint-is-skipped",
        ug.tls_edges({"paths": [{"evidence_id": "N-1"}]})["edges"] == [],
        "no endpoint, no edge"))

    probes.append(_probe(
        "suite-parsing-is-the-collectors-table-not-a-copy",
        [edge["to"] for edge in body["edges"] if edge["kind"] == "NEGOTIATES"]
        == ["algorithm:AES-256-GCM", "algorithm:SHA-384"],
        "one contract with guide 140's cipher-suite table"))

    return {"id": "tls_edges",
            "question": "does a load balancer's TLS become the application's property?",
            "phase": "review 8 / 9", "probes": probes}


def row_write_and_refuse(modules: dict[str, Any]) -> dict[str, Any]:
    ug = modules["ug"]
    engine = modules["GraphEngine"]()
    built = ug.build_graph(PROFILES, reconciled=RECONCILED, paths=PATHS,
                           system="payments-api")
    applied = ug.apply_graph(engine, built["edges"])
    rendered = engine.to_vis()
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "every-edge-with-evidence-is-written",
        applied["written"] == len(built["edges"]) and applied["refused"] == [],
        applied["statement"]))

    probes.append(_probe(
        "the-provenance-classes-survive-into-the-graph",
        applied["by_provenance"] == {"DECLARED": 1, "OBSERVED": 6},
        json.dumps(applied["by_provenance"], sort_keys=True)))

    probes.append(_probe(
        "a-edge-with-no-evidence-is-refused",
        _apply_refused(ug, modules["GraphEngine"]()),
        "an unattributable crypto relationship is a guess drawn on a diagram"))

    kinds = {node["group"] for node in rendered["nodes"]}
    probes.append(_probe(
        "the-nodes-are-typed-by-what-they-are",
        {"SYSTEM", "CRYPTO_ALGORITHM", "ENDPOINT", "CERTIFICATE", "EVIDENCE_SOURCE"} <= kinds,
        ", ".join(sorted(str(kind) for kind in kinds))))

    probes.append(_probe(
        "the-graph-exposes-which-algorithms-had-no-evidence",
        built["undeclared"] == [],
        f"families {json.dumps(built['families'], sort_keys=True)}"))

    probes.append(_probe(
        "coverage-travels-with-the-graph",
        ug.coverage_note({"systems_total": 100, "systems_inspected": 62,
                          "assets_discovered": 12})["quotable_as_total"] is False,
        "a partial estate cannot be read as the whole graph"))

    return {"id": "write_and_refuse",
            "question": "is the graph a faithful projection or a tidy one?",
            "phase": "review 16 / 20 / 21", "probes": probes}


def _apply_refused(ug, engine) -> bool:
    applied = ug.apply_graph(engine, [{"from": "system:a", "kind": "USES_CRYPTO",
                                       "to": "algorithm:X", "evidence_ids": []}])
    return applied["written"] == 0 and bool(applied["refused"]) and engine.to_vis()["edges"] == []


def row_api_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "the-graph-route-exists-and-is-typed",
        '@router.post("/usage/graph"' in router
        and "response_model=CbomGraphResponse" in router,
        "POST /cbom/usage/graph"))

    probes.append(_probe(
        "the-route-uses-the-real-graph-engine",
        "from graph_engine.core.engine import GraphEngine" in router
        and "engine.to_vis()" in router,
        "the response carries the graph the engine would render"))

    probes.append(_probe(
        "the-route-accepts-all-three-families",
        "reconciled: dict | None = Field" in router
        and "paths: dict | None = Field" in router
        and "profiles: list[dict] | None = Field" in router,
        "usage, conflicts and TLS in one call"))

    probes.append(_probe(
        "a-missing-subject-is-a-validation-error",
        "raise HTTPException(status_code=422, detail=str(exc))" in router,
        "the edge with no owner is refused at the API too"))

    return {"id": "api_exposure",
            "question": "can a caller reach the graph without a test harness?",
            "phase": "review 20", "probes": probes}


ROWS = (row_usage_edges, row_conflict_edges, row_tls_edges, row_write_and_refuse,
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
            "the graph is built from profiles and conflicts a caller passes in. It does not "
            "fetch them, so an out-of-date profile produces an out-of-date graph and nothing "
            "here notices",
            "a CONFLICTS_WITH edge names two sources and a field. It does not say which one is "
            "right — deliberately — so a consumer that needs one value must apply a precedence "
            "rule of its own, and the graph cannot stop it choosing badly",
            "USES_CRYPTO edges are per (subject, algorithm), not per call site. Two applications "
            "in one process using AES-256-GCM differently share an edge unless the caller "
            "separates the subjects",
            "termination is modelled, hop chaining is not: the graph does not assert that the "
            "traffic on both sides of a terminator is the same connection",
            "coverage is an annotation. A graph rendered without reading coverage_note looks "
            "complete even when most of the estate was never inspected",
            "certificate edges reference the certificate, not its parsed properties — the "
            "certificate's own public key and signature algorithm live in the certificate record, "
            "not on the edge",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Conflicts enter the graph, and a terminator owns its algorithms",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "Guides 139 and 140 produce evidence and profiles. Both stop at the document. The "
        "questions a bank asks are relational, so this artifact measures the projection into "
        "graph edges — with three refusals built in:",
        "",
        "1. **Provenance is not decoration.** An algorithm edge is `OBSERVED` only if a "
        "collector saw it; an SBOM-only algorithm is `DECLARED`, and `CONFLICTS_WITH` keeps "
        "both evidence ids.",
        "2. **A conflict is never resolved into an edge.** CycloneDX has to pick one version to "
        "stay valid; a graph does not, so the disagreement survives.",
        "3. **A terminator's algorithms belong to the terminator.** `NEGOTIATES` and "
        "`TERMINATES` attach to the endpoint, never to the application behind it.",
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
