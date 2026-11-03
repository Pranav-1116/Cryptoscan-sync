#!/usr/bin/env python3
"""Guide 174 — the chain, closed: evidence per edge, domains, the terminal hop, PQC readiness.

Guide 173 built the chain and read all twenty-six points off it. This guide asks the six
questions the review makes *underneath* those points, the ones a chain alone does not
answer:

1. **the edge's record.** The review names nine fields every relationship should carry —
   ``evidence_id``, ``evidence_type``, ``source``, ``collector``, ``collector_version``,
   ``observed_at``, ``confidence``, ``first_seen``, ``last_seen``. An audit that counts ten
   fields and never looks at the collector is not auditing the list the review wrote.
2. **the SBOM join.** A capability listed by an SBOM is a question. It becomes a CBOM fact
   only when a collector corroborates it, and the guide reports, per capability, which
   class of evidence stands behind it.
3. **the domains.** Application, platform, certificate and network crypto are four sets.
   They may share an algorithm and must never be summed: the certificate's ECDSA is the
   listener's dependency, not the application's usage.
4. **the terminal hop.** A transport path ends at a workload. What that workload does is
   another edge — ``application → HSM (RSA signing)`` — and it has to stay a hop with its
   own parameters rather than an attribute of the listener.
5. **the PQC answer.** "The firmware cannot do ML-KEM" is a claim about the firmware's own
   capability list, and a device that never published one is ``UNKNOWN``, not ``READY``.
6. **the assembled graph.** One projection, the families it reaches, no second store.

The estate is guide 173's, extended by two capability lists and a certificate chain, so
every number below is read off a build rather than asserted next to one.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-chain-closure/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

#: the nine fields the review lists, in the review's order.
REVIEW_FIELDS = ("evidence_id", "evidence_type", "source", "collector", "collector_version",
                 "observed_at", "confidence", "first_seen", "last_seen")

EVID = "EVID-95001"
EVID_REL = "EVID-95002"
EVID_K8S = "EVID-95003"
EVID_RT = "EVID-95004"
EVID_STATIC = "EVID-95005"
EVID_HSM = "EVID-95006"
EVID_NET = "EVID-95007"
EVID_VENDOR = "EVID-95008"
NOW = "2026-11-03T08:30:00Z"


def _chain() -> Any:
    """Guide 173's harness, imported so this guide reads the same estate it built."""
    path = ROOT / "scripts" / "cbom_dependency_chain.py"
    spec = importlib.util.spec_from_file_location("cbom_dependency_chain", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a missing file, not a case
        raise SystemExit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The estate: guide 173's, with two capability lists and a certificate chain
# --------------------------------------------------------------------------- #

def _build(modules: dict[str, Any]) -> dict[str, Any]:
    chain = _chain()
    document = chain._document(modules, rsa_size=2048, kms_basis="api-poll",
                              legacy_library=True)
    estate = document["estate"]
    d, n, t = modules["d"], modules["n"], modules["t"]
    rows = {row["name"]: row for row in estate["assets"]}

    # the certificate's own crypto: a public key, its algorithm, and the CA that signed it
    public_key = t.asset("PUBLIC_KEY", "PUB-001", evidence_ids=[EVID_NET], key_size=256,
                         curve="P-256")
    issuer = n.authority(name="Bank Issuing CA", evidence_ids=[EVID_NET])
    certificate_chain = n.certificate_chain(
        certificate_row=rows["CERT-001"], key_row=public_key,
        key_algorithm_row=rows["ECDSA-P256"], signature_algorithm_row=rows["ECDSA-P256"],
        issuer_row=issuer, basis="packet-capture", evidence_ids=[EVID_NET])

    # two devices publish a capability list and one of them publishes a PQC algorithm:
    # that difference is the whole of point 5, and it has to be in the estate, not in a
    # comparison written into the probe
    mlkem = n.algorithm(name="ML-KEM-768", family="ML-KEM", key_size=768,
                        evidence_ids=[EVID_VENDOR])
    hsm_capability = d.capability(provider_row=rows["HSM-001"], algorithm_row=mlkem,
                                  basis="vendor-datasheet", evidence_ids=[EVID_VENDOR])
    firmware_capability = d.capability(provider_row=rows["BIG-IP 17.1.1"],
                                       algorithm_row=rows["AES-256-GCM"],
                                       basis="capability-list", evidence_ids=[EVID_VENDOR])

    # the load balancer's own certificate is RSA-2048, and that is the same algorithm the
    # application signs with: one algorithm, two domains, and the report has to say so
    # instead of adding them up
    lb_key = t.asset("PUBLIC_KEY", "PUB-002", evidence_ids=[EVID_NET], key_size=2048)
    lb_certificate = n.certificate(name="CERT-002", subject="CN=lb-01", issuer="Bank Issuing CA",
                                   serial="7a:11:c4", signature_algorithm="RSA-SHA256",
                                   evidence_ids=[EVID_NET])
    lb_chain = n.certificate_chain(
        certificate_row=lb_certificate, key_row=lb_key,
        key_algorithm_row=rows["RSA-2048"], signature_algorithm_row=rows["RSA-2048"],
        issuer_row=issuer, basis="packet-capture", evidence_ids=[EVID_NET])
    presented = n.part(claims=[
        t.claim("lb-01:443", "PRESENTS", "CERT-002", basis="tls-handshake",
                evidence_ids=[EVID_NET])])

    merged = n.merge(certificate_chain, lb_chain, presented, hsm_capability,
                     firmware_capability)
    extended = {
        **estate,
        "assets": [*estate["assets"], *merged["assets"]],
        "claims": [*estate["claims"], *merged["claims"]],
    }
    bom = t.build(extended)
    return {"bom": bom, "names": document["names"],
            "rows": rows, "public_key": public_key["name"]}


# --------------------------------------------------------------------------- #
# The six questions
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _chain()._load()
    d = modules["d"]
    built = _build(modules)
    bom, names = built["bom"], built["names"]
    points: list[dict[str, Any]] = []

    def add(point: int, question: str, probes: list[dict[str, Any]]) -> None:
        points.append({"point": point, "question": question, "probes": probes,
                       "ok": all(probe["ok"] for probe in probes)})

    # ---- 1. the edge's record -------------------------------------------------
    audit = d.evidence_audit(bom)
    missing = [field for field in REVIEW_FIELDS if field not in d.EDGE_FIELDS]
    collected = audit["field_coverage"].get("collector", 0)
    shortfall = [text for text in audit["missing_fields"] if "collector" in text]
    add(1, "every dependency edge carries the fields the review names, the collector included",
        [
            _probe("the-review-fields-are-all-declared", not missing,
                   f"{len(REVIEW_FIELDS)} review field(s), "
                   f"{len(d.EDGE_FIELDS)} audited; missing {missing or 'none'}"),
            _probe("the-collector-is-counted-not-assumed", collected > 0
                   and audit["with_collector"] == collected,
                   f"collector on {collected}/{audit['count']} edge(s), "
                   f"collector_version on "
                   f"{audit['field_coverage'].get('collector_version', 0)}/{audit['count']}"),
            _probe("a-field-nobody-supplied-is-a-shortfall", bool(shortfall),
                   f"shortfalls {shortfall or 'none'}; "
                   f"{audit['fully_recorded']}/{audit['count']} carry all "
                   f"{len(d.EDGE_FIELDS)}"),
        ])

    # ---- 2. the SBOM join -----------------------------------------------------
    evidence = d.capability_evidence(bom, query=names["provider"])
    verdicts = evidence["counts"]
    without_class = [row["capability"] for row in evidence["rows"] if not row["classes"]]
    listed = [row["capability"] for row in evidence["rows"] if row["verdict"] == "LISTED_ONLY"]
    corroborated = evidence["corroborated"]
    add(2, "a capability listed by a source is a question, and only an evidence class answers it",
        [
            _probe("a-verdict-and-its-classes-agree",
                   all((row["verdict"] == "LISTED_ONLY") == (not row["classes"])
                       for row in evidence["rows"]),
                   f"{evidence['count']} capability(ies), verdicts {verdicts}; "
                   f"listed with no class: {without_class or 'none'}"),
            _probe("a-listed-and-unused-capability-stays-listed", bool(listed)
                   and not set(listed) & set(corroborated),
                   f"listed only {listed}; corroborated {corroborated or 'none'}"),
            _probe("the-usage-that-was-never-listed-is-still-reported",
                   bool(evidence["used_not_listed"]),
                   f"used but not listed: {evidence['used_not_listed']}"),
        ])

    # ---- 3. the domains -------------------------------------------------------
    domains = d.crypto_domains(bom)
    app = domains["domains"]["APPLICATION"]["algorithms"]
    cert = domains["domains"]["CERTIFICATE"]["algorithms"]
    network = domains["domains"]["NETWORK"]["algorithms"]
    overlaps = domains["shared_algorithms"]
    naive = len(app) + len(cert) + len(network)
    union = len(set(app) | set(cert) | set(network))
    add(3, "application, certificate, network and platform crypto are counted apart",
        [
            _probe("the-four-domains-exist", set(domains["domains"]) == {
                "APPLICATION", "PLATFORM", "CERTIFICATE", "NETWORK"},
                f"domains {sorted(domains['domains'])}, "
                f"nodes {[row['nodes'] for row in domains['domains'].values()]}"),
            _probe("a-certificate-algorithm-is-not-an-application-use",
                   "ECDSA-P256" in cert and "ECDSA-P256" not in app
                   and "RSA-2048" in app,
                   f"certificate {cert}, application {app}"),
            _probe("an-overlap-is-reported-and-never-summed",
                   overlaps.get("APPLICATION+CERTIFICATE") == ["RSA-2048"] and naive > union,
                   f"{len(overlaps)} pair(s) share an algorithm {overlaps}; naive total "
                   f"{naive} vs union {union}"),
        ])

    # ---- 4. the terminal hop --------------------------------------------------
    path = d.full_path(bom, endpoint=names["endpoint"])
    terminal = path["terminal"] or {}
    add(4, "the transport path ends at an operation, a key and the device that holds it",
        [
            _probe("the-transport-hops-stay-hops", path["count"] >= 2
                   and all(row["tls_version"] for row in path["hops"][:-1]),
                   f"{path['count']} hop(s); "
                   + ", ".join(f"{row['source']} → {row['target']}" for row in path["hops"])),
            _probe("the-terminal-hop-is-the-operation-with-its-parameters",
                   terminal.get("mode") == "SIGN" and "RSA-2048" in (terminal.get("crypto")
                                                                     or []),
                   f"HOP {path['count']} {terminal.get('source')} → "
                   f"{terminal.get('target')} ({terminal.get('mode')} / "
                   f"{'/'.join(terminal.get('crypto') or [])})"),
            _probe("the-key-and-the-hsm-hang-off-that-hop",
                   path["key"] == "KEY-REF-4401" and path["holder"] == "HSM-001",
                   f"key {path['key']} held by {path['holder']}"),
        ])

    # ---- 5. the PQC answer ----------------------------------------------------
    readiness = d.pqc_requirement(bom, query=names["algorithm"])
    counts = readiness["counts"]
    firmware = next((row for row in readiness["devices"]
                     if row["name"] == names["firmware"]), {})
    add(5, "a PQC requirement is answered against each device's own capability list",
        [
            _probe("the-three-readiness-answers-are-distinguished",
                   all(counts[state] for state in d.PQC_READINESS),
                   f"{readiness['count']} device(s): {counts}; required "
                   f"{readiness['required']}"),
            _probe("the-firmware-publishes-a-list-without-ml-kem",
                   firmware.get("readiness") == "BLOCKED",
                   f"{names['firmware']}: {firmware.get('readiness')} — supports "
                   f"{firmware.get('supports') or 'nothing listed'}"),
            _probe("a-device-that-published-no-list-is-UNKNOWN-not-READY",
                   bool(readiness["unknown"])
                   and not set(readiness["unknown"]) & set(readiness["ready"]),
                   f"ready {readiness['ready']}, unknown {readiness['unknown']}"),
        ])

    # ---- 6. the assembled graph ----------------------------------------------
    graph = d.dependency_graph(bom)
    families = graph["families"]
    add(6, "the assembled graph is one projection and names the families it reaches",
        [
            _probe("every-family-is-reached", all(families[name] for name in families),
                   f"{graph['statement']}"),
            _probe("the-graph-reads-the-canonical-estate-and-no-second-store",
                   graph["canonical"] == "CANONICAL_ESTATE" and graph["second_store"] is False,
                   f"canonical {graph['canonical']}, second store {graph['second_store']}; "
                   f"{graph['evidence']['edges']} edge(s) of {len(bom['claims'])} claim(s)"),
            _probe("the-domains-and-levels-travel-with-the-graph",
                   set(graph["domains"]["domains"]) == {"APPLICATION", "PLATFORM",
                                                        "CERTIFICATE", "NETWORK"}
                   and graph["levels"]["system"] == 1,
                   f"levels {graph['levels']}; domain pairs {graph['domains']['pairs']}"),
        ])

    rows = _rows(points)
    counts_verdict = {state: len([row for row in rows if row["verdict"] == state])
                      for state in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "estate": {"id": bom.get("estate_id"), "assets": len(bom["assets"]),
                   "claims": len(bom["claims"]), "refusals": len(bom.get("refusals") or [])},
        "counts": counts_verdict,
        "probes": sum(len(row["probes"]) for row in rows),
        "points_present": len([row for row in rows if row["verdict"] == VERDICT_PASS]),
        "statement": (f"{len([row for row in rows if row['verdict'] == VERDICT_PASS])} of "
                      f"{len(rows)} questions close on the built projection, across "
                      f"{sum(len(row['probes']) for row in rows)} probes; "
                      f"{len(bom['assets'])} assets and {len(bom['claims'])} claims"),
        "rows": rows,
        "evidence": audit,
        "capability_evidence": evidence,
        "domains": domains,
        "path": path,
        "readiness": readiness,
        "graph": graph,
        "limits": [
            "the estate is guide 173's fixture, extended: every shape is real, the rows are not",
            "a collector is named only where an evidence record exists; an edge with none is "
            "reported short and never borrows its neighbour's",
            "the domains classify algorithms by who cites them, so an algorithm cited by "
            "nobody appears in no domain rather than in all four",
            "the terminal hop is the first runtime operation reached from the landing workload; "
            "a workload that invokes three operations shows one and the chain query shows all",
            "a PQC readiness answer is the device's own published list, which is a claim and "
            "not a test: READY means it says it can, and nobody has run it",
            "the graph is one projection of the canonical estate; it proves there is no second "
            "store here and not that no other team keeps one",
        ],
    }


def _rows(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for point in points:
        failed = [probe for probe in point["probes"] if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(point["probes"]) else VERDICT_FAIL)
        rows.append({
            "id": f"CLOSE-{point['point']:02d}", "point": point["point"],
            "question": point["question"], "verdict": verdict,
            "probes": point["probes"],
            "failed": [probe["probe"] for probe in failed],
        })
    return rows


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The chain, closed: six questions under the twenty-six points",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        report["statement"],
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")

    audit = report["evidence"]
    lines += ["", "## The edge's record", "", f"**{audit['statement']}**", "",
              "| field | carried by |", "|---|---|"]
    for field, count in audit["field_coverage"].items():
        lines.append(f"| `{field}` | {count}/{audit['count']} |")

    evidence = report["capability_evidence"]
    lines += ["", "## The SBOM join", "", f"**{evidence['statement']}**", "",
              "| capability | algorithms | classes | verdict |", "|---|---|---|---|"]
    for row in evidence["rows"]:
        lines.append(f"| {row['capability']} | {', '.join(row['algorithms'])} | "
                     f"{', '.join(row['classes']) or '—'} | {row['verdict']} |")

    domains = report["domains"]
    lines += ["", "## Four domains, never summed", "", f"**{domains['statement']}**", "",
              "| domain | nodes | algorithms |", "|---|---|---|"]
    for name, block in domains["domains"].items():
        lines.append(f"| {name} | {block['nodes']} | "
                     f"{', '.join(block['algorithms']) or '—'} |")

    path = report["path"]
    lines += ["", "## The path, down to the operation", "", f"**{path['statement']}**", "",
              "| hop | from | to | mode | TLS | suite | class |",
              "|---|---|---|---|---|---|---|"]
    for row in path["hops"]:
        lines.append(f"| {row['hop']} | {row['source']} | {row['target']} | {row['mode']} | "
                     f"{row['tls_version'] or '—'} | {row['suite'] or '—'} | {row['class']} |")
    lines.append(f"\nthe key behind it: `{path['key']}` held by `{path['holder']}`")

    readiness = report["readiness"]
    lines += ["", "## PQC, in the device's own words", "",
              f"**{readiness['statement']}**", "",
              "| device | kind | readiness | supports |", "|---|---|---|---|"]
    for row in readiness["devices"]:
        lines.append(f"| {row['name']} | {row['kind']} | {row['readiness']} | "
                     f"{', '.join(row['supports']) or '—'} |")

    graph = report["graph"]
    lines += ["", "## One graph", "", f"**{graph['statement']}**", "",
              "| family | kinds present |", "|---|---|"]
    for name, kinds in graph["families"].items():
        lines.append(f"| {name} | {', '.join(kinds) or '—'} |")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "", f"*{row['question']}*", ""]
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
