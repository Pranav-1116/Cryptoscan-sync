#!/usr/bin/env python3
"""Guide 140 — the collectors that make the usage profile mean something.

Guide 139 built the evidence model: classes, layers, a confidence ladder, and a
rule that an observation needs an evidence id. It left one thing open, and the
report said so: **nothing fed it**. Every asset's runtime and network rows were
permanently ``NOT_OBSERVED`` because no collector produced them.

This artifact measures the missing half — pure projections from rows the platform
already stores:

* **network** — a probe that completed a handshake negotiated a cipher suite.
  ``TLS_AES_256_GCM_SHA384`` becomes AES-256-GCM (bulk) plus SHA-384 (hash); a
  TLS 1.2 suite adds its signature and key exchange. Each fact keeps the endpoint
  it was observed on and the scan run it came from.
* **static** — a stored crypto finding joined to its evidence rows. A finding
  whose evidence link is missing is **refused**: it is an inventory entry, not an
  observation.
* **runtime** — a recorded crypto operation needs four things (operation,
  algorithm, evidence id, timestamp) before it counts. A process with no
  operation is a claim about runtime.

Then :func:`profiles` groups the evidence per algorithm, so a CBOM asset shows
which layers observed it, with which ids, at what confidence — and which layers
have *no collector at all*, because ``NOT_OBSERVED`` must not read as ``not used``.
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
SCHEMA = "cryptoscan.cbom-usage-collectors-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

PROBE = {
    "endpoint": "payments.bank.example:443",
    "status": "OK",
    "crypto": {"tls_version": "TLS1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
    "observed_on": "External LB",
    "scan_run_id": "run-7",
    "certificates": [{
        "subject": "payments.bank.example", "issuer": "Bank Internal CA",
        "serial_number": "cert-9281", "public_key_algorithm": "ECDSA",
        "public_key_size": 256, "signature_algorithm": "ECDSA-SHA256",
    }],
}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "network_scanner"), str(SERVICES / "governance"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import usage_collectors  # noqa: PLC0415
    from cbom import usage_evidence  # noqa: PLC0415

    return {"uc": usage_collectors, "ue": usage_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _roles(facts: list[dict[str, Any]]) -> dict[str, str]:
    return {str(fact["algorithm"]): str(fact["role"]) for fact in facts}


# --------------------------------------------------------------------------- #
# 1. reading a cipher suite
# --------------------------------------------------------------------------- #


def row_cipher_suites(modules: dict[str, Any]) -> dict[str, Any]:
    uc = modules["uc"]
    probes: list[dict[str, Any]] = []

    tls13 = uc.algorithms_from_cipher_suite("TLS_AES_256_GCM_SHA384")
    probes.append(_probe(
        "a-tls13-suite-names-its-bulk-algorithm-and-hash",
        _roles(tls13) == {"AES-256-GCM": "BULK", "SHA-384": "HASH"},
        json.dumps(_roles(tls13), sort_keys=True)))

    bulk = next(fact for fact in tls13 if fact["algorithm"] == "AES-256-GCM")
    probes.append(_probe(
        "the-bulk-algorithm-carries-its-parameters",
        bulk["parameters"] == {"key_size": 256, "mode": "GCM"},
        json.dumps(bulk["parameters"], sort_keys=True)))

    tls12 = uc.algorithms_from_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    probes.append(_probe(
        "a-tls12-suite-adds-signature-and-key-exchange",
        _roles(tls12) == {"AES-128-GCM": "BULK", "ECDHE": "KEY_EXCHANGE",
                          "RSA": "SIGNATURE", "SHA-256": "HASH"},
        json.dumps(_roles(tls12), sort_keys=True)))

    probes.append(_probe(
        "an-unknown-suite-invents-nothing",
        uc.algorithms_from_cipher_suite("TLS_FUTURE_MAGIC_999") == []
        and uc.algorithms_from_cipher_suite("") == [],
        "a suite outside the table produces no fact rather than a guess"))

    probes.append(_probe(
        "the-longest-token-wins",
        [fact["algorithm"] for fact in
         uc.algorithms_from_cipher_suite("TLS_CHACHA20_POLY1305_SHA256")]
        == ["CHACHA20-POLY1305", "SHA-256"],
        "CHACHA20_POLY1305 is not mistaken for AES or SHA alone"))

    return {"id": "cipher_suites",
            "question": "can a negotiated suite be read as algorithm facts?",
            "phase": "review 8", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. the network source
# --------------------------------------------------------------------------- #


def row_network_source(modules: dict[str, Any]) -> dict[str, Any]:
    uc = modules["uc"]
    probes: list[dict[str, Any]] = []

    body = uc.network_events_from_probes([PROBE], scan_run_id="run-7")
    probes.append(_probe(
        "a-completed-handshake-becomes-network-evidence",
        body["events"] and {event["class"] for event in body["events"]} == {"NETWORK_OBSERVED"}
        and {event["evidence_id"] for event in body["events"]}
        == {"net:run-7:payments.bank.example:443"},
        body["statement"]))

    unobserved = uc.network_events_from_probes([{**PROBE, "status": "TIMEOUT"}])
    probes.append(_probe(
        "an-unprobed-endpoint-observes-nothing",
        unobserved["events"] == [] and unobserved["refused"]
        and "no handshake completed" in unobserved["refused"][0]["reason"],
        unobserved["refused"][0]["reason"]))

    silent = uc.network_events_from_probes([{**PROBE, "crypto": {"tls_version": "TLS1.3"}}])
    probes.append(_probe(
        "a-handshake-with-no-suite-is-not-algorithm-evidence",
        silent["events"] == [] and "no negotiated suite" in silent["refused"][0]["reason"],
        silent["refused"][0]["reason"]))

    orphan = uc.network_events_from_probes([{k: v for k, v in PROBE.items()
                                            if k != "scan_run_id"}])
    probes.append(_probe(
        "network-evidence-without-a-run-or-id-is-refused",
        orphan["events"] == [] and orphan["refused"] != [],
        "an unfalsifiable network fact is not stored"))

    probes.append(_probe(
        "a-probe-yields-a-certificate-record-that-proves-no-operation",
        body["certificates"]
        and body["certificates"][0]["application_operation_proven"] is False
        and body["certificates"][0]["certificate"]["category"] == "CERTIFICATE",
        body["certificates"][0]["statement"]))

    probes.append(_probe(
        "a-probe-yields-one-hop-attributed-to-its-endpoint",
        body["hops"] and body["hops"][0]["endpoint"] == "payments.bank.example:443"
        and body["hops"][0]["evidence_id"],
        f"{len(body['hops'])} hop(s) with the terminating endpoint named"))

    return {"id": "network_source",
            "question": "does the network scanner's own output become CBOM evidence?",
            "phase": "review 8 / 9", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. the static source
# --------------------------------------------------------------------------- #


def row_static_source(modules: dict[str, Any]) -> dict[str, Any]:
    uc = modules["uc"]
    probes: list[dict[str, Any]] = []

    body = uc.static_events_from_assets([{
        "algorithm": "AES", "key_size": 256, "mode": "GCM", "purpose": "ENCRYPTION",
        "file_path": "src/signing.py", "line_number": 42, "evidence_ids": ["EVID-001"]}])
    event = body["events"][0] if body["events"] else {}
    probes.append(_probe(
        "a-finding-with-its-evidence-row-is-a-static-observation",
        (event.get("class"), event.get("evidence_id")) == ("STATIC_OBSERVED", "EVID-001")
        and event.get("location") == "src/signing.py:42",
        body["statement"]))

    probes.append(_probe(
        "the-findings-parameters-travel-with-it",
        event.get("parameters") == {"key_size": 256, "mode": "GCM"},
        json.dumps(event.get("parameters") or {}, sort_keys=True)))

    orphan = uc.static_events_from_assets([{"algorithm": "RSA", "file_path": "a.py"}])
    probes.append(_probe(
        "a-finding-without-an-evidence-row-is-refused",
        orphan["events"] == [] and "no evidence row" in orphan["refused"][0]["reason"],
        orphan["refused"][0]["reason"]))

    probes.append(_probe(
        "a-finding-with-no-algorithm-is-refused",
        uc.static_events_from_assets([{"evidence_ids": ["E-1"]}])["refused"] != [],
        "an evidence row with no algorithm names nothing"))

    return {"id": "static_source",
            "question": "does a stored finding carry the evidence that makes it one?",
            "phase": "review 5 / 6", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. the runtime source
# --------------------------------------------------------------------------- #


def _operation(**overrides: Any) -> dict[str, Any]:
    row = {"operation": "EVP_EncryptInit_ex", "algorithm": "AES-256-GCM", "key_size": 256,
           "mode": "GCM", "evidence_id": "RUNTIME-92821",
           "observed_at": "2026-11-02T10:42:11Z", "process": "payments-api[9182]",
           "purpose": "TLS"}
    row.update(overrides)
    return row


def row_runtime_source(modules: dict[str, Any]) -> dict[str, Any]:
    uc = modules["uc"]
    probes: list[dict[str, Any]] = []

    body = uc.runtime_events_from_operations([_operation()])
    event = body["events"][0] if body["events"] else {}
    probes.append(_probe(
        "a-recorded-operation-is-runtime-evidence",
        (event.get("class"), event.get("evidence_id")) == ("RUNTIME_OBSERVED", "RUNTIME-92821")
        and event.get("location") == "payments-api[9182]",
        body["statement"]))

    for field in ("evidence_id", "observed_at", "operation", "algorithm"):
        missing = uc.runtime_events_from_operations([_operation(**{field: None})])
        probes.append(_probe(
            f"a-runtime-row-without-{field.replace('_', '-')}-is-a-claim",
            missing["events"] == [] and field in missing["refused"][0]["reason"],
            missing["refused"][0]["reason"] if missing["refused"] else "accepted"))

    probes.append(_probe(
        "a-process-with-no-operation-is-not-runtime-evidence",
        uc.runtime_events_from_operations([{"process": "payments-api",
                                            "evidence_id": "E-1",
                                            "observed_at": "2026-11-02"}])["refused"] != [],
        "naming a process is not recording an operation"))

    return {"id": "runtime_source",
            "question": "does a runtime row have to name the operation to count?",
            "phase": "review 7 / 21", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. from collected evidence to a profile
# --------------------------------------------------------------------------- #


def row_collect_to_profile(modules: dict[str, Any]) -> dict[str, Any]:
    uc = modules["uc"]
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    main = (SERVICES / "api" / "api" / "main.py").read_text(encoding="utf-8")
    probes: list[dict[str, Any]] = []

    network = uc.network_events_from_probes([PROBE], scan_run_id="run-7")["events"]
    alone = uc.profiles(network)
    profile = alone["profiles"][0]
    probes.append(_probe(
        "network-alone-is-high-and-names-the-missing-layers",
        profile["confidence"] == "HIGH" and profile["usage"] == "OBSERVED"
        and set(alone["unobserved_layers"]) == {"static", "config", "runtime"},
        alone["statement"]))

    static = uc.static_events_from_assets([{
        "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
        "file_path": "src/tls.py", "line_number": 12,
        "evidence_ids": ["EVID-001"]}])["events"]
    runtime = uc.runtime_events_from_operations([_operation()])["events"]
    combined = uc.profiles(network + static + runtime)
    row = next(item for item in combined["profiles"]
               if item["asset"]["algorithm"] == "AES-256-GCM")
    probes.append(_probe(
        "three-sources-reach-very-high-with-every-id-kept",
        row["confidence"] == "VERY_HIGH"
        and {"net:run-7:payments.bank.example:443", "EVID-001", "RUNTIME-92821"}
        <= set(row["evidence_ids"]),
        row["confidence_reason"]))

    probes.append(_probe(
        "the-profile-keeps-roles-and-locations",
        row["roles"] == ["BULK"] and "payments.bank.example:443" in row["locations"],
        f"roles={row['roles']}, locations={row['locations']}"))

    imported = uc.profiles([{"class": "IMPORTED", "evidence_id": "SBOM-1",
                             "algorithm": "AES-256"}])["profiles"][0]
    probes.append(_probe(
        "an-sbom-fact-stays-a-candidate-in-the-collected-profile",
        imported["usage"] == "CANDIDATE_ONLY" and imported["confidence"] == "LOW",
        imported["statement"]))

    probes.append(_probe(
        "the-collect-routes-are-typed-and-mounted",
        '@router.post("/usage/collect"' in router
        and "response_model=CbomCollectResponse" in router
        and '@router.get("/usage/network"' in router
        and "response_model=CbomNetworkUsageResponse" in router
        and "app.include_router(cbom_usage.router, prefix=prefix)" in main,
        "POST /cbom/usage/collect and GET /cbom/usage/network"))

    probes.append(_probe(
        "the-network-route-reads-stored-scan-runs",
        "NetworkScanRun" in router and "run.result or {}" in router,
        "the network half comes from rows, not from the request body"))

    return {"id": "collect_to_profile",
            "question": "does collected evidence become a CBOM asset's answer?",
            "phase": "review 4 / 20", "probes": probes}


ROWS = (row_cipher_suites, row_network_source, row_static_source, row_runtime_source,
        row_collect_to_profile)


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
            "the network collector reads what the prober negotiated. It cannot see a listener the "
            "prober never reached, and an unreached endpoint is refused rather than recorded as "
            "absent cryptography",
            "cipher-suite parsing is a table, not a spec implementation. A suite outside it "
            "produces no fact rather than a guess, which means a new suite looks like missing "
            "evidence until the table is extended",
            "the static collector joins stored findings to their evidence rows. If the link is "
            "absent the finding is refused, which is correct but means a broken ingestion path "
            "shrinks the profile instead of flagging the ingestion",
            "the runtime collector is fed by whatever records crypto operations. The platform "
            "does not yet trace a process, so a runtime row is only as good as the agent that "
            "wrote it — the collector's job is to insist on the operation, the id and the time, "
            "not to produce them",
            "profiles are grouped by algorithm name, not by call site: two applications using "
            "AES-256-GCM in different ways share one profile unless the caller separates them",
            "a layer with no collector is reported as unobserved_layers. That is honest, but it "
            "is still an absence the console must render as unknown rather than as safe",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The collectors that make the usage profile mean something",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "Guide 139 built the evidence model and said what it could not do: nothing fed it. "
        "This artifact measures the collectors — pure projections from rows the platform "
        "already stores.",
        "",
        "1. **Network** — a completed handshake becomes algorithm facts "
        "(`TLS_AES_256_GCM_SHA384` → AES-256-GCM bulk + SHA-384 hash), a certificate record "
        "that proves no application operation, and one hop attributed to the endpoint that "
        "terminated it. An unprobed endpoint produces a refusal, not an absence.",
        "2. **Static** — a stored finding with its evidence row is an observation; without one "
        "it is refused, because an inventory entry is not a record that something was seen.",
        "3. **Runtime** — an operation needs its name, its algorithm, an evidence id and a "
        "timestamp before it counts.",
        "4. **Profiles** — collected evidence becomes one profile per algorithm, with the "
        "layers that observed it, every evidence id, and the layers that have **no collector "
        "at all** named explicitly so `NOT_OBSERVED` cannot be read as `not used`.",
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
