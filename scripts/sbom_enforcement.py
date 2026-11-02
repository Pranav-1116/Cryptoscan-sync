#!/usr/bin/env python3
"""Guide 134 — the evidence rules where the code runs, not where the guide says.

Guide 133 wrote the rules as pure functions and proved each one in isolation.
That is not the same as enforcing them. This artifact closes the gap the second
review names: *the guarantees have to hold on the path a bank actually calls*.

Six rows, each an executed probe against real code:

* **storage (item 8, blocker 2)** — ``artifact_storage()`` no longer falls back to
  a temporary directory when the configured store is missing or unbacked. In
  production it raises ``StorageRefused`` naming backup, retention and integrity;
  in development it degrades and ``storage_status()`` records which happened. The
  integrity claim is a real write/read/hash round-trip, not an assumption.
* **parser budget (item 17.5)** — ``scan_source`` measures the merged dependency
  graph against the budget: too deep withholds the edges and keeps the
  inventory, a cycle breaks the back edges instead of recursing, and the result
  carries the measurement under ``parser_budget``.
* **vulnerability at document scale (item 10)** — ``assess_document`` gives every
  component a posture and a reason, and reports how many were never assessed, so
  a document cannot be summarised as clean when nobody looked.
* **digital-twin edges (item 14)** — SBOM → component → application → release →
  artifact → deployment → workload, every edge carrying an evidence id, type,
  source, timestamp and confidence; a capability edge is always low-confidence
  and a component with no observation has no path to production.
* **temporal history (item 15)** — a series of snapshots becomes a timeline with
  a change set per transition and the gap in days.
* **import guard (blocker 1)** — ``guard_import`` puts the budget and the
  protected-fact screening in front of every import, and every imported row is
  labelled ``UNTRUSTED`` with ``may_override: False``.
* **VEX governance (item 11)** — a ``not_affected`` statement must name a
  reviewer, evidence and an expiry to be ``COMPLETE``; when it lapses the finding
  returns to triage and the statement says what it used to claim.
* **manifest record** — an artifact's manifest states the environment, root,
  durability, backup and retention of the store that holds it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import textwrap
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.sbom-enforcement-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
DIGEST = "sha256:" + "a" * 64


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "container_scanner"),
                  str(SERVICES / "governance"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import (artifact_store, sbom, sbom_evidence, sbom_scan,  # noqa: PLC0415
                           sbom_vex)

    return {"store": artifact_store, "se": sbom_evidence, "scan": sbom_scan, "sbom": sbom,
            "vex": sbom_vex}


@contextmanager
def _env(**values: str | None) -> Iterator[None]:
    """Set (or clear, with ``None``) a handful of variables for one probe."""
    keys = ("SBOM_STORAGE_DIR", "SBOM_STORAGE_BACKUP_DIR", "SBOM_RETENTION_DAYS",
            "ENVIRONMENT", "CRYPTOSCAN_ENV")
    saved = {key: os.environ.get(key) for key in keys}
    try:
        for key in keys:
            os.environ.pop(key, None)
        for key, value in values.items():
            if value is not None:
                os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refusal(call: Any, expected: type[BaseException]) -> str:
    try:
        call()
    except expected as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - a different error is a different finding
        return f"WRONG-EXCEPTION {type(exc).__name__}: {exc}"
    return ""


# --------------------------------------------------------------------------- #
# 1. storage enforcement
# --------------------------------------------------------------------------- #


def row_storage(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    store = modules["store"]
    probes: list[dict[str, Any]] = []
    workspace = Path(tempfile.mkdtemp(prefix="guide134-store-"))

    with _env(ENVIRONMENT="development", SBOM_STORAGE_DIR=str(workspace / "dev")):
        status = store.storage_status()
        probes.append(_probe(
            "development-uses-its-configured-store",
            status["verdict"] == "ALLOW" and status["mode"] == "CONFIGURED",
            f"development -> {status['verdict']} ({status['mode']}) at {status['root']}"))

    with _env(ENVIRONMENT="production"):
        refusal = _refusal(store.artifact_storage, store.StorageRefused)
        no_store = store.storage_status()
        probes.append(_probe(
            "production-with-no-store-raises-instead-of-writing-to-tmp",
            "no artifact store is configured" in refusal and no_store["mode"] == "NO_STORE",
            refusal[:170]))

    with _env(ENVIRONMENT="production", SBOM_STORAGE_DIR=str(workspace / "prod")):
        refusal = _refusal(store.artifact_storage, store.StorageRefused)
        probes.append(_probe(
            "a-store-without-backup-or-retention-is-refused-by-name",
            "no backup target" in refusal and "no retention period" in refusal,
            refusal[:190]))

    backup = workspace / "dr"
    with _env(ENVIRONMENT="production", SBOM_STORAGE_DIR=str(workspace / "prod"),
              SBOM_STORAGE_BACKUP_DIR=str(backup), SBOM_RETENTION_DAYS="2555"):
        status = store.storage_status()
        instance = store.artifact_storage()
        probes.append(_probe(
            "a-configured-backed-and-retained-store-is-used",
            status["verdict"] == "ALLOW" and status["backup"] and status["retention_days"] == 2555
            and instance is not None,
            f"production -> {status['verdict']}; backup={status['backup']}, "
            f"retention={status['retention_days']} days, integrity={status['integrity_verified']}"))

    blocker = workspace / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    with _env(ENVIRONMENT="production", SBOM_STORAGE_DIR=str(blocker / "sboms"),
              SBOM_STORAGE_BACKUP_DIR=str(backup), SBOM_RETENTION_DAYS="365"):
        status = store.storage_status()
        probes.append(_probe(
            "an-unwritable-store-is-not-reported-as-verified",
            status["writable"] is False and status["integrity_verified"] is False
            and status["verdict"] == "REFUSE",
            f"writable={status['writable']}, integrity={status['integrity_verified']} -> "
            f"{status['verdict']} ({status['error'][:60] if status['error'] else 'no error'})"))

    with _env(ENVIRONMENT="test", SBOM_STORAGE_DIR=str(workspace / "test")):
        scan = modules["scan"]
        bom = scan.render_sbom({"target": "/srv/app",
                                "packages": [{"name": "openssl", "version": "3.0.13"}],
                                "libraries": [], "binaries": [], "vulnerabilities": [],
                                "manifests": [], "lockfiles": [], "dependencies": []},
                               fmt="cyclonedx", created_by="guide-134")
        stored = store.store_binary_artifact(
            scan={"target": "/srv/app", "files_walked": 1},
            result={"target": "/srv/app", "packages": [{"name": "openssl", "version": "3.0.13"}],
                    "manifests": [], "lockfiles": [], "dependencies": [], "libraries": [],
                    "binaries": []},
            bom=bom, cbom={}, created_by="guide-134")
        recorded = stored["manifest"]["storage"]
        probes.append(_probe(
            "the-manifest-records-where-the-evidence-went",
            recorded["environment"] == "test" and Path(recorded["root"]).is_dir()
            and "verdict" in recorded,
            f"manifest storage: {recorded['verdict']} in {recorded['root']} "
            f"(integrity {recorded['integrity_verified']})"))

    return {"id": "storage_enforcement",
            "question": "can production evidence still land in a temporary directory?",
            "phase": "8 / blocker 2", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. graph budget enforcement
# --------------------------------------------------------------------------- #


def _chain_lockfile(depth: int) -> str:
    packages: dict[str, Any] = {"": {"dependencies": {"p0": "^1.0.0"}}}
    for index in range(depth):
        row: dict[str, Any] = {"version": "1.0.0"}
        if index + 1 < depth:
            row["dependencies"] = {f"p{index + 1}": "^1.0.0"}
        packages[f"node_modules/p{index}"] = row
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def row_graph_budget(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    scan = modules["scan"]
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    workspace = Path(tempfile.mkdtemp(prefix="guide134-graph-"))

    ordinary = workspace / "ordinary"
    ordinary.mkdir()
    (ordinary / "package.json").write_text(json.dumps({"dependencies": {"jose": "^5.0.0"}}),
                                           encoding="utf-8")
    small = scan.scan_source(str(ordinary))
    probes.append(_probe(
        "an-ordinary-tree-is-measured-and-passes",
        small["parser_budget"]["verdict"] == "WITHIN_BUDGET"
        and small["parser_budget"]["action"] == "NONE",
        small["parser_budget"]["statement"]))

    deep = workspace / "deep"
    deep.mkdir()
    (deep / "package-lock.json").write_text(_chain_lockfile(80), encoding="utf-8")
    result = scan.scan_source(str(deep))
    budget = result["parser_budget"]
    probes.append(_probe(
        "an-eighty-deep-graph-withholds-the-edges-and-keeps-the-inventory",
        budget["verdict"] == "REFUSED" and budget["action"] == "EDGES_WITHHELD"
        and result["dependencies"] == [] and len(result["packages"]) == 80,
        f"{len(result['packages'])} component(s) kept, {budget['edges_withheld']} edge(s) "
        f"withheld: {budget['problems'][0]}"))

    cyclic = workspace / "cyclic"
    cyclic.mkdir()
    (cyclic / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "^1"}},
        }}), encoding="utf-8")
    looped = scan.scan_source(str(cyclic))
    probes.append(_probe(
        "a-cycle-breaks-one-back-edge-instead-of-recursing",
        looped["parser_budget"]["action"] == "CYCLES_BROKEN"
        and looped["parser_budget"]["edges_broken"] == 1
        and len(looped["dependencies"]) == 1,
        f"cycle detected, {looped['parser_budget']['edges_broken']} back edge removed, "
        f"{len(looped['dependencies'])} edge(s) kept"))

    tight = scan.scan_source(str(ordinary), budget=se.ParserBudget(max_components=0))
    probes.append(_probe(
        "the-budget-can-be-set-by-the-caller",
        tight["parser_budget"]["verdict"] == "REFUSED"
        and tight["parser_budget"]["action"] == "EDGES_WITHHELD",
        f"max_components=0 -> {tight['parser_budget']['verdict']}; the inventory is still "
        f"returned ({len(tight['packages'])} component(s))"))

    probes.append(_probe(
        "the-measurement-travels-with-the-result",
        all(key in result["parser_budget"]
            for key in ("verdict", "problems", "budget", "components", "depth", "cycles")),
        "parser_budget carries verdict, problems, limits, component count, depth and cycles "
        "into the API response and the stored manifest"))

    return {"id": "graph_budget",
            "question": "does a hostile lockfile hit a stated limit before it hits the CPU?",
            "phase": "17.5 / blocker 5", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. vulnerability posture at document scale
# --------------------------------------------------------------------------- #

FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}
ADVISORY = [{"id": "CVE-2024-6119", "package": "pkg:generic/openssl",
             "affected_versions": ["3.0.11"]}]


def _sbom(se: Any, components: tuple[dict, ...], sbom_id: str = "SBOM-9182",
          created_at: date | None = None) -> Any:
    return se.SbomRecord(sbom_id, se.ArtifactIdentity("ghcr.io/bank/payments-api", DIGEST),
                         components, created_at=created_at, build_id="BUILD-2026-1102-0091")


def row_vulnerability_document(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    sbom = _sbom(se, (
        {"name": "openssl", "version": "3.0.11", "purl": "pkg:generic/openssl@3.0.11"},
        {"name": "curl", "version": "8.4.0", "purl": "pkg:generic/curl@8.4.0"},
        {"name": "mystery-lib", "version": None, "purl": None},
    ))

    report = se.assess_document(sbom, feed=FEED, advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "every-component-gets-a-posture-with-its-reason",
        len(report["components"]) == 3
        and all(row.get("reason") for row in report["components"])
        and set(se.VULN_ROW_FIELDS) <= set(report["components"][0]),
        f"{report['statement']}"))

    probes.append(_probe(
        "a-document-cannot-be-summarised-clean-when-nobody-looked",
        report["unassessed"] == 1 and "may not be reported as clean" in report["statement"],
        f"{report['counts']['MATCHED']} matched, {report['counts']['ASSESSED_NO_MATCH']} "
        f"assessed with no match, {report['unassessed']} with no posture"))

    stale = se.assess_document(sbom, advisories=ADVISORY, as_of=as_of,
                               feed={"name": "osv", "version": "2026-08-01",
                                     "updated_at": date(2026, 8, 1)})
    probes.append(_probe(
        "a-stale-feed-leaves-every-component-unassessed",
        stale["assessed"] == 0 and stale["counts"]["STALE_FEED"] == 3,
        stale["statement"]))

    empty = se.assess_document(sbom, feed=None, as_of=as_of)
    probes.append(_probe(
        "no-feed-is-not-assessed-not-clean",
        empty["counts"]["NOT_ASSESSED"] == 3 and empty["assessed"] == 0,
        empty["statement"]))

    return {"id": "vulnerability_document",
            "question": "can 0 matches be reported as clean when nothing was assessed?",
            "phase": "10", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. digital-twin edges
# --------------------------------------------------------------------------- #


def row_twin_edges(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    artifact = se.ArtifactIdentity("ghcr.io/bank/payments-api", DIGEST)
    observation = se.DeploymentObservation(
        "payments-api-prod", "PRODUCTION", artifact, "payments-api-7d9c4f-x2b6q", as_of,
        "OBS-2026-1102-01", "k8s")
    build = se.BuildIdentity("9f2c1ab4d7", "BUILD-2026-1102-0091", "github-actions",
                             "release-payments", artifact, "SBOM-9182", started_at=as_of,
                             finished_at=as_of)
    sbom = _sbom(se, ({"name": "openssl", "version": "3.0.13", "crypto_relevant": True},),
                 created_at=as_of)

    graph = se.twin_edges(sbom, build=build, deployments=[observation],
                          application="payments-api", business_system="Card Processing",
                          algorithms={"openssl": ["AES-256-GCM", "RSA-3072"]})
    kinds = {edge["kind"] for edge in graph["edges"]}
    probes.append(_probe(
        "the-chain-reaches-a-running-workload",
        {"CONTAINS", "DESCRIBED_BY", "PRODUCED", "DEPLOYED_AS", "RUNS_AS", "SERVES",
         "HAS_CAPABILITY"} <= kinds,
        f"{len(graph['edges'])} edge(s): {graph['statement']}"))

    probes.append(_probe(
        "every-edge-carries-its-evidence",
        all(edge["evidence_id"] and edge["evidence_type"] and edge["source"]
            and edge["confidence"] in {"HIGH", "MEDIUM", "LOW"} for edge in graph["edges"]),
        "every edge has evidence_id, evidence_type, source, observed_at and confidence"))

    deployment = next(edge for edge in graph["edges"] if edge["kind"] == "DEPLOYED_AS")
    probes.append(_probe(
        "deployment-edges-come-from-observations-not-from-the-sbom",
        deployment["evidence_type"] == "OBSERVATION"
        and deployment["evidence_id"] == "OBS-2026-1102-01"
        and deployment["source"] == "k8s",
        f"{deployment['from']} --{deployment['kind']}--> {deployment['to']} citing "
        f"{deployment['evidence_id']} from {deployment['source']}"))

    unobserved = se.twin_edges(sbom, build=build, deployments=[])
    probes.append(_probe(
        "an-unobserved-artifact-has-no-path-to-production",
        not any(edge["kind"] in {"DEPLOYED_AS", "RUNS_AS"} for edge in unobserved["edges"])
        and unobserved["unobserved_components"] == ["openssl"],
        unobserved["statement"]))

    capability = [edge for edge in graph["edges"] if edge["kind"] == "HAS_CAPABILITY"]
    probes.append(_probe(
        "a-capability-edge-is-never-high-confidence",
        capability and all(edge["confidence"] == "LOW"
                           and edge["evidence_type"] == "CAPABILITY" for edge in capability),
        f"{len(capability)} capability edge(s), all LOW: "
        f"{', '.join(edge['to'] for edge in capability)}"))

    return {"id": "twin_edges",
            "question": "can the twin answer where a package is deployed, not which file lists it?",
            "phase": "14", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. temporal history
# --------------------------------------------------------------------------- #


def row_history(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    def snapshot(version: str, sbom_id: str, created: date) -> Any:
        return _sbom(se, ({"name": "openssl", "version": version, "crypto_relevant": True},),
                     sbom_id=sbom_id, created_at=created)

    report = se.history([
        snapshot("3.0.13", "SBOM-9182", date(2026, 11, 2)),
        snapshot("3.0.11", "SBOM-8801", date(2026, 10, 1)),
        snapshot("3.0.12", "SBOM-9014", date(2026, 10, 20)),
    ])
    probes.append(_probe(
        "a-series-of-snapshots-becomes-a-timeline",
        report["snapshots"] == ["SBOM-8801", "SBOM-9014", "SBOM-9182"]
        and len(report["transitions"]) == 2,
        report["statement"]))

    kinds = [change["kind"] for row in report["transitions"] for change in row["changes"]]
    probes.append(_probe(
        "each-transition-carries-its-change-set",
        kinds.count("VERSION_CHANGED") == 2
        and report["transitions"][0]["counts"]["VERSION_CHANGED"] == 1,
        f"{report['changed_transitions']} of {len(report['transitions'])} transition(s) moved: "
        f"{', '.join(sorted(set(kinds)))}"))

    probes.append(_probe(
        "the-timeline-keeps-every-version-it-saw",
        [row["version"] for row in report["components"]["openssl"]] ==
        ["3.0.11", "3.0.12", "3.0.13"],
        "openssl: " + " -> ".join(row["version"] for row in report["components"]["openssl"])))

    probes.append(_probe(
        "the-gap-between-snapshots-is-stated",
        report["gap_days"] == 19,
        f"longest gap {report['gap_days']} day(s) — a drift engine that never states its own "
        "blind spots cannot be audited"))

    quiet = se.history([snapshot("3.0.13", "SBOM-9182", date(2026, 11, 2)),
                        snapshot("3.0.13", "SBOM-9183", date(2026, 11, 1))])
    probes.append(_probe(
        "two-identical-snapshots-produce-no-changes",
        quiet["changed_transitions"] == 0,
        quiet["statement"]))

    return {"id": "history",
            "question": "is an SBOM a file, or a series somebody can diff over time?",
            "phase": "15", "probes": probes}


# --------------------------------------------------------------------------- #
# 6. the API records what the evidence layer measured
# --------------------------------------------------------------------------- #


def row_api_wiring(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    router = (ROOT / "services" / "api" / "api" / "routers" / "devsecops.py").read_text(
        encoding="utf-8")
    probes: list[dict[str, Any]] = []
    probes.append(_probe(
        "the-scan-response-carries-the-parser-budget",
        '"parser_budget": result.get("parser_budget")' in router
        and '"parser_budget": manifest.get("parser_budget")' in router,
        "the source manifest reads result['parser_budget'] and the response returns it, so "
        "a withheld graph is visible to the caller"))
    probes.append(_probe(
        "the-manifest-records-the-storage-verdict",
        '"storage": storage_status()' in router,
        "the source manifest records where the artifact was written and whether that store "
        "was allowed to be ephemeral"))
    probes.append(_probe(
        "a-storage-refusal-is-a-503-with-the-reasons",
        "SBOM artifact storage unavailable" in router and "status_code=503" in router,
        "an unconfigured production store fails the request with a reason instead of "
        "writing evidence to a temporary directory"))
    return {"id": "api_wiring",
            "question": "does the API surface what the evidence layer measured?",
            "phase": "5-8 (reporting)", "probes": probes}


def row_import_guard(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    sbom = modules["sbom"]
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                "components": [{"name": "openssl", "version": "3.0.13",
                                "purl": "pkg:generic/openssl@3.0.13"}]}

    screening = sbom.guard_import(document, source="vendor-portal")
    probes.append(_probe(
        "a-normal-import-is-labelled-untrusted-and-measured",
        screening["trust"] == "UNTRUSTED" and screening["may_override"] is False
        and screening["budget"]["verdict"] == "WITHIN_BUDGET"
        and len(screening["content_hash"]) == 64,
        f"{screening['trust']}, may_override={screening['may_override']}, content hash "
        f"{screening['content_hash'][:12]}…, budget {screening['budget']['verdict']}"))

    refusal = ""
    try:
        sbom.guard_import({"bomFormat": "CycloneDX", "deployment_identity": "attacker-prod",
                           "components": []}, source="vendor-portal")
    except ValueError as exc:
        refusal = str(exc)
    probes.append(_probe(
        "an-import-may-not-state-an-observed-fact",
        "asserts deployment_identity" in refusal,
        refusal[:150]))

    refusal = ""
    try:
        sbom.guard_import(document, source="vendor-portal",
                          budget=se.ParserBudget(max_components=0))
    except ValueError as exc:
        refusal = str(exc)
    probes.append(_probe(
        "an-oversized-import-hits-the-budget-before-it-is-read",
        "exceeds the 0 limit" in refusal, refusal[:120]))

    marked = sbom.mark_imported(sbom.import_sbom(document))
    probes.append(_probe(
        "every-imported-row-carries-its-provenance",
        marked and all(row["trust"] == "UNTRUSTED" and row["imported"] is True
                       and row["may_override"] is False for row in marked),
        f"{len(marked)} row(s) labelled UNTRUSTED / imported / may_override=False"))

    router = (ROOT / "services" / "api" / "api" / "routers" / "devsecops.py").read_text(
        encoding="utf-8")
    probes.append(_probe(
        "the-import-endpoint-calls-the-guard",
        "guard_import(body.doc" in router and "mark_imported(import_sbom(body.doc))" in router,
        "/sbom/import screens the document before it reads a component and returns the "
        "trust label, content hash and budget with the rows"))

    return {"id": "import_guard",
            "question": "can an uploaded SBOM change the estate or state a fact nobody observed?",
            "phase": "17.1 / blocker 1", "probes": probes}


def _vuln_bom() -> dict[str, Any]:
    ref = "pkg:npm/left-pad@1.0.0"
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"timestamp": "2026-09-01T00:00:00Z"},
            "components": [{"type": "library", "name": "left-pad", "version": "1.0.0",
                            "bom-ref": ref, "purl": ref}],
            "vulnerabilities": [{"id": "CVE-2024-0001",
                                 "ratings": [{"severity": "high"}],
                                 "affects": [{"ref": ref}]}]}


def row_vex_governance(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    vex = modules["vex"]
    probes: list[dict[str, Any]] = []

    governed = vex.statements(_vuln_bom(), as_of=as_of, analyses={"CVE-2024-0001": {
        "state": "not_affected", "justification": "code_not_reachable",
        "reviewer": "Security Team", "evidence_id": "EVID-9281",
        "assessed_on": "2026-01-01", "expires_on": "2027-01-01"}})[0]
    probes.append(_probe(
        "a-governed-statement-carries-a-reviewer-evidence-and-expiry",
        governed["state"] == "not_affected" and governed["governance"]["state"] == "COMPLETE"
        and governed["governance"]["reviewer"] == "Security Team"
        and governed["governance"]["expires_on"] == "2027-01-01",
        f"{governed['state']}, governance {governed['governance']['state']}, reviewer "
        f"{governed['governance']['reviewer']}, expires "
        f"{governed['governance']['expires_on']}"))

    lapsed = vex.statements(_vuln_bom(), as_of=as_of, analyses={"CVE-2024-0001": {
        "state": "not_affected", "justification": "code_not_reachable",
        "reviewer": "Security Team", "evidence_id": "EVID-9281",
        "assessed_on": "2025-01-01", "expires_on": "2026-01-01"}})[0]
    probes.append(_probe(
        "an-expired-statement-stops-suppressing-the-finding",
        lapsed["state"] == "in_triage" and lapsed["governance"]["expired"] is True
        and lapsed["governance"]["claimed_state"] == "not_affected",
        f"lapsed not_affected -> {lapsed['state']}: {lapsed['detail'][-70:]}"))

    bare = vex.statements(_vuln_bom(), as_of=as_of, analyses={"CVE-2024-0001": {
        "state": "not_affected", "justification": "code_not_reachable"}})[0]
    probes.append(_probe(
        "an-unsigned-statement-is-marked-incomplete-not-blessed",
        bare["governance"]["state"] == "INCOMPLETE"
        and set(bare["governance"]["missing"]) == {"reviewer", "evidence_id", "expires_on"},
        f"governance {bare['governance']['state']}, missing "
        f"{', '.join(bare['governance']['missing'])}"))

    probes.append(_probe(
        "a-free-text-expiry-cannot-be-enforced-so-it-is-refused",
        _refusal(lambda: vex.statements(_vuln_bom(), analyses={"CVE-2024-0001": {
            "state": "not_affected", "justification": "code_not_reachable",
            "expires_on": "next year"}}), ValueError).startswith("analysis for CVE-2024-0001"),
        "expires_on='next year' -> refused: a date nobody can compare is not an expiry"))

    probes.append(_probe(
        "a-statement-cannot-expire-before-it-was-made",
        "before assessed_on" in _refusal(
            lambda: vex.statements(_vuln_bom(), analyses={"CVE-2024-0001": {
                "state": "not_affected", "justification": "code_not_reachable",
                "assessed_on": "2026-05-01", "expires_on": "2026-01-01"}}), ValueError),
        "assessed 2026-05-01, expires 2026-01-01 -> refused"))

    probes.append(_probe(
        "a-justification-is-still-required",
        "requires a justification" in _refusal(
            lambda: vex.statements(_vuln_bom(), analyses={"CVE-2024-0001": {
                "state": "not_affected"}}), ValueError),
        "not_affected without a justification -> refused"))

    return {"id": "vex_governance",
            "question": "does a not_affected statement expire, and does it name an owner?",
            "phase": "11", "probes": probes}


ROWS = (row_storage, row_graph_budget, row_import_guard, row_vex_governance,
        row_vulnerability_document, row_twin_edges, row_history, row_api_wiring)


# --------------------------------------------------------------------------- #
# measure + render
# --------------------------------------------------------------------------- #


def measure(as_of: date | None = None) -> dict[str, Any]:
    as_of = as_of or datetime.now(timezone.utc).date()
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules, as_of)
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
        "as_of": as_of.isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "rows": rows,
        "limits": [
            "the storage policy is enforced in the artifact writer, not in the object store "
            "itself: an operator who points SBOM_STORAGE_DIR at a node-local disk still has "
            "no backup until they set SBOM_STORAGE_BACKUP_DIR, and this code cannot check "
            "that the backup target is a different failure domain",
            "restore is not exercised here. The policy refuses an unbacked store; proving a "
            "restore returns byte-identical evidence is an operational drill",
            "the graph budget protects this repository's parser. A vendor's own lockfile "
            "reader has its own limits and would need the same matrix",
            "twin edges are built from records handed in; the Kubernetes/CMDB collectors "
            "that produce observations are outside this artifact",
            "vulnerability matching is purl+version against a supplied advisory set; range "
            "semantics per ecosystem are still outstanding",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# SBOM evidence, enforced where the code runs",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 133 wrote the SBOM evidence rules as functions and proved each one. "
        "This artifact is the answer to the obvious follow-up — *is any of it on the "
        "path the product takes?* — and closes five gaps where the answer was no:",
        "",
        "1. **The artifact store degraded to `/tmp`.** `artifact_storage()` caught any "
        "failure and fell back to a temporary directory, which turns *we hold the evidence* "
        "into *we held it until the container restarted*. It now consults the same "
        "`storage_policy` the review asked for, verifies integrity with a real write/read/"
        "hash round-trip, records the verdict in the manifest, and in production raises "
        "`StorageRefused` naming backup, retention and integrity rather than degrading.",
        "2. **The parser budget was a library function.** `scan_source` now measures the "
        "merged dependency graph against it and reports the measurement in the scan result: "
        "an 80-deep chain withholds the edges and keeps the inventory, a cycle breaks exactly "
        "one back edge, and the caller can tighten the limits per request.",
        "3. **An imported SBOM was read before it was screened.** `/sbom/import` now "
        "calls `guard_import` first: the parser budget refuses an oversized document by a "
        "stated limit, a document that asserts a protected fact (`deployment_identity`, "
        "`runtime_evidence`, `authorization`, `observed_fact`) is refused rather than "
        "merged, and every row it contributes comes back labelled `UNTRUSTED` with "
        "`may_override: False` and a content hash.",
        "4. **A VEX statement never expired.** A `not_affected` analysis now carries a "
        "reviewer, an evidence id and an ISO expiry. Complete governance reads `COMPLETE`; "
        "a statement without them is `INCOMPLETE` with the missing fields named; and when "
        "the expiry passes the finding returns to `in_triage`, with the lapsed claim kept "
        "visible rather than deleted.",
        "5. **The API could not say any of it.** The source manifest now carries "
        "`parser_budget` and `storage`, the response returns the budget, an import returns "
        "its trust label, and a storage refusal is a 503 with the reasons attached.",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (review item {row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += ["", "## How to run it", "", "```bash",
              "python scripts/sbom_enforcement.py --as-of 2026-11-02 \\",
              "--json docs/bank-environment/134-sbom-enforcement.json \\",
              "--md docs/bank-environment/134-sbom-enforcement.md",
              "python scripts/sbom_enforcement.py --check   # non-zero on FAIL or PARTIAL",
              "```", ""]
    return "\n".join(textwrap.dedent(line) if line.startswith("    ") else line
                     for line in lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure(args.as_of)
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
