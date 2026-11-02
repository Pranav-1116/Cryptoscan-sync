#!/usr/bin/env python3
"""Guide 138 — the SBOM reaches the graph, and the store becomes a timeline.

Guide 137 stopped the gate believing a document. Two things were still true
afterwards:

* **The twin and the SBOM were separate answers.** ``sbom_evidence.twin_edges``
  produced edges for the graph, but nothing wrote them, and nothing carried the
  evidence id onto the edge. An SBOM edge is a *declaration*: it says a component
  is in a build. Only a deployment observation says something is *running*. This
  guide writes those edges with their provenance class attached — ``SBOM`` →
  ``DECLARED``, ``OBSERVATION`` → ``OBSERVED``, ``CAPABILITY`` → ``INFERRED`` — and
  refuses any edge that carries no evidence id at all.
* **History lived in a list, not in the store.** ``history`` was a pure function
  over records a caller already held. A bank asks about the artifacts it kept:
  what moved in production, over time, between two stored SBOMs. ``sbom_timeline``
  reads the manifest and the document behind it, produces a series, and turns
  each change into a drift event that names both snapshots. One stored snapshot is
  not a timeline, and the report says drift is unmeasured instead of "no changes".

Two new routes expose both: ``POST /sbom/{artifact_id}/twin`` and
``GET /sbom/{artifact_id}/history``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.sbom-twin-timeline-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
AS_OF = date(2026, 11, 2)


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "graph_engine"),
                  str(SERVICES / "container_scanner"), str(SERVICES / "universal_crypto"),
                  str(SERVICES / "governance"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import sbom_evidence, sbom_timeline  # noqa: PLC0415
    from graph_engine.core.engine import GraphEngine  # noqa: PLC0415

    return {"se": sbom_evidence, "timeline": sbom_timeline, "GraphEngine": GraphEngine}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _identity(digest: str = DIGEST, reference: str = "ghcr.io/bank/payments-api") -> Any:
    return {"reference": reference, "digest": digest}


def _record(modules, *, artifact: Any = "default", components=None) -> Any:
    se = modules["se"]
    identity = None
    if artifact == "default":
        identity = se.ArtifactIdentity(**_identity())
    elif artifact is not None:
        identity = se.ArtifactIdentity(**artifact)
    return se.SbomRecord(
        "SBOM-1", identity,
        components or ({"name": "openssl", "version": "3.0.12", "crypto_relevant": True},
                       {"name": "curl", "version": "8.5.0"}),
        created_at=AS_OF)


def _observation(modules, *, digest: str = DIGEST, environment: str = "PRODUCTION") -> Any:
    se = modules["se"]
    return se.DeploymentObservation(
        deployment="payments-api-1", environment=environment,
        artifact=se.ArtifactIdentity(**_identity(digest)), workload="payments-api-1",
        observed_at=AS_OF, evidence_id="K8S-2026-1102-01")


def _cyclonedx(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


def _manifest(*, artifact_id: str = "ART-1", digest: str = "a" * 64,
              created: str = "2026-10-01", target: str = "ghcr.io/bank/payments-api",
              build: str | None = None) -> dict[str, Any]:
    manifest: dict[str, Any] = {"artifact_id": artifact_id, "sha256": digest,
                                "created_at": created, "target": target}
    if build:
        manifest["provenance"] = {"build": {"build_id": build}}
    return manifest


# --------------------------------------------------------------------------- #
# 1. the edges, and what each one is allowed to mean
# --------------------------------------------------------------------------- #


def row_twin_edges(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    declared = se.twin_edges(_record(modules))
    probes.append(_probe(
        "an-sbom-edge-stops-at-the-artifact",
        declared["edges"] and "OBSERVED" not in {
            edge["evidence_type"] for edge in declared["edges"]}
        and "no observation reaches this artifact" in declared["statement"],
        declared["statement"]))

    observed = se.twin_edges(_record(modules), deployments=[_observation(modules)])
    kinds = [edge["kind"] for edge in observed["edges"]]
    probes.append(_probe(
        "an-observation-is-what-creates-a-path-to-production",
        "DEPLOYED_AS" in kinds and "RUNS_AS" in kinds
        and any(edge["evidence_type"] == "OBSERVATION" for edge in observed["edges"]),
        f"{len(observed['edges'])} edge(s), including "
        f"{', '.join(sorted(set(kinds) & {'DEPLOYED_AS', 'RUNS_AS'}))}"))

    foreign = se.twin_edges(_record(modules), deployments=[_observation(modules, digest=OTHER_DIGEST)])
    probes.append(_probe(
        "an-observation-of-another-digest-does-not-reach-this-artifact",
        "DEPLOYED_AS" not in [edge["kind"] for edge in foreign["edges"]],
        "an observation of a different digest adds nothing to this SBOM's graph"))

    unbound = se.twin_edges(_record(modules, artifact=None), deployments=[_observation(modules)])
    probes.append(_probe(
        "an-unbound-document-cannot-be-deployed",
        "DEPLOYED_AS" not in [edge["kind"] for edge in unbound["edges"]],
        "an SBOM with no artifact digest has no path to an observation"))

    capable = se.twin_edges(_record(modules), algorithms={"openssl": ["AES-256-GCM"]})
    capability = [edge for edge in capable["edges"] if edge["kind"] == "HAS_CAPABILITY"]
    probes.append(_probe(
        "a-capability-is-inference-and-says-so",
        len(capability) == 1 and capability[0]["evidence_type"] == "CAPABILITY"
        and capability[0]["confidence"] == "LOW",
        f"{len(capability)} HAS_CAPABILITY edge(s), confidence "
        f"{capability[0]['confidence'] if capability else 'n/a'}"))

    probes.append(_probe(
        "every-edge-carries-an-evidence-id-and-a-time",
        all(edge.get("evidence_id") and edge.get("source") for edge in observed["edges"]),
        f"{len(observed['edges'])} edge(s), each with evidence_id and source"))

    return {"id": "twin_edges",
            "question": "does the graph distinguish declared from observed?",
            "phase": "review item 14", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. writing them, with provenance attached
# --------------------------------------------------------------------------- #


def row_provenance_bridge(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    edges = se.twin_edges(_record(modules), deployments=[_observation(modules)],
                          application="application:payments-api",
                          business_system="business:cards",
                          algorithms={"openssl": ["AES-256-GCM"]})["edges"]
    engine = modules["GraphEngine"]()
    applied = se.apply_twin_edges(engine, edges)
    probes.append(_probe(
        "the-whole-sbom-graph-is-written",
        applied["written"] == len(edges) and applied["refused"] == [],
        applied["statement"]))

    probes.append(_probe(
        "each-evidence-kind-earns-its-provenance-class",
        applied["by_provenance"].get("DECLARED", 0) >= 3
        and applied["by_provenance"].get("OBSERVED") == 2
        and applied["by_provenance"].get("INFERRED") == 1,
        json.dumps(applied["by_provenance"], sort_keys=True)))

    rendered = engine.to_vis()
    provenances = {edge.get("provenance") for edge in rendered["edges"]}
    probes.append(_probe(
        "the-rendered-graph-shows-the-classes",
        {"DECLARED", "OBSERVED", "INFERRED"} <= provenances,
        f"{len(rendered['nodes'])} node(s), {len(rendered['edges'])} edge(s)"))

    refs = {edge.get("evidence_ref") for edge in rendered["edges"]}
    probes.append(_probe(
        "every-written-edge-keeps-its-evidence-reference",
        None not in refs and len(refs) >= 3,
        f"{len(refs)} distinct evidence reference(s)"))

    probes.append(_probe(
        "the-nodes-are-typed-by-what-they-are",
        {node["group"] for node in rendered["nodes"]} >=
        {"SBOM", "COMPONENT", "APPLICATION", "BUSINESS_SYSTEM", "DEPLOYMENT", "WORKLOAD"},
        ", ".join(sorted({str(node["group"]) for node in rendered["nodes"]}))))

    loose = modules["GraphEngine"]()
    refused = se.apply_twin_edges(loose, [
        {"evidence_type": "SBOM", "from": "sbom:X", "kind": "CONTAINS", "to": "component:y"}])
    probes.append(_probe(
        "an-edge-with-no-evidence-is-refused-not-written",
        refused["written"] == 0 and refused["refused"] and loose.to_vis()["edges"] == [],
        refused["statement"]))

    partial = modules["GraphEngine"]()
    half = se.apply_twin_edges(partial, [
        {**edges[0], "evidence_id": ""}, edges[1]])
    probes.append(_probe(
        "one-refused-edge-does-not-stop-the-rest",
        half["written"] == 1 and len(half["refused"]) == 1,
        f"{half['written']} written, {len(half['refused'])} refused"))

    unknown = modules["GraphEngine"]()
    guessed = se.apply_twin_edges(unknown, [
        {"evidence_id": "R-1", "evidence_type": "RUMOUR", "from": "sbom:X",
         "kind": "CONTAINS", "to": "component:y"}])
    probes.append(_probe(
        "an-unknown-evidence-kind-is-visible-as-unattributed",
        guessed["by_provenance"] == {"UNATTRIBUTED": 1} and guessed["unattributed_kinds"] == 1
        and "UNATTRIBUTED" in guessed["statement"],
        guessed["statement"]))

    return {"id": "provenance_bridge",
            "question": "is the provenance class decided by the evidence, not the edge?",
            "phase": "review item 14", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. the store becomes a series
# --------------------------------------------------------------------------- #


def _document(version: str, *, extra: str | None = None) -> dict[str, Any]:
    components = [{"name": "openssl", "version": version}]
    if extra:
        components.append({"name": extra, "version": "1.0.0"})
    return _cyclonedx(components)


def row_artifact_timeline(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    timeline = modules["timeline"]
    probes: list[dict[str, Any]] = []

    record = timeline.record_from_document(_manifest(), _document("3.0.12"))
    probes.append(_probe(
        "a-stored-manifest-and-its-document-become-a-snapshot",
        record.sbom_id == "ART-1" and record.artifact is not None
        and record.component("openssl")["version"] == "3.0.12"
        and record.created_at == date(2026, 10, 1),
        f"{record.sbom_id} at {record.created_at}, bound to {record.artifact.digest}"))

    spdx = timeline.record_from_document(
        _manifest(), {"spdxVersion": "SPDX-2.3",
                      "packages": [{"name": "openssl", "versionInfo": "3.0.12"}]})
    probes.append(_probe(
        "an-spdx-document-produces-the-same-shape",
        spdx.component("openssl")["version"] == "3.0.12",
        f"{len(spdx.components)} component(s) from SPDX"))

    unbound = timeline.record_from_document(_manifest(digest=""), _document("3.0.12"))
    probes.append(_probe(
        "a-manifest-with-no-digest-binds-the-document-to-nothing",
        unbound.artifact is None,
        "no artifact identity is claimed for a manifest with no sha256"))

    crypto = timeline.record_from_document(
        _manifest(), _cyclonedx([{"name": "openssl", "version": "3.0.12"}]))
    probes.append(_probe(
        "the-scanners-own-crypto-registry-is-read",
        crypto.component("openssl")["crypto_relevant"] is True,
        "openssl is crypto-relevant by the registry the scanner ships"))

    two = timeline.timeline([
        (_manifest(artifact_id="ART-1", created="2026-10-01"), _document("3.0.12", extra="curl")),
        (_manifest(artifact_id="ART-2", digest="b" * 64, created="2026-10-15"),
         _document("3.0.13")),
    ], target="ghcr.io/bank/payments-api")
    probes.append(_probe(
        "two-snapshots-produce-a-change-with-both-ends-named",
        two["changed_transitions"] == 1
        and any(event["type"] == "VERSION_CHANGED" and event["from"] == "3.0.12"
                and event["to"] == "3.0.13" for event in two["events"]),
        f"{two['event_counts']}"))

    probes.append(_probe(
        "the-input-order-does-not-decide-the-timeline",
        timeline.timeline([
            (_manifest(artifact_id="ART-2", digest="b" * 64, created="2026-10-15"),
             _document("3.0.13")),
            (_manifest(artifact_id="ART-1", created="2026-10-01"),
             _document("3.0.12", extra="curl")),
        ])["events"] == two["events"],
        two["statement"]))

    single = timeline.timeline([(_manifest(), _document("3.0.12"))])
    probes.append(_probe(
        "one-snapshot-reports-drift-as-unmeasured",
        single["events"] == [] and "drift is unmeasured" in single["statement"]
        and "no change" not in single["statement"],
        single["statement"]))

    same = timeline.timeline([
        (_manifest(artifact_id="ART-1"), _document("3.0.12")),
        (_manifest(artifact_id="ART-2", created="2026-10-15"), _document("3.0.12")),
    ])
    probes.append(_probe(
        "identical-snapshots-are-no-drift-not-unmeasured",
        same["transitions"][0]["changes"] == []
        and "drift is unmeasured" not in same["statement"],
        same["statement"]))

    same_day = timeline.timeline([
        (_manifest(artifact_id="ART-b", created="2026-10-01T09:00:00+00:00"),
         _document("3.0.12")),
        (_manifest(artifact_id="ART-a", digest="b" * 64, created="2026-10-01T17:00:00+00:00"),
         _document("3.0.13")),
    ])
    probes.append(_probe(
        "two-snapshots-on-the-same-day-keep-their-stored-order",
        same_day["snapshots"] == ["ART-b", "ART-a"]
        and same_day["events"][0]["from"] == "3.0.12",
        f"{same_day['snapshots']} from the stored timestamps, not from the ids"))

    probes.append(_probe(
        "the-gap-between-snapshots-is-reported",
        two["gap_days"] == 14, f"{two['gap_days']} day(s)"))

    return {"id": "artifact_timeline",
            "question": "can the store answer what moved, between which artifacts?",
            "phase": "review items 12 / 15", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. the drift feed
# --------------------------------------------------------------------------- #


def row_drift_feed(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    timeline = modules["timeline"]
    probes: list[dict[str, Any]] = []

    report = timeline.timeline([
        (_manifest(artifact_id="ART-1", created="2026-10-01", build="BUILD-7"),
         _document("3.0.12", extra="curl")),
        (_manifest(artifact_id="ART-2", digest="b" * 64, created="2026-10-15",
                   build="BUILD-9"), _document("3.0.13")),
    ], target="ghcr.io/bank/payments-api")
    events = report["events"]
    probes.append(_probe(
        "each-change-becomes-an-event-a-drift-engine-can-consume",
        bool(events) and all({"type", "component", "from", "to", "from_sbom", "to_sbom", "at"}
                             <= set(event) for event in events),
        f"{len(events)} event(s): {report['event_counts']}"))

    version_event = next(event for event in events if event["type"] == "VERSION_CHANGED")
    probes.append(_probe(
        "an-event-names-the-two-artifacts-it-sits-between",
        (version_event["from_sbom"], version_event["to_sbom"]) == ("ART-1", "ART-2")
        and version_event["at"] == "2026-10-15",
        f"{version_event['from_sbom']} -> {version_event['to_sbom']} at {version_event['at']}"))

    artifact_events = [event for event in events if event["artifact_level"]]
    probes.append(_probe(
        "a-change-to-the-artifact-is-not-reported-as-a-component",
        bool(artifact_events) and all(event["component"] is None for event in artifact_events),
        f"{len(artifact_events)} artifact-level event(s)"))

    probes.append(_probe(
        "the-event-counts-add-up-to-the-events",
        sum(report["event_counts"].values()) == len(events),
        f"{sum(report['event_counts'].values())} counted, {len(events)} emitted"))

    quiet = timeline.timeline([(_manifest(), _document("3.0.12"))])
    probes.append(_probe(
        "a-single-snapshot-emits-no-events-and-says-why",
        timeline.drift_events(quiet) == [] and "unmeasured" in quiet["statement"],
        quiet["statement"]))

    probes.append(_probe(
        "the-component-series-keeps-every-version-with-its-snapshot",
        [row["version"] for row in report["components"]["openssl"]] == ["3.0.12", "3.0.13"]
        and [row["sbom"] for row in report["components"]["openssl"]] == ["ART-1", "ART-2"],
        f"{len(report['components'])} component series"))

    probes.append(_probe(
        "the-schema-is-declared-on-every-report",
        timeline.timeline([])["schema"] == timeline.SCHEMA == "cryptoscan.sbom-timeline/1",
        timeline.SCHEMA))

    probes.append(_probe(
        "an-empty-store-is-an-empty-timeline-not-an-error",
        timeline.timeline([])["snapshots"] == [] and "unmeasured" in timeline.timeline([])["statement"],
        timeline.timeline([])["statement"]))

    return {"id": "drift_feed",
            "question": "can a drift engine consume this without a human reading it?",
            "phase": "review item 12", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. the API surface
# --------------------------------------------------------------------------- #


def row_api_exposure(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "devsecops.py").read_text(encoding="utf-8")
    probes: list[dict[str, Any]] = []

    probes.append(_probe(
        "the-twin-edges-are-reachable",
        '@router.post("/sbom/{artifact_id}/twin"' in router
        and "response_model=SbomTwinResponse" in router,
        "POST /sbom/{artifact_id}/twin is declared"))

    probes.append(_probe(
        "the-history-is-reachable",
        '@router.get("/sbom/{artifact_id}/history"' in router
        and "response_model=SbomHistoryResponse" in router,
        "GET /sbom/{artifact_id}/history is declared"))

    probes.append(_probe(
        "both-routes-are-typed",
        "class SbomTwinResponse(BaseModel)" in router
        and "class SbomHistoryResponse(BaseModel)" in router,
        "both responses are Pydantic models, so the untyped inventory is unchanged"))

    probes.append(_probe(
        "the-schema-key-is-not-renamed-by-the-response-model",
        'schema_: str = Field(alias="schema")' in router,
        "the report's `schema` key survives response validation"))

    probes.append(_probe(
        "the-twin-route-can-bind-a-digest-and-carry-observations",
        "image_digest: str | None = Field" in router
        and "observations: list[dict] | None = Field" in router,
        "an operator can bind the stored SBOM to a digest and hand it observations"))

    probes.append(_probe(
        "the-twin-route-uses-the-real-graph-engine",
        "from graph_engine.core.engine import GraphEngine" in router
        and "engine.to_vis()" in router,
        "the response carries the graph the engine would render"))

    probes.append(_probe(
        "the-history-route-reads-the-store-not-the-request",
        "_visible_manifests(store, tenant_id=tenant)" in router
        and 'row.get("target") == target' in router,
        "history is scoped to the tenant and to the artifact's target"))

    probes.append(_probe(
        "both-routes-require-the-existing-sbom-roles",
        router.count("_SBOM_READERS") >= 2,
        "no new permission surface was invented for these reads"))

    return {"id": "api_exposure",
            "question": "can a caller reach these answers through the API?",
            "phase": "review items 12 / 14", "probes": probes}


ROWS = (row_twin_edges, row_provenance_bridge, row_artifact_timeline, row_drift_feed,
        row_api_exposure)


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
            "provenance is a classification of the evidence, not a judgement of it: an SBOM "
            "edge marked DECLARED is only as true as the document, and the graph saying "
            "OBSERVED means somebody reported an observation, not that the observation is right",
            "the twin writes what it is given. A deployment observation supplied by a caller "
            "can be fabricated, which is why the evidence id and observed_at travel onto the "
            "edge rather than being summarised away",
            "HAS_CAPABILITY is inference from a name-based registry: a component that can do "
            "AES is not a component that uses AES, and the edge keeps confidence LOW for that "
            "reason",
            "the timeline is built from stored manifests for one target. Two targets with the "
            "same components produce two separate timelines, and nothing here decides whether "
            "an artifact change is a release or a rebuild",
            "drift events describe what the documents say changed. A component whose version "
            "is identical but whose bytes differ is invisible to a component-level diff",
            "retention is the store's policy: a history is only as long as the artifacts that "
            "were kept, so a pruned series can report fewer transitions without anything "
            "having been stable",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The SBOM reaches the graph, and the store becomes a timeline",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 137 stopped the gate believing a document. What it left, and what this "
        "artifact measures, is the gap between *declared* and *observed*:",
        "",
        "1. **The twin had edges nobody wrote.** `twin_edges` produced them with an evidence "
        "id; `apply_twin_edges` now writes them into the graph with the provenance class the "
        "evidence earns — SBOM → `DECLARED`, observation → `OBSERVED`, capability → "
        "`INFERRED` — and refuses any edge that carries no evidence at all.",
        "2. **History lived in a list, not in the store.** `sbom_timeline` reads the stored "
        "manifest and the document behind it, produces the series, and turns each change into "
        "a drift event naming both snapshots. One snapshot reports drift as *unmeasured* "
        "rather than as no change.",
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
