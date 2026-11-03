#!/usr/bin/env python3
"""Guide 177 — live collection: real payloads → a chain that can be walked.

Guides 175 and 176 built the chain, and then built it from a store. Both started after the
gathering had happened. This guide starts at the payloads a bank's own systems actually
return — a git API answer, a pipeline run, an OCI manifest, a scanner's package list, a
cluster's Deployment objects, a process trace, a CycloneDX component list, a host agent's
dpkg inventory — and ends at the twelve levels, with the class each one supports stated.

    payload → collector → inventory → estate → chain

The five rules every collector obeys, and what this harness measures:

1. the transport decides the class — an API answer is ``CONFIGURED``, a scan is
   ``STATIC_OBSERVED``, and only a probe is ``OBSERVED``;
2. identity comes from the immutable field — a sha, a digest, a purl at a version;
3. every row carries the evidence reference that produced it;
4. two transports that disagree are a finding, not an overwrite;
5. a stale read is imported and labelled, never called live.
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
SCHEMA = "cryptoscan.sbom-live-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

NOW = "2026-11-03T08:30:00Z"
RECENT = "2026-11-03T06:30:00Z"
STALE = "2026-10-24T06:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"

DIGEST_JAR = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"
DIGEST_OTHER = "sha256:99999999aaaabbbbccccddddeeeeffff"
LAYER = "sha256:aa11bb22cc33dd44ee55ff66aa77bb88"

REPO = "bank/payments-api"
OPENSSL = "pkg:generic/openssl"
OPENSSL_VERSION = "3.0.13"
SDK = "pkg:generic/payments-sdk"
HTTP = "pkg:generic/http-core"

PAYLOADS: dict[str, dict[str, Any]] = {
    "git": {
        "transport": "git", "collected_at": RECENT,
        "repository": {"full_name": REPO, "url": "https://git.bank.internal/bank/payments-api",
                       "default_branch": "main", "applications": ["Payments API"]},
        "commits": [{"sha": "a81f92c", "author": "payments-team", "committed_at": EARLIER,
                     "message": "harden card data path"},
                    {"branch": "main", "author": "payments-team"}],
    },
    "ci": {
        "transport": "ci", "collected_at": RECENT,
        "build": {"name": "BUILD-18291", "commit": "a81f92c", "repository": REPO,
                  "pipeline": "jenkins-payments-ci", "status": "SUCCESS"},
        "artifacts": [{"name": "payments-api-4.2.1.jar", "digest": DIGEST_JAR, "kind": "JAR"},
                      {"name": "payments-api.jar"}],
    },
    "registry": {
        "transport": "registry", "collected_at": RECENT,
        "image": {"repository": "payments-api", "tag": "4.2.1", "digest": DIGEST_IMAGE},
        "layers": [{"digest": LAYER, "size": 74_000_000, "media_type": "application/vnd.oci"}],
    },
    "scan": {
        "transport": "scan", "collected_at": RECENT,
        "image": {"name": "payments-api:4.2.1", "digest": DIGEST_IMAGE},
        "packages": [
            {"coordinate": OPENSSL, "name": "openssl", "version": OPENSSL_VERSION, "crypto": True},
            {"coordinate": SDK, "name": "payments-sdk", "version": "2.4.0"},
            {"coordinate": HTTP, "name": "http-core", "version": "1.2.0"},
        ],
    },
    "kubernetes": {
        "transport": "kubernetes", "collected_at": RECENT,
        "cluster": "prod-cluster",
        "nodes": [{"name": "node-03", "host": "srv-k8s-03", "datacenter": "Mumbai-DC2"}],
        "deployments": [{"name": "payments-api-deploy", "namespace": "payments",
                         "replica_set": "payments-api-7d9f4c",
                         "image": "payments-api:4.2.1",
                         "pods": [{"name": "payments-api-7d9f4c-x2m8p", "node": "node-03",
                                   "host": "srv-k8s-03",
                                   "containers": ["payments-api-ctr"]}]},
                        {"name": "ghost-deploy", "namespace": "payments"}],
    },
    "process": {
        "transport": "process", "collected_at": NOW,
        "host": "node-03",
        "processes": [{"name": "payments-api[1821]", "pid": 1821,
                       "application": "Payments API", "pod": "payments-api-7d9f4c-x2m8p",
                       "libraries": [{"name": "libcrypto.so.3", "package": "pkg:generic/openssl",
                                      "version": "3.0.11", "crypto": True,
                                      "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                                      "sha256": "sha256:1f2e3d4c5b6a7988"},
                                     {"name": "libssl.so.3", "package": "pkg:generic/openssl",
                                      "version": "3.0.11", "crypto": True}],
                       "operations": [
                           {"operation": "SIGN", "algorithm": "RSA", "family": "RSA",
                            "key_size": 2048, "hash": "SHA-256",
                            "purpose": "payment instruction signature",
                            "observed_at": NOW},
                           {"operation": "ENCRYPT", "algorithm": "AES", "family": "AES",
                            "key_size": 256, "mode": "GCM", "observed_at": NOW}]}],
    },
    "sbom": {
        "transport": "sbom", "collected_at": RECENT,
        "document": "SBOM-18291", "artifact": "payments-api-4.2.1.jar", "tool": "syft-1.18",
        "components": [
            {"purl": f"{OPENSSL}@{OPENSSL_VERSION}", "name": "openssl", "version": OPENSSL_VERSION,
             "component_type": "library", "crypto_bearing": True,
             "product": "OpenSSL 3.x", "scope": "RUNTIME", "direct": False},
            {"purl": f"{SDK}@2.4.0", "name": "payments-sdk", "version": "2.4.0", "direct": True,
             "depends_on": [HTTP]},
            {"purl": f"{HTTP}@1.2.0", "name": "http-core", "version": "1.2.0",
             "depends_on": [OPENSSL]},
            {"name": "left-pad", "version": "^1.3.0"},
            {"name": "mystery"},
        ],
    },
    "host": {
        "transport": "host", "collected_at": RECENT,
        "host": "srv-lb-01", "os": "Ubuntu 22.04", "type": "PHYSICAL_SERVER",
        "packages": [{"name": "openssl-dev", "version": "3.0.13", "crypto": True},
                     {"name": "nginx", "version": "1.24.0"}],
    },
    "cmdb": {
        "transport": "cmdb", "collected_at": RECENT, "source": "service-registry",
        "applications": [
            {"id": "APP-9281", "name": "Payments API", "system": "Payments System",
             "owner": "payments-team", "criticality": "TIER-1"},
            {"id": "APP-9310", "name": "Reporting API", "system": "Payments System"},
            {"name": "Unregistered Thing"},
        ],
    },
}


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import sbom_collectors, sbom_dependency, sbom_supply, techbom  # noqa: PLC0415

    return {"c": sbom_collectors, "s": sbom_dependency, "su": sbom_supply, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _payloads() -> list[dict[str, Any]]:
    """The payloads, in the order a bank reads them, plus two the platform must refuse."""
    ordered = ["cmdb", "git", "ci", "registry", "scan", "kubernetes", "process", "sbom",
               "host"]
    return [
        *[PAYLOADS[key] for key in ordered],
        {**PAYLOADS["git"], "transport": "spreadsheet", "collected_at": RECENT},
    ]


def measure() -> dict[str, Any]:
    modules = _load()
    c, s = modules["c"], modules["s"]
    results = c.collect_all(_payloads(), as_of=NOW)
    by_transport = {result["transport"]: result for result in results}
    collected = c.collect(*results, as_of=NOW)
    built = c.assemble(*results, as_of=NOW, environment="PRODUCTION",
                       estate_id="live:production")
    bom = built["bom"]
    levels = built["levels"]

    points: list[dict[str, Any]] = []

    def add(number: int, phase: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"LIVE-{number:02d}", "number": number, "phase": phase,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    # ---- 1. git ------------------------------------------------------------ #
    git = by_transport["git"]
    add(1, "source", "a repository and a commit are read from the git host's own answer", [
        _probe("the-repository-row-carries-its-name",
               git["rows"]["repositories"][0]["name"] == REPO,
               git["rows"]["repositories"][0]["evidence_ref"]),
        _probe("the-commit-is-identified-by-its-sha",
               git["rows"]["commits"][0]["sha"] == "a81f92c",
               git["rows"]["commits"][0]["evidence_ref"]),
        _probe("a-branch-name-is-not-an-identity",
               any(row["code"] == "MUTABLE_IDENTITY" for row in git["refusals"]),
               git["refusals"][0]["reason"]),
    ])

    # ---- 2. CI ------------------------------------------------------------- #
    ci = by_transport["ci"]
    add(2, "build", "a build names its commit and an artifact anchors on its digest", [
        _probe("the-build-names-the-commit",
               ci["rows"]["builds"][0]["commit"] == "a81f92c",
               ci["rows"]["builds"][0]["evidence_ref"]),
        _probe("the-artifact-carries-a-digest",
               ci["rows"]["artifacts"][0]["digest"] == DIGEST_JAR,
               ci["rows"]["artifacts"][0]["name"]),
        _probe("an-artifact-with-only-a-name-is-refused",
               any(row["code"] == "ARTIFACT_WITHOUT_DIGEST" for row in ci["refusals"]),
               next(row["reason"] for row in ci["refusals"]
                    if row["code"] == "ARTIFACT_WITHOUT_DIGEST")),
    ])

    # ---- 3. registry ------------------------------------------------------- #
    registry = by_transport["registry"]
    add(3, "image", "the registry's digest is the identity and the tag is recorded beside it", [
        _probe("the-image-is-anchored-on-its-digest",
               registry["rows"]["images"][0]["digest"] == DIGEST_IMAGE,
               registry["rows"]["images"][0]["evidence_ref"]),
        _probe("the-tag-is-kept-as-a-pointer-not-an-identity",
               registry["rows"]["images"][0]["tag"] == "4.2.1",
               registry["rows"]["images"][0]["name"]),
        _probe("a-registry-that-returns-only-a-tag-is-refused",
               c.from_registry({"image": {"repository": "payments-api", "tag": "latest"}}
                               )["refusals"][0]["code"] == "IMAGE_WITHOUT_DIGEST",
               "IMAGE_WITHOUT_DIGEST"),
    ])

    # ---- 4. the scan ------------------------------------------------------- #
    scan = by_transport["scan"]
    add(4, "image", "a scanner says what is installed in a digest, one class above the SBOM", [
        _probe("the-scan-lists-the-packages-it-found",
               len(scan["rows"]["software"]) == 3,
               ", ".join(row["coordinate"] for row in scan["rows"]["software"])),
        _probe("the-scan-is-STATIC_OBSERVED",
               scan["class"] == "STATIC_OBSERVED", f"class {scan['class']}"),
        _probe("the-image-row-names-what-is-installed",
               len(scan["rows"]["images"][0]["installed"]) == 3,
               str(scan["rows"]["images"][0]["installed"])),
    ])

    # ---- 5. kubernetes ----------------------------------------------------- #
    kubernetes = by_transport["kubernetes"]
    add(5, "deployment", "a Deployment is metadata, and it stops at the pod", [
        _probe("the-deployment-names-its-image-and-pods",
               kubernetes["rows"]["deployments"][0]["image"] == "payments-api:4.2.1"
               and len(kubernetes["rows"]["deployments"][0]["pods"]) == 1,
               kubernetes["rows"]["deployments"][0]["evidence_ref"]),
        _probe("the-class-is-CONFIGURED-not-OBSERVED",
               kubernetes["class"] == "CONFIGURED" and not kubernetes["observed"],
               f"class {kubernetes['class']}"),
        _probe("a-deployment-with-no-image-is-refused",
               any(row["code"] == "DEPLOYMENT_WITHOUT_IMAGE" for row in kubernetes["refusals"]),
               next(row["reason"] for row in kubernetes["refusals"]
                    if row["code"] == "DEPLOYMENT_WITHOUT_IMAGE")),
    ])

    # ---- 6. the probe ------------------------------------------------------ #
    probe = by_transport["process"]
    add(6, "runtime", "a trace is the only transport that may say OBSERVED", [
        _probe("the-probe-is-OBSERVED", probe["class"] == "OBSERVED" and probe["observed"],
               f"class {probe['class']}"),
        _probe("the-loaded-object-names-the-package-that-ships-it",
               probe["rows"]["processes"][0]["loads"] == ["pkg:generic/openssl",
                                                          "pkg:generic/openssl"],
               str(probe["rows"]["processes"][0]["loads"])),
        _probe("the-runtime-version-is-kept-as-a-runtime-source",
               probe["rows"]["software"][0]["version_sources"][0]["source"] == "process-map",
               str(probe["rows"]["software"][0]["version_sources"])),
    ])

    # ---- 7. the SBOM ------------------------------------------------------- #
    sbom = by_transport["sbom"]
    add(7, "component", "an SBOM imports components at IMPORTED and refuses a range", [
        _probe("the-pinned-components-arrive",
               {row["coordinate"] for row in sbom["rows"]["software"]} ==
               {OPENSSL, SDK, HTTP},
               ", ".join(row["coordinate"] for row in sbom["rows"]["software"])),
        _probe("a-range-is-refused-as-a-version",
               any(row["code"] == "UNPINNED_VERSION" for row in sbom["refusals"]),
               next(row["reason"] for row in sbom["refusals"]
                    if row["code"] == "UNPINNED_VERSION")),
        _probe("the-dependency-edges-travel-with-the-components",
               {(row["source"], row["target"]) for row in sbom["rows"]["dependencies"]} ==
               {(SDK, HTTP), (HTTP, OPENSSL)},
               str([(row["source"], row["target"]) for row in sbom["rows"]["dependencies"]])),
    ])

    # ---- 8. the host inventory --------------------------------------------- #
    host = by_transport["host"]
    add(8, "host", "an agent's inventory is a filesystem fact on a named host", [
        _probe("the-host-is-named", host["rows"]["hosts"][0]["name"] == "srv-lb-01",
               host["rows"]["hosts"][0]["evidence_ref"]),
        _probe("the-host-says-what-it-holds",
               len(host["rows"]["hosts"][0]["installed"]) == 2,
               str(host["rows"]["hosts"][0]["installed"])),
        _probe("an-inventory-with-no-host-is-refused",
               c.from_host_inventory({"packages": [{"name": "x", "version": "1"}]}
                                     )["refusals"][0]["code"] == "NO_IDENTITY",
               "NO_IDENTITY"),
    ])

    # ---- 9. the class ceiling ---------------------------------------------- #
    ceiling = {transport: c.TRANSPORTS[transport] for transport in c.TRANSPORTS}
    observed = sorted(transport for transport, result in by_transport.items()
                      if isinstance(result, dict) and result.get("observed"))
    add(9, "evidence", "no transport claims a class stronger than it can support", [
        _probe("only-the-probe-is-OBSERVED", observed == ["process"], str(observed)),
        _probe("every-collector-states-its-basis",
               all(result.get("basis") in ceiling.values() for result in by_transport.values()
                   if result.get("basis")),
               ", ".join(f"{name} {result['basis']}" for name, result in
                         sorted(by_transport.items()) if result.get("basis"))),
        _probe("an-unknown-transport-is-refused-by-name",
               any(row["code"] == "UNKNOWN_TRANSPORT" for row in collected["refusals"]),
               next((row["reason"] for row in collected["refusals"]
                     if row["code"] == "UNKNOWN_TRANSPORT"), "—")),
    ])

    # ---- 10. the merge ------------------------------------------------------ #
    add(10, "merge", "two transports describing one component are merged, not duplicated", [
        _probe("openssl-is-one-row-with-two-version-sources",
               sum(1 for row in collected["inventory"]["software"]
                   if row.get("coordinate") == "pkg:generic/openssl") == 1,
               str([row.get("version_sources") for row in collected["inventory"]["software"]
                    if row.get("coordinate") == "pkg:generic/openssl"])),
        _probe("the-observations-are-all-kept",
               {entry["source"] for entry in
                next(row["version_sources"] for row in collected["inventory"]["software"]
                     if row.get("coordinate") == "pkg:generic/openssl")}
               == {"sbom", "image-scan", "process-map"},
               str([(entry["source"], entry["value"]) for entry in
                    next(row["version_sources"] for row in collected["inventory"]["software"]
                         if row.get("coordinate") == "pkg:generic/openssl")])),
        _probe("the-merge-states-what-it-read",
               "transport(s)" in collected["statement"], collected["statement"]),
    ])

    # ---- 11. disagreement --------------------------------------------------- #
    dr = c.from_registry({"collected_at": RECENT,
                          "image": {"repository": "payments-api", "tag": "4.2.1",
                                    "digest": DIGEST_OTHER}}, )
    disagreeing = c.collect(registry, dr, as_of=NOW)
    add(11, "merge", "a disagreement between two reads is a finding, not an overwrite", [
        _probe("the-disagreement-is-recorded",
               any(row["code"] == "COLLECTOR_DISAGREEMENT"
                   for row in disagreeing["conflicts"]),
               disagreeing["statement"]),
        _probe("neither-read-wins",
               disagreeing["conflicts"][0]["kept"] == DIGEST_IMAGE
               and disagreeing["conflicts"][0]["reported"] == DIGEST_OTHER,
               f"{disagreeing['conflicts'][0]['kept']} vs "
               f"{disagreeing['conflicts'][0]['reported']}"),
        _probe("only-one-row-survives-into-the-inventory",
               len(disagreeing["inventory"]["images"]) == 1,
               str(len(disagreeing["inventory"]["images"]))),
    ])

    # ---- 12. freshness ------------------------------------------------------ #
    stale_result = c.from_git({**PAYLOADS["git"], "collected_at": STALE}, collected_at=STALE)
    fresh = c.freshness(by_transport["git"], as_of=NOW)
    old = c.freshness(stale_result, as_of=NOW)
    stale_merge = c.collect(by_transport["git"], stale_result, as_of=NOW)
    add(12, "freshness", "a stale read is imported and labelled, never called live", [
        _probe("a-read-this-morning-is-live", fresh["stale"] is False, fresh["statement"]),
        _probe("a-read-last-week-is-stale", old["stale"] is True, old["statement"]),
        _probe("the-stale-rows-are-still-imported",
               stale_merge["counts"]["stale"] >= 1
               and stale_merge["inventory"]["repositories"],
               stale_merge["statement"]),
    ])

    # ---- 13. the chain ------------------------------------------------------ #
    add(13, "chain", "the payloads assemble into every level of the twelve-level chain", [
        _probe("every-level-is-populated",
               all(levels[name] for _, name in s.SUPPLY_LEVELS),
               ", ".join(f"{name} {count}" for name, count in levels.items())),
        _probe("the-chain-builds-without-a-refusal", bom.get("refusals") == [],
               f"{len(bom.get('refusals') or [])} refusal(s)"),
        _probe("the-projection-says-where-it-came-from",
               bom.get("source_of_truth") == "CANONICAL_ESTATE",
               f"{bom.get('source_of_truth')} / {bom.get('derived_from')}"),
    ])

    # ---- 14. the readers answer on live data -------------------------------- #
    provenance = s.provenance(bom, artifact="payments-api-4.2.1.jar")
    owners = s.component_owners(bom, query="pkg:generic/openssl")
    versions = s.version_layers(bom, query="pkg:generic/openssl")
    add(14, "chain", "the chain answers the questions it exists for, from live rows", [
        _probe("provenance-reaches-the-commit-and-the-build",
               provenance["complete"] and provenance["steps"]["commit"] == "a81f92c"
               and provenance["steps"]["build"] == "BUILD-18291",
               provenance["statement"]),
        _probe("the-component-names-the-application-that-owns-it",
               owners["applications"] == ["Payments API"], owners["statement"]),
        _probe("two-transports-produce-a-version-conflict-not-a-winner",
               versions["conflict"] and versions["layers"]["DECLARED_VERSION"] == "3.0.13"
               and versions["layers"]["RUNTIME_VERSION"] == "3.0.11",
               versions["statement"]),
    ])

    # ---- 15. the states ----------------------------------------------------- #
    states = s.component_states(bom, query="pkg:generic/openssl")
    deployment = s.deployment_state(bom, query=OPENSSL)
    tree = s.dependency_tree(bom, query="Payments API")
    add(15, "chain", "installed, loaded and used stay apart, and directness keeps its path", [
        _probe("the-component-is-installed-and-loaded",
               {"INSTALLED", "LOADED"} <= set(states["present"]), states["statement"]),
        _probe("the-component-reaches-its-deployment",
               deployment["states"]["DEPLOYED"] is True, deployment["statement"]),
        _probe("the-transitive-path-is-printed",
               any(row["component"] == "pkg:generic/openssl" and len(row["path"]) == 3
                   for row in tree["transitive"]), tree["statement"]),
    ])

    # ---- 16. what was refused is visible ------------------------------------ #
    refused_subjects = {row["subject"] for row in collected["refusals"]}
    asset_names = {row["name"] for row in bom["assets"]}
    add(16, "honesty", "a refused row never becomes an asset, and the refusals are published", [
        _probe("the-refused-artifact-is-not-in-the-chain",
               "payments-api.jar" not in asset_names, "payments-api.jar absent"),
        _probe("the-unpinned-component-is-not-in-the-chain",
               "left-pad" not in asset_names and "mystery" not in asset_names,
               "left-pad and mystery absent"),
        _probe("every-refusal-names-its-transport",
               all(row.get("transport") for row in collected["refusals"])
               and len(refused_subjects) >= 4,
               f"{len(collected['refusals'])} refusal(s) across "
               f"{len({row['transport'] for row in collected['refusals']})} transport(s)"),
    ])

    rows = points
    counts = {state: len([row for row in rows if row["verdict"] == state])
              for state in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "points_present": counts[VERDICT_PASS],
        "statement": (f"{counts[VERDICT_PASS]} of {len(rows)} points of live collection hold, "
                      f"across {sum(len(row['probes']) for row in rows)} probes; "
                      f"{collected['counts']['rows']} row(s) from "
                      f"{collected['counts']['transports']} transport(s), "
                      f"{collected['counts']['refusals']} refusal(s), "
                      f"{len(bom['assets'])} asset(s) in the chain"),
        "transports": {name: {"class": result["class"], "basis": result["basis"],
                              "rows": result["counts"],
                              "freshness": c.freshness(result, as_of=NOW),
                              "statement": result["statement"]}
                       for name, result in sorted(by_transport.items())
                       if result.get("basis")},
        "collected": {"statement": collected["statement"],
                      "counts": collected["counts"],
                      "refusals": collected["refusals"],
                      "conflicts": disagreeing["conflicts"]},
        "levels": levels,
        "rows": rows,
        "provenance": provenance,
        "owners": owners,
        "versions": versions,
        "states": states,
        "deployment": deployment,
        "tree": tree,
        "chain_statement": built["statement"],
        "limits": [
            "the payloads are recorded answers from each system, not live calls: the collectors "
            "are proven against the shapes those systems return, not against a running estate",
            "a collector reads one answer at one moment; nothing here polls, retries or "
            "reconciles a partial read, and freshness is the only statement about age",
            "the class ceiling is stated per transport, so a collector cannot claim more than "
            "its transport — but a transport that lies is a trust question, not a code one",
            "an SBOM's declared version and a probe's runtime version are two rows: the chain "
            "keeps the conflict and does not decide which one the bank is running",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Live collection: payloads, transports and the chain they build",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['counts'][VERDICT_PASS]} pass · {report['counts'][VERDICT_PARTIAL]} partial"
        f" · {report['counts'][VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "```",
        "payload → collector → inventory → estate → chain",
        "BUSINESS SYSTEM → APPLICATION → REPOSITORY → COMMIT → BUILD → ARTIFACT",
        "    → IMAGE → DEPLOYMENT → POD / HOST → PROCESS → COMPONENT → CAPABILITY",
        "```",
        "",
        "| Transport | Basis | Class | Rows | Freshness |",
        "|---|---|---|---|---|",
    ]
    for name, entry in report["transports"].items():
        rows = ", ".join(f"{section} {count}" for section, count in entry["rows"].items())
        lines.append(f"| `{name}` | `{entry['basis']}` | `{entry['class']}` | {rows} | "
                     f"{entry['freshness']['statement']} |")
    lines += ["", "| Level | Nodes |", "|---|---|"]
    for name, count in report["levels"].items():
        lines.append(f"| `{name}` | {count} |")

    lines += ["", "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")

    lines += ["", "## What was refused while collecting", ""]
    for row in report["collected"]["refusals"]:
        lines.append(f"- `{row['transport']}` — {row['subject']}: {row['reason']} "
                     f"(`{row['code']}`)")
    if not report["collected"]["refusals"]:
        lines.append("- nothing")
    if report["collected"]["conflicts"]:
        lines += ["", "## Where two reads disagreed", ""]
        for row in report["collected"]["conflicts"]:
            lines.append(f"- `{row['asset']}` {row['field']}: kept `{row['kept']}` "
                         f"({row['kept_from']}), also reported `{row['reported']}` "
                         f"({row['reported_from']})")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 177, {row['phase']})", ""]
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
