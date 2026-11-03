#!/usr/bin/env python3
"""Guide 176 — the SBOM chain read from the store, seventeen points, one build.

Guide 175 built the twelve levels from a fixture. This guide starts at the other end: a
gathered *inventory*, the shape the platform already stores, is handed to
``cbom.sbom_supply.from_inventory`` and the chain has to appear out of it — with the same
refusals, the same classes and the same gaps.

    BUSINESS SYSTEM → APPLICATION → REPOSITORY → COMMIT → BUILD → ARTIFACT
        → IMAGE → DEPLOYMENT → POD / NODE / HOST → PROCESS → COMPONENT → CAPABILITY

The inventory below is deliberately imperfect, because a real one is: a software row with no
identity, a row asking for a probe class it cannot evidence, a layer shipping a package the
inventory does not hold, a dependency naming a component nobody recorded, an SBOM whose
artifact has only a tag. Each one has to be *reported*, not repaired.
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
SCHEMA = "cryptoscan.sbom-supply-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID_SRC = "EVID-97001"
EVID_CI = "EVID-97002"
EVID_SBOM = "EVID-97003"
EVID_IMG = "EVID-97004"
EVID_K8S = "EVID-97005"
EVID_RT = "EVID-97006"
EVID_HSM = "EVID-97007"
EVID_NET = "EVID-97008"

NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"

DIGEST_ARTIFACT = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"
DIGEST_OLD = "sha256:00112233445566778899aabbccddeeff"

SDK = "pkg:generic/payments-sdk@2.4.0"
HTTP = "pkg:generic/http-core@1.2.0"
OPENSSL = "pkg:generic/openssl"
OPENSSL_DEV = "pkg:generic/openssl-dev"
MAVEN = "pkg:generic/maven@3.9.6"
MOCKITO = "pkg:generic/mockito@5.4.0"
GHOST = "pkg:generic/ghost@0.0.9"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import (  # noqa: PLC0415
        digital_twin, sbom_dependency, sbom_supply, techbom,
    )

    return {"s": sbom_dependency, "su": sbom_supply, "twin": digital_twin, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# The inventory: what the store returns, including the rows it gets wrong
# --------------------------------------------------------------------------- #

def _inventory(*, moved: bool = True) -> dict[str, Any]:
    """A gathered inventory. ``moved=False`` is the projection before the upgrade."""
    software: list[dict[str, Any]] = [
        {"coordinate": SDK, "name": "payments-sdk", "version": "2.4.0", "origin": "SBOM",
         "scope": "RUNTIME", "direct": True, "evidence_ref": EVID_SBOM},
        {"coordinate": OPENSSL, "name": "openssl", "version": "3.0.13", "origin": "SBOM",
         "scope": "RUNTIME", "component_type": "library", "crypto_bearing": True,
         "product": "OpenSSL 3.x", "evidence_ref": EVID_SBOM,
         "version_sources": [
             {"source": "sbom", "value": "3.0.13", "class": "IMPORTED",
              "evidence_id": EVID_SBOM},
             {"source": "process-map", "value": "3.0.11", "class": "RUNTIME_OBSERVED",
              "evidence_id": EVID_RT}]},
        {"coordinate": MAVEN, "name": "maven", "version": "3.9.6", "origin": "MANIFEST",
         "scope": "BUILD", "direct": True, "evidence_ref": EVID_CI},
        {"coordinate": MOCKITO, "name": "mockito", "version": "5.4.0", "origin": "MANIFEST",
         "scope": "TEST", "evidence_ref": EVID_CI},
        {"coordinate": GHOST, "name": "ghost", "version": "0.0.9", "origin": "SBOM",
         "scope": "RUNTIME", "evidence_ref": EVID_SBOM},
        # a component the store knows about that no release, image or SBOM reaches
        {"coordinate": "pkg:generic/legacy-agent@0.4.2", "name": "legacy-agent",
         "version": "0.4.2", "origin": "SCAN", "scope": "RUNTIME", "evidence_ref": EVID_IMG},
        # a row the store cannot place, and it says so instead of inventing an identity
        {"version": "1.0.0", "origin": "SBOM", "scope": "RUNTIME"},
        # a row claiming a probe class with nothing behind it
        {"coordinate": "pkg:generic/sneaky@1.0.0", "name": "sneaky", "version": "1.0.0",
         "origin": "SBOM", "scope": "RUNTIME", "basis": "runtime-probe"},
        # a tag-only artifact's SBOM list: the artifact itself is refused below
    ]
    dependencies: list[dict[str, Any]] = [
        {"source": SDK, "target": HTTP, "type": "depends_on", "evidence_ref": EVID_SBOM},
        {"source": HTTP, "target": OPENSSL, "type": "depends_on", "evidence_ref": EVID_SBOM},
        {"source": OPENSSL, "target": "pkg:generic/zlib@1.3", "type": "depends_on"},
    ]
    if not moved:
        # before the upgrade: the SDK depended on OpenSSL directly, and openssl-dev was not
        # installed anywhere
        dependencies = [{"source": SDK, "target": OPENSSL, "type": "depends_on",
                         "evidence_ref": EVID_SBOM}]
        software = [row for row in software if row.get("coordinate") != OPENSSL_DEV]
        software.append({"coordinate": HTTP, "name": "http-core", "version": "1.2.0",
                         "origin": "SBOM", "scope": "RUNTIME", "evidence_ref": EVID_SBOM})
    else:
        software.append({"coordinate": HTTP, "name": "http-core", "version": "1.2.0",
                         "origin": "SBOM", "scope": "RUNTIME", "evidence_ref": EVID_SBOM})
        software.append({"coordinate": OPENSSL_DEV, "name": "openssl-dev",
                         "version": "3.0.13", "origin": "SCAN", "scope": "BUILD",
                         "evidence_ref": EVID_IMG})
    installed = [OPENSSL]
    return {
        "environment": "PRODUCTION",
        "applications": [
            {"id": "APP-1", "name": "Payments API", "system": "Payments System",
             "evidence_ref": EVID_SRC},
            {"id": "APP-2", "name": "Reporting API", "system": "Payments System",
             "evidence_ref": EVID_IMG},
        ],
        "software": software,
        "dependencies": dependencies,
        "supply": {
            "repositories": [{
                "name": "git.bank.internal/payments/payments-api",
                "url": "https://git.bank.internal", "applications": ["Payments API"],
                "default_branch": "main", "evidence_ref": EVID_SRC}],
            "commits": [{"sha": "a81f92c", "repository": "git.bank.internal/payments/payments-api",
                         "author": "payments-team", "committed_at": EARLIER,
                         "evidence_ref": EVID_SRC}],
            "builds": [{"name": "BUILD-18291", "commit": "a81f92c",
                        "repository": "git.bank.internal/payments/payments-api",
                        "pipeline": "jenkins-payments-ci", "status": "SUCCESS",
                        "evidence_ref": EVID_CI}],
            "artifacts": [
                {"name": "payments-api-4.2.1.jar", "digest": DIGEST_ARTIFACT,
                 "build": "BUILD-18291", "kind": "JAR", "evidence_ref": EVID_CI},
                {"name": "payments-api-3.9.0.jar", "digest": DIGEST_OLD,
                 "build": "BUILD-17001", "kind": "JAR", "evidence_ref": EVID_CI},
                # a tag is a pointer, so the store's tag-only artifact is refused
                {"name": "payments-api:latest", "build": "BUILD-18291",
                 "evidence_ref": EVID_IMG}],
            "layers": [{
                "name": "layer:ubuntu-22.04-base", "image": "payments-api:4.2.1",
                "base": "ubuntu:22.04", "evidence_ref": EVID_IMG,
                "packages": [OPENSSL, HTTP, "pkg:generic/not-in-inventory"]}],
            "images": [{
                "name": "payments-api:4.2.1", "digest": DIGEST_IMAGE,
                "artifact": "payments-api-4.2.1.jar", "tag": "4.2.1", "base": "ubuntu:22.04",
                "layers": ["layer:ubuntu-22.04-base"], "installed": installed,
                "evidence_ref": EVID_IMG},
                # installed somewhere and deployed nowhere: the distinction that matters
                {"name": "reporting-api:1.0.0",
                 "digest": "sha256:1122aabbccdd3344eeff5566", "base": "ubuntu:22.04",
                 "installed": [OPENSSL_DEV] if moved else [],
                 "evidence_ref": EVID_IMG}],
            "releases": [{"name": "payments-api 4.2.1", "application": "Payments API",
                          "version": "4.2.1", "artifact": "payments-api-4.2.1.jar",
                          "evidence_ref": EVID_CI}],
            "sboms": [{"name": "SBOM-18291", "artifact": "payments-api-4.2.1.jar",
                       "format": "CycloneDX-1.6", "tool": "syft-1.18",
                       "generated_at": EARLIER, "serial": "urn:uuid:9a8b7c",
                       "components": [SDK, HTTP, OPENSSL, MAVEN, MOCKITO, GHOST,
                                      "pkg:generic/never-installed@9.9.9"],
                       "evidence_ref": EVID_SBOM}],
            "deployments": [{
                "name": "payments-api-deploy", "image": "payments-api:4.2.1",
                "namespace": "payments", "cluster": "prod-cluster",
                "replica_set": "payments-api-7d9f4c", "evidence_ref": EVID_K8S,
                "pods": [{"name": "payments-api-7d9f4c-x2m8p", "node": "node-03",
                          "host": "srv-k8s-03", "containers": ["payments-api-ctr"]}]}],
            "processes": [{"name": "payments-api[1821]", "pid": 1821,
                           "application": "Payments API",
                           "pod": "payments-api-7d9f4c-x2m8p",
                           "loads": [OPENSSL, "libcrypto.so.3"], "basis": "process-trace",
                           "evidence_ref": EVID_RT}],
        },
        "crypto": [
            {"id": "CR-1", "algorithm": "RSA", "key_size": 2048, "family": "RSA",
             "library": OPENSSL, "operation": "SIGN", "process": "payments-api[1821]",
             "application": "Payments API", "purpose": "payment instruction signature",
             "hash": "SHA-256", "observed_at": NOW, "evidence_ref": EVID_RT},
            {"id": "CR-2", "algorithm": "AES", "key_size": 256, "mode": "GCM",
             "library": OPENSSL, "evidence_ref": EVID_SBOM},
            {"id": "CR-3", "algorithm": "ECDSA", "key_size": 256, "curve": "P-256",
             "library": OPENSSL, "evidence_ref": EVID_SBOM},
        ],
        "vendors": [{"name": "OpenSSL Project", "product": "OpenSSL 3.x", "version": "3.0.13",
                     "lifecycle": "ACTIVE", "evidence_ref": EVID_SBOM}],
        "hardware": [{"name": "HSM-001", "type": "HSM", "model": "nShield",
                      "manufacturer": "Entrust", "algorithms": ["RSA-2048"],
                      "evidence_ref": EVID_HSM}],
        "certificates": [{"name": "CERT-001", "subject": "CN=payments.bank.example",
                          "issuer": "Bank Issuing CA", "signature_algorithm": "ECDSA-256",
                          "key_algorithm": "ECDSA-256", "application": "Payments API",
                          "evidence_ref": EVID_NET}],
        "endpoints": [{"name": "payments.bank.example:443", "host": "203.0.113.10",
                       "port": 443, "suite": "TLS_AES_256_GCM_SHA384",
                       "algorithm": "AES-256", "application": "Payments API",
                       "evidence_ref": EVID_NET}],
    }


def _build(modules: dict[str, Any]) -> dict[str, Any]:
    current = modules["su"].from_inventory(_inventory())
    previous = modules["su"].from_inventory(_inventory(moved=False))
    bom = modules["t"].build(current["estate"])
    return {"bom": bom, "previous": modules["t"].build(previous["estate"]),
            "current": current, "previous_source": previous,
            "twin": modules["twin"].build(current["estate"])}


# --------------------------------------------------------------------------- #
# The measurement
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _load()
    s = modules["s"]
    built = _build(modules)
    bom, previous = built["bom"], built["previous"]
    current = built["current"]

    points: list[dict[str, Any]] = []

    def add(number: int, phase: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"STORE-{number:02d}", "number": number, "phase": phase,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    levels = s.levels(bom)
    kinds = {row["kind"] for row in bom["assets"]}
    skipped = current["skipped"]
    codes = {row["code"] for row in skipped if row["code"]}

    # ---- 1. the inventory becomes the chain -------------------------------- #
    add(1, "store", "a gathered inventory becomes the twelve levels, not a list of packages", [
        _probe("every-level-present",
               all(levels[name] for _, name in s.SUPPLY_LEVELS),
               ", ".join(f"{name} {count}" for name, count in levels.items())),
        _probe("the-two-branches-are-both-there",
               {"IMAGE", "PROCESS", "DEPLOYMENT", "POD"} <= kinds and "REPOSITORY" in kinds,
               f"{len(kinds)} kind(s) in the projection"),
        _probe("the-store-builds-through-techbom",
               bom.get("source_of_truth") == "CANONICAL_ESTATE" and bom.get("projection"),
               f"source_of_truth {bom.get('source_of_truth')}, projection "
               f"{bom.get('projection')}"),
    ])

    # ---- 2. what the store cannot place is reported ------------------------ #
    add(2, "store", "a row the store cannot place is reported with a reason, never repaired", [
        _probe("the-nameless-software-row-is-skipped",
               any(row["kind"] == "SOFTWARE" or "software" in row["kind"].lower()
                   for row in skipped),
               f"{len([row for row in skipped if 'software' in row['kind'].lower()])} "
               "software row(s) skipped"),
        _probe("a-probe-class-needs-the-collectors-evidence",
               "PROBE_BASIS_WITHOUT_EVIDENCE" in codes,
               f"{sorted(codes)}"),
        _probe("nothing-was-invented-to-fill-the-gap",
               "pkg:generic/sneaky@1.0.0" not in {row["name"] for row in bom["assets"]},
               f"{len(skipped)} row(s) skipped, {len(bom['assets'])} asset(s) placed"),
    ])

    # ---- 3. nothing is joined by name -------------------------------------- #
    add(3, "store", "an edge that names a node the inventory does not hold is refused", [
        _probe("the-unknown-dependency-target-is-skipped",
               any("zlib" in row["subject"] for row in skipped),
               next((row["reason"] for row in skipped if "zlib" in row["subject"]), "—")),
        _probe("the-layer-does-not-invent-its-packages",
               any("not-in-inventory" in row["subject"] for row in skipped),
               next((row["reason"] for row in skipped
                     if "not-in-inventory" in row["subject"]), "—")),
        _probe("the-sbom-does-not-invent-its-components",
               any("never-installed" in row["subject"] for row in skipped),
               next((row["reason"] for row in skipped
                     if "never-installed" in row["subject"]), "—")),
    ])

    # ---- 4. provenance ------------------------------------------------------ #
    provenance = s.provenance(bom, artifact="payments-api-4.2.1.jar")
    add(4, "provenance", "the chain says which revision built the SBOM, from stored rows", [
        _probe("repository-commit-build-sbom",
               provenance["complete"] and provenance["steps"]["commit"] == "a81f92c"
               and provenance["steps"]["build"] == "BUILD-18291",
               provenance["statement"]),
        _probe("the-artifact-is-bound-to-a-digest",
               provenance["steps"]["digest"] == DIGEST_ARTIFACT,
               f"digest {provenance['steps']['digest']}"),
    ])

    # ---- 5. a tag is not an identity --------------------------------------- #
    tag_refusals = [row for row in skipped if row["code"] == "ARTIFACT_WITHOUT_DIGEST"]
    add(5, "provenance", "a stored artifact with only a tag is refused rather than anchored", [
        _probe("the-tag-only-artifact-is-refused", bool(tag_refusals),
               tag_refusals[0]["reason"] if tag_refusals else "no refusal"),
        _probe("the-tag-is-not-in-the-projection",
               "payments-api:latest" not in {row["name"] for row in bom["assets"]},
               "payments-api:latest is absent" if "payments-api:latest" not in
               {row["name"] for row in bom["assets"]} else "present"),
    ])

    # ---- 6. ownership ------------------------------------------------------- #
    owners = s.component_owners(bom, query=OPENSSL)
    ghost = s.component_owners(bom, query="pkg:generic/legacy-agent@0.4.2")
    add(6, "ownership", "the component names the application that owns it, through a release", [
        _probe("the-owner-is-payments-api", owners["applications"] == ["Payments API"],
               owners["statement"]),
        _probe("the-path-goes-through-a-release",
               any("RELEASED_AS" in step for row in owners["owners"] for step in row["path"]),
               " → ".join(owners["owners"][0]["path"]) if owners["owners"] else "—"),
        _probe("a-component-nobody-owns-says-so", ghost["applications"] == [],
               ghost["statement"]),
        _probe("a-component-the-sbom-lists-is-owned-through-it",
               s.component_owners(bom, query=GHOST)["applications"] == ["Payments API"],
               s.component_owners(bom, query=GHOST)["statement"]),
    ])

    # ---- 7. deployment and topology ---------------------------------------- #
    kubernetes = s.kubernetes_chain(bom, query="payments-api:4.2.1")
    hosts = s.host_chain(bom, query="payments-api-7d9f4c-x2m8p")
    add(7, "deployment", "the image reaches its deployment, pod, node and host from the store", [
        _probe("the-kubernetes-walk-has-its-kinds",
               {"POD", "DEPLOYMENT", "CONTAINER"} <= set(kubernetes["kinds"]),
               kubernetes["statement"]),
        _probe("the-host-walk-reaches-the-physical-server",
               "srv-k8s-03" in hosts["hosts"], hosts["statement"]),
    ])

    # ---- 8. installed, loaded, used ---------------------------------------- #
    states = s.component_states(bom, query=OPENSSL)
    deployment = s.deployment_state(bom, query=OPENSSL_DEV)
    add(8, "runtime", "installed, loaded and used stay three facts after the store mapping", [
        _probe("the-component-is-listed-installed-and-loaded",
               {"SBOM_PRESENT", "INSTALLED", "LOADED"} <= set(states["present"]),
               states["statement"]),
        _probe("the-runtime-operation-is-a-use-not-a-capability",
               "RUNTIME_USED" in states["present"], states["statement"]),
        _probe("a-build-only-package-is-installed-and-not-deployed",
               deployment["states"]["INSTALLED"] and not deployment["deployed"],
               deployment["statement"]),
    ])

    # ---- 9. versions -------------------------------------------------------- #
    versions = s.version_layers(bom, query=OPENSSL)
    add(9, "runtime", "two stored sources disagree and both versions survive", [
        _probe("declared-and-runtime-are-both-kept",
               versions["layers"]["DECLARED_VERSION"] == "3.0.13"
               and versions["layers"]["RUNTIME_VERSION"] == "3.0.11",
               versions["statement"]),
        _probe("the-conflict-is-named-not-resolved",
               versions["conflict"] and versions["code"] == "DEPENDENCY_VERSION_CONFLICT",
               versions["code"] or "no conflict"),
    ])

    # ---- 10. direct versus transitive -------------------------------------- #
    tree = s.dependency_tree(bom, query="Payments API")
    add(10, "graph", "directness comes from the manifest and transitivity from the walk", [
        _probe("the-sdk-is-direct-and-http-core-is-not",
               SDK in {row["component"] for row in tree["direct"]}
               and HTTP in {row["component"] for row in tree["transitive"]},
               tree["statement"]),
        _probe("the-transitive-row-carries-its-path",
               any(row["component"] == OPENSSL and len(row["path"]) == 3
                   for row in tree["transitive"]),
               next((str(row["path"]) for row in tree["transitive"]
                     if row["component"] == OPENSSL), "—")),
    ])

    # ---- 11. canonical identity -------------------------------------------- #
    canonical = s.canonical_assets(bom)
    merged = [row for row in canonical["canonical"] if len(row["records"]) > 1]
    add(11, "identity", "records join through an anchor and get one canonical id each", [
        _probe("records-with-a-shared-digest-merge",
               any(row["by"] == "evidence" and len(row["records"]) > 1 for row in merged),
               canonical["statement"]),
        _probe("ids-are-issued-per-asset-not-per-record",
               canonical["counts"]["canonical"] < canonical["counts"]["records"],
               f"{canonical['counts']}"),
    ])

    # ---- 12. vendor --------------------------------------------------------- #
    component = next(row for row in bom["assets"] if row["name"] == OPENSSL)
    vendor = s.vendor_chain(bom, query=OPENSSL)
    add(12, "vendor", "a component reaches the product and the vendor behind it", [
        _probe("the-product-is-recorded", bool(vendor["product"]), vendor["statement"]),
        _probe("the-deployments-behind-it-are-counted",
               bool(vendor["deployments"]) and bool(vendor["applications"]),
               f"{vendor['deployments']} / {vendor['applications']}"),
        _probe("a-component-with-no-product-says-so",
               s.vendor_chain(bom, query=MAVEN)["product"] is None,
               s.vendor_chain(bom, query=MAVEN)["statement"]),
    ]) if component else []

    # ---- 13. blast radius --------------------------------------------------- #
    radius = s.remediation_blast_radius(bom, query=OPENSSL, target_version="3.0.14")
    add(13, "remediation", "an upgrade of a crypto library is counted as a crypto change", [
        _probe("the-application-and-system-are-counted",
               radius["affected"]["applications"] >= 1
               and radius["affected"]["systems"] >= 1, radius["statement"]),
        _probe("the-algorithms-behind-it-are-named",
               "RSA-2048" in radius["algorithms"], ", ".join(radius["algorithms"])),
        _probe("the-hardware-and-the-certificate-are-in-the-blast-radius",
               "HSM-001" in radius["hardware"] and "CERT-001" in radius["certificates"],
               f"hardware {radius['hardware']}, certificates {radius['certificates']}"),
        _probe("the-regression-list-is-derived",
               any("re-validation" in item for item in radius["regression"]),
               "; ".join(radius["regression"])),
    ])

    # ---- 14. lifecycle ------------------------------------------------------ #
    lifecycle = s.supply_lifecycle(bom, previous, detected_at=NOW)
    add(14, "history", "a superseded dependency keeps the row that replaced it", [
        _probe("the-superseded-edge-is-retained",
               any(row["state"] == "SUPERSEDED" for row in lifecycle["rows"]),
               lifecycle["statement"]),
        _probe("the-replacement-is-named",
               all(row.get("superseded_by") for row in lifecycle["rows"]
                   if row["state"] == "SUPERSEDED"),
               next((row["superseded_by"] for row in lifecycle["rows"]
                     if row["state"] == "SUPERSEDED"), "—")),
        _probe("a-first-seen-edge-is-not-an-active-one",
               "FIRST_SEEN" in lifecycle["counts"], f"{lifecycle['counts']}"),
    ])

    # ---- 15. evidence types ------------------------------------------------- #
    profile = s.evidence_profile(bom)
    add(15, "evidence", "every crypto dependency carries one of the eight evidence types", [
        _probe("the-rows-carry-a-type-and-an-id",
               all(row["evidence_type"] in s.EVIDENCE_TYPES and row["evidence_id"]
                   for row in profile["rows"]), profile["statement"]),
        _probe("capability-and-usage-are-counted-apart",
               profile["proven"] > 0 and profile["unproven"] > 0,
               f"proven {profile['proven']}, unproven {profile['unproven']}"),
        _probe("no-row-is-promoted-to-a-stronger-type",
               all(row["class"] not in ("OBSERVED",) or row["evidence_type"] in
                   s.PROVEN_EVIDENCE for row in profile["rows"]),
               ", ".join(f"{name} {count}" for name, count in profile["counts"].items())),
    ])

    # ---- 16. the projection -------------------------------------------------- #
    twin = s.twin_projection(bom)
    covered = len({entry["id"] for entry in canonical["canonical"]})
    add(16, "projection", "the graph is a projection, and every node has a canonical id", [
        _probe("every-record-resolves-to-a-canonical-asset",
               covered == canonical["counts"]["canonical"]
               and canonical["counts"]["canonical"] <= canonical["counts"]["records"],
               canonical["statement"]),
        _probe("there-is-one-store", twin["second_store"] is False
               and bom.get("source_of_truth") == "CANONICAL_ESTATE",
               f"second_store {twin['second_store']}, canonical {twin['canonical']}, "
               f"derived from {twin['derived_from']}"),
    ])

    # ---- 17. the handoff ---------------------------------------------------- #
    handoff = s.crypto_handoff(bom, query=OPENSSL)
    pqc = s.pqc_handoff(bom, query=OPENSSL)
    add(17, "handoff", "the store's crypto rows hand capability to the CBOM and decide nothing", [
        _probe("the-capabilities-arrive", handoff["count"] >= 3, handoff["statement"]),
        _probe("only-a-caller-corroborates",
               set(handoff["corroborated"]) == {"pkg:generic/openssl:RSA-2048"},
               f"corroborated {handoff['corroborated']}"),
        _probe("pqc-keeps-the-two-lists-apart",
               pqc["capabilities"] and pqc["observed_usage"] == ["RSA-2048"],
               pqc["statement"]),
    ])

    rows = _rows(points)
    counts = {state: len([row for row in rows if row["verdict"] == state])
              for state in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "estate": {"id": bom.get("estate_id"), "assets": len(bom["assets"]),
                   "claims": len(bom["claims"]),
                   "skipped": len(current["skipped"]),
                   "refusals": len(bom.get("refusals") or [])},
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "points_present": counts[VERDICT_PASS],
        "statement": (f"{counts[VERDICT_PASS]} of {len(rows)} points of the chain are present "
                      f"in a projection built from the store, across "
                      f"{sum(len(row['probes']) for row in rows)} probes; "
                      f"{len(bom['assets'])} assets, {len(bom['claims'])} claims, "
                      f"{len(current['skipped'])} row(s) skipped"),
        "levels": levels,
        "placed": current["placed"],
        "skipped": current["skipped"],
        "rows": rows,
        "provenance": provenance,
        "owners": owners,
        "states": states,
        "versions": versions,
        "tree": tree,
        "canonical": canonical,
        "vendor": vendor,
        "radius": radius,
        "lifecycle": lifecycle,
        "profile": profile,
        "twin": twin,
        "handoff": handoff,
        "pqc": pqc,
        "limits": [
            "the inventory is a fixture: its shapes are the store's, its rows are not",
            "a stored row records what a collector saw when it ran; nothing here re-runs a "
            "collector, so a stale row stays a stale row and the class says so",
            "the chain is only as complete as the columns: a row that names no commit stops "
            "the provenance there, and the gap is printed rather than filled",
            "the twin is a CBOM projection with its own input shape, so this guide proves "
            "the SBOM nodes carry the canonical ids a twin is keyed by, not that a twin was "
            "rebuilt from them",
        ],
    }


def _rows(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return points


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The SBOM chain, from the store: seventeen points",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['counts'][VERDICT_PASS]} pass · {report['counts'][VERDICT_PARTIAL]} partial"
        f" · {report['counts'][VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "```",
        "BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD",
        "    → ARTIFACT → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST",
        "    → PROCESS → SOFTWARE COMPONENT → CRYPTO CAPABILITY",
        "```",
        "",
        "| Level | Nodes |",
        "|---|---|",
    ]
    for name, count in report["levels"].items():
        lines.append(f"| `{name}` | {count} |")
    lines += ["", "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")

    lines += ["", "## What the store could not place", ""]
    for row in report["skipped"]:
        lines.append(f"- `{row['kind']}` — {row['subject']}: {row['reason']}"
                     + (f" (`{row['code']}`)" if row["code"] else ""))
    if not report["skipped"]:
        lines.append("- nothing: every row had an identity, an evidence reference and a basis")

    lines += ["", "## One canonical asset, several records", "",
              f"**{report['canonical']['statement']}**", "",
              "| canonical | by | records |", "|---|---|---|"]
    for row in report["canonical"]["canonical"][:12]:
        names = ", ".join(f"{entry['kind']}:{entry['name']}" for entry in row["records"])
        lines.append(f"| `{row['id']}` | {row['by']} | {names} |")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 176, {row['phase']})", ""]
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
