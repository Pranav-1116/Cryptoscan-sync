#!/usr/bin/env python3
"""Guide 133 — SBOM evidence: a parser matrix that runs, and a chain that ends in a pod.

The review stored beside this artifact (`133-sbom-review-as-received.md`) lists
nineteen items. This guide answers the ones that can be *executed* today, and
says so plainly about the rest:

* **item 3, parser correctness** — a qualification matrix that runs `scan_source`
  over a real file for every ecosystem and lockfile revision the review named.
  Two defects it found are fixed in this commit: `.csproj` files were never
  dispatched (the parser was keyed by a name no filename could match), and an
  npm range like `^5.0.0` was coerced to `5.0.0` with the caret discarded, which
  turns a range into a pinned version in the one place the review says that
  distinction matters most.
* **items 5/6, deployment identity** — a tag is refused as identity, a digest is
  required, and "present in production" needs an observation of that digest, not
  merely a component in a document.
* **item 7, build provenance** — commit → build → digest → SBOM → deployment,
  with each missing link named.
* **item 8, durability** — production evidence may not fall back to temporary
  storage; that is a refusal.
* **item 9, signing** — integrity, authenticity and non-repudiation are three
  claims; SHA-256, HMAC and an anchored Ed25519 key earn one, two and three.
* **item 10, vulnerability status** — six states, so zero matches from a stale
  feed is `STALE_FEED` rather than an all-clear.
* **item 11, VEX** — a statement that expires, names a reviewer and cites
  evidence, or it is invalid.
* **item 12, licences** — detected is not approved.
* **item 13, SBOM → CBOM** — a four-rung promotion ladder that cannot skip.
* **items 15/16, history and diff** — changes in the review's vocabulary, and a
  diff whose crypto impact is `UNKNOWN` until something observed it.
* **item 17** — an imported SBOM may not overwrite an observed fact, and a
  hostile document hits a budget before it hits the CPU.

What is *not* executed here is listed at the end of the generated guide.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import textwrap
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
DOCS = ROOT / "docs" / "bank-environment"
SCHEMA = "cryptoscan.sbom-evidence-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

DIGEST = "sha256:" + "a" * 64
NEXT_DIGEST = "sha256:" + "b" * 64


def _load_modules() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "container_scanner"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import sbom_evidence as se  # noqa: PLC0415
    from devsecops import sbom_qualification as sq  # noqa: PLC0415
    from devsecops import sbom_scan  # noqa: PLC0415
    return {"se": se, "sq": sq, "scan": sbom_scan}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _raises(expected: type[BaseException], call: Any) -> str:
    try:
        call()
    except expected as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - a different exception is a different failure
        return f"WRONG-EXCEPTION {type(exc).__name__}: {exc}"
    return ""


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

def _artifact(se: Any, digest: str = DIGEST) -> Any:
    return se.ArtifactIdentity("ghcr.io/bank/payments-api", digest)


def _observation(se: Any, as_of: date, artifact: Any | None = None) -> Any:
    return se.DeploymentObservation(
        deployment="payments-api-prod", environment="PRODUCTION",
        artifact=artifact or _artifact(se), workload="payments-api-7d9c4f-x2b6q",
        observed_at=as_of, evidence_id="OBS-2026-1102-01", source="k8s")


def _sbom(se: Any, *, sbom_id: str = "SBOM-9182", artifact: Any | None = None,
          openssl: str = "3.0.13", created: date | None = None) -> Any:
    return se.SbomRecord(
        sbom_id, artifact if artifact is not None else _artifact(se),
        ({"name": "openssl", "version": openssl, "purl": f"pkg:generic/openssl@{openssl}",
          "crypto_relevant": True, "license": "Apache-2.0"},),
        created_at=created, build_id="BUILD-2026-1102-0091")


# --------------------------------------------------------------------------- #
# 1. parser qualification (item 3)
# --------------------------------------------------------------------------- #


def row_parser_qualification(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    sq = modules["sq"]
    probes: list[dict[str, Any]] = []
    report = sq.qualify()

    probes.append(_probe(
        "every-case-is-executed-not-asserted",
        report["cases"] == len(sq.CASES)
        and all(row["components_found"] for row in report["rows"])
        and all(row["manifests_seen"] for row in report["rows"]),
        f"{report['cases']} case(s) written to disk and scanned by `scan_source`; "
        f"{report['counts']['PASS']} pass, {report['counts']['PARTIAL']} partial, "
        f"{report['counts']['FIX']} need a fix"))

    scan = modules["scan"]
    with tempfile.TemporaryDirectory(prefix="sbom-pyproject-") as workspace:
        tree = Path(workspace)
        (tree / "pyproject.toml").write_text(
            '[project]\nname = "payments-api"\nversion = "1.0.0"\n'
            'dependencies = ["cryptography>=42.0.5", "requests[socks]>=2.31 ; python_version >= \'3.9\'"]\n\n'
            '[tool.poetry.group.audit.dependencies]\nbandit = "^1.7.5"\n',
            encoding="utf-8")
        alone = scan.scan_source(str(tree), use_lockfiles=True)
    names = {row["name"]: row for row in alone["packages"]}
    probes.append(_probe(
        "a-pyproject-only-project-is-not-an-empty-sbom",
        alone["manifests"] == ["pyproject.toml"]
        and {"cryptography", "requests", "bandit"} <= set(names)
        and names["requests"].get("version_constraint") == "RANGE"
        and names["bandit"].get("version_constraint") == "RANGE",
        f"pyproject.toml alone (PEP 621 + poetry group) -> "
        f"{sorted(names)}; before this reader existed the same tree yielded zero components, "
        "indistinguishable from a project with no dependencies"))

    dotnet = next(row for row in report["rows"] if row["id"] == "dotnet_csproj")
    probes.append(_probe(
        "csproj-dispatch-reaches-the-parser",
        dotnet["verdict"] == "PASS" and "bouncycastle.cryptography" in dotnet["components_found"],
        f"{dotnet['manifest']} -> {dotnet['components_found']}; before this fix the same file "
        "produced no package at all because the parser was keyed 'csproj' and looked up by "
        "filename"))

    npm_range = next(row for row in report["rows"]
                     if row["id"] == "npm_declared_range_is_not_a_version")
    probes.append(_probe(
        "a-caret-survives-the-manifest-reader",
        npm_range["verdict"] == "PASS"
        and npm_range["declared_specs"].get("jose") == "^5.0.0"
        and npm_range["version_constraints"].get("jose") == "RANGE",
        f"jose {npm_range['declared_specs'].get('jose')} carried as "
        f"{npm_range['version_constraints'].get('jose')}, so a range cannot be read as a pin"))

    lock_revisions = sorted({row["revision"] for row in report["rows"] if row["lockfile"]})
    npm_v3 = next(row for row in report["rows"] if row["id"] == "npm_lockfile_v3")
    probes.append(_probe(
        "the-lockfile-generations-are-exercised-separately",
        npm_v3["verdict"] == "PASS" and len(lock_revisions) >= 8,
        f"{len(lock_revisions)} revision(s) exercised, {', '.join(lock_revisions[:6])}, …"))

    ecosystems = {row["ecosystem"]: row["verdict"] for row in report["ecosystems"]}
    probes.append(_probe(
        "an-ecosystem-with-one-bad-case-is-not-qualified",
        all(verdict == "PASS" for verdict in ecosystems.values()) == report["qualified"],
        f"{len(ecosystems)} ecosystem(s) scored; qualified={report['qualified']} — one FIX "
        "anywhere would flip that to False, which is the point of a matrix"))

    probes.append(_probe(
        "the-matrix-is-an-artifact-not-a-unit-test",
        report["schema"] == sq.SCHEMA and bool(report["statement"]),
        report["statement"]))

    return {"id": "parser_qualification",
            "question": "which ecosystem and lockfile generation is actually production-qualified?",
            "phase": "3", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. deployment identity (items 5/6)
# --------------------------------------------------------------------------- #


def row_deployment_identity(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    sbom = _sbom(se, created=as_of)
    observation = _observation(se, as_of)

    deployed = se.presence_in_deployment(sbom, "openssl", [observation])
    probes.append(_probe(
        "a-component-in-a-sbom-bound-to-a-digest-and-observed-is-in-production",
        deployed["state"] == "PRESENT_IN_DEPLOYMENT"
        and deployed["environments"] == ["PRODUCTION"]
        and deployed["deployments"][0]["evidence_id"] == "OBS-2026-1102-01",
        f"{deployed['statement']} — cited to {deployed['deployments'][0]['evidence_id']}"))

    unbound = se.presence_in_deployment(
        se.SbomRecord("SBOM-upload", None, ({"name": "openssl", "version": "3.0.11"},)),
        "openssl", [observation])
    probes.append(_probe(
        "an-uploaded-document-is-not-a-deployment",
        unbound["state"] == "PRESENT_IN_SBOM_ONLY",
        f"the same component in a document bound to no digest -> {unbound['state']}: "
        "the review's 'exists somewhere in an uploaded SBOM'"))

    unobserved = se.presence_in_deployment(sbom, "openssl", [])
    probes.append(_probe(
        "a-digest-nobody-observed-running-is-not-deployed",
        unobserved["state"] == "PRESENT_IN_ARTIFACT",
        f"bound digest, no observation -> {unobserved['state']}"))

    probes.append(_probe(
        "a-mutable-tag-is-refused-as-identity",
        "names no digest" in _raises(
            se.IdentityError, lambda: se.parse_image_reference(
                "ghcr.io/bank/payments-api:latest")),
        "`payments-api:latest` is refused outright rather than flagged, because a tag is a "
        "pointer and evidence needs an address"))

    pinned = se.parse_image_reference(f"ghcr.io/bank/payments-api@{DIGEST}")
    probes.append(_probe(
        "a-digest-qualified-reference-parses-into-an-identity",
        pinned.digest == DIGEST and pinned.reference == "ghcr.io/bank/payments-api"
        and pinned.mutable is False,
        f"{pinned.reference}@{pinned.digest[:19]}… parsed as an immutable identity"))

    mismatch = _raises(se.IdentityError, lambda: se.ArtifactIdentity(
        "ghcr.io/bank/payments-api@" + NEXT_DIGEST, DIGEST))
    probes.append(_probe(
        "a-pinned-reference-that-contradicts-its-record-is-refused",
        "pins" in mismatch, mismatch[:100]))

    absent = se.presence_in_deployment(sbom, "curl", [observation])
    probes.append(_probe(
        "a-component-that-is-not-in-the-sbom-is-a-different-answer",
        absent["state"] == "NOT_IN_SBOM",
        "an absent component is NOT_IN_SBOM: a statement about the inventory, not about the "
        "estate"))

    return {"id": "deployment_identity",
            "question": "does a component in an SBOM become 'deployed', or only 'described'?",
            "phase": "5/6", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. build provenance (item 7)
# --------------------------------------------------------------------------- #


def row_build_provenance(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    artifact = _artifact(se)
    sbom = _sbom(se, created=as_of)
    observation = _observation(se, as_of)

    complete = se.BuildIdentity("9f2c1ab4d7", "BUILD-2026-1102-0091", "github-actions",
                                "release-payments", artifact, sbom.sbom_id,
                                started_at=as_of, finished_at=as_of)
    provenance = se.build_provenance(complete, sbom, [observation])
    probes.append(_probe(
        "the-chain-runs-from-commit-to-running-pod",
        provenance["complete"] and provenance["gaps"] == []
        and provenance["deployed_environments"] == ["PRODUCTION"],
        provenance["statement"]))

    no_build = se.BuildIdentity("9f2c1ab4d7", "", "", "release-payments", None, None)
    gaps = se.build_provenance(no_build, None, [])
    probes.append(_probe(
        "a-build-with-no-record-has-every-gap-named",
        len(gaps["gaps"]) >= 4 and not gaps["complete"],
        f"{len(gaps['gaps'])} gap(s): {gaps['gaps'][0]}; … {gaps['gaps'][-1]}"))

    bad_commit = se.build_provenance(
        se.BuildIdentity("not-a-commit", "B-1", "jenkins", "p", artifact, sbom.sbom_id,
                         started_at=as_of, finished_at=as_of), sbom, [observation])
    probes.append(_probe(
        "an-unattributable-commit-breaks-the-chain",
        any("not a commit hash" in gap for gap in bad_commit["gaps"]),
        bad_commit["gaps"][0]))

    other = _sbom(se, sbom_id="SBOM-9182", artifact=se.ArtifactIdentity(
        "ghcr.io/bank/payments-api", NEXT_DIGEST), created=as_of)
    wrong_sbom = se.build_provenance(complete, other, [observation])
    probes.append(_probe(
        "a-sbom-of-a-different-artifact-is-not-this-builds-sbom",
        any("different artifact" in gap for gap in wrong_sbom["gaps"]),
        next(gap for gap in wrong_sbom["gaps"] if "different artifact" in gap)))

    early = _sbom(se, sbom_id=sbom.sbom_id, created=date(2026, 10, 1))
    backdated = se.build_provenance(complete, early, [observation])
    probes.append(_probe(
        "a-sbom-that-predates-the-build-is-refused",
        any("predates" in gap for gap in backdated["gaps"]),
        next(gap for gap in backdated["gaps"] if "predates" in gap)))

    undeployed = se.build_provenance(complete, sbom, [])
    probes.append(_probe(
        "provenance-without-an-observation-stops-at-the-artifact",
        "never observed running" in undeployed["statement"],
        undeployed["statement"]))

    return {"id": "build_provenance",
            "question": "can the running pod be traced back to a commit and a build record?",
            "phase": "7", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. artifact durability (item 8)
# --------------------------------------------------------------------------- #


def row_storage_durability(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    refused = se.storage_policy(environment="PRODUCTION", configured_store=None,
                                writable=False, durable=False)
    probes.append(_probe(
        "production-with-no-store-is-refused-not-degraded",
        refused["verdict"] == "REFUSE" and refused["fallback"] is False,
        f"PRODUCTION with SBOM_STORAGE_DIR unset -> {refused['verdict']}: "
        f"{refused['reasons'][0]}"))

    partial = se.storage_policy(environment="PRODUCTION", configured_store="s3://evidence",
                                writable=True, durable=True, backup=None, retention_days=None,
                                integrity_verified=False)
    probes.append(_probe(
        "a-durable-store-without-backup-retention-or-integrity-is-still-refused",
        partial["verdict"] == "REFUSE" and len(partial["reasons"]) == 3,
        f"{len(partial['reasons'])} refusal(s): {partial['reasons'][0]}"))

    allowed = se.storage_policy(environment="PRODUCTION", configured_store="s3://evidence",
                                writable=True, durable=True, backup="s3://evidence-dr",
                                retention_days=2555, integrity_verified=True)
    probes.append(_probe(
        "a-configured-durable-store-with-dr-and-retention-passes",
        allowed["verdict"] == "ALLOW" and allowed["fallback"] is False,
        allowed["statement"]))

    dev = se.storage_policy(environment="dev", configured_store=None, writable=False,
                            durable=False)
    probes.append(_probe(
        "ephemeral-storage-is-allowed-only-where-the-record-does-not-depend-on-it",
        dev["verdict"] == "ALLOW" and dev["mode"] == "EPHEMERAL_OK",
        f"dev -> {dev['verdict']} ({dev['mode']}); the same call in PRODUCTION is REFUSE"))

    return {"id": "storage_durability",
            "question": "can production evidence quietly land in a temporary directory?",
            "phase": "8", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. the signing ladder (item 9)
# --------------------------------------------------------------------------- #


def row_signing_ladder(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    def verify(key: Any, signed_on: date | None = None) -> dict[str, Any]:
        return se.verify_signature(
            "SBOM-9182", DIGEST, se.Signature(key.key_id, signed_on or as_of, "sig-value",
                                              "SBOM-9182"),
            key, known_anchors=["bank-root-ca"], as_of=as_of)

    sha = verify(se.SigningKey("hash-1", "SHA-256", "ACTIVE"))
    probes.append(_probe(
        "a-hash-gives-integrity-and-nothing-else",
        sha["verdict"] == "INTEGRITY_ONLY" and sha["claims"]["integrity"]
        and not sha["claims"]["authenticity"],
        "SHA-256 -> integrity yes, authenticity no: a digest proves the bytes did not change, "
        "not who produced them"))

    hmac = verify(se.SigningKey("hmac-1", "HMAC-SHA256", "ACTIVE"))
    probes.append(_probe(
        "hmac-gives-authenticity-within-a-shared-secret",
        hmac["verdict"] == "AUTHENTIC" and hmac["claims"]["authenticity"]
        and not hmac["claims"]["non_repudiation"],
        "HMAC-SHA256 -> authenticity yes, non-repudiation no: anyone holding the key could have "
        "signed it"))

    anchored = verify(se.SigningKey("ed-2026", "Ed25519", "ACTIVE", trust_anchor="bank-root-ca"))
    probes.append(_probe(
        "an-anchored-asymmetric-key-earns-non-repudiation",
        anchored["verdict"] == "NON_REPUDIABLE" and anchored["claims"]["non_repudiation"],
        anchored["statement"]))

    unanchored = verify(se.SigningKey("ed-unknown", "Ed25519", "ACTIVE"))
    probes.append(_probe(
        "an-unanchored-key-proves-possession-not-identity",
        unanchored["verdict"] == "AUTHENTIC" and not unanchored["claims"]["non_repudiation"],
        unanchored["reasons"][0]))

    revoked = verify(se.SigningKey("ed-old", "Ed25519", "REVOKED", trust_anchor="bank-root-ca"))
    probes.append(_probe(
        "a-revoked-key-invalidates-everything-it-signed",
        revoked["verdict"] == "REVOKED_KEY" and not revoked["claims"]["authenticity"],
        revoked["statement"]))

    rotated = verify(se.SigningKey("ed-2025", "Ed25519", "ROTATED", trust_anchor="bank-root-ca",
                                   rotated_to="ed-2026"))
    probes.append(_probe(
        "rotation-keeps-an-old-signature-valid-and-says-so",
        rotated["verdict"] == "NON_REPUDIABLE" and "rotated to ed-2026" in rotated["statement"],
        rotated["statement"]))

    expired = verify(se.SigningKey("ed-exp", "Ed25519", "ACTIVE", trust_anchor="bank-root-ca",
                                   valid_until=date(2026, 1, 1)))
    probes.append(_probe(
        "an-expired-key-fails-even-when-it-is-anchored",
        expired["verdict"] == "EXPIRED_KEY",
        expired["statement"]))

    unsigned = se.verify_signature("SBOM-9182", DIGEST, None, None, as_of=as_of)
    probes.append(_probe(
        "no-signature-is-its-own-verdict",
        unsigned["verdict"] == "UNSIGNED" and not unsigned["claims"]["integrity"],
        unsigned["statement"]))

    unknown_algorithm = _raises(se.IdentityError, lambda: se.SigningKey("k", "ROT13", "ACTIVE"))
    probes.append(_probe(
        "an-unknown-algorithm-cannot-be-treated-as-a-signature",
        "not an algorithm" in unknown_algorithm, unknown_algorithm[:90]))

    return {"id": "signing_ladder",
            "question": "which of integrity, authenticity and non-repudiation does a signature "
                        "actually support?",
            "phase": "9", "probes": probes}


# --------------------------------------------------------------------------- #
# 6. vulnerability status (item 10)
# --------------------------------------------------------------------------- #

FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}
OPENSSL_311 = {"name": "openssl", "version": "3.0.11",
               "purl": "pkg:generic/openssl@3.0.11"}
ADVISORY = [{"id": "CVE-2024-6119", "package": "pkg:generic/openssl",
             "affected_versions": ["3.0.11"]}]


def row_vulnerability_status(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    matched = se.assess_vulnerabilities(OPENSSL_311, feed=FEED, advisories=ADVISORY,
                                        as_of=as_of)
    probes.append(_probe(
        "a-match-carries-the-feed-the-method-and-the-advisory",
        matched["status"] == "MATCHED" and matched["feed"] == "osv"
        and matched["match_method"] == "purl+version" and matched["advisories"],
        f"{matched['status']} against {matched['feed']} {matched['feed_timestamp']} by "
        f"{matched['match_method']}: {matched['reason']}"))

    clean = se.assess_vulnerabilities(
        dict(OPENSSL_311, version="3.0.13", purl="pkg:generic/openssl@3.0.13"),
        feed=FEED, advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "zero-matches-is-assessed-and-says-so",
        clean["status"] == "ASSESSED_NO_MATCH",
        f"{clean['status']}: {clean['reason']}"))

    stale = se.assess_vulnerabilities(OPENSSL_311, feed={
        "name": "osv", "version": "2026-09-01", "updated_at": date(2026, 9, 1)},
        advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "zero-matches-from-a-stale-feed-is-not-an-all-clear",
        stale["status"] == "STALE_FEED" and stale["advisories"] == [],
        f"{stale['status']}: {stale['reason']}"))

    no_purl = se.assess_vulnerabilities({"name": "openssl", "version": "3.0.11"}, feed=FEED,
                                        as_of=as_of)
    probes.append(_probe(
        "a-component-with-no-identifier-cannot-be-matched",
        no_purl["status"] == "INSUFFICIENT_IDENTIFIER", no_purl["reason"]))

    not_assessed = se.assess_vulnerabilities(OPENSSL_311, feed=None, as_of=as_of)
    probes.append(_probe(
        "no-feed-is-not-assessed-rather-than-clean",
        not_assessed["status"] == "NOT_ASSESSED", not_assessed["reason"]))

    undated = se.assess_vulnerabilities(OPENSSL_311, feed={"name": "osv"}, as_of=as_of)
    probes.append(_probe(
        "a-feed-that-cannot-be-dated-yields-unknown",
        undated["status"] == "UNKNOWN", undated["reason"]))

    probes.append(_probe(
        "the-vocabulary-is-closed-and-six-state",
        tuple(se.VULN_STATES) == ("NOT_ASSESSED", "ASSESSED_NO_MATCH", "MATCHED", "UNKNOWN",
                                 "STALE_FEED", "INSUFFICIENT_IDENTIFIER"),
        ", ".join(se.VULN_STATES)))

    return {"id": "vulnerability_status",
            "question": "does '0 vulnerabilities' mean clean, or that nobody looked?",
            "phase": "10", "probes": probes}


# --------------------------------------------------------------------------- #
# 7. VEX and licences (items 11/12)
# --------------------------------------------------------------------------- #


def row_vex_and_licence(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    good = se.vex_statement(
        cve="CVE-2024-6119", component="openssl", affected_versions=["3.0.11"],
        application="payments-api", deployment="payments-api-prod", status="NOT_AFFECTED",
        justification="VULNERABLE_CODE_NOT_IN_EXECUTE_PATH", reviewer="Security Team",
        evidence_id="EVID-9281", assessed_at=date(2026, 1, 1), expires_at=date(2027, 1, 1),
        as_of=as_of)
    probes.append(_probe(
        "a-vex-statement-names-a-reviewer-a-reason-and-an-expiry",
        good["verdict"] == "CURRENT" and good["justification"] and good["reviewer"]
        and good["evidence_id"],
        good["statement"]))

    expired = se.vex_statement(
        cve="CVE-2024-6119", component="openssl", affected_versions=["3.0.11"],
        application="payments-api", deployment="prod", status="NOT_AFFECTED",
        justification="VULNERABLE_CODE_NOT_IN_EXECUTE_PATH", reviewer="Security Team",
        evidence_id="EVID-9281", assessed_at=date(2025, 1, 1), expires_at=date(2026, 1, 1),
        as_of=as_of)
    probes.append(_probe(
        "an-expired-vex-statement-stops-suppressing-the-finding",
        expired["verdict"] == "EXPIRED" and expired["expired"],
        expired["statement"]))

    sloppy = se.vex_statement(
        cve="CVE-2024-6119", component="openssl", affected_versions=["3.0.11"],
        application="payments-api", deployment="prod", status="NOT_AFFECTED",
        justification="because we said so", reviewer=None, evidence_id=None,
        assessed_at=date(2026, 1, 1), expires_at=date(2027, 1, 1), as_of=as_of)
    probes.append(_probe(
        "free-text-is-not-a-justification",
        sloppy["verdict"] == "INVALID" and len(sloppy["problems"]) == 3,
        f"{len(sloppy['problems'])} problem(s): {sloppy['problems'][0]}"))

    never_expires = se.vex_statement(
        cve="CVE-2024-6119", component="openssl", affected_versions=[], application="a",
        deployment="p", status="NOT_AFFECTED",
        justification="VULNERABLE_CODE_NOT_PRESENT", reviewer="R", evidence_id="E1",
        assessed_at=date(2026, 2, 1), expires_at=date(2026, 1, 1), as_of=as_of)
    probes.append(_probe(
        "a-statement-cannot-expire-before-it-was-made",
        never_expires["verdict"] == "INVALID"
        and any("before it was assessed" in problem for problem in never_expires["problems"]),
        never_expires["problems"][0]))

    detected = se.license_assessment(declared="Apache-2.0", detected="Apache-2.0")
    probes.append(_probe(
        "a-detected-licence-is-not-an-approval",
        detected["state"] == "REQUIRES_REVIEW",
        f"declared and detected Apache-2.0 -> {detected['state']}: {detected['statement']}"))

    conflict = se.license_assessment(declared="MIT", detected="GPL-3.0")
    probes.append(_probe(
        "a-declared-and-detected-conflict-is-its-own-state",
        conflict["state"] == "CONFLICT", conflict["statement"]))

    allowed = se.license_assessment(declared="MIT", detected="MIT",
                                    policy={"MIT": "ALLOW"})
    denied = se.license_assessment(declared="GPL-3.0", detected="GPL-3.0",
                                   policy={"GPL-3.0": "DENY"})
    probes.append(_probe(
        "only-a-policy-decision-produces-accepted-or-rejected",
        allowed["state"] == "POLICY_ACCEPTED" and denied["state"] == "POLICY_REJECTED",
        f"MIT -> {allowed['state']}, GPL-3.0 -> {denied['state']}, both from a policy and "
        "neither from a scanner"))

    unknown = se.license_assessment(declared=None, detected=None)
    probes.append(_probe(
        "no-licence-is-unknown-not-permissive",
        unknown["state"] == "UNKNOWN", unknown["statement"]))

    return {"id": "vex_and_licence",
            "question": "does a VEX statement expire and name an owner, and is a detected "
                        "licence ever mistaken for an approval?",
            "phase": "11/12", "probes": probes}


# --------------------------------------------------------------------------- #
# 8. SBOM → CBOM promotion (item 13)
# --------------------------------------------------------------------------- #


def row_crypto_promotion(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    candidate = se.crypto_candidate("openssl", "3.0.13",
                                    algorithms=["AES-256-GCM", "RSA-3072", "ECDSA"])

    probes.append(_probe(
        "an-inventory-row-starts-at-capability-and-says-so",
        candidate["rung"] == "CAPABILITY" and candidate["confidence"] == "LOW"
        and "not a statement that any application uses it" in candidate["statement"],
        candidate["statement"]))

    static = se.promote(candidate, [se.CryptoEvidence(
        "STATIC_OBSERVED", "file:src/tls/conn.go#L142", as_of, "AES-256-GCM")])
    probes.append(_probe(
        "static-evidence-raises-the-rung-by-one",
        static["rung"] == "STATIC_OBSERVED" and static["confidence"] == "MEDIUM",
        static["statement"]))

    skipped = se.promote(candidate, [se.CryptoEvidence(
        "RUNTIME_OBSERVED", "session:S-1", as_of, "AES-256-GCM")])
    probes.append(_probe(
        "a-skipped-rung-stops-the-ladder",
        skipped["rung"] == "CAPABILITY" and skipped["gaps"],
        skipped["gaps"][0]))

    runtime = se.promote(static, [se.CryptoEvidence(
        "RUNTIME_OBSERVED", "session:S-1", as_of, "AES-256-GCM")])
    network = se.promote(runtime, [se.CryptoEvidence(
        "NETWORK_OBSERVED", "pcap:payments-api-2026-11-02#42", as_of,
        "TLS_AES_256_GCM_SHA384")])
    probes.append(_probe(
        "the-ladder-reaches-network-with-four-kinds-of-evidence",
        [static["rung"], runtime["rung"], network["rung"]]
        == ["STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"]
        and network["confidence"] == "HIGH",
        f"{static['rung']} -> {runtime['rung']} -> {network['rung']}; "
        f"{network['statement']}"))

    probes.append(_probe(
        "every-rung-cites-what-it-came-from",
        all(isinstance(row, dict) and row.get("reference")
            for row in network["evidence"]),
        "; ".join(str(row.get("reference")) for row in network["evidence"])))

    bad = _raises(se.IdentityError, lambda: se.CryptoEvidence("OBSERVED", "x"))
    probes.append(_probe(
        "an-observation-outside-the-ladder-is-refused",
        "not a rung" in bad, bad[:100]))

    return {"id": "crypto_promotion",
            "question": "does a crypto-capable component become 'used' without evidence?",
            "phase": "13", "probes": probes}


# --------------------------------------------------------------------------- #
# 9. history and evidence-aware diff (items 15/16)
# --------------------------------------------------------------------------- #


def row_history_and_diff(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []
    artifact = _artifact(se)
    observation = _observation(se, as_of)

    older = se.SbomRecord("SBOM-8801", artifact, (
        {"name": "openssl", "version": "3.0.11", "crypto_relevant": True,
         "license": "Apache-2.0", "depends_on": ["cffi"]},
        {"name": "cffi", "version": "1.16.0"},
    ), created_at=date(2026, 10, 1))
    newer = se.SbomRecord("SBOM-9182", se.ArtifactIdentity(
        "ghcr.io/bank/payments-api", NEXT_DIGEST), (
        {"name": "openssl", "version": "3.0.13", "crypto_relevant": True,
         "license": "Apache-2.0", "depends_on": ["cffi", "libssl"]},
        {"name": "libssl", "version": "3.0.13"},
    ), created_at=as_of, build_id="BUILD-2026-1102-0091")

    changes = se.snapshot_changes(older, newer)
    kinds = [row["kind"] for row in changes]
    probes.append(_probe(
        "every-kind-of-movement-is-named",
        {"VERSION_CHANGED", "PACKAGE_ADDED", "DEPENDENCY_CHANGED",
         "ARTIFACT_CHANGED"} <= set(kinds),
        f"{len(changes)} change(s): {', '.join(sorted(set(kinds)))}"))

    diff = se.evidence_aware_diff(older, newer, deployments=[observation])
    open_impact = [row for row in diff["changes"] if row["crypto_impact"] == "UNKNOWN"]
    probes.append(_probe(
        "a-version-bump-does-not-decide-its-own-crypto-impact",
        open_impact and all(row["runtime_verification"] == "NOT_OBSERVED"
                            for row in open_impact),
        f"{len(open_impact)} change(s) with crypto_impact UNKNOWN because nothing observed the "
        "new version: the alternative is a diff that reads like a conclusion"))

    row = next(item for item in diff["changes"] if item["kind"] == "VERSION_CHANGED")
    probes.append(_probe(
        "a-change-carries-the-artifact-release-and-deployment-it-happened-to",
        row["artifact"] == "ghcr.io/bank/payments-api" and row["release"] == "BUILD-2026-1102-0091"
        and row["deployment"] == ["PRODUCTION"],
        f"openssl {row['from']} -> {row['to']} on {row['artifact']} release {row['release']} in "
        f"{row['deployment']}"))

    verified = se.evidence_aware_diff(older, newer, deployments=[observation],
                                      runtime_verified=["openssl"],
                                      network_verified=["openssl"])
    verified_row = next(item for item in verified["changes"]
                        if item["kind"] == "VERSION_CHANGED")
    probes.append(_probe(
        "observed-runtime-and-network-evidence-close-the-question",
        verified_row["crypto_impact"] == "RUNTIME_EVIDENCE_PRESENT"
        and verified_row["runtime_verification"] == "OBSERVED"
        and verified_row["network_impact"] == "OBSERVED",
        f"with runtime and network evidence the same change reads "
        f"{verified_row['crypto_impact']} / {verified_row['runtime_verification']} / "
        f"{verified_row['network_impact']}"))

    probes.append(_probe(
        "the-diff-itself-carries-an-evidence-id",
        diff["evidence_id"].startswith("DIF-"),
        f"{diff['evidence_id']} — recomputable from the change set, so two runs over the same "
        "snapshots are the same finding"))

    return {"id": "history_and_diff",
            "question": "does a diff say what changed, or what it means?",
            "phase": "15/16", "probes": probes}


# --------------------------------------------------------------------------- #
# 10. untrusted import and parser budgets (item 17)
# --------------------------------------------------------------------------- #


def row_input_safety(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    imported = se.import_sbom(
        {"deployment_identity": "attacker-prod", "components": [
            {"name": "implanted-lib", "version": "1.0.0"}]},
        source="vendor-portal", existing={"deployment_identity": "payments-api-prod"})
    probes.append(_probe(
        "an-import-may-not-overwrite-an-observed-fact",
        imported["verdict"] == "REJECTED"
        and imported["refused"][0]["field"] == "deployment_identity",
        imported["refused"][0]["reason"]))

    clean = se.import_sbom({"components": [{"name": "openssl", "version": "3.0.13"}]},
                           source="vendor-portal")
    probes.append(_probe(
        "an-accepted-import-is-labelled-untrusted-and-cannot-override",
        clean["verdict"] == "ACCEPTED_AS_EVIDENCE" and clean["trust"] == "UNTRUSTED"
        and all(row["may_override"] is False for row in clean["components"]),
        f"{len(clean['components'])} row(s) marked IMPORTED with a content hash "
        f"{clean['content_hash'][:12]}…, may_override False"))

    deep = {"components": [{"name": f"c{index}", "dependsOn": [f"c{index + 1}"]}
                           for index in range(200)] + [{"name": "c200"}]}
    budget = se.check_budget(deep)
    probes.append(_probe(
        "a-deep-graph-hits-the-depth-limit",
        budget["verdict"] == "REFUSED"
        and any("depth" in problem for problem in budget["problems"]),
        budget["problems"][0]))

    cycle = {"components": [{"name": "a", "dependsOn": ["b"]},
                            {"name": "b", "dependsOn": ["a"]}]}
    cyclic = se.check_budget(cycle)
    probes.append(_probe(
        "a-cyclic-graph-is-refused-rather-than-recursed",
        cyclic["verdict"] == "REFUSED" and cyclic["cycles"] == 1,
        f"{cyclic['cycles']} cycle(s) found iteratively, so a hostile graph cannot exhaust the "
        "stack before it reaches the limit"))

    oversized = se.check_budget({"components": []}, size_bytes=100 * 1024 * 1024)
    probes.append(_probe(
        "a-hundred-megabyte-file-is-refused-by-its-size",
        oversized["verdict"] == "REFUSED"
        and "exceeds the" in oversized["problems"][0],
        oversized["problems"][0]))

    small = se.check_budget({"components": [{"name": "openssl", "dependsOn": ["cffi"]},
                                            {"name": "cffi"}]}, size_bytes=4_096)
    probes.append(_probe(
        "an-ordinary-document-passes-the-budget",
        small["verdict"] == "WITHIN_BUDGET",
        small["statement"]))

    return {"id": "input_safety",
            "question": "can an imported SBOM or a hostile document change the estate?",
            "phase": "17", "probes": probes}


ROWS = (row_parser_qualification, row_deployment_identity, row_build_provenance,
        row_storage_durability, row_signing_ladder, row_vulnerability_status,
        row_vex_and_licence, row_crypto_promotion, row_history_and_diff, row_input_safety)


# --------------------------------------------------------------------------- #
# measure + render
# --------------------------------------------------------------------------- #


def _check_policy() -> dict[str, int]:
    return {"pass": 0, "partial": 1, "fail": 2}


def measure(as_of: date | None = None) -> dict[str, Any]:
    as_of = as_of or datetime.now(timezone.utc).date()
    modules = _load_modules()
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
    qualification = modules["sq"].qualify()
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "counts": counts,
        "rows": rows,
        "qualification": qualification,
        "check_policy": _check_policy(),
        "limits": [
            "the parser matrix runs the readers this repository has, against files this "
            "repository generates. A bank's exporter will produce shapes nobody wrote a case "
            "for, and the honest answer then is an unqualified ecosystem, not a guess",
            "the qualification cases are small files. They prove the readers parse the shape; "
            "they do not prove throughput against a 50,000-component real SBOM",
            "deployment observations are supplied by the platform integration. The chain is "
            "graded here; producing the observation from Kubernetes needs a cluster",
            "the signing ladder verifies the claims a key algorithm can support. Key custody, "
            "HSM-backed signing and certificate chain validation are outside this module",
            "licence states are a vocabulary and a policy lookup. Which licences a bank "
            "accepts is a legal decision this code must not make",
            "the promotion ladder requires evidence of each rung. Producing static, runtime "
            "and network evidence at bank scale needs the collectors named in guides 130-132",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    qualification = report["qualification"]
    lines = [
        "# SBOM evidence: a qualification matrix that runs, and a chain that ends in a pod",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail**",
        "",
        "The review beside this file lists nineteen items. Its sharpest observation is that "
        "*recognised filename ≠ complete compatibility with every format revision* — so this "
        "artifact starts by running the parsers instead of describing them — and it found "
        "three real defects on the first attempt.",
        "",
        "## The parser qualification matrix (item 3)",
        "",
        f"`{qualification['schema']}` · **{qualification['counts']['PASS']} pass · "
        f"{qualification['counts']['PARTIAL']} partial · {qualification['counts']['FIX']} need "
        f"a fix** · qualified: **{qualification['qualified']}**",
        "",
        qualification["statement"],
        "",
        "| Ecosystem | Manifest | Lockfile | Revisions exercised | Verdict |",
        "|---|---|---|---|---|",
    ]
    for ecosystem in qualification["ecosystems"]:
        lines.append(
            f"| {ecosystem['ecosystem']} | {', '.join(ecosystem['manifests'])} | "
            f"{', '.join(ecosystem['lockfiles']) or '—'} | "
            f"{'; '.join(ecosystem['revisions'])} | **{ecosystem['verdict']}** |")
    lines += ["", "### Every case, with what it proved", "",
              "| Case | Revision | Verdict | Result |", "|---|---|---|---|"]
    for row in qualification["rows"]:
        lines.append(f"| `{row['id']}` | {row['revision']} | **{row['verdict']}** | "
                     f"{row['reason']} |")
    lines += [
        "",
        "Three defects were found and fixed in this commit:",
        "",
        "1. **`.csproj` was never dispatched.** `_parse_manifest` looked the parser up by exact "
        "filename, and the `.NET` parser was registered under the key `csproj`, which no "
        "filename equals — so a project file with two `PackageReference` entries produced an "
        "empty SBOM that looked perfectly valid. Parsers registered under an extension now "
        "dispatch by suffix.",
        "2. **An npm range was silently pinned.** `jose: \"^5.0.0\"` was read as version "
        "`5.0.0` with the caret discarded, which is exactly the confusion review item 2 says "
        "the SBOM must keep visible. The reader now carries `raw_spec` verbatim and a "
        "`version_constraint` (`EXACT`, `RANGE`, `ANY`, `NON_VERSION`), so `git+https://…` no "
        "longer lands in a version field at all.",
        "3. **`pyproject.toml` and `Pipfile` were never read as manifests.** Poetry and pipenv "
        "projects whose only declaration is `pyproject.toml` produced a *valid-looking empty "
        "SBOM*: the file was recognised (the lockfile readers used it to attribute direct "
        "dependencies) but no reader ever produced a component from it, so \"no dependencies\" "
        "and \"dependencies we cannot see\" were the same answer. Both files now have manifest "
        "readers, covering PEP 621 `[project]` dependencies, `[project.optional-dependencies]` "
        "extras, Poetry groups, and Pipfile `[packages]`/`[dev-packages]`, with markers and "
        "extras stripped and the specifier preserved.",
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
    lines += [
        "",
        "## What is still missing, in the review's order",
        "",
        "1. **Deployment correlation needs a cluster.** The chain is graded; the observation "
        "that feeds it comes from a Kubernetes or agent integration that is not in this "
        "artifact.",
        "2. **Binary and container format breadth.** The readers here are source-ecosystem "
        "readers; binary/firmware and archive formats need their own qualification matrix.",
        "3. **HA/DR for the artifact store.** The policy refuses unsafe production storage; "
        "proving a restore works is an operational drill, not a unit test.",
        "4. **Vulnerability feed depth.** Matching is purl+version against a supplied advisory "
        "set; range parsing per ecosystem (npm semver, PEP 440, Maven ranges) is the next "
        "step, and until then `INSUFFICIENT_IDENTIFIER` is the honest answer more often than "
        "a bank will like.",
        "5. **SBOM to Digital Twin edges.** Every edge in this artifact carries an evidence id; "
        "wiring those edges into the twin's graph is the integration that still has to land.",
        "",
        "## How to run it",
        "",
        "```bash",
        "python scripts/sbom_evidence.py --as-of 2026-11-02 \\",
        "    --json docs/bank-environment/133-sbom-evidence-and-qualification.json \\",
        "    --md docs/bank-environment/133-sbom-evidence-and-qualification.md",
        "python scripts/sbom_evidence.py --check   # non-zero on FAIL or PARTIAL",
        "```",
        "",
    ]
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
        return _check_policy()["fail"]
    if counts[PARTIAL]:
        return _check_policy()["partial"]
    return _check_policy()["pass"]


if __name__ == "__main__":
    raise SystemExit(main())
