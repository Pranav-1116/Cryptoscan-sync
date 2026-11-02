#!/usr/bin/env python3
"""Guide 135 — three gaps that were still a list: ranges, restore, licence states.

Guide 134 ended with a limits section, and this artifact is the work that removes
three of its entries rather than restating them.

* **Advisory ranges (item 10).** Matching used to be exact-string equality on a
  list of versions, so an advisory that says ``<3.0.13`` or ``^5.0.0`` either
  matched nothing or was never applied. ``devsecops.version_ranges`` now
  implements ordering for semver, PEP 440 and Maven-style versions — including
  the prerelease ordering the old comparator got backwards — plus the constraint
  syntax advisory feeds actually carry. A range the platform *cannot* read is
  reported as ``UNKNOWN``, never as "assessed and clean".
* **Restore (item 8, the half a policy cannot prove).** ``backup_artifact``
  copies an artifact and reads it back; ``restore_drill`` restores into a fresh
  store and verifies byte identity, the manifest digest, the signature, and — the
  control that makes verification mean something — that a single flipped byte is
  detected as ``TAMPERED``.
* **Licence states (item 12).** ``license_states`` gives every component one of
  the seven states the review lists, so "declared" can never render as
  "approved", and the counts say how many nobody has reviewed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import textwrap
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.sbom-gaps-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
DIGEST = "sha256:" + "a" * 64


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "container_scanner"),
                  str(SERVICES / "governance"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import (artifact_store, sbom_evidence, sbom_license,  # noqa: PLC0415
                           sbom_scan, version_ranges)

    return {"store": artifact_store, "se": sbom_evidence, "license": sbom_license,
            "scan": sbom_scan, "vr": version_ranges}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# 1. version ordering
# --------------------------------------------------------------------------- #

#: The orderings the old "split on dots" comparator got wrong, plus the ordinary
#: ones that must keep working. Every row is a version pair and its answer.
ORDERING_CASES: tuple[tuple[str, str, str, int, str], ...] = (
    ("1.0.0-rc1", "1.0.0", "semver", -1, "a release candidate precedes its release"),
    ("1.0.0", "1.0.0+build", "semver", 0, "build metadata does not order"),
    ("1.10.0", "1.9.0", "semver", 1, "10 is not less than 9"),
    ("1.0.0-rc1", "1.0.0-beta.2", "semver", 1, "rc sorts after beta"),
    ("1.0.0a1", "1.0.0", "pep440", -1, "a PEP 440 prerelease precedes the final"),
    ("1.0.0.dev1", "1.0.0a1", "pep440", -1, "a dev release precedes every prerelease"),
    ("1.0.0a1.dev1", "1.0.0a1", "pep440", -1, "a dev of a prerelease precedes that prerelease"),
    ("1.0.0.post1", "1.0.0", "pep440", 1, "a post release follows the final"),
    ("1!1.0", "2.0", "pep440", 1, "an epoch outranks the release numbers"),
    ("1.0", "1.0.0", "pep440", 0, "trailing zeros are not a different version"),
    ("2.0.0", "10.0.0", "generic", -1, "numeric segments compare as numbers"),
    ("1.0.0", "1.0", "generic", 0, "a missing segment is zero"),
)


def row_version_ordering(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    vr = modules["vr"]
    probes: list[dict[str, Any]] = []
    wrong: list[str] = []
    for left, right, ecosystem, expected, why in ORDERING_CASES:
        got = vr.compare(left, right, ecosystem=ecosystem)
        if got != expected:
            wrong.append(f"{ecosystem}: {left} vs {right} -> {got}, expected {expected} ({why})")
    probes.append(_probe(
        "the-ordering-the-old-comparator-got-backwards",
        not wrong,
        f"{len(ORDERING_CASES)} ordering case(s) hold, including a release candidate before its "
        "release and a dev release before its prereleases"
        if not wrong else "; ".join(wrong[:3])))

    families = {name: vr.family_for(name) for name in
                ("npm", "pip", "maven", "nuget", "gem", "composer", "cargo", "debian")}
    probes.append(_probe(
        "each-ecosystem-gets-its-own-comparator",
        families["npm"] == "semver" and families["pip"] == "pep440"
        and families["maven"] == "maven" and families["gem"] == "generic",
        ", ".join(f"{name}→{family}" for name, family in families.items())))

    refusal = ""
    try:
        vr.compare("not-a-version", "1.0.0", ecosystem="semver")
    except vr.ConstraintError as exc:
        refusal = str(exc)
    probes.append(_probe(
        "an-unreadable-version-raises-instead-of-sorting-arbitrarily",
        "not a semantic version" in refusal, refusal[:110]))

    probes.append(_probe(
        "the-platform-has-one-comparator",
        _delegates_to_version_ranges(),
        "container_scan.version_compare delegates to version_ranges: the container matcher "
        "and the SBOM matcher share one engine, and the ecosystem decides whether 1.0.0-rc1 "
        "is a prerelease (npm) or a package revision (Debian)"))

    return {"id": "version_ordering",
            "question": "is 1.0.0-rc1 older than 1.0.0, in every ecosystem?",
            "phase": "10 (range depth)", "probes": probes}


def _delegates_to_version_ranges() -> bool:
    source = (SERVICES / "devsecops" / "devsecops" / "container_scan.py").read_text(
        encoding="utf-8")
    return "from devsecops.version_ranges import ConstraintError, compare" in source


# --------------------------------------------------------------------------- #
# 2. constraint syntax
# --------------------------------------------------------------------------- #

CONSTRAINT_CASES: tuple[tuple[str, str, str, bool], ...] = (
    ("5.2.3", "^5.0.0", "semver", True),
    ("6.0.0", "^5.0.0", "semver", False),
    ("0.2.5", "^0.2.3", "semver", True),
    ("0.3.0", "^0.2.3", "semver", False),
    ("1.2.9", "~1.2.3", "semver", True),
    ("1.3.0", "~1.2.3", "semver", False),
    ("1.2.7", "1.2.x", "semver", True),
    ("1.3.0", "1.2.x", "semver", False),
    ("1.5.0", ">=1.0.0 <2.0.0", "semver", True),
    ("2.0.0", ">=1.0.0 <2.0.0", "semver", False),
    ("3.0.11", ">=3.0.0, <3.0.13", "semver", True),
    ("3.0.13", ">=3.0.0, <3.0.13", "semver", False),
    ("1.4.9", "~=1.4.5", "pep440", True),
    ("1.5.0", "~=1.4.5", "pep440", False),
    ("1.5.0", "[1.0,2.0)", "maven", True),
    ("2.0.0", "[1.0,2.0)", "maven", False),
    ("1.9.0", "1.0.0 || 1.9.0", "semver", True),
    ("1.8.0", "1.0.0 || 1.9.0", "semver", False),
    ("2.32.0", "*", "generic", True),
    ("1.2.3", "!=1.2.3", "semver", False),
    ("3.0.13", "3.0.13", "semver", True),
    ("3.0.12", "3.0.13", "semver", False),
)


def row_constraint_syntax(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    vr = modules["vr"]
    probes: list[dict[str, Any]] = []
    wrong: list[str] = []
    for version, constraint, ecosystem, expected in CONSTRAINT_CASES:
        try:
            got = vr.satisfies(version, constraint, ecosystem=ecosystem)
        except vr.ConstraintError as exc:  # a case that raises is a case that failed
            got = f"ERROR {exc}"
        if got != expected:
            wrong.append(f"{ecosystem} {version} in {constraint!r} -> {got}")
    probes.append(_probe(
        "the-constraint-syntax-advisory-feeds-carry",
        not wrong,
        f"{len(CONSTRAINT_CASES)} constraint case(s) hold across caret, tilde, x-range, "
        "comparator sets, PEP 440 compatible release, Maven intervals, unions and exact pins"
        if not wrong else "; ".join(wrong[:3])))

    parsed = vr.parse_constraint(">=bogus.1", ecosystem="semver")
    probes.append(_probe(
        "an-unreadable-constraint-is-invalid-not-empty",
        parsed["kind"] == "INVALID" and "not a semantic version" in parsed.get("reason", ""),
        f"{parsed['kind']}: {parsed.get('reason')}"))

    probes.append(_probe(
        "a-constraint-explains-itself",
        vr.explain("^1.2.3", ecosystem="npm")["predicates"] == [(">=", "1.2.3"), ("<", "2")],
        f"^1.2.3 (npm) decomposes to {vr.explain('^1.2.3', ecosystem='npm')['predicates']}"))

    affected, unevaluable = vr.any_affected(
        "3.0.11", [">=bogus", ">=3.0.0 <3.0.13"], ecosystem="semver")
    probes.append(_probe(
        "one-unreadable-range-does-not-hide-a-match",
        affected is True and unevaluable == [">=bogus"],
        f"matched on the readable range and kept {unevaluable} as unevaluable"))

    return {"id": "constraint_syntax",
            "question": "can the platform read the ranges a feed actually writes?",
            "phase": "10 (range depth)", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. advisory matching, end to end
# --------------------------------------------------------------------------- #

FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}


def _component(**overrides: Any) -> dict[str, Any]:
    base = {"name": "openssl", "version": "3.0.11", "purl": "pkg:generic/openssl@3.0.11"}
    base.update(overrides)
    return base


def row_advisory_matching(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se = modules["se"]
    probes: list[dict[str, Any]] = []

    def assess(component: dict[str, Any], advisories: list[dict[str, Any]]) -> dict[str, Any]:
        return se.assess_vulnerabilities(component, feed=FEED, advisories=advisories,
                                         as_of=as_of)

    exact = assess(_component(), [{"id": "CVE-1", "package": "pkg:generic/openssl",
                                  "affected_versions": ["3.0.11"]}])
    probes.append(_probe(
        "an-exact-version-list-still-matches",
        exact["status"] == "MATCHED" and exact["match_method"] == "purl+version",
        f"{exact['status']} via {exact['match_method']}"))

    ranged = assess(_component(), [{"id": "CVE-2", "package": "pkg:generic/openssl",
                                   "affected_versions": [">=3.0.0, <3.0.13"]}])
    probes.append(_probe(
        "a-comparator-range-matches-the-version-inside-it",
        ranged["status"] == "MATCHED" and ranged["match_method"] == "purl+range",
        f"{ranged['status']} via {ranged['match_method']}: {ranged['reason']}"))

    outside = assess(_component(version="3.0.13", purl="pkg:generic/openssl@3.0.13"),
                     [{"id": "CVE-2", "package": "pkg:generic/openssl",
                       "affected_versions": [">=3.0.0, <3.0.13"]}])
    probes.append(_probe(
        "a-version-outside-the-range-is-a-real-non-match",
        outside["status"] == "ASSESSED_NO_MATCH" and outside["match_method"] == "purl+range",
        f"{outside['status']}: {outside['reason']}"))

    npm = assess({"name": "jose", "version": "5.2.3", "purl": "pkg:npm/jose@5.2.3",
                  "manager": "npm"},
                 [{"id": "CVE-3", "package": "pkg:npm/jose", "affected_versions": ["^5.0.0"]}])
    probes.append(_probe(
        "a-caret-is-read-the-way-npm-reads-it",
        npm["status"] == "MATCHED" and npm["ecosystem"] == "semver",
        f"jose 5.2.3 in ^5.0.0 -> {npm['status']} (comparator {npm['ecosystem']})"))

    pypi = assess({"name": "cryptography", "version": "41.0.7",
                   "purl": "pkg:pypi/cryptography@41.0.7"},
                  [{"id": "CVE-4", "package": "pkg:pypi/cryptography",
                    "affected_versions": ["<42.0.0"]}])
    probes.append(_probe(
        "the-purl-decides-which-comparator-applies",
        pypi["status"] == "MATCHED" and pypi["ecosystem"] == "pep440",
        f"pypi component compared with the PEP 440 comparator ({pypi['ecosystem']})"))

    prerelease = assess({"name": "widget", "version": "2.0.0-rc1",
                         "purl": "pkg:npm/widget@2.0.0-rc1"},
                        [{"id": "CVE-5", "package": "pkg:npm/widget",
                          "affected_versions": [">=2.0.0"]}])
    probes.append(_probe(
        "a-prerelease-is-not-inside-a-range-that-starts-at-the-release",
        prerelease["status"] == "ASSESSED_NO_MATCH",
        f"2.0.0-rc1 against >=2.0.0 -> {prerelease['status']}: the old comparator would have "
        "matched this"))

    windowed = assess(_component(), [{"id": "CVE-6", "package": "pkg:generic/openssl",
                                      "introduced": "3.0.0", "fixed": "3.0.13"}])
    probes.append(_probe(
        "an-introduced-fixed-window-is-understood",
        windowed["status"] == "MATCHED" and windowed["match_method"] == "purl+range",
        f"{windowed['status']}: the container scanner's advisory shape is read by the same "
        "engine"))

    broken = assess(_component(), [{"id": "CVE-7", "package": "pkg:generic/openssl",
                                    "affected_versions": [">=three"]}])
    probes.append(_probe(
        "an-advisory-range-nobody-can-read-is-unknown",
        broken["status"] == "UNKNOWN" and broken["unevaluable_ranges"],
        f"{broken['status']} rather than a clean result: {broken['reason']}"))

    clean = assess(_component(version="3.0.13", purl="pkg:generic/openssl@3.0.13"),
                   [{"id": "CVE-8", "package": "pkg:generic/openssl",
                     "affected_versions": [">=3.0.0, <3.0.13"]}])
    probes.append(_probe(
        "a-clean-answer-still-carries-the-feed-and-the-method",
        clean["status"] == "ASSESSED_NO_MATCH" and clean["feed"] == "osv"
        and clean["feed_timestamp"] and clean["match_method"] == "purl+range",
        f"{clean['status']} against {clean['feed']} {clean['feed_timestamp']} by "
        f"{clean['match_method']}"))

    return {"id": "advisory_matching",
            "question": "does an advisory range apply, or only an exact version string?",
            "phase": "10", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. restore drill
# --------------------------------------------------------------------------- #


def row_restore(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    store = modules["store"]
    scan = modules["scan"]
    probes: list[dict[str, Any]] = []
    workspace = Path(tempfile.mkdtemp(prefix="guide135-restore-"))
    primary_root = workspace / "primary"
    backup_root = workspace / "backup"
    primary_root.mkdir()

    saved = os.environ.get("SBOM_STORAGE_DIR")
    os.environ["SBOM_STORAGE_DIR"] = str(primary_root)
    os.environ["ENVIRONMENT"] = "test"
    try:
        from governance.backup_jobs import DiskBackupStorage

        bom = scan.render_sbom({"target": "/srv/app",
                               "packages": [{"name": "openssl", "version": "3.0.13"}],
                               "libraries": [], "binaries": [], "vulnerabilities": [],
                               "manifests": [], "lockfiles": [], "dependencies": []},
                              fmt="cyclonedx", created_by="guide-135")
        stored = store.store_binary_artifact(
            scan={"target": "/srv/app", "files_walked": 1},
            result={"target": "/srv/app", "packages": [{"name": "openssl", "version": "3.0.13"}],
                    "manifests": [], "lockfiles": [], "dependencies": [], "libraries": [],
                    "binaries": []},
            bom=bom, cbom={}, created_by="guide-135", secret=("demo-secret", "settings"))
        key = stored["artifact_key"]
        primary = store.artifact_storage()
        backup = DiskBackupStorage(backup_root)

        backed = store.backup_artifact(primary, backup, key)
        probes.append(_probe(
            "a-backup-is-read-back-and-compared",
            backed["verdict"] == "BACKED_UP" and backed["byte_identical"]
            and backed["manifest"],
            backed["statement"]))

        drill = store.restore_drill(backup, key, secret="demo-secret")
        probes.append(_probe(
            "the-drill-restores-into-a-fresh-store-not-the-primary",
            drill["verdict"] == "RESTORED" and drill["byte_identical"],
            drill["statement"]))

        probes.append(_probe(
            "the-restored-artifact-still-verifies",
            drill["digest_check"] == "MATCH" and drill["signature_check"] == "VALID",
            f"digest {drill['digest_check']}, signature {drill['signature_check']} — a restore "
            "that only checks presence would pass a corrupted file"))

        probes.append(_probe(
            "a-flipped-byte-is-caught-so-the-check-is-not-a-rubber-stamp",
            drill["tamper_detected"] is True,
            "one byte of the restored artifact was inverted and verification returned "
            "TAMPERED"))

        unsigned = store.restore_drill(backup, key)
        probes.append(_probe(
            "without-a-secret-the-signature-check-is-reported-as-absent",
            unsigned["signature_check"] is None and unsigned["verdict"] == "RESTORED",
            "no secret supplied -> signature_check null rather than an invented VALID"))

        tampered = DiskBackupStorage(workspace / "tampered")
        blob = bytearray(backup.get(key))
        blob[-1] ^= 0xFF
        tampered.put(key, bytes(blob))
        manifest = store._manifest_for(backup, key)
        tampered.put_manifest(key, manifest or {})
        broken = store.restore_drill(tampered, key, secret="demo-secret")
        probes.append(_probe(
            "a-corrupted-backup-fails-the-drill",
            broken["verdict"] == "FAILED",
            f"a backup whose bytes were altered -> {broken['verdict']} "
            f"(digest {broken['digest_check']})"))

        many = store.restore_drill_all(backup, secret="demo-secret")
        probes.append(_probe(
            "the-drill-runs-over-every-artifact",
            many["verdict"] == "RESTORED" and many["artifacts"] >= 1,
            many["statement"]))

        empty = store.restore_drill_all(DiskBackupStorage(workspace / "empty"))
        probes.append(_probe(
            "an-empty-backup-proves-nothing-and-says-so",
            empty["verdict"] == "NO_ARTIFACTS"
            and "proves nothing" in empty["statement"],
            empty["statement"]))
    finally:
        if saved is None:
            os.environ.pop("SBOM_STORAGE_DIR", None)
        else:
            os.environ["SBOM_STORAGE_DIR"] = saved

    return {"id": "restore_drill",
            "question": "has a restore ever actually been run, or only configured?",
            "phase": "8", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. licence states
# --------------------------------------------------------------------------- #

LICENCE_BOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [
        {"name": "openssl", "version": "3.0.13",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"name": "left-pad", "version": "1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "gpl-helper", "version": "2.1.0",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"name": "mystery-lib", "version": "0.1"},
    ],
}


def row_license_states(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    license_module = modules["license"]
    probes: list[dict[str, Any]] = []

    states = license_module.license_states(
        LICENCE_BOM, policy={"allowed": ["MIT"], "forbidden": ["GPL-3.0"]})
    by_component = {row["component"]: row["state"] for row in states["components"]}
    probes.append(_probe(
        "a-declared-licence-is-not-an-approval",
        by_component["openssl"] == "DECLARED",
        f"openssl declares Apache-2.0 -> {by_component['openssl']}: nothing has reviewed it"))

    probes.append(_probe(
        "only-a-policy-decision-produces-accepted-or-rejected",
        by_component["left-pad"] == "POLICY_ACCEPTED"
        and by_component["gpl-helper"] == "POLICY_REJECTED",
        f"MIT on the allowed list -> {by_component['left-pad']}; GPL-3.0 forbidden -> "
        f"{by_component['gpl-helper']}"))

    probes.append(_probe(
        "a-component-with-no-licence-is-unknown",
        by_component["mystery-lib"] == "UNKNOWN", "no declaration, no detection -> UNKNOWN"))

    conflicting = license_module.license_states(LICENCE_BOM,
                                                detected={"openssl": "GPL-3.0-only"})
    conflict = next(row for row in conflicting["components"] if row["component"] == "openssl")
    probes.append(_probe(
        "declaration-and-detection-disagreeing-is-a-conflict",
        conflict["state"] == "CONFLICT",
        f"declared Apache-2.0, detected GPL-3.0-only -> {conflict['state']}"))

    detected_only = license_module.license_states(
        {"bomFormat": "CycloneDX", "specVersion": "1.5",
         "components": [{"name": "silent", "version": "1.0"}]},
        detected={"silent": "MIT"})
    probes.append(_probe(
        "a-detection-without-a-declaration-is-DETECTED-not-approved",
        detected_only["components"][0]["state"] == "DETECTED",
        f"document silent, detector found MIT -> {detected_only['components'][0]['state']}"))

    probes.append(_probe(
        "the-vocabulary-is-the-reviews-seven-states",
        tuple(license_module.LICENSE_STATES) == (
            "DECLARED", "DETECTED", "UNKNOWN", "CONFLICT", "POLICY_ACCEPTED",
            "POLICY_REJECTED", "REQUIRES_REVIEW"),
        ", ".join(license_module.LICENSE_STATES)))

    probes.append(_probe(
        "the-summary-says-how-many-nobody-reviewed",
        states["counts"]["POLICY_ACCEPTED"] == 1 and "not legal advice" in states["statement"],
        states["statement"]))

    router = (ROOT / "services" / "api" / "api" / "routers" / "devsecops.py").read_text(
        encoding="utf-8")
    probes.append(_probe(
        "the-licence-endpoint-returns-the-states",
        "license_states(doc" in router and '"state_rows": states["components"]' in router,
        "/sbom/license returns `states`, `state_rows` and `state_statement` beside the policy "
        "verdict"))

    return {"id": "license_states",
            "question": "does the licence report ever render a detection as an approval?",
            "phase": "12", "probes": probes}


ROWS = (row_version_ordering, row_constraint_syntax, row_advisory_matching, row_restore,
        row_license_states)


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
        "ordering_cases": len(ORDERING_CASES),
        "constraint_cases": len(CONSTRAINT_CASES),
        "rows": rows,
        "limits": [
            "the comparator is a library, not a package manager: it does not resolve "
            "dependency graphs and it cannot know that a vendor's build rewrote a version "
            "string before it was recorded",
            "advisory matching is still against a supplied feed. Which advisory is true for "
            "a given build is the feed vendor's claim, not the platform's",
            "the restore drill runs against the configured artifact store. It proves the "
            "backup target holds a restorable copy; it does not prove the backup is in a "
            "different failure domain (that is an operational control, not code)",
            "licence states are a vocabulary and a policy lookup. Which licences a bank "
            "accepts remains a legal decision this code must not make",
            "the seven licence states are reported per component; obligations that depend on "
            "distribution model (SaaS versus shipped binary) are outside this artefact",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Three gaps, closed by measurement",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 134 ended with a list of things it had not proven. Three of those entries are "
        "now code, and this artifact is where they are measured:",
        "",
        "1. **Advisory ranges.** Matching was exact-string equality, so an advisory that says "
        "`<3.0.13` or `^5.0.0` never applied. `devsecops/version_ranges.py` implements "
        "ordering per ecosystem and the constraint syntax feeds carry; a range it cannot read "
        "is `UNKNOWN`, never \"assessed and clean\".",
        "2. **Restore.** A backup nobody restored is a hope. `backup_artifact` reads its own "
        "copy back, and `restore_drill` restores into a *fresh* store and verifies byte "
        "identity, the manifest digest, the signature, and that one flipped byte is caught.",
        "3. **Licence states.** The review's seven values are now produced per component, so "
        "\"declared\" can never render as \"approved\" and the summary says how many nobody "
        "has reviewed.",
        "",
        f"The comparator is exercised by {report['ordering_cases']} ordering cases and "
        f"{report['constraint_cases']} constraint cases, including the ones the previous "
        "\"split on dots\" comparator got backwards.",
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
              "python scripts/sbom_gaps.py --as-of 2026-11-02 \\",
              "--json docs/bank-environment/135-sbom-ranges-restore-licences.json \\",
              "--md docs/bank-environment/135-sbom-ranges-restore-licences.md",
              "python scripts/sbom_gaps.py --check   # non-zero on FAIL or PARTIAL",
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
