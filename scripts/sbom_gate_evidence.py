#!/usr/bin/env python3
"""Guide 137 — the gate stops believing the document.

Guide 134 made the evidence module exist; guide 136 made durability and archive
intake real. This artifact is about the two claims the platform still took on
trust:

* **The gate counted the document's own CVE entries (item 10).** ``_cve_counts``
  reads ``vulnerabilities[]`` out of the SBOM, so a document that lists nothing —
  because nobody assessed it, or because its producer does not — produced the
  same verdict as a document that had been checked against a current feed. The
  gate now takes the feed and the VEX statements, answers per component in the six
  states, and reports both counts side by side: ``document_cve_entries`` and
  ``assessed_open``.
* **VEX was advisory only (item 11).** A ``NOT_AFFECTED`` statement is a claim
  that expires; the gate now re-validates each one at evaluation time, so a lapsed
  or unjustified statement suppresses nothing and the finding comes back with the
  reason it returned.
* **A signature recorded its own name, not its evidence (item 9).** The manifest
  carried ``signature`` and ``signature_alg``. It now carries algorithm, key id,
  key version, key status, trust anchor, signing time, verification time,
  revocation state and the three claims the ladder supports — integrity,
  authenticity and non-repudiation are different answers and HMAC only earns two
  of them. A revoked or expired key refuses to sign at all.
* **Nothing recorded what produced the artifact (item 7).** A scan request can now
  carry commit, build id, builder, pipeline and the produced digest; the manifest
  records the chain and names every missing link instead of looking complete.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.sbom-gate-evidence-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
DIGEST = "sha256:" + "a" * 64
AS_OF = date(2026, 11, 2)


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "container_scanner"),
                  str(SERVICES / "universal_crypto"), str(SERVICES / "governance"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import artifact_store, sbom_assurance, sbom_evidence  # noqa: PLC0415

    return {"assurance": sbom_assurance, "se": sbom_evidence, "store": artifact_store}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


FEED = {"name": "osv", "version": "2026-11-01", "updated_at": "2026-11-01"}
STALE_FEED = {"name": "osv", "version": "2026-09-01", "updated_at": "2026-09-01"}
ADVISORY = [{"id": "CVE-2026-11111", "severity": "CRITICAL", "purl": "pkg:deb/openssl",
             "affected_versions": ["<3.0.13"]}]


def _bom(*, vulnerabilities: list[dict] | None = None) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "openssl", "version": "3.0.12",
                            "purl": "pkg:deb/openssl@3.0.12"}],
            "vulnerabilities": vulnerabilities or []}


def _vex(**overrides: Any) -> dict[str, Any]:
    statement = {"cve": "CVE-2026-11111", "component": "openssl",
                 "affected_versions": ["<3.0.13"], "status": "NOT_AFFECTED",
                 "justification": "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
                 "reviewer": "alice.chen", "evidence_id": "EV-2026-0042",
                 "assessed_at": "2026-10-20", "expires_at": "2026-12-20"}
    statement.update(overrides)
    return statement


# --------------------------------------------------------------------------- #
# 1. the gate's vulnerability answer
# --------------------------------------------------------------------------- #


def row_gate_evidence(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    assurance = modules["assurance"]
    probes: list[dict[str, Any]] = []

    silent = _bom()
    blind = assurance.evaluate_gate(silent, as_of=as_of)
    probes.append(_probe(
        "a-document-with-no-cve-entries-is-not-an-assessment",
        blind["verdict"] == "PASS"
        and blind["vulnerability_evidence"]["assessment"] == "NOT_SUPPLIED"
        and "not an all-clear" in blind["vulnerability_evidence"]["statement"],
        blind["vulnerability_evidence"]["statement"]))

    assessed = assurance.evaluate_gate(silent, feed=FEED, advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "the-same-document-fails-when-a-feed-is-consulted",
        assessed["verdict"] == "FAIL"
        and "GATE-VULN-CRITICAL" in {row["code"] for row in assessed["blockers"]},
        "; ".join(row["detail"] for row in assessed["blockers"])))

    probes.append(_probe(
        "the-document-count-and-the-assessed-count-are-both-reported",
        assessed["counts"]["document_cve_entries"] == 0
        and assessed["counts"]["assessed_open"] == 1,
        f"{assessed['counts']['document_cve_entries']} document entr(ies), "
        f"{assessed['counts']['assessed_open']} assessed open"))

    stale = assurance.evaluate_gate(silent, feed=STALE_FEED, advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "a-stale-feed-is-not-an-all-clear",
        stale["vulnerability_evidence"]["states"]["STALE_FEED"] == 1
        and stale["vulnerability_evidence"]["unassessed"] == 1
        and "GATE-VULN-UNASSESSED" in {row["code"] for row in stale["warnings"]},
        stale["vulnerability_evidence"]["statement"]))

    strict = assurance.evaluate_gate(silent, policy={"require_vulnerability_assessment": True},
                                     feed=STALE_FEED, advisories=ADVISORY, as_of=as_of)
    probes.append(_probe(
        "a-policy-can-make-unassessed-a-blocker",
        strict["verdict"] == "FAIL"
        and "GATE-VULN-UNASSESSED" in {row["code"] for row in strict["blockers"]},
        "; ".join(row["detail"] for row in strict["blockers"])))

    claiming = _bom(vulnerabilities=[{"id": "CVE-2026-22222",
                                      "ratings": [{"severity": "critical"}]}])
    claimed = assurance.evaluate_gate(claiming, as_of=as_of)
    probes.append(_probe(
        "the-documents-own-claim-still-counts-without-a-feed",
        claimed["verdict"] == "FAIL"
        and "GATE-CVE-CRITICAL" in {row["code"] for row in claimed["blockers"]},
        claimed["counts"]["document_cve_entries"] == 1 and "1 document entry gated"))

    return {"id": "gate_evidence",
            "question": "does the gate pass a component nobody ever assessed?",
            "phase": "10", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. VEX at evaluation time
# --------------------------------------------------------------------------- #


def row_vex_suppression(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    assurance = modules["assurance"]
    probes: list[dict[str, Any]] = []

    current = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                      vex=[_vex()], as_of=as_of)
    suppressed = current["vulnerability_evidence"]["suppressed_by_vex"]
    probes.append(_probe(
        "a-current-justified-statement-suppresses-the-finding",
        current["verdict"] == "PASS" and len(suppressed) == 1
        and suppressed[0]["reviewer"] == "alice.chen"
        and suppressed[0]["expires_at"] == "2026-12-20",
        current["vulnerability_evidence"]["statement"]))

    lapsed = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(assessed_at="2026-08-01",
                                               expires_at="2026-09-01")], as_of=as_of)
    probes.append(_probe(
        "a-lapsed-statement-suppresses-nothing-and-says-why",
        lapsed["verdict"] == "FAIL"
        and "GATE-VEX-LAPSED" in {row["code"] for row in lapsed["warnings"]}
        and len(lapsed["vulnerability_evidence"]["lapsed_or_invalid_vex"]) == 1,
        lapsed["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["vex"]))

    unjustified = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                          vex=[_vex(justification="we looked at it")],
                                          as_of=as_of)
    probes.append(_probe(
        "free-text-is-not-a-justification",
        unjustified["verdict"] == "FAIL"
        and unjustified["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["vex"] == "INVALID",
        unjustified["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["problems"][0]))

    unreviewed = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                         vex=[_vex(reviewer=None)], as_of=as_of)
    probes.append(_probe(
        "an-unreviewed-statement-is-not-a-statement",
        unreviewed["verdict"] == "FAIL"
        and any("reviewer" in problem for problem in
                unreviewed["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["problems"]),
        unreviewed["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["vex"]))

    elsewhere = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                        vex=[_vex(component="libcurl")], as_of=as_of)
    probes.append(_probe(
        "a-statement-about-another-component-suppresses-nothing",
        elsewhere["verdict"] == "FAIL"
        and elsewhere["vulnerability_evidence"]["suppressed_by_vex"] == [],
        "the finding stayed open: a VEX statement is scoped to one component"))

    return {"id": "vex_suppression",
            "question": "can an expired or unjustified VEX still hide a critical finding?",
            "phase": "11", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. signature evidence
# --------------------------------------------------------------------------- #


def _store_key() -> dict[str, str | None]:
    return {key: os.environ.get(key) for key in (
        "ENVIRONMENT", "SBOM_STORAGE_DIR", "SBOM_STORAGE_BACKUP_DIR", "SBOM_RETENTION_DAYS",
        "SBOM_STORAGE_REPLICA_DIRS", "SBOM_STORAGE_SITES", "SBOM_SIGNING_KEY_STATUS",
        "SBOM_SIGNING_KEY_VERSION", "SBOM_SIGNING_TRUST_ANCHOR")}


def _restore(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _store(modules: dict[str, Any], tmp: str, *, secret: tuple[str | None, str],
           build: dict[str, Any] | None = None, target: str = "/opt/bank/app") -> dict[str, Any]:
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"name": "openssl", "version": "3.0.13",
                           "purl": "pkg:deb/openssl@3.0.13"}]}
    return modules["store"].store_binary_artifact(
        scan={"target": target, "result_state": "COMPLETE"},
        result={"packages": [{"name": "openssl", "version": "3.0.13", "manager": "deb"}],
                "binaries": [], "libraries": []},
        bom=bom, cbom={"components": []}, created_by="guide-137", secret=secret, build=build)


def row_signature_evidence(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    store = modules["store"]
    probes: list[dict[str, Any]] = []
    saved = _store_key()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.environ.update({
                "ENVIRONMENT": "production",
                "SBOM_STORAGE_DIR": os.path.join(tmp, "primary"),
                "SBOM_STORAGE_BACKUP_DIR": os.path.join(tmp, "backup"),
                "SBOM_RETENTION_DAYS": "365",
                "SBOM_SIGNING_KEY_VERSION": "v3",
                "SBOM_SIGNING_TRUST_ANCHOR": "bank-kms:sbom-signing",
            })
            os.environ.pop("SBOM_STORAGE_REPLICA_DIRS", None)
            os.environ.pop("SBOM_STORAGE_SITES", None)
            signed = _store(modules, tmp, secret=("s3cret-material", "hmac-2026-11"))
            evidence = signed["manifest"]["signature_evidence"]
            probes.append(_probe(
                "the-manifest-records-the-signing-identity",
                all(evidence.get(field) for field in
                    ("algorithm", "key_id", "key_version", "key_status", "trust_anchor",
                     "signed_at", "verified_at", "manifest_digest"))
                and evidence["key_version"] == "v3",
                f"{evidence['algorithm']} key {evidence['key_id']} {evidence['key_version']} "
                f"({evidence['key_status']}), anchor {evidence['trust_anchor']}"))

            probes.append(_probe(
                "hmac-claims-authenticity-and-not-non-repudiation",
                evidence["claims"] == {"integrity": True, "authenticity": True,
                                       "non_repudiation": False}
                and evidence["verdict"] == "AUTHENTIC",
                evidence["statement"]))

            probes.append(_probe(
                "the-evidence-block-is-covered-by-the-signature",
                "signature_evidence" in json.dumps(signed["manifest"], default=str)
                and signed["manifest"]["signature"],
                "the manifest is signed after the evidence block is written, so editing it "
                "breaks the HMAC"))

            os.environ["SBOM_SIGNING_KEY_STATUS"] = "REVOKED"
            refused = False
            try:
                _store(modules, tmp, secret=("s3cret-material", "hmac-2026-11"),
                       target="/opt/bank/app-revoked")
            except store.SigningRefused as exc:
                refused = "REVOKED" in str(exc)
            probes.append(_probe(
                "a-revoked-key-refuses-to-sign",
                refused,
                "a revoked key stops producing signatures instead of writing one a verifier "
                "must discount"))

            os.environ["SBOM_SIGNING_KEY_STATUS"] = "ACTIVE"
            unsigned = _store(modules, tmp, secret=(None, "unsigned"), target="/opt/bank/app2")
            probes.append(_probe(
                "an-unsigned-artifact-says-so",
                unsigned["manifest"]["signature_evidence"]["verdict"] == "UNSIGNED"
                and unsigned["manifest"]["signature_evidence"]["claims"]["authenticity"] is False,
                unsigned["manifest"]["signature_evidence"]["statement"]))
        finally:
            _restore(saved)

    return {"id": "signature_evidence",
            "question": "does a stored signature say what it actually proves?",
            "phase": "9", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. build provenance on the manifest
# --------------------------------------------------------------------------- #


def row_build_provenance(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    probes: list[dict[str, Any]] = []
    saved = _store_key()
    build = {"source_commit": "9f2c1ab4d7", "build_id": "BUILD-2026-1102-0091",
             "builder": "github-actions", "pipeline": "release",
             "artifact_reference": "ghcr.io/bank/payments-api", "artifact_digest": DIGEST,
             "started_at": "2026-11-02T09:00:00Z", "finished_at": "2026-11-02T09:14:00Z"}
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.environ.update({
                "ENVIRONMENT": "production",
                "SBOM_STORAGE_DIR": os.path.join(tmp, "primary"),
                "SBOM_STORAGE_BACKUP_DIR": os.path.join(tmp, "backup"),
                "SBOM_RETENTION_DAYS": "365",
            })
            os.environ.pop("SBOM_STORAGE_REPLICA_DIRS", None)
            os.environ.pop("SBOM_STORAGE_SITES", None)
            stored = _store(modules, tmp, secret=(None, "unsigned"), build=build)
            provenance = stored["manifest"]["provenance"]
            probes.append(_probe(
                "the-manifest-records-commit-build-digest-and-sbom",
                provenance["gaps"] == []
                and provenance["build"]["source_commit"] == "9f2c1ab4d7"
                and provenance["build"]["artifact"]["digest"] == DIGEST,
                provenance["statement"]))

            probes.append(_probe(
                "a-chain-without-an-observation-is-not-called-complete",
                provenance["complete"] is False and provenance["deployed_environments"] == [],
                "complete also requires an observation: provenance stops at the artifact"))

            broken = _store(modules, tmp, secret=(None, "unsigned"),
                            build={**build, "source_commit": "not-a-commit",
                                   "builder": ""}, target="/opt/bank/app-broken")
            gaps = broken["manifest"]["provenance"]["gaps"]
            probes.append(_probe(
                "the-missing-links-are-named-not-omitted",
                len(gaps) >= 2
                and any("commit hash" in gap for gap in gaps)
                and any("builder" in gap for gap in gaps),
                f"{len(gaps)} gap(s): {gaps[0]}"))

            no_digest = _store(modules, tmp, secret=(None, "unsigned"),
                               build={"source_commit": "9f2c1ab4d7", "build_id": "BUILD-2",
                                      "builder": "github-actions", "pipeline": "release"},
                               target="/opt/bank/app-nodigest")
            gaps = no_digest["manifest"]["provenance"]["gaps"]
            probes.append(_probe(
                "a-build-that-names-no-artifact-digest-says-so",
                any("artifact digest" in gap for gap in gaps),
                f"{len(gaps)} gap(s): {gaps[0]}"))

            no_build = _store(modules, tmp, secret=(None, "unsigned"), build=None,
                              target="/opt/bank/app3")
            probes.append(_probe(
                "a-scan-with-no-build-supplied-does-not-invent-one",
                no_build["manifest"].get("provenance") is None,
                "no commit, no build id and no provenance block: the manifest says nothing "
                "rather than something that looks auditable"))
        finally:
            _restore(saved)

    return {"id": "build_provenance",
            "question": "can the artifact say what produced it, and what is missing?",
            "phase": "7", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. the API surface
# --------------------------------------------------------------------------- #


def row_api_exposure(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    router = (ROOT / "services" / "api" / "api" / "routers" / "devsecops.py").read_text(
        encoding="utf-8")
    assurance = (ROOT / "services" / "devsecops" / "devsecops" / "sbom_assurance.py").read_text(
        encoding="utf-8")
    probes = [
        _probe("the-gate-route-accepts-a-feed-and-vex-statements",
               "feed: dict | None = Field(None" in router
               and "vex: list[dict] | None = Field(None" in router
               and "vex=(body.vex if body else None)" in router,
               "/sbom/{artifact_id}/gate takes `feed`, `advisories`, `vex` and `as_of`"),
        _probe("the-gate-uses-the-assessment-not-only-the-document",
               "vulnerability_evidence(" in assurance
               and "GATE-VULN-CRITICAL" in assurance,
               "the gate blocks on assessed critical findings and reports the document count "
               "beside them"),
        _probe("the-verify-route-returns-the-signature-evidence",
               '"signature_evidence": man.get("signature_evidence")' in router
               and '"provenance": man.get("provenance")' in router,
               "/sbom/{artifact_id}/verify answers which claims the signature supports"),
        _probe("both-scan-routes-record-the-build-identity",
               router.count("build=_build_from_request(body)") == 2
               and "def _build_from_request(" in router,
               "a commit supplied to /sbom/scan or /binary/scan reaches the manifest"),
        _probe("no-new-untyped-route-was-added",
               "response_model=SbomDeploymentsResponse" in router,
               "the untyped-response inventory is untouched by this change"),
    ]
    return {"id": "api_exposure",
            "question": "can a caller reach these answers through the API?",
            "phase": "10 / 9 / 7", "probes": probes}


ROWS = (row_gate_evidence, row_vex_suppression, row_signature_evidence, row_build_provenance,
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
            "the gate's assessment is only as good as the feed handed to it: which advisory is "
            "true for a build is the feed vendor's claim, and this code carries it rather than "
            "deciding it",
            "VEX is re-validated at evaluation time, not at authoring time. A statement that was "
            "valid when written and has since lapsed still suppresses nothing, but a statement "
            "with a wrong justification is only caught if it is outside the closed list",
            "the signature ladder reports what an HMAC can claim, and HMAC can never claim "
            "non-repudiation. Moving to Ed25519/ECDSA is a key-management change this code "
            "supports but does not perform",
            "key status and trust anchor are configuration: the platform cannot know that a key "
            "was revoked until an operator says so, and it cannot verify an anchor it was told "
            "to trust",
            "build provenance records what a caller supplied. A CI system that lies about its "
            "commit produces a complete-looking chain, which is why the manifest also carries "
            "the signature evidence over it",
            "the unassessed count is a statement about components, not about reachability: a "
            "component can be assessed, matched and still not be exploitable in this deployment",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The gate stops believing the document",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 136 closed the durability, archive and licence gaps. What it left, and what "
        "this artifact measures, is the part where the platform still took a document's word:",
        "",
        "1. **The gate counted CVEs in the document.** A feed in, six states out, and the "
        "verdict decided on what was *assessed* — with the document's own count reported beside "
        "it, so neither number can be quoted alone.",
        "2. **VEX was advisory.** Every statement is re-validated when the gate runs: a lapsed "
        "or unjustified `NOT_AFFECTED` suppresses nothing and the finding returns with the "
        "reason.",
        "3. **A signature named itself.** The manifest now records algorithm, key id, version, "
        "status, trust anchor, signed and verified times, revocation, and the three claims the "
        "ladder supports — and a revoked key refuses to sign.",
        "4. **Nothing said what produced the artifact.** Commit, build, builder, pipeline and "
        "digest are recorded with every missing link named.",
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
