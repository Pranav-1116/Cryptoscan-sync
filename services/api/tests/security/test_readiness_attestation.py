"""PASS-shaped local JSON is not bank readiness without an external signature."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import bank_readiness
from scripts.bank_readiness import artifact, require_attestation
from scripts.readiness_attestation import SCHEMA, verify_artifact

COMMIT = "a" * 40
SITE = "test-bank-installation"


def signed_fixture(tmp_path: Path, *, category: str = "hsm", report=None):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(report if report is not None else
                                   {"verdict": "PASS", "checks": [{"status": "PASS"}]}))
    key = Ed25519PrivateKey.generate()  # test-only: never a deployment signer
    public = tmp_path / "test-public.pem"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    directory = tmp_path / "attestations"
    directory.mkdir()
    body = {
        "schema": SCHEMA, "algorithm": "Ed25519", "category": category,
        "artifact_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "repository_commit": COMMIT, "site_id": SITE,
        "issued_at": "2026-11-13T00:00:00Z", "key_id": "test-only",
        "issuer": "test assessor", "approval_ref": "test-review-1",
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    attestation = directory / f"{category}.attestation.json"
    attestation.write_text(json.dumps({**body,
        "signature": base64.b64encode(key.sign(payload)).decode("ascii")}))
    return evidence, directory, public


def test_unsigned_pass_artifact_fails_readiness(tmp_path):
    evidence, directory, key = signed_fixture(tmp_path)
    row = artifact(evidence, "hsm")
    assert row["status"] == "PASS"  # content status, not independent proof
    refused = require_attestation(row, evidence, category="hsm",
                                  attestation_dir=None,
                                  trusted_public_key=key,
                                  site_id=SITE, repository_commit=COMMIT)
    assert refused["status"] == "FAIL"
    accepted = require_attestation(row, evidence, category="hsm",
                                   attestation_dir=directory,
                                   trusted_public_key=key,
                                   site_id=SITE, repository_commit=COMMIT)
    assert accepted["status"] == "PASS"
    assert accepted["attestation"]["artifact_sha256"] == row["artifact_sha256"]


def test_signature_is_bound_to_site_revision_category_and_bytes(tmp_path):
    evidence, directory, key = signed_fixture(tmp_path)
    attestation = directory / "hsm.attestation.json"
    for category, commit, site in (("postgresql_dr", COMMIT, SITE),
                                   ("hsm", "b" * 40, SITE),
                                   ("hsm", COMMIT, "other-bank")):
        try:
            verify_artifact(evidence, attestation, key, category=category,
                            repository_commit=commit, site_id=site)
            assert False, "wrong signed scope must fail"
        except ValueError:
            pass
    evidence.write_text('{"verdict":"PASS","altered":true}')
    refused = require_attestation(artifact(evidence, "hsm"), evidence,
                                  category="hsm", attestation_dir=directory,
                                  trusted_public_key=key, site_id=SITE,
                                  repository_commit=COMMIT)
    assert refused["status"] == "FAIL"


def test_readiness_report_refuses_an_unsigned_external_pass(tmp_path):
    evidence, _, _ = signed_fixture(tmp_path)
    engineering = tmp_path / "engineering.json"
    engineering.write_text('{"verdict":"PASS"}')
    output = tmp_path / "readiness.json"
    result = bank_readiness.main([
        "--out", str(output), "--engineering", str(engineering),
        "--hsm", str(evidence), "--site-id", SITE])
    assert result != 0
    rows = {row["category"]: row for row in json.loads(output.read_text())["categories"]}
    assert rows["hsm"]["status"] == "FAIL"
    assert "signed attestation" in rows["hsm"]["detail"]
    assert rows["browser_journey"]["status"] == "SKIP"
    assert "browser_journey" in bank_readiness.REQUIRED_CATEGORIES
    # The durable binary job backend is now real and declared (binary_scan_jobs
    # leased handoff + BINARY_ASYNC_BACKEND=database in the deploy configs), so
    # this code-level check passes; its remaining restart/replica proof must be
    # NAMED as deferred to the signed integrations artifact, never assumed.
    assert rows["binary_async_durability"]["status"] == "PASS"
    assert "signed integrations artifact" in rows["binary_async_durability"]["detail"]
    assert "binary_async_durability" in bank_readiness.REQUIRED_CATEGORIES


def test_browser_report_requires_named_steps_and_trace_digests(tmp_path):
    evidence, directory, key = signed_fixture(tmp_path, category="browser_journey")
    refused = require_attestation(artifact(evidence, "browser_journey"), evidence,
                                  category="browser_journey", attestation_dir=directory,
                                  trusted_public_key=key, site_id=SITE,
                                  repository_commit=COMMIT)
    assert refused["status"] == "FAIL"

    fresh = tmp_path / "valid"
    fresh.mkdir()
    steps = ("login", "authorized_scan", "retained_evidence", "six_boms",
             "digital_twin", "simulation_unchanged", "remediation_rescan")
    report = {"schema": "cryptoscan.browser-journey/1", "verdict": "PASS",
              "site_id": SITE, "repository_commit": COMMIT,
              "browser": {"name": "test-chromium", "version": "test-only"},
              "checks": [{"id": step, "status": "PASS", "evidence_sha256": "a" * 64}
                         for step in steps]}
    evidence, directory, key = signed_fixture(fresh, category="browser_journey",
                                               report=report)
    accepted = require_attestation(artifact(evidence, "browser_journey"), evidence,
                                   category="browser_journey", attestation_dir=directory,
                                   trusted_public_key=key, site_id=SITE,
                                   repository_commit=COMMIT)
    assert accepted["status"] == "PASS"


def test_strict_gate_executes_engineering_instead_of_trusting_supplied_pass(tmp_path, monkeypatch):
    supplied = tmp_path / "self-issued-engineering.json"
    supplied.write_text('{"verdict":"PASS"}')
    calls = []
    monkeypatch.setattr(bank_readiness, "git_metadata",
                        lambda: {"commit": COMMIT, "branch": "test", "dirty": False})
    monkeypatch.setattr(bank_readiness, "run_engineering",
                        lambda out: (calls.append(out) or 1, supplied))
    output = tmp_path / "strict.json"
    assert bank_readiness.main(["--strict", "--out", str(output),
                                "--engineering", str(supplied)]) == 1
    assert calls == [output]
    rows = {row["category"]: row for row in json.loads(output.read_text())["categories"]}
    assert rows["engineering"]["status"] == "FAIL"


def test_strict_policy_refuses_unapproved_repository_baseline():
    policy = bank_readiness.operational_policy_check(strict=True)
    assert policy["status"] == "FAIL"
    assert any("status=approved" in finding for finding in policy["findings"])


def test_signed_failure_stays_failure(tmp_path):
    evidence, directory, key = signed_fixture(tmp_path)
    evidence.write_text('{"verdict":"FAIL"}')
    row = artifact(evidence, "hsm")
    assert require_attestation(row, evidence, category="hsm",
                               attestation_dir=directory,
                               trusted_public_key=key, site_id=SITE,
                               repository_commit=COMMIT)["status"] == "FAIL"
