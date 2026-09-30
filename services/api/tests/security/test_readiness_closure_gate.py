"""The bank-readiness closure gate must reject incomplete or weak evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "readiness_closure_gate.py"
POLICY_PATH = ROOT / "config" / "readiness-closure-policy.json"


def _gate():
    spec = importlib.util.spec_from_file_location("readiness_closure_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _complete_manifest(gate, tmp_path: Path, commit: str = "a" * 40):
    policy = gate.load_json(POLICY_PATH)
    artifacts = []
    captured = "2026-09-29T00:00:00Z"
    for gap in policy["gaps"]:
        for kind in gap["required_kinds"]:
            artifact = tmp_path / f"{gap['id']}-{kind}.json"
            artifact.write_text(json.dumps({"status": "PASS", "evidence_id": f"{gap['id']}-{kind}"}), encoding="utf-8")
            artifacts.append({
                "evidence_id": f"{gap['id']}-{kind}",
                "gap_id": gap["id"],
                "kind": kind,
                "status": "PASS",
                "evidence_tier": gap["minimum_tier"],
                "artifact_source": "external_controlled",
                "artifact_path": str(artifact),
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "captured_at": captured,
                "release_commit": commit,
                "environment": "bank-lab-01",
                "scope": f"approved scope for {gap['id']}",
                "limitations": ["external evidence remains subject to issuer truth and approval"],
                "owner": gap["owner"],
                "issuer": f"issuer-{gap['id']}",
                "reviewed_by": "independent-reviewer",
                "reviewed_at": captured,
                "operator": "evidence-operator",
                "independent_review": True,
            })
    return policy, {"schema": gate.SCHEMA, "release_commit": commit, "environment": "bank-lab-01", "artifacts": artifacts}


def test_policy_covers_all_documented_p0_and_p1_gaps():
    gate = _gate()
    policy = gate.load_json(POLICY_PATH)
    assert gate.validate_policy(policy) == []
    assert {gap["id"] for gap in policy["gaps"]} == {f"P0-{i}" for i in range(1, 10)} | {f"P1-{i}" for i in range(1, 6)}


def test_empty_manifest_keeps_every_gap_open():
    gate = _gate()
    policy = gate.load_json(POLICY_PATH)
    manifest = {"schema": gate.SCHEMA, "release_commit": "a" * 40, "environment": "bank-lab-01", "artifacts": []}
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    required_kinds = sum(len(gap["required_kinds"]) for gap in policy["gaps"])
    assert sum(f["code"] == "gap_open" for f in findings) == required_kinds
    assert {finding["gap_id"] for finding in findings if finding["code"] == "gap_open"} == {gap["id"] for gap in policy["gaps"]}


def test_complete_release_bound_manifest_passes(tmp_path):
    gate = _gate()
    policy, manifest = _complete_manifest(gate, tmp_path)
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    assert findings == []


def test_release_binding_and_hash_tampering_are_blocking(tmp_path):
    gate = _gate()
    policy, manifest = _complete_manifest(gate, tmp_path)
    first = manifest["artifacts"][0]
    first["release_commit"] = "b" * 40
    Path(first["artifact_path"]).write_text(json.dumps({"status": "PASS", "tampered": True}), encoding="utf-8")
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    codes = {finding["code"] for finding in findings}
    assert {"release_binding", "artifact_hash"} <= codes


def test_nested_skip_cannot_be_wrapped_as_a_passing_artifact(tmp_path):
    gate = _gate()
    policy, manifest = _complete_manifest(gate, tmp_path)
    first = manifest["artifacts"][0]
    path = Path(first["artifact_path"])
    path.write_text(json.dumps({"status": "PASS", "checks": [{"status": "SKIP"}]}), encoding="utf-8")
    first["artifact_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    assert "artifact_nested_failure" in {finding["code"] for finding in findings}


def test_independent_review_is_required(tmp_path):
    gate = _gate()
    policy, manifest = _complete_manifest(gate, tmp_path)
    del manifest["artifacts"][0]["independent_review"]
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    assert "artifact_metadata" in {finding["code"] for finding in findings}


def test_repository_file_cannot_close_a_customer_attestation(tmp_path):
    gate = _gate()
    policy, manifest = _complete_manifest(gate, tmp_path)
    item = next(item for item in manifest["artifacts"] if item["gap_id"] == "P0-2")
    repo_file = ROOT / "README.md"
    item["artifact_path"] = str(repo_file)
    item["artifact_sha256"] = hashlib.sha256(repo_file.read_bytes()).hexdigest()
    findings = gate.validate_manifest(policy, manifest, "a" * 40, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
    assert "self_issued_artifact" in {finding["code"] for finding in findings}
