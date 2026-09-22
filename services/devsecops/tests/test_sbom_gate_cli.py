"""The supply-chain gate CLI: exit codes a pipeline can trust, and the same
policy engine the API uses (no network, deterministic)."""

from __future__ import annotations

import json
import os
import subprocess
import sys

CLEAN = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"timestamp": "2026-09-01T00:00:00Z", "authors": [{"name": "ci"}]},
    "components": [{"type": "library", "name": "lodash", "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21", "supplier": {"name": "ACME"},
                    "bom-ref": "pkg:npm/lodash@4.17.21"}],
    "dependencies": [{"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []}],
}

VULNERABLE = json.loads(json.dumps(CLEAN))
VULNERABLE["vulnerabilities"] = [{"id": "CVE-2024-0001", "ratings": [{"severity": "critical"}],
                                  "affects": [{"ref": "pkg:npm/lodash@4.17.21"}]}]

LICENSED = json.loads(json.dumps(CLEAN))
LICENSED["components"][0]["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]


def _run(*args, stdin: str | None = None):
    env = dict(os.environ)
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(root, "services", "devsecops"), env.get("PYTHONPATH", "")])
    return subprocess.run([sys.executable, "-m", "devsecops.sbom_gate", *args],
                          capture_output=True, text=True, input=stdin, env=env, timeout=60)


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_gate_passes_a_clean_document(tmp_path):
    proc = _run(_write(tmp_path, "clean.json", CLEAN), "--unpinned", "0")
    assert proc.returncode == 0, proc.stderr
    assert "gate: PASS" in proc.stdout
    assert "minimum elements: 7/7" in proc.stdout


def test_gate_fails_on_critical_and_reports_the_rule(tmp_path):
    proc = _run(_write(tmp_path, "bad.json", VULNERABLE))
    assert proc.returncode == 1
    assert "gate: FAIL" in proc.stdout
    assert "GATE-CVE-CRITICAL" in proc.stdout


def test_gate_honours_the_allowance_flag(tmp_path):
    proc = _run(_write(tmp_path, "bad.json", VULNERABLE), "--allow-critical", "1")
    assert proc.returncode == 0, proc.stdout
    assert "critical 1" in proc.stdout  # counted, but allowed


def test_gate_reads_stdin_and_a_policy_file(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"policy": {"deny_licenses": ["GPL-3.0-only"]}}), encoding="utf-8")
    blocked = _run("-", "--policy", str(policy), stdin=json.dumps(LICENSED))
    assert blocked.returncode == 1
    assert "GATE-LICENSE-DENIED" in blocked.stdout
    allowed = _run("-", stdin=json.dumps(LICENSED))
    assert allowed.returncode == 0, allowed.stdout


def test_gate_json_output_is_machine_readable(tmp_path):
    proc = _run(_write(tmp_path, "bad.json", VULNERABLE), "--json")
    report = json.loads(proc.stdout)
    assert report["verdict"] == "FAIL"
    assert report["blockers"][0]["code"] == "GATE-CVE-CRITICAL"
    assert report["policy"]["allow_critical"] == 0


def test_gate_require_minimum_elements_is_a_blocker(tmp_path):
    sparse = {"bomFormat": "CycloneDX", "specVersion": "1.5",
              "components": [{"type": "library", "name": "a", "version": "1"}]}
    warned = _run(_write(tmp_path, "sparse.json", sparse))
    assert warned.returncode == 0                       # gap is advisory by default
    assert "warn" in warned.stdout
    strict = _run(_write(tmp_path, "sparse.json", sparse), "--require-minimum-elements")
    assert strict.returncode == 1
    assert "GATE-MINIMUM-ELEMENTS" in strict.stdout


def test_gate_signature_rules_need_an_explicit_assertion(tmp_path):
    signed = _run(_write(tmp_path, "clean.json", CLEAN), "--require-signed", "--signed")
    assert signed.returncode == 0, signed.stdout
    unsigned = _run(_write(tmp_path, "clean.json", CLEAN), "--require-signed", "--unsigned")
    assert unsigned.returncode == 1
    assert "GATE-UNSIGNED" in unsigned.stdout
    # without an assertion the document alone cannot prove signing — no blocker
    unknown = _run(_write(tmp_path, "clean.json", CLEAN), "--require-signed")
    assert unknown.returncode == 0, unknown.stdout


def test_gate_exit_codes_for_bad_input(tmp_path):
    missing = _run(str(tmp_path / "nope.json"))
    assert missing.returncode == 2                       # IO error
    broken = tmp_path / "broken.json"
    broken.write_text("{oops", encoding="utf-8")
    assert _run(str(broken)).returncode == 3             # not JSON
    assert _run(_write(tmp_path, "notasbom.json", {"hello": 1})).returncode == 3
    assert _run(_write(tmp_path, "clean.json", CLEAN), "--no-such-flag").returncode == 2
