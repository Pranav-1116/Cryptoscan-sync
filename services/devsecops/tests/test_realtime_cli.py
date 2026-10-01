"""Focused contracts for the multi-mode DevSecOps realtime adapter."""

import json

from devsecops import realtime_cli


def test_unconfigured_modes_are_explicitly_skipped():
    result = realtime_cli.run({})

    assert result["scan_status"] == "SKIP"
    assert result["modes"] == {
        "binary": "SKIP", "source": "SKIP", "container": "SKIP", "sbom": "SKIP"
    }
    assert result["observations"] == {}


def test_source_mode_runs_real_sbom_scan_and_emits_evidence(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.0\n", encoding="utf-8")

    result = realtime_cli.run({"source": str(tmp_path)})

    assert result["scan_status"] == "PASS"
    assert result["modes"]["source"] == "PASS"
    assert result["observations"]["source"]["evidence_reference"].startswith("sha256:")
    assert any(row["name"] == "cryptography" for row in result["observations"]["source"]["libraries"])


def test_missing_binary_is_a_failed_mode_not_an_empty_success(tmp_path):
    result = realtime_cli.run({"binary": str(tmp_path / "missing.bin")})

    assert result["scan_status"] == "FAIL"
    assert result["modes"]["binary"] == "FAIL"
    assert result["errors"][0]["mode"] == "binary"


def test_container_mode_preserves_completed_degraded_posture(monkeypatch):
    monkeypatch.setattr(
        "devsecops.sbom_scan.scan_container",
        lambda target, as_image=False: {
            "target": target,
            "risk_report": {"posture": "HIGH"},
            "findings": [{"severity": "HIGH", "message": "weak crypto package"}],
        },
    )

    result = realtime_cli.run({"container": {"target": "operator-image:1", "as_image": True}})

    assert result["scan_status"] == "DEGRADED"
    assert result["modes"]["container"] == "DEGRADED"
    assert result["observations"]["container"]["evidence_reference"].startswith("sha256:")
    assert result["findings"][0]["evidence_reference"].startswith("sha256:")


def test_sbom_mode_is_bounded_to_metadata_and_has_evidence(tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "openssl"}]}), encoding="utf-8")

    result = realtime_cli.run({"sbom": str(sbom)})
    observation = result["observations"]["sbom"]

    assert result["scan_status"] == "PASS"
    assert observation["component_count"] == 1
    assert observation["evidence_reference"].startswith("sha256:")
    assert "document" not in observation
