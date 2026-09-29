"""The release gate must inspect rendered image locks, not source templates."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "release_check.py"
DIGESTS = {"api": "a" * 64, "worker": "b" * 64, "neo4j": "c" * 64}


def _release_check():
    pytest.importorskip("pydantic")
    spec = importlib.util.spec_from_file_location("release_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rendered(root: Path, mutable: bool = False) -> Path:
    (root / "app").mkdir(parents=True)
    (root / "neo4j").mkdir()
    suffix = ":v1.0.0" if mutable else "@sha256:" + DIGESTS["api"]
    worker = ":v1.0.0" if mutable else "@sha256:" + DIGESTS["worker"]
    neo4j = ":5.26-community" if mutable else "@sha256:" + DIGESTS["neo4j"]
    (root / "app" / "deployment.yaml").write_text(
        f"containers:\n  image: registry/api{suffix}\n  image: registry/worker{worker}\n",
        encoding="utf-8",
    )
    (root / "neo4j" / "statefulset.yaml").write_text(
        f"containers:\n  image: registry/neo4j{neo4j}\n", encoding="utf-8"
    )
    (root / "release-image-lock.json").write_text(
        json.dumps({"schema": "cryptoscan.immutable-image-release/1", "digests": DIGESTS}),
        encoding="utf-8",
    )
    return root


def test_release_gate_accepts_matching_rendered_lock(tmp_path):
    release_check = _release_check()

    findings = release_check._image_digest_findings(_rendered(tmp_path / "release"))

    assert findings == []


def test_release_gate_rejects_mutable_rendered_image(tmp_path):
    release_check = _release_check()

    findings = release_check._image_digest_findings(
        _rendered(tmp_path / "release", mutable=True)
    )

    assert findings
    assert any("mutable" in finding.message for finding in findings)


def test_release_gate_requires_a_rendered_directory():
    release_check = _release_check()

    findings = release_check._image_digest_findings()

    assert len(findings) == 1
    assert "no rendered release manifests" in findings[0].message


def test_approval_release_requires_readiness_closure_manifest():
    release_check = _release_check()

    findings = release_check._readiness_closure_findings(None, required=True)

    assert len(findings) == 1
    assert findings[0].check == "readiness-closure"
    assert "manifest is required" in findings[0].message


def test_readiness_closure_is_opt_in_for_pre_release_checks():
    release_check = _release_check()

    assert release_check._readiness_closure_findings(None, required=False) == []
