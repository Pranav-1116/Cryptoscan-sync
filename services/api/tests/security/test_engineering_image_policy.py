"""Rendered release manifests, not mutable source templates, are deployable."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / "scripts" / "engineering_gate.py"


def _gate():
    spec = importlib.util.spec_from_file_location("engineering_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rendered_digest_manifests_pass(tmp_path):
    gate = _gate()
    (tmp_path / "deployment.yaml").write_text(
        "containers:\n  image: registry.example/api@sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    checks: list[dict] = []

    gate.image_policy(checks, tmp_path)

    assert checks[0]["status"] == "PASS", checks[0]
    assert checks[0]["image_references"]


def test_rendered_tag_is_a_release_failure(tmp_path):
    gate = _gate()
    (tmp_path / "deployment.yaml").write_text(
        "containers:\n  image: registry.example/api:v1.0.0\n",
        encoding="utf-8",
    )
    checks: list[dict] = []

    gate.image_policy(checks, tmp_path)

    assert checks[0]["status"] == "FAIL"
    assert checks[0]["references"]


def test_source_templates_are_explicitly_not_release_evidence():
    gate = _gate()
    checks: list[dict] = []

    gate.image_policy(checks)

    assert checks[0]["status"] == "SKIP"
    assert "--release-manifests" in checks[0]["detail"]
