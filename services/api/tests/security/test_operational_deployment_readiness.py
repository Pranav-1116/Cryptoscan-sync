"""Repository operational deployment readiness remains explicit and bounded."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "operational_deployment_readiness.py"
ROLLBACK = ROOT / "scripts" / "rollback_plan.py"
WEIGHTED = ROOT / "scripts" / "weighted_production_qualification.py"


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_repository_controls_reach_the_80_to_90_band_without_external_claims():
    readiness = _module(SCRIPT, "operational_deployment_readiness")
    report = readiness.evaluate(ROOT)
    assert report["score"]["value"] == 85
    assert report["score"]["band"] == "80-90%"
    assert report["score"]["maximum_repository_controls"] == 85
    assert report["production_qualification"] == "BLOCKED_UNTIL_EXTERNAL_EVIDENCE"
    assert report["external_qualification_reserve"]["status"] == "UNVERIFIED"
    assert report["safety"]["destructive_commands_run"] is False


def test_weighted_view_keeps_external_evidence_unverified():
    weighted = _module(WEIGHTED, "weighted_production_qualification")
    report = weighted.build_report(ROOT)
    view = report["weighted_view"]
    assert view["engineering"]["points"] == 40
    assert view["operations"]["points"] == 45
    assert view["external_evidence"]["status"] == "UNVERIFIED"
    assert view["overall_points"] is None
    assert report["production_qualification"] == "BLOCKED_UNTIL_EXTERNAL_EVIDENCE"


def test_frontend_boundary_allows_public_docs_but_not_direct_api_navigation(tmp_path):
    readiness = _module(SCRIPT, "operational_deployment_readiness_frontend")
    source = tmp_path / "frontend" / "src"
    api = source / "lib" / "api.ts"
    api.parent.mkdir(parents=True)
    api.write_text("tenantFetch credentials", encoding="utf-8")
    page = source / "pages" / "Readiness.tsx"
    page.parent.mkdir()
    page.write_text('<a href="/api/docs">API schemas</a>', encoding="utf-8")
    assert readiness._frontend_boundary(tmp_path)[0] is True

    page.write_text('<a href="/api/v1/scans">Bypass tenantFetch</a>', encoding="utf-8")
    passed, detail = readiness._frontend_boundary(tmp_path)
    assert passed is False
    assert "Readiness.tsx" in detail


def test_rollback_plan_is_metadata_only_and_requires_immutable_release_lock(tmp_path):
    rollback = _module(ROLLBACK, "rollback_plan")
    target = tmp_path / "v1.2.3"
    target.mkdir()
    (target / "release-image-lock.json").write_text(
        json.dumps({"digests": {service: "a" * 64 for service in ("api", "worker", "neo4j")}}),
        encoding="utf-8",
    )
    plan = rollback.build_plan(target)
    assert plan["execution"]["status"] == "PLAN_ONLY"
    assert plan["execution"]["commands_executed"] is False
    assert plan["execution"]["production_mutation"] is False
    assert plan["target_image_digests"]["api"] == "a" * 64


def test_rollback_plan_rejects_mutable_or_missing_image_locks(tmp_path):
    rollback = _module(ROLLBACK, "rollback_plan_invalid")
    target = tmp_path / "mutable"
    target.mkdir()
    (target / "release-image-lock.json").write_text(
        json.dumps({"digests": {"api": "latest", "worker": "b" * 64, "neo4j": "c" * 64}}),
        encoding="utf-8",
    )
    try:
        rollback.build_plan(target)
    except ValueError as exc:
        assert "invalid digests" in str(exc)
    else:
        raise AssertionError("mutable release lock was accepted")
