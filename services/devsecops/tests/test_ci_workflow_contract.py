"""Prevent omitted suites, fake migration proof and unsafe image publishing in CI."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[3]


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


suites = _script("ci_suites")
junit = _script("check_junit")


def _workflow(name):
    # BaseLoader preserves 'on' (YAML 1.1 would turn it into boolean True) and
    # keeps scalar values as strings, matching the assertions below.
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def _fixture(tmp_path):
    for area in ("services", "shared"):
        (tmp_path / area).mkdir()
    return tmp_path


def test_discovery_matches_every_existing_service_and_shared_suite():
    expected = sorted(p.relative_to(ROOT).as_posix()
                      for area in ("services", "shared") for p in (ROOT / area).rglob("tests")
                      if p.is_dir() and not p.is_symlink())
    assert suites.discover_suites(ROOT) == expected
    assert any(p.startswith("shared/") for p in expected)
    assert "services/devsecops/tests" in expected
    assert set(suites.discover_suites(ROOT, scanners_only=True)) <= set(expected)


def test_new_services_and_shared_packages_are_automatically_included(tmp_path):
    root = _fixture(tmp_path)
    for path in ("services/new_collector/tests", "shared/new_models/tests"):
        (root / path).mkdir(parents=True)
    assert suites.discover_suites(root) == ["services/new_collector/tests", "shared/new_models/tests"]


def test_nested_tests_and_dependencies_are_not_scheduled_twice(tmp_path):
    root = _fixture(tmp_path)
    for path in ("services/real/tests/fixtures/tests", "services/real/node_modules/dependency/tests",
                 "services/real/.venv/package/tests", "shared/__pycache__/tests"):
        (root / path).mkdir(parents=True)
    assert suites.discover_suites(root) == ["services/real/tests"]


def test_symlinks_cannot_add_out_of_tree_suites(tmp_path):
    root = _fixture(tmp_path)
    (root / "services/real/tests").mkdir(parents=True)
    outside = root / "outside/tests"
    outside.mkdir(parents=True)
    (root / "shared/linked").symlink_to(outside.parent, target_is_directory=True)
    assert suites.discover_suites(root) == ["services/real/tests"]


@pytest.mark.parametrize("name", ["bad;name", "bad name", "bad\nname"])
def test_discovery_rejects_unsafe_matrix_values(tmp_path, name):
    root = _fixture(tmp_path)
    (root / "services" / name / "tests").mkdir(parents=True)
    with pytest.raises(ValueError, match="unsafe"):
        suites.discover_suites(root)


def test_missing_roots_or_empty_matrix_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="missing suite root"):
        suites.discover_suites(tmp_path)
    _fixture(tmp_path)
    with pytest.raises(ValueError, match="no backend test suites"):
        suites.discover_suites(tmp_path)


def test_matrix_limit_cannot_silently_drop_suites(tmp_path):
    root = _fixture(tmp_path)
    for index in range(257):
        (root / f"services/service_{index}/tests").mkdir(parents=True)
    with pytest.raises(ValueError, match="256"):
        suites.discover_suites(root)


@pytest.mark.parametrize("xml", [
    "<testsuites/>",
    '<testsuite><testcase name="unavailable"><skipped/></testcase></testsuite>',
    '<testsuite><testcase name="broken"><failure/></testcase></testsuite>',
    '<testsuite><testcase name="error"><error/></testcase></testsuite>',
])
def test_required_qualification_rejects_missing_or_skipped_proof(tmp_path, xml):
    report = tmp_path / "results.xml"
    report.write_text(xml)
    with pytest.raises(ValueError):
        junit.require_executed(report)


def test_required_qualification_counts_real_testcases_not_summary_claims(tmp_path):
    report = tmp_path / "results.xml"
    report.write_text('<testsuites tests="999"><testsuite><testcase name="ran"/></testsuite></testsuites>')
    assert junit.require_executed(report) == 1


def test_main_ci_uses_discovery_and_a_fail_closed_aggregate():
    jobs = _workflow("ci.yml")["jobs"]
    discover = jobs["discover"]
    assert "scripts/ci_suites.py" in json.dumps(discover)
    backend = jobs["backend"]
    assert "fromJSON(needs.discover.outputs.matrix)" in backend["strategy"]["matrix"]
    assert backend["strategy"]["fail-fast"] == "false"
    assert "-p no:xdist" in json.dumps(backend)
    assert "-c requirements.lock.txt" in json.dumps(backend)
    commands = [step.get("run", "") for step in jobs["frontend"]["steps"]]
    assert "npm test" in commands
    assert commands.index("npm test") < commands.index("npx vite build")
    gate = jobs["gate"]
    assert gate["name"] == "ci"
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == set(jobs) - {"gate"}
    assert 'job["result"] != "success"' in json.dumps(gate).replace('\\"', '"')
    assert "continue-on-error" not in json.dumps(jobs)


def test_workflows_are_active_read_only_and_do_not_run_privileged_pr_code():
    for name in ("ci.yml", "scanner-tests.yml", "db-migration.yml", "docker-build.yml"):
        workflow = _workflow(name)
        assert workflow["jobs"]
        assert "pull_request" in workflow["on"]
        assert "workflow_dispatch" in workflow["on"]
        assert "pull_request_target" not in workflow["on"]
        assert workflow["permissions"] == {"contents": "read"}
        assert all("timeout-minutes" in job for job in workflow["jobs"].values())


def test_migration_lane_runs_alembic_tests_not_only_create_all():
    jobs = _workflow("db-migration.yml")["jobs"]
    assert "test_migration_chain.py" in json.dumps(jobs["sqlite-chain"])
    postgres = jobs["postgres-chain"]
    assert "postgres" in postgres["services"]
    commands = "\n".join(step.get("run", "") for step in postgres["steps"])
    assert "-m live" in commands
    assert "test_migration_chain_postgres.py" in commands
    assert "scripts/check_junit.py migrations-postgres.xml" in commands
    assert "continue-on-error" not in json.dumps(jobs)


def test_image_lane_covers_all_dockerfiles_with_correct_contexts_and_no_push():
    build = _workflow("docker-build.yml")["jobs"]["build"]
    images = build["strategy"]["matrix"]["include"]
    expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / ".docker").glob("*/Dockerfile")}
    assert {row["dockerfile"] for row in images} == expected
    for row in images:
        assert (ROOT / row["context"]).is_dir()
    nginx = next(row for row in images if row["name"] == "nginx")
    assert nginx["context"] == ".docker/nginx"
    assert (ROOT / nginx["context"] / "nginx.conf").is_file()
    dashboard = next(row for row in images if row["name"] == "dashboard")
    assert dashboard["context"] == "."
    action = next(step for step in build["steps"] if step.get("uses", "").startswith("docker/build-push-action@"))
    assert action["with"]["push"] == "false"
    assert "secrets." not in json.dumps(build)


def test_every_direct_dependency_has_a_compatible_unique_lock_pin():
    locked = {}
    for line in (ROOT / "requirements.lock.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        requirement = Requirement(line)
        key = canonicalize_name(requirement.name)
        assert key not in locked, f"duplicate lock entry: {key}"
        pins = list(requirement.specifier)
        assert len(pins) == 1 and pins[0].operator == "=="
        locked[key] = pins[0].version
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        requirement = Requirement(line)
        key = canonicalize_name(requirement.name)
        assert key in locked, f"dependency omitted from lock: {key}"
        assert locked[key] in requirement.specifier


@pytest.mark.parametrize("expect_reject", [False, True])
def test_production_guard_ci_fixtures_match_current_runtime_contract(expect_reject):
    import os
    import subprocess
    import sys

    steps = _workflow("ci.yml")["jobs"]["prod-config-guard"]["steps"]
    step = next(s for s in steps if "scripts/check_prod_guard.py" in s.get("run", "")
                and ("--expect-reject" in s["run"]) == expect_reject)
    pythonpath = os.pathsep.join(str(p) for area in ("services", "shared")
                                for p in (ROOT / area).iterdir() if p.is_dir())
    environment = dict(os.environ, **step["env"], PYTHONPATH=pythonpath)
    args = [sys.executable, "scripts/check_prod_guard.py"]
    if expect_reject:
        args.append("--expect-reject")
    result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_frontend_ci_uses_frozen_installs_all_dependency_audit_and_coverage_smoke():
    steps = _workflow("ci.yml")["jobs"]["frontend"]["steps"]
    commands = [step.get("run", "").strip() for step in steps]
    assert "npm ci --no-audit --no-fund" in commands
    assert "npm audit --include=dev --audit-level=low" in commands
    assert "npm run test:toolchain" in commands
    assert "npm run test:coverage -- src/lib/api.test.ts" in commands
    for command in ("npm audit --include=dev --audit-level=low", "npm run test:toolchain",
                    "npm run test:coverage -- src/lib/api.test.ts"):
        step = next(step for step in steps if step.get("run", "").strip() == command)
        assert step.get("working-directory") == "frontend"
        assert step.get("continue-on-error", "false") == "false"
