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
    expected = sorted(
        p.relative_to(ROOT).as_posix()
        for area in ("services", "shared")
        for p in (ROOT / area).rglob("tests")
        if p.is_dir() and not p.is_symlink()
    )
    all_suites = set(suites.discover_suites(ROOT))
    scanner_suites = set(suites.discover_suites(ROOT, scanners_only=True))
    non_scanner_suites = set(suites.discover_suites(ROOT, non_scanners_only=True))
    assert sorted(all_suites) == expected
    assert len(all_suites) == 54
    assert scanner_suites and non_scanner_suites
    assert scanner_suites.isdisjoint(non_scanner_suites)
    assert scanner_suites | non_scanner_suites == all_suites
    assert any(p.startswith("shared/") for p in non_scanner_suites)
    assert "services/devsecops/tests" in non_scanner_suites
    assert {p.split("/")[1] for p in scanner_suites} == suites.SCANNERS


def test_new_services_and_shared_packages_are_automatically_included(tmp_path):
    root = _fixture(tmp_path)
    for path in ("services/new_collector/tests", "shared/new_models/tests"):
        (root / path).mkdir(parents=True)
    assert suites.discover_suites(root) == ["services/new_collector/tests", "shared/new_models/tests"]


def test_nested_tests_and_dependencies_are_not_scheduled_twice(tmp_path):
    root = _fixture(tmp_path)
    for path in (
        "services/real/tests/fixtures/tests",
        "services/real/node_modules/dependency/tests",
        "services/real/.venv/package/tests",
        "shared/__pycache__/tests",
    ):
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


@pytest.mark.parametrize(
    "xml",
    [
        "<testsuites/>",
        '<testsuite><testcase name="unavailable"><skipped/></testcase></testsuite>',
        '<testsuite><testcase name="broken"><failure/></testcase></testsuite>',
        '<testsuite><testcase name="error"><error/></testcase></testsuite>',
    ],
)
def test_required_qualification_rejects_missing_or_skipped_proof(tmp_path, xml):
    report = tmp_path / "results.xml"
    report.write_text(xml)
    with pytest.raises(ValueError):
        junit.require_executed(report)


def test_required_qualification_counts_real_testcases_not_summary_claims(tmp_path):
    report = tmp_path / "results.xml"
    report.write_text('<testsuites tests="999"><testsuite><testcase name="ran"/></testsuite></testsuites>')
    assert junit.require_executed(report) == 1


def test_optional_skips_are_reported_but_cannot_replace_executed_proof(tmp_path):
    report = tmp_path / "results.xml"
    report.write_text('<testsuite><testcase name="optional"><skipped/></testcase><testcase name="ran"/></testsuite>')
    assert junit.require_executed(report, allow_skips=True) == 1
    with pytest.raises(ValueError, match="skipped"):
        junit.require_executed(report)
    report.write_text('<testsuite><testcase name="only-skip"><skipped/></testcase></testsuite>')
    with pytest.raises(ValueError, match="no executed"):
        junit.require_executed(report, allow_skips=True)


def test_main_ci_uses_discovery_and_a_fail_closed_aggregate():
    jobs = _workflow("ci.yml")["jobs"]
    discover = jobs["discover"]
    assert "scripts/ci_suites.py --non-scanners" in json.dumps(discover)
    assert "matrix" in discover["outputs"]
    backend = jobs["backend"]
    assert backend["needs"] == "discover"
    assert "fromJSON(needs.discover.outputs.matrix)" in backend["strategy"]["matrix"]
    assert backend["strategy"]["fail-fast"] == "false"
    assert "-p no:xdist" in json.dumps(backend)
    assert "-c requirements.lock.txt" in json.dumps(backend)
    assert "scripts/check_junit.py --allow-skips" in json.dumps(backend)
    assert any(
        step.get("uses", "").startswith("actions/upload-artifact@") and step.get("if") == "always()"
        for step in backend["steps"]
    )
    for lane, workflow in (
        ("scanner-offline", "scanner-tests.yml"),
        ("db-migration", "db-migration.yml"),
        ("images-build-only", "docker-build.yml"),
    ):
        assert jobs[lane]["uses"] == f"./.github/workflows/{workflow}"
        assert jobs[lane]["permissions"] == {"contents": "read"}
        assert "secrets" not in jobs[lane]
    commands = [step.get("run", "").strip() for step in jobs["frontend"]["steps"]]
    assert "npm test" in commands
    assert commands.index("npm test") < commands.index("npm run build")
    gate = jobs["ci-required"]
    assert gate["name"] == "ci-required"
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == set(jobs) - {"ci-required"}
    assert 'job["result"] != "success"' in json.dumps(gate).replace('\\"', '"')
    assert "continue-on-error" not in json.dumps(jobs)


def test_workflows_are_active_read_only_and_do_not_run_privileged_pr_code():
    main = _workflow("ci.yml")
    assert "pull_request" in main["on"]
    assert main["on"]["push"] == {"branches": ["main", "arena/bb4b80dd-cryproscan"]}
    assert "workflow_dispatch" in main["on"]
    for name in ("ci.yml", "scanner-tests.yml", "db-migration.yml", "docker-build.yml"):
        workflow = _workflow(name)
        assert workflow["jobs"]
        assert "workflow_dispatch" in workflow["on"]
        assert "pull_request_target" not in workflow["on"]
        assert workflow["permissions"] == {"contents": "read"}
        assert all("timeout-minutes" in job for job in workflow["jobs"].values() if "runs-on" in job)
        if name != "ci.yml":
            assert "workflow_call" in workflow["on"]
            assert "pull_request" not in workflow["on"]
            assert "push" not in workflow["on"]


def test_reusable_scanner_lane_discovers_and_proves_offline_suites():
    jobs = _workflow("scanner-tests.yml")["jobs"]
    assert "scripts/ci_suites.py --scanners-only" in json.dumps(jobs["discover"])
    scanner = jobs["scanner"]
    assert scanner["needs"] == "discover"
    assert "fromJSON(needs.discover.outputs.matrix)" in scanner["strategy"]["matrix"]
    commands = "\n".join(step.get("run", "") for step in scanner["steps"])
    assert "-m 'not live'" in commands
    assert "--disable-socket" in commands
    assert "--junitxml=junit/results.xml" in commands
    assert "scripts/check_junit.py --allow-skips junit/results.xml" in commands
    assert any(
        step.get("uses", "").startswith("actions/upload-artifact@") and step.get("if") == "always()"
        for step in scanner["steps"]
    )


def test_migration_lane_runs_alembic_tests_not_only_create_all():
    workflow = _workflow("db-migration.yml")
    jobs = workflow["jobs"]
    postgres = jobs["migration-parity"]
    assert postgres["strategy"]["matrix"]["postgres"] == ["15", "16"]
    assert postgres["services"]["postgres"]["image"] == "postgres:${{ matrix.postgres }}-alpine"
    assert "127.0.0.1:5432/cs_ci_parity" in workflow["env"]["DATABASE_URL"]
    assert "127.0.0.1:5432/cs_ci_migration" in workflow["env"]["CRYPTOSCAN_TEST_PG_URL"]
    commands = "\n".join(step.get("run", "") for step in postgres["steps"])
    assert "scripts/postgres_parity.sh" in commands
    assert "SHOW server_version_num" in commands
    assert "-m live" in commands
    assert "test_migration_chain_postgres.py" in commands
    assert "scripts/check_junit.py" in commands
    assert "scripts/check_junit.py --allow-skips" not in commands
    assert "continue-on-error" not in json.dumps(jobs)


def test_image_lane_covers_standard_dockerfiles_with_correct_contexts_and_no_push():
    build = _workflow("docker-build.yml")["jobs"]["build"]
    images = build["strategy"]["matrix"]["include"]
    standard = {"api", "dashboard", "frontend", "nginx", "scanner", "worker"}
    assert len(images) == len(standard)
    assert {row["name"] for row in images} == standard
    assert {row["dockerfile"] for row in images} == {f".docker/{name}/Dockerfile" for name in standard}
    for row in images:
        assert (ROOT / row["context"]).is_dir()
        assert (ROOT / row["dockerfile"]).is_file()
        assert row["context"] == (".docker/nginx" if row["name"] == "nginx" else ".")
    assert (ROOT / ".docker/nginx/nginx.conf").is_file()
    # This separate dispatcher Dockerfile cannot be built without reviewed digests.
    runtime = ROOT / ".docker/worker-runtime/Dockerfile"
    assert runtime.is_file()
    runtime_lines = runtime.read_text().splitlines()
    assert "ARG DOCKER_CLI_IMAGE" in runtime_lines
    assert "ARG WORKER_IMAGE" in runtime_lines
    assert "FROM ${DOCKER_CLI_IMAGE} AS cli" in runtime_lines
    assert "FROM ${WORKER_IMAGE}" in runtime_lines
    action = next(step for step in build["steps"] if step.get("uses", "").startswith("docker/build-push-action@"))
    assert action["with"]["context"] == "${{ matrix.context }}"
    assert action["with"]["file"] == "${{ matrix.dockerfile }}"
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

    job = _workflow("ci.yml")["jobs"]["prod-config-guard"]
    step = next(
        s
        for s in job["steps"]
        if "scripts/check_prod_guard.py" in s.get("run", "") and ("--expect-reject" in s["run"]) == expect_reject
    )
    pythonpath = os.pathsep.join(
        str(p) for area in ("services", "shared") for p in (ROOT / area).iterdir() if p.is_dir()
    )
    environment = {**os.environ, **job["env"], **step.get("env", {}), "PYTHONPATH": pythonpath}
    args = [sys.executable, "scripts/check_prod_guard.py"]
    if expect_reject:
        assert step["env"]["SECRET_KEY"] == "cryptoscan-dev-secret"
        args.append("--expect-reject")
    result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    if expect_reject:
        assert "invalid production config rejected as required" in output
        assert "SECRET_KEY" in output
    else:
        assert "production configuration is valid" in output


def test_frontend_ci_uses_frozen_installs_and_coverage_without_unapproved_audit():
    steps = _workflow("ci.yml")["jobs"]["frontend"]["steps"]
    node = next(step for step in steps if step.get("uses", "").startswith("actions/setup-node@"))
    assert node["with"]["node-version"] == "22.22.3"  # locked css-color needs >=22.22.2
    assert node["with"]["cache-dependency-path"] == "frontend/package-lock.json"
    commands = [step.get("run", "").strip() for step in steps]
    assert "npm ci --no-audit --no-fund" in commands
    assert all("npm audit" not in command for command in commands)
    assert "npm run typecheck" in commands
    assert "npm test" in commands
    assert "npm run build" in commands
    assert "npm run test:toolchain" in commands
    assert "npm run test:coverage -- src/lib/api.test.ts" in commands
    for command in (
        "npm ci --no-audit --no-fund",
        "npm run typecheck",
        "npm test",
        "npm run build",
        "npm run test:toolchain",
        "npm run test:coverage -- src/lib/api.test.ts",
    ):
        step = next(step for step in steps if step.get("run", "").strip() == command)
        assert step.get("working-directory") == "frontend"
        assert step.get("continue-on-error", "false") == "false"


def test_python_images_install_with_the_committed_constraints():
    for name in ("api", "worker", "scanner"):
        dockerfile = (ROOT / ".docker" / name / "Dockerfile").read_text()
        assert "COPY requirements.txt requirements.lock.txt /app/" in dockerfile
        assert "pip install --no-cache-dir -r /app/requirements.txt -c /app/requirements.lock.txt" in dockerfile


def test_release_preflight_is_manual_read_only_and_explicitly_unqualified():
    workflow = _workflow("release-preflight.yml")
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["render"]
    assert job["environment"] == "release-review"
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "CRYPTOSCAN_RELEASE_REVIEW_READY" in json.dumps(job)
    assert "refs/tags/v*" in commands
    assert "scripts/pin_release_images.py" in commands
    assert "'site_qualified': False" in commands
    assert "push: true" not in json.dumps(workflow)
    assert "packages: write" not in json.dumps(workflow)
