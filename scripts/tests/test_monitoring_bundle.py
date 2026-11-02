"""The monitoring bundle check, and the two defects it was written to catch.

Three things are pinned here:

* the bundle itself grades clean, so a config that drifts from the overlay fails
  CI rather than at container start;
* the negative control still catches every injected defect — a check that cannot
  fail is decoration;
* the two bugs found while writing it stay fixed. ``${MONITORING_SECRETS_DIR:-…}``
  contains a colon the shell owns, and splitting a mount spec on ``:`` turned a
  mounted secret into "not mounted"; and a severity that matches no sub-route is
  *not* unrouted — it lands on the default receiver, so the real question is
  whether a paging severity is being silenced.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "monitoring_bundle.py"
RENDER = ROOT / "scripts" / "render_monitoring_secrets.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def bundle_script():
    return _load(SCRIPT, "monitoring_bundle_under_test")


@pytest.fixture(scope="module")
def render_script():
    return _load(RENDER, "render_monitoring_secrets_under_test")


@pytest.fixture(scope="module")
def report(bundle_script) -> dict:
    return bundle_script.measure()


def test_the_bundle_grades_clean(report):
    assert report["counts"] == {"PASS": 3, "PARTIAL": 0, "FAIL": 0}, [
        (row["id"], [probe for probe in row["probes"] if not probe["ok"]])
        for row in report["rows"]
    ]


def test_every_injected_defect_is_caught(report):
    control = report["negative_control"]
    assert control["caught_every_injection"], {
        name: item for name, item in control["injections"].items() if not item["caught"]
    }
    # the control must exercise all three rows, or one of them is unguarded
    exercised = {row for item in control["injections"].values() for row in item["affected_rows"]}
    assert exercised == {"compose_wiring", "config_chain", "secret_wiring"}


def test_the_token_check_executes_the_api_dependency(report):
    """400/401/503 must come from the real dependency, not from a literal."""
    secret = next(row for row in report["rows"] if row["id"] == "secret_wiring")
    assert secret["statuses"] == {"right": 200, "wrong": 401, "missing": 401,
                                  "unconfigured": 503}
    assert secret["token_length"] >= 32


def test_a_compose_mount_is_not_split_inside_a_shell_default(bundle_script):
    """The bug: `${VAR:-./dir}/file:/etc/file:ro` has four colons and two fields."""
    parts = bundle_script._split_mount("${MONITORING_SECRETS_DIR:-./infra/monitoring/secrets}/webhook_token:/etc/alertmanager/secrets/webhook_token:ro")
    assert parts == [
        "${MONITORING_SECRETS_DIR:-./infra/monitoring/secrets}/webhook_token",
        "/etc/alertmanager/secrets/webhook_token",
        "ro",
    ]


def test_a_severity_with_no_sub_route_lands_on_the_default_receiver(bundle_script):
    """It is not "unrouted": the default receiver is where it goes."""
    row = None
    probes = bundle_script.check_config_chain(
        bundle_script.Bundle(bundle_script.REPO_ROOT),
        {bundle_script.RECEIVER_PATH},
    )["probes"]
    names = {probe["probe"]: probe for probe in probes}
    row = names["no-paging-severity-is-silenced"]
    assert row["ok"], row["observed"]
    assert "critical->" in names["every-rule-severity-resolves-to-a-receiver"]["observed"]


# --------------------------------------------------------------- secret renderer


def test_renderer_writes_both_files_and_refuses_a_short_token(tmp_path, render_script):
    with pytest.raises(SystemExit):
        render_script.render(tmp_path, {"ALERTMANAGER_WEBHOOK_TOKEN": "short",
                                        "METRICS_TOKEN": "c" * 64})
    written = render_script.render(tmp_path, {"ALERTMANAGER_WEBHOOK_TOKEN": "a" * 64,
                                              "METRICS_TOKEN": "c" * 64})
    assert {record["file"].rsplit("/", 1)[-1] for record in written} == {
        "webhook_token", "metrics_token"}
    for name in ("webhook_token", "metrics_token"):
        mode = (tmp_path / name).stat().st_mode & 0o777
        assert mode == 0o400, oct(mode)


def test_renderer_refuses_the_same_token_for_both_credentials(tmp_path, render_script):
    with pytest.raises(SystemExit):
        render_script.render(tmp_path, {"ALERTMANAGER_WEBHOOK_TOKEN": "a" * 64,
                                        "METRICS_TOKEN": "a" * 64})
