"""Actual opt-in Linux kernel namespace fixture, not Windows/Docker qualification."""

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from qualify_owned_namespace_container import fixture_plan, run_owned
from shared_models.tpm_quote_verification import sha


def test_plan_mismatch_refuses_before_compilation_or_native_calls(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("No execution before approved scope")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="changed"):
        run_owned("a" * 64)


def test_cli_requires_ack_and_does_not_overwrite(tmp_path):
    script = Path(__file__).resolve().parents[3] / "scripts/qualify_owned_namespace_container.py"
    result = subprocess.run([sys.executable, str(script), "--describe-plan"], capture_output=True, check=True)
    described = json.loads(result.stdout)
    assert described["plan_sha256"] == sha(fixture_plan())
    out = tmp_path / "output"
    out.write_bytes(b"original")
    r = subprocess.run(
        [
            sys.executable,
            str(script),
            "--approved-plan-sha256",
            described["plan_sha256"],
            "--output",
            str(out),
            "--acknowledge-owned-container",
        ],
        capture_output=True,
    )
    assert r.returncode == 64 and out.read_bytes() == b"original"


@pytest.mark.skipif(
    os.environ.get("CRYPTOSCAN_RUN_OWNED_NAMESPACE_TEST") != "1",
    reason="Actual owned Linux namespace execution requires explicit local opt-in; not a qualification PASS",
)
def test_actual_rootless_namespace_image_limits_cancel_and_cleanup():
    before = set(Path.home().glob("cryptoscan-owned-container-*"))
    r = run_owned(sha(fixture_plan()))
    assert r["actual_native_namespace_execution"] and r["actual_image_package_records_matched"]
    assert r["normal_run"]["pid"] == 1 and r["cancellation_exercised"] and r["owned_work_directory_removed"]
    assert (
        not r["customer_container_qualified"] and not r["docker_or_kubernetes_qualified"] and not r["windows_qualified"]
    )
    assert set(Path.home().glob("cryptoscan-owned-container-*")) == before
    from shared_models.container_admission import ADMITTED_CONTAINER_PROFILES

    assert not ADMITTED_CONTAINER_PROFILES
