"""The mTLS rotation drill — the runbook's ordering, rehearsed with real
TLS handshakes.

docs/runbooks/mtls-cert-rotation.md says "server first, clients second,
CA last, always overlapped" and lists what must never happen. The drill
executes that order against a TLS stack that DEMANDS client certificates
and proves each claim live — so the procedure is exercised on every
certify run, not just read before an incident.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
_spec = importlib.util.spec_from_file_location(
    "mtls_rotation_drill", REPO / "scripts" / "mtls_rotation_drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    return drill.run_drill(tmp_path_factory.mktemp("mtls-drill"))


def _step(report, name):
    return next(s for s in report["steps"] if s["step"] == name)


class TestTheDrillRehearsesTheRunbook:
    def test_every_claim_holds(self, report):
        assert report["verdict"] == "PASS"
        assert [s["step"] for s in report["steps"]] == [
            "baseline", "server_swap", "client_reissue",
            "ca_overlap", "ca_retire", "wrong_order_demo"]

    def test_the_gate_demands_client_certificates(self, report):
        checks = {c["client"]: c for c in _step(report, "baseline")["checks"]}
        assert checks["enrolled-client"]["connected"] is True
        bare = checks["no-client-cert"]
        assert bare["connected"] is False
        assert "CERTIFICATE_REQUIRED" in bare["detail"]

    def test_server_first_locked_nobody_out(self, report):
        for check in _step(report, "server_swap")["checks"]:
            assert check["connected"] is True, check

    def test_the_overlap_keeps_both_generations_connected(self, report):
        checks = {c["client"]: c for c in _step(report, "ca_overlap")["checks"]}
        assert checks["old-CA-client"]["connected"] is True
        assert checks["new-CA-client"]["connected"] is True

    def test_retiring_the_old_root_is_the_intended_end_state(self, report):
        checks = {c["client"]: c for c in _step(report, "ca_retire")["checks"]}
        assert checks["old-CA-client"]["connected"] is False
        assert "UNKNOWN_CA" in checks["old-CA-client"]["detail"]
        assert checks["new-CA-client"]["connected"] is True

    def test_the_wrong_order_failure_mode_is_observed_not_ignored(self, report):
        check = _step(report, "wrong_order_demo")["checks"][0]
        assert check["connected"] is False  # the lockout the ordering prevents

    def test_the_cli_reports_and_exits_honestly(self, tmp_path):
        out = tmp_path / "drill.json"
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "mtls_rotation_drill.py"),
             "--out", str(out)],
            capture_output=True, text=True, timeout=180)
        assert proc.returncode == 0, proc.stderr[-500:]
        written = json.loads(out.read_text())
        assert written["verdict"] == "PASS"
        assert "throwaway drill material" in written["pki"]
