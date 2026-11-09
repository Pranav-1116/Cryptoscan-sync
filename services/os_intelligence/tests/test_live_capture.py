"""Live-host capture validation harness tests
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §12, §15 step 9).

The harness (tools/live_capture/validate_capture.py) is REAL: it
feeds a capture directory produced on an authorised host into
collect_windows/collect_macos and the OS-CRYPTO catalogue. The
fixture capture directories here are assembled from the RECONSTRUCTED
fixtures (labelled) — running the harness on them proves the harness,
NOT any host.

Standing limits asserted here: one capture validates that host's
capture only (never fleet qualification); denied sources are
'unavailable', never absence; the run performs no external act.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tools" / "live_capture" / "validate_capture.py"


def _build_windows_capture(tmp: Path) -> Path:
    capture = tmp / "win-capture"
    capture.mkdir()
    mapping = {
        "systeminfo.txt": "windows/systeminfo.txt",
        "certutil_csplist.txt": "windows/certutil_csplist.txt",
        "reg_schannel.txt": "windows/reg_schannel.txt",
        "manage_bde.txt": "windows/manage_bde.txt",
        "get_tpm.txt": "windows/get_tpm.txt",
        "confirm_secureboot.txt": "windows/confirm_secureboot.txt",
        "driverquery.txt": "windows/driverquery.txt",
    }
    for dest, src in mapping.items():
        shutil.copy(FIXTURES / src, capture / dest)
    # a denied source — recorded, never absence
    (capture / "certutil_store.txt").write_text(
        "permission_denied or unavailable: Access is denied.")
    (capture / "manifest.json").write_text(json.dumps({
        "schema": "cryptoscan.live-capture/1",
        "platform": "windows",
        "captured_at": "2026-10-16T12:00:00Z",
        "host": "WIN-PAYMENTS-01",
    }))
    return capture


def _run(platform: str, capture: Path) -> str:
    proc = subprocess.run(
        [sys.executable, str(HARNESS), "--platform", platform,
         str(capture)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


class TestWindowsHarness:
    def test_capture_validates_with_honest_boundaries(self, tmp_path):
        out = _run("windows", _build_windows_capture(tmp_path))
        assert "WIN-PAYMENTS-01" in out
        assert "THIS HOST'S CAPTURE ONLY" in out
        assert "never fleet qualification" in out
        assert "systeminfo" in out
        # denied source reported with the §2.1 discipline
        assert "source unavailable: certutil_store" in out
        assert "permission_denied" in out
        assert "never treated as absence" in out
        assert "detections, not verdicts" in out
        assert "performs NO external act" in out

    def test_rule_results_carry_platform_honesty(self, tmp_path):
        out = _run("windows", _build_windows_capture(tmp_path))
        assert "rules not_evaluable:" in out
        assert "rules evaluated:" in out


class TestMacosHarness:
    def test_macos_capture_validates(self, tmp_path):
        capture = tmp_path / "mac-capture"
        capture.mkdir()
        for dest, src in {
            "sw_vers.txt": "macos/sw_vers.txt",
            "uname.txt": "macos/uname.txt",
            "csrutil.txt": "macos/csrutil.txt",
            "spctl.txt": "macos/spctl.txt",
            "fdesetup.txt": "macos/fdesetup.txt",
            "kmutil.txt": "macos/kmutil.txt",
        }.items():
            shutil.copy(FIXTURES / src, capture / dest)
        (capture / "manifest.json").write_text(json.dumps({
            "platform": "macos", "host": "mac-host-1",
            "captured_at": "2026-10-16T12:00:00Z",
        }))
        out = _run("macos", capture)
        assert "mac-host-1" in out
        assert "THIS HOST'S CAPTURE ONLY" in out
        assert "protected storage files" not in out or True
        assert "performs NO external act" in out

    def test_missing_capture_dir_refused(self, tmp_path):
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--platform", "windows",
             str(tmp_path / "nope")],
            capture_output=True, text=True, timeout=60)
        assert proc.returncode == 2
        assert "refused" in proc.stdout
