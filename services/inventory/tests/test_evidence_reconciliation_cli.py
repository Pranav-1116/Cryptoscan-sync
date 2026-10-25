"""Public verifier CLIs, replay fence, exact software denominator and no probing."""

from datetime import datetime, timezone, timedelta
import subprocess
import sys
from pathlib import Path
import pytest
from shared.shared_models.tests.test_operation_evidence import packet
from shared_models.host_collection import HostManifest, HostInput, HostSnapshot, digest
from shared_models.software_truth import SoftwareTruthPlan, ExpectedSoftwareInput, ExpectedPackage, reconcile_software
from shared_models.tpm_quote_verification import canonical, sha
from inventory.host import collect

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def package_fixture(tmp_path):
    file = tmp_path / "status"
    file.write_text(
        "Package: alpha\nStatus: install ok installed\nVersion: 1\n\nPackage: beta\nStatus: hold ok installed\nVersion: 2\n"
    )
    manifest = HostManifest(
        approval_reference="fixture/approved-packages",
        host_id="owned-fixture",
        environment="test",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[HostInput(input_id="packages", kind="DPKG_STATUS", path=str(file))],
    )
    snapshot = collect(manifest)
    assert snapshot.receipts[0].status == "PARSED"
    expected = ExpectedSoftwareInput(
        input_id="packages",
        kind="DPKG_STATUS",
        expected_content_sha256=snapshot.receipts[0].content_sha256,
        records=[ExpectedPackage(name="alpha", version="1"), ExpectedPackage(name="beta", version="2")],
    )
    plan = SoftwareTruthPlan(
        manifest_sha256=digest(manifest), reviewer_reference="fixture/not-independent", inputs=[expected]
    )
    return plan, snapshot


def test_exact_agreed_records_not_whole_host_coverage(tmp_path):
    p, s = package_fixture(tmp_path)
    r = reconcile_software(p, s)
    assert r["agreed_package_record_coverage_verified"] and r["whole_host_software_inventory_complete"] is False
    assert r["independent_reviewer_identity_verified"] is False and r["application_crypto_use"] == "UNKNOWN"


@pytest.mark.parametrize(
    "mode",
    ["missing", "extra", "duplicate", "wrong-version", "wrong-hash", "omitted-input", "wrong-source", "wrong-manifest"],
)
def test_software_denominator_and_mismatches_never_complete(tmp_path, mode):
    p, s = package_fixture(tmp_path)
    item = p.inputs[0]
    rows = item.records
    if mode == "missing":
        item = item.model_copy(update={"records": rows[:1]})
    elif mode == "extra":
        item = item.model_copy(update={"records": [*rows, ExpectedPackage(name="extra", version="1")]})
    elif mode == "duplicate":
        item = item.model_copy(update={"records": [*rows, rows[0]]})
    elif mode == "wrong-version":
        item = item.model_copy(update={"records": [rows[0].model_copy(update={"version": "9"}), rows[1]]})
    elif mode == "wrong-hash":
        item = item.model_copy(update={"expected_content_sha256": "a" * 64})
    elif mode == "wrong-source":
        item = item.model_copy(update={"kind": "APK_INSTALLED"})
    elif mode == "wrong-manifest":
        p = p.model_copy(update={"manifest_sha256": "a" * 64})
    if mode == "omitted-input":
        p = p.model_copy(update={"inputs": []})
    else:
        p = p.model_copy(update={"inputs": [item]})
    try:
        r = reconcile_software(p, s)
    except ValueError:
        return
    assert not r["agreed_package_record_coverage_verified"] and not r["whole_host_software_inventory_complete"]


def test_failed_input_stays_gap(tmp_path):
    p, s = package_fixture(tmp_path)
    r = s.receipts[0].model_copy(
        update={"status": "UNAVAILABLE", "reason": "NOT_FOUND", "facts": [], "content_sha256": None}
    )
    s = HostSnapshot.model_validate(s.model_copy(update={"receipts": [r]}).model_dump(mode="json"))
    report = reconcile_software(p, s)
    assert report["verdict"] == "BLOCKED_SOFTWARE_TRUTH_GAPS"
    row = report["inputs"][0]
    assert row["observed_records"] is None and row["record_comparison_performed"] is False
    assert row["missing"] == row["unexpected"] == []


def test_operation_cli_atomic_replay_refusal_and_no_overwrite(tmp_path):
    a, e, _ = packet()
    approval = tmp_path / "approval.json"
    approval.write_bytes(canonical(a))
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(canonical(e))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    out = tmp_path / "report.json"
    cmd = [
        sys.executable,
        str(SCRIPTS / "verify_operation_evidence.py"),
        "--approval",
        str(approval),
        "--approved-sha256",
        sha(a),
        "--evidence",
        str(evidence),
        "--state-dir",
        str(state),
        "--output",
        str(out),
    ]
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode == 0, result.stderr
    original = out.read_bytes()
    assert subprocess.run(cmd, capture_output=True).returncode == 64 and out.read_bytes() == original
    cmd[-1] = str(tmp_path / "replay.json")
    assert subprocess.run(cmd, capture_output=True).returncode == 64
    assert len(list(state.iterdir())) == 1


def test_software_cli_checks_review_hash_and_never_recollects(tmp_path):
    p, s = package_fixture(tmp_path)
    plan = tmp_path / "plan.json"
    plan.write_bytes(canonical(p))
    snap = tmp_path / "snapshot.json"
    snap.write_bytes(canonical(s))
    out = tmp_path / "report.json"
    Path(s.manifest.inputs[0].path).unlink()  # Original source no longer available; retained evidence only.
    cmd = [
        sys.executable,
        str(SCRIPTS / "reconcile_software_truth.py"),
        "--plan",
        str(plan),
        "--approved-plan-sha256",
        digest(p),
        "--snapshot",
        str(snap),
        "--output",
        str(out),
    ]
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run(cmd, capture_output=True).returncode == 64
