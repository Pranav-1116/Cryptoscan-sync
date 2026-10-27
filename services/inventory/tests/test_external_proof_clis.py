"""Offline v2/estate verification and live capture preflight; never contact real providers."""

import json
from pathlib import Path
import subprocess
import sys
from shared.shared_models.tests.test_operation_evidence_v2 import packet as operation_packet
from shared.shared_models.tests.test_software_estate import fixture as estate_fixture
from shared_models.hsm_operation_request import HsmOperationRequest
from shared_models.tpm_quote_verification import canonical, sha

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def test_v2_cli_verifies_public_packet_once(tmp_path):
    approval, evidence, _, _ = operation_packet("ECDSA_P256_SHA256")
    a = tmp_path / "approval"
    a.write_bytes(canonical(approval))
    e = tmp_path / "evidence"
    e.write_bytes(canonical(evidence))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    out = tmp_path / "out"
    cmd = [
        sys.executable,
        str(SCRIPTS / "verify_operation_evidence.py"),
        "--approval",
        str(a),
        "--approved-sha256",
        sha(approval),
        "--evidence",
        str(e),
        "--state-dir",
        str(state),
        "--output",
        str(out),
    ]
    r = subprocess.run(cmd, capture_output=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_bytes())["schema_version"] == "cryptoscan.operation-verification/v2"
    original = out.read_bytes()
    assert subprocess.run(cmd, capture_output=True).returncode == 64 and out.read_bytes() == original
    cmd[-1] = str(tmp_path / "replay")
    assert subprocess.run(cmd, capture_output=True).returncode == 64


def test_estate_cli_valid_and_missing_returns(tmp_path):
    plan, packet, artifacts, _ = estate_fixture()
    p = tmp_path / "plan"
    p.write_bytes(canonical(plan))
    e = tmp_path / "packet"
    e.write_bytes(canonical(packet))
    directory = tmp_path / "sources"
    directory.mkdir()
    for digest, data in artifacts.items():
        (directory / digest).write_bytes(data)
    cmd = [
        sys.executable,
        str(SCRIPTS / "reconcile_software_estate.py"),
        "--plan",
        str(p),
        "--approved-plan-sha256",
        sha(plan),
        "--packet",
        str(e),
        "--artifacts",
        str(directory),
        "--output",
        str(tmp_path / "out"),
    ]
    r = subprocess.run(cmd, capture_output=True)
    assert r.returncode == 0, r.stderr
    report = json.loads((tmp_path / "out").read_bytes())
    assert report["matched_units"] == 12 and not report["whole_estate_software_complete"]
    packet = packet.model_copy(update={"returns": []})
    e.write_bytes(canonical(packet))
    cmd[-1] = str(tmp_path / "blocked")
    assert subprocess.run(cmd, capture_output=True).returncode == 2
    assert json.loads((tmp_path / "blocked").read_bytes())["matched_units"] == 0


def test_live_hsm_wrong_approval_no_sdk_no_state_consumption(tmp_path):
    a, _, _, _ = operation_packet()
    request = HsmOperationRequest(region="ap-south-1", approval=a)
    p = tmp_path / "request"
    p.write_bytes(canonical(request))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    r = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "capture_approved_hsm_operation.py"),
            "--request",
            str(p),
            "--approved-request-sha256",
            "f" * 64,
            "--state-dir",
            str(state),
            "--output",
            str(tmp_path / "out"),
            "--acknowledge-provider-sign",
        ],
        capture_output=True,
    )
    assert r.returncode == 64 and not list(state.iterdir()) and not (tmp_path / "out").exists()


def test_live_hsm_attempt_is_not_retried_after_sdk_failure(tmp_path, monkeypatch, capsys):
    import types
    import capture_approved_hsm_operation as cli

    a, _, _, _ = operation_packet()
    request = HsmOperationRequest(region="ap-south-1", approval=a)
    source = tmp_path / "request"
    source.write_bytes(canonical(request))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    calls = []

    def fail_client(*args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError("synthetic-credential-must-not-print")

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=fail_client))
    monkeypatch.setitem(sys.modules, "botocore.config", types.SimpleNamespace(Config=lambda **kw: kw))
    args = [
        "capture",
        "--request",
        str(source),
        "--approved-request-sha256",
        sha(request),
        "--state-dir",
        str(state),
        "--output",
        str(tmp_path / "out"),
        "--acknowledge-provider-sign",
    ]
    monkeypatch.setattr(sys, "argv", args)
    assert cli.main() == 64
    args[-2] = str(tmp_path / "second")
    monkeypatch.setattr(sys, "argv", args)
    assert cli.main() == 64
    assert len(calls) == 1 and len(list(state.iterdir())) == 1
    assert calls[0]["config"]["retries"] == {"max_attempts": 0}
    assert "synthetic-credential-must-not-print" not in capsys.readouterr().err
