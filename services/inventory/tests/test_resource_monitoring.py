"""Passive resource parser, path safety and explicit CLI integrity contracts."""

from datetime import timedelta
import os
from pathlib import Path
import subprocess
import sys
import pytest
from inventory import resource_monitoring as reader
from shared_models.host_collection import digest
from shared.shared_models.tests.test_resource_monitoring import authorization, capture

ROOT = Path(__file__).resolve().parents[3]
RAW = b"Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n eth0: 999 1 0 0 0 0 0 0 777 1 0 0 0 0 0 0\n"


def test_exact_interfaces_only_are_projected():
    result = reader.parse_netdev(RAW, ["lo"])
    assert list(result) == ["lo"] and result["lo"].rx_bytes == 100 and result["lo"].tx_bytes == 200


@pytest.mark.parametrize(
    "bad",
    [
        RAW + RAW.splitlines(keepends=True)[2],
        RAW.replace(b"100 2", b"-1 2"),
        RAW.replace(b"100 2", b"18446744073709551616 2"),
        b"not netdev",
        RAW + b"x" * 131073,
    ],
)
def test_malformed_or_oversize_counter_source_refused(bad):
    with pytest.raises(ValueError):
        reader.parse_netdev(bad, ["lo"])


def test_symlink_and_missing_paths_are_gaps_not_capacity(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    assert reader._storage(str(link))["status"] == "UNSUPPORTED"
    assert reader._storage(str(tmp_path / "missing"))["status"] == "UNAVAILABLE"
    assert reader._storage(str(directory))["total_bytes"] > 0


def test_wrong_approval_hash_and_root_refused_before_read(monkeypatch):
    monkeypatch.setattr(reader.os, "geteuid", lambda: 1001)
    with pytest.raises(ValueError, match="APPROVAL_COMMITMENT"):
        reader.collect_resources(authorization(), "0" * 64)
    monkeypatch.setattr(reader.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="ORDINARY_USER"):
        reader.collect_resources(authorization(), "a" * 64)


def test_expired_scope_refused_without_sampling(monkeypatch):
    monkeypatch.setattr(reader.os, "geteuid", lambda: 1001)
    auth = authorization()
    scope = auth.scope.model_copy(
        update={
            "not_before": auth.scope.not_before - timedelta(hours=1),
            "expires_at": auth.scope.expires_at - timedelta(hours=1),
        }
    )
    auth = auth.model_copy(update={"scope": scope, "scope_sha256": digest(scope)})
    with pytest.raises(ValueError, match="CAPTURE_WINDOW"):
        reader.collect_resources(auth, "a" * 64)


def test_cli_report_preserves_commitments_and_never_overwrites(tmp_path):
    value = capture()
    source = tmp_path / "capture.json"
    source.write_text(value.model_dump_json())
    output = tmp_path / "report.json"
    cmd = [
        sys.executable,
        str(ROOT / "scripts/collect_resources.py"),
        "report",
        "--capture",
        str(source),
        "--expected-capture-sha256",
        digest(value),
        "--output",
        str(output),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    before = output.read_bytes()
    assert (output.stat().st_mode & 0o777) == 0o600
    assert subprocess.run(cmd, capture_output=True, timeout=15).returncode == 64
    assert output.read_bytes() == before
    wrong = cmd.copy()
    wrong[wrong.index(digest(value))] = "0" * 64
    wrong[-1] = str(tmp_path / "bad.json")
    assert subprocess.run(wrong, capture_output=True, timeout=15).returncode == 64
    assert not (tmp_path / "bad.json").exists()


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0, reason="Actual ordinary-user Linux required")
def test_native_cli_reads_only_approved_resources(tmp_path):
    auth = authorization()
    source = tmp_path / "scope.json"
    source.write_text(auth.model_dump_json())
    output = tmp_path / "capture.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/collect_resources.py"),
            "collect",
            "--authorization",
            str(source),
            "--approved-record-sha256",
            auth.plan_record_sha256,
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    from shared_models.resource_monitoring import ResourceCapture

    value = ResourceCapture.model_validate_json(output.read_bytes())
    assert [n.interface for n in value.network] == ["lo"] and [s.path for s in value.storage] == ["/"]
    assert value.elapsed_ns >= 1000000000 and not value.configuration_changed and not value.packet_payload_captured
