"""Phase 2: explicit Linux source facts, not running OS or whole-host proof."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json, subprocess, sys
import pytest
from pydantic import ValidationError
from inventory.collection import OfflineLinuxCollector
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.host_collection import HostInput, HostManifest, HostFact


def spec(tmp_path, contents):
    path = tmp_path / "os-release"
    path.write_bytes(contents)
    manifest = HostManifest(
        approval_reference="change/linux-02",
        host_id="payments-1",
        environment="prod",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        inputs=[HostInput(input_id="os", kind="LINUX_OS_RELEASE", path=str(path))],
    )
    return TargetSpec(
        target_key="payments-linux-01",
        system_id="system-a",
        owner="Payments",
        environment="prod",
        collection_method="offline_host",
        address="payments-1",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(seconds=1),
        manifest=manifest,
    )


def test_linux_adapter_reads_allowlisted_os_fields_not_shell_or_secrets(tmp_path):
    target = spec(
        tmp_path,
        b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="secret display label"\nPASSWORD=do-not-export\nEVIL=$(touch /tmp/never-run)\n',
    )
    result = OfflineLinuxCollector().collect(target)
    fact = result.receipts[0].facts[0]
    assert fact.kind == "OS_RELEASE" and fact.software_name == "ubuntu" and fact.software_version == "24.04"
    assert fact.local_basis == "DECLARED" and fact.algorithm == fact.runtime_use == "UNKNOWN"
    assert "secret" not in result.model_dump_json() and "EVIL" not in result.model_dump_json()
    assert OfflineLinuxCollector().health()["remote_execution"] is False


@pytest.mark.parametrize(
    "contents",
    [
        b"ID=$(echo ubuntu)\n",
        b"ID=ubuntu\nID=debian\n",
        b"NAME=Ubuntu\n",
        b'ID="ubuntu\n',
        b"ID=ubuntu\nVERSION_ID=24.04;command\n",
        b"\xff",
    ],
)
def test_os_release_does_not_expand_ambiguous_or_executable_values(tmp_path, contents):
    result = OfflineLinuxCollector().collect(spec(tmp_path, contents))
    assert result.receipts[0].status == "INVALID" and not result.receipts[0].facts


def test_unknown_os_version_is_not_invented(tmp_path):
    result = OfflineLinuxCollector().collect(spec(tmp_path, b"ID=ubuntu\n"))
    assert result.receipts[0].facts[0].software_version is None


def test_scope_time_window_and_method_are_checked_before_io(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\n")
    future = target.model_copy(update={"not_before": datetime.now(timezone.utc) + timedelta(minutes=1)})
    with pytest.raises(ValueError, match="window"):
        OfflineLinuxCollector().collect(future)
    with pytest.raises(ValueError, match="supported"):
        OfflineLinuxCollector().collect(target.model_copy(update={"collection_method": "network"}))


def test_os_release_cannot_be_promoted_to_observed_runtime_or_crypto(tmp_path):
    fact = OfflineLinuxCollector().collect(spec(tmp_path, b"ID=ubuntu\n")).receipts[0].facts[0].model_dump(mode="json")
    for changes in [{"algorithm": "RSA", "key_size": 2048}, {"local_basis": "OBSERVED"}, {"runtime_use": "OBSERVED"}]:
        with pytest.raises(ValidationError):
            HostFact.model_validate({**fact, **changes})


def test_target_cli_uses_same_snapshot_and_exclusive_output(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\nVERSION_ID=24.04\n")
    input_path = tmp_path / "target.json"
    input_path.write_text(target.model_dump_json())
    output = tmp_path / "snapshot.json"
    script = Path(__file__).resolve().parents[3] / "scripts/collect_host.py"
    command = [sys.executable, str(script), "--target-spec", str(input_path), "--output", str(output)]
    first = subprocess.run(command, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert json.loads(output.read_text())["receipts"][0]["facts"][0]["software_name"] == "ubuntu"
    assert output.stat().st_mode & 0o777 == 0o600
    assert subprocess.run(command, capture_output=True).returncode == 64


@pytest.mark.parametrize(
    "model,name", [(TargetSpec, "collection-target-v1"), (CollectionResult, "collection-evidence-v1")]
)
def test_pinned_foundation_contract_schemas(model, name):
    import shared_models

    folder = Path(shared_models.__file__).parent / "schemas"
    assert json.loads((folder / (name + ".schema.json")).read_text()) == model.model_json_schema()
