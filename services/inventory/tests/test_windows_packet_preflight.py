"""Preflight runs no native interfaces, creates no approval and dispatches nobody."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import pytest
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostManifest, HostInput
from shared_models.qualification_acceptance import NativePlan, ExpectedNativeInput
from shared_models.windows_qualification import prepare_windows_preflight, WindowsQualificationPreflight
from shared_models.tpm_quote_verification import sha, canonical
from shared_models.windows_cng import unsupported_expected_value
from services.inventory.tests.test_windows_metadata import snapshot

ROOT = Path(__file__).resolve().parents[3]


def fixture():
    inputs = [
        HostInput(input_id="os", kind="WINDOWS_OS_RELEASE", path="windows-os://local/current-version"),
        HostInput(input_id="scm", kind="WINDOWS_SERVICE", path="windows-service://ReviewedService"),
        HostInput(
            input_id="capi",
            kind="WINDOWS_CAPI_DEFAULT_PROVIDER",
            path="windows-capi://local/current-user/rsa-aes/default-provider",
        ),
        HostInput(input_id="tcp", kind="WINDOWS_TCP_LISTENERS", path="windows-sockets://local/ipv4/tcp-listeners"),
    ]
    target = TargetSpec(
        target_key="synthetic-windows-packet",
        system_id="fixture-system",
        owner="Fixture owner",
        environment="test",
        collection_method="offline_host",
        address="fixture-windows",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
        manifest=HostManifest(
            approval_reference="synthetic-review",
            host_id="fixture-windows",
            environment="test",
            platform="windows",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            inputs=inputs,
        ),
    )
    # Deliberately hand-authored public fixture, NOT independent human approval.
    base = {"algorithm": "UNKNOWN", "runtime_use": "UNKNOWN", "capabilities_observed": False}
    expected = [
        ExpectedNativeInput(input_id="os", facts=[{"kind": "OS_RELEASE", "software_name": "Reviewed Windows"}]),
        ExpectedNativeInput(input_id="scm", facts=[{"kind": "SERVICE", "service_name": "ReviewedService"}]),
        ExpectedNativeInput(
            input_id="capi",
            facts=[
                {
                    **base,
                    "kind": "WINDOWS_CAPI_DEFAULT_PROVIDER",
                    "provider_type": 24,
                    "provider_context": "CURRENT_USER",
                    "provider_name": "Reviewed Provider",
                }
            ],
        ),
        ExpectedNativeInput(
            input_id="tcp",
            facts=[
                {
                    **base,
                    "kind": "WINDOWS_TCP_LISTENER_TABLE",
                    "address_family": "ipv4",
                    "listener_count": 1,
                    "listeners": [{"address": "127.0.0.1", "port": 443, "owning_pid": 1234, "scope_id": 0}],
                    "tls_observed": False,
                    "process_identity_verified": False,
                }
            ],
        ),
    ]
    plan = NativePlan(target_sha256=sha(target), expected=expected, reviewer_reference="synthetic-review")
    return target, plan


def test_preflight_has_no_native_or_approval_claims():
    target, plan = fixture()
    packet = prepare_windows_preflight(target, plan, "a" * 64, sha(plan), "a" * 64)
    assert packet.status == "PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR"
    assert (
        packet.native_execution_performed
        is packet.independent_approval_verified
        is packet.production_execution_qualified
        is packet.container_admission_granted
        is False
    )
    raw = packet.model_dump(mode="json")
    raw["native_execution_performed"] = True
    with pytest.raises(ValueError):
        WindowsQualificationPreflight.model_validate(raw)


@pytest.mark.parametrize(
    "change",
    [
        "plan-hash",
        "source-hash",
        "target-hash",
        "missing-os",
        "missing-expected",
        "weak-truth",
        "promoted-tls",
        "wrong-type",
        "wrong-count",
        "unknown-key",
        "nested-row",
    ],
)
def test_preflight_refuses_unreviewed_or_incomplete_truth(change):
    target, plan = fixture()
    approved_plan = sha(plan)
    approved_source = "a" * 64
    if change == "plan-hash":
        approved_plan = "b" * 64
    elif change == "source-hash":
        approved_source = "b" * 64
    elif change == "target-hash":
        plan = plan.model_copy(update={"target_sha256": "b" * 64})
    elif change == "missing-os":
        target = target.model_copy(
            update={"manifest": target.manifest.model_copy(update={"inputs": target.manifest.inputs[1:]})}
        )
        plan = plan.model_copy(update={"target_sha256": sha(target), "expected": plan.expected[1:]})
    elif change == "missing-expected":
        plan = plan.model_copy(update={"expected": plan.expected[:-1]})
    else:
        pattern = plan.expected[-1].facts[0]
        if change == "weak-truth":
            pattern.pop("listeners")
        elif change == "promoted-tls":
            pattern["tls_observed"] = True
        elif change == "wrong-type":
            pattern["listeners"][0]["owning_pid"] = True
        elif change == "wrong-count":
            pattern["listener_count"] = 2
        elif change == "unknown-key":
            pattern["unapproved_claim"] = "attested"
        else:
            pattern["listeners"][0]["port"] = {"nested": 443}
    if change not in {"plan-hash", "source-hash"}:
        approved_plan = sha(plan)
    with pytest.raises(ValueError):
        prepare_windows_preflight(target, plan, "a" * 64, approved_plan, approved_source)


@pytest.mark.parametrize(
    "rows,invalid",
    [
        ([], False),
        ([{"address": "127.0.0.1", "port": 443, "owning_pid": 1234, "scope_id": 0}], False),
        ([{"address": "not-an-ip", "port": 443, "owning_pid": 1234, "scope_id": 0}], True),
        ([{"address": "127.0.0.1", "port": 443, "owning_pid": True, "scope_id": 0}], True),
        ([{"address": "127.0.0.1", "port": 443, "owning_pid": 1234, "scope_id": 1}], True),
        ([{"address": "::1%eth0", "port": 443, "owning_pid": 1234, "scope_id": 0}], True),
        ([{"address": "127.0.0.1", "port": 443, "owning_pid": 1234, "scope_id": 0}] * 2, True),
        ([{"address": "127.0.0.1", "port": {"nested": 443}, "owning_pid": 1234, "scope_id": 0}], True),
    ],
)
def test_only_bounded_canonical_tcp_truth_rows(rows, invalid):
    assert unsupported_expected_value("listeners", rows) == invalid
    assert unsupported_expected_value("unapproved_rows", rows) is True


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_exact_metadata_truth_matches_existing_fixture_runner(monkeypatch, which):
    from qualify_host_profile import FixturePlan, ExpectedInput, validate_plan, evaluate

    value, _ = snapshot(monkeypatch, which)
    target = TargetSpec(
        target_key="fixture-metadata",
        system_id="fixture-system",
        owner="Fixture owner",
        environment="test",
        collection_method="offline_host",
        address="fixture-windows",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
        manifest=value.manifest,
    )
    actual = value.receipts[0].facts[0].model_dump(mode="json")
    # This portable roundtrip is not a native expected-truth/independence witness.
    plan = FixturePlan(
        schema_version="cryptoscan.native-fixture/v1",
        target_sha256=sha(target),
        expected=[ExpectedInput(input_id="metadata", facts=[actual])],
        reviewer_reference="fixture-review",
    )
    validate_plan(target, plan)
    assert evaluate(target, plan, value)["verdict"] == "PASS_SCOPED_FIXTURE"
    if which == "capi":
        plan.expected[0].facts[0]["provider_name"] = "Different Provider"
    else:
        plan.expected[0].facts[0]["listeners"][0]["port"] = 8443
    assert evaluate(target, plan, value)["verdict"] == "FAIL_GAPS_OR_TRUTH_MISMATCH"


def test_cli_preflight_exclusive_output_changed_packet_and_non_windows_refusal(tmp_path):
    from inventory.collector_release import build_lock

    target, plan = fixture()
    source = tmp_path / "source-lock.json"
    source.write_bytes(canonical(build_lock(ROOT)))
    target_path = tmp_path / "target.json"
    target_path.write_bytes(canonical(target))
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical(plan))
    packet = tmp_path / "preflight.json"
    args = [
        sys.executable,
        str(ROOT / "scripts/capture_native_qualification.py"),
        "--category",
        "windows",
        "--target",
        str(target_path),
        "--plan",
        str(plan_path),
        "--source-lock",
        str(source),
        "--approved-plan-sha256",
        sha(plan),
        "--approved-source-lock-sha256",
        hashlib.sha256(source.read_bytes()).hexdigest(),
    ]

    def run(*extra):
        return subprocess.run([*args, *extra], capture_output=True, timeout=20, cwd=ROOT)

    result = run("--preflight-only", "--output", str(packet))
    assert result.returncode == 0, result.stderr
    parsed = json.loads(packet.read_bytes())
    assert parsed["native_execution_performed"] is False
    assert run("--preflight-only", "--output", str(packet)).returncode == 64
    before = packet.read_bytes()
    parsed["target_sha256"] = "b" * 64
    packet.write_text(json.dumps(parsed))
    output = tmp_path / "native.json"
    assert run("--preflight-packet", str(packet), "--output", str(output)).returncode == 64 and not output.exists()
    packet.write_bytes(before)
    if sys.platform != "win32":
        result = run("--preflight-packet", str(packet), "--output", str(output))
        assert result.returncode == 64 and not output.exists()  # No fabricated Windows result.


def test_preflight_hashes_and_parses_same_source_read_without_native_calls(tmp_path, monkeypatch):
    import capture_native_qualification as cli
    from inventory.collector_release import build_lock

    target, plan = fixture()
    source = tmp_path / "source.json"
    raw = canonical(build_lock(ROOT))
    source.write_bytes(raw)
    t = tmp_path / "target.json"
    t.write_bytes(canonical(target))
    p = tmp_path / "plan.json"
    p.write_bytes(canonical(plan))
    output = tmp_path / "packet.json"
    reads = []
    read = cli.read_public

    def once(path, limit):
        reads.append(path)
        assert len(reads) == 1  # Shape and digest must use these SAME immutable bytes.
        return read(path, limit)

    monkeypatch.setattr(cli, "read_public", once)

    def no_native(*a):
        raise AssertionError("Preflight must not query OS token/native collector")

    monkeypatch.setattr(cli, "elevated", no_native)
    monkeypatch.setattr(cli.OfflineWindowsCollector, "collect", no_native)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "capture_native_qualification.py",
            "--category",
            "windows",
            "--target",
            str(t),
            "--plan",
            str(p),
            "--source-lock",
            str(source),
            "--approved-plan-sha256",
            sha(plan),
            "--approved-source-lock-sha256",
            hashlib.sha256(raw).hexdigest(),
            "--preflight-only",
            "--output",
            str(output),
        ],
    )
    assert cli.main() == 0 and reads == [source]
    assert json.loads(output.read_bytes())["source_lock_sha256"] == hashlib.sha256(raw).hexdigest()
