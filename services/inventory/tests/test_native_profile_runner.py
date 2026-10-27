"""Qualification fails on unavailable interfaces, not skipped-to-success."""

import importlib.util
from pathlib import Path
import pytest
from inventory.host import collect
from services.inventory.tests.test_collection_linux import spec
from shared_models.host_collection import digest, HostInput

path = Path(__file__).resolve().parents[3] / "scripts" / "qualify_host_profile.py"
specification = importlib.util.spec_from_file_location("native_qualification", path)
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)


def test_reviewed_native_os_fixture_and_gaps_are_distinct(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\nVERSION_ID=24.04\n")
    plan = module.FixturePlan(
        schema_version="cryptoscan.native-fixture/v1",
        target_sha256=digest(target),
        reviewer_reference="fixture/review",
        expected=[
            module.ExpectedInput(
                input_id="os",
                facts=[
                    {
                        "kind": "OS_RELEASE",
                        "software_name": "ubuntu",
                        "software_version": "24.04",
                        "local_basis": "DECLARED",
                    }
                ],
            )
        ],
    )
    snapshot = collect(target.manifest)
    report = module.evaluate(target, plan, snapshot)
    assert report["verdict"] == "PASS_SCOPED_FIXTURE" and not report["production_execution_qualified"]
    target = target.model_copy(
        update={
            "manifest": target.manifest.model_copy(
                update={"inputs": [HostInput(input_id="os", kind="LINUX_HARDWARE", path="linux-hardware://tpm999")]}
            )
        }
    )
    plan = plan.model_copy(update={"target_sha256": digest(target)})
    report = module.evaluate(target, plan, collect(target.manifest))
    assert report["verdict"] == "FAIL_GAPS_OR_TRUTH_MISMATCH"


def test_fixture_binding_and_assertions_are_validated_before_collection(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\n")
    for pattern in [
        {},
        {"kind": "OS_RELEASE", "not_a_field": "invented"},
        {"kind": "OS_RELEASE", "software_name": {"nested": "no"}},
    ]:
        plan = module.FixturePlan(
            schema_version="cryptoscan.native-fixture/v1",
            target_sha256=digest(target),
            reviewer_reference="fixture/review",
            expected=[module.ExpectedInput(input_id="os", facts=[pattern])],
        )
        with pytest.raises(ValueError):
            module.validate_plan(target, plan)


def test_actual_isolated_qualification_cli_missing_hardware_is_gap_not_pass(tmp_path):
    import subprocess, sys, json

    target = spec(tmp_path, b"ID=debian\n")
    expected = [module.ExpectedInput(input_id="os", facts=[{"kind": "OS_RELEASE", "software_name": "debian"}])]
    plan = module.FixturePlan(
        schema_version="cryptoscan.native-fixture/v1",
        target_sha256=digest(target),
        reviewer_reference="fixture/independent-pending",
        expected=expected,
    )
    target_path = tmp_path / "target.json"
    plan_path = tmp_path / "expected.json"
    output = tmp_path / "actual-isolation.json"
    target_path.write_text(target.model_dump_json())
    plan_path.write_text(plan.model_dump_json())
    result = subprocess.run(
        [
            sys.executable,
            str(path),
            "--target",
            str(target_path),
            "--expectations",
            str(plan_path),
            "--output",
            str(output),
            "--isolated",
        ],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(output.read_bytes())
    assert report["verdict"] == "PASS_SCOPED_FIXTURE" and report["isolation"]["network"] == "DENIED"
    assert not report["production_execution_qualified"] and not report["independent_review_verified"]
    inputs = [HostInput(input_id="os", kind="LINUX_HARDWARE", path="linux-hardware://tpm999")]
    target = target.model_copy(update={"manifest": target.manifest.model_copy(update={"inputs": inputs})})
    plan = plan.model_copy(update={"target_sha256": digest(target)})
    target_path.write_text(target.model_dump_json())
    plan_path.write_text(plan.model_dump_json())
    output.unlink()
    result = subprocess.run(
        [
            sys.executable,
            str(path),
            "--target",
            str(target_path),
            "--expectations",
            str(plan_path),
            "--output",
            str(output),
            "--isolated",
        ],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads(output.read_bytes())["verdict"] == "FAIL_GAPS_OR_TRUTH_MISMATCH"
