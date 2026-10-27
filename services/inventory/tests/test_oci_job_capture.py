"""Bound-return CLI and pre-I/O checks with owned OCI fixtures."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import pytest
from inventory.oci_job_capture import capture_oci_job
from inventory.oci_evidence import OciRefused
from shared_models.host_collection import digest
from shared_models.oci_intake import OciCaptureBinding, OciJobReturn
from services.inventory.tests.test_oci_evidence import fixture

ROOT = Path(__file__).resolve().parents[3]


def binding_for(target):
    return OciCaptureBinding(
        job_id="11111111-1111-1111-1111-111111111111",
        target_id="22222222-2222-2222-2222-222222222222",
        target_revision=2,
        target_record_sha256="3" * 64,
        target_sha256=digest(target),
        nonce="4" * 64,
        issued_at=datetime.now(timezone.utc),
        expires_at=target.expires_at,
    )


def test_actual_bound_capture_preserves_original_evidence_contract(tmp_path):
    target, _ = fixture(tmp_path)
    binding = binding_for(target)
    result = capture_oci_job(target, binding, digest(target), digest(binding))
    assert result.binding == binding and result.evidence.target == target
    assert result.evidence.schema_version == "cryptoscan.oci-evidence/v1"
    assert not result.producer_authenticity_verified and result.runtime_use == "UNKNOWN"
    assert OciJobReturn.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("change", ["binding_sha", "target_sha", "expired", "future"])
def test_bad_handoff_refuses_before_reading_image(tmp_path, monkeypatch, change):
    target, _ = fixture(tmp_path)
    binding = binding_for(target)
    approved = digest(binding)
    if change == "binding_sha":
        approved = "0" * 64
    if change == "target_sha":
        binding = binding.model_copy(update={"target_sha256": "0" * 64})
        approved = digest(binding)
    if change == "expired":
        now = datetime.now(timezone.utc)
        binding = binding.model_copy(
            update={"issued_at": now - timedelta(minutes=2), "expires_at": now - timedelta(minutes=1)}
        )
        approved = digest(binding)
    if change == "future":
        binding = binding.model_copy(update={"issued_at": datetime.now(timezone.utc) + timedelta(minutes=2)})
        approved = digest(binding)

    def no_read(*args):
        raise AssertionError("Rejected binding must not read image")

    monkeypatch.setattr("inventory.oci_evidence.read_public", no_read)
    with pytest.raises(OciRefused):
        capture_oci_job(target, binding, digest(target), approved)


@pytest.mark.parametrize(
    "field,value",
    [("nonce", "not-a-digest"), ("job_id", "free-text"), ("target_revision", 1), ("expires_at", "2026-10-25T12:00:00")],
)
def test_binding_is_strict_and_aware(tmp_path, field, value):
    target, _ = fixture(tmp_path)
    raw = binding_for(target).model_dump(mode="json")
    raw[field] = value
    with pytest.raises(ValueError):
        OciCaptureBinding.model_validate(raw)


def test_return_cannot_promote_authenticity_or_change_bound_target(tmp_path):
    target, _ = fixture(tmp_path)
    binding = binding_for(target)
    result = capture_oci_job(target, binding, digest(target), digest(binding))
    for change in [
        lambda d: d.update(producer_authenticity_verified=True),
        lambda d: d["binding"].update(target_sha256="0" * 64),
    ]:
        data = result.model_dump()
        change(data)
        with pytest.raises(ValueError):
            OciJobReturn.model_validate(data)


def test_bound_cli_refuses_duplicate_binding_and_wrong_digest(tmp_path):
    target, _ = fixture(tmp_path)
    binding = binding_for(target)
    plan, handoff, output = [tmp_path / n for n in ["target.json", "binding.json", "output.json"]]
    plan.write_text(target.model_dump_json())
    handoff.write_text(binding.model_dump_json())
    base = [
        sys.executable,
        str(ROOT / "scripts/capture_oci_job_evidence.py"),
        "--target",
        str(plan),
        "--binding",
        str(handoff),
        "--approved-target-sha256",
        digest(target),
        "--output",
        str(output),
        "--approved-binding-sha256",
    ]
    wrong = subprocess.run(base + ["0" * 64], capture_output=True)
    assert wrong.returncode == 64 and not output.exists()
    data = json.dumps({"job_id": "wrong"})[:-1] + "," + binding.model_dump_json()[1:]
    handoff.write_text(data)
    duplicate = subprocess.run(base + [digest(binding)], capture_output=True)
    assert duplicate.returncode == 64 and not output.exists()
