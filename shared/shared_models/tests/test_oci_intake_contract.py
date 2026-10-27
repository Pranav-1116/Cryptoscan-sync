"""Published job-bound OCI schemas and challenge-window constraints."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from shared_models.oci_intake import OciCaptureBinding, OciIntakeRequest, OciJobReturn


@pytest.mark.parametrize(
    "name,model",
    [
        ("oci-capture-binding-v1", OciCaptureBinding),
        ("oci-job-return-v1", OciJobReturn),
        ("oci-intake-request-v1", OciIntakeRequest),
    ],
)
def test_job_bound_schema_matches_model(name, model):
    path = Path(__file__).resolve().parents[1] / "shared_models/schemas" / (name + ".schema.json")
    schema = json.loads(path.read_text())
    assert schema == model.model_json_schema()
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("hours", [0, -1, 25])
def test_binding_window_is_positive_and_bounded(hours):
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        OciCaptureBinding(
            job_id="11111111-1111-1111-1111-111111111111",
            target_id="22222222-2222-2222-2222-222222222222",
            target_revision=2,
            target_record_sha256="3" * 64,
            target_sha256="4" * 64,
            nonce="5" * 64,
            issued_at=now,
            expires_at=now + timedelta(hours=hours),
        )
