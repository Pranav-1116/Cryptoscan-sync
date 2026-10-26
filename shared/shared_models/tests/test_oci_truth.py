"""Strict pre-capture expected-truth models and published schemas."""

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from shared_models.oci_truth import OciTruthProposal, OciTruthDecision


@pytest.mark.parametrize(
    "model,name", [(OciTruthProposal, "oci-truth-proposal-v1"), (OciTruthDecision, "oci-truth-decision-v1")]
)
def test_truth_schema_matches_model(model, name):
    path = Path(__file__).resolve().parents[1] / "shared_models/schemas" / (name + ".schema.json")
    published = json.loads(path.read_text())
    assert published == model.model_json_schema()
    Draft202012Validator.check_schema(published)


def proposal():
    return {
        "target_sha256": "1" * 64,
        "target_record_sha256": "2" * 64,
        "reviewer_user_id": "33333333-3333-3333-3333-333333333333",
        "source_reference": "build/17",
        "expected": [
            {
                "source": {"input_id": "binary", "kind": "BINARY_METADATA", "path": "usr/lib/library"},
                "expected_content_sha256": "4" * 64,
                "facts": [{"kind": "BINARY", "local_basis": "OBSERVED", "purpose": "FILE_PRESENCE"}],
            }
        ],
    }


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(expected=[]),
        lambda p: p["expected"][0].update(facts=[]),
        lambda p: p["expected"].append(p["expected"][0]),
        lambda p: p.update(reviewer_user_id="not-a-real-identifier"),
        lambda p: p["expected"][0]["facts"][0].update(runtime_use="OBSERVED"),
        lambda p: p["expected"][0]["source"].update(kind="NETWORK_TLS_SESSION"),
        lambda p: p.update(expected_job_revision=2),
        lambda p: p.update(expected_job_revision=True),
        lambda p: p.update(customer_truth_verified=True),
        lambda p: p["expected"][0].update(expected_content_sha256="not-a-digest"),
    ],
)
def test_truth_cannot_manufacture_scope_or_usage(change):
    raw = proposal()
    change(raw)
    with pytest.raises(ValueError):
        OciTruthProposal.model_validate(raw)
