"""Strict OCI contract and published-schema checks; no collector execution."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from shared_models.oci_collection import ImageInput, OciEvidence, OciTarget
from shared_models.oci_projection import OciProjection

SCHEMAS = Path(__file__).resolve().parents[1] / "shared_models/schemas"


@pytest.mark.parametrize(
    "model,name",
    [(OciTarget, "oci-target-v1"), (OciEvidence, "oci-evidence-v1"), (OciProjection, "oci-six-bom-projection-v1")],
)
def test_published_schema_exactly_matches_model(model, name):
    published = json.loads((SCHEMAS / (name + ".schema.json")).read_text())
    assert published == model.model_json_schema()
    Draft202012Validator.check_schema(published)


def plan():
    now = datetime.now(timezone.utc)
    return dict(
        target_id="payments-image",
        system_id="payments",
        environment="UAT",
        authorization_reference="change/oci-1",
        layout_path="/approved/payments/oci",
        manifest_sha256="1" * 64,
        architecture="amd64",
        not_before=now,
        expires_at=now + timedelta(hours=1),
        inputs=[ImageInput(input_id="os", kind="LINUX_OS_RELEASE", path="etc/os-release")],
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("layout_path", "relative"),
        ("layout_path", "/"),
        ("layout_path", "/approved/../other"),
        ("layout_path", "//server/share"),
        ("architecture", "windows"),
        ("manifest_sha256", "sha256:" + "1" * 64),
    ],
)
def test_scope_shape_is_explicit_and_canonical(field, value):
    data = plan()
    data[field] = value
    with pytest.raises(ValueError):
        OciTarget(**data)


@pytest.mark.parametrize("hours", [0, -1, 25])
def test_window_must_be_positive_and_bounded(hours):
    data = plan()
    data["expires_at"] = data["not_before"] + timedelta(hours=hours)
    with pytest.raises(ValueError):
        OciTarget(**data)


def test_duplicate_scope_and_naive_time_refused():
    data = plan()
    data["inputs"] *= 2
    with pytest.raises(ValueError):
        OciTarget(**data)
    data = plan()
    data["not_before"] = datetime(2026, 10, 25)
    with pytest.raises(ValueError):
        OciTarget(**data)


@pytest.mark.parametrize(
    "kind,path",
    [
        ("DPKG_STATUS", "etc/arbitrary"),
        ("APK_INSTALLED", "etc/shadow"),
        ("RPM_SQLITE", "var/lib/rpm/Packages"),
        ("LINUX_OS_RELEASE", "etc/profile"),
    ],
)
def test_package_and_os_parsers_cannot_be_repurposed(kind, path):
    with pytest.raises(ValueError):
        ImageInput(input_id="metadata", kind=kind, path=path)
