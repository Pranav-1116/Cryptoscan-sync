"""Report-manifest contract tests (gap analysis §B: export manifests)."""

from __future__ import annotations

import pytest

from shared_models.report_manifest import (
    MANIFEST_SCHEMA, REQUIRED_FIELDS,
    build_manifest, verify_manifest,
)


def _good(**over):
    base = dict(
        schema_version=MANIFEST_SCHEMA,
        report_id="rep-2026-11-07-0001",
        tenant_id=None,
        scope="platform-estate",
        filters={"hsm_events_days": 90},
        totals={"files": 3},
    )
    base.update(over)
    return base


def test_manifest_carries_every_required_field():
    manifest = build_manifest(**_good())
    for field in REQUIRED_FIELDS:
        assert field in manifest
    assert manifest["tenant_id"] is None, "NULL = platform estate, stated honestly"
    assert manifest["scope"] == "platform-estate"
    verify_manifest(manifest)


def test_missing_fields_are_refused_not_defaulted():
    for field in ("schema_version", "report_id", "scope"):
        with pytest.raises(ValueError):
            build_manifest(**_good(**{field: ""}))
    with pytest.raises(ValueError):
        build_manifest(**_good(filters=None))
    with pytest.raises(ValueError):
        build_manifest(**_good(totals={}))


def test_totals_must_be_counted_non_negative_ints():
    with pytest.raises(ValueError):
        build_manifest(**_good(totals={"files": -1}))
    with pytest.raises(ValueError):
        build_manifest(**_good(totals={"files": "three"}))
    with pytest.raises(ValueError):
        build_manifest(**_good(totals={"files": True}))


def test_empty_filters_are_allowed_only_as_explicit_dict():
    manifest = build_manifest(**_good(filters={}))
    assert manifest["filters"] == {}
    with pytest.raises(ValueError):
        build_manifest(**_good(filters="none"))


def test_extra_cannot_shadow_required_fields():
    with pytest.raises(ValueError):
        build_manifest(**_good(extra={"report_id": "hijacked"}))


def test_verify_manifest_rejects_incomplete_manifests():
    manifest = build_manifest(**_good())
    for field in REQUIRED_FIELDS:
        broken = dict(manifest)
        del broken[field]
        with pytest.raises(ValueError):
            verify_manifest(broken)


def test_generated_at_defaults_to_a_utc_timestamp():
    manifest = build_manifest(**_good())
    assert manifest["generated_at"].endswith("+00:00") or manifest["generated_at"].endswith("Z")
