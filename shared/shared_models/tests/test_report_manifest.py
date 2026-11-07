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


# ---------------------------------------------------------------------------
# P0-2: the manifest's file digests are binding. A hashed artifact that is
# present and matches is VALID; a missing artifact is unverifiable, not
# valid; a changed artifact is a named mismatch, never a pass.
# ---------------------------------------------------------------------------


def _hashed_manifest(files: dict):
    import hashlib
    manifest = build_manifest(**_good(extra={
        "files": {
            name: {"sha256": hashlib.sha256(payload).hexdigest(),
                   "bytes": len(payload)}
            for name, payload in files.items()
        },
    }))
    return manifest


def test_verify_manifest_files_accepts_an_untouched_pack():
    from shared_models.report_manifest import VALID, verify_manifest_files
    files = {"events.json": b"{}", "report.md": b"# report"}
    verdict = verify_manifest_files(_hashed_manifest(files), files)
    assert verdict["verified"] is True
    assert verdict["problems"] == []
    assert set(verdict["files"].values()) == {VALID}


def test_a_missing_artifact_is_unverifiable_never_valid():
    from shared_models.report_manifest import (
        ARTIFACT_UNVERIFIABLE, VALID, verify_manifest_files,
    )
    files = {"events.json": b"{}", "report.md": b"# report"}
    manifest = _hashed_manifest(files)
    present_only = {"events.json": b"{}"}
    verdict = verify_manifest_files(manifest, present_only)
    assert verdict["verified"] is False
    assert verdict["files"]["report.md"] == ARTIFACT_UNVERIFIABLE
    assert verdict["files"]["events.json"] == VALID
    assert verdict["problems"][0]["code"] == "ARTIFACT_UNVERIFIABLE"
    assert "unverifiable, not valid" in verdict["problems"][0]["detail"]


def test_a_changed_artifact_is_a_named_digest_mismatch():
    from shared_models.report_manifest import DIGEST_MISMATCH, verify_manifest_files
    files = {"events.json": b"{}"}
    manifest = _hashed_manifest(files)
    verdict = verify_manifest_files(manifest, {"events.json": b'{"tampered": true}'})
    assert verdict["verified"] is False
    assert verdict["files"]["events.json"] == DIGEST_MISMATCH
    assert verdict["problems"][0]["code"] == "DIGEST_MISMATCH"


def test_a_manifest_with_no_recorded_files_verifies_nothing():
    import pytest as _pytest
    from shared_models.report_manifest import verify_manifest_files
    manifest = build_manifest(**_good())
    with _pytest.raises(ValueError):
        verify_manifest_files(manifest, {"events.json": b"{}"})
