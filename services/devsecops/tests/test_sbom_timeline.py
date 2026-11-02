"""A timeline over stored artifacts: two snapshots compare, one does not.

The distinction the API must preserve is between "no drift" and "drift was never
measured". A single stored SBOM is the second case, and it says so.
"""

from __future__ import annotations


from devsecops import sbom_timeline as timeline_mod

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _manifest(*, artifact_id="ART-1", digest=DIGEST_A, created="2026-10-01",
              target="ghcr.io/bank/payments-api", build_id=None):
    manifest = {"artifact_id": artifact_id, "sha256": digest, "created_at": created,
                "target": target}
    if build_id:
        manifest["provenance"] = {"build": {"build_id": build_id}}
    return manifest


def _cyclonedx(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": list(components)}


def _spdx(*packages):
    return {"spdxVersion": "SPDX-2.3", "packages": list(packages)}


def test_a_cyclonedx_document_becomes_a_snapshot():
    record = timeline_mod.record_from_document(
        _manifest(), _cyclonedx({"name": "openssl", "version": "3.0.13"}))
    assert record.sbom_id == "ART-1"
    assert record.component("openssl")["version"] == "3.0.13"
    assert record.artifact.digest == f"sha256:{DIGEST_A}"
    assert record.created_at.isoformat() == "2026-10-01"


def test_an_spdx_document_becomes_the_same_shape():
    record = timeline_mod.record_from_document(
        _manifest(), _spdx({"name": "openssl", "versionInfo": "3.0.13"}))
    assert record.component("openssl")["version"] == "3.0.13"


def test_a_manifest_without_a_digest_is_not_bound_to_an_artifact():
    record = timeline_mod.record_from_document(_manifest(digest=""), _cyclonedx())
    assert record.artifact is None


def test_licences_and_crypto_flags_survive_the_conversion():
    record = timeline_mod.record_from_document(_manifest(), _cyclonedx({
        "name": "openssl", "version": "3.0.13",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "cryptoProperties": {"assetType": "algorithm"}}))
    row = record.component("openssl")
    assert row["license"] == "Apache-2.0"
    assert row["crypto_relevant"] is True


def test_the_build_id_is_carried_through():
    record = timeline_mod.record_from_document(
        _manifest(build_id="BUILD-7"), _cyclonedx({"name": "openssl", "version": "3.0.13"}))
    assert record.build_id == "BUILD-7"


def test_two_snapshots_produce_events_with_both_ends_named():
    report = timeline_mod.timeline([
        (_manifest(artifact_id="ART-1", created="2026-10-01"),
         _cyclonedx({"name": "openssl", "version": "3.0.13"},
                    {"name": "curl", "version": "8.5.0"})),
        (_manifest(artifact_id="ART-2", digest=DIGEST_B, created="2026-10-15"),
         _cyclonedx({"name": "openssl", "version": "3.0.14"})),
    ], target="ghcr.io/bank/payments-api")
    assert report["snapshots"] == ["ART-1", "ART-2"]
    assert report["changed_transitions"] == 1
    assert report["event_counts"] == {"ARTIFACT_CHANGED": 1, "PACKAGE_REMOVED": 1,
                                      "VERSION_CHANGED": 1}
    event = next(row for row in report["events"] if row["type"] == "VERSION_CHANGED")
    assert (event["component"], event["from"], event["to"]) == ("openssl", "3.0.13", "3.0.14")
    assert (event["from_sbom"], event["to_sbom"]) == ("ART-1", "ART-2")
    assert event["at"] == "2026-10-15"
    assert event["artifact_level"] is False


def test_a_single_snapshot_reports_drift_as_unmeasured():
    report = timeline_mod.timeline([(_manifest(), _cyclonedx({"name": "openssl"}))])
    assert report["transitions"] == [] and report["events"] == []
    assert report["changed_transitions"] == 0
    assert "drift is unmeasured" in report["statement"]
    assert "no change" not in report["statement"]


def test_identical_snapshots_are_no_drift_not_unmeasured():
    document = _cyclonedx({"name": "openssl", "version": "3.0.13"})
    report = timeline_mod.timeline([(_manifest(artifact_id="ART-1"), document),
                                    (_manifest(artifact_id="ART-2"), document)])
    assert report["transitions"][0]["changes"] == []
    assert report["changed_transitions"] == 0
    assert "drift is unmeasured" not in report["statement"]
    assert "no change" in report["statement"]


def test_the_target_is_named_in_the_statement():
    report = timeline_mod.timeline([(_manifest(), _cyclonedx())], target="ghcr.io/bank/api")
    assert report["target"] == "ghcr.io/bank/api"
    assert "ghcr.io/bank/api" in report["statement"]


def test_events_can_be_left_out_without_losing_the_transitions():
    report = timeline_mod.timeline([
        (_manifest(artifact_id="ART-1"), _cyclonedx({"name": "openssl", "version": "1"})),
        (_manifest(artifact_id="ART-2", digest=DIGEST_B,
                   created="2026-10-15"), _cyclonedx({"name": "openssl", "version": "2"})),
    ], include_events=False)
    assert report["events"] == [] and report["event_counts"] == {}
    assert len(report["transitions"]) == 1


def test_the_snapshot_order_does_not_depend_on_the_input_order():
    one = (_manifest(artifact_id="ART-1", created="2026-10-01"),
           _cyclonedx({"name": "openssl", "version": "3.0.13"}))
    two = (_manifest(artifact_id="ART-2", digest=DIGEST_B, created="2026-10-15"),
           _cyclonedx({"name": "openssl", "version": "3.0.14"}))
    forward = timeline_mod.timeline([one, two])
    backward = timeline_mod.timeline([two, one])
    assert forward["snapshots"] == backward["snapshots"] == ["ART-1", "ART-2"]
    assert forward["events"] == backward["events"]


def test_two_snapshots_on_the_same_day_keep_their_stored_order():
    """Same-day scans must not be ordered by their random artifact ids."""
    first = _manifest(artifact_id="ART-b", created="2026-10-01T09:00:00+00:00")
    second = _manifest(artifact_id="ART-a", digest=DIGEST_B,
                       created="2026-10-01T17:00:00+00:00")
    report = timeline_mod.timeline([
        (second, _cyclonedx({"name": "openssl", "version": "3.0.14"})),
        (first, _cyclonedx({"name": "openssl", "version": "3.0.13"})),
    ])
    assert report["snapshots"] == ["ART-b", "ART-a"]
    event = report["events"][0]
    assert (event["from"], event["to"]) == ("3.0.13", "3.0.14")


def test_the_schema_is_declared():
    report = timeline_mod.timeline([])
    assert report["schema"] == timeline_mod.SCHEMA == "cryptoscan.sbom-timeline/1"
    assert report["snapshots"] == []


def test_an_artifact_level_change_does_not_name_a_component():
    report = timeline_mod.timeline([
        (_manifest(artifact_id="ART-1", target="ghcr.io/bank/api"), _cyclonedx()),
        (_manifest(artifact_id="ART-2", digest=DIGEST_B, created="2026-10-15",
                   target="ghcr.io/bank/api-v2"), _cyclonedx()),
    ])
    artifact_events = [row for row in report["events"] if row["artifact_level"]]
    assert artifact_events
    assert all(row["component"] is None for row in artifact_events)


def test_the_component_history_is_a_series():
    report = timeline_mod.timeline([
        (_manifest(artifact_id="ART-1", created="2026-10-01"),
         _cyclonedx({"name": "openssl", "version": "3.0.13"})),
        (_manifest(artifact_id="ART-2", digest=DIGEST_B, created="2026-10-15"),
         _cyclonedx({"name": "openssl", "version": "3.0.14"})),
    ])
    history = report["components"]["openssl"]
    assert [row["version"] for row in history] == ["3.0.13", "3.0.14"]
    assert [row["sbom"] for row in history] == ["ART-1", "ART-2"]
    assert report["gap_days"] == 14
