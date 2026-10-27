"""Snapshot diff semantics (§4.4, round 56) — pure function tests.

The diff must report exactly what changed between two pinned payloads —
added/removed components and field-level drift on survivors — keyed by
bom-ref, deterministic, and never inventing identity or semantics.
"""

from __future__ import annotations

from cbom.snapshot_diff import diff_components, diff_snapshots, component_ref


def _comp(ref: str, name: str = "AES-256-GCM", **overrides):
    component = {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": ref,
        "cryptoProperties": {
            "assetType": "algorithm",
            "oid": "2.16.840.1.101.3.4.1.46",
            "algorithmProperties": {
                "primitive": "symmetric",
                "algorithm": "AES",
                "mode": "GCM",
                "padding": None,
                "parameterSetIdentifier": "256",
            },
            "nistDesignation": "AES-256-GCM",
            "quantumVulnerable": False,
        },
        "evidence": {"compliance_status": "PASS"},
        "properties": [
            {"name": "cryptoscan:confidence", "value": "HIGH"},
            {"name": "cryptoscan:system", "value": "payments"},
        ],
    }
    component.update(overrides)
    return component


def test_added_removed_and_unchanged_are_keyed_by_bom_ref():
    diff = diff_components(
        [_comp("ev-1"), _comp("ev-2"), _comp("ev-3")],
        [_comp("ev-1"), _comp("ev-2"), _comp("ev-4")],
    )
    assert [c["bom-ref"] for c in diff["added"]] == ["ev-4"]
    assert [c["bom-ref"] for c in diff["removed"]] == ["ev-3"]
    assert diff["unchanged"] == 2
    assert diff["changed"] == []


def test_field_drift_reports_exact_paths_and_values():
    before = _comp("ev-1")
    after = _comp("ev-1")
    after["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = "128"
    after["cryptoProperties"]["algorithmProperties"]["mode"] = "CBC"
    after["evidence"]["compliance_status"] = "FAIL"
    diff = diff_components([before], [after])
    assert diff["changed"][0]["bom-ref"] == "ev-1"
    paths = {c["path"]: c for c in diff["changed"][0]["changes"]}
    assert paths["cryptoProperties.algorithmProperties.parameterSetIdentifier"] == {
        "path": "cryptoProperties.algorithmProperties.parameterSetIdentifier",
        "before": "256", "after": "128"}
    assert paths["cryptoProperties.algorithmProperties.mode"]["after"] == "CBC"
    assert paths["evidence.compliance_status"]["after"] == "FAIL"
    assert diff["unchanged"] == 0


def test_properties_diff_is_keyed_by_name_not_order():
    before = _comp("ev-1", properties=[
        {"name": "cryptoscan:confidence", "value": "HIGH"},
        {"name": "cryptoscan:system", "value": "payments"},
    ])
    # same properties, REORDERED — semantically identical document
    reordered = _comp("ev-1", properties=[
        {"name": "cryptoscan:system", "value": "payments"},
        {"name": "cryptoscan:confidence", "value": "HIGH"},
    ])
    assert diff_components([before], [reordered])["changed"] == []
    # a VALUE change is a real change regardless of order
    drifted = _comp("ev-1", properties=[
        {"name": "cryptoscan:system", "value": "payments"},
        {"name": "cryptoscan:confidence", "value": "LOW"},
    ])
    changed = diff_components([before], [drifted])["changed"]
    assert changed[0]["changes"] == [
        {"path": "properties.cryptoscan:confidence", "before": "HIGH", "after": "LOW"}]


def test_diff_is_deterministic_regardless_of_input_order():
    before = [_comp("ev-b"), _comp("ev-a")]
    after = [_comp("ev-a"), _comp("ev-c"), _comp("ev-b", name="RSA-2048")]
    first = diff_components(before, after)
    second = diff_components(list(reversed(before)), list(reversed(after)))
    assert first == second
    assert [c["bom-ref"] for c in first["added"]] == ["ev-c"]  # sorted, not incidental


def test_component_without_bom_ref_falls_back_to_name_and_type():
    assert component_ref({"name": "AES-256-GCM", "type": "cryptographic-asset"}) == "AES-256-GCM@cryptographic-asset"


def test_diff_snapshots_flags_metadata_drift_and_identical_documents():
    baseline = {"components": [_comp("ev-1")], "metadata": {"component": {"name": "app", "version": "1.0"}}}
    target_same = {"components": [_comp("ev-1")], "metadata": {"component": {"name": "app", "version": "1.0"}}}
    assert diff_snapshots(baseline, target_same)["identical"] is True

    target_drift = {
        "components": [_comp("ev-1")],
        "metadata": {"component": {"name": "app", "version": "2.0"}},
    }
    result = diff_snapshots(baseline, target_drift)
    assert result["identical"] is False
    assert result["metadata_changes"] == [
        {"path": "component.version", "before": "1.0", "after": "2.0"}]
    assert result["summary"] == {
        "baseline_components": 1, "target_components": 1,
        "added": 0, "removed": 0, "changed": 0, "unchanged": 1}


def _spine_comp(ref: str, asset_key: str, name: str = "AES-256-GCM",
                compliance: str = "PASS", confidence: str = "HIGH"):
    return {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": ref,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "symmetric", "algorithm": "AES", "mode": "GCM",
                "padding": None, "parameterSetIdentifier": "256",
            },
        },
        "evidence": {"compliance_status": compliance,
                     "file": "src/A.java", "line": 10,
                     "content_hash": "c" * 64, "chain_hash": "h" * 64,
                     "occurrences": [{"location": "src/A.java", "line": 10}],
                     "identity": [{"field": "bom-ref", "confidence": 1,
                                   "methods": [{"technique": "source-code-analysis",
                                                "confidence": 0.9,
                                                "value": "src/A.java:10"}]}]},
        "properties": [
            {"name": "cryptoscan:asset_key", "value": asset_key},
            {"name": "cryptoscan:confidence", "value": confidence},
        ],
    }


def test_spine_keying_joins_the_same_asset_across_scans():
    """Cross-scan semantics: a re-scan mints NEW evidence rows (new
    bom-ref, new hashes/positions) for unchanged crypto BY DESIGN. Under
    bom-ref keying that is 100% churn; under asset_key keying the same
    crypto fact is ONE unchanged identity."""
    scan_a = [_spine_comp("ev-run1-1", "fact:v1:aaa")]
    scan_b = [_spine_comp("ev-run2-9", "fact:v1:aaa", confidence="MEDIUM")]
    churned = diff_components(scan_a, scan_b, key_by="bom_ref")
    assert len(churned["added"]) == 1 and len(churned["removed"]) == 1
    assert churned["unchanged"] == 0

    stable = diff_components(scan_a, scan_b, key_by="asset_key")
    assert stable["added"] == [] and stable["removed"] == []
    assert stable["unchanged"] == 0, "the confidence change IS drift"
    # only asset-stable drift shows: confidence changed, evidence churn does not
    assert stable["changed"] == [{
        "key": "spine:fact:v1:aaa", "bom-ref": "ev-run1-1",
        "changes": [{"path": "properties.cryptoscan:confidence",
                     "before": "HIGH", "after": "MEDIUM"}]}]
    # and with confidence identical too, the same fact is fully unchanged
    same = diff_components(scan_a, [_spine_comp("ev-run2-9", "fact:v1:aaa")], key_by="asset_key")
    assert same["unchanged"] == 1 and same["changed"] == []


def test_spine_keying_reports_estate_drift_not_evidence_churn():
    """The two-scan operator question: 3DES retired, one AES added, the
    rest unchanged — regardless of evidence-row turnover."""
    scan_a = [_spine_comp("ev-1", "fact:v1:keep"), _spine_comp("ev-2", "fact:v1:3des", name="3DES")]
    scan_b = [_spine_comp("ev-3", "fact:v1:keep"), _spine_comp("ev-4", "fact:v1:newaes")]
    diff = diff_components(scan_a, scan_b, key_by="asset_key")
    assert [c["name"] for c in diff["removed"]] == ["3DES"]
    assert [c["name"] for c in diff["added"]] == ["AES-256-GCM"]
    assert diff["unchanged"] == 1


def test_spine_keying_still_sees_real_compliance_drift():
    """The policy verdict is asset-stable drift: PASS→FAIL across scans
    must survive the observation-field exclusions."""
    scan_a = [_spine_comp("ev-1", "fact:v1:aaa", compliance="PASS")]
    scan_b = [_spine_comp("ev-2", "fact:v1:aaa", compliance="FAIL")]
    diff = diff_components(scan_a, scan_b, key_by="asset_key")
    assert diff["changed"][0]["changes"] == [
        {"path": "evidence.compliance_status", "before": "PASS", "after": "FAIL"}]


def test_spine_keying_falls_back_to_ref_namespaced():
    """Pre-spine components must not collide with spine-keyed ones."""
    legacy = [{"type": "cryptographic-asset", "name": "AES-256-GCM", "bom-ref": "fact:v1:aaa"}]
    keyed = [_spine_comp("ev-1", "fact:v1:aaa")]
    diff = diff_components(legacy, keyed, key_by="asset_key")
    assert len(diff["added"]) == 1 and len(diff["removed"]) == 1


def test_invalid_key_by_is_refused():
    import pytest as _pytest
    with _pytest.raises(ValueError):
        diff_components([], [], key_by="nonsense")
