"""Estate-HBOM snapshot diff (§4.4, round 72).

Two pinned estate documents compared deterministically: devices added /
removed, field-level drift on survivors (firmware, TPM/HSM posture,
risk, identity fingerprints), observation churn separated from estate
drift by NAMED exclusions, self-diff identical, cross-format refusal.
"""

from __future__ import annotations

import pytest

from cbom.hbom import generate_hbom
from cbom.hbom_diff import (
    HBOM_METADATA_EXCLUDED_PATHS,
    HBOM_OBSERVATION_EXCLUDED_PATHS,
    diff_hbom_documents,
)

ROW_HSM = {
    "asset_id": "hw-hsm-1", "agent_id": "agent-dc-1",
    "manufacturer": "Utimaco", "model": "CryptoServer", "device_type": "hsm",
    "serial_reference": "SER-0001", "hardware_revision": "C",
    "current_fingerprint": "f" * 64, "previous_fingerprint": "e" * 64,
    "first_seen": "2026-10-01T08:00:00+00:00",
    "last_seen": "2026-10-10T09:30:00+00:00",
    "last_verified": "2026-10-10T09:31:00+00:00",
    "firmware": {"version": "4.21.2"}, "tpm": None, "hsm": {"fips_mode": True},
    "capabilities": {"rng": True}, "crypto_capabilities": {"rsa": [2048, 4096]},
    "evidence_history": ["ev-h1", "ev-h2"], "risk_score": 40, "risk_level": "MEDIUM",
}
ROW_TPM = {
    "asset_id": "hw-tpm-1", "agent_id": "agent-branch-7",
    "manufacturer": "Infineon", "model": "SLB9665", "device_type": "tpm",
    "current_fingerprint": "a" * 64,
    "first_seen": "2026-10-02T10:00:00+00:00",
    "last_seen": "2026-10-12T11:00:00+00:00",
    "firmware": None, "tpm": {"spec": "2.0"}, "hsm": None,
    "evidence_history": ["ev-t1"], "risk_score": 10, "risk_level": "LOW",
}
ROW_NEW = {
    "asset_id": "hw-se-1", "agent_id": "agent-dc-1",
    "manufacturer": "NXP", "model": "SE050", "device_type": "secure_element",
    "current_fingerprint": "c" * 64,
    "first_seen": "2026-10-14T10:00:00+00:00",
    "last_seen": "2026-10-14T10:00:00+00:00",
    "firmware": None, "tpm": None, "hsm": None,
    "evidence_history": ["ev-s1"], "risk_score": 5, "risk_level": "LOW",
}


def test_added_removed_and_field_drift_on_survivors():
    baseline = generate_hbom([ROW_HSM, ROW_TPM], environment="prod")
    # estate change: firmware bump on the HSM, TPM REMOVED, a new secure element
    changed_hsm = dict(ROW_HSM, firmware={"version": "4.22.0"}, risk_score=70,
                       risk_level="HIGH", current_fingerprint="9" * 64,
                       previous_fingerprint="f" * 64)
    target = generate_hbom([changed_hsm, ROW_NEW], environment="prod")

    result = diff_hbom_documents(baseline, target)
    assert result["key_by"] == "asset_id"
    assert result["identical"] is False
    assert result["summary"] == {
        "baseline_components": 2, "target_components": 2,
        "added": 1, "removed": 1, "changed": 1, "unchanged": 0,
    }
    (added,) = result["components"]["added"]
    assert added["key"] == "hw:hw-se-1"
    assert added["name"] == "NXP SE050"
    (removed,) = result["components"]["removed"]
    assert removed["key"] == "hw:hw-tpm-1"

    (changed,) = result["components"]["changed"]
    assert changed["key"] == "hw:hw-hsm-1"
    by_path = {c["path"]: (c["before"], c["after"]) for c in changed["changes"]}
    assert by_path["firmware.details.version"] == ("4.21.2", "4.22.0")
    assert by_path["risk.score"] == (40, 70)
    assert by_path["risk.level"] == ("MEDIUM", "HIGH")
    assert by_path["identity.current_fingerprint"] == ("f" * 64, "9" * 64)
    assert by_path["identity.previous_fingerprint"] == ("e" * 64, "f" * 64)
    # a real posture change (HSM block) is estate drift too
    dropped_hsm = generate_hbom([dict(ROW_HSM, hsm=None), ROW_TPM], environment="prod")
    posture = diff_hbom_documents(baseline, dropped_hsm)
    (hsm_change,) = posture["components"]["changed"]
    assert any(p["path"] == "security_modules.hsm.fips_mode" for p in hsm_change["changes"])


def test_observation_churn_is_not_estate_drift_in_asset_mode():
    baseline = generate_hbom([ROW_HSM, ROW_TPM], environment="prod")
    # the SAME devices, merely re-observed: later last_seen, one more
    # evidence id, later anchor — the estate itself did not change
    reobserved_hsm = dict(ROW_HSM, last_seen="2026-10-13T09:30:00+00:00",
                          last_verified="2026-10-13T09:31:00+00:00",
                          evidence_history=["ev-h1", "ev-h2", "ev-h3"])
    reobserved_tpm = dict(ROW_TPM, last_seen="2026-10-13T12:00:00+00:00",
                          evidence_history=["ev-t1", "ev-t2"])
    target = generate_hbom([reobserved_hsm, reobserved_tpm], environment="prod")

    result = diff_hbom_documents(baseline, target)
    assert result["identical"] is True
    assert result["summary"]["changed"] == 0
    assert result["summary"]["unchanged"] == 2
    # the anchor moved (it is derived from last_seen) but is excluded here
    assert target["metadata"]["as_of"] == "2026-10-13T12:00:00+00:00"
    assert "as_of" in result["excluded_paths"]
    assert set(HBOM_OBSERVATION_EXCLUDED_PATHS) <= set(result["excluded_paths"])

    # the SAME pair under bom_ref keying shows the observation churn
    exact = diff_hbom_documents(baseline, target, key_by="bom_ref")
    assert exact["identical"] is False
    assert exact["summary"]["changed"] == 2
    paths = {c["path"] for ch in exact["components"]["changed"] for c in ch["changes"]}
    assert "evidence.last_seen" in paths
    assert "evidence.evidence_ids[2]" in paths
    assert "metadata.as_of" not in paths  # metadata is a separate section


def test_self_diff_is_identical_and_deterministic():
    doc = generate_hbom([ROW_HSM, ROW_TPM], environment="prod")
    one = diff_hbom_documents(doc, doc)
    two = diff_hbom_documents(doc, doc)
    assert one["identical"] is True
    assert one == two
    assert one["summary"]["unchanged"] == 2


def test_metadata_drift_beyond_the_anchor_is_reported():
    baseline = generate_hbom([ROW_HSM], environment="prod")
    # environment is a document fact: a different environment is drift
    target = generate_hbom([ROW_HSM], environment="staging")
    result = diff_hbom_documents(baseline, target)
    assert result["identical"] is False
    paths = {c["path"] for c in result["metadata_changes"]}
    assert "environment" in paths
    assert "as_of" not in paths  # excluded in asset mode


def test_empty_to_populated_and_back():
    empty = generate_hbom([], environment="prod")
    full = generate_hbom([ROW_HSM, ROW_TPM], environment="prod")
    grown = diff_hbom_documents(empty, full)
    assert grown["summary"]["added"] == 2
    assert grown["summary"]["removed"] == 0
    shrunk = diff_hbom_documents(full, empty)
    assert shrunk["summary"]["removed"] == 2
    assert shrunk["summary"]["added"] == 0
    removed_keys = [r["key"] for r in shrunk["components"]["removed"]]
    assert removed_keys == ["hw:hw-hsm-1", "hw:hw-tpm-1"]


def test_refuses_to_diff_mismatched_formats():
    doc = generate_hbom([ROW_HSM], environment="prod")
    not_an_hbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    with pytest.raises(ValueError, match="baseline"):
        diff_hbom_documents(not_an_hbom, doc)
    with pytest.raises(ValueError, match="target"):
        diff_hbom_documents(doc, not_an_hbom)
    with pytest.raises(ValueError, match="key_by"):
        diff_hbom_documents(doc, doc, key_by="spine")


def test_exclusion_lists_are_named_and_minimal():
    # every excluded path is an observation-recording field, nothing else
    assert HBOM_OBSERVATION_EXCLUDED_PATHS == (
        "evidence.last_seen", "evidence.first_seen",
        "evidence.last_verified", "evidence.last_crypto_check",
        "evidence.evidence_ids",
    )
    assert HBOM_METADATA_EXCLUDED_PATHS == ("as_of",)
