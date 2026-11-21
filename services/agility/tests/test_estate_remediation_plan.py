"""Remediation from the Digital Twin, on the Meridian-shaped estate.

What must hold:

* every finding comes from observed evidence and names the action, who acts and the
  observation that closes it;
* the RSA-1024 certificate is the most urgent item; an asset with a short key does not also
  get a "quantum-vulnerable" duplicate;
* the order is providers first: the Payment HSM moves before the SWIFT Gateway that calls it.
  Core Banking holds no weak crypto in the fixture, so it gets no wave;
* the issues of a simulated change become task candidates with stable ids, and INFO is not
  work;
* verification never treats silence as a fix.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from agility.estate_remediation_plan import (
    estate_findings,
    migration_task_candidates,
    migration_waves,
    verify_candidate,
)

_SPEC = importlib.util.spec_from_file_location(
    "_twin_fixture", Path(__file__).with_name("test_estate_migration_twin.py"))
_FIX = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_FIX)  # type: ignore[union-attr]
_BOM_SPEC = importlib.util.spec_from_file_location(
    "_bom_fixture", Path(__file__).with_name("test_bom_migration_impact.py"))
_BOM = importlib.util.module_from_spec(_BOM_SPEC)
_BOM_SPEC.loader.exec_module(_BOM)  # type: ignore[union-attr]


def _findings():
    return estate_findings(_FIX._twin(), now=_FIX.NOW)


def test_findings_are_ranked_and_evidenced():
    out = _findings()
    assert out["mutates_nothing"] is True and out["total"] == len(out["findings"])
    first = out["findings"][0]
    assert first["code"] == "WEAK_KEY" and first["severity"] == "CRITICAL"
    assert first["systems"] == ["Branch Banking"] and "RSA-1024" in first["title"]
    codes = {f["code"] for f in out["findings"]}
    assert {"TLS_PROTOCOL_OLD", "DEPRECATED_ALGORITHM", "LIBRARY_NO_PQC", "HSM_NOT_FIPS_MODE",
            "VENDOR_NOT_PQC_READY", "QUANTUM_VULNERABLE", "CERT_EXPIRING"} <= codes
    for f in out["findings"]:
        assert f["action"] and f["who_acts"] and f["verify_by"] and f["basis"]
    scores = [f["score"] for f in out["findings"]]
    assert scores == sorted(scores, reverse=True)
    # the short key covers the migration: no separate quantum finding on the same certificate
    legacy = [f for f in out["findings"] if f["asset_id"] == "cert-legacy"]
    assert [f["code"] for f in legacy] == ["WEAK_KEY"]
    # RSA and SHA256withRSA on one certificate are a single finding
    gw = [f for f in out["findings"] if f["asset_id"] == "cert-gw" and f["code"] == "QUANTUM_VULNERABLE"]
    assert len(gw) == 1 and "SHA256withRSA" in gw[0]["algorithm"]
    # the 3DES key slot of the payment HSM, filed under the hardware BOM
    hsm = next(f for f in out["findings"] if f["code"] == "DEPRECATED_ALGORITHM")
    assert hsm["bom"] == "HBOM" and hsm["replace_with"] == "AES-256-GCM"
    # a vendor's readiness is declared, never observed
    vendor = next(f for f in out["findings"] if f["code"] == "VENDOR_NOT_PQC_READY")
    assert vendor["basis"] == "VENDOR_DECLARATION" and "declared" in vendor["cause"]
    # what the twin cannot see is said, not skipped
    assert any("payShield" in u for u in out["unknowns"])


def test_findings_are_deterministic():
    a, b = _findings(), _findings()
    assert [f["id"] for f in a["findings"]] == [f["id"] for f in b["findings"]]


def test_waves_put_providers_first():
    twin = _FIX._twin()
    out = migration_waves(twin, estate_findings(twin, now=_FIX.NOW))
    placed = {s["name"]: w["wave"] for w in out["waves"] for s in w["systems"]}
    assert placed["Payment HSM"] < placed["SWIFT Gateway"]
    assert "Core Banking" not in placed
    assert [r["name"] for r in out["no_migration_needed"]] == ["Core Banking"]
    swift = next(s for w in out["waves"] for s in w["systems"] if s["name"] == "SWIFT Gateway")
    assert "Payment HSM" in swift["rationale"] and swift["depends_on"] == ["Core Banking", "Payment HSM"]
    assert {m["algorithm"] for m in swift["moves"]} == {"RSA", "SHA256withRSA"}
    rsa = next(w for w in out["workstreams"] if w["family"] == "RSA")
    assert rsa["simulate"] == {"from_algo": "RSA", "to_algo": "ML-KEM-768"}
    assert out["workstreams"][0]["class"] == "deprecated"  # 3DES before the quantum work
    assert out["totals"]["to_migrate"] == 3


def test_migration_issues_become_task_candidates():
    impact = _BOM._run(from_algo="RSA", to_algo="ML-KEM-768")
    out = migration_task_candidates(impact)
    assert out["change"] == {"from_algo": "RSA", "to_algo": "ML-KEM-768"}
    assert out["total"] == len(out["candidates"]) > 0
    assert all(c["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") for c in out["candidates"])
    codes = {c["code"] for c in out["candidates"]}
    assert "LIBRARY_LACKS_TARGET" in codes and "TLS_VERSION_TOO_OLD" in codes
    again = migration_task_candidates(impact)
    assert [c["id"] for c in out["candidates"]] == [c["id"] for c in again["candidates"]]


def test_verification_never_reads_silence_as_a_fix():
    assert verify_candidate("rf-1", ["rf-1"], asset_id="a", observed_assets=["a"])["result"] == "FAILED"
    assert verify_candidate("rf-1", [], asset_id="a", observed_assets=["a"])["result"] == "VERIFIED"
    assert verify_candidate("rf-1", [], asset_id="a", observed_assets=["b"])["result"] == "INCONCLUSIVE"
    assert verify_candidate("rf-1", [], asset_id=None, observed_assets=None, system_ids=["s1"],
                            observed_systems=["s2"])["result"] == "INCONCLUSIVE"
    assert verify_candidate("rf-1", [], asset_id=None, observed_assets=None, system_ids=["s1"],
                            observed_systems=["s1"])["result"] == "VERIFIED"
