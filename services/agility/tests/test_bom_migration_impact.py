"""The twin through its six BOMs, with a migration and the system connections laid over it.

Runs on the same Meridian-shaped estate as the migration-twin tests: SWIFT Gateway
(RSA-3072 certificate, OpenSSL 3.3.2 without ML-KEM, an Alpine OS with no contract),
Core Banking (a ledger database the gateway reaches by IP), Payment HSM (3DES and AES key
slots, capability unknown) and Branch Banking (TLS 1.0, RSA-1024).
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from agility.bom_migration_impact import BOM_ORDER, simulate_bom_impact
from agility.estate_migration_twin import twin_from_estate

# the Meridian fixture lives beside this file; pytest runs in importlib mode, so load it by path
_spec = importlib.util.spec_from_file_location(
    "_meridian_twin_fixture", Path(__file__).with_name("test_estate_migration_twin.py"))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
NOW, _meridian = _fixture.NOW, _fixture._meridian

_SBOM = {"PACKAGE", "LIBRARY", "IMAGE"}
_HBOM = {"HARDWARE", "FIRMWARE", "HOST"}
_NBOM = {"NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY", "DATABASE", "MESSAGE_BROKER", "CLOUD_RESOURCE"}
_TECH = {"SYSTEM", "APPLICATION", "SERVICE", "CONTAINER", "POD", "NAMESPACE", "CLUSTER", "HOST",
         "DATABASE", "HSM", "KMS_KEY", "VENDOR", "HARDWARE"}


def _bom_set(e) -> dict:
    """The shape ``EstateGraph.project_all()`` returns, built from the fixture."""
    by_id = {a["asset_id"]: a for a in e.assets}

    def comps(types):
        return [dict(a) for a in e.assets if a["type"] in types]

    artifacts = []
    for row in e.evidence:
        facts, asset = row["facts"], by_id[row["target"]]
        base = {"type": "CRYPTO_ARTIFACT", "asset_id": asset["asset_id"], "asset_name": asset["name"],
                "asset_type": asset["type"], "layer": "NETWORK_TRANSPORT", "protocol": facts.get("protocol")}
        if facts.get("algorithm"):
            artifacts.append({**base, "artifact_id": f"a-{row['evidence_id']}", "algorithm": facts["algorithm"],
                              "role": facts.get("role"), "key_size": facts.get("key_size"),
                              "usage_state": "NEGOTIATED" if "NETWORK" in row["evidence_type"] else "OBSERVED"})
        for alg in facts.get("supported_algorithms") or []:
            artifacts.append({**base, "artifact_id": f"s-{row['evidence_id']}-{alg}", "algorithm": alg,
                              "role": "capability", "key_size": None, "usage_state": "SUPPORTED"})
        for slot in facts.get("key_slots") or []:
            artifacts.append({**base, "artifact_id": f"k-{row['evidence_id']}-{slot['slot']}",
                              "algorithm": slot["algorithm"], "role": "key", "key_size": None,
                              "layer": "HARDWARE", "usage_state": "OBSERVED"})
    return {"projection_id": "p-1", "boms": {
        "SBOM": {"question": "What software exists?", "components": comps(_SBOM)},
        "CBOM": {"question": "What crypto exists?", "components": artifacts + comps({"CERTIFICATE", "CA"})},
        "HBOM": {"question": "What hardware exists?", "components": comps(_HBOM)},
        "NBOM": {"question": "What is on the network?", "components": comps(_NBOM)},
        "VBOM": {"question": "Which vendors?", "components": comps({"VENDOR"}),
                 "declared_capabilities": [{"vendor_asset_id": "v-openssl", "pqc_ready": False}],
                 "contracts": []},
        "TECHBOM": {"question": "How is it connected?", "components": comps(_TECH)},
    }}


def _run(**kw):
    e = _meridian()
    twin = twin_from_estate(e.assets, e.edges, e.evidence, estate="meridian-bank", now=NOW)
    return simulate_bom_impact(_bom_set(e), twin, e.edges, now=NOW, **kw)


def _bom(result, name):
    return next(b for b in result["boms"] if b["bom"] == name)


def _row(result, bom, name, kind="asset"):
    return next(r for r in _bom(result, bom)["components"] if r["name"] == name and r["kind"] == kind)


def test_inventory_lists_every_bom_with_the_systems_each_component_belongs_to():
    result = _run()
    assert [b["bom"] for b in result["boms"]] == list(BOM_ORDER)
    assert result["change"] is None and result["totals"]["affected"] is None
    # every component carries its business systems through evidenced edges only
    assert _row(result, "SBOM", "OpenSSL 3.3.2")["systems"] == ["SWIFT Gateway"]
    assert _row(result, "HBOM", "VMware7,1 virtual platform")["systems"] == ["SWIFT Gateway"]
    assert _row(result, "CBOM", "Meridian Bank Issuing CA")["systems"] == ["SWIFT Gateway"]
    assert "SWIFT Gateway" in _row(result, "VBOM", "OpenSSL Software Foundation · OpenSSL")["systems"]
    # a certificate no system claims stays unowned, never assigned by resemblance
    assert _row(result, "CBOM", "old-vpn.example")["systems"] == []
    assert all(r["status"] is None for b in result["boms"] for r in b["components"])
    swift = next(s for s in result["systems"] if s["name"] == "SWIFT Gateway")
    assert swift["calls"] == ["Core Banking", "Payment HSM"]
    assert swift["bom_counts"]["SBOM"]["components"] >= 2
    assert result["mutates_nothing"] is True


def test_rsa_to_mlkem_marks_each_bom_layer_with_cause_and_action():
    result = _run(from_algo="RSA", to_algo="ML-KEM-768")
    assert result["strategy"]["recommended"] == "PARALLEL"
    cert = _row(result, "CBOM", "swift-gateway.bank.sandbox")
    assert cert["status"] == "AFFECTED" and "RSA" in cert["impact"] and "reissue" in cert["action"]
    assert _row(result, "CBOM", "Meridian Bank Issuing CA")["status"] == "AFFECTED"
    # capability-only RSA in the library is AT_RISK (switch off later), never AFFECTED
    capability = next(r for r in _bom(result, "CBOM")["components"]
                      if r["kind"] == "crypto" and r["name"] == "OpenSSL 3.3.2" and r["detail"].startswith("RSA"))
    assert capability["status"] == "AT_RISK"
    assert _row(result, "SBOM", "OpenSSL 3.3.2")["status"] == "AFFECTED"
    # presence only: an installed package is not use
    assert _row(result, "SBOM", "libssl3")["status"] == "NOT_AFFECTED"
    # TLS 1.0 cannot carry ML-KEM; the endpoint is affected and its clients are unseen
    legacy = _row(result, "NBOM", "legacy-branch:443")
    assert legacy["status"] == "AFFECTED" and "TLS 1.3" in legacy["impact"]
    nbom_codes = {i["code"] for i in _bom(result, "NBOM")["issues"]}
    assert {"TLS_VERSION_TOO_OLD", "ENDPOINT_CLIENTS_UNSEEN"} <= nbom_codes
    # the platform server is never a blocker
    assert _row(result, "HBOM", "VMware7,1 virtual platform")["status"] == "NOT_AFFECTED"
    vendor = _row(result, "VBOM", "OpenSSL Software Foundation · OpenSSL")
    assert vendor["status"] == "AFFECTED" and "declared" in vendor["impact"]
    assert {i["code"] for i in _bom(result, "SBOM")["issues"]} >= {"LIBRARY_LACKS_TARGET"}
    assert {i["code"] for i in _bom(result, "VBOM")["issues"]} >= {"VENDOR_RELEASE_NOT_READY"}
    assert _row(result, "TECHBOM", "SWIFT Gateway")["status"] == "AFFECTED"
    # every issue states its cause, its effect and the action
    for bom in result["boms"]:
        for issue in bom["issues"]:
            assert issue["cause"] and issue["action"], issue
    assert result["totals"]["affected"]["CBOM"] >= 3


def test_connections_say_which_side_changes_and_what_happens_to_the_other():
    result = _run(from_algo="RSA", to_algo="ML-KEM-768")
    by_pair = {(c["caller"], c["provider"]): c for c in result["connections"]}
    swift_core = by_pair[("SWIFT Gateway", "Core Banking")]
    assert swift_core["status"] == "CALLER_CHANGES" and swift_core["severity"] == "HIGH"
    assert "Core Banking" in swift_core["effect_on_provider"]
    assert "keep RSA" in swift_core["action"]
    assert any(i["code"] == "PEER_OUTSIDE_CHANGE" for i in swift_core["issues"])
    assert by_pair[("Branch Banking", "Core Banking")]["status"] == "CALLER_CHANGES"
    # Core Banking does not hold RSA but is reached through the connections
    ripple = {r["name"]: r for r in result["ripple"]}
    assert ripple["Core Banking"]["hops"] == 1
    assert ripple["Core Banking"]["path"][0] in ("SWIFT Gateway", "Branch Banking")
    assert _row(result, "TECHBOM", "Core Banking")["status"] == "AT_RISK"


def test_a_provider_change_reaches_its_callers_and_shared_hsm_is_named():
    result = _run(from_algo="3DES", to_algo="AES-256")
    by_pair = {(c["caller"], c["provider"]): c for c in result["connections"]}
    swift_hsm = by_pair[("SWIFT Gateway", "Payment HSM")]
    assert swift_hsm["status"] == "PROVIDER_CHANGES"
    assert "SWIFT Gateway must accept" in swift_hsm["effect_on_caller"]
    hsm = _row(result, "TECHBOM", "payShield-10K-sim")
    assert hsm["status"] == "UNKNOWN" and "unknown" in hsm["impact"]
    assert any(i["code"] == "HARDWARE_CAPABILITY_UNKNOWN" for i in _bom(result, "HBOM")["issues"])


def test_scope_and_validation():
    scoped = _run(from_algo="RSA", to_algo="ML-KEM-768", systems=["Branch Banking"])
    assert scoped["totals"]["systems_in_change"] == 1
    assert _row(scoped, "TECHBOM", "SWIFT Gateway")["status"] != "AFFECTED"
    with pytest.raises(ValueError):
        _run(from_algo="RSA")


def test_pure_and_deterministic():
    e = _meridian()
    twin = twin_from_estate(e.assets, e.edges, e.evidence, estate="meridian-bank", now=NOW)
    boms = _bom_set(e)
    before = copy.deepcopy((boms, twin, e.edges))
    first = simulate_bom_impact(boms, twin, e.edges, from_algo="RSA", to_algo="ML-DSA-65", now=NOW)
    second = simulate_bom_impact(boms, twin, e.edges, from_algo="RSA", to_algo="ML-DSA-65", now=NOW)
    assert first == second
    assert (boms, twin, e.edges) == before
