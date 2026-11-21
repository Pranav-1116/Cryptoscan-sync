"""Migration simulation: a crypto change read against the whole Digital Twin.

Pins the five answers — what is there, can it run the target, what can go
wrong, parallel or direct, and how — and the honesty rules behind them:
unknown capability is never a pass, a direct cut-over is only recommended when
nothing in the twin needs the old algorithm to stay alive, and the function
reads the snapshot without changing it.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from agility.migration_simulation import algorithm_profile, simulate_migration
from agility.twin_scenarios import run_scenario

NOW = datetime(2026, 11, 16, 9, 0, 0, tzinfo=timezone.utc)


def _estate() -> dict:
    """Payments calls Core; both use RSA. Core's keys live on an HSM whose
    capability list has no ML-KEM; Payments is served by a vendor whose recorded
    products only do RSA; Core talks to a Ledger that is not part of the change."""
    return {
        "systems": [
            {"id": "s-core", "name": "Core Banking", "criticality": "critical"},
            {"id": "s-pay", "name": "Payments", "criticality": "high"},
            {"id": "s-ledger", "name": "Ledger", "criticality": "medium"},
        ],
        "assets": [
            {"asset_id": "a-core", "system_ids": ["s-core"],
             "algorithms": {"RSA-2048": 4}, "libraries": {"openssl": "1.1.1"},
             "usage": {"key_exchange": "tls"}},
            {"asset_id": "a-pay", "system_ids": ["s-pay"],
             "algorithms": {"RSA-3072": 2}, "libraries": {"bouncycastle": "1.70"}},
            {"asset_id": "a-ledger", "system_ids": ["s-ledger"],
             "algorithms": {"AES-256-GCM": 1}},
        ],
        "hardware": [
            {"asset_id": "hsm-1", "device_type": "hsm", "manufacturer": "Thales",
             "model": "Luna 7", "firmware": {"version": "7.4"},
             "hsm": {"pqc_capability": "NOT_SUPPORTED"},
             "crypto_capabilities": {"algorithms": ["RSA", "ECDSA", "AES"]}},
        ],
        "crypto_hardware": {"hsm-1": ["a-core"]},
        "vendors": [{"id": "v-acme", "name": "Acme Switch", "criticality": "critical"}],
        "system_vendors": [{"system_id": "s-pay", "vendor_id": "v-acme",
                            "dependency_type": "payment_switch"}],
        "vendor_crypto": {"v-acme": [{"algorithm": "RSA-2048", "key_size": 2048,
                                      "pqc_ready": False, "crypto_use_case": "tls"}]},
        "dependencies": [
            {"source": "s-pay", "target": "s-core", "type": "calls"},
            {"source": "s-core", "target": "s-ledger", "type": "writes"},
        ],
        "network_endpoints": [
            {"host": "pay.bank", "port": 443, "protocol": "tls", "version": "TLSv1.2",
             "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "observed": True,
             "system_id": "s-pay"},
        ],
        "certificates": [
            {"fingerprint_sha256": "f" * 64, "subject": "CN=pay.bank", "issuer": "Bank CA",
             "public_key_algorithm": "RSA", "days_until_expiry": 40},
        ],
        "certificate_usages": {"f" * 64: ["s-pay"]},
        "library_catalog": {"openssl": {"algorithms": ["RSA", "AES", "ECDSA"], "deprecated": True},
                            "bouncycastle": None},
        "evidence": [
            {"id": "e1", "system_id": "s-core", "algorithm": "RSA-2048", "key_size": 2048,
             "is_hardcoded_key": True, "file_path": "src/Keys.java"},
        ],
        "business_processes": {"s-pay": [{"name": "Card payments", "role": "primary"}]},
    }


def _system(result: dict, name: str) -> dict:
    return next(s for s in result["systems"] if s["name"] == name)


def _codes(items: list[dict]) -> set[str]:
    return {item["code"] for item in items}


def test_reads_hardware_software_connections_and_vendors_from_the_twin():
    result = simulate_migration(_estate(), from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    assert {s["name"] for s in result["systems"]} == {"Core Banking", "Payments"}
    core = _system(result, "Core Banking")["twin"]
    assert [h["asset_id"] for h in core["hardware"]] == ["hsm-1"]
    assert core["hardware"][0]["target_support"] == "NOT_SUPPORTED"
    assert core["hardware"][0]["holds_affected_keys"] is True
    assert [lib["name"] for lib in core["software"]["libraries"]] == ["openssl"]
    assert core["software"]["libraries"][0]["target_support"] == "NOT_SUPPORTED"
    assert {(c["name"], c["direction"]) for c in core["connections"]} == {
        ("Payments", "CALLED_BY"), ("Ledger", "CALLS")}
    pay = _system(result, "Payments")["twin"]
    assert pay["vendors"][0]["name"] == "Acme Switch"
    assert pay["vendors"][0]["readiness"] == "NOT_READY"
    assert pay["network_endpoints"][0]["negotiates_source"] is True
    assert pay["certificates"][0]["fingerprint_sha256"] == "f" * 64
    assert pay["business_processes"][0]["name"] == "Card payments"
    # an unknown library is UNKNOWN, never assumed to implement the target
    assert pay["software"]["libraries"][0]["target_support"] == "UNKNOWN"
    ctx = result["twin_context"]
    assert (ctx["hardware"], ctx["vendors"], ctx["connected_systems"]) == (1, 1, 3)


def test_hardware_and_vendor_that_cannot_run_the_target_block_the_migration():
    result = simulate_migration(_estate(), from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    assert result["strategy"]["recommended"] == "BLOCKED"
    assert _system(result, "Core Banking")["strategy"] == "BLOCKED"
    assert _codes(_system(result, "Core Banking")["blocked_by"]) == {"HARDWARE_CANNOT_RUN_TARGET"}
    assert _codes(_system(result, "Payments")["blocked_by"]) == {"VENDOR_NOT_READY"}
    problems = _codes(result["problems"])
    assert {"HARDWARE_CANNOT_RUN_TARGET", "VENDOR_NOT_READY", "LIBRARY_LACKS_TARGET",
            "LIBRARY_DEPRECATED", "HARDCODED_KEYS", "TLS_VERSION_TOO_OLD",
            "CERTIFICATES_TO_REISSUE", "PEER_OUTSIDE_CHANGE", "HANDSHAKE_SIZE"} <= problems
    assert result["problems"][0]["severity"] == "BLOCKER"
    for problem in result["problems"]:
        assert problem["mitigation"] and problem["if_ignored"] and problem["basis"]


def test_impact_on_vendors_and_connected_systems():
    result = simulate_migration(_estate(), from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    vendor = result["vendor_impact"][0]
    assert vendor["name"] == "Acme Switch" and vendor["systems"] == ["Payments"]
    assert vendor["readiness"] == "NOT_READY" and "ML-KEM-768" in vendor["needs_to"]
    connected = {c["name"]: c for c in result["connected_impact"]}
    assert connected["Ledger"]["in_change"] is False
    assert "RSA" in connected["Ledger"]["action"]
    assert connected["Payments"]["in_change"] is True


def test_plan_moves_providers_before_their_callers():
    result = simulate_migration(_estate(), from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    order = {row["system"]: row["wave"] for row in result["dependency_order"]}
    assert order["Core Banking"] < order["Payments"]  # Payments calls Core
    phases = [step["phase"] for step in result["plan"]]
    assert phases[0] == "PREREQUISITES" and phases[-1] == "DECOMMISSION"
    assert "ENABLE_ALONGSIDE" in phases and "CUT_OVER" in phases
    assert [step["order"] for step in result["plan"]] == list(range(1, len(phases) + 1))
    for step in result["plan"]:
        assert step["rollback"] and step["exit_criteria"]


def _isolated(capabilities: list[str] | None) -> dict:
    hardware = {"asset_id": "hsm-9", "device_type": "hsm"}
    if capabilities is not None:
        hardware["crypto_capabilities"] = {"algorithms": capabilities}
    return {
        "systems": [{"id": "s-batch", "name": "Batch", "criticality": "low"}],
        "assets": [{"asset_id": "a-batch", "system_ids": ["s-batch"],
                    "algorithms": {"ECDH-P256": 1}}],
        "hardware": [hardware],
        "crypto_hardware": {"hsm-9": ["a-batch"]},
    }


def test_direct_migration_only_when_nothing_needs_the_old_algorithm():
    result = simulate_migration(_isolated(["ECDH", "ML-KEM-768"]), from_algo="ECDH",
                                to_algo="ML-KEM-768", now=NOW)
    assert result["strategy"]["recommended"] == "DIRECT"
    assert _system(result, "Batch")["parallel_because"] == []
    assert "ENABLE_ALONGSIDE" not in [step["phase"] for step in result["plan"]]
    assert result["strategy"]["parallel_mechanisms"] == []
    # direct still names what the twin cannot see
    assert result["unknowns"]


def test_unknown_hardware_capability_is_never_a_pass():
    result = simulate_migration(_isolated(None), from_algo="ECDH", to_algo="ML-KEM-768", now=NOW)
    batch = _system(result, "Batch")
    assert batch["twin"]["hardware"][0]["target_support"] == "UNKNOWN"
    assert batch["strategy"] == "PARALLEL"
    assert "HARDWARE_CAPABILITY_UNKNOWN" in _codes(batch["parallel_because"])


def test_a_flag_that_is_not_an_algorithm_is_not_a_capability_list():
    estate = _isolated(None)
    estate["hardware"][0]["hsm"] = {"fips": True, "clustered": True}
    estate["hardware"][0]["crypto_capabilities"] = {"tamper_evident": True}
    result = simulate_migration(estate, from_algo="ECDH", to_algo="ML-KEM-768", now=NOW)
    assert _system(result, "Batch")["twin"]["hardware"][0]["target_support"] == "UNKNOWN"


def test_declared_pqc_capability_is_read_from_the_hsm():
    estate = _isolated(None)
    estate["hardware"][0]["hsm"] = {"pqc_capability": "PQC_READY"}
    result = simulate_migration(estate, from_algo="ECDH", to_algo="ML-KEM-768", now=NOW)
    assert _system(result, "Batch")["twin"]["hardware"][0]["target_support"] == "SUPPORTED_DECLARED"
    assert result["strategy"]["recommended"] == "DIRECT"


def test_ready_vendor_still_moves_in_parallel():
    estate = _isolated(["ML-KEM-768"])
    estate["vendors"] = [{"id": "v1", "name": "Ready Co"}]
    estate["system_vendors"] = [{"system_id": "s-batch", "vendor_id": "v1"}]
    estate["vendor_crypto"] = {"v1": [{"algorithm": "ML-KEM-768", "pqc_ready": True}]}
    result = simulate_migration(estate, from_algo="ECDH", to_algo="ML-KEM-768", now=NOW)
    assert result["vendor_impact"][0]["readiness"] == "READY"
    assert result["strategy"]["recommended"] == "PARALLEL"
    assert "VENDOR_NOT_READY" not in _codes(result["problems"])


def test_stored_data_under_a_symmetric_algorithm_needs_a_dual_key_period():
    estate = {"systems": [{"id": "s1", "name": "Archive"}],
              "assets": [{"asset_id": "a1", "system_ids": ["s1"], "algorithms": {"3DES": 1}}]}
    result = simulate_migration(estate, from_algo="3DES", to_algo="AES-256-GCM", now=NOW)
    assert "STORED_DATA" in _codes(result["problems"])
    assert result["strategy"]["recommended"] == "PARALLEL"
    assert "DUAL_KEY_PERIOD" in {m["mechanism"] for m in result["strategy"]["parallel_mechanisms"]}


def test_a_target_that_cannot_do_the_job_is_a_blocker():
    estate = {"systems": [{"id": "s1", "name": "Signer"}],
              "assets": [{"asset_id": "a1", "system_ids": ["s1"], "algorithms": {"ECDSA-P256": 1}}]}
    result = simulate_migration(estate, from_algo="ECDSA", to_algo="ML-KEM-768", now=NOW)
    assert result["strategy"]["recommended"] == "BLOCKED"
    mismatch = next(p for p in result["problems"] if p["code"] == "TARGET_ROLE_MISMATCH")
    assert "ML-DSA" in mismatch["mitigation"]


def test_nothing_matched_is_not_determined_not_no_impact():
    result = simulate_migration(_estate(), from_algo="Blowfish", to_algo="AES", now=NOW)
    assert result["strategy"]["recommended"] == "NOT_DETERMINED"
    assert result["systems"] == [] and result["plan"] == []
    assert "not 'no impact'" in result["headline"]


def test_scope_narrows_to_named_systems_and_reports_unknown_names():
    result = simulate_migration(_estate(), from_algo="RSA", to_algo="ML-KEM-768",
                                systems="Payments, nope", now=NOW)
    assert [s["name"] for s in result["systems"]] == ["Payments"]
    assert any("nope" in u for u in result["unknowns"])
    # Core is connected to Payments but outside the requested scope
    assert "PEER_OUTSIDE_CHANGE" in _codes(_system(result, "Payments")["parallel_because"])


def test_pure_and_deterministic():
    snapshot = _estate()
    before = copy.deepcopy(snapshot)
    first = simulate_migration(snapshot, from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    second = simulate_migration(snapshot, from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    assert first == second and snapshot == before
    assert first["mutates_nothing"] is True and first["deterministic"] is True


def test_missing_algorithms_raise():
    with pytest.raises(ValueError):
        simulate_migration(_estate(), from_algo="RSA", to_algo="", now=NOW)


def test_algorithm_profiles():
    assert algorithm_profile("RSA-2048")["roles"] == ["key_establishment", "signature"]
    assert algorithm_profile("ML-KEM-768")["roles"] == ["key_establishment"]
    assert algorithm_profile("ML-DSA-65")["roles"] == ["signature"]
    assert algorithm_profile("X25519MLKEM768")["family"] == "PQC_HYBRID"
    assert algorithm_profile("AES-256-GCM")["family"] == "SYMMETRIC"
    assert algorithm_profile("SHA-256")["family"] == "HASH"
    assert algorithm_profile("mystery")["family"] == "UNKNOWN"


def test_algorithm_migration_scenario_carries_the_migration_answer():
    result = run_scenario("algorithm_migration", _estate(), now=NOW,
                          params={"from_algo": "RSA", "to_algo": "ML-KEM-768",
                                  "systems": "Core Banking"})
    assert result["affected"]["assets"] == ["a-core", "a-pay"]  # existing keys intact
    assert result["inputs"]["systems"] == "Core Banking"
    assert result["migration"]["schema"] == "cryptoscan.migration-simulation/1"
    assert [s["name"] for s in result["migration"]["systems"]] == ["Core Banking"]
