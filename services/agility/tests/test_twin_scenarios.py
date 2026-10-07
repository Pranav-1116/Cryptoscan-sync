"""Digital-twin scenario engine: determinism, honesty, and all ten types.

The engine is a pure function of (snapshot, now, params). These tests pin:
every scenario id runs; results never mutate the snapshot; the same inputs
always produce the same output; missing data becomes an honest unknown
rather than an invented number; and bad input raises instead of guessing.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from agility.twin_scenarios import (
    SCENARIOS,
    reconcile,
    run_scenario,
    twin_fidelity,
)

NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)


def _snapshot() -> dict:
    """A small, deliberately mixed estate: fresh and stale, clean and weak."""
    return {
        "assets": [
            {
                "asset_id": "sys-core", "cbom_version": 4,
                "algorithms": {"RSA-2048": 12, "AES-256-GCM": 30},
                "quantum_status": {"status": "vulnerable"},
                "protocols": {"tls": "1.1"},
                "libraries": {"openssl": "3.0"},
                "usage": {"signing": "hsm"},
                "last_event_at": (NOW - timedelta(minutes=5)).isoformat(),
                "event_count": 12,
            },
            {
                "asset_id": "sys-pay", "cbom_version": 2,
                "algorithms": {"ML-KEM-768": 3},
                "quantum_status": {"status": "ready"},
                "protocols": {"tls": "1.3"},
                "libraries": {"liboqs": "0.10"},
                "usage": {},
                "last_event_at": (NOW - timedelta(days=3)).isoformat(),
                "event_count": 5,
            },
            {
                "asset_id": "sys-legacy", "cbom_version": 1,
                "algorithms": {},
                "quantum_status": {},
                "last_event_at": None,
                "event_count": 0,
            },
        ],
        "systems": [
            {"id": "sys-core", "name": "Core", "environment": "prod",
             "evidence": []},
            {"id": "sys-pay", "name": "Payments", "environment": "prod",
             "evidence": []},
            {"id": "sys-dark", "name": "Unregistered-but-known", "environment": "prod",
             "evidence": []},
        ],
        "certificates": [
            {"fingerprint_sha256": "a" * 64, "issuer": "Internal CA",
             "not_after": (NOW - timedelta(days=1)).isoformat(),
             "renewal_status": "NONE"},
            {"fingerprint_sha256": "b" * 64, "issuer": "Public CA",
             "not_after": (NOW + timedelta(days=30)).isoformat(),
             "renewal_status": "PLANNED"},
            {"fingerprint_sha256": "c" * 64, "issuer": "Public CA",
             "not_after": (NOW + timedelta(days=400)).isoformat(),
             "renewal_status": "DONE"},
            {"fingerprint_sha256": "d" * 64, "issuer": "Unknown",
             "not_after": None, "renewal_status": None},
        ],
        "vendors": [{"id": "v1", "name": "Thales", "criticality": "critical"}],
        "system_vendors": [{"system_id": "sys-core", "vendor_id": "v1",
                            "dependency_type": "hsm"}],
        "evidence": [
            {"id": "e1", "system_id": "sys-core", "algorithm": "RSA-2048",
             "key_size": 2048, "is_hardcoded_key": True, "file_path": "src/k.java"},
            {"id": "e2", "system_id": "sys-core", "algorithm": "MD5",
             "key_size": None, "is_hardcoded_key": False, "file_path": "src/h.py"},
            {"id": "e3", "system_id": "sys-pay", "algorithm": "ML-KEM-768",
             "key_size": None, "is_hardcoded_key": False, "file_path": "src/p.go"},
        ],
        "dependencies": [
            {"source": "sys-core", "target": "sys-pay", "type": "calls"},
            {"source": "sys-pay", "target": "sys-legacy", "type": "reads"},
        ],
        "network_endpoints": [
            {"host": "api.bank", "port": 443, "protocol": "tls", "version": "1.1"},
            {"host": "api.bank", "port": 8443, "protocol": "tls", "version": "1.3"},
        ],
    }


def test_registry_has_exactly_the_ten_documented_types():
    assert len(SCENARIOS) == 10
    assert set(SCENARIOS) == {
        "algorithm_migration", "certificate_expiry", "key_rotation",
        "hsm_outage", "vendor_compromise", "protocol_deprecation",
        "compliance_change", "attack_path", "pqc_migration", "drift_regression",
    }
    for entry in SCENARIOS.values():
        assert entry["name"] and entry["description"]
        assert callable(entry["run"]) and isinstance(entry["inputs"], dict)


def test_every_scenario_runs_and_never_mutates_the_snapshot():
    snap = _snapshot()
    frozen = copy.deepcopy(snap)
    for scenario, entry in SCENARIOS.items():
        params = {
            "algorithm_migration": {"from_algo": "RSA", "to_algo": "ML-KEM-768"},
            "certificate_expiry": {"horizon_days": 90},
            "key_rotation": {"algorithm": "RSA"},
            "hsm_outage": {},
            "vendor_compromise": {"vendor": "thales"},
            "protocol_deprecation": {"protocol": "TLS", "min_version": "1.2"},
            "compliance_change": {"min_key_bits": 3072},
            "attack_path": {"seed_asset": "sys-core"},
            "pqc_migration": {},
            "drift_regression": {"system_id": "sys-core", "actions": ["move_to_kms"]},
        }[scenario]
        result = run_scenario(scenario, snap, now=NOW, params=params)
        assert result["scenario"] == scenario
        assert result["deterministic"] is True
        assert result["mutates_nothing"] is True
        assert isinstance(result["honest_unknowns"], list) and result["honest_unknowns"]
        assert "affected" in result and "impact" in result
    assert snap == frozen, "a scenario mutated the estate snapshot"


def test_same_input_same_output_all_scenarios():
    snap = _snapshot()
    for scenario in SCENARIOS:
        params = {
            "algorithm_migration": {"from_algo": "RSA", "to_algo": "ML-KEM-768"},
            "certificate_expiry": {"horizon_days": 90},
            "key_rotation": {"algorithm": "RSA"},
            "hsm_outage": {},
            "vendor_compromise": {"vendor": "thales"},
            "protocol_deprecation": {"protocol": "TLS", "min_version": "1.2"},
            "compliance_change": {"min_key_bits": 3072},
            "attack_path": {"seed_asset": "sys-core"},
            "pqc_migration": {},
            "drift_regression": {"system_id": "sys-core", "actions": ["move_to_kms"]},
        }[scenario]
        a = run_scenario(scenario, snap, now=NOW, params=params)
        b = run_scenario(scenario, snap, now=NOW, params=params)
        assert a == b, f"{scenario} is not deterministic"


def test_algorithm_migration_finds_rsa_assets_evidence_and_certs():
    snap = _snapshot()
    snap["certificates"].append({"fingerprint_sha256": "e" * 64,
                                 "public_key_algorithm": "RSA-2048"})
    result = run_scenario("algorithm_migration", snap, now=NOW,
                          params={"from_algo": "RSA", "to_algo": "ML-KEM-768"})
    assert result["affected"]["assets"] == ["sys-core"]
    assert result["affected"]["evidence_records"] == 1
    assert result["affected"]["certificates"] == ["e" * 64]
    assert "sys-pay" in result["impact"]["target_already_in_use_by"]


def test_certificate_expiry_buckets_and_backlog():
    result = run_scenario("certificate_expiry", _snapshot(), now=NOW,
                          params={"horizon_days": 90})
    aff = result["affected"]
    assert aff["expired"] == ["a" * 64]
    assert aff["expiring_in_horizon"] == ["b" * 64]
    assert "c" * 64 not in aff["renewal_backlog_not_done"]
    assert "a" * 64 in aff["renewal_backlog_not_done"]
    assert result["impact"]["counts"]["no_expiry_date"] == 1


def test_key_rotation_flags_hardcoded_blockers():
    result = run_scenario("key_rotation", _snapshot(), now=NOW,
                          params={"algorithm": "RSA"})
    assert result["impact"]["blockers"]["hardcoded_key_count"] == 1
    assert result["affected"]["hardcoded_keys"] == ["e1"]


def test_hsm_outage_finds_usage_signals():
    result = run_scenario("hsm_outage", _snapshot(), now=NOW, params={})
    assert result["affected"]["assets"] == ["sys-core"]
    assert result["impact"]["dependency_signals"]["sys-core"]
    # No hardware fleet in the base fixture: the fleet list is honestly empty.
    assert result["affected"]["hardware_hsms"] == []
    assert result["affected"]["hardware_hsm_count"] == 0


def test_hsm_outage_lists_the_real_hardware_fleet():
    """With hardware rows from the live engine, the fleet is inventory,
    not keyword inference — and the blast-radius limit is named."""
    snap = _snapshot()
    snap["hardware"] = [
        {"asset_id": "hsm-01", "manufacturer": "Thales", "model": "Luna 7",
         "device_type": "hsm", "firmware": "7.7.0",
         "hsm": {"pqc_capability": "HYBRID_SUPPORTED"}, "last_seen": NOW.isoformat()},
        {"asset_id": "hsm-02", "manufacturer": "Utimaco", "model": "Se Gen2",
         "device_type": "hsm", "firmware": "4.5",
         "hsm": {"pqc_capability": "NOT_READY"}, "last_seen": NOW.isoformat()},
        {"asset_id": "srv-01", "manufacturer": "Dell", "model": "R750",
         "device_type": "server", "hsm": None, "last_seen": NOW.isoformat()},
    ]
    result = run_scenario("hsm_outage", snap, now=NOW, params={})
    fleet = result["affected"]["hardware_hsms"]
    assert [d["asset_id"] for d in fleet] == ["hsm-01", "hsm-02"]
    assert fleet[0]["manufacturer"] == "Thales"
    assert result["impact"]["hsm_fleet"] == ["Thales Luna 7", "Utimaco Se Gen2"]
    assert any("not the blast radius" in u for u in result["honest_unknowns"])


def test_pqc_migration_reports_hardware_capability():
    snap = _snapshot()
    snap["hardware"] = [
        {"asset_id": "hsm-01", "device_type": "hsm",
         "hsm": {"pqc_capability": "HYBRID_SUPPORTED"}},
        {"asset_id": "hsm-02", "device_type": "hsm",
         "hsm": {"pqc_capability": "NOT_READY"}},
        {"asset_id": "hsm-03", "device_type": "hsm",
         "hsm": {"pqc_capability": "UNKNOWN"}},
    ]
    result = run_scenario("pqc_migration", snap, now=NOW, params={})
    hw = result["impact"]["hardware"]
    assert hw == {"hsms": 3, "pqc_capable": 1, "pqc_not_capable": 1,
                  "pqc_unknown": 1, "not_capable_devices": ["hsm-02"]}
    assert any("not independently verified" in u for u in result["honest_unknowns"])


def test_vendor_compromise_blast_radius():
    result = run_scenario("vendor_compromise", _snapshot(), now=NOW,
                          params={"vendor": "thales"})
    assert result["affected"]["systems"] == ["Core"]
    assert result["impact"]["dependency_type"] == ["hsm"]
    assert result["affected"]["criticality"] == "critical"


def test_protocol_deprecation_below_floor():
    result = run_scenario("protocol_deprecation", _snapshot(), now=NOW,
                          params={"protocol": "TLS", "min_version": "1.2"})
    assert result["affected"]["endpoints"] == ["api.bank:443"]
    assert "api.bank:8443" not in result["affected"]["endpoints"]
    assert result["affected"]["assets"] == ["sys-core"]


def test_protocol_deprecation_parses_wire_format_versions():
    """Scan probes report 'TLSv1.0', not '1.0' — the floor must still bite."""
    snap = _snapshot()
    snap["network_endpoints"] = [
        {"host": "old.bank", "port": 443, "protocol": "tls",
         "version": "TLSv1.0", "observed": True},
        {"host": "new.bank", "port": 443, "protocol": "tls",
         "version": "TLSv1.3", "observed": True},
        {"host": "dark.bank", "port": 8443, "protocol": "tls",
         "version": None, "observed": False},  # registered, never probed
    ]
    result = run_scenario("protocol_deprecation", snap, now=NOW,
                          params={"protocol": "TLS", "min_version": "1.2"})
    assert result["affected"]["endpoints"] == ["old.bank:443"]
    # The unprobed endpoint is unknown, not "below the floor".
    assert "dark.bank:8443" not in result["affected"]["endpoints"]


def test_compliance_change_flips_weak_keys_and_hashes():
    result = run_scenario("compliance_change", _snapshot(), now=NOW,
                          params={"min_key_bits": 3072})
    assert result["affected"]["newly_failing_key_size"] == ["e1"]  # RSA 2048 < 3072
    assert result["affected"]["newly_failing_hash"] == ["e2"]      # MD5


def test_attack_path_bfs_depths():
    result = run_scenario("attack_path", _snapshot(), now=NOW,
                          params={"seed_asset": "sys-core", "max_depth": 5})
    assert result["affected"]["by_depth"] == {1: ["sys-pay"], 2: ["sys-legacy"]}
    assert result["impact"]["reachable_count"] == 2


def test_attack_path_without_edges_is_honest_not_empty():
    snap = _snapshot()
    snap["dependencies"] = []
    result = run_scenario("attack_path", snap, now=NOW,
                          params={"seed_asset": "sys-core"})
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert result["affected"]["reachable_assets"] == []
    assert "no dependency edges" in result["honest_unknowns"][0]


def test_pqc_migration_buckets():
    result = run_scenario("pqc_migration", _snapshot(), now=NOW, params={})
    assert "sys-core" in result["affected"]["vulnerable"]
    assert "sys-pay" in result["affected"]["ready"]
    assert "sys-legacy" in result["affected"]["unknown"]


def test_drift_regression_uses_real_formula():
    result = run_scenario("drift_regression", _snapshot(), now=NOW,
                          params={"system_id": "sys-core",
                                  "actions": ["move_to_kms"]})
    assert result["impact"]["current"]["agility_score"] is not None
    assert result["impact"]["projected"]["agility_score"] is not None
    assert result["impact"]["assumptions"]


def test_bad_inputs_raise_instead_of_guessing():
    snap = _snapshot()
    with pytest.raises(ValueError):
        run_scenario("nope", snap, now=NOW, params={})
    with pytest.raises(ValueError):
        run_scenario("algorithm_migration", snap, now=NOW, params={})
    with pytest.raises(ValueError):
        run_scenario("attack_path", snap, now=NOW,
                     params={"seed_asset": "x", "bogus": 1})
    with pytest.raises(ValueError):
        run_scenario("drift_regression", snap, now=NOW,
                     params={"system_id": "missing", "actions": []})


def test_empty_estate_is_honest_not_zero_division():
    result = run_scenario("certificate_expiry", {}, now=NOW, params={})
    assert result["impact"]["counts"]["expired"] == 0
    fidelity = twin_fidelity({}, now=NOW)
    assert fidelity["twin"]["assets"] == 0
    assert fidelity["coverage"]["systems_covered_pct"] is None


def test_fidelity_measures_staleness_and_coverage():
    snap = _snapshot()
    fidelity = twin_fidelity(snap, now=NOW, stale_after_seconds=86400)
    # sys-pay last event 3 days ago, sys-legacy never: both stale.
    assert fidelity["staleness"]["assets_stale"] == 2
    assert fidelity["staleness"]["assets_fresh"] == 1
    assert fidelity["twin"]["systems_known"] == 3
    assert fidelity["twin"]["systems_with_twin_state"] == 2
    assert fidelity["coverage"]["systems_covered_pct"] == 66.7
    assert fidelity["twin"]["journal_events"] == 17
    assert fidelity["twin"]["cbom_versions"]["max"] == 4
    # The fixture's two endpoints carry versions (observed by construction).
    assert fidelity["coverage"]["network_endpoints_observed"] == 2
    assert fidelity["coverage"]["network_observed_pct"] == 100.0
    # The reconciliation unknown must be declared, not silently omitted.
    assert any("reconciliation" in u for u in fidelity["honest_unknowns"])


def test_fidelity_reports_unprobed_network_surface():
    """Registered-but-unprobed endpoints are named, not silently healthy."""
    snap = _snapshot()
    snap["network_endpoints"] = [
        {"host": "a.bank", "port": 443, "protocol": "tls",
         "version": "TLSv1.3", "observed": True},
        {"host": "b.bank", "port": 443, "protocol": None,
         "version": None, "observed": False},
        {"host": "c.bank", "port": 8443, "protocol": None,
         "version": None, "observed": False},
    ]
    fidelity = twin_fidelity(snap, now=NOW)
    assert fidelity["coverage"]["network_endpoints"] == 3
    assert fidelity["coverage"]["network_endpoints_observed"] == 1
    assert fidelity["coverage"]["network_observed_pct"] == 33.3
    assert any("never observed" in u for u in fidelity["honest_unknowns"])


def test_fidelity_is_deterministic_and_time_explicit():
    snap = _snapshot()
    a = twin_fidelity(snap, now=NOW)
    b = twin_fidelity(snap, now=NOW)
    assert a == b
    later = twin_fidelity(snap, now=NOW + timedelta(days=2))
    assert later["staleness"]["assets_stale"] >= a["staleness"]["assets_stale"]


def test_fidelity_counts_the_hardware_fleet():
    snap = _snapshot()
    snap["hardware"] = [
        {"asset_id": "hsm-01", "device_type": "hsm", "hsm": {"pqc_capability": "READY"}},
        {"asset_id": "srv-01", "device_type": "server", "hsm": None},
    ]
    fidelity = twin_fidelity(snap, now=NOW)
    assert fidelity["twin"]["hardware_assets"] == 2


# --------------------------------------------------------- reconciliation

def test_reconcile_in_sync_when_twin_matches_evidence():
    snap = _snapshot()
    snap["assets"] = [{"asset_id": "a", "algorithms": {"RSA-2048": 1, "MD5": 2}}]
    snap["evidence"] = [{"algorithm": "RSA-2048"}, {"algorithm": "MD5"}]
    result = reconcile(snap, now=NOW)
    assert result["schema"] == "cryptoscan.twin-reconciliation/1"
    assert result["verdict"] == "IN_SYNC"
    assert result["families_in_both"] == ["md5", "rsa-2048"]
    assert result["families_only_in_twin"] == []
    assert result["families_only_in_evidence"] == []
    assert result["deterministic"] is True


def test_reconcile_flags_twin_lagging_its_evidence():
    """Scanners keep finding MD5; no twin asset reflects it."""
    snap = _snapshot()
    snap["assets"] = [{"asset_id": "a", "algorithms": {"RSA-2048": 1}}]
    snap["evidence"] = [{"algorithm": "RSA-2048"}, {"algorithm": "MD5"}]
    result = reconcile(snap, now=NOW)
    assert result["verdict"] == "TWIN_LAGS_EVIDENCE"
    assert result["families_only_in_evidence"] == ["md5"]


def test_reconcile_flags_twin_claims_without_evidence():
    """The twin still claims RSA; no current evidence record backs it."""
    snap = _snapshot()
    snap["assets"] = [{"asset_id": "a",
                       "algorithms": {"AES-256-GCM": 1, "RSA-2048": 2}}]
    snap["evidence"] = [{"algorithm": "AES-256-GCM"}]
    result = reconcile(snap, now=NOW)
    assert result["verdict"] == "EVIDENCE_LAGS_TWIN"
    assert result["families_only_in_twin"] == ["rsa-2048"]
    assert result["families_only_in_evidence"] == []


def test_reconcile_diverged_when_both_sides_lag():
    snap = _snapshot()
    snap["assets"] = [{"asset_id": "a", "algorithms": {"RSA-2048": 1, "AES-256-GCM": 1}}]
    snap["evidence"] = [{"algorithm": "RSA-2048"}, {"algorithm": "MD5"}]
    result = reconcile(snap, now=NOW)
    assert result["verdict"] == "DIVERGED"


def test_reconcile_is_honest_when_either_side_is_empty():
    result = reconcile({}, now=NOW)
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert any("evidence store is empty" in u for u in result["honest_unknowns"])
    assert any("no algorithm inventory" in u for u in result["honest_unknowns"])

    snap = {"assets": [{"asset_id": "a", "algorithms": {"RSA-2048": 1}}]}
    result = reconcile(snap, now=NOW)
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert result["twin_algorithm_families"] == {"rsa-2048": 1}


def test_reconcile_is_deterministic():
    snap = _snapshot()
    assert reconcile(snap, now=NOW) == reconcile(snap, now=NOW)
