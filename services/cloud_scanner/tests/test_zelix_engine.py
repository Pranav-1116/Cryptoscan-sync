"""ZELNX engine integration — modes, discovery pipeline, report, drift,
events, scrub contract and CLI wiring."""

from __future__ import annotations

import json

import pytest

from cloud_scanner.enterprise import (
    CloudScanMode,
    ZelixCloudDiscoveryEngine,
    fake_provider,
)
from cloud_scanner.enterprise.pqc_readiness import PQC_READY

from zelix_fixtures import all_providers


def _engine(*, modes=None, options=None, providers=None):
    return ZelixCloudDiscoveryEngine(
        providers=providers if providers is not None else all_providers(),
        modes=modes,
        options=options,
    )


# ------------------------------------------------------------------ discovery


def test_engine_default_modes_discover_inventory_and_crypto():
    engine = _engine()
    report = engine.discover()
    assert engine.modes == {CloudScanMode.INVENTORY_ONLY, CloudScanMode.CRYPTO_DISCOVERY}
    assert report.organization.account_count == 5
    assert report.inventory.count() == 6
    assert report.keys.count() == 6
    assert report.certificates.count() == 4
    assert report.tls.summary()["endpoints"] == 4


def test_engine_inventory_only_mode_skips_crypto():
    engine = _engine(modes=["INVENTORY_ONLY"])
    report = engine.discover()
    assert report.keys.count() == 0
    assert report.certificates.count() == 0
    assert report.inventory.count() == 6
    assert report.organization.account_count == 5


def test_engine_deep_mode_adds_k8s_serverless_secrets_iam():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY"])
    report = engine.discover()
    assert report.kubernetes.count() == 3
    assert report.serverless.count() == 2
    assert report.secrets.count() == 3
    assert report.access.count() == 4
    assert report.multi_cloud.count() == 2


def test_engine_report_shape_covers_all_23_areas():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY"])
    engine.discover()
    report = engine.report()
    sections = {
        "organization", "asset_inventory", "keys", "certificates", "pki",
        "encryption", "network_crypto", "tls", "kubernetes", "serverless",
        "secrets", "iam_access", "dependency_graph", "multi_cloud", "posture",
        "pqc_readiness", "compliance", "migration_simulation", "cost",
        "evidence", "drift", "events",
    }
    assert sections <= set(report)
    assert report["scan"]["read_only"] is True
    assert report["scan"]["modes"] == [
        "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY", "INVENTORY_ONLY"]


def test_engine_dependency_graph_built_from_discovery():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"])
    report = engine.discover()
    relations = {edge["relation"] for edge in report.graph.to_dicts()}
    assert "USES_KEY" in relations
    assert "RUNS_ON" in relations
    assert "EXPOSED_BY" in relations


def test_engine_evidence_chain_verifies():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"])
    report = engine.discover()
    assert report.evidence.verify() is True
    assert len(report.evidence) > 0
    assert engine.report()["evidence_verified"] is True


def test_engine_report_json_serializable():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY"])
    engine.discover()
    payload = json.dumps(engine.report(), default=str)
    assert "SUPER-SECRET" not in payload  # scrub contract holds end-to-end


def test_engine_never_exposes_key_material_in_report():
    rows = {
        "keys": [{"key_id": "k1", "key_spec": "RSA_2048", "key_material": "PRIVATE-KEY-BYTES"}],
    }
    engine = ZelixCloudDiscoveryEngine(
        providers=[fake_provider("aws", rows, accounts=[{"account_id": "1", "name": "a"}])],
        modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"],
    )
    engine.discover()
    assert "PRIVATE-KEY-BYTES" not in json.dumps(engine.report(), default=str)


def test_engine_posture_and_pqc_in_report():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"])
    engine.discover()
    report = engine.report()
    assert report["posture"]["unified"]["total_assets"] > 0
    assert report["pqc_readiness"]["summary"]["assessed"] > 0
    assert report["compliance_summary"]["evaluations"] > 0
    assert report["migration_simulation"]["steps"]
    assert report["cost"]["lines"]


def test_engine_network_path_simulation_wired():
    """§17 — cloud simulation feeds the existing network simulation engine."""
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY"])
    report = engine.discover()
    assert report.simulation is not None
    assert report.simulation.path_simulations, "network simulator not wired"
    simulated = report.simulation.path_simulations[0]
    assert "verdict" in simulated
    assert "paths_evaluated" in simulated


def test_engine_errors_recorded_never_raised():
    def boom():
        raise RuntimeError("provider down")

    engine = ZelixCloudDiscoveryEngine(
        providers=[fake_provider("aws", {"keys": []}, accounts=None)],
        modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"],
    )
    # patch enumerators to raise
    engine._providers[0].enumerate_workloads = boom
    engine._providers[0].enumerate_keys = boom
    report = engine.discover()
    assert report.errors  # errors surface in the report, scan does not crash
    assert report.inventory.count() == 0
    assert report.keys.count() == 0


# ------------------------------------------------------------------ modes


def test_engine_rejects_unknown_mode():
    with pytest.raises(ValueError):
        ZelixCloudDiscoveryEngine(providers=[], modes=["NOPE"])


def test_engine_requires_events_mode_for_event_processing():
    engine = _engine(modes=["INVENTORY_ONLY"])
    result = engine.process_events([
        {"provider": "aws", "event_type": "kms", "resource": "k1",
         "details": {"rotation_enabled": False}},
    ])
    assert CloudScanMode.EVENT_DRIVEN in engine.modes
    assert len(result.events) == 1
    assert len(result.changes) == 1


def test_engine_event_evidence_recorded():
    engine = _engine()
    result = engine.process_events([
        {"provider": "aws", "event_type": "kms", "resource": "k1",
         "details": {"keyState": "Disabled"}},
    ])
    assert result.events
    assert engine.report()["events"]["processed"] == 1
    assert engine.report()["events"]["cbom"]["components"] == 1


# ------------------------------------------------------------------ drift / cycles


def test_engine_run_cycles_detects_drift_between_snapshots():

    def mutate_rows():
        return {"keys": [{"key_id": "k1", "key_spec": "RSA_2048", "rotation_enabled": True}]}

    adapter = fake_provider("aws", {}, accounts=[{"account_id": "1", "name": "a"}])
    adapter.enumerate_keys = lambda: [{"key_id": "k1", "key_spec": "RSA_2048",
                                       "rotation_enabled": True}]

    engine = ZelixCloudDiscoveryEngine(
        providers=[adapter], modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"])
    engine.discover()
    # simulate external change: rotation disabled
    adapter.enumerate_keys = lambda: [{"key_id": "k1", "key_spec": "RSA_2048",
                                       "rotation_enabled": False}]
    engine.discover()
    assert engine.report()["drift"]["latest"]
    drift = engine.report()["drift"]["latest"][0]
    assert drift["kind"] == "KMS_KEY_ROTATION_DISABLED"
    assert drift["classification"] == "HIGH_RISK"


def test_engine_run_cycles_with_stop():
    engine = _engine()
    reports = engine.run(cycles=5, stop=lambda: True)
    assert reports == []


def test_engine_continuous_mode_added_by_run():
    engine = _engine(modes=["INVENTORY_ONLY"])
    reports = engine.run(cycles=2)
    assert len(reports) == 2
    assert CloudScanMode.CONTINUOUS_MONITORING in engine.modes


# ------------------------------------------------------------------ CLI


def test_cli_zelix_empty_inventory_is_valid(tmp_path):
    from cloud_scanner.main import main

    out = tmp_path / "zelix.json"
    code = main(["--zelix", "--zelix-modes", "INVENTORY_ONLY", "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text())
    assert report["scan"]["read_only"] is True
    assert report["scan"]["modes"] == ["CONTINUOUS_MONITORING", "INVENTORY_ONLY"]
    assert report["evidence_verified"] is True


def test_cli_zelix_accepts_all_modes(tmp_path):
    from cloud_scanner.main import main

    out = tmp_path / "zelix-deep.json"
    code = main(["--zelix", "--zelix-modes",
                 "INVENTORY_ONLY,CRYPTO_DISCOVERY,DEEP_CRYPTO_DISCOVERY,EVENT_DRIVEN",
                 "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text())
    assert "DEEP_CRYPTO_DISCOVERY" in report["scan"]["modes"]
    assert "EVENT_DRIVEN" in report["scan"]["modes"]


# ------------------------------------------------------------------ misc


def test_engine_accepts_dict_providers():
    engine = ZelixCloudDiscoveryEngine(
        providers=[{"provider": "aws",
                    "enumerate_accounts": lambda: {"accounts": [
                        {"account_id": "1", "name": "a"}], "truncated": False,
                        "errors": []}}],
        modes=["INVENTORY_ONLY"],
    )
    report = engine.discover()
    assert report.organization.account_count == 1
    assert "aws" in engine.report()["scan"]["providers"]


def test_engine_clock_injectable():
    engine = ZelixCloudDiscoveryEngine(
        providers=[{"provider": "aws",
                    "enumerate_accounts": lambda: {"accounts": [
                        {"account_id": "1", "name": "a"}], "truncated": False,
                        "errors": []}}],
        modes=["INVENTORY_ONLY"], clock=lambda: "2026-08-30T00:00:00Z")
    report = engine.discover()
    assert report.evidence.verify() is True
    assert "2026-08-30T00:00:00Z" in report.evidence.to_dicts()[0]["observation"]["evidence"]["timestamp"]


def test_pqc_never_ready_without_engine_evidence():
    engine = _engine(modes=["INVENTORY_ONLY", "CRYPTO_DISCOVERY"])
    engine.discover()
    verdicts = engine.report()["pqc_readiness"]["summary"]["by_verdict"]
    assert verdicts[PQC_READY] == 0
