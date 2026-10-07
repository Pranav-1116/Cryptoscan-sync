"""Digital-twin API — overview, scenarios, simulate, fidelity, timeline.

Real sqlite + real sessions (same pattern as test_cert_lifecycle_api.py).
The twin surface is read-only by contract: these tests also pin that a
simulation call leaves the underlying rows untouched.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.certificate import Certificate
from db.models.crypto_live import CryptoLiveState
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.evidence_record import EvidenceRecord
from db.models.system_asset import SystemAsset
from db.models.graph_snapshot import GraphSnapshot
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.system import System
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor
from db.repositories.crypto_repository import CryptoRepository
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    c = TestClient(app)
    manager = SessionManager()
    token = manager.create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer",
                        datetime.now(timezone.utc) + timedelta(hours=1),
                        ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


def _seed_twin(session) -> None:
    """Two assets (one quantum-vulnerable, one ready), journal, deps, vendor."""
    crypto = CryptoRepository(session)

    crypto.upsert_state({
        "asset_id": "hsm-core-01",
        "cbom_version": 4,
        "algorithms": {"RSA-2048": 12, "AES-256-GCM": 30},
        "quantum_status": {"status": "vulnerable"},
        "protocols": {"tls": "1.1"},
        "usage": {"signing": "hsm"},
        "libraries": {"openssl": "3.0"},
        "readiness": "AT_RISK",
        "agility": 42,
        "last_seen": NOW - timedelta(minutes=5),
    })
    crypto.update_risk("hsm-core-01", score=78, level="HIGH")
    crypto.upsert_state({
        "asset_id": "pay-edge-02",
        "cbom_version": 2,
        "algorithms": {"ML-KEM-768": 3},
        "quantum_status": {"status": "ready"},
        "protocols": {"tls": "1.3"},
        "libraries": {"liboqs": "0.10"},
        "readiness": "READY",
        "agility": 88,
        "last_seen": NOW - timedelta(days=3),
    })

    for asset_id, version, hours in (("hsm-core-01", 1, 72),
                                     ("hsm-core-01", 2, 48),
                                     ("hsm-core-01", 4, 5),
                                     ("pay-edge-02", 1, 74)):
        crypto.append_event({
            "event_type": "CBOM_UPDATED",
            "asset_id": asset_id,
            "source": "live",
            "observed_at": NOW - timedelta(hours=hours),
            "cbom_version": version,
            "risk_score": 70,
        })

    session.add(System(id="sys-core", name="Core", environment="prod",
                       criticality="critical"))
    session.add(System(id="sys-pay", name="Payments", environment="prod"))
    session.add(SystemDependency(parent_id="sys-core", child_id="sys-pay",
                                 relation="calls"))

    session.add(Certificate(
        fingerprint_sha256="a" * 64, subject="CN=old", issuer="CN=Internal CA",
        not_after=NOW - timedelta(days=1), renewal_status="NONE",
        expiry_status="EXPIRED", days_until_expiry=-1,
    ))
    session.add(Certificate(
        fingerprint_sha256="b" * 64, subject="CN=soon", issuer="CN=Public CA",
        not_after=NOW + timedelta(days=30), renewal_status="PLANNED",
    ))
    session.add(Certificate(
        fingerprint_sha256="c" * 64, subject="CN=fine", issuer="CN=Public CA",
        not_after=NOW + timedelta(days=400), renewal_status="DONE",
    ))

    session.add(EvidenceRecord(
        scan_id="scan-1", content_hash="e" * 64, chain_hash="f" * 64,
        chain_position=1, algorithm="RSA-2048", key_size=2048,
        is_hardcoded_key=True, file_path="src/Kek.java", line_number=10,
        finding_data={"metadata": {}},
    ))
    session.add(EvidenceRecord(
        scan_id="scan-1", content_hash="1" * 64, chain_hash="2" * 64,
        chain_position=2, algorithm="MD5", file_path="src/hash.py",
        line_number=3, finding_data={"metadata": {}},
    ))

    vendor = Vendor(name="Thales", criticality="critical", vendor_type="hsm")
    session.add(vendor)
    session.flush()
    session.add(SystemVendor(system_id="sys-core", vendor_id=vendor.id,
                             dependency_type="hsm"))
    session.add(NetworkScanTarget(endpoint="api.bank.example:443"))
    session.commit()


# ------------------------------------------------------------ overview

def test_overview_reports_replica_and_fidelity(client, session):
    _seed_twin(session)
    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == "cryptoscan.digital-twin/1"
    assert body["twin_assets"] == 2
    assert body["systems"] == 2
    assert body["certificates"] == 3
    assert body["evidence_records"] == 2
    assert body["dependency_edges"] == 1
    assert body["network_endpoints"] == 1
    assert body["quantum_mix"] == {"vulnerable": 1, "ready": 1, "unknown": 0}
    assert len(body["scenarios_available"]) == 10
    # fidelity embedded: fresh hsm-core (5 min ago), stale pay-edge (3 days)
    assert body["fidelity"]["staleness"]["assets_fresh"] == 1
    assert body["fidelity"]["staleness"]["assets_stale"] == 1


def test_overview_on_empty_estate_is_honest_not_500(client, session):
    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["twin_assets"] == 0
    assert body["fidelity"]["coverage"]["systems_covered_pct"] is None
    assert body["fidelity"]["honest_unknowns"]


# ------------------------------------------------------------ scenarios

def test_scenarios_endpoint_lists_all_ten_with_inputs(client, session):
    r = client.get("/api/v1/digital-twin/scenarios")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario_count"] == 10
    ids = {s["id"] for s in body["scenarios"]}
    assert "algorithm_migration" in ids and "pqc_migration" in ids
    for entry in body["scenarios"]:
        assert entry["name"] and entry["description"]
        assert isinstance(entry["inputs"], dict)


# ------------------------------------------------------------ simulate

def test_simulate_algorithm_migration_finds_the_rsa_asset(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "algorithm_migration",
        "params": {"from_algo": "RSA", "to_algo": "ML-KEM-768"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deterministic"] is True
    assert body["mutates_nothing"] is True
    assert body["affected"]["assets"] == ["hsm-core-01"]
    assert body["affected"]["evidence_records"] == 1
    assert body["honest_unknowns"]


def test_simulate_pqc_migration_buckets_both_assets(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "pqc_migration", "params": {},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "hsm-core-01" in body["affected"]["vulnerable"]
    assert "pay-edge-02" in body["affected"]["ready"]


def test_simulate_certificate_expiry_sees_backlog(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "certificate_expiry", "params": {"horizon_days": 90},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "a" * 64 in body["affected"]["expired"]
    assert "b" * 64 in body["affected"]["expiring_in_horizon"]


def test_simulate_vendor_compromise_blast_radius(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "vendor_compromise", "params": {"vendor": "thales"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["affected"]["systems"] == ["Core"]
    assert body["affected"]["criticality"] == "critical"


def test_simulate_rejects_unknown_scenario_with_400(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "flip_the_switch", "params": {},
    })
    assert r.status_code == 400
    assert "unknown scenario" in r.json()["detail"]


def test_simulate_rejects_bad_params_with_400(client, session):
    _seed_twin(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "algorithm_migration",
        "params": {"from_algo": "RSA"},  # to_algo missing
    })
    assert r.status_code == 400
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "certificate_expiry",
        "params": {"horizon_days": 90, "sneaky": True},  # unknown input
    })
    assert r.status_code == 400


def test_simulate_never_mutates_the_twin(client, session):
    _seed_twin(session)
    before = session.query(CryptoLiveState).order_by(
        CryptoLiveState.asset_id).all()
    frozen = [(s.asset_id, s.cbom_version, s.algorithms, s.quantum_status)
              for s in before]
    cert_count = session.query(Certificate).count()
    event_count = session.query(CryptoLiveState.asset_id).count()

    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "drift_regression",
        "params": {"system_id": "sys-core", "actions": ["move_to_kms"]},
    })
    assert r.status_code == 200, r.text

    session.expire_all()
    after = session.query(CryptoLiveState).order_by(
        CryptoLiveState.asset_id).all()
    assert [(s.asset_id, s.cbom_version, s.algorithms, s.quantum_status)
            for s in after] == frozen
    assert session.query(Certificate).count() == cert_count
    assert session.query(CryptoLiveState.asset_id).count() == event_count


# ------------------------------------------------------------ fidelity

def test_fidelity_measures_staleness_and_unknowns(client, session):
    _seed_twin(session)
    r = client.get("/api/v1/digital-twin/fidelity")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == "cryptoscan.twin-fidelity/1"
    assert body["staleness"]["assets_fresh"] == 1
    assert body["staleness"]["assets_stale"] == 1
    assert body["twin"]["journal_events"] == 4
    assert body["twin"]["systems_known"] == 2
    assert body["twin"]["systems_with_twin_state"] == 0  # no system↔asset link
    assert body["coverage"]["systems_covered_pct"] == 0.0
    assert any("reconciliation" in u for u in body["honest_unknowns"])


# ------------------------------------------------- network evidence feed

def test_network_endpoints_come_from_stored_scan_probes(client, session):
    """The twin reads the wire, not just the target registry: endpoints and
    their TLS versions are derived from stored scan runs (newest wins)."""
    _seed_twin(session)
    session.add(NetworkScanRun(
        target_kind="hosts", verdict="OK", probed=3, ok=2,
        result={"probes": [
            {"endpoint": "api.bank.ae:443", "status": "TLS_OK",
             "tls_version": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
             "certificates": [{"subject": "CN=old", "issuer": "CN=CA",
                               "serial_number": "01",
                               "public_key_algorithm": "RSA",
                               "public_key_size": 1024}]},
            {"endpoint": "ib.bank.ae:443", "status": "TLS_OK",
             "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
             "certificates": []},
            {"endpoint": "legacy.bank.ae:8443", "status": "TIMEOUT"},
        ]},
    ))
    session.commit()

    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    body = r.json()
    # 3 probe endpoints (2 probed OK + 1 unreachable, inventoried but not
    # judged — same semantics as the NBOM) + the registered target
    # api.bank.example:443 which no run has seen yet.
    assert body["network_endpoints"] == 4
    assert body["network_endpoints_observed"] == 2

    # The protocol floor now bites on real wire evidence.
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "protocol_deprecation",
        "params": {"protocol": "TLS", "min_version": "1.2"},
    })
    assert r.status_code == 200, r.text
    affected = r.json()["affected"]["endpoints"]
    assert "api.bank.ae:443" in affected          # TLSv1.0 — below the floor
    assert "ib.bank.ae:443" not in affected       # TLSv1.3 — fine
    assert "legacy.bank.ae:8443" not in affected  # never probed — unknown


# --------------------------------------------------- graph edge fallback

def test_attack_path_uses_graph_snapshot_when_no_relational_edges(client, session):
    """Estates that keep their dependency graph in the graph engine still
    get attack paths: edges come from the latest versioned snapshot."""
    _seed_twin(session)
    session.query(SystemDependency).delete()
    session.add(GraphSnapshot(
        version=1, fingerprint="a" * 64, node_count=3, edge_count=2,
        nodes=[{"id": "sys-core", "kind": "system"},
               {"id": "sys-pay", "kind": "system"},
               {"id": "sys-legacy", "kind": "system"}],
        edges=[{"from": "sys-core", "to": "sys-pay", "label": "CALLS"},
               {"from": "sys-pay", "to": "sys-legacy", "label": "READS"}],
    ))
    session.commit()

    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    assert r.json()["dependency_source"] == "graph_snapshot:v1"
    assert r.json()["dependency_edges"] == 2

    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "attack_path",
        "params": {"seed_asset": "sys-core", "max_depth": 5},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    # JSON turns the depth keys into strings.
    assert body["affected"]["by_depth"] == {"1": ["sys-pay"], "2": ["sys-legacy"]}
    assert body["impact"]["reachable_count"] == 2


def test_relational_edges_win_over_graph_snapshot(client, session):
    """Both sources present: the relational table is the authority."""
    _seed_twin(session)
    session.add(GraphSnapshot(
        version=1, fingerprint="b" * 64, node_count=2, edge_count=1,
        edges=[{"from": "sys-pay", "to": "sys-core", "label": "CALLS"}],
    ))
    session.commit()
    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dependency_source"] == "system_dependencies"
    assert body["dependency_edges"] == 1


# ---------------------------------------------- evidence linkage shape

def test_evidence_linked_to_two_systems_is_one_record(client, session):
    """The adapter ships one row per (record, system) so per-system
    attribution works, and estate-wide counts dedup it back to one record."""
    _seed_twin(session)
    session.query(EvidenceRecord).delete()

    record = EvidenceRecord(
        scan_id="scan-1", content_hash="e" * 64, chain_hash="", chain_position=1,
        algorithm="RSA-2048", key_size=1024, is_hardcoded_key=True,
        file_path="src/Shared.java", line_number=1, finding_data={"metadata": {}},
    )
    session.add(record)
    asset_a = CryptoAsset(algorithm="RSA-2048", file_path="src/Shared.java",
                          line_number=1, is_hardcoded_key=True)
    asset_b = CryptoAsset(algorithm="RSA-2048", file_path="src/Shared.java",
                          line_number=1, is_hardcoded_key=True)
    session.add_all([asset_a, asset_b])
    session.flush()
    session.add(CryptoAssetEvidence(asset_id=asset_a.id, evidence_id=record.id))
    session.add(CryptoAssetEvidence(asset_id=asset_b.id, evidence_id=record.id))
    # the same asset also sits in two systems -> two (record, system) rows
    session.add(SystemAsset(system_id="sys-core", asset_id=asset_a.id))
    session.add(SystemAsset(system_id="sys-pay", asset_id=asset_a.id))
    session.commit()

    body = client.get("/api/v1/digital-twin").json()
    # one record, however many systems/assets reference it
    assert body["evidence_records"] == 1

    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "compliance_change", "params": {"min_key_bits": 3072},
    })
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["affected"]["newly_failing_key_size"] == [record.id]  # once
    assert result["impact"]["counts"]["key_size"] == 1


# ---------------------------------------------------- hardware fleet feed

def _seed_hardware(session) -> None:
    session.add(HardwareAsset(
        asset_id="hsm-core-01", agent_id="agent-1",
        manufacturer="Thales", model="Luna 7", device_type="hsm",
        firmware={"version": "7.7.0"},
        hsm={"device_type": "hsm", "manufacturer": "Thales", "model": "Luna 7",
             "firmware": "7.7.0", "pqc_capability": "HYBRID_SUPPORTED"},
        capabilities={}, crypto_capabilities={},
    ))
    session.add(HardwareAsset(
        asset_id="hsm-pay-02", agent_id="agent-2",
        manufacturer="Utimaco", model="Se Gen2", device_type="hsm",
        firmware={"version": "4.5"},
        hsm={"device_type": "hsm", "manufacturer": "Utimaco", "model": "Se Gen2",
             "firmware": "4.5", "pqc_capability": "NOT_READY"},
        capabilities={}, crypto_capabilities={},
    ))
    session.commit()


def test_overview_counts_the_hardware_fleet(client, session):
    _seed_twin(session)
    _seed_hardware(session)
    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hardware_assets"] == 2
    assert body["hardware_hsms"] == 2
    assert body["fidelity"]["twin"]["hardware_assets"] == 2


def test_hsm_outage_lists_real_devices_not_keywords(client, session):
    _seed_twin(session)
    _seed_hardware(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "hsm_outage", "params": {},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    fleet = body["affected"]["hardware_hsms"]
    assert [d["asset_id"] for d in fleet] == ["hsm-core-01", "hsm-pay-02"]
    assert fleet[0]["pqc_capability"] == "HYBRID_SUPPORTED"
    assert body["impact"]["hsm_fleet"] == ["Thales Luna 7", "Utimaco Se Gen2"]


def test_pqc_migration_reports_hardware_pqc_capability(client, session):
    _seed_twin(session)
    _seed_hardware(session)
    r = client.post("/api/v1/digital-twin/simulate", json={
        "scenario": "pqc_migration", "params": {},
    })
    assert r.status_code == 200, r.text
    hw = r.json()["impact"]["hardware"]
    assert hw["hsms"] == 2
    assert hw["pqc_capable"] == 1
    assert hw["pqc_not_capable"] == 1
    assert hw["not_capable_devices"] == ["hsm-pay-02"]


# ---------------------------------------------------------- reconciliation

def test_reconciliation_flags_divergence_between_twin_and_evidence(client, session):
    """Seeded twin claims RSA+AES+ML-KEM; evidence holds RSA+MD5."""
    _seed_twin(session)
    r = client.get("/api/v1/digital-twin/reconciliation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == "cryptoscan.twin-reconciliation/1"
    assert body["verdict"] == "DIVERGED"
    assert "md5" in body["families_only_in_evidence"]
    assert "aes-256-gcm" in body["families_only_in_twin"]
    assert "rsa-2048" in body["families_in_both"]
    assert body["honest_unknowns"]


def test_reconciliation_on_empty_estate_is_insufficient_not_synced(client, session):
    r = client.get("/api/v1/digital-twin/reconciliation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "INSUFFICIENT_DATA"
    assert body["families_in_both"] == []
    assert any("evidence store is empty" in u for u in body["honest_unknowns"])


# ------------------------------------------------------------ timeline

def test_timeline_returns_journal_newest_first(client, session):
    _seed_twin(session)
    r = client.get("/api/v1/digital-twin/timeline/hsm-core-01")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["asset_id"] == "hsm-core-01"
    assert body["current_cbom_version"] == 4
    assert body["risk"]["level"] == "HIGH"
    assert [e["cbom_version"] for e in body["events"]] == [4, 2, 1]
    observed = [e["observed_at"] for e in body["events"]]
    assert observed == sorted(observed, reverse=True)


def test_timeline_unknown_asset_is_404(client, session):
    _seed_twin(session)
    r = client.get("/api/v1/digital-twin/timeline/no-such-asset")
    assert r.status_code == 404


def test_twin_endpoints_require_auth(session):
    from fastapi.testclient import TestClient as TC
    app = create_app()
    anonymous = TC(app)
    for method, path in (
        ("get", "/api/v1/digital-twin"),
        ("get", "/api/v1/digital-twin/fidelity"),
        ("get", "/api/v1/digital-twin/scenarios"),
        ("get", "/api/v1/digital-twin/timeline/x"),
        ("post", "/api/v1/digital-twin/simulate"),
    ):
        if method == "post":
            r = anonymous.post(path, json={"scenario": "pqc_migration"})
        else:
            r = anonymous.get(path)
        assert r.status_code == 401, (method, path, r.status_code)
