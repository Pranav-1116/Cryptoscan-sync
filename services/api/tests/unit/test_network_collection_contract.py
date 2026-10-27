"""A01 first slice: authenticated bank requests, no real network packets.

Only the external TCP/TLS executors and admission's authoritative-data seams
are controlled. Auth sessions, tenant middleware, SQL persistence and job
transitions are real. These tests do not qualify a live bank/device/runtime.
"""

from copy import deepcopy
import uuid

import pytest
from sqlalchemy import event

from db.models.network_scan_run import NetworkScanRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.scan_job import ScanJob
from test_software_supply_chain_api import banks as banks

ROUTES = ["direct", "alias", "due", "discovery"]


@pytest.fixture()
def contract(banks, monkeypatch):
    clients, db, _ = banks
    import api.security.scan_admission as admission
    from network_scanner.core.scanner import NetworkTlsScanner
    import network_scanner.discovery.subnet_discoverer as discovery

    state = {"policy": {}, "ot": False, "outage": False, "queue": 0, "calls": [], "sweeps": [], "status": "OK"}

    def policy():
        if state["outage"]:
            raise RuntimeError("control-plane unavailable")
        return [], deepcopy(state["policy"])

    monkeypatch.setattr(admission, "_control_plane_state", policy)
    monkeypatch.setattr(admission, "_ot_declared", lambda: state["ot"])
    monkeypatch.setattr(admission, "_active_job_count", lambda: state["queue"])
    monkeypatch.setattr(admission, "_authorized_network_scope", lambda: ["10.0.0.0/30"])
    monkeypatch.setenv("MAX_QUEUE_DEPTH", "5")

    def scan(self, hosts, **kwargs):
        state["calls"].append(list(hosts))
        jobs = db.query(ScanJob).all()
        state["running_at_probe"] = [j.status for j in jobs]
        if state.get("scanner_failure"):
            raise RuntimeError("controlled scanner failure")
        return {
            "scan_id": uuid.uuid4().hex,
            "findings": [],
            "certificates": [],
            "usages": [],
            "probe_telemetry": {
                "status": state["status"],
                "probed": len(hosts),
                "ok": 0 if state["status"] == "ERROR" else len(hosts),
            },
        }

    def sweep(cidr, ports, **kwargs):
        state["sweeps"].append(cidr)
        if state.get("stop_after_sweep"):
            state["policy"] = {"emergency_stop": True}
        return {
            "cidr": cidr,
            "endpoints": ["10.0.0.1:443"],
            "candidates": 2,
            "open_count": 1,
            "hosts_checked": 2,
            "truncated": False,
        }

    monkeypatch.setattr(NetworkTlsScanner, "scan_hosts", scan)
    monkeypatch.setattr(discovery, "discover_subnet", sweep)
    db.add(NetworkScanTarget(endpoint="10.0.0.1:443", tenant_id="a", enabled=True))
    db.commit()
    return clients, db, state


def request(contract, route, **extra):
    clients, _db, _state = contract
    client = clients["bank_a"]
    if route == "due":
        return client.post("/api/v1/network/run-due")
    if route == "discovery":
        return client.post("/api/v1/network/discover", json={"cidr": "10.0.0.0/30", "ports": [443], **extra})
    path = "/api/v1/network/scan" if route == "direct" else "/api/v1/network-scans"
    return client.post(path, json={"hosts": ["10.0.0.1:443"], **extra})


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "condition,code", [("stop", 409), ("outage", 503), ("passive", 409), ("ot", 409), ("excluded", 409), ("queue", 429)]
)
def test_denied_batch_has_no_packets_or_collection_side_effects(contract, route, condition, code):
    _, db, state = contract
    if condition == "stop":
        state["policy"] = {"emergency_stop": True}
    if condition == "outage":
        state["outage"] = True
    if condition == "passive":
        state["policy"] = {"mode": "passive"}
    if condition == "ot":
        state["ot"] = True
    if condition == "excluded":
        state["policy"] = {"excluded_assets": ["10.0.0.1:443", "10.0.0.0/30"]}
    if condition == "queue":
        state["queue"] = 6
    response = request(contract, route)
    assert response.status_code == code, response.text
    assert state["calls"] == state["sweeps"] == []
    assert db.query(NetworkScanRun).count() == db.query(ScanJob).count() == 0
    assert db.query(NetworkScanTarget).one().last_scan_time is None


@pytest.mark.parametrize("route", ROUTES)
def test_accepted_collection_links_committed_job_and_probe_ledger(contract, route):
    clients, db, state = contract
    response = request(contract, route)
    assert response.status_code == 200, response.text
    body = response.json()
    assert state["running_at_probe"] == ["RUNNING"]
    assert len(state["calls"]) == 1
    row = db.query(NetworkScanRun).filter_by(id=body["run_id"]).one()
    job = db.query(ScanJob).filter_by(id=body["job_id"]).one()
    assert row.tenant_id == job.tenant_id == "a"
    assert job.status == "COMPLETED"
    assert row.result["collection"]["job_id"] == job.id
    assert job.progress["coverage"]["network_run_id"] == row.id
    assert job.progress["admission"]["active_probing"] is True
    assert clients["bank_a"].get("/api/v1/network/runs/" + row.id).status_code == 200
    assert clients["bank_b"].get("/api/v1/network/runs/" + row.id).status_code == 404
    assert clients["bank_a"].get("/api/v1/jobs/" + job.id).status_code == 200
    assert clients["bank_b"].get("/api/v1/jobs/" + job.id).status_code == 404


@pytest.mark.parametrize("route", ROUTES)
def test_executor_failure_is_durable_and_does_not_advance_schedule(contract, route):
    _, db, state = contract
    state["scanner_failure"] = True
    # TestClient propagates an unhandled runtime exception; storage invariants
    # remain inspectable after the request fails.
    with pytest.raises(RuntimeError, match="controlled scanner failure"):
        request(contract, route)
    db.expire_all()
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0
    assert db.query(NetworkScanTarget).one().last_scan_time is None


@pytest.mark.parametrize("route", ["direct", "alias"])
@pytest.mark.parametrize(
    "body", [{"live": False}, {"timeout": 0}, {"timeout": -1}, {"workers": 0}, {"workers": 100000}]
)
def test_unsafe_or_misleading_options_rejected_before_packets(contract, route, body):
    _, db, state = contract
    response = request(contract, route, **body)
    assert response.status_code == 422, response.text
    assert state["calls"] == []
    assert db.query(ScanJob).count() == 0


def test_persistence_opt_out_is_not_an_unrecorded_scan(contract):
    _, db, state = contract
    response = request(contract, "direct", persist_run=False)
    assert response.status_code == 422
    assert state["calls"] == []
    assert db.query(NetworkScanRun).count() == 0


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "exclusion",
    [
        {"excluded_ports": [443]},
        {"excluded_protocols": ["tcp"]},
        {"excluded_assets": ["10.0.0.1"]},
        {"excluded_assets": ["10.0.0.0/29"]},
    ],
)
def test_network_exclusion_cannot_be_bypassed_by_route_or_endpoint_format(contract, route, exclusion):
    _, _db, state = contract
    state["policy"] = exclusion
    response = request(contract, route)
    assert response.status_code == 409, response.text
    assert state["calls"] == state["sweeps"] == []


def test_discovery_rechecks_stop_before_optional_tls_or_registration(contract):
    _, db, state = contract
    state["stop_after_sweep"] = True
    response = request(contract, "discovery", register=True)
    assert response.status_code == 409, response.text
    assert len(state["sweeps"]) == 1 and not state["calls"]
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanTarget).one().last_scan_time is None


@pytest.mark.parametrize("route", ROUTES)
def test_ledger_insert_failure_rolls_back_and_is_not_success(contract, route):
    _, db, _ = contract

    def fail_insert(*args):
        raise RuntimeError("controlled ledger insert failure")

    event.listen(NetworkScanRun, "before_insert", fail_insert)
    try:
        with pytest.raises(RuntimeError, match="controlled ledger insert failure"):
            request(contract, route)
    finally:
        event.remove(NetworkScanRun, "before_insert", fail_insert)
    db.expire_all()
    assert db.query(NetworkScanRun).count() == 0
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanTarget).one().last_scan_time is None


def test_error_telemetry_is_not_a_successful_observation_or_schedule_refresh(contract):
    _, db, state = contract
    state["status"] = "ERROR"
    response = request(contract, "due")
    assert response.status_code == 200, response.text
    assert response.json()["probe_telemetry"]["status"] == "ERROR"
    assert db.query(NetworkScanRun).one().verdict == "ERROR"
    assert db.query(NetworkScanTarget).one().last_scan_time is None


def test_platform_and_foreign_targets_are_not_executed_by_bank_due_rotation(contract):
    _, db, state = contract
    db.add_all(
        [
            NetworkScanTarget(endpoint="10.0.0.2:443", enabled=True),
            NetworkScanTarget(endpoint="10.0.0.3:443", tenant_id="b", enabled=True),
        ]
    )
    db.commit()
    response = request(contract, "due")
    assert response.status_code == 200, response.text
    assert state["calls"] == [["10.0.0.1:443"]]


@pytest.mark.parametrize("route", ROUTES)
def test_refused_completion_cas_cannot_commit_a_successful_receipt(contract, route, monkeypatch):
    _, db, _ = contract
    from db.repositories.job_repository import JobRepository

    original = JobRepository.update_status

    def refuse_completed(self, identifier, status, **kwargs):
        return None if status == "COMPLETED" else original(self, identifier, status, **kwargs)

    monkeypatch.setattr(JobRepository, "update_status", refuse_completed)
    with pytest.raises(RuntimeError, match="completion was refused"):
        request(contract, route)
    db.expire_all()
    assert db.query(NetworkScanRun).count() == 0
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanTarget).one().last_scan_time is None


@pytest.mark.parametrize("route", ROUTES)
def test_final_commit_failure_retains_only_failed_job(contract, route):
    _, db, state = contract
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    failed = []

    def fail_commit(session):
        if not failed and session.execute(select(NetworkScanRun.id).limit(1)).first():
            failed.append(True)
            raise RuntimeError("controlled final commit failure")

    event.listen(Session, "before_commit", fail_commit)
    try:
        with pytest.raises(RuntimeError, match="controlled final commit failure"):
            request(contract, route)
    finally:
        event.remove(Session, "before_commit", fail_commit)
    db.expire_all()
    assert failed and len(state["calls"]) == 1
    assert db.query(NetworkScanRun).count() == 0
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanTarget).one().last_scan_time is None


def test_policy_findings_do_not_make_successful_observations_stale_or_retry_spin(contract):
    _, db, state = contract
    state["status"] = "PARTIAL"  # every handshake observed, but posture has findings
    response = request(contract, "due")
    assert response.status_code == 200
    assert db.query(NetworkScanRun).one().verdict == "PARTIAL"
    assert db.query(NetworkScanTarget).one().last_scan_time is not None
    assert db.query(ScanJob).one().progress["coverage"]["probe_status"] == "PARTIAL"


@pytest.mark.parametrize("route", ["direct", "alias"])
def test_mixed_batch_is_all_preflighted_before_first_packet(contract, route):
    _, db, state = contract
    state["policy"] = {"excluded_assets": ["10.0.0.2"]}
    response = request(contract, route, hosts=["10.0.0.1:443", "10.0.0.2:443"])
    assert response.status_code == 409
    assert state["calls"] == []
    assert db.query(ScanJob).count() == 0


@pytest.mark.parametrize("route", ROUTES)
def test_explicit_exclusion_of_different_port_does_not_block_allowed_port(contract, route):
    _, _db, state = contract
    state["policy"] = {"excluded_assets": ["10.0.0.1:8443"]}
    response = request(contract, route)
    assert response.status_code == 200, response.text
    assert state["calls"] == [["10.0.0.1:443"]]


def test_port_discovery_only_is_durable_but_not_tls_evidence(contract):
    _, db, state = contract
    response = request(contract, "discovery", scan=False)
    assert response.status_code == 200, response.text
    assert state["sweeps"] and not state["calls"]
    row = db.query(NetworkScanRun).one()
    assert row.target_kind == "discovery" and row.verdict is None
    assert "probe_telemetry" not in row.result
    assert db.query(ScanJob).one().progress["coverage"]["probe_status"] == "NOT_EVALUATED"


def test_wrong_scope_discovery_output_is_not_followed_or_registered(contract, monkeypatch):
    _, db, state = contract
    import network_scanner.discovery.subnet_discoverer as discovery

    monkeypatch.setattr(discovery, "discover_subnet", lambda *a, **k: {"endpoints": ["10.9.0.1:443"]})
    response = request(contract, "discovery", register=True)
    assert response.status_code == 422
    assert not state["calls"]
    assert db.query(NetworkScanTarget).count() == 1
    assert db.query(ScanJob).one().status == "FAILED"


@pytest.mark.parametrize("route", ["direct", "alias"])
def test_multi_host_request_cannot_overdraw_remaining_single_host_quota(contract, route):
    _, db, state = contract
    from api.security.tenancy import PLANS
    from db.models.tenant import Tenant
    from db.repositories.tenant_repository import TenantRepository

    tenant = db.query(Tenant).filter_by(id="a").one()
    tenant.plan = "FREE"
    repo = TenantRepository(db)
    repo.record_usage("a", "scan_run", PLANS["FREE"]["max_scans_per_month"] - 1)
    db.commit()
    response = request(contract, route, hosts=["10.0.0.1:443", "10.0.0.2:443"])
    assert response.status_code == 402, response.text
    assert not state["calls"]
    assert db.query(ScanJob).count() == 0


@pytest.mark.parametrize("route", ["direct", "alias"])
def test_network_scope_and_metering_do_not_depend_on_optional_test_middleware(contract, route):
    clients, db, _ = contract
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as bare:
        bare.cookies.update(clients["bank_a"].cookies)
        path = "/api/v1/network/scan" if route == "direct" else "/api/v1/network-scans/"
        response = bare.post(path, json={"hosts": ["10.0.0.1:443"], "tenant_id": "b"})
    assert response.status_code == 200, response.text
    assert db.query(ScanJob).one().tenant_id == db.query(NetworkScanRun).one().tenant_id == "a"
    from db.repositories.tenant_repository import TenantRepository

    assert TenantRepository(db).month_usage("a", "scan_run") == 1
    assert TenantRepository(db).month_usage("b", "scan_run") == 0


@pytest.mark.parametrize("route", ROUTES)
def test_protocol_service_alias_exclusions_use_shared_registry(contract, route):
    _, _db, state = contract
    state["policy"] = {"excluded_protocols": ["https"]}
    response = request(contract, route)
    assert response.status_code == 409
    assert state["sweeps"] == state["calls"] == []


def test_discovery_receipt_keeps_tcp_and_tls_admission_distinct(contract):
    _, db, _ = contract
    response = request(contract, "discovery")
    assert response.status_code == 200, response.text
    assert db.query(ScanJob).one().progress["admission"]["protocol"] == "tcp"
    decision = db.query(NetworkScanRun).one().result["collection"]["phase_admission"]
    assert decision["protocol"] == "tls"
    assert decision["checked_targets"] == 1


@pytest.mark.parametrize("route", ROUTES)
def test_forged_tenant_cannot_launch_collection(contract, route):
    clients, db, state = contract
    clients["bank_a"].headers["X-Tenant-ID"] = "b"
    response = request(contract, route)
    assert response.status_code == 404
    assert state["calls"] == state["sweeps"] == []
    assert db.query(ScanJob).count() == 0


@pytest.mark.parametrize("route", ROUTES)
def test_generic_repository_retry_does_not_reinterpret_network_profiles(contract, route):
    clients, db, state = contract
    response = request(contract, route)
    assert response.status_code == 200
    retry = clients["bank_a"].post("/api/v1/jobs/" + response.json()["job_id"] + "/retry")
    assert retry.status_code == 409, retry.text
    assert db.query(ScanJob).count() == 1
    assert len(state["calls"]) == 1


def test_receipts_do_not_disclose_other_assets_in_global_policy(contract):
    _, db, state = contract
    import json

    secret = "private-other-bank.example.test"
    state["policy"] = {"excluded_assets": [secret]}
    response = request(contract, "direct")
    assert response.status_code == 200
    assert secret not in json.dumps(db.query(ScanJob).one().progress)
    assert secret not in json.dumps(db.query(NetworkScanRun).one().result)


@pytest.mark.parametrize("route", ROUTES)
def test_receipt_retains_admitted_request_profile_without_unknown_body_fields(contract, route):
    _, db, _ = contract
    kwargs = {} if route == "due" else {"workers": 3, "credential": "must-not-be-retained"}
    response = request(contract, route, **kwargs)
    assert response.status_code == 200, response.text
    profile = db.query(ScanJob).one().progress["run"]["profile"]
    assert profile["workers"] == (8 if route == "due" else 3)
    assert "credential" not in profile
    if route == "discovery":
        assert profile["ports"] == [443] and profile["scan"] is True
