"""Exact local-source admission preview never queues a scan or claims field coverage."""
from pathlib import Path
from types import SimpleNamespace

from db.models.scan_job import ScanJob
from db.repositories.execution_control import ExecutionDenied
from test_assurance_workflows import assured as assured, admin as selected_admin  # noqa: F401 — real-session fixture
from test_software_supply_chain_api import banks as banks  # noqa: F401 — assured dependency

PATH = "/api/v1/scans/preflight"


def test_development_preflight_is_not_production_qualification(assured, monkeypatch):
    clients, db, root = assured
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("CRYPTOSCAN_EXECUTION_CONTROLS", raising=False)
    source = Path(root) / "repo"
    source.mkdir()
    response = selected_admin(clients, "a").post(PATH, json={"repo_url": str(source), "scan_mode": "safe"})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "decision": "NOT_QUALIFIED", "reason": "Controlled local-source deployment is not enabled",
        "job_created": False, "collection_performed": False,
    }
    assert db.query(ScanJob).count() == 0


def test_preflight_refuses_paths_outside_approved_roots_without_queueing(assured):
    clients, db, _ = assured
    response = selected_admin(clients, "a").post(PATH, json={"repo_url": "/etc"})
    assert response.status_code == 400
    assert db.query(ScanJob).count() == 0


def test_local_preflight_rejects_unattested_branch_without_queuing(assured):
    clients, db, root = assured
    source = Path(root) / "repo"
    source.mkdir()
    response = selected_admin(clients, "a").post(PATH, json={"repo_url": str(source), "branch": "release-4"})
    assert response.status_code == 409 and "Git branch" in response.text
    assert db.query(ScanJob).count() == 0


def test_controlled_preflight_requires_positive_approval_and_an_isolation_runtime(assured, monkeypatch):
    from api.security import scan_admission
    from db.repositories import execution_control
    from worker.core import controlled_source

    clients, db, root = assured
    source = Path(root) / "repo"
    source.mkdir()
    monkeypatch.setattr(execution_control, "required", lambda: True)
    monkeypatch.setattr(scan_admission, "admit_scan", lambda **_kwargs: {"mode": "safe"})
    monkeypatch.setattr(execution_control, "typed_authority", lambda _db, _job, principal: (principal, ["superadmin"]))
    monkeypatch.setattr(execution_control, "matching_approval", lambda *_args, **_kw: (_ for _ in ()).throw(ExecutionDenied("No current approval")))
    operator = selected_admin(clients, "a")
    denied = operator.post(PATH, json={"repo_url": str(source), "scan_mode": "safe"})
    assert denied.status_code == 409 and "No current approval" in denied.text
    assert db.query(ScanJob).count() == 0

    monkeypatch.setattr(execution_control, "matching_approval", lambda *_args, **_kw: (
        SimpleNamespace(revision=4), SimpleNamespace(id="approval-1")))
    monkeypatch.setattr(controlled_source, "preflight", lambda: (_ for _ in ()).throw(ExecutionDenied("Pinned isolation runtime is not provisioned")))
    no_runtime = operator.post(PATH, json={"repo_url": str(source), "scan_mode": "safe"})
    assert no_runtime.status_code == 409 and "Pinned isolation runtime" in no_runtime.text
    assert db.query(ScanJob).count() == 0

    monkeypatch.setattr(controlled_source, "preflight", lambda: None)
    preview = operator.post(PATH, json={"repo_url": str(source), "scan_mode": "safe"})
    assert preview.status_code == 200
    assert preview.json()["decision"] == "ADMITTED"
    assert preview.json()["job_created"] is False and preview.json()["collection_performed"] is False
    assert db.query(ScanJob).count() == 0
