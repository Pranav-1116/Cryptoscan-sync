"""Same host authority/closure contracts on explicitly owned PostgreSQL."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_host_evidence as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_host_collection_intake_inspection_and_exact_schema_export,
        contracts.test_exact_scope_and_one_use_idempotency,
        contracts.test_host_write_rate_limit_is_enforced_on_actual_http,
        contracts.test_analyst_cannot_self_approve_or_escalate_body_authority,
    ],
)
def test_postgres_host_contract(assured, contract):
    contract(assured)


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_postgres_read_authority(assured, role):
    contracts.test_durable_readonly_auditor_can_inspect_not_modify_scan(assured, role)


@pytest.mark.parametrize(
    "change",
    [
        "content",
        "projection",
        "chain",
        "manifest",
        "snapshot",
        "tombstone",
        "foreign_row",
        "foreign_scan",
        "scope",
        "target",
        "evidence_id",
        "time",
        "version",
    ],
)
def test_postgres_closure_refusal(assured, change):
    contracts.test_export_refuses_broken_evidence_closure(assured, change)


def test_postgres_atomic_audit_failure(assured, monkeypatch):
    contracts.test_audit_failure_rolls_back_intake_not_just_receipt(assured, monkeypatch)


def test_postgres_one_approval_cannot_commit_two_scans(assured):
    from concurrent.futures import ThreadPoolExecutor

    clients, db, identifier, _, snapshot = contracts.setup(assured)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: contracts.submit(clients, identifier, snapshot).status_code, range(2)))
    assert sorted(statuses) in ([200, 201], [201, 409])
    from db.models.scan import Scan
    from db.models.assurance import AssuranceRevision

    assert db.query(Scan).count() == 1
    assert db.query(AssuranceRevision).filter_by(kind="host_intake").count() == 1


def test_postgres_approval_atomic_audit_failure(assured, monkeypatch):
    contracts.test_approval_audit_failure_rolls_back_scope_authorization(assured, monkeypatch)
