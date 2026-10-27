"""Real persisted authority and transitions, with collectors replaced by sentinels."""

from copy import deepcopy
from dataclasses import replace

import pytest
from sqlalchemy import select
from api.routers.trigger import _run_inline
from db.models.scan_job import ScanJob as JobRow
from db.models.tenant import Tenant, TenantMembership
from db.models.user import User
from db.models.repo_configuration import RepoConfiguration
from db.repositories.job_repository import JobRepository
from db.repositories.api_key_repository import ApiKeyRepository
from db.tenancy import tenant_scope, current_tenant
from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor
from test_software_supply_chain_api import banks as banks


def queued(db, owner="a", actor="bank_a", **changes):
    with tenant_scope(owner):
        row = JobRepository(db).create(
            job_type=changes.pop("job_type", "BINARY"),
            target_repo="binary:///approved/image",
            target_branch="main",
            triggered_by=actor,
            tenant_id=owner,
            progress={"scan_options": {"artifact_id": "approved"}},
            **changes,
        )
        db.commit()
    descriptor = ScanJob(
        job_id=row.id,
        **{
            key: getattr(row, key)
            for key in (
                "tenant_id",
                "target_repo",
                "target_branch",
                "target_commit",
                "triggered_by",
                "job_type",
                "system_id",
            )
        },
        progress=deepcopy(row.progress),
    )
    return row, descriptor


@pytest.fixture()
def execution(banks, monkeypatch):
    _, db, _ = banks
    seen = []
    monkeypatch.setattr("worker.core.job_executor.gate_job", lambda *a, **k: (True, None))

    def collector(job):
        from db.connection.session import SessionLocal

        with SessionLocal() as observer:
            row = observer.execute(select(JobRow).where(JobRow.id == job.job_id)).scalar_one()
            seen.append((current_tenant(), row.status, job.scan_options))
        return True

    monkeypatch.setattr("worker.pipeline.binary_job.run_binary_job", collector)
    return db, seen


@pytest.mark.parametrize("owner,actor", [("a", "bank_a"), ("b", "bank_b"), (None, "platform_admin")])
def test_authorized_job_claims_in_its_persisted_estate_and_duplicate_is_not_run(execution, owner, actor):
    db, seen = execution
    row, descriptor = queued(db, owner, actor)
    assert row.progress["execution_authority"]["kind"] == "user"
    assert JobExecutor().execute(descriptor)
    assert seen == [(owner, "RUNNING", {"artifact_id": "approved"})]
    assert not JobExecutor().execute(descriptor)
    assert len(seen) == 1
    db.expire_all()
    assert row.status == "RUNNING"  # rejected duplicate cannot fail the claimant


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "b"),
        ("tenant_id", None),
        ("target_repo", "binary:///other"),
        ("triggered_by", "platform_admin"),
        ("job_type", "CLOUD"),
        ("target_branch", "other"),
        ("target_commit", "forged"),
        ("system_id", "foreign"),
        ("progress", {"scan_options": {"artifact_id": "forged"}}),
    ],
)
def test_forged_descriptor_cannot_probe_or_change_the_victim(execution, field, value):
    db, seen = execution
    row, job = queued(db)
    assert not JobExecutor().execute(replace(job, **{field: value}))
    db.expire_all()
    assert row.status == "QUEUED" and row.error_message is None
    assert seen == []


@pytest.mark.parametrize(
    "fault", ["disabled", "removed", "role", "membership", "viewer", "suspended", "replacement", "legacy"]
)
def test_live_initiating_authority_is_required_at_dequeue(execution, fault):
    db, seen = execution
    row, job = queued(db)
    user = db.execute(select(User).where(User.username == "bank_a")).scalar_one()
    if fault == "disabled":
        user.is_active = False
    elif fault == "removed":
        user.deleted_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    elif fault == "role":
        user.roles = "readonly"
    elif fault == "membership":
        db.query(TenantMembership).filter_by(username="bank_a").delete()
    elif fault == "viewer":
        db.query(TenantMembership).filter_by(username="bank_a").update({"tenant_role": "viewer"})
    elif fault == "suspended":
        db.get(Tenant, "a").status = "SUSPENDED"
    elif fault == "replacement":
        user.username = "old-bank-a"
        db.flush()
        db.add(User(username="bank_a", password_hash="unused", roles="security_analyst"))
    else:
        row.progress = {"scan_options": job.scan_options}
    db.commit()
    assert not JobExecutor().execute(job)
    assert seen == []
    db.expire_all()
    assert row.status == "FAILED"


def test_revocation_between_reconciliation_and_claim_is_not_cached(execution, monkeypatch):
    db, seen = execution
    row, job = queued(db)

    def revoke(*args, **kwargs):
        user = db.execute(select(User).where(User.username == "bank_a")).scalar_one()
        user.is_active = False
        db.commit()
        return True, None

    monkeypatch.setattr("worker.core.job_executor.gate_job", revoke)
    assert not JobExecutor().execute(job)
    assert not seen


@pytest.mark.parametrize("fault", [None, "revoked", "scope", "role", "duplicate", "replaced"])
def test_machine_authority_pins_key_incarnation_and_policy(execution, fault):
    db, seen = execution
    key, _ = ApiKeyRepository(db).create(name="bot", created_by="platform_admin", roles=["scanner"], tenant_id="a")
    db.commit()
    row, job = queued(db, actor="apikey:bot")
    if fault == "revoked":
        key.revoked_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    elif fault == "scope":
        key.scopes = "/events"
    elif fault == "role":
        key.roles = "readonly"
    elif fault == "duplicate":
        ApiKeyRepository(db).create(name="bot", created_by="platform_admin", roles=["scanner"], tenant_id="a")
    elif fault == "replaced":
        key.revoked_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        ApiKeyRepository(db).create(name="bot", created_by="platform_admin", roles=["scanner"], tenant_id="a")
    db.commit()
    assert JobExecutor().execute(job) is (fault is None)
    assert bool(seen) is (fault is None)


@pytest.mark.parametrize("disabled", [False, True])
def test_monitor_config_authority_remains_internal_but_must_be_current(execution, disabled):
    db, seen = execution
    config = RepoConfiguration(repo_url="binary:///approved/image", repo_name="repo", tenant_id="a", enabled=True)
    db.add(config)
    db.commit()
    row, job = queued(db, actor="monitor", job_type="MONITOR_REPOSITORY")
    assert row.progress["execution_authority"]["id"] == config.id
    config.enabled = not disabled
    db.commit()
    assert JobExecutor().execute(job) is (not disabled)
    assert bool(seen) is (not disabled)


def test_inline_execution_uses_the_same_descriptor_boundary(execution):
    db, seen = execution
    row, job = queued(db)
    payload = {**job.__dict__, "tenant_id": "b"}
    _run_inline(payload)
    assert not seen
    db.expire_all()
    assert row.status == "QUEUED"


def test_authority_store_outage_does_not_probe_or_write_using_queue_claims(execution, monkeypatch):
    db, seen = execution
    row, job = queued(db)

    def fail():
        raise RuntimeError("private-db-address")

    monkeypatch.setattr("db.connection.session.SessionLocal", fail)
    assert not JobExecutor().execute(job)
    assert not seen
    assert row.status == "QUEUED"


def test_object_form_producer_pins_live_authority_and_preserves_options(execution):
    db, seen = execution
    with tenant_scope("a"):
        row = JobRepository(db).create(
            JobRow(
                job_type="BINARY",
                target_repo="binary:///approved/image",
                target_branch="main",
                triggered_by="bank_a",
                status="QUEUED",
                progress={"scan_options": {"artifact_id": "approved"}},
            )
        )
        db.commit()
    assert row.progress["execution_authority"]["kind"] == "user"
    descriptor = ScanJob(
        job_id=row.id,
        **{
            key: getattr(row, key)
            for key in (
                "tenant_id",
                "target_repo",
                "target_branch",
                "target_commit",
                "triggered_by",
                "job_type",
                "system_id",
            )
        },
        progress=deepcopy(row.progress),
    )
    assert JobExecutor().execute(descriptor)
    assert seen == [("a", "RUNNING", {"artifact_id": "approved"})]


@pytest.mark.parametrize("fault", [None, "disabled"])
def test_human_named_monitor_does_not_gain_repository_configuration_authority(execution, fault):
    db, seen = execution
    user = User(username="monitor", password_hash="unused", roles="security_analyst")
    db.add_all(
        [
            user,
            TenantMembership(username="monitor", tenant_id="a", tenant_role="member"),
            RepoConfiguration(repo_url="binary:///approved/image", repo_name="repo", tenant_id="a", enabled=True),
        ]
    )
    db.commit()
    row, job = queued(db, actor="monitor")
    assert row.progress["execution_authority"] == {"v": 1, "kind": "user", "id": user.id}
    if fault:
        user.is_active = False
        db.commit()
    assert JobExecutor().execute(job) is (fault is None)
    assert bool(seen) is (fault is None)


@pytest.mark.parametrize("actor", ["scheduler:bank_a", "apikey:bot"])
def test_reserved_actor_namespace_collision_is_refused(execution, actor):
    db, seen = execution
    db.add(User(username=actor, password_hash="unused", roles="security_analyst"))
    if actor.startswith("apikey:"):
        ApiKeyRepository(db).create(name="bot", created_by="platform_admin", roles=["scanner"], tenant_id="a")
    db.commit()
    row, job = queued(db, actor=actor)
    assert "execution_authority" not in row.progress
    assert not JobExecutor().execute(job)
    assert not seen
