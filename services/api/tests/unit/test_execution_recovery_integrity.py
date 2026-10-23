"""Durable recovery contracts using real sessions/SQL; collectors/Redis are doubles.

These checks do not establish process-kill, daemon, real Redis/PostgreSQL or site
qualification. Source of authority remains SQL, not transport acknowledgements.
"""
from copy import deepcopy
from datetime import timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import select, update

from db.connection.session import SessionLocal
from db.models.base import utcnow
from db.models.execution_control import ExecutionAttempt, ExecutionBudget, ExecutionControlEvent, ExecutionOutbox
from db.models.scan_job import ScanJob
from db.repositories import execution_control as controls
from db.repositories.execution_outbox import dispatch_one, dispatch_pending
from db.repositories.job_repository import JobRepository
from db.tenancy import tenant_scope
from worker.core.job_consumer import JobConsumer
from worker.core.job_executor import JobExecutor
from worker.core.job_reaper import fail_job, reap_stale_jobs
from worker.core.queued_authority import QueueRefused, claim
from test_execution_controls import PREFIX, approve, configure, queue
from test_execution_controls import controlled as controlled
from test_software_supply_chain_api import banks as banks


def start(state):
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    with tenant_scope("a"):
        active = claim(descriptor)
    return row.id, descriptor, active


def snapshot(job_id):
    """Always inspect committed state through a new session, not a cached row."""
    with SessionLocal() as db:
        job = db.get(ScanJob, job_id)
        attempt = db.execute(select(ExecutionAttempt).where(ExecutionAttempt.job_id == job_id)).scalar_one()
        return {
            "job": (job.status, job.version, deepcopy(job.progress), job.scan_id, job.error_message),
            "attempt": (attempt.status, attempt.version, attempt.checkpoint),
            "budgets": sorted((b.id, b.active, b.version) for b in db.query(ExecutionBudget)),
        }


def expire():
    with tenant_scope("a"), SessionLocal() as db:
        count = controls.recover_expired(db, now=utcnow() + timedelta(hours=1))
        db.commit()
        return count


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_interrupt_persists_unknown_and_duplicate_never_relaunches(controlled, interruption):
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    executor = JobExecutor()
    calls = []

    def abort(**kwargs):
        calls.append(kwargs["job_id"])
        controls.checkpoint("before-interruption", request=True)
        raise interruption("synthetic parser interruption")

    executor.runner.run = abort
    with pytest.raises(interruption, match="synthetic parser interruption"):
        executor.execute(descriptor)
    persisted = snapshot(row.id)
    assert persisted["job"][0] == persisted["attempt"][0] == "UNKNOWN"
    assert all(active == 1 for _, active, _ in persisted["budgets"])
    assert controls.active_execution() is None
    assert not executor.execute(descriptor) and calls == [row.id]
    assert snapshot(row.id) == persisted
    with tenant_scope("a"), pytest.raises(QueueRefused):
        claim(descriptor)
    assert snapshot(row.id) == persisted


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_cleanup_outage_preserves_original_interrupt_until_deadline_recovery(controlled, monkeypatch, interruption):
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    executor = JobExecutor()
    executor.runner.run = Mock(side_effect=interruption("original interruption"))
    with monkeypatch.context() as patch:
        patch.setattr(controls, "finish_attempt", Mock(side_effect=OSError("SQL unavailable")))
        with pytest.raises(interruption, match="original interruption"):
            executor.execute(descriptor)
    assert controls.active_execution() is None
    persisted = snapshot(row.id)
    assert persisted["job"][0] == persisted["attempt"][0] == "RUNNING"
    assert all(active == 1 for _, active, _ in persisted["budgets"])
    assert expire() == 1
    unknown = snapshot(row.id)
    assert unknown["job"][0] == unknown["attempt"][0] == "UNKNOWN"
    assert not executor.execute(descriptor)
    assert executor.runner.run.call_count == 1


@pytest.mark.parametrize("state_name", ["RUNNING", "UNKNOWN", "RESOLVED"])
def test_duplicate_dead_letter_is_not_sql_execution_authority(controlled, state_name):
    job_id, descriptor, active = start(controlled)
    if state_name != "RUNNING":
        assert expire() == 1
    if state_name == "RESOLVED":
        reconcile(controlled, active)
    before = snapshot(job_id)
    with SessionLocal() as db:
        fail_job(db, job_id, "duplicate Redis delivery exhausted")
    assert snapshot(job_id) == before
    assert not JobExecutor().execute(descriptor)


def test_queued_controlled_dead_letter_keeps_sql_outbox_recovery_possible(controlled):
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    delivered = []
    assert dispatch_one(row.id, delivered.append)
    with SessionLocal() as db:
        fail_job(db, row.id, "transport duplicate exhausted")
    with SessionLocal() as db:
        job = db.get(ScanJob, row.id)
        assert job.status == "QUEUED"
        job.updated_at = utcnow() - timedelta(hours=1)
        db.commit()
    with SessionLocal() as db:
        stats = reap_stale_jobs(db, queued_ids=set(), publish=None)
        assert stats == {"failed_running": 0, "requeued": 0, "failed_queued": 0}
    assert dispatch_pending(delivered.append) == 1
    assert len(delivered) == 2
    with tenant_scope("a"):
        claim(descriptor)
        with pytest.raises(QueueRefused):
            claim(descriptor)
    with SessionLocal() as db:
        assert db.query(ExecutionAttempt).count() == 1
        assert all(b.active == 1 for b in db.query(ExecutionBudget))


def reconcile(state, active, **changes):
    body = {"resolution": "CONFIRMED_STOPPED", "evidence_ref": "incident/verified-external-stop",
            "confirm_external_work_stopped": True, **changes}
    return state["clients"]["platform_admin"].post(
        PREFIX + f"/attempts/{active['id']}/reconcile", headers={"X-Tenant-ID": "a"}, json=body)


@pytest.mark.parametrize("resolution", ["CONFIRMED_STOPPED", "CONFIRMED_COMPLETED"])
def test_fresh_session_recovery_and_reconciliation_release_once_without_fabricating_results(controlled, resolution):
    job_id, descriptor, active = start(controlled)
    assert expire() == 1
    unknown = snapshot(job_id)
    assert expire() == 0
    assert snapshot(job_id) == unknown
    with tenant_scope("a"), controls.execution_scope(active), pytest.raises(controls.ExecutionDenied):
        controls.checkpoint("late-worker")
    with tenant_scope("a"), pytest.raises(controls.ExecutionDenied):
        controls.finish_attempt(active, True)
    assert snapshot(job_id) == unknown
    response = reconcile(controlled, active, resolution=resolution)
    assert response.status_code == 200, response.text
    settled = snapshot(job_id)
    assert settled["attempt"][0] == "RESOLVED"
    assert settled["job"][0] == "FAILED" and settled["job"][3] is None
    assert all(active == 0 for _, active, _ in settled["budgets"])
    assert reconcile(controlled, active, resolution=resolution).status_code == 409
    with SessionLocal() as db:
        assert db.query(ExecutionControlEvent).filter_by(action="OUTCOME_RECONCILED").count() == 1
        assert db.query(ExecutionAttempt).count() == 1
    assert not JobExecutor().execute(descriptor)
    assert snapshot(job_id) == settled


@pytest.mark.parametrize("changes", [
    {"evidence_ref": ""}, {"confirm_external_work_stopped": False}, {"resolution": "RETRY"},
])
def test_invalid_reconciliation_never_releases_unknown_reservations(controlled, changes):
    job_id, _descriptor, active = start(controlled)
    assert expire() == 1
    before = snapshot(job_id)
    assert reconcile(controlled, active, **changes).status_code == 422
    assert snapshot(job_id) == before


def test_outbox_publish_failure_never_acknowledges_a_memory_only_delivery(controlled, monkeypatch):
    from worker.core import job_consumer
    from queue import Queue
    state = controlled
    configure(state)
    approve(state)
    row, _descriptor = queue(state)
    memory = Queue()
    monkeypatch.setattr(job_consumer, "_MEMORY_QUEUE", memory)
    client = Mock()
    client.rpush.side_effect = OSError("synthetic Redis outage")
    monkeypatch.setattr(JobConsumer, "_connect_redis", lambda self: setattr(self, "redis_client", client))
    consumer = JobConsumer(redis_url="rediss://test.invalid", allow_memory_fallback=False)
    with pytest.raises(RuntimeError):
        dispatch_one(row.id, consumer.enqueue)
    with SessionLocal() as db:
        outbox = db.query(ExecutionOutbox).one()
        assert outbox.state == "PENDING" and outbox.lease_until is None
        assert db.get(ScanJob, row.id).status == "QUEUED"
        assert db.query(ExecutionAttempt).count() == 0
    assert memory.empty()
    delivered = []
    assert dispatch_pending(delivered.append) == 1 and len(delivered) == 1


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_actual_publish_then_interruption_recovers_lease_and_duplicate_is_nonexecutable(controlled, interruption):
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    delivered = []

    def interrupted_ack(payload):
        delivered.append(payload)
        raise interruption("crash after external publish")

    with pytest.raises(interruption):
        dispatch_one(row.id, interrupted_ack)
    with SessionLocal() as db:
        outbox = db.query(ExecutionOutbox).one()
        assert outbox.state == ("PENDING" if interruption is RuntimeError else "PUBLISHING")
        assert db.get(ScanJob, row.id).status == "QUEUED"
        db.execute(update(ExecutionOutbox).where(ExecutionOutbox.id == outbox.id).values(
            lease_until=utcnow() - timedelta(seconds=1)))
        db.commit()
    assert dispatch_pending(delivered.append) == 1 and len(delivered) == 2
    assert delivered[0] == delivered[1]
    with tenant_scope("a"):
        claim(descriptor)
        with pytest.raises(QueueRefused):
            claim(descriptor)
    assert snapshot(row.id)["attempt"][0] == "RUNNING"


def test_stale_worker_repository_cannot_overwrite_durable_unknown(controlled):
    job_id, _descriptor, active = start(controlled)
    with tenant_scope("a"), SessionLocal() as stale:
        cached = stale.get(ScanJob, job_id)
        assert cached.status == "RUNNING"
        assert expire() == 1
        before = snapshot(job_id)
        assert JobRepository(stale).update_status(job_id, "COMPLETED", scan_id="not-a-receipt") is None
        stale.commit()
    assert snapshot(job_id) == before


def test_interrupted_reaper_transaction_has_no_partial_unknown_verdict(controlled):
    job_id, _descriptor, active = start(controlled)
    before = snapshot(job_id)
    with tenant_scope("a"), SessionLocal() as db:
        assert controls.recover_expired(db, now=utcnow() + timedelta(hours=1)) == 1
        # Simulate process/transaction loss before commit: Session.close rolls back.
    assert snapshot(job_id) == before
    assert expire() == 1
    assert snapshot(job_id)["attempt"][0] == "UNKNOWN"
    assert expire() == 0


def test_reconciliation_budget_failure_rolls_back_attempt_and_both_reservations(controlled, monkeypatch):
    job_id, _descriptor, active = start(controlled)
    assert expire() == 1
    before = snapshot(job_id)
    original = controls._budget_change
    releases = []

    def fault_after_first_release(db, budget_id, **kwargs):
        if kwargs.get("release"):
            releases.append(budget_id)
            if len(releases) == 2:
                raise controls.ExecutionDenied("Synthetic concurrent reservation transition")
        return original(db, budget_id, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(controls, "_budget_change", fault_after_first_release)
        assert reconcile(controlled, active).status_code == 409
    assert len(releases) == 2
    assert snapshot(job_id) == before
    with SessionLocal() as db:
        assert db.query(ExecutionControlEvent).filter_by(action="OUTCOME_RECONCILED").count() == 0
    assert reconcile(controlled, active).status_code == 200
    assert all(active == 0 for _, active, _ in snapshot(job_id)["budgets"])


def test_actual_orphan_dead_letter_does_not_fence_a_healthy_sql_attempt(controlled, monkeypatch):
    import json
    from dataclasses import asdict
    import fakeredis

    job_id, descriptor, _active = start(controlled)
    before = snapshot(job_id)
    server = fakeredis.FakeServer()
    monkeypatch.setattr(JobConsumer, "_connect_redis", lambda self: None)

    def dead_letter(payload, reason):
        with SessionLocal() as db:
            fail_job(db, payload["job_id"], reason)

    consumer = JobConsumer(redis_url="", worker_id="recoverer", max_redeliveries=0,
                           on_dead_letter=dead_letter)
    consumer.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    orphan_key = consumer._processing_prefix() + "old-delivery"
    consumer.redis_client.rpush(orphan_key, json.dumps(asdict(descriptor)))
    assert consumer.recover_orphans() == {"requeued": 0, "dead_lettered": 1, "workers": 1}
    assert consumer.redis_client.llen(consumer.dead_letter_key) == 1
    assert snapshot(job_id) == before
