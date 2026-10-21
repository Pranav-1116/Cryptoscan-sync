"""SQL authority for controlled execution. No queue payload is a grant.

Public functions participate in the caller's transaction unless documented.
Expired/ambiguous attempts retain reservations until an operator confirms that
external work stopped. A timeout is not proof that a remote effect did not occur.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import secrets

from sqlalchemy import func, select, update
from db.models.base import utcnow
from db.models.execution_control import (
    EstateExecutionPolicy, ScanApproval, ExecutionBudget, ExecutionAttempt, ExecutionOutbox,
)
from db.models.scan_job import ScanJob

_request_principal = ContextVar("execution_request_principal", default=None)
_active_execution = ContextVar("controlled_execution", default=None)
_enforced_profile = ContextVar("enforced_execution_profile", default=False)


class ExecutionDenied(RuntimeError):
    """Refusal text is deliberately free of targets, secrets and foreign IDs."""


class BudgetBusy(ExecutionDenied):
    """No external work started: keep QUEUED and retry publication later."""


def required():
    # OS environment is the normal deployment contract. Honor the shared
    # dotenv/normalization rules too, rather than accidentally treating
    # ENVIRONMENT=prod or a dotenv-only deployment as development.
    if _enforced_profile.get():
        return True
    environment = os.getenv("ENVIRONMENT")
    enabled = os.getenv("CRYPTOSCAN_EXECUTION_CONTROLS", "").lower() in {"1", "true"}
    if environment is not None:
        return environment.strip().lower() in {"prod", "production"} or enabled
    from shared_config.base_settings import BaseSettings
    return BaseSettings().is_production or enabled


@contextmanager
def enforced_profile():
    token = _enforced_profile.set(True)
    try:
        yield
    finally:
        _enforced_profile.reset(token)


def aware(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def key(namespace, value):
    return hashlib.sha256(json.dumps([namespace, value], sort_keys=True).encode()).hexdigest()[:32]


@contextmanager
def request_principal(principal):
    token = _request_principal.set(principal)
    try:
        yield
    finally:
        _request_principal.reset(token)


def current_request_principal():
    return _request_principal.get()


def authenticated_principal(session, *, username=None, token=None, key_id=None, path="", method="", request_id="", client_ip=""):
    """Called only after HTTP authentication; record incarnation, never secret."""
    from db.models.user import User
    from db.models.api_key import ApiKey
    from db.repositories.user_repository import UserRepository

    common = {"v": 2, "path": path, "method": method, "request_id": request_id,
              "client_ip": client_ip}
    if key_id is not None:
        row = session.get(ApiKey, key_id)
        if row is None or not row.is_active_key:
            raise ExecutionDenied("Credential is no longer active")
        return {**common, "kind": "api_key", "id": row.id, "credential_id": row.id,
                "policy_digest": credential_digest(row)}
    user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
    credential = UserRepository(session).get_session(token) if token else None
    if user is None or not user.is_active or user.deleted_at or credential is None or credential.revoked_at or aware(credential.expires_at) <= utcnow() or credential.username != user.username or credential.user_id != user.id:
        raise ExecutionDenied("Durable authenticated credential is required")
    return {**common, "kind": "user", "id": user.id, "username": user.username,
            "credential_id": credential.id}


def credential_digest(row):
    policy = {name: str(getattr(row, name) or "") for name in
              ("key_hash", "roles", "scopes", "allowed_methods", "allowed_ips", "rate_per_minute")}
    policy["expires_at"] = aware(row.expires_at).isoformat() if row.expires_at else ""
    # A digest of a one-way verifier is NOT the raw credential/verifier.
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def typed_authority(session, job, pinned):
    """Fresh resolution by immutable ID. Actor strings never select identities."""
    from db.models.user import User, UserSession
    from db.models.api_key import ApiKey
    from db.models.repo_configuration import RepoConfiguration
    from db.models.tenant import Tenant, TenantMembership

    owner = job.tenant_id
    if pinned.get("estate") != owner:
        return None, []
    if owner is not None:
        tenant = session.get(Tenant, owner)
        if tenant is None or tenant.status != "ACTIVE":
            return None, []
    kind = pinned.get("kind")
    if kind == "repository":
        row = session.execute(select(RepoConfiguration).where(
            RepoConfiguration.id == pinned.get("id"), RepoConfiguration.tenant_id == owner,
            RepoConfiguration.repo_url == job.target_repo, RepoConfiguration.enabled.is_(True),
        )).scalar_one_or_none()
        valid_origin = job.job_type == "GITHUB_WEBHOOK" or (job.job_type == "MONITOR_REPOSITORY" and job.triggered_by == "monitor")
        if row and valid_origin and (job.job_type != "GITHUB_WEBHOOK" or row.scan_on_push and row.scan_on_pr):
            return pinned, []
        return None, []
    if kind == "api_key":
        row = session.execute(select(ApiKey).where(ApiKey.id == pinned.get("id"), ApiKey.tenant_id == owner)).scalar_one_or_none()
        if row and row.is_active_key and pinned.get("credential_id") == row.id and credential_digest(row) == pinned.get("policy_digest"):
            return pinned, row.role_list
        return None, []
    if kind != "user":
        return None, []
    user = session.get(User, pinned.get("id"))
    credential = session.get(UserSession, pinned.get("credential_id"))
    if user is None or not user.is_active or user.deleted_at or user.username != pinned.get("username") or credential is None or credential.username != user.username or credential.user_id != user.id or credential.revoked_at or aware(credential.expires_at) <= utcnow():
        return None, []
    roles = user.role_list
    platform = bool(set(roles) & {"admin", "superadmin"})
    if owner is not None and not platform:
        member = session.execute(select(TenantMembership).where(TenantMembership.tenant_id == owner, TenantMembership.username == user.username)).scalar_one_or_none()
        if member is None or member.tenant_role == "viewer":
            return None, []
    elif owner is None and not platform:
        return None, []
    return pinned, roles


def policy_for(session, owner, *, allow_stopped=False):
    policy = session.execute(select(EstateExecutionPolicy).where(EstateExecutionPolicy.tenant_id == owner, EstateExecutionPolicy.estate_key == key("estate", owner))).scalar_one_or_none()
    if policy is None or policy.stopped and not allow_stopped:
        raise ExecutionDenied("Estate execution policy is absent or stopped")
    if not allow_stopped:
        provider = session.execute(select(ExecutionBudget).where(ExecutionBudget.id == key("provider-budget", "local-source/v1"))).scalar_one_or_none()
        if provider is None or provider.capacity <= 0:
            raise ExecutionDenied("Shared provider execution is stopped or unprovisioned")
    for field, env in (("execution_region", "CRYPTOSCAN_EXECUTION_REGION"), ("evidence_region", "CRYPTOSCAN_EVIDENCE_REGION"), ("evidence_destination", "CRYPTOSCAN_EVIDENCE_DESTINATION")):
        if not os.getenv(env) or policy.contract[field] != os.getenv(env):
            raise ExecutionDenied("Execution/evidence destination is not approved on this node")
    return policy


def profile_for(target):
    # Qualified control adapter currently covers staged local source only.
    # Remote acquisition, binary/archive/import/report parsers and active
    # probes need their own bounded, no-secret adapter; never silently inherit
    # the source-parser container's isolation claim.
    if not target or "://" in target and not target.startswith(("local://", "file://")):
        raise ExecutionDenied("No controlled adapter for this target or acquisition method")
    return "local-source/v1"


def matching_approval(session, job, principal, *, approval_id=None, available_request=False):
    policy = policy_for(session, job.tenant_id)
    profile = profile_for(job.target_repo)
    if job.job_type not in {"MANUAL", "REPOSITORY", "SCHEDULED", "MONITOR_REPOSITORY", "GITHUB_WEBHOOK", "RETRY"}:
        raise ExecutionDenied("Job method has no controlled execution adapter")
    if job.target_commit:
        raise ExecutionDenied("Local staging cannot attest a requested Git commit")
    if (job.progress or {}).get("scan_options", {}).get("scan_mode") not in (None, "safe", "passive"):
        raise ExecutionDenied("Active/alternate methods are not covered by the local source profile")
    query = select(ScanApproval).where(ScanApproval.tenant_id == job.tenant_id, ScanApproval.revoked_at.is_(None))
    if approval_id is not None:
        query = query.where(ScanApproval.id == approval_id)
    matches = []
    now = utcnow()
    for approval in session.execute(query).scalars():
        c = approval.contract
        if available_request and approval.requests_used >= c["max_requests"]:
            continue
        if (approval.policy_revision == policy.revision and c["target"] == job.target_repo
                and c["profile"] == profile and c["subject_kind"] == principal["kind"] and c["subject_id"] == principal["id"]
                and aware(c["not_before"]) <= now < aware(c["expires_at"])):
            if principal["kind"] == "user" and principal["id"] == approval.approved_by:
                raise ExecutionDenied("Approver cannot execute their own approval")
            matches.append(approval)
    if len(matches) != 1:
        raise ExecutionDenied("Exactly one current positive approval is required; revoke overlapping revisions")
    return policy, matches[0]


def pin_controls(session, job, legacy_authority):
    """At the repository write boundary: pin trusted provenance and SQL outbox."""
    principal = _request_principal.get()
    if principal is None and legacy_authority and legacy_authority["kind"] == "repository":
        principal = {**legacy_authority, "v": 2, "credential_id": legacy_authority["id"], "request_id": key("internal-job", job.id)}
    if principal is None:
        if required():
            raise ExecutionDenied("Controlled enqueue requires typed authentication provenance")
        return
    principal = {**principal, "estate": job.tenant_id}
    authority, _roles = typed_authority(session, job, principal)
    if authority is None:
        raise ExecutionDenied("Initiating identity does not own this estate")
    progress = dict(job.progress or {})
    progress["execution_authority"] = principal
    job.progress = progress
    if required():
        policy, approval = matching_approval(session, job, principal, available_request=True)
        progress["execution_control"] = {"v": 1, "approval_id": approval.id, "policy_revision": policy.revision,
                                         "profile": approval.contract["profile"], "legal_entity": policy.contract["legal_entity"],
                                         "execution_region": policy.contract["execution_region"], "evidence_region": policy.contract["evidence_region"], "evidence_destination": policy.contract["evidence_destination"]}
        job.progress = progress
        session.add(ExecutionOutbox(job_id=job.id, tenant_id=job.tenant_id))
    session.flush()


def budget_clock(session):
    # Shared rate windows must not be reset by a fast/slow worker's wall clock.
    # PostgreSQL is the production authority; SQLite is the local test backend.
    if session.get_bind().dialect.name == "postgresql":
        return aware(session.scalar(select(func.clock_timestamp()))).timestamp()
    return float(session.scalar(select((func.julianday("now") - 2440587.5) * 86400)))


def _budget_change(session, budget_id, *, acquire=False, release=False, request=False):
    budget = session.execute(select(ExecutionBudget).where(ExecutionBudget.id == budget_id).execution_options(populate_existing=True)).scalar_one_or_none()
    if budget is None:
        raise ExecutionDenied("Shared execution budget has not been provisioned")
    if acquire and budget.active >= budget.capacity:
        raise BudgetBusy("Shared execution capacity is exhausted")
    times = list(budget.request_times or [])
    if request:
        now = budget_clock(session)
        times = [t for t in times if now - t < 1]
        if len(times) >= budget.requests_per_second:
            raise ExecutionDenied("Shared rolling request budget is exhausted")
        times.append(now)
    active = budget.active + int(acquire) - int(release)
    if active < 0:
        raise ExecutionDenied("Reservation accounting is inconsistent")
    result = session.execute(update(ExecutionBudget).execution_options(synchronize_session=False).where(ExecutionBudget.id == budget.id, ExecutionBudget.version == budget.version).values(
        version=budget.version + 1, active=active, request_times=times).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise BudgetBusy("Concurrent budget transition; no work was authorized")


def _fair_turn(session, job):
    """Durable least-recently-served estate turn, FIFO inside each estate.

    Provider/estate reservations are already acquired in sorted lock order in
    this transaction. Losing the scheduling turn rolls both reservations back.
    The ready set is bounded to the oldest 500 SQL-queued controlled jobs.
    Offline regions, revoked principals and estates at capacity are ineligible.
    """
    from db.tenancy import platform_scope
    from db.repositories.queued_authority import current_authority
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX
    provider = session.execute(select(ExecutionBudget).where(ExecutionBudget.id == key("provider-budget", "local-source/v1")).execution_options(populate_existing=True)).scalar_one()
    schedule = dict(provider.schedule or {})
    turns = dict(schedule.get("owners") or {})
    ready = {}
    with platform_scope():  # Internal scheduling only; no foreign row escapes.
        rows = session.execute(select(ScanJob).where(ScanJob.status == "QUEUED",
            ScanJob.progress["execution_control"]["profile"].as_string() == "local-source/v1"
        ).order_by(ScanJob.created_at, ScanJob.id).limit(500)).scalars()
        for candidate in rows:
            owner_key = key("estate", candidate.tenant_id)
            if owner_key in ready:
                continue
            try:
                principal, roles = current_authority(session, candidate)
                if principal is None or principal.get("v") != 2 or principal["kind"] != "repository" and not set(normalize_roles(roles)) & PERMISSION_MATRIX["scan.trigger"]:
                    continue
                matching_approval(session, candidate, principal, approval_id=candidate.progress["execution_control"]["approval_id"], available_request=True)
                budget = session.execute(select(ExecutionBudget).where(ExecutionBudget.id == key("estate-budget", candidate.tenant_id)).execution_options(populate_existing=True)).scalar_one_or_none()
                own_reservation = int(candidate.tenant_id == job.tenant_id)
                if budget is None or budget.active - own_reservation >= budget.capacity:
                    continue
                ready[owner_key] = candidate.id
            except ExecutionDenied:
                continue
    own = key("estate", job.tenant_id)
    chosen = min(ready, key=lambda owner: turns.get(owner, 0)) if ready else None
    if chosen != own or ready.get(own) != job.id:
        raise BudgetBusy("Another ready estate/job holds the next scheduling turn")
    if own not in turns and len(turns) >= 10000:
        raise ExecutionDenied("Provider scheduling state requires operator maintenance")
    sequence = int(schedule.get("sequence", 0)) + 1
    turns[own] = sequence
    changed = session.execute(update(ExecutionBudget).execution_options(synchronize_session=False).where(
        ExecutionBudget.id == provider.id, ExecutionBudget.version == provider.version
    ).values(schedule={"sequence": sequence, "owners": turns}, version=provider.version + 1))
    if changed.rowcount != 1:
        raise BudgetBusy("Concurrent scheduling turn changed")


def claim_attempt(session, job):
    """Called in the SAME SQL transaction as QUEUED→RUNNING CAS."""
    control = (job.progress or {}).get("execution_control")
    if control is None:
        if required():
            raise ExecutionDenied("Legacy job has no positive approval; explicit resubmission required")
        return None
    principal = (job.progress or {}).get("execution_authority") or {}
    if principal.get("v") != 2:
        raise ExecutionDenied("Typed execution provenance is required")
    policy, approval = matching_approval(session, job, principal, approval_id=control["approval_id"], available_request=True)
    if control["policy_revision"] != policy.revision:
        raise ExecutionDenied("Approval/policy revision changed")
    from db.repositories.queued_authority import current_authority
    authority, roles = current_authority(session, job)
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX
    if authority != principal or principal["kind"] != "repository" and not set(normalize_roles(roles)) & PERMISSION_MATRIX["scan.trigger"]:
        raise ExecutionDenied("Initiating authority no longer permits execution")
    budgets = sorted([key("estate-budget", job.tenant_id), key("provider-budget", "local-source/v1")])
    for budget in budgets:
        _budget_change(session, budget, acquire=True)
    _fair_turn(session, job)
    now = utcnow()
    attempt = ExecutionAttempt(job_id=job.id, tenant_id=job.tenant_id, approval_id=approval.id,
                               status="RUNNING", checkpoint="claimed", heartbeat_at=now,
                               deadline_at=min(aware(approval.contract["expires_at"]), now + timedelta(seconds=policy.contract["max_runtime_seconds"])),
                               budget_ids=budgets, fence=secrets.token_hex(32))
    session.add(attempt)
    session.flush()
    return {"id": attempt.id, "job_id": job.id, "owner": job.tenant_id, "fence": attempt.fence,
            "profile": approval.contract["profile"], "deadline_unix": aware(attempt.deadline_at).timestamp()}


@contextmanager
def execution_scope(attempt):
    token = _active_execution.set(attempt)
    try:
        yield
    finally:
        _active_execution.reset(token)


def active_execution():
    return _active_execution.get()


def checkpoint(stage, *, request=False):
    """Fresh stop, credential, revision, deadline and lease check (fail closed)."""
    active = active_execution()
    if active is None:
        if required():
            raise ExecutionDenied("Operation lacks a controlled execution lease")
        return
    from db.connection.session import SessionLocal
    with SessionLocal() as session:
        attempt = session.execute(select(ExecutionAttempt).where(ExecutionAttempt.id == active["id"], ExecutionAttempt.tenant_id == active["owner"], ExecutionAttempt.fence == active["fence"], ExecutionAttempt.status == "RUNNING")).scalar_one_or_none()
        job = session.execute(select(ScanJob).where(ScanJob.id == active["job_id"], ScanJob.tenant_id == active["owner"])).scalar_one_or_none()
        if attempt is None or job is None or job.status != "RUNNING" or utcnow() >= aware(attempt.deadline_at):
            raise ExecutionDenied("Execution lease is absent, fenced or expired")
        from db.repositories.queued_authority import current_authority
        principal, roles = current_authority(session, job)
        from api.security.rbac import normalize_roles, PERMISSION_MATRIX
        if principal is None or principal != (job.progress or {}).get("execution_authority") or principal["kind"] != "repository" and not set(normalize_roles(roles)) & PERMISSION_MATRIX["scan.trigger"]:
            raise ExecutionDenied("Execution authority was revoked")
        _policy, approval = matching_approval(session, job, principal, approval_id=attempt.approval_id)
        # Same global emergency/safe-scan policy as enqueue, not just the
        # estate's dedicated stop switch. Outage/denial terminates the adapter.
        from api.security.scan_admission import admit_scan
        admit_scan(asset=job.target_repo, scan_mode="safe")
        if request:
            changed = session.execute(update(ScanApproval).execution_options(synchronize_session=False).where(ScanApproval.id == approval.id,
                ScanApproval.tenant_id == active["owner"], ScanApproval.version == approval.version,
                ScanApproval.requests_used < approval.contract["max_requests"]).values(
                requests_used=ScanApproval.requests_used + 1, version=approval.version + 1))
            if changed.rowcount != 1:
                raise ExecutionDenied("Approval request/retry allowance is exhausted")
            for budget in sorted(attempt.budget_ids):
                _budget_change(session, budget, request=True)
        result = session.execute(update(ExecutionAttempt).execution_options(synchronize_session=False).where(ExecutionAttempt.id == attempt.id, ExecutionAttempt.tenant_id == active["owner"], ExecutionAttempt.status == "RUNNING", ExecutionAttempt.version == attempt.version, ExecutionAttempt.fence == active["fence"]).values(
            heartbeat_at=utcnow(), checkpoint=str(stage)[:80], version=attempt.version + 1))
        if result.rowcount != 1:
            raise ExecutionDenied("Execution checkpoint lost its fence")
        session.commit()


def finish_attempt(active, outcome):
    """An unsuccessful/ambiguous launcher retains capacity for reconciliation."""
    if active is None:
        return outcome
    from db.connection.session import SessionLocal
    with SessionLocal() as session:
        attempt = session.execute(select(ExecutionAttempt).where(ExecutionAttempt.id == active["id"], ExecutionAttempt.tenant_id == active["owner"], ExecutionAttempt.fence == active["fence"], ExecutionAttempt.status == "RUNNING")).scalar_one_or_none()
        if attempt is None:
            raise ExecutionDenied("Attempt was fenced; operator reconciliation required")
        job = session.execute(select(ScanJob).where(ScanJob.id == active["job_id"], ScanJob.tenant_id == active["owner"])).scalar_one_or_none()
        # A collector's truthy return is not a durable completion receipt.
        outcome = bool(outcome and job is not None and job.status == "COMPLETED" and job.scan_id)
        if outcome:
            from db.models.scan import Scan
            receipt = session.execute(select(Scan).where(Scan.id == job.scan_id,
                Scan.tenant_id == active["owner"], Scan.target_location == job.target_repo,
                Scan.status == "COMPLETED")).scalar_one_or_none()
            outcome = receipt is not None
        terminal = "SUCCEEDED" if outcome else "UNKNOWN"
        changed = session.execute(update(ExecutionAttempt).execution_options(synchronize_session=False).where(ExecutionAttempt.id == attempt.id, ExecutionAttempt.tenant_id == active["owner"], ExecutionAttempt.version == attempt.version, ExecutionAttempt.status == "RUNNING").values(status=terminal, version=attempt.version + 1))
        if changed.rowcount != 1:
            raise ExecutionDenied("Attempt completion lost a concurrent transition")
        if outcome:
            for budget in sorted(attempt.budget_ids):
                _budget_change(session, budget, release=True)
        else:
            session.execute(update(ScanJob).execution_options(synchronize_session=False).where(ScanJob.id == active["job_id"], ScanJob.tenant_id == active["owner"]).values(status="UNKNOWN", version=ScanJob.version + 1, error_message="Execution outcome requires operator reconciliation"))
        session.commit()
        return outcome


def recover_expired(session, *, now=None):
    """Fence timed-out attempts. NEVER release their slots or restart work."""
    now = now or utcnow()
    count = 0
    rows = session.execute(select(ExecutionAttempt).where(ExecutionAttempt.status == "RUNNING", ExecutionAttempt.deadline_at <= now)).scalars().all()
    for row in rows:
        changed = session.execute(update(ExecutionAttempt).execution_options(synchronize_session=False).where(ExecutionAttempt.id == row.id, ExecutionAttempt.tenant_id == row.tenant_id, ExecutionAttempt.status == "RUNNING", ExecutionAttempt.version == row.version).values(status="UNKNOWN", version=row.version + 1))
        if changed.rowcount == 1:
            session.execute(update(ScanJob).execution_options(synchronize_session=False).where(ScanJob.id == row.job_id, ScanJob.tenant_id == row.tenant_id).values(status="UNKNOWN", version=ScanJob.version + 1, error_message="Execution lease expired; external outcome is unknown"))
            count += 1
    return count


def settle_unknown(session, attempt, *, resolution):
    """Caller must authenticate an operator, exact-owner and evidence receipt."""
    if resolution not in {"CONFIRMED_STOPPED", "CONFIRMED_COMPLETED"}:
        raise ExecutionDenied("Explicit external-state confirmation is required")
    changed = session.execute(update(ExecutionAttempt).execution_options(synchronize_session=False).where(ExecutionAttempt.id == attempt.id, ExecutionAttempt.tenant_id == attempt.tenant_id, ExecutionAttempt.status == "UNKNOWN", ExecutionAttempt.version == attempt.version).values(status="RESOLVED", checkpoint=resolution, version=attempt.version + 1))
    if changed.rowcount != 1:
        raise ExecutionDenied("Attempt is not unresolved or changed concurrently")
    for budget in sorted(attempt.budget_ids):
        _budget_change(session, budget, release=True)
    # Do not manufacture completed findings or mutate the old job into QUEUED.
    session.execute(update(ScanJob).execution_options(synchronize_session=False).where(ScanJob.id == attempt.job_id, ScanJob.tenant_id == attempt.tenant_id).values(status="FAILED", version=ScanJob.version + 1, error_message="Unknown outcome reconciled; any new work requires a new approved job"))
