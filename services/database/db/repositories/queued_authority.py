"""Database-backed enqueue/dequeue actor identity, without caller-supplied grants."""

import hashlib
import json
from sqlalchemy import select
from db.models.user import User
from db.models.tenant import Tenant, TenantMembership
from db.models.api_key import ApiKey
from db.models.repo_configuration import RepoConfiguration


def current_authority(session, job):
    pinned = (job.progress or {}).get("execution_authority") or {}
    if pinned.get("v") == 2:
        from db.repositories.execution_control import typed_authority
        return typed_authority(session, job, pinned)
    owner = job.tenant_id
    if owner is not None:
        tenant = session.get(Tenant, owner)
        if tenant is None or tenant.status != "ACTIVE":
            return None, []
    actor = job.triggered_by
    # Only a persisted internal origin can use configuration authority. A
    # descriptor cannot turn a human job into a monitor/webhook job.
    if job.job_type == "GITHUB_WEBHOOK" or (job.job_type == "MONITOR_REPOSITORY" and actor == "monitor"):
        config = session.execute(
            select(RepoConfiguration).where(
                RepoConfiguration.tenant_id == owner,
                RepoConfiguration.repo_url == job.target_repo,
                RepoConfiguration.enabled.is_(True),
            )
        ).scalar_one_or_none()
        # Both event switches must remain enabled for legacy webhook rows
        # which did not record the event kind. Conservative, not a bypass.
        if config is None or job.job_type == "GITHUB_WEBHOOK" and not (config.scan_on_push and config.scan_on_pr):
            return None, []
        return {"v": 1, "kind": "repository", "id": config.id}, []
    if actor.startswith(("scheduler:", "apikey:")):
        # Legacy string namespaces must not turn a real human whose literal
        # username has a reserved prefix into a different user or API key.
        # Ambiguity fails closed until typed request provenance is introduced.
        if session.execute(select(User.id).where(User.username == actor)).first() is not None:
            return None, []
    if actor.startswith("scheduler:"):
        actor = actor[len("scheduler:") :]
    if actor.startswith("apikey:"):
        rows = list(
            session.execute(
                select(ApiKey).where(
                    ApiKey.name == actor[len("apikey:") :],
                    ApiKey.tenant_id == owner,
                )
            ).scalars()
        )
        active = [row for row in rows if row.is_active_key]
        if len(active) != 1:
            return None, []
        row = active[0]
        policy = {
            key: str(getattr(row, key) or "")
            for key in ("roles", "scopes", "allowed_methods", "allowed_ips", "expires_at")
        }
        from shared_models.chrono import aware

        policy["expires_at"] = aware(row.expires_at).isoformat() if row.expires_at else ""
        digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
        return {"v": 1, "kind": "api_key", "id": row.id, "policy_digest": digest}, row.role_list
    user = session.execute(select(User).where(User.username == actor)).scalar_one_or_none()
    if user is None or not user.is_active or user.deleted_at is not None:
        return None, []
    roles = user.role_list
    if owner is not None:
        # Platform operators may explicitly enqueue in a bank; ordinary users
        # still need a current membership. A viewer cannot initiate writes.
        membership = session.execute(
            select(TenantMembership).where(
                TenantMembership.tenant_id == owner,
                TenantMembership.username == actor,
            )
        ).scalar_one_or_none()
        platform = bool(set(roles) & {"admin", "superadmin"})
        if not platform and (membership is None or membership.tenant_role == "viewer"):
            return None, []
    elif not set(roles) & {"admin", "superadmin"}:
        return None, []
    return {"v": 1, "kind": "user", "id": user.id}, roles


def pin_authority(session, job):
    """Capture incarnation IDs on new repository-created queue records.

    Missing legacy authority is not invented. Dequeue rechecks it and refuses
    unresolved actors; no environment-admin or literal 'system' bypass exists.
    """
    if job.status != "QUEUED":
        return
    authority, _ = current_authority(session, job)
    if authority is not None:
        progress = dict(job.progress or {})
        progress["execution_authority"] = authority
        job.progress = progress
    from db.repositories.execution_control import pin_controls
    pin_controls(session, job, authority)
