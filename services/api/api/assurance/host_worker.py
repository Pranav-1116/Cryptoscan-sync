"""Development-only local host-worker lifecycle on the existing target ledger.

No Redis authority, automatic stale-claim takeover, hidden signing key, remote
host assertion, or production adapter. Every checkpoint reopens DB authority.
"""

import hashlib
import os
import secrets
from types import SimpleNamespace
from fastapi import HTTPException
from api.assurance import collection as core, store
from api.security.rbac import PERMISSION_MATRIX, normalize_roles
from db.models.assurance import AssuranceBlob
from db.repositories.queued_authority import current_authority
from db.repositories.control_plane_repository import ControlPlaneRepository
from shared_models.host_collection import HostSnapshot, digest
from shared_models.host_worker import LocalWorkerBinding
from shared_models.chrono import utcnow
from control_plane import safety


def authority(db, owner, username, pinned=None):
    pinned = pinned or {**(store.current_request_principal() or {}), "estate": owner}
    trusted = {k: v for k, v in pinned.items() if k != "roles"}
    if trusted.get("v") != 2 or trusted.get("username") != username:
        raise HTTPException(409, "Typed worker credential is required")
    principal, roles = current_authority(
        db,
        SimpleNamespace(
            tenant_id=owner,
            triggered_by=username,
            progress={"execution_authority": trusted},
            job_type="HOST_COLLECTION",
        ),
    )
    roles = sorted(normalize_roles(roles))
    if principal is None or principal.get("kind") != "user" or not set(roles) & PERMISSION_MATRIX["assurance.manage"]:
        raise HTTPException(409, "Worker initiating human authority revoked")
    return {**principal, "roles": roles}


def current(db, owner, row):
    _, _, target = core.resolve_job(db, owner, row.subject_id)
    spec = core.admitted(db, owner, target, row.payload["target_revision"])
    approval = store.latest(db, owner, "host_approval", row.payload["approval_id"])
    if not approval.payload.get("worker"):
        raise HTTPException(409, "No approved local worker binding")
    pinned = row.payload.get("worker_authority")
    if pinned and authority(db, owner, row.payload["worker_actor"], pinned) != pinned:
        raise HTTPException(409, "Worker human authority changed")
    policy = ControlPlaneRepository(db).matching_policy(
        environment=spec.environment, region=os.getenv("CRYPTOSCAN_EXECUTION_REGION")
    )
    if not safety.evaluate_scan(policy.to_dict() if policy else None, asset=spec.address).permitted:
        raise HTTPException(409, "Worker policy stop is active")
    # Identity/residency are checked on every admission, not just HTTP enqueue.
    store.residency(db, owner)
    return target, spec, approval


def locked(db, owner, identifier):
    row = core.chain(db, owner, core.JOB, identifier)[-1]
    core.lock_target(db, owner, row.payload["target_id"])
    return core.chain(db, owner, core.JOB, identifier)[-1]


def enqueue(db, owner, identifier, expected, actor, user):
    core.boundary()

    def operation():
        row = locked(db, owner, identifier)
        if row.revision != expected or row.payload["state"] != "READY":
            raise HTTPException(409, "Worker job is not ready")
        _, spec, approval = current(db, owner, row)
        if spec.manifest.platform != "linux":
            raise HTTPException(409, "Native Windows worker is not qualified")
        principal = authority(db, owner, user)
        if principal["id"] != actor:
            raise HTTPException(409, "Worker actor incarnation mismatch")
        result = core.save(
            db,
            owner,
            core.JOB,
            identifier,
            row.revision,
            {
                **row.payload,
                "state": "QUEUED",
                "worker_actor": user,
                "worker_actor_id": actor,
                "execution_basis": "ISOLATED_LOCAL_WORKER_NOT_REMOTE_HOST",
                "worker_authority": principal,
                "worker_binding": approval.payload["worker"],
            },
            actor,
            user,
            "worker.enqueue",
        )
        return store.public(result)

    return core.atomic(operation, db)


def cancel(db, owner, identifier, expected, actor, user):
    core.boundary()

    def operation():
        row = locked(db, owner, identifier)
        if (
            row.revision != expected
            or row.payload["state"] not in {"QUEUED", "RUNNING", "AWAITING_EVIDENCE"}
            or not row.payload.get("worker_binding")
        ):
            raise HTTPException(409, "Worker job cannot be cancelled")
        return store.public(
            core.save(
                db,
                owner,
                core.JOB,
                identifier,
                row.revision,
                {**row.payload, "state": "CANCELLED"},
                actor,
                user,
                "worker.cancel",
            )
        )

    return core.atomic(operation, db)


def binding_matches(binding, target, spec, approval):
    pin = approval.payload.get("worker")
    if (
        target.subject_id != binding.target_id
        or spec.system_id != binding.system_id
        or spec.manifest.host_id != binding.host_id
        or pin != {"binding_id": binding.binding_id, "source_lock_sha256": binding.source_lock_sha256}
    ):
        raise HTTPException(409, "Worker local binding does not match current approval")
    # The envelope signing key can differ from the source-release signing key.
    if approval.payload.get("collector_identity", {}).get("release_sha256") != binding.source_lock_sha256:
        raise HTTPException(409, "Worker release approval mismatch")


def claim(db, binding, identifier, token):
    core.boundary()

    def operation():
        row = locked(db, binding.tenant_id, identifier)
        if row.payload["state"] != "QUEUED":
            raise HTTPException(409, "Worker job already claimed or not queued")
        target, spec, approval = current(db, binding.tenant_id, row)
        binding_matches(binding, target, spec, approval)
        value = {
            **row.payload,
            "state": "RUNNING",
            "claim_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "claimed_at": utcnow().isoformat(),
        }
        core.save(
            db,
            binding.tenant_id,
            core.JOB,
            identifier,
            row.revision,
            value,
            row.payload["worker_actor_id"],
            row.payload["worker_actor"],
            "worker.claim",
        )
        return spec

    return core.atomic(operation, db)


def running(db, binding, identifier, token, *, lock=False):
    core.boundary()
    row = (
        locked(db, binding.tenant_id, identifier)
        if lock
        else core.chain(db, binding.tenant_id, core.JOB, identifier)[-1]
    )
    if row.payload["state"] != "RUNNING" or not secrets.compare_digest(
        row.payload.get("claim_sha256", ""), hashlib.sha256(token.encode()).hexdigest()
    ):
        raise HTTPException(409, "Worker claim is no longer current")
    target, spec, approval = current(db, binding.tenant_id, row)
    binding_matches(binding, target, spec, approval)
    return row, spec


def finish(db, binding, identifier, token, snapshot, isolation, release):
    def operation():
        row, _ = running(db, binding, identifier, token, lock=True)
        data = store.encoded(snapshot.model_dump(mode="json"))
        if len(data) > 1048576:
            raise HTTPException(409, "Worker result exceeds durable artifact bound")
        blob = AssuranceBlob(
            tenant_id=binding.tenant_id,
            scope_key=store.scope_key(binding.tenant_id),
            data=data,
            byte_count=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_by=row.payload["worker_actor_id"],
        )
        db.add(blob)
        db.flush()
        return store.public(
            core.save(
                db,
                binding.tenant_id,
                core.JOB,
                identifier,
                row.revision,
                {
                    **row.payload,
                    "state": "AWAITING_EVIDENCE",
                    "worker_snapshot_sha256": digest(snapshot),
                    "worker_snapshot_blob_id": blob.id,
                    "worker_snapshot_blob_sha256": blob.sha256,
                    "worker_isolation": isolation,
                    "worker_release": release,
                    "production_execution_qualified": False,
                },
                row.payload["worker_actor_id"],
                row.payload["worker_actor"],
                "worker.collected",
            )
        )

    return core.atomic(operation, db)


def refuse(db, binding, identifier, token):
    # Never overwrite cancellation, superseding approval, or a newer worker claim.
    def operation():
        row = locked(db, binding.tenant_id, identifier)
        if row.payload.get("state") == "RUNNING" and secrets.compare_digest(
            row.payload.get("claim_sha256", ""), hashlib.sha256(token.encode()).hexdigest()
        ):
            core.save(
                db,
                binding.tenant_id,
                core.JOB,
                identifier,
                row.revision,
                {**row.payload, "state": "REFUSED", "worker_reason": "COLLECTION_OR_AUTHORITY_REFUSED"},
                row.payload["worker_actor_id"],
                row.payload["worker_actor"],
                "worker.refused",
            )

    core.atomic(operation, db)


def admit_result(db, owner, approval, snapshot):
    # Original intake locks this target before this check. It cannot race a
    # target cancellation or worker result publication protected by that mutex.
    row = core.chain(
        db,
        owner,
        core.JOB,
        store.subject(
            "collection-job/v1", store.scope_key(owner), approval.payload["collection_target_id"], approval.subject_id
        ),
    )[-1]
    if (
        row.payload.get("state") != "AWAITING_EVIDENCE"
        or row.payload.get("approval_id") != approval.subject_id
        or row.payload.get("worker_snapshot_sha256") != digest(snapshot)
    ):
        raise HTTPException(409, "Snapshot is not the current approved worker result")


def run_local(session_factory, binding: LocalWorkerBinding, identifier, source_root, lock_bytes, signature):
    """Collect once; return unsigned public handoff for an EXTERNAL signer."""
    from db.tenancy import tenant_scope
    from inventory.collector_release import verified_stage
    from inventory.isolation import collect_isolated

    token = secrets.token_hex(32)

    def session_call(fn):
        with tenant_scope(binding.tenant_id), session_factory() as db:
            return fn(db)

    # Wrong release/binding never consumes a durable claim.
    with verified_stage(source_root, lock_bytes, signature, binding.release_public_key, binding.source_lock_sha256) as (
        stage,
        release,
    ):
        spec = session_call(lambda db: claim(db, binding, identifier, token))
        try:
            snapshot, isolation = collect_isolated(
                spec,
                checkpoint=lambda: session_call(lambda db: running(db, binding, identifier, token)),
                stage_root=stage,
            )
            session_call(lambda db: finish(db, binding, identifier, token, snapshot, isolation, release))
        except BaseException:
            session_call(lambda db: refuse(db, binding, identifier, token))
            raise
    # No new intake path: the prepared snapshot still needs the approved
    # collector identity proof and normal API admission/verification.
    return HostSnapshot.model_validate(snapshot.model_dump(mode="json"))
