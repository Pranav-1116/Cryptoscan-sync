"""Phase 1 registry/job/envelope adapter over existing evidence, not a second DB.

Offline execution is NEVER performed by these HTTP handlers. Completion references
one existing approved intake; source revalidation precedes every materialization.
"""

from fastapi import HTTPException
from datetime import timedelta
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.system import System
from db.repositories.execution_control import required
from db.repositories.user_repository import UserRepository
from shared_models.collection import TargetSpec, Observation, CollectionResult
from shared_models.host_collection import digest
from api.assurance import store

TARGET, JOB = "collection_target", "collection_job"
LIMIT = 100


def boundary():
    if required():
        raise HTTPException(409, "Universal collection production adapter is not qualified")


def chain(db, owner, kind, identifier):
    rows = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind=kind, subject_id=identifier)
        .order_by(AssuranceRevision.revision)
        .limit(LIMIT + 1)
        .all()
    )
    if not rows:
        raise HTTPException(404, "Collection record not found")
    if len(rows) > LIMIT:
        raise HTTPException(409, "Collection history exceeds complete verification budget")
    previous = None
    for index, row in enumerate(rows, 1):
        store.verify(row)
        if row.revision != index or row.previous_sha256 != previous:
            raise HTTPException(409, "Collection revision chain is incomplete")
        previous = row.payload_sha256
    return rows


def lock_target(db, owner, identifier):
    # All admission/withdrawal paths share the immutable first row as mutex.
    row = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind=TARGET, subject_id=identifier, revision=1)
        .with_for_update()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Collection target not found")


def save(db, owner, kind, identifier, expected, payload, actor, user, action):
    if expected >= LIMIT:
        raise HTTPException(409, "Collection revision budget exhausted")
    row = store.append(db, owner, kind, identifier, expected, payload, actor, commit=False)
    UserRepository(db).audit(
        user,
        "collection." + action,
        target_type=kind,
        target_id=identifier,
        detail={
            "scope_key": row.scope_key,
            "revision": row.revision,
            "payload_sha256": row.payload_sha256,
            "actor_id": actor,
        },
    )
    return row


def atomic(operation, db):
    try:
        value = operation()
        db.commit()
        return value
    except Exception:
        db.rollback()
        raise


def supported(spec):
    if spec.collection_method != "offline_host" or not spec.manifest or spec.manifest.platform != "linux":
        raise HTTPException(409, "Collector is registered as a future capability, not an executable adapter")


def register(db, owner, spec, actor, user, *, identifier=None, expected=0):
    boundary()
    store.exact(db, System, owner, spec.system_id)
    key = store.subject("collection-target/v1", store.scope_key(owner), spec.target_key)
    if identifier is not None:
        lock_target(db, owner, identifier)
        old = chain(db, owner, TARGET, identifier)[-1]
        if key != identifier or old.payload["target"]["system_id"] != spec.system_id:
            raise HTTPException(409, "Stable target key/system cannot be reassigned")
    value = {
        "schema_version": "cryptoscan.collection-target/v1",
        "state": "REGISTERED",
        "target": spec.model_dump(mode="json"),
        "evidence_status": "DECLARED",
        "host_identity_attested": False,
    }
    return atomic(
        lambda: store.public(save(db, owner, TARGET, key, expected, value, actor, user, "target.register")), db
    )


def authorize(db, owner, identifier, body, actor, user, *, revoke=False):
    boundary()
    lock_target(db, owner, identifier)
    row = chain(db, owner, TARGET, identifier)[-1]
    if row.revision != body.expected_revision:
        raise HTTPException(409, "Target revision changed")
    spec = TargetSpec.model_validate(row.payload["target"])
    if revoke:
        if row.payload["state"] == "REVOKED":
            raise HTTPException(409, "Target already revoked")
        value = {
            **row.payload,
            "state": "REVOKED",
            "decision_evidence_ref": body.evidence_ref,
            "decision_reason": body.reason,
        }
        return atomic(
            lambda: store.public(
                save(db, owner, TARGET, identifier, row.revision, value, actor, user, "target.revoke")
            ),
            db,
        )
    if row.payload["state"] != "REGISTERED":
        raise HTTPException(409, "Target must be registered before authorization")
    supported(spec)
    worker = getattr(body, "worker", None)
    if worker is not None and (
        body.collector_identity is None or worker.source_lock_sha256 != body.collector_identity.release_sha256
    ):
        raise HTTPException(422, "Worker requires matching approved signing/release policy")
    system = store.exact(db, System, owner, spec.system_id)
    if system.environment != spec.environment:
        raise HTTPException(409, "System and target environments differ")
    now = utcnow()
    if not now < spec.manifest.expires_at <= now + timedelta(days=1):
        raise HTTPException(422, "Authorization must expire within 24 hours")
    from api.routers.host_evidence import _audit
    import uuid

    approval_id = str(uuid.uuid4())

    def operation():
        approval = store.append(
            db,
            owner,
            "host_approval",
            approval_id,
            0,
            {
                "system_id": spec.system_id,
                "manifest": spec.manifest.model_dump(mode="json"),
                "manifest_sha256": digest(spec.manifest),
                "source_basis": "DECLARED",
                "authorizes_remote_execution": False,
                "host_identity_attested": False,
                "collection_target_id": identifier,
                "collection_target_revision": row.revision + 1,
                **identity_approval_fields(getattr(body, "collector_identity", None)),
                **({"worker": worker.model_dump(mode="json")} if worker else {}),
            },
            actor,
            commit=False,
        )
        _audit(
            db,
            user,
            "host.approve",
            approval_id,
            {
                "manifest_sha256": digest(spec.manifest),
                "system_id": spec.system_id,
                **(
                    {"collector_identity_sha256": digest(body.collector_identity)}
                    if getattr(body, "collector_identity", None)
                    else {}
                ),
            },
        )
        value = {
            **row.payload,
            "state": "AUTHORIZED",
            "approval_id": approval_id,
            "approval_sha256": approval.payload_sha256,
            "decision_evidence_ref": body.evidence_ref,
            "decision_reason": body.reason,
        }
        return store.public(save(db, owner, TARGET, identifier, row.revision, value, actor, user, "target.authorize"))

    return atomic(operation, db)


def admitted(db, owner, target, revision):
    spec = TargetSpec.model_validate(target.payload["target"])
    supported(spec)
    if (
        target.revision != revision
        or target.payload["state"] != "AUTHORIZED"
        or not spec.not_before <= utcnow() < spec.manifest.expires_at
    ):
        raise HTTPException(409, "Target authorization changed, revoked or outside time window")
    system = store.exact(db, System, owner, spec.system_id)
    if system.environment != spec.environment:
        raise HTTPException(409, "System environment changed")
    approval = store.latest(db, owner, "host_approval", target.payload["approval_id"])
    if approval.payload_sha256 != target.payload["approval_sha256"] or approval.payload["manifest_sha256"] != digest(
        spec.manifest
    ):
        raise HTTPException(409, "Target/approval commitment mismatch")
    return spec


def create_job(db, owner, body, actor, user):
    boundary()
    lock_target(db, owner, body.target_id)
    target = chain(db, owner, TARGET, body.target_id)[-1]
    admitted(db, owner, target, body.expected_target_revision)
    identifier = store.subject(
        "collection-job/v1", store.scope_key(owner), body.target_id, target.payload["approval_id"]
    )
    payload = {
        "schema_version": "cryptoscan.collection-job/v1",
        "state": "READY",
        "target_id": body.target_id,
        "target_revision": target.revision,
        "target_sha256": target.payload_sha256,
        "approval_id": target.payload["approval_id"],
        "collector": "offline-linux/v1",
        "execution_basis": "OFFLINE_OPERATOR_HANDOFF_NOT_SERVER_EXECUTION",
    }
    return atomic(lambda: store.public(save(db, owner, JOB, identifier, 0, payload, actor, user, "job.ready")), db)


def resolve_job(db, owner, identifier):
    row = chain(db, owner, JOB, identifier)[-1]
    targets = chain(db, owner, TARGET, row.payload["target_id"])
    revision = row.payload["target_revision"]
    if revision > len(targets) or targets[revision - 1].payload_sha256 != row.payload["target_sha256"]:
        raise HTTPException(409, "Job target commitment mismatch")
    return row, targets[revision - 1], targets[-1]


def envelope(db, owner, job, target):
    from api.routers.host_evidence import _check

    intake = store.latest(db, owner, "host_intake", job.payload["approval_id"])
    snapshot, scan, records, _ = _check(db, owner, intake)
    if target.payload["approval_id"] != intake.subject_id or digest(snapshot.manifest) != digest(
        target.payload["target"]["manifest"]
    ):
        raise HTTPException(409, "Job evidence does not match exact authorized target")
    refs = {
        (r.finding_data["host_evidence"]["input_id"], r.finding_data["host_evidence"]["fact_ordinal"]): r
        for r in records
    }
    observations = []
    for item, receipt in zip(snapshot.manifest.inputs, snapshot.receipts):
        for ordinal, fact in enumerate(receipt.facts):
            reference = refs.get((item.input_id, ordinal), refs[(item.input_id, -1)])
            from shared_models.host_runtime import domains as fact_domains

            domains = fact_domains(fact)
            slot = store.subject(
                "metadata-slot/v1",
                store.scope_key(owner),
                job.payload["target_id"],
                item.kind,
                item.path,
                fact.kind,
                getattr(fact, "identity_key", None) or fact.software_name or "",
            )
            observation = Observation(
                observation_id=store.subject("observation/v1", scan.id, item.input_id, ordinal),
                identity_slot=slot,
                input_id=item.input_id,
                fact_ordinal=ordinal,
                fact=fact,
                source={
                    "kind": item.kind,
                    "path": item.path,
                    "input_content_sha256": receipt.content_sha256,
                    "host_id": snapshot.manifest.host_id,
                },
                collected_at=snapshot.finished_at.isoformat(),
                evidence_id=reference.id,
                content_hash=reference.content_hash,
                fact_sha256=digest(fact),
                contributes_to=domains,
            )
            observations.append(observation.model_dump(mode="json"))
    errors = [
        {"input_id": r.input_id, "status": r.status, "reason": r.reason, "asset_absence_proven": False}
        for r in snapshot.receipts
        if r.status != "PARSED"
    ]
    parsed = sum(r.status == "PARSED" for r in snapshot.receipts)
    value = {
        "schema_version": "cryptoscan.collection-evidence/v1",
        "job_id": job.subject_id,
        "target_id": job.payload["target_id"],
        "target_revision": target.revision,
        "target_sha256": target.payload_sha256,
        "system_id": intake.payload["system_id"],
        "environment": snapshot.manifest.environment,
        "collector": {"name": "offline-linux/v1", "version": snapshot.collector_version},
        "status": "COMPLETED" if not errors else "PARTIAL" if parsed else "FAILED",
        "provenance": "IMPORTED",
        "started_at": snapshot.started_at.isoformat(),
        "finished_at": snapshot.finished_at.isoformat(),
        "source_revision": None,
        "evidence_manifest": {
            "approval_id": intake.subject_id,
            "scan_id": scan.id,
            "snapshot_sha256": digest(snapshot),
            "scan_manifest_sha256": scan.manifest_hash,
        },
        "observations": observations,
        "errors": errors,
        "coverage": {
            "parsed_inputs": parsed,
            "approved_inputs": len(snapshot.receipts),
            "basis": "APPROVED_INPUT_RECEIPTS_ONLY",
            "whole_host_percent": None,
            "whole_host_coverage_verified": False,
        },
        "host_identity_attested": False,
        "runtime_use": "UNKNOWN",
        "pqc_use": "UNKNOWN",
    }
    value = CollectionResult.model_validate(value).model_dump(mode="json")
    if len(store.encoded(value)) > 4 * 1024 * 1024:
        raise HTTPException(409, "Complete evidence envelope exceeds budget")
    return {**value, "envelope_sha256": digest(value)}


def transition(db, owner, identifier, body, actor, user, action):
    boundary()
    initial, _, _ = resolve_job(db, owner, identifier)
    lock_target(db, owner, initial.payload["target_id"])
    job, target, current = resolve_job(db, owner, identifier)
    if job.revision != body.expected_revision:
        raise HTTPException(409, "Job revision changed")
    admitted(db, owner, current, job.payload["target_revision"])
    if action == "handoff":
        if job.payload["state"] != "READY":
            raise HTTPException(409, "Job is not ready for an offline handoff")
        value = {**job.payload, "state": "AWAITING_EVIDENCE"}
    else:
        if job.payload["state"] != "AWAITING_EVIDENCE":
            raise HTTPException(409, "Job is not awaiting evidence")
        result = envelope(db, owner, job, target)
        value = {**job.payload, "state": result["status"], "envelope_sha256": result["envelope_sha256"]}
    return atomic(
        lambda: store.public(save(db, owner, JOB, identifier, job.revision, value, actor, user, "job." + action)), db
    )


def evidence(db, owner, identifier):
    boundary()
    job, target, _ = resolve_job(db, owner, identifier)
    if job.payload["state"] not in {"COMPLETED", "PARTIAL", "FAILED"}:
        raise HTTPException(409, "Job has no committed completion")
    value = envelope(db, owner, job, target)
    if job.payload["envelope_sha256"] != value["envelope_sha256"]:
        raise HTTPException(409, "Envelope projection commitment changed")
    return value


def projections(db, owner, identifier):
    result = evidence(db, owner, identifier)
    domains = {
        name: {"observations": [], "operational_use": "UNKNOWN", "complete_coverage_verified": False}
        for name in ["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"]
    }
    for obs in result["observations"]:
        for name in obs["contributes_to"]:
            domains[name]["observations"].append(obs["observation_id"])
    return {
        "schema_version": "cryptoscan.collection-projections/v1",
        "envelope_sha256": result["envelope_sha256"],
        "domains": domains,
        "standard_document": False,
        "materialized_without_collection": True,
    }


def admit_host_intake(db, owner, approval, snapshot):
    """Bound approvals cannot bypass registry revocation via the older intake URL."""
    identifier = approval.payload.get("collection_target_id")
    if identifier is None:
        return  # historical standalone host authorization remains its own contract
    boundary()
    lock_target(db, owner, identifier)
    target = chain(db, owner, TARGET, identifier)[-1]
    spec = admitted(db, owner, target, approval.payload["collection_target_revision"])
    if approval.payload.get("worker"):
        from api.assurance.host_worker import admit_result

        admit_result(db, owner, approval, snapshot)
    if target.payload["approval_id"] != approval.subject_id or snapshot.started_at < spec.not_before:
        raise HTTPException(409, "Registry authorization does not admit this host intake")


def identity_approval_fields(policy):
    if policy is None:
        return {}
    import secrets

    return {"collector_identity": policy.model_dump(mode="json"), "collector_nonce": secrets.token_hex(32)}


def surface_coverage(db, owner, identifier):
    from shared_models.collection_coverage import project_coverage

    value = evidence(db, owner, identifier)  # reopens originals; no execution or new scan
    _, target, _ = resolve_job(db, owner, identifier)
    if value["target_sha256"] != target.payload_sha256 or value["target_revision"] != target.revision:
        raise HTTPException(409, "Coverage target binding changed")
    try:
        result = CollectionResult.model_validate({k: v for k, v in value.items() if k != "envelope_sha256"})
        return project_coverage(
            result, TargetSpec.model_validate(target.payload["target"]), value["envelope_sha256"]
        ).model_dump(mode="json")
    except ValueError:
        raise HTTPException(409, "Coverage evidence/approved-input reconciliation failed") from None


def linux_software(db, owner, identifier):
    from shared_models.linux_software import project_linux_software

    value = evidence(db, owner, identifier)
    _, target, _ = resolve_job(db, owner, identifier)
    if value["target_sha256"] != target.payload_sha256 or value["target_revision"] != target.revision:
        raise HTTPException(409, "Software evidence target binding changed")
    try:
        result = CollectionResult.model_validate({k: v for k, v in value.items() if k != "envelope_sha256"})
        return project_linux_software(
            result, TargetSpec.model_validate(target.payload["target"]), value["envelope_sha256"]
        ).model_dump(mode="json")
    except ValueError:
        raise HTTPException(409, "Linux software evidence/scope reconciliation failed") from None


def linux_relationships(db, owner, identifier):
    from shared_models.linux_relationships import project_linux_relationships

    value = evidence(db, owner, identifier)
    _, target, _ = resolve_job(db, owner, identifier)
    if value["target_sha256"] != target.payload_sha256 or value["target_revision"] != target.revision:
        raise HTTPException(409, "Relationship evidence target binding changed")
    try:
        result = CollectionResult.model_validate({k: v for k, v in value.items() if k != "envelope_sha256"})
        return project_linux_relationships(
            result, TargetSpec.model_validate(target.payload["target"]), value["envelope_sha256"]
        ).model_dump(mode="json")
    except ValueError:
        raise HTTPException(409, "Linux relationship evidence/scope reconciliation failed") from None


def linux_sbom(db, owner, identifier):
    from cbom.linux_sbom import build_linux_sbom, LinuxSBOMValidationError
    from shared_models.linux_software import LinuxSoftwareInventory

    inventory = LinuxSoftwareInventory.model_validate(linux_software(db, owner, identifier))
    try:
        return build_linux_sbom(inventory)
    except LinuxSBOMValidationError:
        raise HTTPException(503, "Pinned official CycloneDX validation failed; no export available") from None
