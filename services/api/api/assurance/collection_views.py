"""Durable shared metadata snapshots/drift over original host and OCI evidence.

Reuses assurance revisions and their audit transaction. No collector invocation,
new evidence intake, operational relationship writer, baseline approval or alert.
"""

from fastapi import HTTPException
from pydantic import ValidationError
from db.models.assurance import AssuranceRevision
from shared_models.collection_views import CollectionSnapshot, compare_snapshots, snapshot_views
from shared_models.host_collection import digest
from shared_models.host_runtime import domains as fact_domains
from api.assurance import collection as base, oci_collection as oci, store

SNAPSHOT = "collection_snapshot"
DRIFT = "collection_metadata_drift"


def source_snapshot(db, owner, family, identifier):
    base.boundary()
    if family == "host":
        source = base.evidence(db, owner, identifier)
        _, target, _ = base.resolve_job(db, owner, identifier)
        errors = {e["input_id"]: e for e in source["errors"]}
        inputs = [
            {
                "input_id": i["input_id"],
                "kind": i["kind"],
                "path": i["path"],
                "status": errors.get(i["input_id"], {}).get("status", "PARSED"),
                "reason": errors.get(i["input_id"], {}).get("reason", "METADATA_ONLY"),
            }
            for i in target.payload["target"]["manifest"]["inputs"]
        ]
        observations = [
            {
                "observation_id": o["observation_id"],
                "identity_slot": o["identity_slot"],
                "input_id": o["input_id"],
                "fact_kind": o["fact"]["kind"],
                "fact_sha256": o["fact_sha256"],
                "evidence_id": o["evidence_id"],
                "local_basis": o["fact"]["local_basis"],
                "domains": o["contributes_to"],
            }
            for o in source["observations"]
        ]
        return CollectionSnapshot(
            family=family,
            job_id=identifier,
            target_id=source["target_id"],
            system_id=source["system_id"],
            environment=source["environment"],
            source_sha256=source["envelope_sha256"],
            started_at=source["started_at"],
            finished_at=source["finished_at"],
            inputs=inputs,
            observations=observations,
        )
    if family != "oci":
        raise HTTPException(422, "Unsupported snapshot source family")
    capture = oci.retained(db, owner, identifier)
    evidence = capture.evidence
    source_sha = digest(evidence)
    inputs = [
        {"input_id": i.input_id, "kind": i.kind, "path": i.path, "status": receipt.status, "reason": receipt.reason}
        for i, receipt in zip(evidence.target.inputs, evidence.receipts)
    ]
    observations = []
    for item, receipt in zip(evidence.target.inputs, evidence.receipts):
        for ordinal, fact in enumerate(receipt.facts):
            ref = "oci-fact:" + digest(
                {"evidence_sha256": source_sha, "input_id": receipt.input_id, "ordinal": ordinal}
            )
            slot = store.subject(
                "oci-metadata-slot/v1",
                store.scope_key(owner),
                capture.binding.target_id,
                item.kind,
                receipt.path,
                fact.kind,
                fact.software_name or "",
            )
            observations.append(
                {
                    "observation_id": ref,
                    "identity_slot": slot,
                    "input_id": receipt.input_id,
                    "fact_kind": fact.kind,
                    "fact_sha256": digest(fact),
                    "evidence_id": ref,
                    "local_basis": fact.local_basis,
                    "domains": fact_domains(fact),
                }
            )
    # Image config is a pinned source, not an additional approved metadata input.
    # Include even an empty declaration set so disappearance is not a scope gap.
    config_id = "oci-config:" + evidence.config_sha256
    inputs.append(
        {
            "input_id": config_id,
            "kind": "OCI_IMAGE_CONFIG",
            "path": "oci://image-config/config.json",
            "status": "PARSED",
            "reason": "METADATA_ONLY",
            "input_basis": "PINNED_IMAGE_CONFIG",
        }
    )
    if evidence.declarations.vendor:
        state = {"kind": "VENDOR_DECLARATION", "vendor": evidence.declarations.vendor}
        ref = "oci-declaration:" + digest({"evidence_sha256": source_sha, "state": state})
        observations.append(
            {
                "observation_id": ref,
                "identity_slot": store.subject("oci-vendor-slot/v1", store.scope_key(owner), capture.binding.target_id),
                "input_id": config_id,
                "fact_kind": "VENDOR_DECLARATION",
                "fact_sha256": digest(state),
                "evidence_id": ref,
                "local_basis": "DECLARED",
                "domains": ["VBOM", "TechBOM"],
            }
        )
    return CollectionSnapshot(
        family=family,
        job_id=identifier,
        target_id=capture.binding.target_id,
        system_id=evidence.target.system_id,
        environment=evidence.target.environment,
        source_sha256=source_sha,
        started_at=evidence.started_at,
        finished_at=evidence.finished_at,
        inputs=inputs,
        observations=observations,
    )


def payload(snapshot):
    return {"snapshot": snapshot.model_dump(mode="json"), **snapshot_views(snapshot)}


def create_snapshot(db, owner, body, actor, user):
    base.boundary()

    def operation():
        try:
            snapshot = source_snapshot(db, owner, body.family, body.job_id)
        except (ValidationError, KeyError, TypeError):
            raise HTTPException(409, "Source cannot be materialized under the snapshot contract") from None
        if snapshot.source_sha256 != body.expected_source_sha256:
            raise HTTPException(409, "Expected retained source commitment changed")
        identifier = store.subject(
            "collection-snapshot/v1", store.scope_key(owner), body.family, body.job_id, body.expected_source_sha256
        )
        row = base.save(db, owner, SNAPSHOT, identifier, 0, payload(snapshot), actor, user, "snapshot.create")
        return store.public(row)

    return base.atomic(operation, db)


def read_snapshot(db, owner, identifier):
    base.boundary()
    records = base.chain(db, owner, SNAPSHOT, identifier)
    if len(records) != 1:
        raise HTTPException(409, "Collection snapshot must be write-once")
    row = records[0]
    try:
        snapshot = CollectionSnapshot.model_validate(row.payload["snapshot"])
        original = source_snapshot(db, owner, snapshot.family, snapshot.job_id)
    except (ValidationError, KeyError, TypeError):
        raise HTTPException(409, "Stored collection snapshot structure changed") from None
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        raise HTTPException(409, "Collection snapshot original source unavailable") from None
    expected_id = store.subject(
        "collection-snapshot/v1", store.scope_key(owner), snapshot.family, snapshot.job_id, snapshot.source_sha256
    )
    if row.subject_id != expected_id or row.payload != payload(original) or snapshot != original:
        raise HTTPException(409, "Collection snapshot/source/view commitment mismatch")
    return row, snapshot


def listing(db, owner, cursor, limit):
    base.boundary()
    rows = (
        store.rows(db, AssuranceRevision, owner)
        .filter(AssuranceRevision.kind == SNAPSHOT, AssuranceRevision.subject_id > cursor)
        .order_by(AssuranceRevision.subject_id)
        .limit(limit + 1)
        .all()
    )
    result = []
    for row in rows[:limit]:
        row, snapshot = read_snapshot(db, owner, row.subject_id)
        result.append(
            {
                "snapshot_id": row.subject_id,
                "snapshot_sha256": digest(snapshot),
                "family": snapshot.family,
                "job_id": snapshot.job_id,
                "target_id": snapshot.target_id,
                "system_id": snapshot.system_id,
                "environment": snapshot.environment,
                "started_at": snapshot.started_at.isoformat(),
                "finished_at": snapshot.finished_at.isoformat(),
                "source_revalidated": True,
            }
        )
    return {"snapshots": result, "next_cursor": rows[limit - 1].subject_id if len(rows) > limit else None}


def drift_payload(db, owner, baseline_id, candidate_id):
    if baseline_id == candidate_id:
        raise HTTPException(409, "Distinct snapshots required")
    baseline_row, baseline = read_snapshot(db, owner, baseline_id)
    candidate_row, candidate = read_snapshot(db, owner, candidate_id)
    try:
        report = compare_snapshots(baseline, candidate)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {
        "baseline_snapshot_id": baseline_id,
        "candidate_snapshot_id": candidate_id,
        "baseline_record_sha256": baseline_row.payload_sha256,
        "candidate_record_sha256": candidate_row.payload_sha256,
        "report": report,
    }


def create_drift(db, owner, body, actor, user):
    base.boundary()

    def operation():
        value = drift_payload(db, owner, body.baseline_snapshot_id, body.candidate_snapshot_id)
        identifier = store.subject(
            "collection-drift/v1", store.scope_key(owner), body.baseline_snapshot_id, body.candidate_snapshot_id
        )
        return store.public(base.save(db, owner, DRIFT, identifier, 0, value, actor, user, "metadata-drift.create"))

    return base.atomic(operation, db)


def read_drift(db, owner, identifier):
    base.boundary()
    records = base.chain(db, owner, DRIFT, identifier)
    if len(records) != 1:
        raise HTTPException(409, "Collection drift must be write-once")
    row = records[0]
    try:
        baseline_id, candidate_id = row.payload["baseline_snapshot_id"], row.payload["candidate_snapshot_id"]
        expected = store.subject("collection-drift/v1", store.scope_key(owner), baseline_id, candidate_id)
        original = drift_payload(db, owner, baseline_id, candidate_id)
    except (KeyError, TypeError):
        raise HTTPException(409, "Stored collection drift structure changed") from None
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        raise HTTPException(409, "Collection drift snapshot source unavailable") from None
    if expected != identifier or original != row.payload:
        raise HTTPException(409, "Collection drift/source commitment mismatch")
    return store.public(row)
