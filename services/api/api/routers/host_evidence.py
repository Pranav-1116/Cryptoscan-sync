"""Explicit host approval -> offline IMPORTED snapshot -> committed evidence.

Deliberately NOT on the local-source/v1 production allowlist. No HTTP handler
opens host paths or executes a collector. Approvals bind metadata/scope, not an
attested host identity, production scanner execution or whole-system coverage.
"""

from __future__ import annotations

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.assurance import store, host_associations
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author, new_id, Key
from db.models.base import utcnow
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System
from db.loader.bulk_inserter import BulkInserter
from db.repositories.execution_control import aware
from db.repositories.user_repository import UserRepository
from evidence.core.pipeline import EvidencePipeline
from evidence.verification.stored_scan import verify_stored_scan
from shared_models.host_collection import HostManifest, HostSnapshot, Strict, Token, digest, snapshot_findings
from shared_models.safe_finding import safe_finding
from shared_models.host_associations import AssociationProposal, AssociationDecision, TargetType

from shared_models.collector_identity import CollectorIdentityPolicy, CollectorAttestation, verify_collector

router = APIRouter(prefix="/host-evidence", tags=["host-evidence"])


class ApprovalRequest(Strict):
    system_id: Token
    manifest: HostManifest
    collector_identity: CollectorIdentityPolicy | None = None


class IntakeRequest(Strict):
    snapshot: HostSnapshot
    collector_attestation: CollectorAttestation | None = None


def _system(db, owner, identifier):
    return store.exact(db, System, owner, identifier)


def _audit(db, user, action, identifier, detail):
    UserRepository(db).audit(user, action, target_type="host_evidence", target_id=identifier, detail=detail)


def _check(db, owner, intake):
    """Check the full source/snapshot/evidence closure before ANY read/export."""
    payload = intake.payload
    try:
        snapshot = HostSnapshot.model_validate(payload["snapshot"])
        approval = store.latest(db, owner, "host_approval", intake.subject_id)
        if (
            digest(snapshot) != payload["snapshot_sha256"]
            or digest(snapshot.manifest) != approval.payload["manifest_sha256"]
        ):
            raise ValueError("snapshot/approval mismatch")
        scan = store.exact(db, Scan, owner, payload["scan_id"])
        rows = list(
            db.query(EvidenceRecord)
            .filter(EvidenceRecord.tenant_id == owner, EvidenceRecord.scan_id == scan.id)
            .order_by(EvidenceRecord.chain_position)
            .limit(1101)
        )
        expected = snapshot_findings(snapshot, intake.subject_id, approval.payload["system_id"])
        verdict = verify_stored_scan(scan, rows)
        if (
            len(rows) != len(expected)
            or [r.id for r in rows] != payload["evidence_ids"]
            or len(rows) != payload["evidence_count"]
            or any(r.deleted_at is not None for r in rows)
            or verdict["result"] != "PASS"
            or scan.target_type != "HOST_SNAPSHOT_IMPORT"
            or scan.scanner_id != "host-snapshot-import-v1"
            or scan.scanner_version != "1.0"
            or scan.operator != payload["imported_by"]
            or aware(scan.scan_start) != snapshot.started_at
            or scan.scan_end is None
            or aware(scan.scan_end) != snapshot.finished_at
            or scan.target_commit is not None
            or scan.target_branch is not None
            or scan.status != "COMPLETED"
            or scan.target_location != "urn:cryptoscan:host:" + snapshot.manifest.host_id
            or scan.statistics
            != {"source_basis": "IMPORTED", "snapshot_sha256": digest(snapshot), "approval_id": intake.subject_id}
            or [r.finding_data for r in rows] != [safe_finding(f) for f in expected]
        ):
            raise ValueError("host evidence closure mismatch")
        # Persisted denormalized columns must agree too: exports elsewhere read
        # them rather than finding_data. A valid chain cannot bless drift here.
        for row, finding in zip(rows, expected):
            crypto, source = finding["crypto"], finding["source"]
            if (
                any(getattr(row, key) != crypto[key] for key in ("algorithm", "key_size", "mode", "purpose"))
                or row.file_path != source["file_path"]
                or row.confidence != "LOW"
            ):
                raise ValueError("host evidence projection mismatch")
        _verify_identity(approval, snapshot, payload.get("collector_attestation"), snapshot.manifest.expires_at)
        _system(db, owner, approval.payload["system_id"])
        return snapshot, scan, rows, verdict
    except (KeyError, ValueError, TypeError):
        raise HTTPException(409, "Host snapshot/evidence integrity mismatch; no export or verified receipt") from None


@router.post("/approvals", status_code=201)
def approve(
    body: ApprovalRequest,
    request: Request,
    response: Response,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    actor_id = author(db, request, user, permission="assurance.trust")
    _system(db, ctx.tenant_id, body.system_id)
    now = utcnow()
    if not now < body.manifest.expires_at <= now + timedelta(days=1):
        raise HTTPException(422, "Approval must expire within the next 24 hours")
    identifier = new_id()
    from api.assurance.collection import identity_approval_fields

    try:
        row = store.append(
            db,
            ctx.tenant_id,
            "host_approval",
            identifier,
            0,
            {
                "system_id": body.system_id,
                "manifest": body.manifest.model_dump(mode="json"),
                "manifest_sha256": digest(body.manifest),
                "source_basis": "DECLARED",
                "authorizes_remote_execution": False,
                "host_identity_attested": False,
                **identity_approval_fields(body.collector_identity),
            },
            actor_id,
            commit=False,
        )
        _audit(
            db,
            user,
            "host.approve",
            identifier,
            {
                "manifest_sha256": digest(body.manifest),
                "system_id": body.system_id,
                **({"collector_identity_sha256": digest(body.collector_identity)} if body.collector_identity else {}),
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    response.headers["Cache-Control"] = "no-store"
    return store.public(row)


@router.post("/approvals/{approval_id}/intake", status_code=201)
def intake(
    approval_id: Key,
    body: IntakeRequest,
    request: Request,
    response: Response,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    actor_id = author(db, request, user)  # auditors/viewers cannot ingest or approve
    approval = store.latest(db, ctx.tenant_id, "host_approval", approval_id)
    snapshot, now = body.snapshot, utcnow()
    old = store.latest(db, ctx.tenant_id, "host_intake", approval_id, required=False)
    if old:
        if old.payload.get("collector_attestation") != (
            body.collector_attestation.model_dump(mode="json") if body.collector_attestation else None
        ):
            raise HTTPException(409, "Collector signature replay/downgrade mismatch")
        if old.payload["snapshot_sha256"] != digest(snapshot):
            raise HTTPException(409, "This one-use approval already holds a different snapshot")
        _check(db, ctx.tenant_id, old)
        response.status_code = 200
        return _public_receipt(old)
    if (
        snapshot.manifest_sha256 != approval.payload["manifest_sha256"]
        or not aware(approval.created_at) <= snapshot.started_at <= snapshot.finished_at <= now
        or now >= snapshot.manifest.expires_at
    ):
        raise HTTPException(409, "Approval scope, collection time or expiry mismatch")
    from api.assurance.collection import admit_host_intake

    admit_host_intake(db, ctx.tenant_id, approval, snapshot)
    _verify_identity(approval, snapshot, body.collector_attestation, now)
    _system(db, ctx.tenant_id, approval.payload["system_id"])
    scan_id = new_id()
    pipeline = EvidencePipeline(scan_id)
    records, manifest = pipeline.process(snapshot_findings(snapshot, approval_id, approval.payload["system_id"]))
    try:
        scan, inserted = BulkInserter(db).insert_scan_with_evidence(
            {
                "scan_id": scan_id,
                "scan_start": snapshot.started_at,
                "scan_end": snapshot.finished_at,
                "scanner_id": "host-snapshot-import-v1",
                "scanner_version": "1.0",
                "target_type": "HOST_SNAPSHOT_IMPORT",
                "target_location": "urn:cryptoscan:host:" + snapshot.manifest.host_id,
                "operator": user,
                "status": "COMPLETED",
            },
            [r.model_dump() for r in records],
        )
        scan.manifest_hash = manifest.manifest_hash
        scan.statistics = {"source_basis": "IMPORTED", "snapshot_sha256": digest(snapshot), "approval_id": approval_id}
        db.flush()
        row = store.append(
            db,
            ctx.tenant_id,
            "host_intake",
            approval_id,
            0,
            {
                "snapshot": snapshot.model_dump(mode="json"),
                "snapshot_sha256": digest(snapshot),
                "scan_id": scan_id,
                "system_id": approval.payload["system_id"],
                "evidence_count": inserted,
                "evidence_ids": [r.evidence_id for r in records],
                "imported_by": user,
                "source_basis": "IMPORTED",
                **(
                    {"collector_attestation": body.collector_attestation.model_dump(mode="json")}
                    if body.collector_attestation
                    else {}
                ),
            },
            actor_id,
            commit=False,
        )
        _check(db, ctx.tenant_id, row)
        _audit(
            db,
            user,
            "host.intake",
            scan_id,
            {
                "approval_id": approval_id,
                "snapshot_sha256": digest(snapshot),
                "evidence_count": inserted,
                "evidence_ids": [r.evidence_id for r in records],
                "imported_by": user,
                "source_basis": "IMPORTED",
                **(
                    {"collector_attestation_sha256": digest(body.collector_attestation)}
                    if body.collector_attestation
                    else {}
                ),
            },
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "Concurrent approval consumption; inspect the existing receipt, do not retry blindly"
        ) from None
    except Exception:
        db.rollback()
        raise
    return _public_receipt(row)


def _public_receipt(row):
    return {
        "approval_id": row.subject_id,
        "scan_id": row.payload["scan_id"],
        "system_id": row.payload["system_id"],
        "snapshot_sha256": row.payload["snapshot_sha256"],
        "evidence_count": row.payload["evidence_count"],
        "source_basis": "IMPORTED",
        "whole_host_coverage_verified": False,
        "runtime_use": "UNKNOWN",
        "policy_result": "NOT_EVALUATED",
        "pqc_assessment": "UNKNOWN",
        "host_identity_attested": False,
        **(
            {
                "collector_identity_verified": True,
                "collector_identity_basis": "APPROVAL_PINNED_SIGNING_KEY_NOT_HOST_ATTESTATION",
                "collector_key_id": row.payload["collector_attestation"]["statement"]["key_id"],
            }
            if row.payload.get("collector_attestation")
            else {}
        ),
    }


@router.get("/approvals/{approval_id}")
def approval(
    approval_id: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return store.public(store.latest(db, ctx.tenant_id, "host_approval", approval_id))


@router.get("/approvals/{approval_id}/snapshot")
def inspection(
    approval_id: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    row = store.latest(db, ctx.tenant_id, "host_intake", approval_id)
    snapshot, _, records, verdict = _check(db, ctx.tenant_id, row)
    return {
        **_public_receipt(row),
        "snapshot": snapshot.model_dump(mode="json"),
        "integrity": verdict,
        "evidence": [
            {
                "evidence_id": r.id,
                "input_id": r.finding_data["host_evidence"]["input_id"],
                "fact_ordinal": r.finding_data["host_evidence"]["fact_ordinal"],
                "content_hash": r.content_hash,
            }
            for r in records
        ],
    }


@router.get("/approvals/{approval_id}/cbom")
def export_cbom(
    approval_id: Key,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    from cbom.generator import CbomGenerator
    from cbom.cyclonedx16 import validate_cyclonedx16

    row = store.latest(db, ctx.tenant_id, "host_intake", approval_id)
    snapshot, scan, records, _ = _check(db, ctx.tenant_id, row)
    bom = CbomGenerator().from_records(
        records,
        name=snapshot.manifest.host_id,
        scan_id=scan.id,
        spec_version="1.6",
        metadata_properties=[{"name": "cryptoscan:source_basis", "value": "IMPORTED"}],
    )
    if not validate_cyclonedx16(bom)["ok"]:
        raise HTTPException(409, "Host CBOM failed exact CycloneDX 1.6 schema/reference validation")
    _audit(
        db,
        user,
        "host.export",
        scan.id,
        {
            "approval_id": approval_id,
            "snapshot_sha256": digest(snapshot),
            "format": "CycloneDX-1.6",
            "document_sha256": digest(bom),
        },
    )
    db.commit()
    return bom


@router.get("/approvals/{approval_id}/association-target")
def association_target(
    approval_id: Key,
    target_type: TargetType,
    target_id: str = Query(min_length=1, max_length=36),
    package_identity: str | None = Query(default=None, min_length=1, max_length=500),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    bundle = host_associations.source(db, ctx.tenant_id, approval_id)
    return host_associations.target(
        db,
        ctx.tenant_id,
        bundle[0].payload["system_id"],
        target_type,
        target_id,
        package_identity,
        environment=bundle[1].manifest.environment,
    )


@router.post("/approvals/{approval_id}/associations", status_code=201)
def propose_host_association(
    approval_id: Key,
    body: AssociationProposal,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return host_associations.propose(db, ctx.tenant_id, approval_id, body, author(db, request, user), user)


@router.post("/approvals/{approval_id}/associations/{identifier}/review")
def review_host_association(
    approval_id: Key,
    identifier: Key,
    body: AssociationDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return host_associations.decide(
        db, ctx.tenant_id, approval_id, identifier, body, author(db, request, user, "assurance.trust"), user
    )


@router.post("/approvals/{approval_id}/associations/{identifier}/retract")
def retract_host_association(
    approval_id: Key,
    identifier: Key,
    body: AssociationDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return host_associations.decide(
        db,
        ctx.tenant_id,
        approval_id,
        identifier,
        body,
        author(db, request, user, "assurance.trust"),
        user,
        retract=True,
    )


@router.get("/approvals/{approval_id}/graph")
def host_estate_graph(
    approval_id: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return host_associations.graph(db, ctx.tenant_id, approval_id)


@router.get("/approvals/{approval_id}/graph/export")
def host_estate_graph_export(
    approval_id: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    value = host_associations.graph(db, ctx.tenant_id, approval_id)
    _audit(
        db,
        user,
        "host.graph.export",
        value["scan_id"],
        {
            "approval_id": approval_id,
            "graph_sha256": value["graph_sha256"],
            "evidence_status": "DECLARED_ASSOCIATIONS_IMPORTED_SOURCE",
        },
    )
    db.commit()
    return value


def _verify_identity(approval, snapshot, proof, latest):
    policy = approval.payload.get("collector_identity")
    if policy is None:
        if proof is not None:
            raise HTTPException(409, "Collector signing key was not pinned by approval")
        return
    try:
        if proof is None:
            raise ValueError("Collector signature required")
        proof = proof if isinstance(proof, CollectorAttestation) else CollectorAttestation.model_validate(proof)
        return verify_collector(
            CollectorIdentityPolicy.model_validate(policy),
            proof,
            snapshot,
            approval.subject_id,
            approval.payload["collector_nonce"],
            aware(approval.created_at),
            latest,
        )
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, "Collector identity proof missing, invalid, out of scope or expired") from None
