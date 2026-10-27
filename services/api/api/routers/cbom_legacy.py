"""Historical declaration containment/review on the existing CBOM surface.

Original findings, signatures, hashes, stored confidence and scan timestamps
are never rewritten. Mixed rows are deliberately NOT auto-reconciled.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.import_provenance import archived_legacy_clause, legacy_import_clause
from db.models.base import BaseModel as RowModel
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.evidence_record import EvidenceRecord
from db.tenancy import current_tenant
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.repositories.user_repository import UserRepository
from shared_models.import_provenance import ARCHIVED_DECLARATION, is_legacy_import

REVIEW_MAX_ASSETS = 2000


class ReconcileLegacyRequest(BaseModel):
    expected_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=20, max_length=500)


def refuse_unreviewed_export(db: Session, *, system_id: str | None = None,
                             asset_ids: list[str] | None = None) -> None:
    stmt = select(CryptoAsset.id).where(legacy_import_clause(), ~archived_legacy_clause())
    if system_id is not None:
        stmt = stmt.join(SystemAsset, SystemAsset.asset_id == CryptoAsset.id).where(SystemAsset.system_id == system_id)
    if asset_ids is not None:
        stmt = stmt.where(CryptoAsset.id.in_(asset_ids))
    if db.execute(stmt.limit(1)).first():
        raise HTTPException(409, "Unreviewed historical CBOM import: review provenance and reimport the original declaration before export or assessment")


def refuse_legacy_records(records) -> None:
    """Also fence source rows changing between the SQL precheck and read."""
    if any(is_legacy_import(row.to_dict() if hasattr(row, "to_dict") else row) for row in records):
        raise HTTPException(409, "Unreviewed historical CBOM records cannot be exported or assessed as current inventory")


def _system(db: Session, system_id: str, *, lock: bool = False) -> System:
    stmt = select(System).where(System.id == system_id, System.tenant_id == current_tenant())
    if lock:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    system = db.execute(stmt).scalar_one_or_none()
    if system is None:
        raise HTTPException(404, "System not found")
    return system


def evidence_membership(db, asset_ids, *, lock=False):
    if lock and asset_ids:
        links = list(db.execute(select(CryptoAssetEvidence).where(CryptoAssetEvidence.asset_id.in_(asset_ids))
            .order_by(CryptoAssetEvidence.id).limit(10001).with_for_update()).scalars())
        if len(links) > 10000:
            raise HTTPException(413, "Evidence membership exceeds 10000-link safety limit")
        evidence_ids = sorted({link.evidence_id for link in links})
        if evidence_ids:
            db.execute(select(EvidenceRecord.id).where(EvidenceRecord.id.in_(evidence_ids))
                       .order_by(EvidenceRecord.id).with_for_update()).all()
    rows = db.execute(select(CryptoAssetEvidence, EvidenceRecord.updated_at, EvidenceRecord.content_hash,
                             EvidenceRecord.chain_hash, EvidenceRecord.deleted_at)
        .outerjoin(EvidenceRecord, EvidenceRecord.id == CryptoAssetEvidence.evidence_id)
        .where(CryptoAssetEvidence.asset_id.in_(asset_ids)).order_by(CryptoAssetEvidence.id).limit(10001)).all()
    if len(rows) > 10000:
        raise HTTPException(413, "Evidence membership exceeds 10000-link safety limit")
    counts, membership = {}, []
    for link, updated, content, chain, deleted in rows:
        if content is None:
            raise HTTPException(409, "Evidence linkage unavailable or inconsistent; controlled investigation required")
        counts[link.asset_id] = counts.get(link.asset_id, 0) + 1
        membership.append([link.id, link.asset_id, link.evidence_id, str(link.updated_at), str(updated), content, chain, str(deleted)])
    return membership, counts


def _review(db: Session, system: System, *, lock: bool = False) -> tuple[dict, list[CryptoAsset], list[CryptoAsset]]:
    stmt = select(CryptoAsset).join(SystemAsset, SystemAsset.asset_id == CryptoAsset.id).where(
        SystemAsset.system_id == system.id, legacy_import_clause(), ~archived_legacy_clause()
    ).order_by(CryptoAsset.id).limit(REVIEW_MAX_ASSETS + 1)
    if lock:
        # Stable order also serializes shared legacy rows across two systems.
        stmt = stmt.with_for_update(of=CryptoAsset).execution_options(populate_existing=True)
    assets = list(db.execute(stmt).scalars())
    if len(assets) > REVIEW_MAX_ASSETS:
        raise HTTPException(413, "Historical review exceeds the 2000-asset safety limit; controlled operator reconciliation required")
    membership, evidence_counts = evidence_membership(db, [asset.id for asset in assets], lock=lock)
    replacement_query = (select(CryptoAsset).join(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
        .where(SystemAsset.system_id == system.id,
               CryptoAsset.extra["cbom_import"]["system_id"].as_string() == system.id)
        .order_by(CryptoAsset.id).limit(REVIEW_MAX_ASSETS + 1))
    if lock:
        replacement_query = replacement_query.with_for_update(of=CryptoAsset).execution_options(populate_existing=True)
    replacements = list(db.execute(replacement_query).scalars())
    if len(replacements) > REVIEW_MAX_ASSETS:
        raise HTTPException(413, "Replacement inventory exceeds the 2000-asset review safety limit")
    system_extra = system.extra if isinstance(system.extra, dict) else {}
    receipt = system_extra.get("cbom_import") or {}
    fingerprint = receipt.get("document_sha256") if isinstance(receipt, dict) else None
    # Hash complete persisted source state, but return no arbitrary extra data,
    # raw snippets, paths, credentials or findings in the review listing.
    canonical = {"system":RowModel.to_dict(system),
                 "legacy":[RowModel.to_dict(asset) for asset in assets],
                 "evidence_counts":evidence_counts, "evidence_membership":membership,
                 "replacements":[RowModel.to_dict(asset) for asset in replacements]}
    snapshot = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    return {"system_id":system.id, "system_name":system.name, "snapshot_sha256":snapshot,
            "replacement_document_sha256":fingerprint, "pending_assets":len(assets),
            "mixed_evidence_assets":sum(bool(evidence_counts.get(asset.id)) for asset in assets),
            "assets":[{"id":asset.id, "algorithm":asset.algorithm,
                       "reported_confidence":asset.confidence, "source_basis":"LEGACY_IMPORT_REVIEW_REQUIRED",
                       "linked_evidence_count":evidence_counts.get(asset.id, 0)} for asset in assets],
            "limit":REVIEW_MAX_ASSETS,
            "message":"Reimport is declaration metadata, not a scan or bank approval. Linked evidence requires controlled manual review."}, assets, replacements


def _identity(asset: CryptoAsset) -> tuple:
    return asset.algorithm, asset.purpose or "", asset.file_path or "", int(asset.line_number or 0)


def register_legacy_routes(router, require_writer) -> None:
    @router.get("/legacy-imports")
    def list_legacy_imports(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                            user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
        pending = legacy_import_clause() & ~archived_legacy_clause()
        linked = select(SystemAsset.id).join(CryptoAsset, CryptoAsset.id == SystemAsset.asset_id).where(
            SystemAsset.system_id == System.id, pending).correlate(System).exists()
        total = int(db.execute(select(func.count()).select_from(System).where(linked)).scalar_one())
        systems = db.execute(select(System.id, System.name).where(linked).order_by(System.name, System.id)
                             .offset((page-1)*page_size).limit(page_size)).all()
        assigned = select(SystemAsset.id).where(SystemAsset.asset_id == CryptoAsset.id).correlate(CryptoAsset).exists()
        orphaned = int(db.execute(select(func.count()).select_from(CryptoAsset).where(pending, ~assigned)).scalar_one())
        return {"systems":[{"id":row.id, "name":row.name} for row in systems], "total":total,
                "page":page, "page_size":page_size, "unassigned_review_required":orphaned}

    @router.get("/system/{system_id}/legacy-imports")
    def get_legacy_imports(system_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
        return _review(db, _system(db, system_id))[0]

    @router.post("/system/{system_id}/reconcile-legacy")
    def reconcile_legacy(system_id: str, body: ReconcileLegacyRequest,
                         user: str = Depends(require_writer), db: Session = Depends(get_db_session)):
        try:
            system = _system(db, system_id, lock=True)
            review, assets, replacements = _review(db, system, lock=True)
            if review["snapshot_sha256"] != body.expected_snapshot_sha256:
                raise HTTPException(409, "Historical inventory changed; reload and review before submitting again")
            if not assets:
                raise HTTPException(409, "No pending historical imports; no automatic replay")
            if review["mixed_evidence_assets"]:
                raise HTTPException(409, "Historical rows have linked scanner evidence; automatic reconciliation refused. Preserve evidence and use controlled manual review.")
            if len(body.reason.strip()) < 20:
                raise HTTPException(422, "A review rationale of at least 20 non-padding characters is required; do not include secrets")
            fingerprint = body.replacement_document_sha256
            matching = [a for a in replacements if (a.extra or {}).get("cbom_import", {}).get("document_sha256") == fingerprint]
            if review["replacement_document_sha256"] != fingerprint or not matching:
                raise HTTPException(409, "Reimport and review the original declaration before reconciliation")
            identities = {_identity(asset) for asset in matching}
            if any(_identity(asset) not in identities for asset in assets):
                raise HTTPException(409, "Replacement does not cover every historical identity; incomplete reconciliation refused")
            audit = UserRepository(db).audit(user, "cbom.legacy_reconciled", target_type="system", target_id=system.id,
                detail={"source_snapshot_sha256":review["snapshot_sha256"], "replacement_document_sha256":fingerprint,
                        "asset_ids":[asset.id for asset in assets], "reason":body.reason.strip(),
                        "source_basis":"DECLARATION_RECONCILIATION_NOT_SCANNER_OBSERVATION"})
            ids = [asset.id for asset in assets]
            db.execute(delete(SystemAsset).where(SystemAsset.system_id == system.id, SystemAsset.asset_id.in_(ids)))
            still_linked = set(db.execute(select(SystemAsset.asset_id).where(SystemAsset.asset_id.in_(ids))).scalars())
            archived = 0
            for asset in assets:
                if asset.id not in still_linked:
                    # Retain original fields, confidence, scan marker and evidence.
                    # This marker affects *current* declarations, not pinned history.
                    asset.extra = {**(asset.extra or {}), "legacy_cbom_disposition":{
                        "state":ARCHIVED_DECLARATION, "audit_id":audit.id,
                        "reconciled_at":datetime.now(timezone.utc).isoformat(), "document_sha256":fingerprint}}
                    archived += 1
            system.extra = {**(system.extra or {}), "legacy_cbom_observation_unproven":True,
                            "legacy_cbom_reconciliation":{"audit_id":audit.id, "document_sha256":fingerprint}}
            audit_id = audit.id
            db.commit()  # response is a durable receipt, never a pre-commit promise
            return {"system_id":system_id, "audit_id":audit_id, "detached_assets":len(ids),
                    "archived_declarations":archived, "source_basis":"DECLARATION_RECONCILIATION_NOT_SCANNER_OBSERVATION"}
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Concurrent inventory change; reload and review") from None
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(503, "Reconciliation outcome unconfirmed; reload inventory and audit before retrying") from None
        except Exception:
            db.rollback()
            raise
