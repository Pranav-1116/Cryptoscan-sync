"""Explicit human ownership and two-person retention, never evidence rewriting."""
from fastapi import Depends, HTTPException, Request, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from api.assurance import store
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author
from db.models import CryptoAsset, SystemAsset
from db.models.base import BaseModel as RowModel
from db.import_provenance import legacy_import_clause, archived_legacy_clause
from db.repositories.user_repository import UserRepository
from db.tenancy import current_tenant
from shared_models.import_provenance import ARCHIVED_DECLARATION, RETAINED_MIXED_EVIDENCE

KIND = 'legacy_mixed_review'


class Statement(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    reason: str = Field(min_length=20, max_length=500)
    evidence_ref: str = Field(min_length=3, max_length=500)


class Assignment(Statement):
    expected_snapshot_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    system_id: str = Field(min_length=1, max_length=36)


class Proposal(Statement):
    expected_snapshot_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    replacement_document_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


class Approval(Statement):
    expected_case_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


def _asset(db, identifier, lock=False):
    query = select(CryptoAsset).where(CryptoAsset.id == identifier, CryptoAsset.tenant_id == current_tenant(),
                                    legacy_import_clause(), ~archived_legacy_clause())
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    row = db.execute(query).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, 'Pending historical asset not found in selected estate')
    return row


def _orphan_review(db, asset, *, lock=False):
    from api.routers.cbom_legacy import evidence_membership
    membership, counts = evidence_membership(db, [asset.id], lock=lock)
    associations = list(db.execute(select(SystemAsset.id, SystemAsset.system_id, SystemAsset.updated_at)
        .where(SystemAsset.asset_id == asset.id).order_by(SystemAsset.id).limit(2001)).all())
    if len(associations) > 2000:
        raise HTTPException(413, 'Association review exceeds safety bound')
    snapshot = store.digest({'asset':RowModel.to_dict(asset), 'evidence':membership,
                             'associations':[[str(v) for v in row] for row in associations]})
    return {'asset_id':asset.id,'algorithm':asset.algorithm,'snapshot_sha256':snapshot,
            'linked_evidence_count':counts.get(asset.id,0),'unassigned':not associations,
            'source_basis':'LEGACY_IMPORT_REVIEW_REQUIRED'}


def _replacement(review, assets, replacements, fingerprint):
    from api.routers.cbom_legacy import _identity
    matching = [a for a in replacements if (a.extra or {}).get('cbom_import',{}).get('document_sha256') == fingerprint]
    if review['replacement_document_sha256'] != fingerprint or not matching:
        raise HTTPException(409,'Reimport and review original replacement declarations first')
    keys = {_identity(a) for a in matching}
    if any(_identity(a) not in keys for a in assets):
        raise HTTPException(409,'Replacement does not cover every historical identity')


def _finish(db, fn):
    try:
        result = fn()
        db.commit()
        return result
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(503,'Decision outcome unconfirmed; reload inventory and audit, do not automatically replay') from None
    except Exception:
        db.rollback()
        raise


def register_controlled_routes(router):
    from api.routers.cbom_legacy import _system, _review

    @router.get('/legacy-imports/unassigned')
    def unassigned(page: int = Query(1,ge=1),page_size: int = Query(50,ge=1,le=200),
                   user=Depends(get_current_user),db=Depends(get_db_session),ctx=Depends(estate)):
        associated = select(SystemAsset.id).where(SystemAsset.asset_id == CryptoAsset.id).correlate(CryptoAsset).exists()
        conditions = (CryptoAsset.tenant_id == ctx.tenant_id,legacy_import_clause(),~archived_legacy_clause(),~associated)
        total = db.execute(select(func.count()).select_from(CryptoAsset).where(*conditions)).scalar_one()
        rows = db.execute(select(CryptoAsset).where(*conditions).order_by(CryptoAsset.id)
                          .offset((page-1)*page_size).limit(page_size)).scalars()
        return {'total':total,'page':page,'page_size':page_size,
                'assets':[{'id':a.id,'algorithm':a.algorithm,'confidence':'LOW','source_basis':'LEGACY_IMPORT_REVIEW_REQUIRED'} for a in rows]}

    @router.get('/legacy-assets/{asset_id}/review')
    def orphan_review(asset_id: str,user=Depends(get_current_user),db=Depends(get_db_session),ctx=Depends(estate)):
        return _orphan_review(db,_asset(db,asset_id))

    @router.post('/legacy-assets/{asset_id}/assign')
    def assign(asset_id: str,body: Assignment,request: Request,user=Depends(get_current_user),
               db=Depends(get_db_session),ctx=Depends(estate)):
        actor = author(db,request,user)
        def perform():
            system = _system(db,body.system_id,lock=True)
            asset = _asset(db,asset_id,lock=True)
            state = _orphan_review(db,asset,lock=True)
            if state['snapshot_sha256'] != body.expected_snapshot_sha256 or not state['unassigned']:
                raise HTTPException(409,'Ownership/evidence changed; reload and review')
            db.add(SystemAsset(tenant_id=ctx.tenant_id,system_id=system.id,asset_id=asset.id))
            system.extra = {**(system.extra or {}),'legacy_cbom_observation_unproven':True}
            receipt = UserRepository(db).audit(user,'cbom.legacy_assigned',target_type='asset',target_id=asset.id,
                detail={**body.model_dump(),'human_id':actor,'source_basis':'OPERATOR_DECLARED_ASSIGNMENT_NOT_SCAN_OR_APPROVAL'})
            return {'asset_id':asset.id,'system_id':system.id,'audit_id':receipt.id,
                    'source_basis':'OPERATOR_DECLARED_ASSIGNMENT_NOT_SCAN_OR_APPROVAL'}
        return _finish(db,perform)

    @router.get('/system/{system_id}/mixed-review')
    def case(system_id: str,user=Depends(get_current_user),db=Depends(get_db_session),ctx=Depends(estate)):
        _system(db,system_id)
        row = store.latest(db,ctx.tenant_id,KIND,system_id,required=False)
        return {'case':store.public(row) if row else None,'bank_approved':False}

    @router.post('/system/{system_id}/mixed-review',status_code=201)
    def propose(system_id: str,body: Proposal,request: Request,user=Depends(get_current_user),
                db=Depends(get_db_session),ctx=Depends(estate)):
        actor = author(db,request,user)
        def perform():
            system = _system(db,system_id,lock=True)
            review,assets,replacements = _review(db,system,lock=True)
            if review['snapshot_sha256'] != body.expected_snapshot_sha256 or not review['mixed_evidence_assets']:
                raise HTTPException(409,'Current mixed-source snapshot required')
            _replacement(review,assets,replacements,body.replacement_document_sha256)
            previous = store.latest(db,ctx.tenant_id,KIND,system_id,required=False)
            row = store.append(db,ctx.tenant_id,KIND,system_id,previous.revision if previous else 0,
                {**body.model_dump(),'state':'PENDING_SECOND_HUMAN','submitted_by':actor,'system_id':system.id},actor,commit=False)
            UserRepository(db).audit(user,'cbom.mixed_proposed',target_type='system',target_id=system.id,
                                     detail={'case_sha256':row.payload_sha256,'evidence_ref':body.evidence_ref})
            return store.public(row)
        return _finish(db,perform)

    @router.post('/system/{system_id}/mixed-review/approve')
    def approve(system_id: str,body: Approval,request: Request,user=Depends(get_current_user),
                db=Depends(get_db_session),ctx=Depends(estate)):
        actor = author(db,request,user,'assurance.trust')
        def perform():
            system = _system(db,system_id,lock=True)
            old = store.latest(db,ctx.tenant_id,KIND,system_id)
            if old.payload_sha256 != body.expected_case_sha256 or old.payload['state'] != 'PENDING_SECOND_HUMAN' or old.created_by == actor:
                raise HTTPException(409,'A different current human must review the pending case once')
            review,assets,replacements = _review(db,system,lock=True)
            if review['snapshot_sha256'] != old.payload['expected_snapshot_sha256']:
                raise HTTPException(409,'Source or evidence changed; submit a new reviewed case')
            _replacement(review,assets,replacements,old.payload['replacement_document_sha256'])
            from sqlalchemy import delete
            ids = [a.id for a in assets]
            counts = {a['id']:a['linked_evidence_count'] for a in review['assets']}
            audit = UserRepository(db).audit(user,'cbom.mixed_reconciled',target_type='system',target_id=system.id,
                detail={'proposal_sha256':old.payload_sha256,'evidence_ref':body.evidence_ref,'reason':body.reason,
                        'asset_ids':ids,'submitted_by':old.created_by,'reviewed_by':actor})
            db.execute(delete(SystemAsset).where(SystemAsset.system_id == system.id,SystemAsset.asset_id.in_(ids)))
            shared = set(db.execute(select(SystemAsset.asset_id).where(SystemAsset.asset_id.in_(ids))).scalars())
            for asset in assets:
                if asset.id not in shared:
                    asset.extra = {**(asset.extra or {}),'legacy_cbom_disposition':{
                        'state':RETAINED_MIXED_EVIDENCE if counts[asset.id] else ARCHIVED_DECLARATION,
                        'evidence_link_count':counts[asset.id],'audit_id':audit.id}}
            extra = system.extra or {}
            system.extra = {**extra,'legacy_cbom_observation_unproven':True,
                'retained_mixed_evidence_count':int(extra.get('retained_mixed_evidence_count',0))+review['mixed_evidence_assets']}
            db.flush()  # source updates precede the immutable review timestamp
            row = store.append(db,ctx.tenant_id,KIND,system_id,old.revision,
                {**old.payload,'state':'DECLARATIONS_RECONCILED_EVIDENCE_RETAINED','reviewed_by':actor,
                 'review_reason':body.reason,'review_evidence_ref':body.evidence_ref,'audit_id':audit.id,
                 'bank_approved':False,'requires_verified_rescan_for_current_evidence':True,
                 'retained_assets':{a.id:str(counts[a.id]) for a in assets if a.id not in shared}},actor,commit=False)
            for asset in assets:
                if asset.id not in shared:
                    asset.extra = {**asset.extra,'legacy_cbom_disposition':{**asset.extra['legacy_cbom_disposition'],'review_id':row.id}}
            return {'case':store.public(row),'audit_id':audit.id,'detached_associations':len(ids),
                    'retained_mixed_assets':review['mixed_evidence_assets'],'bank_approved':False}
        return _finish(db,perform)


def _metadata(count):
    return ([{'name':'cryptoscan:retained_mixed_evidence_assets','value':str(count)},
             {'name':'cryptoscan:inventory_completeness','value':'PARTIAL_RETAINED_MIXED_EVIDENCE'}] if count else [])


def retained_system_metadata(system):
    return _metadata(int((system.extra or {}).get('retained_mixed_evidence_count',0)))


def retained_metadata(db):
    from db.import_provenance import retained_mixed_clause
    count = db.execute(select(func.count()).select_from(CryptoAsset).where(retained_mixed_clause(),archived_legacy_clause())).scalar_one()
    return _metadata(count)


def refuse_partial_assessment(db, system_id=None):
    from db.models.system import System
    query = select(System.id).where(func.coalesce(System.extra['retained_mixed_evidence_count'].as_integer(),0) > 0)
    if system_id is not None:
        query = query.where(System.id == system_id)
    if db.execute(query.limit(1)).first():
        raise HTTPException(409,'Mixed evidence retained outside current inventory; no clean posture grade until verified rescan and controlled reassessment')
