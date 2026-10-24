"""Read-only proof inspection: a parsed source scope is not complete inventory."""
from fastapi import Depends,HTTPException,Query
from sqlalchemy import func,select
from api.dependencies import get_current_user,get_db_session
from api.assurance import store
from api.assurance.coverage import _source_completion
from api.routers.assurance_boundary import estate
from api.routers.cbom_legacy import _system
from api.routers.cbom_legacy_controlled import KIND
from db.models import System,Scan,EvidenceRecord
from db.models.scan_job import ScanJob
from db.models.base import BaseModel,utcnow
from db.repositories.execution_control import aware
from evidence.verification.stored_scan import verify_stored_scan

MAX_RECORDS=10000


def inspect_rescan(db,owner,system,job_id):
    case=store.latest(db,owner,KIND,system.id)
    if (case.payload.get('state')!='DECLARATIONS_RECONCILED_EVIDENCE_RETAINED'
            or int((system.extra or {}).get('retained_mixed_evidence_count',0))<=0):
        raise HTTPException(409,'An approved retained mixed history is required; no automatic clearance')
    job=db.execute(select(ScanJob).where(ScanJob.id==job_id,ScanJob.tenant_id==owner)
                   .execution_options(populate_existing=True)).scalar_one_or_none()
    if job is None:raise HTTPException(404,'Job not found in selected estate')
    if job.system_id!=system.id or not system.scan_target or job.target_repo!=system.scan_target:
        raise HTTPException(409,'Job must bind the exact selected system and configured source target')
    scan=db.execute(select(Scan).where(Scan.id==job.scan_id,Scan.tenant_id==owner)
                    .execution_options(populate_existing=True)).scalar_one_or_none()
    if scan is None:raise HTTPException(404,'Scan not found in selected estate')
    now=utcnow()
    completed=_source_completion(job,scan,system.scan_target,now)
    if (scan.target_type!='LOCAL_DIRECTORY' or job.target_commit or scan.target_commit
            or job.target_branch!=scan.target_branch
            or (system.scan_branch and job.target_branch!=system.scan_branch)):
        raise HTTPException(409,'Exact local-source method/branch required; Git commit identity is not inferred')
    if aware(scan.scan_start)<=aware(case.created_at) or system.last_scan_id!=scan.id:
        raise HTTPException(409,'Latest system rescan must start after the retained-history approval')
    # Include tombstones in committed integrity; never verify a filtered chain.
    rows=list(db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id==scan.id,EvidenceRecord.tenant_id==owner)
                         .order_by(EvidenceRecord.chain_position,EvidenceRecord.id).limit(MAX_RECORDS+1)
                         .execution_options(populate_existing=True)).scalars())
    if len(rows)>MAX_RECORDS:raise HTTPException(409,'Rescan exceeds bounded 10000-record inspection; no clearance assumed')
    try:
        verdict=verify_stored_scan(scan,rows)
    except (ValueError,TypeError,RecursionError):
        raise HTTPException(409,'Stored rescan payload cannot be verified') from None
    if verdict['result'] not in {'PASS','EMPTY'}:
        raise HTTPException(409,'Committed rescan content, order or manifest is unverified; investigate scan integrity')
    receipts=scan.statistics['file_observation_receipts']
    parsed={r['file'] for r in receipts if r['parser_completed'] is True}
    for row in rows:
        # Use the HASH-VERIFIED content, not mutable denormalized path/algorithm columns.
        finding=row.finding_data
        source=finding.get('source') if isinstance(finding,dict) else None
        if not isinstance(source,dict) or not isinstance(source.get('file_path'),str) or source['file_path'] not in parsed:
            raise HTTPException(409,'Every committed finding requires a completed exact source-file parser receipt')
    snapshot=store.digest({'system':BaseModel.to_dict(system),'case_sha256':case.payload_sha256,
        'job':BaseModel.to_dict(job),'scan':BaseModel.to_dict(scan),'evidence':[
            [r.id,r.content_hash,r.chain_hash,str(r.updated_at),str(r.deleted_at)] for r in rows]})
    return {'system_id':system.id,'job_id':job.id,'scan_id':scan.id,'source_snapshot_sha256':snapshot,
        'retained_case_sha256':case.payload_sha256,'result':'VERIFIED_SCOPED_RESCAN' if rows else 'VERIFIED_EMPTY_SCOPED_RESCAN',
        'integrity':{k:verdict[k] for k in ('result','records','chain_intact','content_intact','manifest_intact','hash_format_valid')},
        'parsed_files':len(parsed),'unparsed_files':len(receipts)-len(parsed),'completed_at':completed.isoformat(),
        'inspected_at':now.isoformat(),'clears_partial_history':False,'bank_approved':False,'absence_proven':False,
        'whole_system_coverage_verified':False,'freshness_slo_qualified':False,
        'basis':'CURRENT_SQL_JOB_SOURCE_RECEIPTS_AND_COMMITTED_CONTENT_NOT_COMPLETENESS_OR_RUNTIME_PROOF'}


def register_rescan_routes(router):
    @router.get('/retained-histories')
    def retained(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=200),
                 user=Depends(get_current_user),db=Depends(get_db_session),ctx=Depends(estate)):
        conditions=(System.tenant_id==ctx.tenant_id,func.coalesce(System.extra['retained_mixed_evidence_count'].as_integer(),0)>0)
        total=db.execute(select(func.count()).select_from(System).where(*conditions)).scalar_one()
        systems=db.execute(select(System.id,System.name).where(*conditions).order_by(System.name,System.id)
                           .offset((page-1)*page_size).limit(page_size)).all()
        return {'systems':[{'id':s.id,'name':s.name} for s in systems],'page':page,'page_size':page_size,'total':total,'bank_approved':False}

    @router.get('/system/{system_id}/rescan-inspection')
    def inspect(system_id:str,job_id:str=Query(min_length=1,max_length=36),
                user=Depends(get_current_user),db=Depends(get_db_session),ctx=Depends(estate)):
        return inspect_rescan(db,ctx.tenant_id,_system(db,system_id),job_id)
