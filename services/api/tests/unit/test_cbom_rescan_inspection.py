"""A committed rescan is scoped evidence, never automatic complete-estate proof."""
from datetime import timedelta
from sqlalchemy import text
import pytest
from test_assurance_workflows import assured as assured
from test_software_supply_chain_api import banks as banks
from test_cbom_controlled_history import completed
from db.models import EvidenceRecord,Scan
from db.models.scan_job import ScanJob
from db.models.system import System
from db.models.base import utcnow
from evidence.core.pipeline import EvidencePipeline


def rescan(assured):
    clients,db,sid,aid,eid,_=completed(assured)
    start=utcnow();end=start+timedelta(microseconds=1)
    scan=Scan(tenant_id='a',target_location='/synthetic/payments',scan_start=start,scan_end=end,status='COMPLETED',target_type='LOCAL_DIRECTORY',target_branch='main',
        statistics={'file_observation_receipts':[{'file':'src/crypto.py','sha256':'c'*64,'parser_completed':True}]})
    db.add(scan);db.flush()
    pipeline=EvidencePipeline(scan.id)
    records,manifest=pipeline.process(findings=[{'crypto':{'algorithm':'AES','key_size':256},
        'source':{'file_path':'src/crypto.py','line_number':1},'metadata':{'confidence':'HIGH'}}])
    for r in records:
        db.add(EvidenceRecord(id=r.evidence_id,tenant_id='a',scan_id=scan.id,content_hash=r.content_hash,
            chain_hash=r.chain_hash,chain_position=r.chain_position,previous_hash=r.previous_hash,
            file_path='src/crypto.py',line_number=1,algorithm='AES',finding_data=r.finding))
    scan.manifest_hash=manifest.manifest_hash
    job=ScanJob(tenant_id='a',system_id=sid,target_repo=scan.target_location,triggered_by='synthetic',
        status='COMPLETED',scan_id=scan.id,started_at=start,completed_at=end)
    db.add(job);system=db.get(System,sid);system.scan_target=scan.target_location;system.last_scan_id=scan.id;system.scan_branch='main'
    db.commit()
    return clients,db,sid,scan.id,job.id


def inspect(client,sid,jid):return client.get(f'/api/v1/cbom/system/{sid}/rescan-inspection?job_id={jid}')


def test_verified_rescan_is_scoped_not_automatic_clearance(assured):
    clients,db,sid,scan,jid=rescan(assured)
    response=inspect(clients['bank_a'],sid,jid);assert response.status_code==200,response.text
    result=response.json()
    assert result['result']=='VERIFIED_SCOPED_RESCAN'
    assert result['integrity']['result']=='PASS' and result['integrity']['records']==1
    assert result['parsed_files']==1 and result['unparsed_files']==0
    assert result['clears_partial_history'] is False and result['bank_approved'] is False
    assert clients['bank_a'].post('/api/v1/cbom/assess',json={'system_id':sid}).status_code==409
    assert 'src/crypto.py' not in response.text and '/synthetic/payments' not in response.text
    assert clients['bank_a'].get('/api/v1/cbom/retained-histories').json()['systems'][0]['id']==sid


@pytest.mark.parametrize('change',['wrong_system','foreign_job','null_tenant','wrong_target','old_scan','unfinished',
    'wrong_branch','requested_commit','nonlocal_type','future','no_receipts','all_unparsed','content_tamper','manifest_tamper','unreceipted_finding','not_latest','oversize'])
def test_unproven_or_changed_rescan_cannot_be_verified(assured,change):
    clients,db,sid,scan_id,jid=rescan(assured)
    scan=db.get(Scan,scan_id);job=db.get(ScanJob,jid)
    if change=='wrong_system':job.system_id='system-a'
    elif change=='foreign_job':
        # Corrupt stored ownership via test-only SQL; ordinary ORM mutation is correctly forbidden.
        db.execute(text('UPDATE scan_jobs SET tenant_id=:tenant WHERE id=:id'),{'tenant':'b','id':jid})
    elif change=='null_tenant':
        db.execute(text('UPDATE scans SET tenant_id=NULL WHERE id=:id'),{'id':scan_id})
    elif change=='wrong_target':job.target_repo='/synthetic/other'
    elif change=='old_scan':
        scan.scan_start-=timedelta(days=1);job.started_at=scan.scan_start
    elif change=='wrong_branch':scan.target_branch='other'
    elif change=='requested_commit':job.target_commit='a'*40
    elif change=='nonlocal_type':scan.target_type='GIT_REPOSITORY'
    elif change=='unfinished':job.status='RUNNING'
    elif change=='future':scan.scan_end=utcnow()+timedelta(days=1);job.completed_at=scan.scan_end
    elif change=='no_receipts':scan.statistics={}
    elif change=='all_unparsed':scan.statistics={'file_observation_receipts':[{'file':'src/crypto.py','sha256':'c'*64,'parser_completed':False}]}
    elif change=='content_tamper':db.query(EvidenceRecord).filter_by(scan_id=scan_id).one().finding_data={'tampered':True}
    elif change=='manifest_tamper':scan.manifest_hash='d'*64
    elif change=='unreceipted_finding':scan.statistics={'file_observation_receipts':[{'file':'other.py','sha256':'c'*64,'parser_completed':True}]}
    elif change=='not_latest':db.get(System,sid).last_scan_id='other-scan'
    elif change=='oversize':
        # Bound check does not need allocating a giant payload in the API test.
        scan.statistics={'file_observation_receipts':[{'file':f'{i}.py','sha256':'c'*64,'parser_completed':True} for i in range(1001)]}
    db.commit()
    response=inspect(clients['bank_a'],sid,jid)
    assert response.status_code== (404 if change in {'foreign_job','null_tenant'} else 409),response.text
    assert clients['bank_a'].post('/api/v1/cbom/assess',json={'system_id':sid}).status_code==409


def test_retained_inventory_and_inspection_are_exact_estate(assured):
    clients,db,sid,scan,jid=rescan(assured)
    platform=System(name='Synthetic platform retained',extra={'retained_mixed_evidence_count':1})
    db.add(platform);db.commit()
    assert clients['bank_a'].get('/api/v1/cbom/retained-histories').json()['total']==1
    assert inspect(clients['bank_a'],platform.id,jid).status_code==404
    assert clients['bank_b'].get('/api/v1/cbom/retained-histories').json()['total']==0
    assert inspect(clients['bank_b'],sid,jid).status_code==404
    assert clients['bank_a'].get('/api/v1/cbom/retained-histories?page_size=201').status_code==422
    from db.repositories.user_repository import UserRepository
    UserRepository(db).set_roles('reader_a',['readonly']);db.commit()
    assert inspect(clients['reader_a'],sid,jid).status_code==200


def test_empty_manifest_is_not_absence_or_complete_inventory_proof(assured):
    import hashlib
    clients,db,sid,scan_id,jid=rescan(assured)
    db.query(EvidenceRecord).filter_by(scan_id=scan_id).delete()
    db.get(Scan,scan_id).manifest_hash=hashlib.sha256(b'').hexdigest();db.commit()
    response=inspect(clients['bank_a'],sid,jid);assert response.status_code==200,response.text
    assert response.json()['result']=='VERIFIED_EMPTY_SCOPED_RESCAN'
    assert response.json()['absence_proven'] is False
    assert response.json()['whole_system_coverage_verified'] is False


def test_evidence_bound_fails_closed_before_any_prefix_verdict(assured,monkeypatch):
    import api.routers.cbom_rescan_inspection as module
    clients,db,sid,scan,jid=rescan(assured)
    monkeypatch.setattr(module,'MAX_RECORDS',0)
    response=inspect(clients['bank_a'],sid,jid)
    assert response.status_code==409 and 'bounded' in response.text


def test_metadata_path_is_not_trusted_over_committed_content(assured):
    clients,db,sid,scan_id,jid=rescan(assured)
    db.query(EvidenceRecord).filter_by(scan_id=scan_id).one().file_path='forged-column.py';db.commit()
    response=inspect(clients['bank_a'],sid,jid)
    assert response.status_code==200,response.text
    assert 'forged-column.py' not in response.text


def test_actual_scanner_and_evidence_loader_to_scoped_inspection(assured):
    """Real local parser/file receipts/hashes/load; job envelope is test-provisioned."""
    from scanner.core.scanner import Scanner
    from db.loader.evidence_loader import EvidenceLoader
    from db.tenancy import tenant_scope
    clients,db,sid,aid,eid,_=completed(assured)
    root=assured[2]/'rescan-source';root.mkdir()
    (root/'crypto.py').write_text("import hashlib\nhashlib.md5(b'non-secret synthetic fixture')\n")
    (root/'negative.py').write_text('def add(a,b):\n    return a+b\n')
    started=utcnow()
    real=Scanner().scan(root_path=root,target_type='LOCAL_DIRECTORY',target_location=str(root),target_branch='main')
    assert any(f.crypto.algorithm=='MD5' for f in real.findings)
    records,manifest=EvidencePipeline(real.scan_id).process(findings=real.findings,scan_id=real.scan_id)
    with tenant_scope('a'):
        scan=EvidenceLoader(db).load(scan_meta={
            'scan_start':real.scan_start,'scan_end':real.scan_end,'status':'COMPLETED',
            'target_type':'LOCAL_DIRECTORY','target_location':str(root),'target_branch':'main',
            'statistics':real.statistics.model_dump(mode='json')},
            evidence_records=[r.model_dump(mode='json') for r in records],manifest=manifest.model_dump(mode='json'),scan_id=real.scan_id)
        system=db.get(System,sid);system.scan_target=str(root);system.scan_branch='main';system.last_scan_id=scan.id
        job=ScanJob(tenant_id='a',system_id=sid,scan_id=scan.id,status='COMPLETED',started_at=started,completed_at=utcnow(),
                    target_repo=str(root),target_branch='main',triggered_by='synthetic')
        db.add(job);db.commit();jid=job.id
    response=inspect(clients['bank_a'],sid,jid);assert response.status_code==200,response.text
    assert response.json()['parsed_files']==2
    assert response.json()['integrity']['result']=='PASS'
    assert clients['bank_a'].post('/api/v1/cbom/assess',json={'system_id':sid}).status_code==409
