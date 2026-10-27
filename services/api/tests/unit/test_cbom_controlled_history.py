"""Controlled histories use actual durable humans, not body-provided approvers."""
import pytest
from test_assurance_workflows import assured as assured
from test_software_supply_chain_api import banks as banks
from test_cbom_legacy_reconciliation import legacy, detail
from test_cbom_production_flow import ingest
from db.models import CryptoAsset, SystemAsset, Scan, EvidenceRecord
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.base import BaseModel, utcnow
from db.repositories.user_repository import UserRepository


def mixed(db):
    sid, aid = legacy(db)
    scan = Scan(tenant_id="a", target_location="synthetic-only", scan_start=utcnow(), status="COMPLETED")
    db.add(scan); db.flush()
    evidence = EvidenceRecord(tenant_id="a", scan_id=scan.id, content_hash="a"*64,chain_hash="b"*64,
        chain_position=1, file_path="synthetic-only",line_number=1,finding_data={"preserve":"synthetic"})
    db.add(evidence);db.flush()
    db.add(CryptoAssetEvidence(tenant_id="a",asset_id=aid,evidence_id=evidence.id));db.commit();db.expire_all()
    return sid,aid,evidence.id


def proposal(client,sid):
    state=detail(client,sid)
    return client.post(f"/api/v1/cbom/system/{sid}/mixed-review",json={
        "expected_snapshot_sha256":state['snapshot_sha256'],
        "replacement_document_sha256":state['replacement_document_sha256'],
        "reason":"Reviewed replacement declarations and preserved original mixed evidence.","evidence_ref":"change/synthetic-42"})


def approve(client,sid,case):
    return client.post(f"/api/v1/cbom/system/{sid}/mixed-review/approve",json={
        "expected_case_sha256":case['payload_sha256'],"reason":"Second human reviewed retained evidence and partial export implications.",
        "evidence_ref":"review/synthetic-42"})


def test_two_humans_preserve_mixed_rows_and_disclose_partial_exports(assured):
    clients,db,_=assured;sid,aid,eid=mixed(db)
    before=BaseModel.to_dict(db.get(EvidenceRecord,eid))
    assert ingest(clients['bank_a']).status_code==200
    UserRepository(db).set_roles('bank_a',['ciso']);db.commit()
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    assert approve(clients['bank_a'],sid,p.json()).status_code==409
    assert clients['bank_a'].get(f'/api/v1/cbom/system/{sid}').status_code==409
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    result=approve(clients['reader_a'],sid,p.json());assert result.status_code==200,result.text
    db.expire_all()
    assert BaseModel.to_dict(db.get(EvidenceRecord,eid))==before
    assert db.query(CryptoAssetEvidence).filter_by(asset_id=aid,evidence_id=eid).count()==1
    assert db.get(CryptoAsset,aid).confidence=='HIGH'
    assert db.query(SystemAsset).filter_by(system_id=sid,asset_id=aid).count()==0
    exported=clients['bank_a'].get(f'/api/v1/cbom/system/{sid}?fmt=cyclonedx16')
    assert exported.status_code==200,exported.text
    props={p['name']:p['value'] for p in exported.json()['metadata']['properties']}
    assert props['cryptoscan:retained_mixed_evidence_assets']=='1'
    assert props['cryptoscan:inventory_completeness']=='PARTIAL_RETAINED_MIXED_EVIDENCE'
    assert clients['bank_a'].get('/api/v1/cbom/portfolio?fmt=cyclonedx16').status_code==200
    assert clients['bank_a'].get('/api/v1/cbom/assess/portfolio').status_code==409
    assert approve(clients['reader_a'],sid,p.json()).status_code==409


def test_link_membership_change_invalidates_pending_second_review(assured):
    clients,db,_=assured;sid,aid,eid=mixed(db);ingest(clients['bank_a'])
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    link=db.query(CryptoAssetEvidence).filter_by(asset_id=aid).one();db.delete(link);db.commit()
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    response=approve(clients['reader_a'],sid,p.json());assert response.status_code==409,response.text
    assert db.query(SystemAsset).filter_by(system_id=sid,asset_id=aid).count()==1


def test_unassigned_assignment_is_exact_estate_snapshot_checked_and_not_clearance(assured):
    clients,db,_=assured
    asset=CryptoAsset(tenant_id='a',algorithm='AES',file_path='synthetic-orphan',line_number=0,confidence='HIGH',scanner_ids=['cbom-ingest'])
    db.add(asset);db.commit();aid=asset.id
    inventory=clients['bank_a'].get('/api/v1/cbom/legacy-imports/unassigned')
    assert inventory.status_code==200,inventory.text
    assert inventory.json()['total']==1
    state=clients['bank_a'].get(f'/api/v1/cbom/legacy-assets/{aid}/review').json()
    body={'expected_snapshot_sha256':state['snapshot_sha256'],'system_id':'system-a',
          'reason':'Operator declared responsibility after reviewing inventory records.','evidence_ref':'cmdb/synthetic-42'}
    assert clients['bank_b'].get(f'/api/v1/cbom/legacy-assets/{aid}/review').status_code==404
    assert clients['reader_a'].post(f'/api/v1/cbom/legacy-assets/{aid}/assign',json=body).status_code==403
    wrong={**body,'system_id':'system-b'}
    assert clients['bank_a'].post(f'/api/v1/cbom/legacy-assets/{aid}/assign',json=wrong).status_code==404
    response=clients['bank_a'].post(f'/api/v1/cbom/legacy-assets/{aid}/assign',json=body)
    assert response.status_code==200,response.text
    assert response.json()['source_basis']=='OPERATOR_DECLARED_ASSIGNMENT_NOT_SCAN_OR_APPROVAL'
    assert clients['bank_a'].post(f'/api/v1/cbom/legacy-assets/{aid}/assign',json=body).status_code==409
    assert clients['bank_a'].get('/api/v1/cbom/legacy-imports/unassigned').json()['total']==0
    assert clients['bank_a'].get('/api/v1/cbom/system/system-a').status_code==409


def test_mixed_proposal_requires_original_replacement_and_roles(assured):
    clients,db,_=assured;sid,_,_=mixed(db)
    state=detail(clients['bank_a'],sid)
    body={'expected_snapshot_sha256':state['snapshot_sha256'],'replacement_document_sha256':'0'*64,
          'reason':'Reviewed original mixed source records without altering findings.','evidence_ref':'review/synthetic'}
    assert clients['reader_a'].post(f'/api/v1/cbom/system/{sid}/mixed-review',json=body).status_code==403
    assert clients['bank_a'].post(f'/api/v1/cbom/system/{sid}/mixed-review',json=body).status_code==409


def completed(assured):
    clients,db,_=assured;sid,aid,eid=mixed(db);assert ingest(clients['bank_a']).status_code==200
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    response=approve(clients['reader_a'],sid,p.json());assert response.status_code==200,response.text
    db.expire_all()
    return clients,db,sid,aid,eid,response.json()


@pytest.mark.parametrize('change',['same_count_swap','record_change','new_link','forged_review'])
def test_retained_history_reopens_after_changed_evidence_or_forged_marker(assured,change):
    clients,db,sid,aid,eid,result=completed(assured)
    assert clients['bank_a'].get('/api/v1/cbom/portfolio').status_code==200
    if change in {'same_count_swap','new_link'}:
        old=db.get(EvidenceRecord,eid)
        new=EvidenceRecord(tenant_id='a',scan_id=old.scan_id,content_hash='c'*64,chain_hash='d'*64,
            chain_position=2,file_path='synthetic-only',line_number=2,finding_data={})
        db.add(new);db.flush()
        if change=='same_count_swap':
            link=db.query(CryptoAssetEvidence).filter_by(asset_id=aid).one();link.evidence_id=new.id
        else:
            db.add(CryptoAssetEvidence(tenant_id='a',asset_id=aid,evidence_id=new.id))
    elif change=='record_change':
        db.get(EvidenceRecord,eid).finding_data={'synthetic':'changed'}
    else:
        asset=db.get(CryptoAsset,aid)
        asset.extra={**asset.extra,'legacy_cbom_disposition':{**asset.extra['legacy_cbom_disposition'],'review_id':'missing'}}
    db.commit();db.expire_all()
    assert clients['bank_a'].get('/api/v1/cbom/portfolio').status_code==409
    orphan=clients['bank_a'].get('/api/v1/cbom/legacy-imports/unassigned')
    assert orphan.status_code==200 and orphan.json()['total']==1,orphan.text
    assert clients['bank_a'].post('/api/v1/cbom/assess',json={'system_id':sid}).status_code==409


def test_audit_failure_rolls_back_assignment_and_mixed_approval(assured,monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    clients,db,_=assured;sid,aid,_=mixed(db);ingest(clients['bank_a'])
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    def fail(*args,**kwargs):raise SQLAlchemyError('synthetic audit unavailable')
    monkeypatch.setattr(UserRepository,'audit',fail)
    result=approve(clients['reader_a'],sid,p.json());assert result.status_code==503,result.text
    db.expire_all()
    assert db.query(SystemAsset).filter_by(asset_id=aid,system_id=sid).count()==1
    state=clients['bank_a'].get(f'/api/v1/cbom/system/{sid}/mixed-review').json()['case']['payload']['state']
    assert state=='PENDING_SECOND_HUMAN'
    orphan=CryptoAsset(tenant_id='a',algorithm='AES',file_path='synthetic',line_number=0,confidence='HIGH',scanner_ids=['cbom-ingest'])
    db.add(orphan);db.commit();oid=orphan.id
    state=clients['bank_a'].get(f'/api/v1/cbom/legacy-assets/{oid}/review').json()
    result=clients['bank_a'].post(f'/api/v1/cbom/legacy-assets/{oid}/assign',json={
        'expected_snapshot_sha256':state['snapshot_sha256'],'system_id':sid,
        'reason':'Synthetic ownership review with required durable audit.','evidence_ref':'synthetic/change'})
    assert result.status_code==503,result.text
    assert db.query(SystemAsset).filter_by(asset_id=oid).count()==0


def test_null_estate_is_not_selected_estate_and_stale_assignment_fails(assured):
    clients,db,_=assured
    rows=[CryptoAsset(tenant_id=t,algorithm='AES',file_path='synthetic',line_number=0,scanner_ids=['cbom-ingest']) for t in (None,'a','b')]
    db.add_all(rows);db.commit();ids=[a.id for a in rows]
    listed=clients['bank_a'].get('/api/v1/cbom/legacy-imports/unassigned').json()
    assert [a['id'] for a in listed['assets']]==[ids[1]]
    assert clients['bank_a'].get(f'/api/v1/cbom/legacy-assets/{ids[0]}/review').status_code==404
    state=clients['bank_a'].get(f'/api/v1/cbom/legacy-assets/{ids[1]}/review').json()
    rows[1].confidence='HIGH';db.commit()
    response=clients['bank_a'].post(f'/api/v1/cbom/legacy-assets/{ids[1]}/assign',json={
        'expected_snapshot_sha256':state['snapshot_sha256'],'system_id':'system-a',
        'reason':'Synthetic owner reviewed stale source and must refresh.','evidence_ref':'synthetic/change'})
    assert response.status_code==409,response.text


def test_approval_checks_current_roles_and_rejects_body_approver(assured):
    clients,db,_=assured;sid,aid,_=mixed(db);ingest(clients['bank_a'])
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    UserRepository(db).set_roles('reader_a',['readonly']);db.commit()
    assert approve(clients['reader_a'],sid,p.json()).status_code==403
    body={'expected_case_sha256':p.json()['payload_sha256'],'reason':'Forged approval field must not authorize this human.',
          'evidence_ref':'synthetic/test','reviewed_by':'some-other-human'}
    assert clients['bank_a'].post(f'/api/v1/cbom/system/{sid}/mixed-review/approve',json=body).status_code==422
    assert db.query(SystemAsset).filter_by(system_id=sid,asset_id=aid).count()==1


def test_partial_export_cannot_be_reassessed_inline_as_clean(assured):
    clients,db,sid,aid,eid,result=completed(assured)
    document=clients['bank_a'].get(f'/api/v1/cbom/system/{sid}?fmt=cyclonedx16').json()
    response=clients['bank_a'].post('/api/v1/cbom/assess',json={'bom':document})
    assert response.status_code==409,response.text


def test_review_marker_cannot_hide_an_asset_not_in_immutable_approval(assured):
    clients,db,sid,aid,eid,result=completed(assured)
    original=db.get(CryptoAsset,aid)
    forged=CryptoAsset(tenant_id='a',algorithm='AES',file_path='synthetic',line_number=0,
                      scanner_ids=['cbom-ingest'],extra=original.extra)
    db.add(forged);db.flush()
    db.add(CryptoAssetEvidence(tenant_id='a',asset_id=forged.id,evidence_id=eid));db.commit()
    assert clients['bank_a'].get('/api/v1/cbom/portfolio').status_code==409


def test_shared_assets_remain_pending_until_last_system_review(assured):
    from db.models import System
    clients,db,_=assured;sid,aid,eid=mixed(db)
    other=System(tenant_id='a',name='Synthetic shared history')
    db.add(other);db.flush();oid=other.id
    db.add(SystemAsset(tenant_id='a',system_id=oid,asset_id=aid));db.commit()
    ingest(clients['bank_a']);ingest(clients['bank_a'],system_name=other.name)
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    p=proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    assert approve(clients['reader_a'],sid,p.json()).status_code==200
    db.expire_all()
    assert not (db.get(CryptoAsset,aid).extra or {}).get('legacy_cbom_disposition')
    assert db.query(SystemAsset).filter_by(asset_id=aid,system_id=oid).count()==1
    assert clients['bank_a'].get('/api/v1/cbom/portfolio').status_code==409
    p=proposal(clients['bank_a'],oid);assert p.status_code==201,p.text
    response=approve(clients['reader_a'],oid,p.json());assert response.status_code==200,response.text
    assert clients['bank_a'].get('/api/v1/cbom/portfolio').status_code==200
    assert db.query(CryptoAssetEvidence).filter_by(asset_id=aid,evidence_id=eid).count()==1
