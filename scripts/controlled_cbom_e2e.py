#!/usr/bin/env python3
"""Opt-in synthetic local browser/PG exercise; NEVER use a customer deployment."""
from _bootstrap import bootstrap
bootstrap()
import argparse,json,re,uuid
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit
from sqlalchemy import create_engine,select,text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from db.models import CryptoAsset,System,SystemAsset,Scan,EvidenceRecord
from db.models.base import BaseModel
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.repositories.user_repository import UserRepository,verify_audit_chain
from cbom.generator import CbomGenerator
from cbom.cyclonedx16 import validate_cyclonedx16


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('config','chromium','report'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--base-url',default='http://127.0.0.1:3003')
    parser.add_argument('--screenshot')
    args=parser.parse_args();config=json.loads(Path(args.config).read_text());url=make_url(config['database_url'])
    assert url.get_backend_name()=='postgresql' and url.database.startswith('cryptoscan_e2e_')
    assert not url.host or url.host in {'localhost','127.0.0.1'} or url.host.startswith('/home/user/')
    assert set(url.query) <= {'host','port'}
    socket_host=url.query.get('host',url.host)
    assert socket_host is None or isinstance(socket_host,str) and (socket_host in {'localhost','127.0.0.1'} or socket_host.startswith('/home/user/'))
    assert urlsplit(args.base_url).hostname in {'localhost','127.0.0.1'}
    engine=create_engine(url);name='Synthetic controlled review '+uuid.uuid4().hex[:10]
    with Session(engine) as db:
        assert db.execute(text('SELECT version_num FROM alembic_version')).scalar_one()=='0107'
        system=System(tenant_id='e2e-a',name=name,coverage_status='CURRENT',last_scanned_at=datetime.now(timezone.utc))
        assets=[CryptoAsset(tenant_id='e2e-a',algorithm='ML-KEM-768',purpose='kem',key_size=1184,
            file_path='synthetic/declared.conf',line_number=1,confidence='HIGH',scanner_ids=['cbom-ingest']) for _ in range(2)]
        scan=Scan(tenant_id='e2e-a',target_location='synthetic-only',scan_start=datetime.now(timezone.utc),status='COMPLETED')
        db.add_all([system,scan,*assets]);db.flush();sid=system.id;aid,oid=[a.id for a in assets]
        evidence=EvidenceRecord(tenant_id='e2e-a',scan_id=scan.id,content_hash='a'*64,chain_hash='b'*64,
            chain_position=1,file_path='synthetic-only',line_number=1,finding_data={'synthetic':'preserved'})
        db.add(evidence);db.flush();eid=evidence.id
        db.add_all([SystemAsset(tenant_id='e2e-a',system_id=sid,asset_id=aid),CryptoAssetEvidence(tenant_id='e2e-a',asset_id=aid,evidence_id=eid)])
        db.commit();original=BaseModel.to_dict(evidence)
        UserRepository(db).set_roles('e2e_bank_a',['ciso']);db.commit()
    checks=[];errors=[]
    document=CbomGenerator().from_records([{'id':'synthetic','algorithm':'ML-KEM-768','purpose':'kem','key_size':1184,
        'file_path':'synthetic/declared.conf','line_number':1}],name=name,spec_version='1.6')
    from playwright.sync_api import sync_playwright,expect
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(executable_path=args.chromium,headless=True,args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--use-angle=swiftshader'])
        def login(username):
            context=browser.new_context(base_url=args.base_url);page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)[:200]))
            page.goto('/login');page.locator('#login-user').fill(username);page.locator('#login-pass').fill(config['password'])
            with page.expect_response(lambda r:r.url.endswith('/api/v1/auth/login') and r.request.method=='POST') as response:
                page.get_by_role('button',name=re.compile('^sign in$',re.I)).click()
            assert response.value.status==200
            page.wait_for_url('**/command-center');page.goto('/cbom');return page
        page=login('e2e_bank_a');checks.append('REAL_PASSWORD_SESSION_AND_CONSOLE')
        assert page.request.get(f'/api/v1/cbom/system/{sid}').status==409
        page.get_by_role('button',name='Review historical imports',exact=True).click()
        page.get_by_role('button',name='Review unassigned records',exact=True).click()
        page.get_by_role('button',name=f'Inspect ML-KEM-768 ({oid})',exact=True).click()
        page.get_by_label('Destination system ID (same estate)',exact=True).fill(sid)
        page.get_by_label('Ownership rationale (no secrets)',exact=True).fill('Synthetic owner reviewed original inventory; no scanner coverage asserted.')
        page.get_by_label('Ownership evidence reference',exact=True).fill('synthetic/cmdb-42')
        with page.expect_response(lambda r:r.url.endswith('/assign') and r.request.method=='POST') as response:
            page.get_by_role('button',name='Assign declared responsibility',exact=True).click()
        assert response.value.status==200
        expect(page.get_by_text(re.compile('Ownership assignment committed'))).to_be_visible();checks.append('BROWSER_SNAPSHOT_BOUND_OWNERSHIP_ASSIGNMENT')
        assert page.request.get(f'/api/v1/cbom/system/{sid}').status==409;checks.append('ASSIGNMENT_DOES_NOT_CLEAR_HISTORY')
        page.get_by_label('Import system name',exact=True).fill(name)
        page.get_by_label('CBOM JSON file',exact=True).set_input_files({'name':'synthetic.json','mimeType':'application/json','buffer':json.dumps(document).encode()})
        with page.expect_response(lambda r:r.url.endswith('/api/v1/cbom/ingest') and r.request.method=='POST') as response:
            page.get_by_role('button',name='Import metadata',exact=True).click()
        assert response.value.status==200;checks.append('BROWSER_NATIVE_REPLACEMENT_REIMPORT')
        page.get_by_role('button',name='Review '+name,exact=True).click()
        page.get_by_role('button',name='Load controlled mixed review',exact=True).click()
        def fill(p):
            p.get_by_label('Mixed-source rationale (no secrets)',exact=True).fill('Synthetic human reviewed retained evidence and partial export consequences.')
            p.get_by_label('Mixed-source evidence reference',exact=True).fill('synthetic/review-42')
            p.get_by_role('region',name='Controlled mixed history decision',exact=True).get_by_role('checkbox').check()
        fill(page)
        with page.expect_response(lambda r:r.url.endswith('/mixed-review') and r.request.method=='POST') as response:
            page.get_by_role('button',name='Submit mixed-source proposal',exact=True).click()
        assert response.value.status==201;checks.append('BROWSER_APPEND_ONLY_PROPOSAL')
        fill(page)
        with page.expect_response(lambda r:r.url.endswith('/approve') and r.request.method=='POST') as response:
            page.get_by_role('button',name='Approve as second human',exact=True).click()
        assert response.value.status==409;checks.append('SAME_CURRENT_CISO_CANNOT_SELF_APPROVE')
        with Session(engine) as db:UserRepository(db).set_roles('e2e_reader',['ciso']);db.commit()
        reviewer=login('e2e_reader');reviewer.get_by_role('button',name='Review historical imports',exact=True).click()
        reviewer.get_by_role('button',name='Review '+name,exact=True).click()
        reviewer.get_by_role('button',name='Load controlled mixed review',exact=True).click();fill(reviewer)
        with reviewer.expect_response(lambda r:r.url.endswith('/approve') and r.request.method=='POST') as response:
            reviewer.get_by_role('button',name='Approve as second human',exact=True).click()
        assert response.value.status==200
        expect(reviewer.get_by_text(re.compile('Mixed-history decision committed'))).to_be_visible();checks.append('DIFFERENT_CURRENT_HUMAN_COMMITS_WITH_AUDIT_RECEIPT')
        if args.screenshot:reviewer.get_by_role('region',name='Historical import review',exact=True).screenshot(path=args.screenshot)
        exported=reviewer.request.get(f'/api/v1/cbom/system/{sid}?fmt=cyclonedx16');assert exported.status==200
        assert validate_cyclonedx16(exported.json())['ok'];checks.append('NATIVE_EXPORT_OFFLINE_OFFICIAL_SCHEMA_VALID')
        props={p['name']:p['value'] for p in exported.json()['metadata']['properties']}
        assert props['cryptoscan:inventory_completeness']=='PARTIAL_RETAINED_MIXED_EVIDENCE';checks.append('EXPORT_DISCLOSES_RETAINED_HISTORY_AS_PARTIAL')
        assert reviewer.request.post('/api/v1/cbom/assess',data={'system_id':sid}).status==409
        assert reviewer.request.post('/api/v1/cbom/assess',data={'bom':exported.json()}).status==409;checks.append('SYSTEM_AND_INLINE_CLEAN_GRADES_BLOCKED')
        foreign=login('e2e_bank_b');assert foreign.request.get(f'/api/v1/cbom/system/{sid}/mixed-review').status==404
        assert foreign.request.get(f'/api/v1/cbom/legacy-assets/{aid}/review').status==404;checks.append('FOREIGN_SYSTEM_AND_ASSET_ISOLATED')
        reviewer.reload();assert reviewer.request.get(f'/api/v1/cbom/system/{sid}/legacy-imports').json()['pending_assets']==0
        checks.append('RELOAD_RETAINS_DECISION_WITHOUT_REPLAY')
        assert not errors;checks.append('NO_BROWSER_PAGE_ERRORS');version=browser.version;browser.close()
    with Session(engine) as db:
        assert BaseModel.to_dict(db.get(EvidenceRecord,eid))==original
        assert db.execute(select(CryptoAssetEvidence).where(CryptoAssetEvidence.asset_id==aid,CryptoAssetEvidence.evidence_id==eid)).scalar_one()
        assert db.get(CryptoAsset,aid).confidence=='HIGH' and db.get(CryptoAsset,oid)
        audit=verify_audit_chain(db);assert audit['status']=='OK',audit
    checks+=['ORIGINAL_ASSET_AND_EVIDENCE_BYTES_PRESERVED','DURABLE_AUDIT_CHAIN_VERIFIED']
    result={'schema':'cryptoscan.controlled-history-browser/1','bank_approved':False,'deployment_qualified':False,
        'scope':'OWNED_LOCAL_SYNTHETIC_POSTGRESQL','system_id':sid,'browser':version,'checks':checks,'audit':audit,'page_errors':errors}
    Path(args.report).write_text(json.dumps(result,indent=2)+'\n');print(f'{len(checks)} real browser/API/PG checks passed; bank acceptance remains external.');engine.dispose()


if __name__=='__main__':main()
