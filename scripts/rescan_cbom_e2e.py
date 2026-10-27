#!/usr/bin/env python3
"""Opt-in LOCAL synthetic rescan browser check; not worker/deployment qualification.

Run controlled_cbom_e2e.py first. This exercises the real Scanner, evidence
pipeline and loader. The durable job/system envelope is fixture-provisioned,
NOT a dispatched production worker job or proof of admission/isolation.
"""
from _bootstrap import bootstrap
bootstrap()
import argparse,json,tempfile
from pathlib import Path
from urllib.parse import urlsplit
from sqlalchemy import create_engine,select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from db.models import System,EvidenceRecord
from db.models.base import utcnow
from db.models.scan_job import ScanJob
from db.loader.evidence_loader import EvidenceLoader
from db.tenancy import tenant_scope,install_tenant_guard
from scanner.core.scanner import Scanner
from evidence.core.pipeline import EvidencePipeline


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('config','history-report','chromium','report'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--base-url',default='http://127.0.0.1:3003');parser.add_argument('--screenshot')
    args=parser.parse_args();config=json.loads(Path(args.config).read_text());history=json.loads(Path(args.history_report).read_text())
    assert history['scope']=='OWNED_LOCAL_SYNTHETIC_POSTGRESQL'
    url=make_url(config['database_url']);assert url.get_backend_name()=='postgresql' and url.database.startswith('cryptoscan_e2e_')
    assert set(url.query)<={'host','port'}
    for host in (url.host,url.query.get('host')):
        assert host is None or isinstance(host,str) and (host in {'localhost','127.0.0.1'} or host.startswith('/home/user/'))
    assert urlsplit(args.base_url).hostname in {'localhost','127.0.0.1'}
    sid=history['system_id'];engine=create_engine(url);install_tenant_guard();checks=[];errors=[]
    try:
        with tempfile.TemporaryDirectory(prefix='rescan-source-',dir='/home/user') as directory:
            root=Path(directory)
            (root/'crypto.py').write_text("import hashlib\nhashlib.md5(b'synthetic non-secret fixture')\n")
            (root/'negative.py').write_text('def add(a,b):\n    return a+b\n')
            started=utcnow()
            real=Scanner().scan(root_path=root,target_type='LOCAL_DIRECTORY',target_location=str(root),target_branch='main')
            assert any(f.crypto.algorithm=='MD5' for f in real.findings)
            records,manifest=EvidencePipeline(real.scan_id).process(findings=real.findings,scan_id=real.scan_id)
            with Session(engine) as db,tenant_scope('e2e-a'):
                system=db.execute(select(System).where(System.id==sid,System.tenant_id=='e2e-a')).scalar_one()
                assert system.name.startswith('Synthetic controlled review ')
                scan=EvidenceLoader(db).load(scan_meta={'scan_start':real.scan_start,'scan_end':real.scan_end,
                    'target_type':'LOCAL_DIRECTORY','target_location':str(root),'target_branch':'main','status':'COMPLETED',
                    'statistics':real.statistics.model_dump(mode='json')},evidence_records=[r.model_dump(mode='json') for r in records],
                    manifest=manifest.model_dump(mode='json'),scan_id=real.scan_id)
                system.scan_target=str(root);system.scan_branch='main';system.last_scan_id=scan.id
                job=ScanJob(tenant_id='e2e-a',system_id=sid,scan_id=scan.id,status='COMPLETED',target_repo=str(root),
                    target_branch='main',triggered_by='synthetic-fixture',started_at=started,completed_at=utcnow())
                db.add(job);db.commit();jid=job.id;name=system.name
            checks.append('REAL_SCANNER_FILE_RECEIPTS_EVIDENCE_HASHING_AND_PG_LOAD')
            from playwright.sync_api import sync_playwright,expect
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=args.chromium,headless=True,args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--use-angle=swiftshader'])
                def login(username):
                    context=browser.new_context(base_url=args.base_url);page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)[:200]))
                    page.goto('/login');page.locator('#login-user').fill(username);page.locator('#login-pass').fill(config['password'])
                    with page.expect_response(lambda r:r.url.endswith('/api/v1/auth/login') and r.request.method=='POST') as response:
                        page.get_by_role('button',name='Sign in',exact=False).click()
                    assert response.value.status==200,'Respect normal login limits; do not disable them'
                    page.wait_for_url('**/command-center');page.goto('/cbom');return page
                page=login('e2e_bank_a');page.get_by_role('button',name='Review historical imports',exact=True).click()
                page.get_by_role('button',name='Review retained histories',exact=True).click()
                page.get_by_role('button',name='Inspect rescan for '+name,exact=True).click()
                page.get_by_label('Completed source job ID',exact=True).fill(jid)
                with page.expect_response(lambda r:'/rescan-inspection?' in r.url) as response:
                    page.get_by_role('button',name='Verify scoped rescan evidence',exact=True).click()
                assert response.value.status==200,response.value.text();proof=response.value.json()
                expect(page.get_by_text('Committed source evidence verified for this scoped rescan.',exact=True)).to_be_visible()
                assert proof['parsed_files']==2 and proof['integrity']['result']=='PASS'
                assert not proof['whole_system_coverage_verified'] and not proof['clears_partial_history'];checks.append('BROWSER_SCOPED_PROOF_AND_EXPLICIT_NON_CLEARANCE')
                if args.screenshot:page.get_by_role('region',name='Retained history rescan inspection',exact=True).screenshot(path=args.screenshot)
                assert page.request.post('/api/v1/cbom/assess',data={'system_id':sid}).status==409;checks.append('CLEAN_POSTURE_GRADE_STILL_BLOCKED')
                with Session(engine) as db:
                    record=db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id==real.scan_id)).scalars().first()
                    original=record.finding_data;record.finding_data={'tampered':'synthetic'};db.commit();eid=record.id
                with page.expect_response(lambda r:'/rescan-inspection?' in r.url) as response:
                    page.get_by_role('button',name='Verify scoped rescan evidence',exact=True).click()
                assert response.value.status==409
                expect(page.get_by_text('Committed source evidence verified for this scoped rescan.',exact=True)).to_have_count(0)
                expect(page.get_by_text('No verified rescan or clearance assumed',exact=False)).to_be_visible();checks.append('TAMPERED_CONTENT_REJECTED_AND_PREVIOUS_PROOF_CLEARED')
                with Session(engine) as db:db.get(EvidenceRecord,eid).finding_data=original;db.commit()
                other=login('e2e_bank_b')
                assert other.request.get(f'/api/v1/cbom/system/{sid}/rescan-inspection?job_id={jid}').status==404
                assert other.request.get('/api/v1/cbom/retained-histories').json()['total']==0;checks.append('FOREIGN_TENANT_PROOF_AND_INVENTORY_ISOLATED')
                assert not errors;checks.append('NO_BROWSER_PAGE_ERRORS');version=browser.version;browser.close()
            report={'schema':'cryptoscan.scoped-rescan-browser/1','checks':checks,'proof':proof,'browser':version,'page_errors':errors,
                'scope':'OWNED_LOCAL_SYNTHETIC_POSTGRESQL','job_envelope_fixture_provisioned':True,'worker_dispatch_exercised':False,
                'bank_approved':False,'deployment_qualified':False,'partial_history_cleared':False}
        report['synthetic_source_directory_removed']=True
        Path(args.report).write_text(json.dumps(report,indent=2)+'\n');print(f'{len(checks)} scoped rescan browser/parser/PG checks passed; no complete-coverage claim.')
    finally:engine.dispose()


if __name__=='__main__':main()
