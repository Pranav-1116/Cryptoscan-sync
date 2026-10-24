#!/usr/bin/env python3
"""Restore synthetic local PG to a new owned DB; no deployment or failover claim.

Requires local pg_dump/psql and an external private config with database_url.
The source is read only and MUST be an owned cryptoscan_e2e_* fixture. Stop
fixture writers first. Encrypted backups and ephemeral keys are not retained.
"""
from _bootstrap import bootstrap
bootstrap()
import argparse,hashlib,json,os,secrets,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from sqlalchemy import create_engine,MetaData,select,text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from db.repositories.user_repository import verify_audit_chain

ROOT=Path(__file__).resolve().parents[1]


def fingerprint(engine):
    metadata=MetaData();metadata.reflect(engine)
    result={}
    with engine.connect() as conn:
        for name,table in sorted(metadata.tables.items()):
            rows=sorted(json.dumps(dict(row),sort_keys=True,default=str,separators=(',',':'))
                        for row in conn.execute(select(table)).mappings())
            result[name]={'rows':len(rows),'sha256':hashlib.sha256('\n'.join(rows).encode()).hexdigest()}
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path);parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args();url=make_url(json.loads(args.config.read_text())['database_url'])
    assert url.get_backend_name()=='postgresql' and url.database.startswith('cryptoscan_e2e_')
    assert not url.host or url.host in {'localhost','127.0.0.1'} or url.host.startswith('/home/user/')
    assert set(url.query) <= {'host','port'}
    socket_host=url.query.get('host',url.host)
    assert socket_host is None or isinstance(socket_host,str) and (socket_host in {'localhost','127.0.0.1'} or socket_host.startswith('/home/user/'))
    target_name='cryptoscan_e2e_restore_'+uuid.uuid4().hex[:12]
    source=create_engine(url);admin=create_engine(url.set(database='postgres'),isolation_level='AUTOCOMMIT')
    target_url=url.set(database=target_name);target=create_engine(target_url)
    with admin.connect() as conn:conn.execute(text('CREATE DATABASE "'+target_name+'"'))
    checks=[];env=dict(os.environ,BACKUP_ENCRYPTION_KEY=secrets.token_urlsafe(40))
    def run(script,*argv,environment=env,success=True):
        result=subprocess.run([sys.executable,str(ROOT/'scripts'/script),*argv],cwd=ROOT,env=environment,
                              capture_output=True,text=True,timeout=120)
        assert (result.returncode==0)==success, f'{script}: unexpected exit {result.returncode}'
        return result
    def empty():
        with target.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")).scalar_one()==0
    try:
        before=fingerprint(source)
        with tempfile.TemporaryDirectory(prefix='controlled-recovery-',dir='/home/user') as directory:
            directory=Path(directory)
            run('backup_evidence.py','--db',url.render_as_string(hide_password=False),'--out',str(directory),'--encrypt')
            encrypted=list(directory.glob('*.sql.enc'));assert len(encrypted)==1
            backup=encrypted[0];assert not list(directory.glob('*.sql'));checks.append('REAL_PG_DUMP_ENCRYPTED_PLAINTEXT_REMOVED')
            target_dsn=target_url.render_as_string(hide_password=False)
            run('restore_evidence.py',str(backup),'--db',target_dsn,
                environment={**env,'BACKUP_ENCRYPTION_KEY':secrets.token_urlsafe(40)},success=False)
            empty();checks.append('WRONG_KEY_REFUSED_BEFORE_DATABASE_WRITE')
            altered=directory/'altered.sql.enc';data=bytearray(backup.read_bytes());data[-1]^=1;altered.write_bytes(data)
            run('restore_evidence.py',str(altered),'--db',target_dsn,success=False)
            empty();checks.append('TAMPERED_CIPHERTEXT_REFUSED_BEFORE_DATABASE_WRITE')
            broken=directory/'broken.sql';broken.write_text('CREATE TABLE synthetic_restore_rollback(id int);\nINSERT INTO synthetic_missing_table VALUES(1);\n')
            broken.with_suffix('.sql.manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(broken.read_bytes()).hexdigest()}))
            run('restore_evidence.py',str(broken),'--db',target_dsn,success=False)
            empty();checks.append('REAL_PSQL_ERROR_ROLLS_BACK_ALL_RESTORE_DDL')
            started=time.monotonic();run('restore_evidence.py',str(backup),'--db',target_dsn);seconds=time.monotonic()-started
            restored=fingerprint(target);assert before==restored;checks.append('ALL_TABLE_COUNTS_AND_CONTENT_DIGESTS_MATCH')
            with Session(target) as db:
                audit=verify_audit_chain(db);assert audit['status']=='OK',audit
                revision=db.execute(text('SELECT version_num FROM alembic_version')).scalar_one();assert revision=='0107'
            checks+=['RESTORED_AUDIT_CHAIN_VERIFIED','RESTORED_SCHEMA_0107']
            assert fingerprint(source)==before;checks.append('SOURCE_UNCHANGED')
            result={'schema':'cryptoscan.synthetic-pg-recovery/1','checks':checks,'restore_command_seconds':seconds,
                'tables':restored,'audit':audit,'bank_approved':False,'deployment_qualified':False,
                'basis':'QUIESCED_SYNTHETIC_LOCAL_LOGICAL_BACKUP_TO_NEW_DATABASE',
                'limits':['Not host loss, replica promotion, PITR or deployed service RTO/RPO','No concurrent writes or load during checkpoint',
                    'Same observer and same host; ephemeral in-memory test key, no external key custody qualification']}
        result['encrypted_backups_and_ephemeral_keys_retained']=False
    finally:
        target.dispose();source.dispose()
        with admin.connect() as conn:conn.execute(text('DROP DATABASE "'+target_name+'"'))
        admin.dispose()
    result['owned_target_database_dropped']=True
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(f'{len(checks)} actual local PostgreSQL backup/restore checks passed; no deployment acceptance claim.')


if __name__=='__main__':main()
