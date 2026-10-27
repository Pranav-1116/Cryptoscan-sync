"""Opt-in real PostgreSQL; each case owns and drops its own synthetic database."""
import os,uuid
import pytest
from sqlalchemy import create_engine,text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from db.tenancy import tenant_scope
from db.repositories.user_repository import UserRepository
from test_assurance_workflows import assured as assured
import test_software_supply_chain_api as source
import test_cbom_controlled_history as contracts
from test_cbom_production_flow import ingest

URL=os.getenv('CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL')
pytestmark=pytest.mark.skipif(not URL,reason='Explicit owned disposable PostgreSQL required')


@pytest.fixture()
def banks(tmp_path,monkeypatch):
    url=make_url(URL)
    assert url.get_backend_name()=='postgresql' and url.database.startswith('cryptoscan_e2e_')
    assert not url.host or url.host in {'localhost','127.0.0.1'} or url.host.startswith('/home/user/')
    name='cryptoscan_e2e_mixed_'+uuid.uuid4().hex[:12]
    admin=create_engine(url.set(database='postgres'),isolation_level='AUTOCOMMIT')
    with admin.connect() as conn:conn.execute(text('CREATE DATABASE "'+name+'"'))
    engine=create_engine(url.set(database=name))
    monkeypatch.setattr(source,'create_engine',lambda *a,**kw:engine)
    try:
        yield from source.banks.__wrapped__(tmp_path,monkeypatch)
    finally:
        engine.dispose()
        with admin.connect() as conn:conn.execute(text('DROP DATABASE "'+name+'"'))
        admin.dispose()


@pytest.mark.parametrize('contract',[
    contracts.test_two_humans_preserve_mixed_rows_and_disclose_partial_exports,
    contracts.test_link_membership_change_invalidates_pending_second_review,
    contracts.test_shared_assets_remain_pending_until_last_system_review,
    contracts.test_review_marker_cannot_hide_an_asset_not_in_immutable_approval,
    contracts.test_partial_export_cannot_be_reassessed_inline_as_clean,
    contracts.test_unassigned_assignment_is_exact_estate_snapshot_checked_and_not_clearance,
    contracts.test_null_estate_is_not_selected_estate_and_stale_assignment_fails,
    contracts.test_approval_checks_current_roles_and_rejects_body_approver,
])
def test_postgres_api_contract(assured,contract):contract(assured)


@pytest.mark.parametrize('change',['same_count_swap','record_change','new_link','forged_review'])
def test_postgres_reopens_changed_retained_evidence(assured,change):
    contracts.test_retained_history_reopens_after_changed_evidence_or_forged_marker(assured,change)


def test_postgres_audit_rollback(assured,monkeypatch):
    contracts.test_audit_failure_rolls_back_assignment_and_mixed_approval(assured,monkeypatch)


def test_postgres_review_locks_evidence_and_membership(assured):
    from api.routers.cbom_legacy import _system,_review
    clients,db,_=assured;sid,aid,eid=contracts.mixed(db)
    with tenant_scope('a'):
        _review(db,_system(db,sid,lock=True),lock=True)
    for statement in (
        text('UPDATE evidence_records SET finding_data=\'{}\' WHERE id=:id'),
        text('UPDATE crypto_asset_evidence SET updated_at=NOW() WHERE evidence_id=:id'),
    ):
        with db.bind.connect() as other:
            other.execute(text("SET LOCAL lock_timeout='100ms'"))
            with pytest.raises(OperationalError) as failure:other.execute(statement,{'id':eid})
            assert failure.value.orig.pgcode=='55P03'
            other.rollback()
    db.rollback()


def test_postgres_concurrent_approval_commits_once(assured):
    from concurrent.futures import ThreadPoolExecutor
    clients,db,_=assured;sid,aid,eid=contracts.mixed(db);ingest(clients['bank_a'])
    p=contracts.proposal(clients['bank_a'],sid);assert p.status_code==201,p.text
    UserRepository(db).set_roles('reader_a',['ciso']);db.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses=list(pool.map(lambda _:contracts.approve(clients['reader_a'],sid,p.json()).status_code,range(2)))
    assert sorted(statuses)==[200,409]
