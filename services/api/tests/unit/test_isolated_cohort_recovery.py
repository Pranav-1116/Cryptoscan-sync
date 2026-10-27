"""Executed native PostgreSQL/cohort drill, never a deployment RPO/RTO claim.

No collector runs. All data and keys are synthetic. Application clients switch
only after operator-side reconciliation. This does not supply automatic site
fencing or a multi-generation artifact key resolver.
"""
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

import pytest
from sqlalchemy import create_engine, inspect, text, update, MetaData, Table, and_
from sqlalchemy.orm import Session
from api.assurance import store
from db.connection import engine as db_engine
from db.connection.session import configure_session
from db.models.base import utcnow
from db.models.assurance import AssuranceRevision
from db.models.evidence_record import EvidenceRecord
from db.models.execution_control import ExecutionAttempt, ExecutionBudget
from db.models.scan_job import ScanJob
from db.models.user import UserSession
from db.repositories import execution_control as controls
from db.tenancy import tenant_scope
from devsecops.artifact_crypto import decrypt_blob, encrypt_blob, ArtifactCryptoError
from worker.core.queued_authority import claim, QueueRefused
from test_trace_workload_postgres import quality_cluster as quality_cluster, pgdb as pgdb, pg_banks as pg_banks, banks as banks
from test_assurance_workflows import assured as assured, P, admin, approval, done, signer_and_key, supplier_body, manifest, blob
from test_relationship_trace_integrity import trace_case as trace_case, review, TRACE
from test_execution_controls import controlled as controlled_fixture, configure, approve, queue
from test_software_supply_chain_api import register

pytestmark = pytest.mark.live
ROOT = Path(__file__).resolve().parents[4]


def cohort_hashes(engine):
    result = {}
    with engine.connect() as connection:
        for table in sorted(inspect(engine).get_table_names()):
            quoted = engine.dialect.identifier_preparer.quote(table)
            rows = sorted(connection.execute(text(f"SELECT row_to_json(t)::text FROM {quoted} t")).scalars())
            result[table] = {"rows": len(rows), "sha256": hashlib.sha256("\n".join(rows).encode()).hexdigest()}
    return result


def cohort_rows(engine):
    with engine.connect() as connection:
        return {name: [dict(row) for row in connection.execute(text(
            "SELECT * FROM " + engine.dialect.identifier_preparer.quote(name))).mappings()]
            for name in inspect(engine).get_table_names()}


def replay_quiesced_delta(engine, before, after):
    """Privileged drill-only row journal; no service/automatic failover added.

    Preserve complete SQL envelopes and ancillary audit rows. Refuse deletions
    or tables without identities rather than silently dropping unknown state.
    """
    changed = {}
    with engine.begin() as connection:
        for name in sorted(after):
            if before[name] == after[name]:
                continue
            table = Table(name, MetaData(), autoload_with=connection)
            keys = [c.name for c in table.primary_key]
            assert keys
            identity = lambda row: tuple(row[k] for k in keys)
            old = {identity(row): row for row in before[name]}
            new = {identity(row): row for row in after[name]}
            assert set(old) <= set(new), "Unjournalled deletion requires explicit reconciliation"
            changed[name] = 0
            for key, row in new.items():
                if key not in old:
                    connection.execute(table.insert().values(**row)); changed[name] += 1
                elif row != old[key]:
                    connection.execute(table.update().where(and_(*(table.c[k] == row[k] for k in keys))).values(**row)); changed[name] += 1
    return changed


def file_hashes(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file()}


def sql_url(engine):
    return engine.url.set(drivername="postgresql").render_as_string(hide_password=False)


def command(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=30, **kwargs)
    assert result.returncode == 0, result.stderr[:1000]
    return result


def backup(engine, output):
    command([sys.executable, str(ROOT / "scripts/backup_evidence.py"), "--db", sql_url(engine), "--out", str(output), "--encrypt"])
    return next(output.glob("*.sql.enc"))


def restore(encrypted, engine):
    command([sys.executable, str(ROOT / "scripts/restore_evidence.py"), str(encrypted), "--db", sql_url(engine)])


def fence(engine, control):
    # Actual server-side connection fence plus termination of already-open
    # writers. Only generated cs_quality_* databases may be targeted.
    name = engine.url.database
    assert name.startswith("cs_quality_") and len(name) == 43
    with control.connect() as connection:
        connection.execute(text(f'ALTER DATABASE "{name}" ALLOW_CONNECTIONS false'))
        connection.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=:db"), {"db": name})


@pytest.fixture
def prepared_cohort(trace_case):
    # Supply-chain writes intentionally occur BEFORE the controlled execution
    # profile is enabled; that profile correctly refuses unqualified adapters.
    case = trace_case
    review(case)
    clients = case["clients"]
    signer, private, signer_body = signer_and_key(clients)
    supplier = done(clients["bank_a"].post(P + "/supplier-evidence", json=supplier_body(register(clients["bank_a"], digest="sha256:" + "c" * 64), signer, private)))
    done(admin(clients).post(P + f"/supplier-evidence/{supplier['subject_id']}/approve", json=approval()), 200)
    return case, signer, signer_body, supplier


@pytest.fixture
def controlled(banks, prepared_cohort, monkeypatch):
    yield from controlled_fixture.__wrapped__(banks, monkeypatch)


def test_isolated_complete_cohort_restore_and_new_write_preserving_failback(prepared_cohort, controlled, quality_cluster, monkeypatch, tmp_path_factory):
    case, signer, signer_body, supplier = prepared_cohort
    state = controlled
    clients, db, live_files = state["clients"], state["db"], state["tmp"]
    source = db.get_bind()
    archive = tmp_path_factory.mktemp("isolated-cohort-archive")
    current_key = secrets.token_urlsafe(32)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", secrets.token_urlsafe(32))
    # The source fixture's SBOM was encrypted with the fixture environment's
    # historical master. Keep that exact generation separately from new keys.
    historical_key = os.getenv("CRYPTOSCAN_ARTIFACT_KEY") or os.getenv("SECRET_KEY")
    assert historical_key, "An explicit synthetic artifact master must be configured for this drill"
    configure(state)
    approve(state)
    queued, descriptor = queue(state)
    job_id = queued.id
    with tenant_scope("a"):
        old_attempt = claim(descriptor)
    db.execute(update(ExecutionAttempt).where(ExecutionAttempt.id == old_attempt["id"]).values(deadline_at=utcnow() - timedelta(seconds=1)))
    db.commit(); db.expire_all()
    # Cohort is quiesced in this single-writer synthetic exercise. Every public
    # table and every referenced file under the isolated fixture root is retained.
    before_rows = cohort_rows(source)
    before_tables = cohort_hashes(source)
    before_files = file_hashes(live_files)
    shutil.copytree(live_files, archive / "files")
    encrypted = backup(source, archive / "initial")
    assert file_hashes(archive / "files") == before_files
    # Capture post-backup acknowledged deltas while source is still authority.
    withdrawn_at = utcnow()
    db.execute(update(EvidenceRecord).where(EvidenceRecord.id == case["evidence"].id).values(deleted_at=withdrawn_at))
    db.execute(update(UserSession).where(UserSession.username == "bank_b").values(revoked_at=withdrawn_at))
    db.commit()
    signer_body.update(expected_revision=1, revoked=True)
    done(admin(clients).put(P + f"/signers/{signer['subject_id']}", json=signer_body), 200)
    store.append(db, "a", "synthetic_recovery_write", "post-backup-accepted", 0, {"acknowledged": True}, "bank_a")
    # Preserve complete immutable SQL rows/envelopes, not reconstructed assertions.
    db.commit()
    after_rows = cohort_rows(source)
    after_tables = cohort_hashes(source)
    control = create_engine(source.url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    database, _ = quality_cluster
    began = time.perf_counter()
    old_connection = source.connect()
    try:
        fence(source, control)
        with pytest.raises(Exception): old_connection.execute(text("CREATE TABLE stale_writer_must_not_write (id integer)"))
        old_connection.close()
        with pytest.raises(Exception):
            with source.connect() as connection: connection.execute(text("SELECT 1"))
        with database() as candidate:
            restore(encrypted, candidate)
            assert cohort_hashes(candidate) == before_tables
            restored_files = archive / "restored-files"
            shutil.copytree(archive / "files", restored_files)
            assert file_hashes(restored_files) == before_files
            # A backup alone loses the accepted delta and resurrects old
            # eligibility. Keep candidate unavailable until the journal is applied.
            with Session(candidate) as recovered:
                assert recovered.query(AssuranceRevision).filter_by(subject_id="post-backup-accepted").count() == 0
                changed_rows = replay_quiesced_delta(candidate, before_rows, after_rows)
                assert cohort_hashes(candidate) == after_tables
                assert controls.recover_expired(recovered) == 1
                recovered.commit()
                assert recovered.get(ScanJob, job_id).status == "UNKNOWN"
                assert all(b.active == 1 for b in recovered.query(ExecutionBudget))
                assert recovered.query(AssuranceRevision).filter_by(subject_id="post-backup-accepted").count() == 1
            import api.routers.devsecops as ds
            from governance.backup_jobs import DiskBackupStorage
            monkeypatch.setattr(ds, "_SBOM_STORE", DiskBackupStorage(restored_files / "sboms"))
            monkeypatch.setattr(db_engine, "_ENGINE", candidate); configure_session(candidate)
            with tenant_scope("a"), pytest.raises(QueueRefused): claim(descriptor)
            with pytest.raises(controls.ExecutionDenied): controls.finish_attempt(old_attempt, True)
            assert done(clients["bank_a"].get(TRACE), 200)["paths"] == []
            assert admin(clients).get(P + f"/evidence-blobs/{supplier['subject_id']}/content").status_code == 409
            assert clients["bank_b"].get(P + f"/records/supplier_evidence/{supplier['subject_id']}").status_code in (401, 403)
            history = done(clients["bank_a"].get(P + f"/records/bom_relationship/{case['proposed']['subject_id']}"), 200)
            assert len(history["revisions"]) == 2
            recovery_seconds = time.perf_counter() - began
            # Actually accept new API writes after cutover, including a second
            # artifact key generation. These MUST survive subsequent failback.
            fresh_register = done(clients["bank_a"].post(P + "/registers", json=manifest()))
            fresh_evidence = blob(clients["bank_a"], b"synthetic post-cutover accepted evidence")
            current_store = ds._sbom_storage()
            old_manifest = next(m for m in current_store.list_manifests() if m["artifact_id"] == case["binding"]["sbom_artifact_id"])
            old_blob = current_store.get(old_manifest["storage_key"])
            # Exercise explicit second-generation key recovery on a synthetic
            # standalone object, NOT an admitted/reviewed SBOM or runtime fact.
            new_blob, _ = encrypt_blob(b"synthetic second-generation object", tenant_id="a", secret=current_key)
            current_store.put("synthetic-unbound-generation-two", new_blob)
            assert decrypt_blob(old_blob, tenant_id="a", secret=historical_key)[0]
            assert decrypt_blob(new_blob, tenant_id="a", secret=current_key)[0]
            with pytest.raises(ArtifactCryptoError): decrypt_blob(old_blob, tenant_id="a", secret=current_key)
            cutover_tables = cohort_hashes(candidate)
            cutover_files = file_hashes(restored_files)
            shutil.copytree(restored_files, archive / "failback-files")
            new_backup = backup(candidate, archive / "failback")
            failback_start = time.perf_counter()
            fence(candidate, control)
            with database() as failed_back:
                restore(new_backup, failed_back)
                assert cohort_hashes(failed_back) == cutover_tables
                assert file_hashes(archive / "failback-files") == cutover_files
                monkeypatch.setattr(db_engine, "_ENGINE", failed_back); configure_session(failed_back)
                with Session(failed_back) as final:
                    from db.models.assurance import AssuranceBlob
                    assert store.latest(final, "a", "estate_register", fresh_register["subject_id"])
                    assert final.get(AssuranceBlob, fresh_evidence["blob_id"])
                    assert final.query(AssuranceRevision).filter_by(subject_id="post-backup-accepted").count() == 1
                    assert final.get(ScanJob, job_id).status == "UNKNOWN"
                assert admin(clients).get(P + f"/evidence-blobs/{supplier['subject_id']}/content").status_code == 409
                failback_seconds = time.perf_counter() - failback_start
                result = {"scenario": "isolated synthetic complete SQL+files cohort; actual encrypted pg_dump/psql restore and failback",
                    "postgres_version": "16.2", "tables": len(before_tables), "table_hashes": before_tables,
                    "initial_files": before_files, "failback_files": cutover_files,
                    "recovery_seconds": recovery_seconds, "failback_seconds": failback_seconds,
                    "post_backup_changed_rows": changed_rows, "acknowledged_post_backup_marker_writes": 1, "lost_without_delta_replay": 1, "lost_after_delta_replay": 0,
                    "new_cutover_api_register_and_evidence_blob_preserved": True, "old_database_connections_and_writer_fenced": True,
                    "old_execution_fence_rejected": True, "expired_attempt_unknown_capacity_retained": True,
                    "post_backup_session_and_signer_revocations_and_withdrawal_preserved": True,
                    "historical_and_current_artifact_keys_verified_separately": True,
                    "independent_review": "PENDING", "deployment_qualification": False,
                    "limits": ["single-writer quiesced synthetic estate; no concurrent site traffic or production cutover", "single cluster / Unix socket / local trust; no TLS or cross-site recovery", "collector and external process outcomes not executed", "privileged operator replay and DB fencing, not automatic failover", "artifact key generations require explicit operator selection; no automatic historical keyring", "no production RPO/RTO promised"]}
                Path(os.environ["CRYPTOSCAN_COHORT_OUT"]).write_text(json.dumps(result, indent=2) + "\n")
    finally:
        old_connection.close()
        # Re-enable only our disposable source so fixture cleanup remains normal.
        with control.connect() as connection:
            connection.execute(text(f'ALTER DATABASE "{source.url.database}" ALLOW_CONNECTIONS true'))
        control.dispose()
        monkeypatch.setattr(db_engine, "_ENGINE", source); configure_session(source)
