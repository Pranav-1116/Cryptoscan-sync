"""Opt-in real PostgreSQL exercises. Never point this at a deployment.

Run with -m live, CRYPTOSCAN_QUALITY_PG_OPT_IN=disposable-local-only and
CRYPTOSCAN_QUALITY_PG_URL pointing at the postgres administrative database on
an approved, disposable local server. Only freshly generated databases are
migrated/dropped; DATABASE_URL and CRYPTOSCAN_TEST_DATABASE_URL are NOT inputs.
The source fixture helpers seed observations; they do not qualify a collector.
"""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event
import os
import time
import uuid

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.assurance import remediation, store
from api.security.passwords import hash_password
from db.connection import engine as db_engine
from db.connection.session import SessionLocal, configure_session
from db.models.tenant import Tenant
from db.models.user import UserSession
from db.repositories.user_repository import UserRepository
from db.tenancy import platform_scope, tenant_scope
from api.config.settings import get_settings
from test_assurance_workflows import assured as assured, P, admin, done
from test_execution_controls import controlled as controlled, configure, approve, queue
from test_remediation_evidence_retraction import condition as condition, prepare, inbox
from test_operator_decisions import check

pytestmark = pytest.mark.live
ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def quality_cluster():
    if os.getenv("CRYPTOSCAN_QUALITY_PG_OPT_IN") != "disposable-local-only":
        pytest.skip("Requires explicit disposable-local-only PostgreSQL authorization; skip is not qualification")
    raw = os.environ["CRYPTOSCAN_QUALITY_PG_URL"]
    url = make_url(raw)
    assert url.drivername in {"postgresql", "postgresql+psycopg2"}
    assert url.database == "postgres", "Only the administrative postgres DB may be the input"
    assert url.host in {None, "localhost", "127.0.0.1", "::1"}, "Remote deployment targets are forbidden"
    if not url.host:
        assert str(url.query.get("host", "")).startswith("/"), "Explicit private Unix socket required"
    else:
        assert "host" not in url.query, "Do not override the validated host"
    assert set(url.query) <= {"host", "port"}, "Connection-service and target overrides are forbidden"
    assert "," not in str(url.query.get("host", "")), "Multi-host failover targets are forbidden"
    control = create_engine(url, isolation_level="AUTOCOMMIT", connect_args={"connect_timeout": 5})

    @contextmanager
    def database(template=None):
        name = "cs_quality_" + uuid.uuid4().hex
        with control.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"' + (f' TEMPLATE "{template}"' if template else "")))
        engine = create_engine(url.set(database=name), connect_args={"options": "-c statement_timeout=15000 -c lock_timeout=10000"})
        try:
            yield engine
        finally:
            engine.dispose()
            with control.connect() as connection:
                connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))

    try:
        with database() as template_engine:
            cfg = Config(str(ROOT / "services/database/migrations/alembic.ini"))
            cfg.set_main_option("sqlalchemy.url", template_engine.url.render_as_string(hide_password=False).replace("%", "%%"))
            command.upgrade(cfg, "head")
            with template_engine.connect() as connection:
                assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0106"
                assert connection.dialect.name == "postgresql"
            template_engine.dispose()
            yield database, template_engine.url.database
    finally:
        control.dispose()


@pytest.fixture
def pgdb(quality_cluster, monkeypatch):
    database, template = quality_cluster
    with database(template) as engine:
        monkeypatch.setenv("DATABASE_URL", engine.url.render_as_string(hide_password=False))
        get_settings.cache_clear()
        yield engine
        get_settings.cache_clear()


@pytest.fixture
def banks(pgdb, monkeypatch, tmp_path):
    """Same estate identities as the SQLite contracts, but real password login + PG."""
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    get_settings.cache_clear()
    previous = SessionLocal.kw.get("bind")
    monkeypatch.setattr(db_engine, "_ENGINE", pgdb)
    configure_session(pgdb)
    clients = {}
    with SessionLocal() as db:
        db.add_all([Tenant(id="a", name="Bank A", slug="bank-a"), Tenant(id="b", name="Bank B", slug="bank-b")])
        repo = UserRepository(db)
        password = "Disposable-quality-password-741!"
        for name, roles in [("bank_a", ["security_analyst"]), ("bank_b", ["security_analyst"]),
                            ("reader_a", ["readonly"]), ("platform_admin", ["admin"])]:
            repo.create_user(name, hash_password(password), roles=roles)
        db.commit()
        from db.models.tenant import TenantMembership
        db.add_all([TenantMembership(tenant_id=t, username=u, tenant_role="member")
                    for t, u in [("a", "bank_a"), ("a", "reader_a"), ("b", "bank_b")]])
        db.commit()
        app = create_app()
        app.add_middleware(TenantScopeMiddleware)
        try:
            for name in ("bank_a", "bank_b", "reader_a", "platform_admin"):
                client = TestClient(app)
                clients[name] = client
                assert client.post("/api/v1/auth/login", json={"username": name, "password": "wrong"}).status_code == 401
                response = client.post("/api/v1/auth/login", json={"username": name, "password": password})
                assert response.status_code == 200, response.text
                assert client.cookies.get("cryptoscan_session") and response.json()["token"]
            assert db.query(UserSession).count() == 4
            yield clients, db, tmp_path
        finally:
            for client in clients.values():
                client.close()
            SessionLocal.configure(bind=previous)


def test_real_postgres_competing_revision_writers(assured):
    _, db, _ = assured
    engine = db.get_bind()
    barrier = Barrier(2)

    def write(actor):
        with platform_scope(), Session(engine) as session:
            barrier.wait(timeout=5)
            try:
                row = store.append(session, "a", "quality_revision", "shared", 0, {"actor": actor}, actor)
                return row.revision
            except Exception as exc:
                from fastapi import HTTPException
                assert isinstance(exc, HTTPException) and exc.status_code == 409
                return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, ["first", "second"]))
    assert sorted(map(str, results)) == ["1", "CONFLICT"]
    assert len(store.latest_many(db, "a", "quality_revision", ["shared"])) == 1


def test_real_postgres_duplicate_job_claim_is_single_winner(controlled):
    from worker.core.queued_authority import claim, QueueRefused
    from db.models.execution_control import ExecutionAttempt, ExecutionBudget
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)
    barrier = Barrier(2)

    def worker(_):
        with tenant_scope("a"):
            barrier.wait(timeout=5)
            try:
                return claim(descriptor)
            except QueueRefused:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, range(2)))
    assert sum(r is not None for r in results) == 1
    state["db"].expire_all()
    assert row.status == "RUNNING"
    assert state["db"].query(ExecutionAttempt).count() == 1
    assert all(b.active == 1 for b in state["db"].query(ExecutionBudget))


def test_real_postgres_unknown_reconciliation(controlled):
    # Existing transactional API assertions, now exercised without SQLite.
    from test_execution_controls import test_attempt_claim_checkpoint_stop_unknown_and_operator_reconciliation
    test_attempt_claim_checkpoint_stop_unknown_and_operator_reconciliation(controlled)


def test_real_postgres_budget_rollback_on_claim_failure(controlled, monkeypatch):
    from worker.core.queued_authority import claim, QueueRefused
    from db.models.execution_control import ExecutionAttempt, ExecutionBudget
    from db.models.scan_job import ScanJob
    state = controlled
    configure(state)
    approve(state)
    row, descriptor = queue(state)

    def interrupt(_connection, _cursor, statement, *_args):
        if statement.lstrip().startswith("UPDATE scan_jobs"):
            raise RuntimeError("injected failure after reservation writes, before job CAS/commit")

    event.listen(state["db"].get_bind(), "before_cursor_execute", interrupt)
    try:
        with tenant_scope("a"), pytest.raises(QueueRefused):
            claim(descriptor)
    finally:
        event.remove(state["db"].get_bind(), "before_cursor_execute", interrupt)
    state["db"].expire_all()
    assert state["db"].get(ScanJob, row.id).status == "QUEUED"
    assert state["db"].query(ExecutionAttempt).count() == 0
    assert all(b.active == 0 for b in state["db"].query(ExecutionBudget))
    with tenant_scope("a"):
        assert claim(descriptor) is not None  # No manual SQL repair needed.


@pytest.mark.parametrize("target", ["original", "before_other", "replacement", "after_other"])
def test_real_postgres_concurrent_withdrawal_waits_for_positive_proof(condition, monkeypatch, target):
    """A VERIFIED proof may precede withdrawal, never leapfrog its commit."""
    state = condition
    clients, db = state["clients"], state["db"]
    prepare(state)
    after, evidence = state["after"], state[target]
    checked, release, updated = Event(), Event(), Event()
    pid = []
    original = remediation.observation_current

    def pause(*args, **kwargs):
        value = original(*args, **kwargs)
        checked.set()
        assert release.wait(8), "Verifier barrier timed out"
        return value

    def sql_started(connection, cursor, statement, *_args):
        if statement.lstrip().startswith("UPDATE evidence_records"):
            pid.append(cursor.connection.get_backend_pid())

    monkeypatch.setattr(remediation, "observation_current", pause)
    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", sql_started)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            verifying = pool.submit(check, clients, state["identifier"], after)
            assert checked.wait(8), "Positive predicate not reached"

            def withdrawal():
                try:
                    return done(admin(clients).post(f"/api/v1/findings/{evidence.id}/soft-delete", json={"reason": "Synthetic concurrent PostgreSQL withdrawal"}), 200)
                finally:
                    updated.set()

            withdrawing = pool.submit(withdrawal)
            try:
                deadline = time.monotonic() + 5
                blocked = False
                with engine.connect() as observer:
                    while time.monotonic() < deadline and not updated.is_set():
                        if pid and observer.scalar(text("SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid[0]}) == "Lock":
                            blocked = True
                            break
                        updated.wait(.01)
                assert blocked, "Withdrawal committed while the supposedly current positive proof was still uncommitted"
            finally:
                release.set()
            proof = verifying.result(timeout=8)
            withdrawing.result(timeout=8)
        assert proof["payload"]["result"] == "VERIFIED"  # Historical pre-withdrawal verdict remains immutable.
        current = inbox(state)
        assert current["tasks"]["items"][0]["current_condition_verified"] is False
    finally:
        release.set()
        event.remove(engine, "before_cursor_execute", sql_started)


def test_real_postgres_competing_approvals(condition, monkeypatch):
    from test_remediation_evidence_retraction import propose
    from test_assurance_workflows import approval
    state = condition
    row = propose(state)
    original = store.append
    barrier = Barrier(2)

    def append(*args, **kwargs):
        if args[2] == "remediation_change" and args[4] == 1:
            barrier.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "append", append)
    def reviewer(_):
        return admin(state["clients"]).post(P + f"/remediation-changes/{row['subject_id']}/approve", json=approval()).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reviewer, range(2))) == [201, 409]
    state["db"].expire_all()
    revisions = done(admin(state["clients"]).get(P + f"/records/remediation_change/{row['subject_id']}"), 200)["revisions"]
    assert [r["revision"] for r in revisions] == [1, 2]
    assert len(store.latest_many(state["db"], "a", "remediation_assignment", [state["task"]["id"]])) == 1


def source_journey(controlled, monkeypatch, replacement="sha256", expected="VERIFIED"):
    """Real parser/pipeline and API/PG; inline launcher + queue/control-plane doubles.

    Deliberately NOT a Docker, Redis transport, ingress or bank-browser exercise.
    Only normal source changes/API actions follow the initial identity fixture;
    no seeded scan, task, verdict or manual SQL state repair supplies the journey.
    """
    from datetime import timedelta
    from db.models.base import utcnow
    from db.models.scan import Scan
    from db.models.execution_control import ExecutionAttempt, ExecutionBudget
    from worker.core.job_executor import JobExecutor
    from worker.pipeline import pipeline_runner
    from test_operator_decisions import reported
    state = controlled
    configure(state)
    approve(state)
    monkeypatch.setattr("worker.core.static_scan_isolation.execution_mode", lambda *_: "inline")
    monkeypatch.setattr(pipeline_runner.settings, "WORKSPACE_BASE_PATH", str(state["tmp"] / "workspaces"))
    clients = state["clients"]
    assert clients["bank_a"].post("/api/v1/scans/trigger", headers={"X-Tenant-ID": "b"}, json={"repo_url": state["target"]}).status_code == 404
    assert clients["reader_a"].post("/api/v1/scans/trigger", json={"repo_url": state["target"]}).status_code == 403
    row, descriptor = queue(state)
    assert JobExecutor().execute(descriptor) is True
    assert JobExecutor().execute(descriptor) is False  # Duplicate descriptor cannot recollect.
    state["db"].expire_all()
    assert row.status == "COMPLETED" and row.scan_id
    observations = done(clients["bank_a"].get("/api/v1/findings", params={"scan_id": row.scan_id}), 200)["findings"]
    finding = next(f for f in observations if f["algorithm"] == "MD5")
    integrity = done(clients["bank_a"].get(f"/api/v1/scans/{row.scan_id}/verify"), 200)
    assert integrity["result"] == "PASS"  # Integrity is not remediation or policy success.
    export = done(clients["bank_a"].get(f"/api/v1/scans/{row.scan_id}/export"), 200)
    exported = next(f for f in export["findings"] if f["id"] == finding["evidence_id"])
    assert exported["algorithm"] == finding["algorithm"] == "MD5"
    assert exported["compliance_status"] == finding["compliance_status"] == "FAIL"
    assert done(admin(clients).get(f"/api/v1/findings/{finding['evidence_id']}/verify"), 200)["result"] == "PASS"
    task = done(clients["bank_a"].post(P + "/remediation-tasks", json={"evidence_id": finding["evidence_id"], "owner_ref": "payments"}))
    change = done(clients["bank_a"].post(P + "/remediation-changes", json={"kind": "SOURCE_SITE", "owner_ref": "payments", "task_id": task["id"],
        "change_ref": "synthetic/workflow", "expected_algorithm": "SHA-256", "verification_criteria": "Exact original site replacement",
        "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}))
    identifier = change["subject_id"]
    from test_assurance_workflows import approval
    assert clients["bank_a"].post(P + f"/remediation-changes/{identifier}/approve", json=approval()).status_code == 403
    done(admin(clients).post(P + f"/remediation-changes/{identifier}/approve", json=approval()))
    assert admin(clients).post(P + f"/remediation-changes/{identifier}/approve", json=approval()).status_code == 409
    reported(clients, identifier)
    before_proof = done(admin(clients).get(P + "/operator-decisions"), 200)["sections"]["tasks"]["items"][0]
    assert before_proof["reported_complete"] is True and before_proof["current_condition_verified"] is False
    (Path(state["target"]) / "crypto.py").write_text(f"import hashlib\nhashlib.{replacement}(b'x')\n")
    after_job, after_descriptor = queue(state)
    assert JobExecutor().execute(after_descriptor) is True
    state["db"].expire_all()
    after = state["db"].get(Scan, after_job.scan_id)
    proof = check(clients, identifier, after)
    assert proof["payload"]["result"] == expected, proof["payload"]["reason"]
    current = done(admin(clients).get(P + "/operator-decisions"), 200)["sections"]
    assert current["tasks"]["items"][0]["current_condition_verified"] is (expected == "VERIFIED")
    assert current["proofs"]["items"][0]["result"] == expected
    history_url = P + f"/records/condition_proof/{proof['subject_id']}"
    history = done(admin(clients).get(history_url), 200)
    assert history["revisions"][-1] == proof
    configure(state, "b")
    assert clients["bank_b"].get(history_url).status_code == 404
    assert all(b.active == 0 for b in state["db"].query(ExecutionBudget))
    assert {a.status for a in state["db"].query(ExecutionAttempt)} == {"SUCCEEDED"}

    return {"state": state, "proof": proof, "after": after}


@pytest.mark.parametrize("replacement,expected", [("sha256", "VERIFIED"), ("sha384", "INCONCLUSIVE")])
def test_real_postgres_signed_in_supported_source_to_independent_proof(controlled, monkeypatch, replacement, expected):
    source_journey(controlled, monkeypatch, replacement, expected)


def test_real_postgres_populated_outcome_migration(quality_cluster):
    from db.models.scan_job import ScanJob
    database, _ = quality_cluster
    with database() as engine:
        cfg = Config(str(ROOT / "services/database/migrations/alembic.ini"))
        cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False).replace("%", "%%"))
        command.upgrade(cfg, "0105")
        with Session(engine) as db:
            rows = [ScanJob(target_repo="synthetic/populated", triggered_by="migration-fixture", status=status,
                            progress={"marker": status}, version=n + 7) for n, status in enumerate(["QUEUED", "RUNNING", "FAILED"])]
            db.add_all(rows); db.commit()
            retained = {r.id: (r.status, r.version, r.progress) for r in rows}
        command.upgrade(cfg, "head")
        with Session(engine) as db:
            assert {r.id: (r.status, r.version, r.progress) for r in db.query(ScanJob)} == retained
            row = db.get(ScanJob, rows[1].id)
            row.status = "UNKNOWN"; db.commit()
        with pytest.raises(RuntimeError, match="UNKNOWN jobs require reconciliation"):
            command.downgrade(cfg, "0105")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0106"
            assert connection.scalar(text("SELECT status FROM scan_jobs WHERE id=:id"), {"id": rows[1].id}) == "UNKNOWN"
        # Invalid enum values still fail, rather than weakening the column to
        # arbitrary text. Rollback leaves the successfully populated rows intact.
        from sqlalchemy.exc import DataError
        with pytest.raises(DataError), engine.begin() as connection:
            connection.execute(text("UPDATE scan_jobs SET status='ASSUMED_SUCCESS'"))


def test_real_postgres_dump_restore_retains_proof_and_unknown_reservations(controlled, monkeypatch, quality_cluster):
    import hashlib
    import subprocess
    from db.repositories import execution_control as controls
    from db.models.execution_control import ExecutionAttempt, ExecutionBudget
    from worker.core.queued_authority import claim
    result = source_journey(controlled, monkeypatch)
    state, proof = result["state"], result["proof"]
    row, descriptor = queue(state)
    with tenant_scope("a"):
        active = claim(descriptor)
        assert controls.finish_attempt(active, False) is False
    state["db"].expire_all()
    assert row.status == "UNKNOWN"
    assert sum(b.active for b in state["db"].query(ExecutionBudget)) == 2
    attempt = state["db"].query(ExecutionAttempt).filter_by(status="UNKNOWN").one()
    binary_dir = Path(os.environ["CRYPTOSCAN_QUALITY_PG_BIN"])
    for name in ("pg_dump", "pg_restore"):
        assert (binary_dir / name).is_file(), "Native PostgreSQL clients are required; absence is not qualification"
    engine = state["db"].get_bind()
    url = engine.url
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGHOST=url.host or url.query["host"], PGPORT=str(url.port or url.query.get("port", 5432)),
               PGUSER=url.username or "", PGPASSWORD=url.password or "", PGPASSFILE=os.devnull, PGSSLMODE="disable")
    archive = state["tmp"] / "qualification.dump"
    subprocess.run([str(binary_dir / "pg_dump"), "--format=custom", "--compress=0", "--file", str(archive), "--dbname", url.database],
                   env=env, check=True, capture_output=True, timeout=30)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive.stat().st_size > 0
    database, _ = quality_cluster
    with database() as restored:
        subprocess.run([str(binary_dir / "pg_restore"), "--exit-on-error", "--single-transaction", "--dbname", restored.url.database, str(archive)],
                       env=env, check=True, capture_output=True, timeout=30)
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest
        previous = SessionLocal.kw["bind"]
        try:
            configure_session(restored)
            with monkeypatch.context() as patch:
                patch.setattr(db_engine, "_ENGINE", restored)
                patch.setenv("DATABASE_URL", restored.url.render_as_string(hide_password=False))
                clients = state["clients"]
                history = done(admin(clients).get(P + f"/records/condition_proof/{proof['subject_id']}"), 200)
                assert history["revisions"][-1] == proof
                recovered = done(clients["bank_a"].get(f"/api/v1/jobs/{row.id}"), 200)
                assert recovered["status"] == "UNKNOWN"
                assert clients["bank_a"].post(f"/api/v1/jobs/{row.id}/retry").status_code == 409
                with SessionLocal() as db:
                    assert sum(b.active for b in db.query(ExecutionBudget)) == 2
                    restored_attempt = db.get(ExecutionAttempt, attempt.id)
                    assert (restored_attempt.status, restored_attempt.fence) == ("UNKNOWN", attempt.fence)
                body = {"resolution": "CONFIRMED_STOPPED", "evidence_ref": "synthetic/recovery-stopped", "confirm_external_work_stopped": True}
                done(admin(clients).post(f"/api/v1/execution-controls/attempts/{attempt.id}/reconcile", json=body), 200)
                assert admin(clients).post(f"/api/v1/execution-controls/attempts/{attempt.id}/reconcile", json=body).status_code == 409
                with SessionLocal() as db:
                    assert all(b.active == 0 for b in db.query(ExecutionBudget))
        finally:
            SessionLocal.configure(bind=previous)
    # A damaged archive must not leave a partly restored schema masquerading as
    # a successful recovery. This does not measure WAL/PITR, HA, RPO or RTO.
    damaged = state["tmp"] / "damaged.dump"
    damaged.write_bytes(archive.read_bytes()[:100])
    with database() as failed:
        failure = subprocess.run([str(binary_dir / "pg_restore"), "--exit-on-error", "--single-transaction", "--dbname", failed.url.database, str(damaged)],
                                 env=env, capture_output=True, timeout=30)
        assert failure.returncode != 0
        with failed.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0


@pytest.mark.parametrize("middleware", [True, False])
def test_real_postgres_qualified_read_boundary_is_exact_and_resident(controlled, middleware, monkeypatch):
    from api.middleware.auth_middleware import AuthMiddleware
    from db.models.evidence_record import EvidenceRecord
    from test_assurance_workflows import new_scan
    state = controlled
    for owner in (("a", "b", None) if middleware else ("a", "b")):
        configure(state, owner)
    scans = {owner: new_scan(state["db"], owner=owner, path=f"synthetic/private-{owner}") for owner in ("a", "b", None)}
    findings = {owner: state["db"].query(EvidenceRecord).filter_by(scan_id=scan.id).one() for owner, scan in scans.items()}
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    app.add_middleware(AuthMiddleware)
    clients = []
    try:
        identities = [("bank_a", "a"), ("bank_b", "b")] + ([("platform_admin", None)] if middleware else [])
        for who, owner in identities:
            client = TestClient(app)
            client.cookies.update(state["clients"][who].cookies)
            clients.append(client)
            listed = done(client.get("/api/v1/scans"), 200)
            assert listed["total_count"] == 1 and listed["scans"][0]["scan_id"] == scans[owner].id
            listed_findings = done(client.get("/api/v1/findings"), 200)
            assert listed_findings["total_count"] == 1 and listed_findings["findings"][0]["evidence_id"] == findings[owner].id
            assert client.get(f"/api/v1/findings/{findings[owner].id}").status_code == 200
            for other in set(scans) - {owner}:
                for path in (f"scans/{scans[other].id}", f"scans/{scans[other].id}/verify", f"scans/{scans[other].id}/export",
                             f"findings/{findings[other].id}", f"findings/{findings[other].id}/verify"):
                    response = client.get("/api/v1/" + path)
                    expected = 403 if who != "platform_admin" and path.startswith("findings/") and path.endswith("/verify") else 404
                    assert response.status_code == expected, (middleware, who, path, response.text)
                    assert "synthetic/private" not in response.text
        client = clients[0]
        for path, method in [("network/scan", "POST"), ("findings/conflicts", "GET"), ("export/findings.csv", "GET"),
                             (f"findings/{findings['a'].id}/soft-delete", "POST"), ("auth/audit/export", "GET")]:
            assert client.request(method, "/api/v1/" + path).status_code == 409
        with monkeypatch.context() as region:
            region.setenv("CRYPTOSCAN_EVIDENCE_REGION", "wrong-region")
            for path in ("scans", "findings", f"findings/{findings['a'].id}", f"scans/{scans['a'].id}/export"):
                response = client.get("/api/v1/" + path)
                assert response.status_code == 409 and "synthetic/private" not in response.text
    finally:
        for client in clients:
            client.close()


def test_real_postgres_runtime_gate_refuses_missing_and_behind_without_schema_repair(quality_cluster, monkeypatch):
    from sqlalchemy import inspect
    from db.connection.session import init_db, migration_status
    database, template = quality_cluster
    previous = SessionLocal.kw.get("bind")
    monkeypatch.setenv("ENVIRONMENT", "development")
    try:
        with database() as engine:
            assert migration_status(engine)["status"] == "missing"
            with pytest.raises(RuntimeError, match="alembic.*upgrade head"):
                init_db(engine)
            assert inspect(engine).get_table_names() == []
            # Deliberately damaged/behind fixture: this is a refusal exercise,
            # not a repaired successful workflow or a forged-current database.
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
                connection.execute(text("INSERT INTO alembic_version VALUES ('0068')"))
                connection.execute(text("CREATE TABLE systems (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200))"))
            assert migration_status(engine)["status"] == "behind"
            with pytest.raises(RuntimeError, match="alembic.*upgrade head"):
                init_db(engine)
            assert set(inspect(engine).get_table_names()) == {"alembic_version", "systems"}
            assert {column["name"] for column in inspect(engine).get_columns("systems")} == {"id", "name"}
            assert inspect(engine).get_indexes("systems") == []
        with database(template) as engine:
            assert migration_status(engine)["status"] == "current"
            statements = []

            def observed(_connection, _cursor, statement, *_args):
                statements.append(statement.lstrip().split()[0].upper())

            event.listen(engine, "before_cursor_execute", observed)
            try:
                init_db(engine)
            finally:
                event.remove(engine, "before_cursor_execute", observed)
            assert statements and not set(statements) & {"CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE"}
    finally:
        SessionLocal.configure(bind=previous)
