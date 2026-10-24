#!/usr/bin/env python3
"""Owned local API/SQL/Redis/worker dispatch drill, never deployment acceptance.

Creates its own Unix-socket PostgreSQL/Redis and synthetic identities/source.
No deployment URL, customer target, launcher double or gate bypass is accepted.
Development parsing is exercised positively; controlled parsing MUST refuse
without a provisioned pinned container runtime. That refusal is not isolation
qualification. Requires pgserver, the repository requirements and redis-server.
"""
from __future__ import annotations

from _bootstrap import bootstrap

bootstrap()

import argparse
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def until(check, *, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Bounded dispatch observation timed out")


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            return False
    return True


def run(redis_binary, report_path):
    import pgserver
    import redis
    import psutil
    from sqlalchemy import create_engine, select, text
    from sqlalchemy.engine import make_url

    report = {
        "schema": "cryptoscan.worker-dispatch-drill/1", "result": "FAIL", "checks": [],
        "scope": "OWNED_LOCAL_SYNTHETIC_POSTGRESQL_REDIS", "api_transport": "IN_PROCESS_ASGI_TESTCLIENT",
        "worker_process": "REAL_UNMODIFIED_WORKER_ENTRYPOINT", "job_envelope_fixture_provisioned": False,
        "development_pipeline_exercised": True,
        "development_inline_parser_qualified": False, "controlled_isolation_qualified": False,
        "bank_approved": False, "deployment_qualified": False,
        "limits": ["Development success does not qualify controlled or production parsing",
                   "Controlled success remains blocked: pinned container runtime is not provisioned",
                   "Standalone Unix sockets; no deployed TLS/ACL/Sentinel/HA or partition qualification",
                   "Small synthetic workload; no capacity, latency SLO or performance-improvement claim",
                   "ASGI routes and real password/session auth, not a browser or network HTTP drill",
                   "Transport heartbeat is not the SQL execution fence or a collector-stop guarantee"],
    }
    server = redis_process = engine = admin = None
    clients = []
    processes = []
    old_environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="worker-dispatch-", dir="/home/user") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        redis_log = (private / "redis.log").open("w")
        try:
            source = private / "source"
            source.mkdir()
            (source / "crypto.py").write_text("import hashlib\nhashlib.md5(b'synthetic fixture')\n")
            (source / "negative.py").write_text("def add(a, b):\n    return a + b\n")
            server = pgserver.get_server(private / "pgdata", cleanup_mode="delete")
            base = make_url(server.get_uri())
            admin = create_engine(base, isolation_level="AUTOCOMMIT")
            database = "cryptoscan_e2e_dispatch_" + uuid.uuid4().hex[:12]
            with admin.connect() as db:
                db.execute(text('CREATE DATABASE "' + database + '"'))
            database_url = base.set(database=database).render_as_string(hide_password=False)
            redis_url = "unix://" + str(private / "redis.sock")

            def start_redis():
                process = subprocess.Popen([str(redis_binary), "--port", "0", "--unixsocket",
                    str(private / "redis.sock"), "--unixsocketperm", "700", "--save", "",
                    "--appendonly", "no", "--dir", str(private)], stdout=redis_log, stderr=subprocess.STDOUT)
                processes.append(process)
                client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=2)

                def ready():
                    assert process.poll() is None, "Owned Redis exited at startup"
                    try:
                        return client.ping()
                    except redis.ConnectionError:
                        return False
                until(ready, seconds=10)
                return process, client

            redis_process, transport = start_redis()
            report["redis"] = {"version": transport.info("server")["redis_version"],
                "tcp_port": transport.info("server")["tcp_port"],
                "binary_sha256": hashlib.sha256(redis_binary.read_bytes()).hexdigest()}
            queue = "cryptoscan:dispatch-drill:" + uuid.uuid4().hex
            os.environ.update({"ENVIRONMENT": "development", "DATABASE_URL": database_url,
                "REDIS_URL": redis_url, "SCAN_JOB_QUEUE_KEY": queue, "QUEUE_NAME": queue,
                "SECRET_KEY": secrets.token_hex(32), "STREAM_SECRET": secrets.token_hex(32),
                "CRYPTOSCAN_SOURCE_ROOTS": str(source), "WORKSPACE_BASE_PATH": str(private / "workspaces"),
                "CRYPTOSCAN_EXECUTION_CONTROLS": "false", "CRYPTOSCAN_EXECUTION_REGION": "in-south",
                "CRYPTOSCAN_EVIDENCE_REGION": "in-south", "CRYPTOSCAN_EVIDENCE_DESTINATION": "local-synthetic-sql",
                "CRYPTOSCAN_STATIC_SCAN_MODE": "inline", "CRYPTOSCAN_SCANNER_IMAGE": "",
                "NEO4J_URI": "", "GITHUB_TOKEN": "", "MAX_CONCURRENT_JOBS": "1"})
            from _bootstrap import path_entries
            os.environ["PYTHONPATH"] = os.pathsep.join(path_entries())
            subprocess.run([sys.executable, "-m", "alembic", "-c",
                str(ROOT / "services/database/migrations/alembic.ini"), "upgrade", "head"],
                cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            engine = create_engine(database_url)
            from db.connection.session import configure_session, SessionLocal
            configure_session(engine)
            from db.models.tenant import Tenant, TenantMembership
            from db.models.scan_job import ScanJob
            from db.models.scan import Scan
            from db.models.user import User
            from db.models.evidence_record import EvidenceRecord
            from db.models.execution_control import ExecutionOutbox, ExecutionAttempt
            from db.repositories.user_repository import UserRepository
            from db.models.base import utcnow
            from api.security.passwords import hash_password
            from api.config.settings import get_settings
            get_settings.cache_clear()
            password = secrets.token_urlsafe(32)
            with SessionLocal() as db:
                users = UserRepository(db)
                for name, roles in (("dispatch_a", ["security_analyst"]), ("dispatch_b", ["security_analyst"]),
                                    ("dispatch_reader", ["readonly"]), ("dispatch_admin", ["superadmin"])):
                    users.create_user(name, hash_password(password), roles)
                for owner in ("dispatch-a", "dispatch-b"):
                    db.add(Tenant(id=owner, name="Synthetic " + owner, slug=owner))
                    db.add(TenantMembership(tenant_id=owner, username=owner.replace("-", "_"), tenant_role="member"))
                db.add(TenantMembership(tenant_id="dispatch-a", username="dispatch_reader", tenant_role="member"))
                db.commit()
                report["migration"] = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                report["postgres_version"] = db.execute(text("SHOW server_version")).scalar_one()
            from api.main import create_app
            from fastapi.testclient import TestClient
            app = create_app()
            by_name = {}
            for name in ("dispatch_a", "dispatch_b", "dispatch_reader", "dispatch_admin"):
                client = TestClient(app)
                clients.append(client)
                response = client.post("/api/v1/auth/login", json={"username": name, "password": password})
                assert response.status_code == 200, "Real password/session login refused"
                by_name[name] = client
            a, b, reader, operator = [by_name[n] for n in ("dispatch_a", "dispatch_b", "dispatch_reader", "dispatch_admin")]
            report["checks"].append("REAL_PASSWORD_LOGIN_AND_DURABLE_SESSIONS")

            def state(job_id):
                with SessionLocal() as db:
                    row = db.get(ScanJob, job_id)
                    return {"status": row.status, "scan_id": row.scan_id, "owner": row.tenant_id,
                            "error": row.error_message or ""}

            def queued():
                response = a.post("/api/v1/scans/trigger", json={"repo_url": str(source), "scan_mode": "safe"})
                assert response.status_code == 202, response.text
                return response.json()["job_id"]

            @contextmanager
            def worker():
                log = (private / ("worker-" + uuid.uuid4().hex + ".log")).open("w")
                process = subprocess.Popen([sys.executable, "-m", "worker.main"], cwd=ROOT,
                    env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                try:
                    def ready():
                        assert process.poll() is None, "Real worker startup failed"
                        return list(transport.scan_iter(queue + ":worker:*"))
                    until(ready)
                    yield process
                finally:
                    try:
                        assert stop(process), "Owned worker required forced shutdown"
                    finally:
                        log.close()

            # No job/scan/evidence row is seeded. API admission creates the job.
            assert reader.post("/api/v1/scans/trigger", json={"repo_url": str(source)}).status_code == 403
            assert a.post("/api/v1/scans/trigger", json={"repo_url": str(private)}).status_code == 400
            jid = queued()
            raw = transport.lindex(queue, 0)
            assert raw and state(jid)["status"] == "QUEUED"
            transport.rpush(queue, raw)  # true duplicate delivery, same SQL job
            assert b.get("/api/v1/jobs/" + jid).status_code == 404
            report["checks"].append("ADMISSION_RBAC_SOURCE_ROOTS_AND_FOREIGN_JOB_ISOLATION")
            with worker():
                until(lambda: state(jid)["status"] in {"COMPLETED", "FAILED"})
                assert state(jid)["status"] == "COMPLETED", state(jid)
                until(lambda: not transport.llen(queue) and not sum(transport.llen(k) for k in transport.scan_iter(queue + ":processing:*")))
            from evidence.verification.stored_scan import verify_stored_scan
            with SessionLocal() as db:
                scans = db.execute(select(Scan)).scalars().all()
                assert len(scans) == 1 and scans[0].tenant_id == "dispatch-a"
                evidence = db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scans[0].id)).scalars().all()
                assert evidence and all(row.tenant_id == "dispatch-a" for row in evidence)
                integrity = verify_stored_scan(scans[0], evidence)
                assert integrity["result"] == "PASS"
                report["development_scan"] = {"job_id": jid, "status": state(jid)["status"],
                    "integrity": integrity, "evidence_count": len(evidence), "scan_count": len(scans)}
            report["checks"].append("REAL_REDIS_DEQUEUE_WORKER_PARSER_HASH_LOAD_AND_DUPLICATE_FENCE")

            stopped_id = queued()
            response = operator.post("/api/v1/control/safe-scan/emergency-stop", json={"engaged": True})
            assert response.status_code == 200, response.text
            with worker():
                until(lambda: state(stopped_id)["status"] == "FAILED")
            assert "execution gate" in state(stopped_id)["error"]
            assert a.post("/api/v1/scans/trigger", json={"repo_url": str(source)}).status_code == 409
            report["checks"].append("STOP_AFTER_ENQUEUE_REFUSED_AT_REAL_WORKER_AND_NEW_ADMISSION")

            response = operator.post("/api/v1/control/safe-scan/emergency-stop", json={"engaged": False})
            assert response.status_code == 200, response.text

            # Controlled mode is NOT weakened to make this environment pass.
            os.environ["CRYPTOSCAN_EXECUTION_CONTROLS"] = "true"
            prefix = "/api/v1/execution-controls"
            headers = {"X-Tenant-ID": "dispatch-a"}
            response = operator.put(prefix + "/provider-budget", json={"capacity": 2, "requests_per_second": 10})
            assert response.status_code == 200, response.text
            response = operator.put(prefix + "/policy", headers=headers, json={"expected_revision": 0,
                "legal_entity": "Synthetic bank", "execution_region": "in-south", "evidence_region": "in-south",
                "evidence_destination": "local-synthetic-sql", "max_runtime_seconds": 120,
                "capacity": 1, "requests_per_second": 5})
            assert response.status_code == 200, response.text
            with SessionLocal() as db:
                subject = db.execute(select(User).where(User.username == "dispatch_a")).scalar_one().id
            now = utcnow()
            response = operator.post(prefix + "/approvals", headers=headers, json={"target": str(source),
                "subject_kind": "user", "subject_id": subject, "not_before": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(minutes=10)).isoformat(), "max_requests": 10,
                "evidence_ref": "synthetic-change/DISPATCH-1"})
            assert response.status_code == 201, response.text
            controlled_id = queued()
            with SessionLocal() as db:
                assert db.query(ExecutionOutbox).filter_by(job_id=controlled_id).one().state == "PUBLISHED"
            # Observe a valid durable grant and the actual missing-runtime
            # refusal independently; a generic authority error alone would not
            # establish which prerequisite prevented controlled execution.
            from db.tenancy import tenant_scope
            from db.repositories.execution_control import matching_approval, ExecutionDenied
            from db.repositories.queued_authority import current_authority
            with tenant_scope("dispatch-a"), SessionLocal() as db:
                job = db.get(ScanJob, controlled_id)
                principal, roles = current_authority(db, job)
                assert principal == job.progress["execution_authority"] and "security_analyst" in roles
                matching_approval(db, job, principal, available_request=True)
            from worker.core.controlled_source import preflight
            try:
                preflight()
            except ExecutionDenied as exc:
                assert str(exc) == "Controlled parsing requires the approved container profile"
                report["isolation_preflight"] = {"result": "REFUSED", "reason": str(exc),
                                                 "durable_grant_validated_before_dispatch": True}
            else:
                raise AssertionError("Unprovisioned controlled parsing was not refused")
            with worker():
                until(lambda: state(controlled_id)["status"] == "FAILED")
            assert "execution authority" in state(controlled_id)["error"]
            report["checks"].append("CONTROLLED_SQL_OUTBOX_DISPATCH_REFUSES_UNPROVISIONED_ISOLATION")

            # An actual Redis outage must keep the HTTP-created SQL work pending.
            stop(redis_process)
            outage_id = queued()
            with SessionLocal() as db:
                outbox = db.query(ExecutionOutbox).filter_by(job_id=outage_id).one()
                assert outbox.state == "PENDING" and outbox.lease_until is None
            report["checks"].append("REAL_REDIS_OUTAGE_LEAVES_API_OUTBOX_PENDING_NOT_MEMORY_PUBLISHED")
            redis_process, transport = start_redis()
            with worker():  # worker maintenance republishes the pending SQL outbox
                until(lambda: state(outage_id)["status"] == "FAILED")
            with SessionLocal() as db:
                assert db.query(ExecutionOutbox).filter_by(job_id=outage_id).one().state == "PUBLISHED"
            report["checks"].append("REAL_WORKER_MAINTENANCE_REPUBLISHES_PENDING_OUTBOX_AFTER_RESTART")

            # Real Redis TTL: intake has stopped but a transport delivery drains.
            # This synthetic delivery tests transport only, not another scan.
            from worker.core.job_consumer import JobConsumer
            owner = JobConsumer(redis_url=redis_url, queue_name=queue + ":drain", worker_id="draining",
                                poll_interval_seconds=1, lease_ttl_seconds=3, allow_memory_fallback=False)
            observer = JobConsumer(redis_url=redis_url, queue_name=owner.queue_name, worker_id="observer",
                                   poll_interval_seconds=1, lease_ttl_seconds=3, allow_memory_fallback=False)
            with owner.maintain_lease():
                owner.enqueue({"job_id": "transport-only-drain", "target_repo": str(source)})
                delivery = owner._pop()
                assert delivery
                owner.stop()
                threading.Event().wait(3.5)
                assert transport.exists(owner.lease_key)
                assert observer.recover_orphans()["requeued"] == 0
                assert transport.llen(owner.processing_key) == 1
                owner.ack(delivery)
            report["checks"].append("REAL_REDIS_LEASE_SURVIVES_STOPPED_INTAKE_AND_DRAIN_BEYOND_TTL")
            from queue_kill9_drill import drill
            kill_result = drill(redis_url, False)
            assert kill_result["result"] == "PASS"
            # No URL/credentials or private paths are included in the report.
            report["transport_sigkill"] = {k: v for k, v in kill_result.items() if k != "redis"}
            report["checks"].append("REAL_SIGKILL_TRANSPORT_REDELIVERY_AFTER_NOT_BEFORE_LEASE_EXPIRY")
            with SessionLocal() as db:
                assert db.query(Scan).count() == 1
                assert db.query(ExecutionAttempt).count() == 0
                report["controlled_refusals"] = {"jobs": 2, "execution_attempts": 0,
                    "additional_scans": 0, "isolated_execution_qualified": False}
            report["result"] = "PASS"
        finally:
            for client in clients:
                client.close()
            graceful = all([stop(process) for process in reversed(processes)])
            redis_log.close()
            if engine:
                engine.dispose()
            if admin:
                admin.dispose()
            pg_pid = int((private / "pgdata/postmaster.pid").read_text().splitlines()[0]) if server else None
            if server:
                server.cleanup()
            report["cleanup"] = {"owned_children_shutdown_without_forced_kill": graceful,
                "owned_children_exited": all(p.poll() is not None for p in processes),
                "owned_postgresql_stopped": pg_pid is None or not psutil.pid_exists(pg_pid)}
            os.environ.clear()
            os.environ.update(old_environment)
    report["cleanup"]["private_source_database_socket_and_logs_removed"] = not private.exists()
    assert all(report["cleanup"].values())
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['result']}: {len(report['checks'])} real dispatch checks; controlled isolation remains unqualified.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-server", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--acknowledge-local-synthetic", action="store_true", required=True)
    args = parser.parse_args()
    if not args.redis_server.is_file() or not os.access(args.redis_server, os.X_OK):
        parser.error("Provide an existing redis-server executable; this drill never downloads one")
    if shutil.which("docker") is not None:
        parser.error("This refusal-profile drill requires an environment without a provisioned Docker runtime")
    run(args.redis_server.resolve(), args.report.resolve())


if __name__ == "__main__":
    main()
