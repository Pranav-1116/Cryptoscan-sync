"""G — the nine failure modes, each row proven by an executed drill.

A failure matrix written from memory is a wish list. Every row here runs the
code that is supposed to survive the failure, with the failure actually
injected, and records what was observed. Three verdicts only:

    PROVEN     the drill ran and every check passed
    BROKEN     the drill ran and the system did the wrong thing
    UNPROVEN   the drill could not run here (no dependency / no drill at all),
               or there is no drill for this mode yet

``PROVEN`` is never inferred from code reading, and a mode without a drill is
reported ``UNPROVEN`` with the reason rather than left off the table. The
number of rows is fixed at nine; the harness refuses to write a report that
drops one.

Run::

    python scripts/failure_matrix.py                 # measure, print the table
    python scripts/failure_matrix.py --json docs/bank-environment/109-failure-matrix.json \\
        --md docs/bank-environment/109-failure-matrix.md

The drills are in-process and self-contained. Where a drill can only be
proven against a real host (a real Redis for SIGKILL recovery, a real
PostgreSQL for failover), the row says so in its ``limit`` field instead of
claiming more than the executed drill showed.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "cryptoscan.failure-matrix/1"
VERSION = "failure-matrix/1.0"

PROVEN = "PROVEN"
BROKEN = "BROKEN"
UNPROVEN = "UNPROVEN"


class Broken(AssertionError):
    """The drill ran and the system behaved incorrectly."""


class Unavailable(RuntimeError):
    """The drill could not be executed in this environment."""


# --------------------------------------------------------------------- run --- #
class Run:
    """Collects what a drill observed; a failed check aborts the drill."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.observations: dict[str, Any] = {}
        self.notes: list[str] = []

    def check(self, condition: Any, label: str) -> None:
        if not condition:
            raise Broken(f"{self.mode}: {label}")

    def see(self, **observations: Any) -> None:
        self.observations.update(observations)

    def note(self, text: str) -> None:
        self.notes.append(text)


@dataclass
class Row:
    mode: str
    what_breaks: str
    expected: str
    verdict: str
    behavior: str = ""
    observations: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    limit: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "what_breaks": self.what_breaks,
            "expected": self.expected,
            "verdict": self.verdict,
            "behavior": self.behavior,
            "observations": self.observations,
            "reason": self.reason,
            "limit": self.limit,
        }


# ------------------------------------------------------------------ drills --- #
def drill_api(run: Run) -> tuple[str, str | None]:
    """A database that accepts the connection and never answers.

    Unreachable is not refused: a paused or partitioned database hangs, so a
    readiness probe can fail by timing out instead of by answering 503 — which
    looks exactly like a wedged API and ties up a worker thread per interval.
    """
    from db.connection import engine as engine_module
    from api.routers import health

    release = threading.Event()

    class _BlockingConnection:
        def __enter__(self) -> "_BlockingConnection":
            return self

        def __exit__(self, *exc: Any) -> bool:
            return False

        def execute(self, *_a: Any, **_k: Any) -> Any:
            release.wait(15)
            raise RuntimeError("database never answered")

    class _BlockingEngine:
        def connect(self) -> _BlockingConnection:
            return _BlockingConnection()

    original = engine_module.get_engine
    engine_module.get_engine = lambda: _BlockingEngine()  # type: ignore[assignment]
    try:
        started = time.monotonic()
        response = health.readyz()
        ready_seconds = time.monotonic() - started

        # Liveness must still answer while the database is stalled; a restart
        # would not fix a database that is briefly away.
        started = time.monotonic()
        live = health.healthz()
        live_seconds = time.monotonic() - started
    finally:
        engine_module.get_engine = original  # type: ignore[assignment]
        release.set()

    body = json.loads(response.body)
    budget = health.READINESS_PROBE_TIMEOUT_SECONDS
    run.see(readiness_status=response.status_code, readiness_seconds=round(ready_seconds, 2),
            readiness_budget_seconds=budget, liveness_seconds=round(live_seconds, 3),
            readiness_body=body)

    run.check(response.status_code == 503, "readiness answered something other than 503")
    run.check(ready_seconds <= budget + 3.0,
              f"readiness took {ready_seconds:.1f}s, longer than its {budget}s budget")
    run.check("no answer within" in str(body.get("database", "")),
              "readiness did not say the database failed to answer")
    run.check(live_seconds < 1.0, f"liveness took {live_seconds:.1f}s during a database stall")
    run.check(isinstance(live, dict) and live, "liveness returned nothing during a database stall")

    run.note(f"readiness 503 in {ready_seconds:.2f}s (budget {budget}s); liveness answered in "
             f"{live_seconds * 1000:.0f}ms")
    return (f"503 in {ready_seconds:.2f}s with 'no answer within {budget}s'; liveness stayed up",
            "the stalled probe thread is only released when the driver's own timeout expires; the "
            "endpoint stops waiting for it, so a probe-heavy interval can still leave orphaned threads")


def drill_database(run: Run) -> tuple[str, str | None]:
    """Backup restore accepts a good artifact and refuses every altered one."""
    from governance import backup

    class _Pg:
        name = "postgres"

        def __init__(self) -> None:
            self.restored = None
            self.replayed = None

        def dump(self, database_id: str) -> bytes:
            return f"PGDUMP:{database_id}:t1,t2".encode()

        def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
            self.restored = (database_id, payload)
            return {"restored_tables": 2}

        def replay_wal(self, database_id: str, wal: bytes, pit: str) -> dict[str, Any]:
            self.replayed = (database_id, wal, pit)
            return {"wal_records": 5, "pit": pit}

    key = backup.generate_encryption_key()
    backend = _Pg()
    made = backup.create_backup(backend=backend, database_id="proddb", encryption_key=key,
                                signing_secret="drill-secret", sequence=1, wal_tail=b"WAL1")
    manifest = made["manifest"]

    good = backup.restore_backup(backend=backend, database_id="proddb",
                                 ciphertext=made["ciphertext"], manifest=manifest,
                                 encryption_key=key, signing_secret="drill-secret")
    run.check(good["restored"] is True, "a valid backup did not restore")
    run.check(backend.restored is not None, "restore reported success without calling the backend")

    refusals: dict[str, str] = {}

    def refused(label: str, fn: Callable[[], Any]) -> None:
        backend.restored = None
        try:
            fn()
        except backup.BackupError as exc:
            refusals[label] = str(exc)[:100]
        else:
            raise Broken(f"database: restore accepted a {label} artifact")
        if backend.restored is not None:
            raise Broken(f"database: a {label} artifact reached the backend before being refused")

    tampered_manifest = dict(manifest, size_bytes=int(manifest["size_bytes"]) + 1)
    refused("manifest-tampered", lambda: backup.restore_backup(
        backend=backend, database_id="proddb", ciphertext=made["ciphertext"],
        manifest=tampered_manifest, encryption_key=key, signing_secret="drill-secret"))
    refused("wrong-signing-secret", lambda: backup.restore_backup(
        backend=backend, database_id="proddb", ciphertext=made["ciphertext"],
        manifest=manifest, encryption_key=key, signing_secret="not-the-secret"))
    flipped = bytearray(made["ciphertext"])
    flipped[len(flipped) // 2] ^= 0xFF
    refused("ciphertext-corrupt", lambda: backup.restore_backup(
        backend=backend, database_id="proddb", ciphertext=bytes(flipped),
        manifest=manifest, encryption_key=key, signing_secret="drill-secret"))
    refused("wrong-encryption-key", lambda: backup.restore_backup(
        backend=backend, database_id="proddb", ciphertext=made["ciphertext"],
        manifest=manifest, encryption_key=backup.generate_encryption_key(),
        signing_secret="drill-secret"))

    run.see(restored=True, refusals=sorted(refusals), refusal_reasons=refusals,
            wal_applied=good["wal_applied"])
    run.note("valid backup restored; 4 altered artifacts refused before touching the backend")
    return (f"valid restore; {len(refusals)} altered artifacts refused "
            f"({', '.join(sorted(refusals))})",
            "the backend is an in-process fake, so this proves the integrity gate, not that a real "
            "pg_restore refuses a corrupt dump (see scripts/pitr_drill.py and postgres_drill.py)")


def drill_worker(run: Run) -> tuple[str, str | None]:
    """A worker dies holding a job: Redis requeues it, the DB reaper fails it."""
    import fakeredis
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from db.models.base import Base
    import db.models  # noqa: F401 — registers the metadata
    from db.repositories.job_repository import JobRepository
    from worker.core.job_consumer import JobConsumer
    from worker.core.job_reaper import reap_stale_jobs

    queue = "cryptoscan:drill:queue"

    def consumer(server: Any, worker_id: str) -> JobConsumer:
        c = JobConsumer(redis_url="", queue_name=queue, poll_interval_seconds=1,
                        worker_id=worker_id, allow_memory_fallback=True)
        c.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)
        c.redis_url = "redis://drill"
        return c

    server = fakeredis.FakeServer()
    dead = consumer(server, "dead")
    dead.enqueue({"job_id": "j1", "target_repo": "https://example/drill.git", "target_branch": "main"})
    claimed = dead._pop()
    run.check(claimed is not None and claimed.job_id == "j1", "the drill job was never claimed")
    dead.redis_client.delete(dead.lease_key)          # the worker was killed: lease gone

    recoverer = consumer(server, "new")
    stats = recoverer.recover_orphans()
    redelivered = recoverer._pop()
    run.check(stats.get("requeued") == 1, f"orphan recovery requeued {stats.get('requeued')} jobs")
    run.check(redelivered is not None and redelivered.job_id == "j1",
              "the orphaned job was not redelivered")
    run.check(redelivered.attempts == 1, f"redelivery did not count the attempt ({redelivered.attempts})")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        repo = JobRepository(session)
        stale = repo.create_job(job_type="MANUAL", target_repo="https://example/a.git",
                                target_branch="main", triggered_by="drill")
        fresh = repo.create_job(job_type="MANUAL", target_repo="https://example/b.git",
                                target_branch="main", triggered_by="drill")
        stale.status = fresh.status = "RUNNING"
        now = datetime.now(timezone.utc)
        stale.created_at = stale.updated_at = now - timedelta(hours=3)
        session.commit()

        reaped = reap_stale_jobs(session, queued_ids=set(), publish=None,
                                 running_timeout=timedelta(minutes=90))
        session.refresh(stale)
        session.refresh(fresh)
        run.check(reaped["failed_running"] == 1,
                  f"the reaper failed {reaped['failed_running']} stale RUNNING rows")
        run.check(stale.status == "FAILED", f"a stale RUNNING row stayed {stale.status}")
        run.check("worker lost" in (stale.error_message or ""),
                  "a failed row did not record why it failed")
        run.check(fresh.status == "RUNNING", "the reaper failed a job that is still running")
    finally:
        session.close()
        engine.dispose()

    run.see(orphan_requeued=stats.get("requeued"), redelivered_attempts=redelivered.attempts,
            db_failed_running=reaped["failed_running"], fresh_row_status=fresh.status)
    run.note("killed worker's job requeued with attempts=1; stale RUNNING row marked FAILED")
    return ("orphan requeued and redelivered with attempts=1; stale RUNNING row FAILED, fresh one left",
            "Redis here is fakeredis and the lease loss is simulated by deleting the key; the actual "
            "SIGKILL is scripts/queue_kill9_drill.py (see the queue row)")


def drill_collector(run: Run) -> tuple[str, str | None]:
    """A collector raises: the plane is FAILED, never an empty COMPLETE plane."""
    from api import estate_discovery
    from api.estate_planes import PlaneNotConfigured

    def boom(_db: Any, **_kw: Any) -> dict[str, Any]:
        raise RuntimeError("connection reset by peer")

    def no_credentials(_db: Any, **_kw: Any) -> dict[str, Any]:
        raise PlaneNotConfigured("no read-only role configured")

    def healthy(_db: Any, **_kw: Any) -> dict[str, Any]:
        return {"expected": 3, "collected": 3, "assets": [{"ref": "a"}], "evidence": [{"id": "e"}]}

    failed = estate_discovery._collect("NETWORK", boom, None)
    not_attempted = estate_discovery._collect("CLOUD", no_credentials, None)
    complete = estate_discovery._collect("CMDB", healthy, None)

    run.see(failed_status=failed["status"], failed_reason=failed["reason"],
            failed_assets=len(failed["assets"]),
            not_attempted_status=not_attempted["status"], complete_status=complete["status"])

    run.check(failed["status"] == "FAILED", f"a raising collector was reported as {failed['status']}")
    run.check(failed["assets"] == [] and failed["evidence"] == [],
              "a failed plane still produced assets")
    run.check("UNKNOWN" in str(failed["impact"]) and "no absence" in str(failed["impact"]).lower(),
              "a failed plane's impact does not say its inventory is unknown")
    run.check("RuntimeError" in str(failed["reason"]), "a failed plane did not record the error type")
    run.check(not_attempted["status"] == "NOT_ATTEMPTED",
              f"an unconfigured collector was reported as {not_attempted['status']}")
    run.check(complete["status"] == "COMPLETE",
              f"a healthy collector was reported as {complete['status']}")

    run.note("raise → FAILED with 'UNKNOWN / no absence may be inferred'; no creds → NOT_ATTEMPTED")
    return ("raise → FAILED + 'inventory is UNKNOWN, no absence of crypto may be inferred'; "
            "no credentials → NOT_ATTEMPTED; healthy → COMPLETE",
            "the collector is injected, so this proves the runner's status mapping, not any one "
            "vendor API's error behaviour")


def drill_agent(run: Run) -> tuple[str, str | None]:
    """The agent's submit path fails: no exception escapes, and it recovers."""
    from runtime.core.submitter import RuntimeSubmitter

    payload = {"scanner_id": "drill", "findings": []}

    def down(_url: str, _payload: dict[str, Any]) -> Any:
        raise ConnectionError("api unreachable")

    down_result = RuntimeSubmitter(api_url="https://api.internal", transport=down).submit(payload)
    run.check(down_result["ok"] is False, "a failed submission was reported as ok")
    run.check(down_result["skipped"] is False, "a failed submission was reported as skipped")
    run.check("api unreachable" in str(down_result.get("error")), "the failure was not recorded")

    recovered = RuntimeSubmitter(api_url="https://api.internal",
                                 transport=lambda _u, _p: {"accepted": 1}).submit(payload)
    run.check(recovered["ok"] is True, "the agent did not submit once the API came back")

    unconfigured = RuntimeSubmitter(api_url=None, transport=None).submit(payload)
    run.check(unconfigured["ok"] is False and unconfigured["skipped"] is True,
              "an unconfigured agent did not report skipped")

    run.see(failed_result={k: str(v)[:40] for k, v in down_result.items()},
            recovered=recovered["ok"], unconfigured=unconfigured.get("reason"))
    run.note("a raising transport returned ok=False without raising; the next submit succeeded")
    return ("transport raises → {ok: false, error: 'api unreachable'}, no exception escapes; "
            "next submit ok: true",
            "the transport is injected and the agent has no local spool, so findings produced during "
            "the outage are dropped rather than replayed — that is the observed behaviour, not a retry")


def drill_network(run: Run) -> tuple[str, str | None]:
    """A black-holed endpoint and a refused port: UNKNOWN, inside the timeout."""
    from network_scanner.discovery.protocol_detector import detect_protocol

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    try:  # accept nothing: the connection completes and every probe waits for a reply
        started = time.monotonic()
        blackhole = detect_protocol("127.0.0.1", port, timeout=0.4)
        blackhole_seconds = time.monotonic() - started
    finally:
        listener.close()

    refused_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    refused_socket.bind(("127.0.0.1", 0))
    closed_port = refused_socket.getsockname()[1]
    refused_socket.close()
    started = time.monotonic()
    refused = detect_protocol("127.0.0.1", closed_port, timeout=0.4)
    refused_seconds = time.monotonic() - started

    run.see(blackhole_detected=blackhole["detected"], blackhole_method=blackhole["detection_method"],
            blackhole_seconds=round(blackhole_seconds, 2),
            blackhole_attempts=[a["probe"] for a in blackhole.get("attempts", [])],
            refused_detected=refused["detected"], refused_seconds=round(refused_seconds, 2))

    run.check(blackhole["detected"] == "UNKNOWN",
              f"a black-holed endpoint was reported as {blackhole['detected']}")
    run.check(blackhole["detection_method"] == "NO_RESPONSE",
              "a black-holed endpoint got a method that implies a response")
    run.check(blackhole_seconds < 6.0,
              f"probing a black-holed endpoint took {blackhole_seconds:.1f}s")
    run.check(blackhole["detected"] != (blackhole["service_guess"] or {}).get("name"),
              "the port guess was reported as a detection")
    run.check(refused["detected"] == "UNKNOWN",
              f"a closed port was reported as {refused['detected']}")
    run.check(any("UNKNOWN is the result" in str(x) for x in blackhole.get("limitations", [])),
              "the detection did not say that UNKNOWN is the result")

    run.note(f"black-holed endpoint → UNKNOWN in {blackhole_seconds:.2f}s; closed port → UNKNOWN")
    return (f"black-holed endpoint → UNKNOWN/NO_RESPONSE in {blackhole_seconds:.2f}s; "
            f"closed port → UNKNOWN in {refused_seconds:.2f}s",
            "no packet loss or asymmetric routing is simulated; the bounded timeouts are the "
            "production ones scaled down")


def drill_storage(run: Run) -> tuple[str, str | None]:
    """The backup volume: a real roundtrip, a corrupt artifact, an unwritable path."""
    from governance import backup
    from governance import backup_jobs as jobs

    class _Pg:
        name = "postgres"

        def dump(self, database_id: str) -> bytes:
            return f"PGDUMP:{database_id}:accounts".encode()

        def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
            return {"restored_tables": 1, "bytes": len(payload)}

    key = backup.generate_encryption_key()
    with tempfile.TemporaryDirectory() as tmp:
        storage = jobs.DiskBackupStorage(tmp)
        config = jobs.BackupConfig(database_id="proddb", engine="postgres")
        written = jobs.run_backup_job(backend=_Pg(), storage=storage, config=config,
                                      encryption_key=key, signing_secret="drill-secret")
        files = sorted(p.name for p in Path(tmp).iterdir())
        run.check(len(files) == 2, f"the backup wrote {len(files)} files, not a blob + manifest")

        restored = jobs.restore_from_storage(backend=_Pg(), storage=storage, database_id="proddb",
                                            encryption_key=key, signing_secret="drill-secret")
        run.check(restored["restored"] is True, "the backup did not restore from disk")

        blob = storage._blob_path(written["storage_key"])
        raw = bytearray(blob.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        blob.write_bytes(bytes(raw))
        try:
            jobs.restore_from_storage(backend=_Pg(), storage=storage, database_id="proddb",
                                      encryption_key=key, signing_secret="drill-secret")
        except backup.BackupError as exc:
            corrupt_refusal = str(exc)[:90]
        else:
            raise Broken("storage: a corrupt artifact on disk was restored")

        # A real write failure: something occupied the blob's path.
        broken_config = jobs.BackupConfig(database_id="otherdb", engine="postgres")
        occupied = jobs.DiskBackupStorage(tmp)
        blocker = Path(tmp) / "postgres__otherdb__placeholder.enc"
        blocker.mkdir()
        original_put = occupied.put

        def put_or_fail(key_name: str, data: bytes) -> None:
            if "otherdb" in key_name:
                (Path(tmp) / f"{key_name.replace('/', '__')}.enc").mkdir()
                raise IsADirectoryError("the backup volume is not writable at this path")
            original_put(key_name, data)

        occupied.put = put_or_fail  # type: ignore[method-assign]
        last_run_before = broken_config.last_run_at
        try:
            jobs.run_backup_job(backend=_Pg(), storage=occupied, config=broken_config,
                                encryption_key=key, signing_secret="drill-secret")
        except OSError as exc:
            write_refusal = str(exc)[:90]
        else:
            raise Broken("storage: a failed write was reported as a successful backup")
        run.check(broken_config.last_run_at == last_run_before,
                  "a failed backup advanced the schedule as if it had succeeded")

    run.see(files=files, restored=True, corrupt_artifact_refused=corrupt_refusal,
            failed_write_raised=write_refusal)
    run.note("disk roundtrip OK; a bit-flipped artifact refused; an unwritable path raised")
    return ("roundtrip from disk OK; corrupt artifact refused; unwritable path raised and the "
            "schedule did not advance",
            "the volume is a local temp directory, not the mounted production volume or an "
            "S3-compatible sink")


def drill_certificate_expiry(run: Run) -> tuple[str, str | None]:
    """Expiry boundaries: expired / critical / soon / valid / not-yet / unknown."""
    from network_scanner.certificates.cert_parser import _expiry_fields
    from cbom import nbom

    now = datetime.now(timezone.utc)
    cases = {
        "expired": (now - timedelta(days=1), None),
        "critical": (now + timedelta(days=3), None),
        "soon": (now + timedelta(days=20), None),
        "valid": (now + timedelta(days=90), None),
        "not_yet_valid": (now + timedelta(days=90), now + timedelta(days=5)),
        "no_expiry": (None, None),
    }
    got = {name: _expiry_fields(*args)["expiry_status"] for name, args in cases.items()}
    run.see(expiry_statuses=got)

    expected = {"expired": "EXPIRED", "critical": "EXPIRING_CRITICAL", "soon": "EXPIRING_SOON",
                "valid": "VALID", "not_yet_valid": "NOT_YET_VALID", "no_expiry": "UNKNOWN"}
    for name, want in expected.items():
        run.check(got[name] == want, f"{name} certificate reported as {got[name]}, not {want}")
    # Days are whole days remaining (floored), so the boundary is at 7 full
    # days: 7d23h left reads 7 and is critical, 8d1h left reads 8 and is not.
    # Asserted an hour clear of the edge, because a certificate expiring in
    # exactly 8 days is already 7.99 days away by the time it is measured.
    edge = {
        "7d23h": (_expiry_fields(now + timedelta(days=7, hours=23), None), "EXPIRING_CRITICAL"),
        "8d1h": (_expiry_fields(now + timedelta(days=8, hours=1), None), "EXPIRING_SOON"),
        "30d23h": (_expiry_fields(now + timedelta(days=30, hours=23), None), "EXPIRING_SOON"),
        "31d1h": (_expiry_fields(now + timedelta(days=31, hours=1), None), "VALID"),
    }
    for label, (fields, want) in edge.items():
        run.check(fields["expiry_status"] == want,
                  f"{label} left reported as {fields['expiry_status']} with "
                  f"{fields['days_until_expiry']} days, not {want}")
    run.see(days_until_expiry={label: fields["days_until_expiry"] for label, (fields, _) in edge.items()},
            flooring_note="days_until_expiry floors: 7d23h remaining reads 7 and is CRITICAL")

    bom = nbom.build_nbom([{
        "host": "payments.internal", "port": 443, "protocol": "TLS",
        "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "observed": True,
        "certificate": {"subject": "CN=payments.internal", "issuer": "CN=Bank CA",
                        "public_key_algorithm": "RSA", "public_key_size": 2048,
                        "not_after": (now - timedelta(days=1)).isoformat(),
                        "expiry_status": got["expired"]},
    }])
    findings = json.dumps(bom)
    run.check("nbom.certificate_expired" in findings,
              "an expired certificate did not reach the NBOM as a finding")
    run.see(nbom_contains_expiry_finding=True)

    live_bom = json.dumps(nbom.build_nbom([{
        "host": "payments.internal", "port": 443, "protocol": "TLS", "observed": True,
        "certificate": {"subject": "CN=payments.internal", "public_key_algorithm": "RSA",
                        "public_key_size": 2048,
                        "not_after": (now + timedelta(days=365)).isoformat(),
                        "expiry_status": got["valid"]},
    }]))
    run.check("nbom.certificate_expired" not in live_bom,
              "a valid certificate was reported as expired")

    run.note("boundaries verified: -1d EXPIRED, +3d/-7d CRITICAL, +8d/+20d SOON, +90d VALID, "
             "missing not_after → UNKNOWN (not VALID)")
    return ("expiry computed from not_after: -1d EXPIRED, ≤7d CRITICAL, ≤30d SOON, else VALID, "
            "no not_after → UNKNOWN; expired certificate lands in the NBOM as critical",
            "expiry is evaluated at observation time from the certificate's own not_after; no clock "
            "skew or timezone-shifted issuer is simulated, and nothing here renews or rotates")


def drill_queue(run: Run) -> tuple[str, str | None]:
    """A Redis outage must fail closed, and a SIGKILL mid-job must not lose the job."""
    from worker.core.job_consumer import enqueue_job

    started = time.monotonic()
    try:
        enqueue_job({"job_id": "drill", "target_repo": "https://example/x.git"},
                    redis_url="redis://127.0.0.1:1/0")
    except RuntimeError as exc:
        refused = str(exc)[:90]
    else:
        raise Broken("queue: an enqueue during a Redis outage was accepted")
    refuse_seconds = time.monotonic() - started
    run.check(refuse_seconds < 5.0, f"a Redis outage took {refuse_seconds:.1f}s to be refused")

    drill = Path(__file__).with_name("queue_kill9_drill.py")
    started = time.monotonic()
    completed = subprocess.run([sys.executable, str(drill), "--fake"], capture_output=True,
                               text=True, timeout=180)
    kill_seconds = time.monotonic() - started
    run.check(completed.returncode == 0,
              f"the SIGKILL drill exited {completed.returncode}: "
              f"{(completed.stderr or completed.stdout)[-200:]}")
    try:
        record = json.loads(completed.stdout[completed.stdout.index("{"):])
    except (ValueError, json.JSONDecodeError) as exc:
        raise Broken(f"queue: the SIGKILL drill produced no JSON record ({exc})") from exc
    run.check(record.get("result") == "PASS", f"the SIGKILL drill reported {record.get('result')}")
    run.check(int((record.get("recover_orphans") or {}).get("requeued") or 0) == 1,
              "the SIGKILL drill did not requeue the killed job")

    run.see(redis_outage_refused=refused, refuse_seconds=round(refuse_seconds, 2),
            kill9_result=record.get("result"), kill9_requeued=record["recover_orphans"]["requeued"],
            redelivered=record.get("redelivered"), kill9_seconds=round(kill_seconds, 2))
    run.note("enqueue with a dead Redis raised instead of accepting; SIGKILL drill PASS")
    return (f"enqueue during a Redis outage raised in {refuse_seconds:.2f}s; SIGKILL drill PASS "
            f"(orphan requeued, redelivered with attempts=1)",
            "the SIGKILL drill runs against fakeredis; the real-Redis invocation "
            "(REDIS_URL=redis://… python scripts/queue_kill9_drill.py) is a bank-host step and was "
            "not executed here")


DRILLS: dict[str, Callable[[Run], tuple[str, str | None]]] = {
    "api": drill_api,
    "database": drill_database,
    "worker": drill_worker,
    "collector": drill_collector,
    "agent": drill_agent,
    "network": drill_network,
    "storage": drill_storage,
    "certificate_expiry": drill_certificate_expiry,
    "queue": drill_queue,
}

# The matrix is these nine modes. A report missing one is not a report.
MODES: tuple[dict[str, str], ...] = (
    {"mode": "api", "what_breaks": "the API stops answering (database accepts, never replies)"},
    {"mode": "database", "what_breaks": "PostgreSQL is lost and a backup must be restored"},
    {"mode": "worker", "what_breaks": "a worker is killed holding a job"},
    {"mode": "collector", "what_breaks": "a collector errors or has no credentials"},
    {"mode": "agent", "what_breaks": "the agent's submission to the API fails"},
    {"mode": "network", "what_breaks": "an endpoint is unreachable or black-holed"},
    {"mode": "storage", "what_breaks": "the backup volume is corrupt or unwritable"},
    {"mode": "certificate_expiry", "what_breaks": "a certificate in the estate expires"},
    {"mode": "queue", "what_breaks": "Redis drops out or a job is SIGKILLed mid-run"},
)


def measure(only: list[str] | None = None) -> dict[str, Any]:
    """Run every drill and grade it. Never raises for a broken mode."""
    rows: list[Row] = []
    wanted = set(only) if only else None
    for entry in MODES:
        mode = entry["mode"]
        if wanted is not None and mode not in wanted:
            continue
        run = Run(mode)
        drill = DRILLS.get(mode)
        if drill is None:
            rows.append(Row(mode=mode, what_breaks=entry["what_breaks"],
                            expected="(no drill exists for this mode)", verdict=UNPROVEN,
                            reason="no drill exists for this mode"))
            continue
        started = time.monotonic()
        try:
            behavior, limit = drill(run)
        except Broken as exc:
            rows.append(Row(mode=mode, what_breaks=entry["what_breaks"],
                            expected="", verdict=BROKEN, behavior="",
                            observations=run.observations, reason=str(exc)))
            continue
        except Unavailable as exc:
            rows.append(Row(mode=mode, what_breaks=entry["what_breaks"], expected="",
                            verdict=UNPROVEN, observations=run.observations, reason=str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 — a drill that cannot run is not a proof
            rows.append(Row(mode=mode, what_breaks=entry["what_breaks"], expected="",
                            verdict=UNPROVEN, observations=run.observations,
                            reason=f"drill could not execute: {type(exc).__name__}: {exc}"))
            continue
        elapsed = time.monotonic() - started
        rows.append(Row(mode=mode, what_breaks=entry["what_breaks"], expected=behavior,
                        verdict=PROVEN, behavior=behavior, observations=run.observations,
                        limit=limit))
        rows[-1].observations.setdefault("drill_seconds", round(elapsed, 2))

    counts = {PROVEN: 0, BROKEN: 0, UNPROVEN: 0}
    for row in rows:
        counts[row.verdict] += 1
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modes": len(rows),
        "expected_modes": len(MODES),
        "proven": counts[PROVEN],
        "broken": counts[BROKEN],
        "unproven": counts[UNPROVEN],
        "complete": counts[PROVEN] == len(MODES) and len(rows) == len(MODES),
        "rows": [row.as_dict() for row in rows],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Nine failure modes — each row proven by an executed drill",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['proven']} proven / {report['broken']} broken / {report['unproven']} unproven "
        f"of {report['expected_modes']}**",
        "",
        "Every row below ran the code that is supposed to survive the failure, with the failure "
        "actually injected. `PROVEN` means the drill ran and every check passed; it is never "
        "inferred from reading the code. `UNPROVEN` means the drill could not run here or does not "
        "exist — it is not a pass.",
        "",
        "| Mode | What breaks | Observed behaviour | Verdict |",
        "|---|---|---|---|",
    ]
    icons = {PROVEN: "**PROVEN**", BROKEN: "**BROKEN**", UNPROVEN: "**UNPROVEN**"}
    for row in report["rows"]:
        behavior = row["behavior"] or row["reason"] or "—"
        behavior = str(behavior).replace("|", "/")
        lines.append(f"| `{row['mode']}` | {row['what_breaks']} | {behavior} | "
                     f"{icons.get(row['verdict'], row['verdict'])} |")

    if report["broken"]:
        lines += ["", "## Broken", ""]
        for row in report["rows"]:
            if row["verdict"] == BROKEN:
                lines.append(f"- `{row['mode']}`: {row['reason']}")
    if report["unproven"]:
        lines += ["", "## Unproven — do not read these as passes", ""]
        for row in report["rows"]:
            if row["verdict"] == UNPROVEN:
                lines.append(f"- `{row['mode']}`: {row['reason']}")

    lines += ["", "## What this does not prove", ""]
    limits = [(row["mode"], row["limit"]) for row in report["rows"] if row.get("limit")]
    if limits:
        for mode, limit in limits:
            lines.append(f"- `{mode}`: {limit}")
    else:
        lines.append("- (no limits recorded)")
    lines += [
        "",
        "And, across all nine rows: these drills run in-process against injected faults, real local "
        "files and real sockets. They are not a chaos run against a bank's live estate, and a "
        "`PROVEN` row says the code path behaves as specified under that specific fault — not that "
        "the deployment is configured correctly, monitored, or that anyone will notice.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--only", help="comma-separated modes to run")
    parser.add_argument("--min-proven", type=int, default=0,
                        help="exit non-zero when fewer than this many rows are PROVEN")
    args = parser.parse_args(argv)

    only = [m.strip() for m in args.only.split(",") if m.strip()] if args.only else None
    report = measure(only)

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<9} {row['mode']:<20} "
                  f"{(row['behavior'] or row['reason'] or '')[:90]}")
        print(f"\n{report['proven']} proven / {report['broken']} broken / "
              f"{report['unproven']} unproven of {report['expected_modes']}")
    return 0 if report["proven"] >= args.min_proven else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
