#!/usr/bin/env python3
"""Worker-loss drill against a REAL Redis: a child process pops a job, is SIGKILLed mid-scan,
and a fresh consumer must recover the job (requeued at the head, attempts+1) once the lease expires.

    REDIS_URL=redis://redis:6379/0 python scripts/queue_kill9_drill.py            # real drill (bank host)
    python scripts/queue_kill9_drill.py --fake                                    # self-check on fakeredis

Exit code 0 = PASS. Prints a JSON record you can paste into docs/PRODUCTION-READINESS.md.
The drill uses its own queue name (``cryptoscan:drill:<pid>``) and deletes it afterwards, so it is
safe to run next to a live deployment. Requires no scanner, database or repository.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for d in sorted(ROOT.glob("shared/*/")) + sorted(ROOT.glob("services/*/")):
    sys.path.insert(0, str(d))

from worker.core.job_consumer import JobConsumer  # noqa: E402

LEASE = 5  # seconds; production default is 60 — the drill shortens it so it finishes in < 30 s


def _consumer(redis_url: str, queue: str, worker_id: str, fake_server=None) -> JobConsumer:
    c = JobConsumer(redis_url="" if fake_server else redis_url, queue_name=queue, poll_interval_seconds=1,
                    worker_id=worker_id, lease_ttl_seconds=LEASE, allow_memory_fallback=fake_server is not None)
    if fake_server is not None:
        import fakeredis
        c.redis_client = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
        c.redis_url = "redis://fake"
    return c


def child_main(redis_url: str, queue: str) -> None:
    """Runs in the doomed process: pop the job, heartbeat once, then hang 'scanning' until killed."""
    c = _consumer(redis_url, queue, "doomed-worker")
    job = c._pop()
    assert job is not None, "child found no job"
    c.heartbeat()
    print(json.dumps({"child": "popped", "job_id": job.job_id}), flush=True)
    while True:
        time.sleep(0.2)  # never acks — a kill -9 arrives


def drill(redis_url: str, fake: bool) -> dict:
    queue = f"cryptoscan:drill:{os.getpid()}"
    fake_server = None
    if fake:
        import fakeredis
        fake_server = fakeredis.FakeServer()
    parent = _consumer(redis_url, queue, "drill-parent", fake_server)
    parent.enqueue({"job_id": "drill-job", "target_repo": "https://example.invalid/bank-core.git", "target_branch": "main"})
    t0 = time.time()
    record: dict = {"redis": "fakeredis (self-check only)" if fake else redis_url, "lease_ttl_s": LEASE}

    if fake:
        # No second process can share a FakeServer, so simulate the crashed worker in-process.
        doomed = _consumer(redis_url, queue, "doomed-worker", fake_server)
        job = doomed._pop()
        assert job is not None and job.job_id == "drill-job"
        doomed.heartbeat()
        doomed.redis_client.delete(doomed.lease_key)  # the lease expiring == the worker is dead
        record["kill"] = "simulated (lease deleted)"
    else:
        proc = subprocess.Popen([sys.executable, __file__, "--child", "--queue", queue], env={**os.environ, "REDIS_URL": redis_url},
                                stdout=subprocess.PIPE, text=True)
        line = proc.stdout.readline()
        assert '"popped"' in line, f"child did not pop the job: {line!r}"
        assert parent.redis_client.llen(f"{queue}:processing:doomed-worker") == 1
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
        record["kill"] = f"SIGKILL pid {proc.pid} at t+{time.time() - t0:.1f}s while job in processing list"
        # Nothing may recover the job while the lease is still alive
        early = _consumer(redis_url, queue, "early-recoverer").recover_orphans()
        assert early["requeued"] == 0, f"job recovered before lease expiry: {early}"
        record["before_lease_expiry"] = early
        time.sleep(LEASE + 1)

    recoverer = _consumer(redis_url, queue, "replacement-worker", fake_server)
    stats = recoverer.recover_orphans()
    record["recover_orphans"] = stats
    assert stats["requeued"] == 1, f"expected 1 requeued job, got {stats}"
    job = recoverer._pop()
    assert job is not None and job.job_id == "drill-job" and job.attempts == 1, f"bad redelivery: {job}"
    recoverer.ack(job)
    record["redelivered"] = {"job_id": job.job_id, "attempts": job.attempts, "t_plus_s": round(time.time() - t0, 1)}
    # Clean up
    r = recoverer.redis_client
    for k in r.scan_iter(f"{queue}*"):
        r.delete(k)
    record["result"] = "PASS"
    return record


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake", action="store_true", help="self-check on fakeredis (no real process kill)")
    ap.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--queue", default="", help=argparse.SUPPRESS)
    a = ap.parse_args()
    redis_url = os.environ.get("REDIS_URL", "")
    if a.child:
        child_main(redis_url, a.queue)
        return 0
    if not a.fake and not redis_url:
        print("REDIS_URL is not set; run with --fake for a self-check or point REDIS_URL at the deployment's Redis", file=sys.stderr)
        return 2
    try:
        rec = drill(redis_url, a.fake)
    except AssertionError as e:
        print(json.dumps({"result": "FAIL", "reason": str(e)}, indent=2))
        return 1
    print(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
