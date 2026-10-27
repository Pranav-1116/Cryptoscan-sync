#!/usr/bin/env python3
"""Bounded synthetic worker-pool lifecycle witness, NOT a capacity benchmark.

No scanner/tenant/database/Redis/deployment is contacted. Counts observe owned
futures, started jobs, completion callbacks and reclamation across one long-lived
pool. No RSS, throughput, p95/p99 or production-capacity claim is made.
"""
from __future__ import annotations

from _bootstrap import bootstrap

bootstrap()

import argparse
import gc
import json
from pathlib import Path
import threading
import weakref

from worker.core.job_consumer import ScanJob
from worker.core.pool import WorkerPool


def witness(*, batches=24, batch_size=512, workers=2, queue_limit=100):
    if not 1 <= batches <= 100 or not 1 <= batch_size <= 10000 or batches * batch_size > 100000:
        raise ValueError("Use 1–100 batches, 1–10000 jobs/batch and at most 100000 jobs")
    if not 1 <= workers <= 16 or not 0 <= queue_limit <= 1000:
        raise ValueError("Use 1–16 workers and a queue limit of 0–1000")
    expected_jobs = batches * batch_size
    callback_lock = threading.Lock()
    callbacks = succeeded = refused = 0
    sampled_references = []
    observed_bound = 0
    batch_records = []
    pause = threading.Event()

    def handler(descriptor):
        number = int(descriptor.job_id)
        if number % 8 == 0:
            pause.wait(0.001)  # mix immediate and asynchronous completions
        return number % 17 != 0  # explicit synthetic refusal, not a thrown failure

    def completed(future):
        nonlocal callbacks, succeeded, refused
        outcome = future.result()
        with callback_lock:
            callbacks += 1
            succeeded += int(outcome is True)
            refused += int(outcome is False)

    pool = WorkerPool(handler=handler, max_workers=workers, queue_limit=queue_limit)
    try:
        for batch in range(batches):
            for number in range(batch * batch_size, (batch + 1) * batch_size):
                future = pool.submit(ScanJob(job_id=str(number), target_repo="local://synthetic-pool-witness"))
                future.add_done_callback(completed)
                if number % 64 == 0:
                    sampled_references.append(weakref.ref(future))
                del future
                tracked = len(pool.futures)
                observed_bound = max(observed_bound, tracked)
                assert tracked <= workers + queue_limit
            pool.wait()
            gc.collect()
            remaining = len(pool.futures)
            assert remaining <= workers + queue_limit
            batch_records.append({"batch": batch + 1, "completed": pool.stats.completed,
                                  "owned_futures_after_wait": remaining})
    finally:
        pool.shutdown(wait=True)
    gc.collect()
    expected_refusals = (expected_jobs - 1) // 17 + 1
    assert pool.stats.submitted == pool.stats.completed == callbacks == expected_jobs
    assert pool.stats.failed == refused == expected_refusals
    assert succeeded == expected_jobs - expected_refusals
    assert pool.stats.active == 0 and pool.stats.max_active <= workers
    assert not pool.futures
    assert all(reference() is None for reference in sampled_references)
    return {
        "schema": "cryptoscan.worker-pool-lifecycle/1", "result": "PASS",
        "workload": "SYNTHETIC_LOCAL_HANDLERS_NOT_SCANNERS", "batches": batches,
        "batch_size": batch_size, "started_jobs": pool.stats.submitted,
        "completed_jobs": pool.stats.completed, "completion_callbacks": callbacks,
        "synthetic_refusals": refused, "workers": workers, "queue_limit": queue_limit,
        "max_active": pool.stats.max_active, "observed_peak_owned_futures": observed_bound,
        "owned_future_budget": workers + queue_limit, "owned_futures_after_shutdown": len(pool.futures),
        "sampled_futures_reclaimed": len(sampled_references), "batch_observations": batch_records,
        "cleanup": {"pool_shutdown_completed": True, "owned_futures_remaining": 0},
        "limits": ["Not a production scanner, customer workload or bank/deployment acceptance test",
                   "Bookkeeping bound is not an RSS/memory-pressure or process-memory limit",
                   "No throughput, paired 20-percent improvement or p95/p99 qualification",
                   "Local Future cancellation is not SQL job cancellation or durable-budget release"],
        "production_capacity_qualified": False, "bank_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--batches", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--queue-limit", type=int, default=100)
    args = parser.parse_args()
    try:
        report = witness(batches=args.batches, batch_size=args.batch_size,
                         workers=args.workers, queue_limit=args.queue_limit)
    except ValueError as exc:
        parser.error(str(exc))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {report['completed_jobs']} synthetic jobs, {report['completion_callbacks']} terminal callbacks, "
          f"{report['owned_futures_after_shutdown']} futures retained after shutdown; not a capacity benchmark.")


if __name__ == "__main__":
    main()
