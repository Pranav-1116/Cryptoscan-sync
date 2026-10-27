#!/usr/bin/env python3
"""Repeatable disposable SQL/operator read workload; NEVER deployment capacity.

No credentials, network, scans or production DB access. Synthetic dataset lives
in a temporary directory and is removed. Report includes exact shape/iterations,
observed process resource limits, query timings, estate logical retention growth
and before/after index measurements. No extrapolation or self-issued SLOs.
"""
from _bootstrap import bootstrap
bootstrap()
import argparse
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import tempfile
import time
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from db.models.base import Base, utcnow
from db.models.scan_job import ScanJob
from db.models.remediation_task import RemediationTask
from db.tenancy import tenant_scope
from api.assurance.operator import inbox
from observability.workload import measure

INDEXES = {
    "scan_jobs": ("ix_scan_jobs_estate_page", "tenant_id, created_at, id"),
    "remediation_tasks": ("ix_remediation_tasks_estate_page", "tenant_id, created_at, id"),
}


def trial(engine, estates, iterations):
    latencies, queries, payloads, errors = [], [], [], 0
    with Session(engine) as db, measure(engine) as meter:
        meter.transition("operator_sql_reads")
        for n in range(iterations):
            owner = f"synthetic-{n % estates}"
            try:
                with tenant_scope(owner):
                    started = time.perf_counter()
                    result = inbox(db, owner, (n // estates % 4) * 25, 25)
                    latencies.append((time.perf_counter() - started) * 1000)
                    payloads.append(len(json.dumps(result).encode()))
            except Exception:
                errors += 1
                raise
        meter.transition("done", final=True)
        queries.append(meter.report())
    ordered = sorted(latencies)
    return {"requests": iterations, "errors": errors, "median_ms": statistics.median(latencies),
            "p95_ms": ordered[max(0, int(len(ordered) * .95 + .9999) - 1)],
            "response_bytes_mean": statistics.mean(payloads), "measurements": queries[0]}


def run(estates=3, rows=1000, iterations=30):
    with tempfile.TemporaryDirectory(prefix="cryptoscan-workload-") as directory:
        path = Path(directory) / "workload.sqlite"
        engine = create_engine("sqlite:///" + str(path))
        Base.metadata.create_all(engine)
        # Measure the same schema without the two candidate page indexes first.
        with engine.begin() as conn:
            for _, (name, _) in INDEXES.items():
                conn.execute(text(f"DROP INDEX IF EXISTS {name}"))
        baseline = path.stat().st_size
        logical = []
        with Session(engine) as db:
            for estate in range(estates):
                owner = f"synthetic-{estate}"
                payload_bytes = 0
                with tenant_scope(owner):
                    for i in range(rows):
                        finding = {"algorithm": "MD5", "file_path": f"src/file-{i}.py", "line_number": 1, "compliance_status": "FAIL"}
                        payload_bytes += len(json.dumps(finding, separators=(",", ":")).encode())
                        db.add(RemediationTask(tenant_id=owner, evidence_id=f"fixture-evidence-{i}", scan_id="fixture-scan",
                            rule_id="replace-md5", owner="synthetic-owner", status="ACCEPTED", priority="P1", original_finding=finding,
                            target_location="/synthetic/only", created_by="workload", created_at=utcnow() - timedelta(seconds=i)))
                        db.add(ScanJob(tenant_id=owner, target_repo="/synthetic/only", triggered_by="workload",
                            status=["UNKNOWN", "FAILED", "QUEUED", "RUNNING", "DEFERRED"][(i // 10) % 5] if i % 10 == 0 else "COMPLETED",
                            created_at=utcnow() - timedelta(seconds=i)))
                    db.commit()
                logical.append({"estate": owner, "tasks": rows, "jobs": rows,
                    "finding_json_bytes": payload_bytes, "basis": "Synthetic logical finding JSON only; excludes row/index/WAL/blob overhead"})
        seeded = path.stat().st_size
        before = trial(engine, estates, iterations)
        with engine.begin() as conn:
            for table, (name, columns) in INDEXES.items():
                conn.execute(text(f"CREATE INDEX {name} ON {table} ({columns})"))
            conn.execute(text("ANALYZE"))
        after = trial(engine, estates, iterations)
        plans = {}
        with engine.connect() as conn:
            for table in INDEXES:
                condition = " AND status IN ('FAILED', 'UNKNOWN', 'QUEUED', 'RUNNING', 'DEFERRED')" if table == "scan_jobs" else ""
                plans[table] = [list(row) for row in conn.execute(text(f"EXPLAIN QUERY PLAN SELECT * FROM {table} WHERE tenant_id=:owner{condition} ORDER BY created_at DESC, id DESC LIMIT 26"), {"owner": "synthetic-0"})]
        final = path.stat().st_size
        engine.dispose()
        return {"schema": "cryptoscan.operator-workload/1", "created_at": utcnow().isoformat(),
            "runtime": {"python": platform.python_version(), "platform": platform.platform(), "sqlalchemy_backend": "sqlite-disposable"},
            "shape": {"estates": estates, "tasks_per_estate": rows, "jobs_per_estate": rows, "iterations_per_phase": iterations,
                      "job_mix": "90% completed, 10% attention states", "page_size": 25, "offsets": [0, 25, 50, 75]},
            "before_page_indexes": before, "after_page_indexes": after, "query_plans": plans,
            "storage": {"empty_db_bytes": baseline, "seeded_db_bytes": seeded, "indexed_db_bytes": final,
                        "per_estate": logical, "retention_delete_exercised": False},
            "not_measured": ["PostgreSQL/HA/pool contention", "provider HTTP throttling", "Redis replay contention/fault recovery",
                "parser/container resources", "long-running real browser", "production retention deletion/physical per-estate allocation"],
            "capacity_qualified": False, "acceptance": "LOCAL_MEASUREMENT_ONLY_NOT_BANK_CAPACITY"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estates", type=int, default=3)
    parser.add_argument("--rows", type=int, default=1000)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.estates <= 20 or not 25 <= args.rows <= 20000 or not 4 <= args.iterations <= 1000:
        parser.error("bounded workload: estates 1..20, rows 25..20000, iterations 4..1000")
    if args.out.exists():
        parser.error("report exists; choose a new filename to retain prior evidence")
    result = run(args.estates, args.rows, args.iterations)
    data = (json.dumps(result, indent=2, allow_nan=False) + "\n").encode()
    with args.out.open("xb") as stream:
        os.chmod(args.out, 0o600); stream.write(data)
    print(json.dumps({"report": str(args.out), "sha256": hashlib.sha256(data).hexdigest(), "capacity_qualified": False}))


if __name__ == "__main__":
    main()
