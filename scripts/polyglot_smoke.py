#!/usr/bin/env python3
"""CI smoke: scan both demo apps and assert known detections.

Used by .github/workflows/scanner-tests.yml. Fails (exit 1) if any expected
algorithm family is missing from the scan results.
"""
from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
from worker.pipeline.pipeline_runner import PipelineRunner  # noqa: E402


def scan(target: str) -> list[dict]:
    runner = PipelineRunner()
    # Bypass the queue: run the pipeline synchronously against the local demo tree.
    scan_id = runner.run(
        job_id=f"smoke-{os.urandom(4).hex()}",
        target_repo=f"local://{target}",
        target_branch="main",
        triggered_by="ci-smoke",
    )
    from db.connection.session import SessionLocal
    from db.models.evidence_record import EvidenceRecord
    from sqlalchemy import select

    with SessionLocal() as session:
        rows = session.execute(
            select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
        ).scalars().all()
        return [
            {
                "algorithm": r.algorithm,
                "file": r.file_path,
                "status": r.compliance_status,
            }
            for r in rows
        ]


def main() -> int:
    from db.connection.session import init_db

    init_db()
    failures: list[str] = []

    vuln = scan("demo/vulnerable-app")
    vuln_algos = {f["algorithm"] for f in vuln}
    print(f"vulnerable-app: {len(vuln)} findings, algorithms={sorted(vuln_algos)}")
    for expected in ("RSA", "AES", "MD5", "DES", "SHA-1"):
        if expected not in vuln_algos:
            failures.append(f"vulnerable-app: expected algorithm {expected} not detected")
    if not any(f["status"] == "FAIL" for f in vuln):
        failures.append("vulnerable-app: expected at least one FAIL policy verdict")

    poly = scan("demo/polyglot-app")
    poly_algos = {f["algorithm"] for f in poly}
    files = {f["file"] for f in poly}
    print(f"polyglot-app: {len(poly)} findings, algorithms={sorted(poly_algos)}")
    for suffix, label in ((".py", "Python"), (".js", "JavaScript"), (".go", "Go"), (".cs", "C#")):
        if not any(fl.endswith(suffix) for fl in files):
            failures.append(f"polyglot-app: no {label} findings (expected {suffix} files)")
    for expected in ("MD5", "AES"):
        if expected not in poly_algos:
            failures.append(f"polyglot-app: expected algorithm {expected} not detected")

    if failures:
        print("\nSMOKE FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPolyglot detection smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
