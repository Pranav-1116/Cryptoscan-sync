"""External operator harness: stages public source, launches guarded real collector."""

import os
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from tools.banking_sandbox.common import open_estate, dump, file_hash
from tools.banking_sandbox.validator import score_static, integrity

ROOT = Path(__file__).resolve().parents[2]


def run_static(root, output, timeout=600):
    root, meta = open_estate(root)
    integrity(root)
    output = Path(output)
    if output.exists():
        raise ValueError("fresh result directory required")
    if output.resolve().is_relative_to(root / "public"):
        raise ValueError("results cannot contaminate scanner inputs")
    stage = root / "scanner-inputs"
    if stage.exists():
        raise ValueError("one staged run per generated estate; create a fresh copy for another run")
    stage.mkdir(mode=0o700)
    (stage / "SYNTHETIC-LAB.txt").write_text("SYNTHETIC LAB SCAN INPUTS ONLY\n")
    shutil.copytree(root / "public/source", stage / "source", symlinks=False)
    # This sentinel is ONLY a boundary proof, contains no expected result.
    (root / "control/ground_truth/ORACLE-SENTINEL.txt").write_text("FORBIDDEN TO COLLECTOR\n")
    output.mkdir(parents=True, mode=0o700)
    start = time.monotonic()
    failure = None
    with (output / "findings.jsonl").open("xb") as stdout, (output / "collector.log").open("xb") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("scan_child.py")), "--stage", str(stage)],
            stdout=stdout,
            stderr=stderr,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "HOME": "/nonexistent",
            },
        )
        try:
            code = process.wait(timeout=timeout)
            if code:
                failure = "COLLECTOR_EXIT_" + str(code)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            failure = "COLLECTOR_TIMEOUT"
    summaries = []
    for line in (output / "collector.log").read_text().splitlines():
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "summary" in obj:
                    summaries.append(obj["summary"])
            except ValueError:
                pass
    summary = summaries[-1] if summaries else None
    metrics = {
        "mode": "static",
        "collector": "scanner.registry.language_scanners.scan_file",
        "core_modified_for_test": False,
        "collector_source_sha256": file_hash(ROOT / "services/scanner/scanner/registry/language_scanners.py"),
        "wall_seconds": time.monotonic() - start,
        "failure": failure,
        "network_calls": "DENIED_BY_SECCOMP"
        if summary and summary["guard"].get("socket_creation_denied")
        else "UNKNOWN_BOUNDARY_NOT_CONFIRMED",
        "boundary_receipt": summary,
        "queue_time_seconds": None,
        "database_bytes": None,
        "api_latency_ms": None,
        "cbom_generation_seconds": None,
        "correlation_seconds": None,
        "runtime_collection_throughput": None,
        "network_scan_throughput": None,
        "unknown_reason": "NOT_EXERCISED_IN_THIS_OFFLINE_STATIC_RUN",
        "synthetic": True,
    }
    if failure is None:
        score = score_static(root, output / "findings.jsonl")
        dump(output / "accuracy.json", score)
        metrics["files"] = score["files"]
        metrics["failure_rate"] = score["failure_rate"]
        metrics["worker_files_per_second"] = score["files"] / metrics["wall_seconds"]
    dump(output / "metrics.json", metrics)
    return metrics
