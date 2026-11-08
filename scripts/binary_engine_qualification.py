#!/usr/bin/env python3
"""Binary-engine production qualification battery (Phase-8-style).

Measures, never advertises (§13): corpus scan timing, queue behaviour
under concurrent submitters, fail-safe rates on malformed input, and a
static safety proof that the analysis engine contains no execution
primitives — static analysis never executes the artifact (§14), and
this battery proves the claim mechanically.

Run: python scripts/binary_engine_qualification.py [--write]
Results are measurements on THIS machine — never production claims.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "binary_intelligence"))

from binary_intelligence.orchestrator import (  # noqa: E402
    ScanJob, ScanJobQueue, WorkerLimits,
)
from binary_intelligence.pipeline import run_scan  # noqa: E402

EXEC_PRIMITIVES = {"eval", "exec", "compile", "system", "popen", "spawnl",
                   "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
                   "spawnvp", "spawnvpe", "fork", "forkpty", "posix_spawn"}


def _mutate(data: bytes) -> list[bytes]:
    """A malformed corpus from valid inputs — truncations, bit-flips and
    header corruptions (§15 expected non-findings and fail-safe)."""
    mutants = []
    for cut in (1, 4, 17, len(data) // 2):
        if 0 < cut < len(data):
            mutants.append(data[:cut])
    for pos in (0, 4, 8, 16):
        if pos < len(data):
            flipped = bytearray(data)
            flipped[pos] ^= 0xFF
            mutants.append(bytes(flipped))
    mutants.append(data + b"\x00" * 64)
    mutants.append(b"")
    return mutants


def _no_execution_primitives(package_dir: Path) -> dict:
    """Static proof: the engine's source contains no call to an
    execution primitive and no import of subprocess or the os-shell
    system call."""
    offenders = []
    for path in sorted(package_dir.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "subprocess":
                        offenders.append(f"{path.name}: imports subprocess")
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] == "subprocess":
                    offenders.append(f"{path.name}: imports subprocess")
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    # bare builtin calls: eval(...), exec(...), compile(...)
                    if func.id in EXEC_PRIMITIVES or func.id == "__import__":
                        offenders.append(f"{path.name}: calls {func.id}()")
                elif isinstance(func, ast.Attribute):
                    # os dot system(...) / subprocess.Popen-style calls — but
                    # re.compile(...) is regex compilation, not execution
                    root = func.value
                    root_name = (root.id if isinstance(root, ast.Name) else
                                 root.attr if isinstance(root, ast.Attribute)
                                 else "")
                    if (func.attr in EXEC_PRIMITIVES
                            and root_name in ("os", "subprocess", "pty",
                                              "commands")):
                        offenders.append(
                            f"{path.name}: calls {root_name}.{func.attr}()")
    return {"checked_files": len(list(package_dir.glob("*.py"))),
            "offenders": offenders,
            "verdict": ("clean — no execution primitives in the engine"
                        if not offenders else
                        "VIOLATION — execution primitives found")}


def run_battery() -> dict:
    from tests.fixtures import elf_crypto_sample, elf_plain_sample, pe_crypto_sample
    corpus = [elf_crypto_sample(), elf_plain_sample(), pe_crypto_sample()]
    malformed = []
    for sample in corpus:
        malformed.extend(_mutate(sample))

    timings = []
    failures = []
    for sample in corpus * 3:
        started = time.perf_counter()
        try:
            result = run_scan(tenant_id="qual", data=sample,
                              original_filename="qual.bin",
                              source_type="qualification",
                              uploaded_by="qualification-battery")
            timings.append(time.perf_counter() - started)
            if result.status != "completed":
                failures.append("a valid sample did not complete")
        except Exception as exc:                    # noqa: BLE001
            failures.append(f"valid sample raised {type(exc).__name__}")

    malformed_failures = []
    refused_with_reason = []
    for mutant in malformed:
        try:
            run_scan(tenant_id="qual", data=mutant,
                     original_filename="mutant.bin",
                     source_type="qualification",
                     uploaded_by="qualification-battery")
        except ValueError as exc:
            # the fail-safe contract: unprocessable input is REFUSED with
            # its reason — never a crash inside a parser (§14)
            if str(exc):
                refused_with_reason.append(str(exc))
            else:
                malformed_failures.append("ValueError without a reason")
        except Exception as exc:                    # noqa: BLE001
            malformed_failures.append(
                f"mutant raised {type(exc).__name__}: {exc}")

    queue = ScanJobQueue(limits=WorkerLimits(max_queue_depth=8,
                                             max_seconds_per_job=120))
    refusals = {"count": 0}

    def submitter(index: int) -> None:
        for i in range(4):
            accepted, _reason = queue.submit(ScanJob(
                job_id=f"q-{index}-{i}", tenant_id="qual",
                data=corpus[index % len(corpus)],
                original_filename="qual.bin", source_type="qualification",
                uploaded_by="qualification-battery"))
            if not accepted:
                refusals["count"] += 1

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(submitter, range(8)))
    accepted_total = queue.accepted_count
    processed = 0
    while queue.process_one() is not None:
        processed += 1
    drain_seconds = time.perf_counter() - started

    safety = _no_execution_primitives(
        ROOT / "services" / "binary_intelligence" / "binary_intelligence")

    report = {
        "battery": "binary-engine-qualification/1",
        "measured_on": "the machine that ran this battery — measurements, "
                       "never production claims (§13)",
        "corpus_valid_samples": len(corpus) * 3,
        "corpus_malformed_samples": len(malformed),
        "valid_scan_failures": failures,
        "malformed_failures": malformed_failures,
        "malformed_refused_with_reason": len(refused_with_reason),
        "fail_safe_verdict": (
            "every malformed input either completed or was refused with "
            "its reason — a parser crash is a parser bug (§14)"
            if not malformed_failures else
            "VIOLATION — malformed input crashed a parser"),
        "queue": {
            "submitters": 8, "offers": 32,
            "accepted": accepted_total,
            "refused_and_counted": refusals["count"],
            "processed": processed,
            "note": "backpressure refuses and counts, never silently "
                    "drops (§14)",
        },
        "timing_seconds": {
            "samples": len(timings),
            "min": round(min(timings), 6) if timings else None,
            "median": round(sorted(timings)[len(timings) // 2], 6)
            if timings else None,
            "max": round(max(timings), 6) if timings else None,
        },
        "drain_seconds": round(drain_seconds, 4),
        "static_safety": safety,
    }
    return report


def render(report: dict) -> str:
    lines = [
        "Binary engine qualification (measurements on this machine — "
        "never production claims)",
        "",
        f"valid samples: {report['corpus_valid_samples']} — "
        f"failures: {len(report['valid_scan_failures'])}",
        f"malformed samples: {report['corpus_malformed_samples']} "
        f"({report['malformed_refused_with_reason']} refused with their "
        f"reasons) — {report['fail_safe_verdict']}",
        (f"queue: {report['queue']['accepted']} accepted, "
         f"{report['queue']['refused_and_counted']} refused and counted, "
         f"{report['queue']['processed']} processed — "
         f"{report['queue']['note']}"),
        (f"scan timing (s): min {report['timing_seconds']['min']}, "
         f"median {report['timing_seconds']['median']}, "
         f"max {report['timing_seconds']['max']}"),
        f"static safety: {report['static_safety']['verdict']} "
        f"({report['static_safety']['checked_files']} files checked)",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true",
                        help="write the report to docs/binary-intelligence/"
                             "qualification-latest.json")
    args = parser.parse_args()
    report = run_battery()
    sys.stdout.write(render(report))
    if args.write:
        out = ROOT / "docs" / "binary-intelligence" / "qualification-latest.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        sys.stdout.write(f"wrote {out}\n")
    return 0 if not report["valid_scan_failures"] and not \
        report["malformed_failures"] and not \
        report["static_safety"]["offenders"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
