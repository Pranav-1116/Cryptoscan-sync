"""Normal CryptoScan source collector, no truth/expected-results inputs."""

import argparse
import contextlib
import importlib
import json
from pathlib import Path
import resource
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.banking_sandbox.boundary import apply


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage", type=Path, required=True)
    p.add_argument("--mode", choices=("static", "lb-config"), default="static")
    args = p.parse_args()
    stage = args.stage.resolve(strict=True)
    if stage.name != "scanner-inputs" or not (stage / "SYNTHETIC-LAB.txt").is_file():
        raise ValueError("staged synthetic inputs required")
    allowed = [
        stage,
        ROOT / "services/scanner/scanner",
        ROOT / ".venv",
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/dev/null"),
    ]
    # The harness code directory, product test corpus and control/oracle directories
    # are deliberately NOT granted. Imports already loaded before confinement.
    sys.path.insert(0, str(ROOT / "services/scanner"))
    importlib.import_module("scanner")  # establish package path before confinement

    guard = apply([x for x in allowed if x.exists()])
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        guard["socket_creation_denied"] = True
    else:
        raise ValueError("network denial proof failed")
    try:
        (stage.parent / "control/ground_truth/ORACLE-SENTINEL.txt").read_bytes()
    except PermissionError:
        guard["oracle_read_denied"] = True
    else:
        raise ValueError("oracle read proof failed")
    sys.path.insert(0, str(ROOT / "services/scanner"))
    with contextlib.redirect_stdout(sys.stderr):
        from scanner.registry.language_scanners import scan_file
        from scanner.core.sandbox import per_file_timeout

    start = time.monotonic()
    files = errors = 0
    source_extensions = {
        ".py",
        ".java",
        ".kt",
        ".c",
        ".cpp",
        ".cs",
        ".go",
        ".rs",
        ".js",
        ".ts",
        ".php",
        ".rb",
        ".cbl",
        ".config",
    }
    if args.mode == "lb-config":
        source_extensions = {".conf", ".cfg", ".yaml", ".json"}
    for path in sorted((stage / "source").rglob("*")):
        if path.suffix not in source_extensions or not path.is_file():
            continue
        files += 1
        try:
            with contextlib.redirect_stdout(sys.stderr), per_file_timeout(2):
                findings = scan_file(path, stage)
            row = {
                "evidence_type": "STATIC_OBSERVED",
                "semantic_scope": "CONFIGURATION_NOT_NEGOTIATION" if args.mode == "lb-config" else "SOURCE_NOT_RUNTIME",
                "source_file": str(path.relative_to(stage)),
                "status": "COMPLETE",
                "algorithms": sorted({f.crypto.algorithm for f in findings if f.crypto.algorithm}),
                "raw_findings": [f.model_dump(mode="json") for f in findings],
            }
        except Exception as exc:
            errors += 1
            row = {
                "source_file": str(path.relative_to(stage)),
                "status": "FAILED",
                "algorithms": [],
                "error_type": type(exc).__name__,
                "reason": str(exc)[:200],
            }
        print(json.dumps(row, sort_keys=True, allow_nan=False), flush=True)
    print(
        json.dumps(
            {
                "summary": {
                    "files": files,
                    "errors": errors,
                    "wall_seconds": time.monotonic() - start,
                    "cpu_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_utime
                    + resource.getrusage(resource.RUSAGE_SELF).ru_stime,
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "guard": guard,
                }
            }
        ),
        file=sys.stderr,
        flush=True,
    )


if __name__ == "__main__":
    main()
