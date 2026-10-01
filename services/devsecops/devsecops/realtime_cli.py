"""Realtime DevSecOps binary/SBOM adapter.

This is a thin CLI around the existing bounded binary scanner. It preserves
crypto observations, embedded-key metadata, findings, evidence hashes, and
scanner state for the API's common CBOM/replay path.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from devsecops.binary_scan import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a bounded DevSecOps binary/firmware scan")
    parser.add_argument("target", help="operator-supplied binary, archive, firmware, or directory")
    args = parser.parse_args(argv)
    try:
        result: dict[str, Any] = scan_path(args.target)
        result["scanner"] = "devsecops"
        raw_state = str(result.get("result_state") or "COMPLETE").upper()
        result["scan_status"] = {
            "COMPLETE": "PASS", "PARTIAL": "DEGRADED", "REFUSED": "BLOCKED",
        }.get(raw_state, raw_state if raw_state in {"FAIL", "BLOCKED", "SKIP"} else "DEGRADED")
        print(json.dumps(result, sort_keys=True, default=str))
        return 0 if result["scan_status"] in {"PASS", "DEGRADED"} else 2
    except Exception as exc:  # noqa: BLE001 — one artifact must not become success
        print(json.dumps({
            "scanner": "devsecops", "scan_status": "FAIL", "findings": [],
            "error": f"DevSecOps binary scan failed: {exc}",
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
