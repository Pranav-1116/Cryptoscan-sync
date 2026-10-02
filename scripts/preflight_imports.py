#!/usr/bin/env python3
"""Check every scanner family's dependencies resolve, before anything runs.

update.md section 1: "the network scanner could not import yaml ... Verify
imports for network scanning, TLS/certificate parsing, cloud SDKs, container
scanning, HSM/payment adapters, telecom scanning, database and Redis
integration ... Ensure optional dependencies fail with structured PREFLIGHT
or UNAVAILABLE output, not raw tracebacks."

That failure is the shape worth designing against: a dependency that is
declared, installed in one environment and absent in another, discovered when
a scan is already running and surfacing as a traceback from somewhere deep in
a parser. The import graph is knowable up front, so check it up front.

The point is the REQUIRED/OPTIONAL split. A missing boto3 means cloud
scanning is unavailable and should say so; a missing cryptography means the
scanner cannot do its job at all. Treating those the same is how an operator
ends up with a green process that silently cannot scan half the estate.

Exit 0 when every required dependency of every family resolves. Optional gaps
are reported as UNAVAILABLE and do not fail the check.

    python scripts/preflight_imports.py
    python scripts/preflight_imports.py --family cloud_scanner
    python scripts/preflight_imports.py --json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone

#: family -> (required, optional). Derived from the real import graph (an AST
#: walk over each service, minus stdlib and first-party), then split by whether
#: the family can do useful work without the module.
FAMILIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "scanner": (
        ("yaml", "pydantic", "pydantic_settings", "structlog", "click"),
        # tree_sitter raises per-language accuracy; the regex parsers still run.
        # git is only needed for repository targets, not a directory scan.
        ("cryptography", "tree_sitter", "git"),
    ),
    "network_scanner": (
        # yaml is the one update.md caught: discovery reads k8s/config YAML.
        ("yaml", "cryptography"),
        ("httpx",),
    ),
    "cloud_scanner": (
        ("yaml",),
        # each SDK gates one provider; absence must disable that provider only
        ("boto3", "azure", "google", "googleapiclient", "httpx"),
    ),
    "container_scanner": ((), ("httpx", "redis")),
    "telecom_scanner": ((), ()),
    "payment_crypto": ((), ()),
    "keyassure": (("cryptography",), ()),
    "devsecops": (("yaml", "cryptography"), ("confluent_kafka", "pika")),
    "worker": (("sqlalchemy", "pydantic_settings"), ("redis",)),
    "api": (
        ("fastapi", "starlette", "uvicorn", "pydantic", "pydantic_settings",
         "sqlalchemy", "cryptography"),
        ("redis", "httpx"),
    ),
    "database": (("sqlalchemy", "alembic"), ("pgserver",)),
}


def _resolves(module: str) -> bool:
    """True when the module can be found without importing it.

    find_spec rather than import: importing pulls in side effects and costs
    seconds for the cloud SDKs, and presence is the question being asked.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        # A namespace package with a broken parent raises rather than
        # returning None; that is still "cannot be used".
        return False


def check(only: str | None = None) -> dict:
    families = {k: v for k, v in FAMILIES.items() if only in (None, k)}
    if not families:
        raise SystemExit(f"unknown family {only!r}; known: {', '.join(sorted(FAMILIES))}")

    results = []
    for family, (required, optional) in sorted(families.items()):
        missing_required = [m for m in required if not _resolves(m)]
        missing_optional = [m for m in optional if not _resolves(m)]
        if missing_required:
            status = "PREFLIGHT_FAIL"
        elif missing_optional:
            status = "DEGRADED"
        else:
            status = "OK"
        results.append({
            "family": family,
            "status": status,
            "missing_required": missing_required,
            "missing_optional": missing_optional,
            "required": list(required),
            "optional": list(optional),
        })

    return {
        "schema": "cryptoscan.preflight-imports/1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "families": results,
        "verdict": "FAIL" if any(r["status"] == "PREFLIGHT_FAIL" for r in results) else "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--family", help="check one family instead of all")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    report = check(args.family)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for row in report["families"]:
            line = f"{row['status']:15s} {row['family']}"
            if row["missing_required"]:
                line += f"  REQUIRED MISSING: {', '.join(row['missing_required'])}"
            if row["missing_optional"]:
                line += f"  unavailable: {', '.join(row['missing_optional'])}"
            print(line)
        print(f"\nPreflight: {report['verdict']} (python {report['python']})")
        if report["verdict"] == "PASS":
            print("DEGRADED means an optional capability is off, not that the "
                  "family is broken -- it must report UNAVAILABLE at runtime, "
                  "not raise.")

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
