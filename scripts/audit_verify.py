#!/usr/bin/env python3
"""Scheduled audit-chain verification — integrity is a standing signal.

verify_audit_chain proves or disproves the audit hash chain on demand;
discovery by happenstance is not an integrity program. This runner is the
thing a timer calls on a schedule so a TAMPERED chain surfaces as a
FAILED UNIT on the monitoring board, not at the next audit.

Exit contract (the unit's health depends on it):

    0  chain OK
    1  TAMPERED — the chain does not verify; treat as an incident
    2  the verification itself could not run (fail loud, fail distinct)

    python3 scripts/audit_verify.py               # full chain
    python3 scripts/audit_verify.py --incremental # resume from the last verified point
"""
from __future__ import annotations

import argparse
import json
import sys


def evaluate(verdict: dict) -> tuple[int, dict]:
    """Map a verifier verdict to (exit code, report). Unknown verdicts are
    refusals, never successes — a verifier that cannot say OK has not said
    OK."""
    status = str(verdict.get("status", "")).upper()
    if status == "OK":
        return 0, {"exit": 0, "ok": True, "verdict": verdict}
    if status == "TAMPERED":
        return 1, {"exit": 1, "ok": False,
                   "note": "the audit chain does not verify — treat as an incident",
                   "verdict": verdict}
    return 2, {"exit": 2, "ok": False,
               "note": "verifier could not produce a verdict",
               "verdict": verdict}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--incremental", action="store_true",
                    help="resume from the last verified point instead of "
                         "re-walking the whole chain")
    ap.add_argument("--force-full", action="store_true",
                    help="with --incremental: recompute everything anyway")
    args = ap.parse_args()

    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import (
            verify_audit_chain,
            verify_audit_chain_incremental,
        )

        with SessionLocal() as session:
            if args.incremental:
                verdict = verify_audit_chain_incremental(
                    session, force_full=args.force_full)
            else:
                verdict = verify_audit_chain(session)
    except Exception as exc:  # noqa: BLE001 — an unrunnable check is exit 2
        report = {"exit": 2, "ok": False,
                  "note": "verification could not run",
                  "error": type(exc).__name__}
        print(json.dumps(report, indent=2))
        return 2

    code, report = evaluate(verdict)
    print(json.dumps(report, indent=2, default=str))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
