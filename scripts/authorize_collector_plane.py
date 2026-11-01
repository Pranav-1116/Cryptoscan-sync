#!/usr/bin/env python3
"""Approve collector authority for this deployment — one row per plane.

A plane with no approval collects nothing: the gate refuses it with
``NO_APPROVAL`` rather than defaulting to "surely someone approved this". This
script is the deliberate act that creates those approvals, so that turning a
collector on is a decision with an owner and an expiry instead of a side effect
of deploying the code.

    # what would be approved, changing nothing
    python scripts/authorize_collector_plane.py --dry-run --approver ciso@bank

    # approve every plane for 90 days
    python scripts/authorize_collector_plane.py --approver ciso@bank

    # one plane only, with a shorter window and a smaller budget
    python scripts/authorize_collector_plane.py --plane NETWORK --valid-days 14 \
        --max-requests 20 --approver network-ops@bank

Re-running bumps the revision, which is what makes an earlier revision stale: a
collection that names the old revision is refused, so re-approving is how a bank
withdraws an authority it no longer wants anyone to use.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in ("services/api", "services/database", "shared/shared_models",
                 "shared/shared_config", "services/runtime", "services/evidence",
                 "services/worker", "services/observability"):
    candidate = str(ROOT / relative)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--approver", required=True,
                        help="who is signing this approval (recorded verbatim)")
    parser.add_argument("--plane", action="append", default=None,
                        help="approve only this plane (repeatable); default: every plane")
    parser.add_argument("--valid-days", type=int, default=90)
    parser.add_argument("--max-requests", type=int, default=None)
    parser.add_argument("--max-runtime-seconds", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true", help="report, write nothing")
    parser.add_argument("--json", help="write the resulting approvals here")
    args = parser.parse_args(argv)

    from api.security import collector_authority as authority
    from db.connection.session import SessionLocal
    from db.tenancy import platform_scope

    planes = [plane.upper() for plane in (args.plane or authority.PLANES)]
    unknown = [plane for plane in planes if plane not in authority.PLANE_SPECS]
    if unknown:
        parser.error(f"unknown plane(s) {', '.join(sorted(unknown))}; "
                     f"expected a subset of {', '.join(authority.PLANES)}")

    written: list[dict] = []
    session = SessionLocal()
    try:
        with platform_scope():
            for plane in planes:
                spec = authority.PLANE_SPECS[plane]
                if args.dry_run:
                    written.append({"plane": plane, "permission": spec.permission,
                                    "entry": spec.entry,
                                    "expires_in_days": args.valid_days,
                                    "dry_run": True})
                    continue
                row = authority.approve(
                    session, plane=plane, approver=args.approver,
                    valid_days=args.valid_days, max_requests=args.max_requests,
                    max_runtime_seconds=args.max_runtime_seconds,
                )
                written.append({
                    "plane": row.plane, "revision": row.revision,
                    "permission": row.permission, "entry": row.entry,
                    "approved_by": row.approved_by,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                    "max_requests": row.max_requests,
                    "max_runtime_seconds": row.max_runtime_seconds,
                })
    except authority.AuthorityRefused as exc:
        print(json.dumps({"refused": exc.code, "reason": exc.detail}, indent=2),
              file=sys.stderr)
        return 1
    finally:
        session.close()

    payload = {"approver": args.approver, "dry_run": args.dry_run,
               "planes": len(written), "approvals": written}
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
