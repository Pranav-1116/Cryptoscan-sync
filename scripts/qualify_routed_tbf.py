#!/usr/bin/env python3
"""Operator-only routed disposable lab; no real-host apply endpoint."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.disposable_tbf.build import sha
from tools.disposable_tbf.runner import ordinary_parent, strict_json
from tools.routed_tbf import build
from tools.routed_tbf.authority import Authority
from tools.routed_tbf.runner import exclusive, run, verify_receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "assemble"):
        p = sub.add_parser(name)
        p.add_argument("--output", type=Path, required=True)
        if name == "build":
            p.add_argument("--cache", type=Path, required=True)
            p.add_argument("--work", type=Path, required=True)
        else:
            for option in ("kernel", "config", "qemu-root", "loader"):
                p.add_argument("--" + option, type=Path, required=True)
    for name in ("init-authority", "issue", "approve", "revoke", "run"):
        p = sub.add_parser(name)
        p.add_argument("--authority", type=Path, required=True)
        if name in ("init-authority", "issue", "run"):
            p.add_argument("--tenant", default="lab")
            p.add_argument("--device", default="diskless-routed-v1")
        if name in ("issue", "approve", "run"):
            p.add_argument("--output", type=Path, required=True)
        if name in ("issue", "run"):
            p.add_argument("--bundle-sha256", required=True)
        if name in ("approve", "run"):
            p.add_argument("--input", type=Path, required=True)
        if name == "approve":
            p.add_argument("--ack-simulated-reviewer", required=True, action="store_true")
        if name == "run":
            p.add_argument("--bundle", type=Path, required=True)
            p.add_argument("--ack-disposable-vm-only", required=True, action="store_true")
        if name == "revoke":
            p.add_argument("--lease-id", required=True)
    p = sub.add_parser("verify")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--trusted-adapter-public-key", required=True)
    args = parser.parse_args(argv)
    try:
        ordinary_parent()
        if args.command == "build":
            print("BUNDLE_SHA256=" + build.build(args.cache.resolve(), args.work.resolve(), args.output.resolve()))
        elif args.command == "assemble":
            print(
                "BUNDLE_SHA256="
                + build.assemble(
                    args.output.resolve(),
                    args.kernel.resolve(),
                    args.config.resolve(),
                    args.qemu_root.resolve(),
                    args.loader.resolve(),
                )
            )
        elif args.command == "verify":
            print(verify_receipt(args.input, args.expected_sha256, args.trusted_adapter_public_key))
        elif args.command == "init-authority":
            authority = Authority.initialize(args.authority, args.tenant, args.device)
            with authority.transaction() as db:
                print(json.dumps(authority.enrollment(db)[2], sort_keys=True))
        else:
            authority = Authority(args.authority)
            if args.command == "issue":
                value = authority.issue(
                    args.tenant, args.device, args.bundle_sha256, sha(build.HERE / "acceptance.json")
                )
            elif args.command == "approve":
                value = authority.approve(strict_json(args.input.read_bytes()), args.ack_simulated_reviewer)
            elif args.command == "revoke":
                authority.revoke(args.lease_id)
                print("REVOKED")
                return 0
            else:
                value = run(
                    args.bundle,
                    args.bundle_sha256,
                    authority,
                    strict_json(args.input.read_bytes()),
                    args.tenant,
                    args.device,
                    args.output,
                )
                print("RESULT_SHA256=" + sha(args.output / "result.json"))
                print("VERDICT=" + value["payload"]["verdict"])
                return 0 if value["payload"]["verdict"] != "INCONCLUSIVE_OR_FAILED" else 2
            exclusive(args.output, json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print("REFUSED_ROUTED_LAB_OPERATION: " + str(exc), file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
