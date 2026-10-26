#!/usr/bin/env python3
"""Build and qualify a disposable diskless Linux VM, NEVER a parent interface."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from _bootstrap import bootstrap

bootstrap()
from tools.disposable_tbf import build as builder
from tools.disposable_tbf.contracts import Scope, RunReceipt
from tools.disposable_tbf.runner import digest, ordinary_parent, qualify, strict_json, verify_bundle, parse_capture


def exclusive(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    for name in ("cache", "work", "output"):
        build.add_argument("--" + name, required=True, type=Path)
    assemble = commands.add_parser("assemble")
    for name in ("kernel", "config", "qemu-root", "loader", "output"):
        assemble.add_argument("--" + name, required=True, type=Path)
    scope = commands.add_parser("scope")
    scope.add_argument("--bundle", required=True, type=Path)
    scope.add_argument("--expected-bundle-sha256", required=True)
    scope.add_argument("--target-label", required=True)
    scope.add_argument("--output", required=True, type=Path)
    run = commands.add_parser("run")
    run.add_argument("--bundle", required=True, type=Path)
    run.add_argument("--scope", required=True, type=Path)
    run.add_argument("--expected-scope-sha256", required=True)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--acknowledge-disposable-vm-only", required=True, action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("build", "assemble"):
            ordinary_parent()
            if args.command == "build":
                value = builder.build(args.cache.resolve(), args.work.resolve(), args.output.resolve())
            else:
                value = builder.assemble(
                    args.output.resolve(),
                    args.kernel.resolve(),
                    args.config.resolve(),
                    args.qemu_root.resolve(),
                    args.loader.resolve(),
                )
            print("BUNDLE_SHA256=" + value)
            return 0
        if args.command == "scope":
            ordinary_parent()
            verify_bundle(args.bundle, args.expected_bundle_sha256)
            now = datetime.now(timezone.utc)
            value = Scope(
                target_label=args.target_label,
                nonce=secrets.token_hex(32),
                bundle_sha256=args.expected_bundle_sha256,
                issued_at=now,
                expires_at=now + timedelta(minutes=10),
            )
            exclusive(args.output, value.model_dump(mode="json"))
            print("SCOPE_SHA256=" + digest(value))
            return 0
        if args.command == "run":
            if args.scope.stat().st_size > 8192 or args.scope.is_symlink():
                raise ValueError("scope file budget/type")
            raw = args.scope.read_bytes()
            strict_json(raw)
            value = qualify(
                args.bundle, Scope.model_validate_json(raw), args.expected_scope_sha256, args.output.resolve()
            )
            print("RESULT_SHA256=" + digest(value))
            print("VERDICT=" + value["verdict"])
            return 0 if value["verdict"] == "VERIFIED_IN_DISPOSABLE_VM" else 2
        if args.input.stat().st_size > 131072 or args.input.is_symlink():
            raise ValueError("result budget/type")
        value = strict_json(args.input.read_bytes())
        if digest(value) != args.expected_sha256 or value.get("failure") is not None or not value.get("guest"):
            raise ValueError("result commitment or successful execution missing")
        receipt = RunReceipt.model_validate_json(json.dumps(value))
        serial = args.input.parent / "serial.log"
        if serial.is_symlink() or serial.stat().st_size > 131072 or builder.sha(serial) != receipt.serial_sha256:
            raise ValueError("serial artifact changed")
        if receipt.verdict != "VERIFIED_IN_DISPOSABLE_VM" or receipt.guest != parse_capture(
            serial.read_bytes(), receipt.scope.nonce
        ):
            raise ValueError("serial/capture qualification closure mismatch")
        print("ENGINEERING_INTEGRITY_VERIFIED_NOT_DEVICE_AUTHENTICITY")
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        print("REFUSED_DISPOSABLE_TBF_OPERATION", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
