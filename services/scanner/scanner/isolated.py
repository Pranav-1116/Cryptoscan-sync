"""Fixed-input JSON adapter for the restricted scanner image, not a general CLI.

The worker mounts the admitted checkout at /scan; this protocol cannot request
another path, execute a command or supply environment variables. stdout is JSON
only. Diagnostics stay on stderr and are never reflected into API errors.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import re
import secrets
import stat
import sys
import threading
import time
from pathlib import Path

SCHEMA = "cryptoscan.static-parser/1"


def validate_request(request: dict) -> None:
    fields = {"schema", "scan_id", "exclude_test_dirs", "timeout_s", "source_marker", "source_token"}
    if not isinstance(request, dict) or set(request) not in (fields, fields | {"deadline_unix"}):
        raise ValueError("invalid static parser request fields")
    if request["schema"] != SCHEMA:
        raise ValueError("invalid static parser protocol version")
    if not isinstance(request["scan_id"], str) or not 1 <= len(request["scan_id"]) <= 128:
        raise ValueError("invalid scan identity")
    if type(request["exclude_test_dirs"]) is not bool:
        raise ValueError("exclude_test_dirs must be boolean")
    if not isinstance(request["source_marker"], str) or not re.fullmatch(r"\.cryptoscan-scan-[0-9a-f]{32}", request["source_marker"]):
        raise ValueError("invalid source marker")
    if not isinstance(request["source_token"], str) or not re.fullmatch(r"[0-9a-f]{64}", request["source_token"]):
        raise ValueError("invalid source token")
    budget = request["timeout_s"]
    if type(budget) not in (int, float) or not math.isfinite(budget) or not 1 <= budget <= 3600:
        raise ValueError("invalid parser time budget")
    parser_budget(request)


def parser_budget(request):
    budget = request["timeout_s"]
    if "deadline_unix" in request:
        deadline = request["deadline_unix"]
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= time.time():
            raise ValueError("invalid or expired execution deadline")
        budget = min(budget, deadline - time.time())
        if budget <= 0:
            raise ValueError("execution deadline expired before parser start")
    return budget


def verify_runtime() -> dict:
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    checks = {
        "non_root": os.geteuid() == 10001,
        "no_new_privileges": status.get("NoNewPrivs", "").strip() == "1",
        "capabilities_dropped": int(status.get("CapEff", "1").strip(), 16) == 0,
        "seccomp_filter": status.get("Seccomp", "").strip() == "2",
        "root_read_only": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "input_read_only": bool(os.statvfs("/scan").f_flag & os.ST_RDONLY),
        "git_metadata_hidden": not os.path.lexists("/scan/.git") or (
            not os.access("/scan/.git", os.R_OK) and not os.access("/scan/.git", os.X_OK)),
        "network_interfaces_only_loopback": set(os.listdir("/sys/class/net")) <= {"lo"},
    }
    if not all(checks.values()):
        raise RuntimeError("scanner runtime policy was not applied")
    return checks


def verify_source_types(root: Path) -> None:
    """A read-only bind must not accidentally expose host Unix sockets/devices.

    This metadata-only walk stays INSIDE the bounded parser container, never
    follows symlinks and runs before any detector reads repository content.
    The dispatcher must keep its staged checkout quiescent during parsing.
    """
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if directory == root and entry.name == ".git":
                    continue  # already hidden/verified, not source input
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    pending.append(Path(entry.path))
                elif not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                    raise RuntimeError("special files are not admitted parser inputs")


def scan_request(request: dict) -> dict:
    validate_request(request)
    checks = verify_runtime()
    marker = Path("/scan") / request["source_marker"]
    if marker.is_symlink() or not secrets.compare_digest(marker.read_text(), request["source_token"]):
        raise RuntimeError("mounted input does not match the admitted checkout")
    verify_source_types(Path("/scan"))
    # Every scan, even a one-file scan, is now within this process boundary.
    # Docker supplies memory/CPU/pids/filesystem/network controls; rlimits are
    # additional bounds. Never replace an existing runtime seccomp filter.
    from scanner.core.sandbox import apply_child_limits
    from scanner.core.scanner import Scanner

    apply_child_limits(install_seccomp=False)
    result = Scanner(exclude_test_dirs=request["exclude_test_dirs"]).scan(
        root_path=Path("/scan"), scan_id=request["scan_id"], target_location="/scan")
    return {"schema": SCHEMA, "runtime_checks": checks, "result": result.model_dump(mode="json")}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("static parser request too large")
        request = json.loads(raw)
        validate_request(request)
        # Independent of SIGALRM used by individual detectors. If discovery,
        # constants, cascade or a non-main-thread parser hangs, the container's
        # main process exits even when per-file signal budgets cannot fire.
        watchdog = threading.Timer(parser_budget(request), lambda: os._exit(124))
        watchdog.daemon = True
        watchdog.start()
        try:
            with contextlib.redirect_stdout(sys.stderr):
                import structlog

                structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
                response = scan_request(request)
            encoded = json.dumps(response, allow_nan=False)
            if len(encoded.encode()) > 32 * 1024 * 1024:
                raise ValueError("static parser result too large")
            sys.stdout.write(encoded)
            sys.stdout.flush()
        finally:
            watchdog.cancel()
        return 0
    except Exception:
        # Never print exception strings or source lines into the JSON protocol.
        print("isolated static parser failed; no findings accepted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
