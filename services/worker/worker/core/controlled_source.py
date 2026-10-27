"""Bounded, descriptor-relative staging for the local-source/v1 adapter.

No Git invocation, archive extraction, remote acquisition, symlink following or
credential environment forwarding. Parser execution is delegated to the existing
digest-pinned, networkless launcher; container escape qualification is external.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import stat
import time

from db.repositories.execution_control import ExecutionDenied, checkpoint

CHECKPOINT_INTERVAL = 0.25
MAX_FILES = 10000
MAX_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
_SKIP = {".git", ".ssh", ".aws", ".azure", ".kube", "node_modules", ".venv", "__pycache__"}


def preflight():
    from worker.core.static_scan_isolation import _configuration, execution_mode
    import re
    config = _configuration()
    if execution_mode(config) != "container":
        raise ExecutionDenied("Controlled parsing requires the approved container profile")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}", config.CRYPTOSCAN_SCANNER_IMAGE.strip()) or shutil.which("docker") is None:
        raise ExecutionDenied("Pinned isolation runtime is not provisioned")
    # Existence/pull policy, runtime security flags and in-container checks are
    # verified by scan_static. Preflight is not a qualification certificate.


def stage(target, destination):
    from api.security.target_validation import validate_source_target
    raw = target.removeprefix("local://").removeprefix("file://")
    # Recheck confinement at use; an approved pathname is not an open handle.
    validate_source_target(target)
    source = Path(raw)
    if not source.is_absolute() or ".." in source.parts:
        raise ExecutionDenied("Controlled source targets must be absolute")
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    dest = Path(destination)
    total = files = 0
    created = False
    deadline = time.monotonic() + 30
    last_check = float("-inf")

    def check():
        nonlocal last_check
        now = time.monotonic()
        if now >= deadline:
            raise ExecutionDenied("Source staging wall-clock budget exhausted")
        if now - last_check >= CHECKPOINT_INTERVAL:
            checkpoint("staging")
            last_check = now

    def copy_directory(fd, out, depth=0):
        nonlocal total, files
        check()
        if depth > 64:
            raise ExecutionDenied("Source staging depth limit exceeded")
        with os.scandir(fd) as entries:
            for entry in entries:
                copy_entry(fd, out, entry.name, depth)

    def copy_entry(fd, out, name, depth):
        nonlocal total, files
        check()
        if name in _SKIP or name == ".env" or name.startswith(".env."):
            return
        files += 1
        if files > MAX_FILES:
            raise ExecutionDenied("Source staging entry limit exceeded")
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                sub = out / name
                sub.mkdir(mode=0o755)
                sub.chmod(0o755)
                copy_directory(child, sub, depth + 1)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                actual = os.fstat(src)
                if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or actual.st_ino != info.st_ino or actual.st_dev != info.st_dev or actual.st_size > MAX_FILE_BYTES:
                    raise ExecutionDenied("Source file changed or exceeds the staging policy")
                with os.fdopen(src, "rb", closefd=False) as stream, open(out / name, "xb") as output:
                    size = 0
                    while chunk := stream.read(65536):
                        check()
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_FILE_BYTES or total > MAX_BYTES:
                            raise ExecutionDenied("Source staging byte limit exceeded")
                        output.write(chunk)
                os.chmod(out / name, 0o644)
            finally:
                os.close(src)
        else:
            raise ExecutionDenied("Links, devices and special files are not admitted source inputs")

    try:
        # Open EVERY component without following symlinks (not just the leaf).
        for part in source.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = child
        dest.mkdir(mode=0o755, parents=True, exist_ok=False)
        created = True
        dest.chmod(0o755)
        copy_directory(root_fd, dest)
        return str(dest)
    except BaseException:
        # Only a new, private workspace directory may be cleaned here.
        if created and dest.is_dir() and not dest.is_symlink():
            shutil.rmtree(dest)
        raise
    finally:
        os.close(root_fd)


def cleanup_workspace(workspace, base):
    """Unlike legacy best-effort cleanup, failure cannot report success."""
    workspace, base = Path(workspace), Path(base).resolve()
    if workspace.is_symlink():
        raise ExecutionDenied("Controlled workspace cleanup cannot follow a link")
    target = workspace.resolve()
    if target == base or not target.is_relative_to(base):
        raise ExecutionDenied("Controlled cleanup path is outside the private workspace root")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ExecutionDenied("Controlled cleanup requires descriptor-safe removal")
    if workspace.exists():
        shutil.rmtree(workspace)
    if workspace.exists():
        raise ExecutionDenied("Controlled workspace cleanup is unconfirmed")
