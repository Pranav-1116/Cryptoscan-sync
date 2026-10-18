"""Source-parser container boundary. Admission/cloning remain worker operations.

No shell, no Docker socket/credentials mounted into the scanner, no fallback on
runtime failure. A configured immutable image is a deployment prerequisite, not
something this module builds, pulls or publishes on an operator's behalf.
"""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path


_MAX_OUTPUT = 32 * 1024 * 1024


class StaticScanIsolationError(RuntimeError):
    """The requested parser boundary could not complete; no findings accepted."""


def _configuration():
    from worker.config.settings import get_settings

    try:
        return get_settings()
    except ValueError:
        raise StaticScanIsolationError("invalid scanner configuration or timeout") from None


def execution_mode(config=None) -> str:
    config = config or _configuration()
    production = config.ENVIRONMENT.strip().lower() == "production"
    mode = (config.CRYPTOSCAN_STATIC_SCAN_MODE or ("container" if production else "inline")).strip().lower()
    if mode not in {"inline", "container"}:
        raise StaticScanIsolationError("CRYPTOSCAN_STATIC_SCAN_MODE must be inline or container")
    if production and mode != "container":
        raise StaticScanIsolationError("production source parsing requires container isolation")
    return mode


def _budget(config=None) -> float:
    config = config or _configuration()
    try:
        value = float(config.CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S)
    except ValueError:
        raise StaticScanIsolationError("invalid static scan timeout") from None
    if not math.isfinite(value) or not 1 <= value <= 3600:
        raise StaticScanIsolationError("static scan timeout must be finite and between 1 and 3600 seconds")
    return value


def _kill(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _exchange(command: list[str], request: dict, *, timeout: float, limit: int = _MAX_OUTPUT) -> bytes:
    """Bound stdin, stdout, stderr and wall clock, including blocked CLI I/O.

    Nonblocking pipe multiplexing avoids unbounded communicate() buffering,
    reader-thread shutdown races and a blocked stdin write bypassing timeout.
    """
    payload = json.dumps(request, allow_nan=False).encode()
    if len(payload) > 65536:
        raise StaticScanIsolationError("scanner request exceeds the protocol limit")
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, close_fds=True, bufsize=0)
    selector = selectors.DefaultSelector()
    output = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    pending = memoryview(payload)
    deadline = time.monotonic() + timeout
    try:
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StaticScanIsolationError("static parser exceeded its wall-clock budget")
            for key, _mask in selector.select(timeout=min(remaining, 0.1)):
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        pending = pending[os.write(stream.fileno(), pending):]
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                counts[key.data] += len(chunk)
                cap = limit if key.data == "stdout" else 256 * 1024
                if counts[key.data] > cap:
                    raise StaticScanIsolationError("static parser output exceeded the protocol limit")
                if key.data == "stdout":
                    output.extend(chunk)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        if process.returncode != 0:
            raise StaticScanIsolationError(f"static parser runtime failed (exit {process.returncode}); no findings accepted")
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise StaticScanIsolationError("static parser exceeded its wall-clock budget") from None
    except OSError:
        raise StaticScanIsolationError("could not communicate with static parser runtime") from None
    finally:
        _kill(process)
        selector.close()
        for name in ("stdin", "stdout", "stderr"):
            getattr(process, name).close()


def scan_static(*, root_path, exclude_test_dirs=False, **metadata):
    """Run source parsing under the environment's explicit execution policy."""
    from scanner.models.scan_result import ScanResult, ScanTarget

    config = _configuration()
    if execution_mode(config) == "inline":
        from scanner.core.scanner import Scanner

        result = Scanner(exclude_test_dirs=exclude_test_dirs).scan(root_path=root_path, **metadata)
        result.isolation = {"mode": "inline", "isolated": False}
        return result

    if os.name != "posix":
        raise StaticScanIsolationError("container scan launcher requires a POSIX worker")
    image = config.CRYPTOSCAN_SCANNER_IMAGE.strip()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}", image):
        raise StaticScanIsolationError("CRYPTOSCAN_SCANNER_IMAGE must be an immutable image@sha256:digest")
    runtime = shutil.which("docker")
    if runtime is None:
        raise StaticScanIsolationError("Docker runtime unavailable; source parser was not started")
    root = Path(root_path).resolve(strict=True)
    # --mount uses a comma-separated grammar. Never reinterpret a source path
    # containing mount options; fail rather than mount an unintended location.
    if not root.is_dir() or any(char in str(root) for char in (",", "\n", "\r")):
        raise StaticScanIsolationError("source directory is invalid for a read-only bind mount")
    git_path = root / ".git"
    if git_path.is_symlink() or (git_path.exists() and not git_path.is_dir()):
        raise StaticScanIsolationError("linked or non-directory Git metadata is not an admitted parser input")
    # A clone's remote URL/config may retain worker-supplied authentication.
    # Mask it instead of trusting an instruction that tells a parser not to
    # read it. Metadata is reattached by the credentialed parent afterwards.
    git_mask = ["--tmpfs", "/scan/.git:ro,noexec,nosuid,nodev,size=1m,mode=000"] if git_path.is_dir() else []
    timeout = _budget(config)
    name = f"cryptoscan-static-{uuid.uuid4().hex}"
    command = [runtime, "run", "--rm", "--init", "--pull=never", "--name", name,
               "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--user=10001:10001", "--pids-limit=64", "--memory=1g", "--memory-swap=1g", "--cpus=1",
               "--ulimit", "nofile=256:256", "--ulimit", "core=0:0",
               "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
               "--mount", f"type=bind,src={root},dst=/scan,readonly,bind-recursive=disabled",
               *git_mask, "--workdir=/tmp", "--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1",
               "--env=CRYPTOSCAN_SCAN_PROCESSES=1", "--env=GIT_CONFIG_NOSYSTEM=1",
               "--env=GIT_CONFIG_GLOBAL=/dev/null", "--entrypoint=python", "-i", image,
               "-I", "-m", "scanner.isolated"]
    # Deliberately no URLs, credentials, branch names, arbitrary paths, worker
    # environment, database sessions or pickle-encoded objects in this protocol.
    nonce = secrets.token_hex(32)
    marker = root / f".cryptoscan-scan-{uuid.uuid4().hex}"
    # The daemon may live outside the worker's filesystem namespace. A unique
    # marker proves that /scan is THIS staged checkout, not another host path
    # with the same name. Never ask Docker to auto-create a missing source.
    try:
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
        os.fchmod(fd, 0o444)
        with os.fdopen(fd, "w") as stream:
            stream.write(nonce)
    except OSError:
        marker.unlink(missing_ok=True)
        raise StaticScanIsolationError("could not bind scanner input to the admitted checkout") from None
    request = {"schema": "cryptoscan.static-parser/1", "scan_id": metadata.get("scan_id") or str(uuid.uuid4()),
               "exclude_test_dirs": bool(exclude_test_dirs), "timeout_s": timeout,
               "source_marker": marker.name, "source_token": nonce}
    try:
        raw = _exchange(command, request, timeout=timeout + 5)
        envelope = json.loads(raw)
        if envelope.get("schema") != request["schema"]:
            raise ValueError("wrong protocol")
        expected_checks = {"non_root", "no_new_privileges", "capabilities_dropped", "seccomp_filter",
                           "root_read_only", "input_read_only", "network_interfaces_only_loopback", "git_metadata_hidden"}
        checks = envelope.get("runtime_checks", {})
        if set(checks) != expected_checks or any(value is not True for value in checks.values()):
            raise ValueError("runtime policy not verified")
        result = ScanResult.model_validate(envelope["result"])
        if result.status != "COMPLETED" or result.scan_id != request["scan_id"]:
            raise ValueError("scan identity or status mismatch")
        result.scan_target = ScanTarget(type=metadata.get("target_type", "LOCAL_DIRECTORY"),
                                        location=metadata.get("target_location", str(root_path)),
                                        commit=metadata.get("target_commit"), branch=metadata.get("target_branch"))
        from scanner.models.raw_finding import GitContext

        for finding in result.findings:
            # /scan has no readable Git database. Never persist its placeholder
            # "unknown" metadata or let a child override parent-owned identity.
            finding.git_context = GitContext(commit_hash=metadata.get("target_commit"),
                                             branch=metadata.get("target_branch"),
                                             repository_url=metadata.get("target_location"))
        # This records the launcher policy, not a claim of independently audited
        # container execution or complete isolation of the entire pipeline.
        result.isolation = {"mode": "container", "isolated": True, "image": image,
                            "network": "none", "input": "read-only", "timeout_s": timeout,
                            "scope": "static-source-parser-only", "runtime_checks": checks}
        return result
    except BaseException as exc:
        # --rm handles success. On any failure/cancellation explicitly stop the
        # daemon-side workload; killing only the CLI can leave a scanner alive.
        try:
            cleanup = subprocess.run([runtime, "rm", "--force", name], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=10, check=False)
            if cleanup.returncode != 0:
                # --rm may already have removed a failed/exited container.
                # A successful empty daemon listing confirms absence; a daemon
                # connection error does not. Never confuse these two outcomes.
                remaining = subprocess.run([runtime, "ps", "--all", "--quiet", "--filter", f"name=^/{name}$"],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           timeout=10, check=False)
                if remaining.returncode != 0 or remaining.stdout.strip():
                    raise StaticScanIsolationError("scanner failed; container cleanup could not be confirmed")
        except (OSError, subprocess.TimeoutExpired):
            raise StaticScanIsolationError("scanner failed; container cleanup could not be confirmed") from None
        if isinstance(exc, StaticScanIsolationError):
            raise
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise StaticScanIsolationError("scanner runtime returned an invalid or unavailable result") from None
    finally:
        marker.unlink(missing_ok=True)
