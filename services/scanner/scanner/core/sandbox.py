"""Hostile-input sandbox bounds for the static scanner (§4.1).

A hostile repository must not be able to consume unbounded resources on the
worker: catastrophic-regex detectors (CPU) and memory bombs inside a scanned
file must fail THAT FILE, honestly, without taking the worker down.

What this module provides:

* :func:`per_file_timeout` — a per-file WALL-CLOCK bound (``SIGALRM`` /
  ``setitimer``) around every ``scan_file`` call. This is the always-on
  bound: a catastrophic-regex detector or any other runaway fails that one
  file in bounded time and is recorded as a parse error. It works in pool
  children and in the main process's main thread; where signals are
  unavailable (e.g. a non-main worker thread) it degrades to unbounded with
  the job-level lease reaper as the backstop.
* :func:`apply_child_limits` — a pool-child initializer that installs
  ``RLIMIT_AS`` / ``RLIMIT_CPU`` / ``RLIMIT_FSIZE`` bounds and turns
  ``SIGXCPU``/``SIGXFSZ`` into a raised :class:`SandboxLimitExceeded`.
  Kernel-dependent defense-in-depth: RLIMIT_AS (memory bombs) is enforced
  on Linux and gVisor-style sandboxes; **RLIMIT_CPU is NOT enforced under
  gVisor** (found in-round: a child can burn CPU past its rlimit with
  utime frozen at 0), which is exactly why the wall-clock file timeout
  above exists and must stay the primary bound. Since round 51 the same
  initializer also installs the seccomp syscall guard
  (:mod:`scanner.core.seccomp_guard`): a denylist filter (kernel attack
  surface + network egress, ``EPERM``-on-match) so a hostile file cannot
  drive module loading, mount/namespace games, ptrace/bpf/perf, or open
  network connections from inside the scanner child. Env-tunable
  (``CRYPTOSCAN_SANDBOX_SECCOMP`` / ``CRYPTOSCAN_SANDBOX_NET_EGRESS``),
  refuses loudly instead of half-installing, and reports (never raises)
  when the platform cannot install it — x86_64 only, where the syscall
  table is verified against the kernel headers.
* :func:`run_in_sandbox` — run one callable in a forked child under the same
  bounds with a wall-clock timeout; used to VERIFY containment (tests) and
  available for isolated one-off analysis.

Honest scope: rlimits + the seccomp guard bound *processes*, not a
container. They bound wall-clock time per file, address space, file size,
kernel attack surface and new-socket creation for scanner children; fd
hygiene (round 52) closes inherited non-``AF_UNIX`` sockets — a live
database/redis connection inherited at fork — in the child before
scanning, so ``write()`` to it yields ``EBADF``; ``AF_UNIX`` IPC, pipes
and files remain, descriptors opened later and full container isolation
are still the operator-side staged profile in ``deploy/seccomp/``.
Source-root containment is enforced at admission (§4.1). ``RLIMIT_AS``
counts the child's whole address space, including mappings inherited from
the parent at fork time, so the default is generous and every limit is
env-tunable (``0`` disables that limit).
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
import os
import signal
from typing import Any, Callable, Iterator

__all__ = [
    "SandboxLimitExceeded",
    "SandboxTimeout",
    "configured_limits",
    "file_timeout_s",
    "apply_child_limits",
    "per_file_timeout",
    "run_in_sandbox",
]


class SandboxLimitExceeded(RuntimeError):
    """A sandbox resource limit fired inside the sandboxed process."""


class SandboxTimeout(TimeoutError):
    """A file exceeded its per-file wall-clock scan budget."""


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def configured_limits() -> dict[str, int | None]:
    """Sandbox bounds from the environment (``None`` = that limit is off).

    * ``CRYPTOSCAN_SANDBOX_AS_MB`` — child address space, default 4096 MB
    * ``CRYPTOSCAN_SANDBOX_CPU_S`` — child CPU seconds, default 600
    * ``CRYPTOSCAN_SANDBOX_FSIZE_MB`` — file-size cap, default 1024 MB
    """
    return {
        "address_space_mb": _env_int("CRYPTOSCAN_SANDBOX_AS_MB", 4096) or None,
        "cpu_seconds": _env_int("CRYPTOSCAN_SANDBOX_CPU_S", 600) or None,
        "file_size_mb": _env_int("CRYPTOSCAN_SANDBOX_FSIZE_MB", 1024) or None,
    }


def file_timeout_s() -> float:
    """Per-file wall-clock budget (``CRYPTOSCAN_SCAN_FILE_TIMEOUT_S``).

    Default 30s; ``0`` disables the per-file bound (the job lease reaper
    remains the backstop at job level). Parsed as a float so sub-second
    budgets (``0.2``) are honored — an int-only parse silently turned
    ``0.2`` into the 30s default, which is exactly the kind of quiet
    misconfiguration a sandbox must not have.
    """
    raw = (os.environ.get("CRYPTOSCAN_SCAN_FILE_TIMEOUT_S") or "").strip()
    try:
        return float(raw) if raw else 30.0
    except ValueError:
        return 30.0


@contextlib.contextmanager
def per_file_timeout(seconds: float | None = None) -> Iterator[None]:
    """Bound ONE file's scan time on the wall clock.

    Arms ``SIGALRM`` so a runaway detector raises :class:`SandboxTimeout`
    out of ``scan_file`` — caught per-file by ``_scan_one`` and recorded as
    a parse error. Best-effort: where signals cannot be installed (non-main
    thread) the bound is skipped rather than the scan refused.
    """
    budget = file_timeout_s() if seconds is None else float(seconds or 0)
    if budget <= 0:
        yield
        return

    def _fire(signum: int, _frame: Any) -> None:
        raise SandboxTimeout(f"file exceeded its {budget}s scan budget")

    try:
        previous = signal.signal(signal.SIGALRM, _fire)
        signal.setitimer(signal.ITIMER_REAL, budget)
    except (ValueError, OSError):
        yield  # signals unavailable here (e.g. non-main thread) — skip bound
        return
    try:
        yield
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        except (ValueError, OSError):  # pragma: no cover
            pass


def apply_child_limits(
    limits: dict[str, int | None] | None = None,
    *,
    install_signals: bool = True,
    install_seccomp: bool | None = None,
) -> dict[str, Any]:
    """Install rlimit bounds (and the seccomp guard) in the current (child)
    process. Returns what was applied, including the guard's report under
    ``"seccomp"``.

    Never raises: a limit that cannot be set on this platform is skipped —
    the scan still runs, without that particular bound. SIGXCPU/SIGXFSZ are
    converted to :class:`SandboxLimitExceeded` so ``_scan_one``'s per-file
    ``except`` records the limit instead of the child dying silently. The
    seccomp guard follows the same report-not-raise contract
    (``install_seccomp=False`` skips it; ``None`` lets the environment
    configuration decide).
    """
    import resource

    spec = configured_limits() if limits is None else dict(limits)

    def _set(res: int, value: int | None, label: str, scale: int = 1) -> None:
        if not value:
            return
        requested = int(value) * scale
        try:
            cur_soft, cur_hard = resource.getrlimit(res)
            hard = requested if cur_hard == resource.RLIM_INFINITY else min(requested, cur_hard)
            soft = min(requested, hard)
            resource.setrlimit(res, (soft, hard))
            applied[label] = soft
        except (OSError, ValueError):  # pragma: no cover - platform-dependent
            pass

    applied: dict[str, Any] = {}
    _set(resource.RLIMIT_AS, spec.get("address_space_mb"), "address_space_bytes", 1024 * 1024)
    _set(resource.RLIMIT_CPU, spec.get("cpu_seconds"), "cpu_seconds")
    _set(resource.RLIMIT_FSIZE, spec.get("file_size_mb"), "file_size_bytes", 1024 * 1024)

    # fd hygiene BEFORE the syscall guard: an inherited live TCP socket
    # (database/redis) cannot be blocked by a seccomp denylist — close it
    # in this child so a hostile file hits EBADF, not a working channel.
    # Independent switch: it has its own env var, not the seccomp flag.
    from scanner.core.seccomp_guard import close_inherited_network_sockets, seccomp_config

    if seccomp_config()["fd_hygiene"]:
        applied["fd_hygiene"] = close_inherited_network_sockets()
    else:
        applied["fd_hygiene"] = {"closed": 0, "reason": "disabled by CRYPTOSCAN_SANDBOX_FD_HYGIENE"}

    if install_seccomp is not False:
        from scanner.core.seccomp_guard import install_seccomp_guard

        applied["seccomp"] = install_seccomp_guard()

    if install_signals and applied:

        def _fire(signum: int, _frame: Any) -> None:
            raise SandboxLimitExceeded(f"sandbox limit fired (signal {signum})")

        for sig in (signal.SIGXCPU, signal.SIGXFSZ):
            try:
                signal.signal(sig, _fire)
            except (ValueError, OSError):  # pragma: no cover - non-main thread
                pass
    return applied


def run_in_sandbox(
    fn: Callable[..., Any],
    args: tuple = (),
    *,
    limits: dict[str, int | None] | None = None,
    timeout_s: float | None = None,
    install_seccomp: bool | None = None,
) -> tuple[Any, str | None]:
    """Run ``fn(*args)`` in a forked child under sandbox bounds.

    Returns ``(result, None)`` on success or ``(None, error)`` where ``error``
    names what happened — a raised exception (``MemoryError``,
    ``SandboxLimitExceeded``) or a wall-clock timeout (child terminated).
    The parent process is never taken down by the hostile callable.
    ``install_seccomp`` controls the syscall guard in the child (default:
    environment configuration, i.e. on where supported).
    """
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    parent_conn, child_conn = ctx.Pipe(False)

    def _child() -> None:
        kind, payload = "err", "sandbox child failed before running"
        try:
            apply_child_limits(limits, install_seccomp=install_seccomp)
            payload = fn(*args)
            kind = "ok"
        except BaseException as exc:  # noqa: BLE001 — report, never crash the parent
            payload = f"{type(exc).__name__}: {exc}"
        try:
            child_conn.send((kind, payload))
        except (BrokenPipeError, EOFError, OSError):
            # the parent is gone — nothing left to report to; exit quietly
            pass
        finally:
            child_conn.close()

    proc = ctx.Process(target=_child, daemon=True)
    proc.start()
    try:
        if parent_conn.poll(timeout_s):
            try:
                kind, payload = parent_conn.recv()
            except (EOFError, OSError):
                return None, "sandbox child died without reporting"
            proc.join(5)
            return (payload, None) if kind == "ok" else (None, str(payload))
        proc.terminate()
        proc.join(5)
        return None, f"sandbox: wall-clock timeout after {timeout_s}s"
    finally:
        parent_conn.close()
        if proc.is_alive():  # pragma: no cover - stubborn child
            proc.kill()
            proc.join(5)
