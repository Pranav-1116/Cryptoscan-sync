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
  above exists and must stay the primary bound.
* :func:`run_in_sandbox` — run one callable in a forked child under the same
  bounds with a wall-clock timeout; used to VERIFY containment (tests) and
  available for isolated one-off analysis.

Honest scope: these are process-level bounds, **not** a container. They
bound wall-clock time per file, address space and file size for scanner
children; they do not block network egress, syscalls or filesystem reads
outside the scan root (source-root containment is enforced at admission —
§4.1 — and full seccomp/container isolation remains open; see
``deploy/seccomp/`` for the staged policy). ``RLIMIT_AS`` counts the child's
whole address space, including mappings inherited from the parent at fork
time, so the default is generous and every limit is env-tunable (``0``
disables that limit).
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


def apply_child_limits(limits: dict[str, int | None] | None = None, *, install_signals: bool = True) -> dict[str, int]:
    """Install rlimit bounds in the current (child) process. Returns applied.

    Never raises: a limit that cannot be set on this platform is skipped —
    the scan still runs, without that particular bound. SIGXCPU/SIGXFSZ are
    converted to :class:`SandboxLimitExceeded` so ``_scan_one``'s per-file
    ``except`` records the limit instead of the child dying silently.
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

    applied: dict[str, int] = {}
    _set(resource.RLIMIT_AS, spec.get("address_space_mb"), "address_space_bytes", 1024 * 1024)
    _set(resource.RLIMIT_CPU, spec.get("cpu_seconds"), "cpu_seconds")
    _set(resource.RLIMIT_FSIZE, spec.get("file_size_mb"), "file_size_bytes", 1024 * 1024)

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
) -> tuple[Any, str | None]:
    """Run ``fn(*args)`` in a forked child under sandbox bounds.

    Returns ``(result, None)`` on success or ``(None, error)`` where ``error``
    names what happened — a raised exception (``MemoryError``,
    ``SandboxLimitExceeded``) or a wall-clock timeout (child terminated).
    The parent process is never taken down by the hostile callable.
    """
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    parent_conn, child_conn = ctx.Pipe(False)

    def _child() -> None:
        kind, payload = "err", "sandbox child failed before running"
        try:
            apply_child_limits(limits)
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
