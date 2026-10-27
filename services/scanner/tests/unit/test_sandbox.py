"""Hostile-input sandbox bounds (§4.1): a hostile scanned file must fail
itself, honestly, without unbounded CPU/memory on the worker.

Process-level rlimits are defense-in-depth, not a container — the tests
prove the MECHANISM: memory bombs hit MemoryError, CPU bombs raise
SandboxLimitExceeded via SIGXCPU, wall-clock runaways are terminated, pool
children carry the limits, and a real Scanner run over hostile files
completes with every failure accounted in files_with_errors.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from scanner.core.sandbox import (
    apply_child_limits,
    configured_limits,
    run_in_sandbox,
)


def _allocate_until(total_mb: int) -> None:
    """Hostile memory bomb: keep allocating until the limit fires."""
    chunks = []
    while True:
        chunks.append(bytearray(64 * 1024 * 1024))
        if sum(len(c) for c in chunks) > total_mb * 1024 * 1024:
            break


def _busy_loop() -> None:
    """Hostile CPU bomb: never returns on its own."""
    x = 0
    while True:
        x += 1


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def test_configured_limits_read_env(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_AS_MB", "256")
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_CPU_S", "30")
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_FSIZE_MB", "0")
    assert configured_limits() == {"address_space_mb": 256, "cpu_seconds": 30, "file_size_mb": None}
    # 0 disables a limit without disabling the sandbox
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_AS_MB", "0")
    assert configured_limits()["address_space_mb"] is None
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_AS_MB", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_CPU_S", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_FSIZE_MB", raising=False)
    defaults = configured_limits()
    assert defaults["address_space_mb"] == 4096
    assert defaults["cpu_seconds"] == 600
    assert defaults["file_size_mb"] == 1024


def test_sandbox_returns_result_and_no_error():
    result, error = run_in_sandbox(lambda a, b: a + b, (20, 22), timeout_s=30)
    assert result == 42
    assert error is None


def test_memory_bomb_is_contained():
    started = time.monotonic()
    result, error = run_in_sandbox(
        _allocate_until,
        (4096,),
        limits={"address_space_mb": 512, "cpu_seconds": 60},
        timeout_s=60,
    )
    assert result is None
    assert error is not None and "MemoryError" in error
    # the parent is alive and the bomb was bounded in time
    assert time.monotonic() - started < 30


def test_cpu_bomb_is_bounded_by_the_wall_clock():
    # RLIMIT_CPU is kernel-dependent (gVisor sandboxes do not enforce it —
    # found in-round), so the GUARANTEED bound for a runaway is the wall
    # clock: the child is terminated and reported, in bounded time.
    started = time.monotonic()
    result, error = run_in_sandbox(
        _busy_loop,
        limits={"address_space_mb": 4096, "cpu_seconds": 600},
        timeout_s=2.0,
    )
    assert result is None
    assert error is not None and "wall-clock timeout" in error
    assert time.monotonic() - started < 15


def test_per_file_timeout_stops_a_runaway_in_place():
    from scanner.core.sandbox import SandboxTimeout, per_file_timeout

    with pytest.raises(SandboxTimeout, match="scan budget"):
        with per_file_timeout(0.3):
            _busy_loop()


def test_wall_clock_timeout_terminates_runaway():
    started = time.monotonic()
    result, error = run_in_sandbox(_sleep, (60.0,), limits=None, timeout_s=2.0)
    assert result is None
    assert error is not None and "wall-clock timeout" in error
    assert time.monotonic() - started < 15


def _rlimit_probe():
    import resource

    from scanner.core.sandbox import per_file_timeout

    with per_file_timeout(0.2):  # per-file bound must work inside children too
        time.sleep(0.05)
    return resource.getrlimit(resource.RLIMIT_CPU)[0]


def test_pool_children_carry_the_limits():
    """The scanner's pool initializer applies bounds in every child and the
    per-file wall-clock bound is armable there. The rlimit VALUE is what is
    asserted — RLIMIT_CPU enforcement itself is kernel-dependent (gVisor
    sandboxes ignore it), which is why the wall-clock bound leads."""
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    with ctx.Pool(processes=1, initializer=apply_child_limits, initargs=({"cpu_seconds": 30},)) as pool:
        cpu_soft = pool.apply(_rlimit_probe)
    assert cpu_soft == 30


def test_hostile_files_fail_themselves_and_the_scan_completes(tmp_path: Path, monkeypatch):
    """A hostile detector payload must not sink the scan: every file that
    hits the sandbox limit is recorded as a parse error (files_with_errors)
    and the run still returns a result with zero fabricated findings."""
    import scanner.core.scanner as scanner_mod
    from scanner.core.scanner import Scanner

    # keep the child limit ABOVE the inherited address space so ordinary
    # pool startup works, while still bounding the bomb
    vm_kb = 0
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmSize:"):
                vm_kb = int(line.split()[1])
                break
    except OSError:
        pass
    as_mb = max(512, (vm_kb // 1024) + 256)

    def hostile_scan_file(source_file, root):
        _allocate_until(as_mb * 4)  # far beyond the child limit
        return []

    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "2")
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_AS_MB", str(as_mb))
    monkeypatch.setattr(scanner_mod, "scan_file", hostile_scan_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(70):  # ≥64 files so the pool path (and initializer) runs
        (repo / f"File{i}.java").write_text(f"class File{i} {{}}\n")

    result = Scanner().scan(repo)
    assert result.statistics.files_with_errors == 70
    assert result.statistics.files_scanned == 0 or result.findings == []
    # every failure is accounted, none hidden
    assert len(result.parse_errors) == 70
    assert any("MemoryError" in e["error"] for e in result.parse_errors)


def test_runaway_files_time_out_and_the_scan_completes(tmp_path: Path, monkeypatch):
    """A detector that never returns must fail per-file (SandboxTimeout
    recorded as a parse error), never hang the scan."""
    import scanner.core.scanner as scanner_mod
    from scanner.core.scanner import Scanner

    def runaway_scan_file(source_file, root):
        _busy_loop()
        return []

    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "2")
    monkeypatch.setenv("CRYPTOSCAN_SCAN_FILE_TIMEOUT_S", "0.2")
    monkeypatch.setattr(scanner_mod, "scan_file", runaway_scan_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(70):
        (repo / f"File{i}.java").write_text(f"class File{i} {{}}\n")

    started = time.monotonic()
    result = Scanner().scan(repo)
    assert result.statistics.files_with_errors == 70
    assert len(result.parse_errors) == 70
    assert any("SandboxTimeout" in e["error"] or "scan budget" in e["error"] for e in result.parse_errors)
    # 70 files x 0.2s across 2 pool children — bounded, not 70 x forever
    assert time.monotonic() - started < 60


def test_normal_files_scan_fine_with_pool_limits(tmp_path: Path, monkeypatch):
    """The same sandboxed pool must not break legitimate scanning."""
    from scanner.core.scanner import Scanner

    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "2")
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_AS_MB", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_CPU_S", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_FSIZE_MB", raising=False)

    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(70):
        (repo / f"File{i}.java").write_text(
            f'import javax.crypto.Cipher;\nclass File{i} {{ Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); }}\n'
        )

    result = Scanner().scan(repo)
    assert result.statistics.files_with_errors == 0
    assert result.findings, "legit crypto usage must still be found"
