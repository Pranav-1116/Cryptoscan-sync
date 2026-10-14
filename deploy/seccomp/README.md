# Seccomp isolation for scanner workloads (§4.1)

Two layers, honestly scoped. Neither is a substitute for running the
scanner tier inside its own container/network boundary in production —
they raise the cost of a hostile scanned file reaching the host or the
network from *inside a worker process*.

## 1. Process-level guard (active, tested) — `services/scanner/scanner/core/seccomp_guard.py`

Every scanner **pool child** (and `run_in_sandbox` child) installs a
seccomp-BPF **denylist** filter at initialization, via raw `prctl` — no
libseccomp dependency:

- **Kernel attack surface → `EPERM`:** module loading, mount/namespace
  manipulation (`mount`, `unshare`, `setns`, `pivot_root`, the new mount
  API), `ptrace`/`process_vm_*`, `bpf`, `perf_event_open`, `kexec_*`,
  clock/time setting, keyrings, `fanotify`, `io_uring_*`, `quotactl`,
  `reboot`, and the legacy module machinery. Blocked syscalls return
  `EPERM` (never `SIGSYS`), so a legitimate need surfaces as a visible
  per-file error rather than a dead child.
- **Network egress → `EPERM`:** `socket` creation and the socket data
  path (`connect`, `bind`, `listen`, `accept*`, `send*`, `recv*`,
  `shutdown`). `socketpair` creation stays allowed (local IPC used by
  process internals; pipe-style `read`/`write` on the pair still works).
- **Foreign-arch syscalls** (32-bit compat, x32) are denied, not allowed
  through — the compat path is how a payload would dodge an x86_64 table.
- `PR_SET_NO_NEW_PRIVS` is set in the child (irreversible, children only).

Configuration: `CRYPTOSCAN_SANDBOX_SECCOMP=on|off` (default `on`),
`CRYPTOSCAN_SANDBOX_NET_EGRESS=block|allow` (default `block`).

Verified scope and known limits:

- **fd hygiene (round 52):** the same child initializer closes inherited
  non-`AF_UNIX` socket descriptors before scanning — a seccomp filter
  cannot block `write()` to an inherited live database/redis socket, so
  the child closes it and a hostile write hits `EBADF`
  (`CRYPTOSCAN_SANDBOX_FD_HYGIENE=on|off`, default `on`). `AF_UNIX` IPC
  (multiprocessing socketpairs, `/dev/log`), pipes and files are
  preserved, and descriptors opened *after* the sweep remain — the
  container boundary is still the authoritative fix.
- The syscall-number tables are **x86_64 and aarch64 (arm64)**, verified
  against the kernel's `asm/unistd_64.h` and the asm-generic numbering
  arm64 actually uses (`asm-generic/unistd.h`; unit tests re-verify both
  where the headers exist). The denylist is a name-level policy —
  identical across arches minus the seven x86_64-legacy syscalls with no
  arm64 number. Other architectures still report `unsupported` and run
  without this guard — an unverified table could block the wrong syscall.
- Empirical tests (`services/scanner/tests/unit/test_seccomp_guard.py`)
  run every install inside forked children: a named syscall returns
  `EPERM` after the install, sockets are refused while file reads and
  local IPC keep working, the env switch is a real control, pool children
  that scan files run with the filter active, and a refused install
  leaves no filter behind.

## 2. Container-level profile (staged, operator-applied) — `deterministic-services.json`

A Docker/OCI seccomp profile for the scanner/worker **containers**:
default-deny with an explicit allowlist covering what the services need
(arch map for x86_64 + aarch64, `SCMP_ACT_ERRNO`/`EPERM` for the same
kernel-attack families plus `userfaultfd`, `vm86`, …). Apply it with
`security_opt: ["seccomp:./deploy/seccomp/deterministic-services.json"]`
on the worker/scanner service.

This profile is **staged, not gate-tested**: the local test lane runs
processes, not containers, so applying it is an operator decision that
needs a deployment-environment burn-in (a too-narrow allowlist fails
visibly — a blocked syscall returns `EPERM` — but it still fails). It
complements the process guard: the container profile bounds the whole
worker including its network clients, while the process guard bounds the
individual scan children inside it.
