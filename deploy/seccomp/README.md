# Seccomp isolation for scanner workloads (§4.1)

The existing process guard and staged custom profile are distinct from the
new static source-parser container launcher. Production worker source scans
now require that launcher; development/test default to labelled inline mode.
The launcher is implemented and unit-tested locally, **not yet qualified on a
real Docker runtime**. See [scanner isolation](../../docs/dev/scanner-isolation.md)
for scope and required runtime/image/staging provisioning. It does not isolate
all optional collectors or the rest of the credentialed worker.

## 1. Process-level guard (active, tested) — `services/scanner/scanner/core/seccomp_guard.py`

Scanner **pool children** (and `run_in_sandbox` children) attempt a
seccomp-BPF **denylist** filter at initialization, via raw `prctl` — no
libseccomp dependency. If a runtime filter is already active, the installer
reports not-installed rather than treating the existing filter as this
custom policy. The source-parser adapter retains Docker's runtime filter;
its check for Seccomp=2 is NOT proof of the following custom denylist:

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

## 3. Static parser container launcher (implemented; runtime qualification open)

`worker/core/static_scan_isolation.py` runs `python -I -m scanner.isolated`
in a preloaded immutable scanner image, with no networking, no capabilities,
no-new-privileges, read-only root/input, hidden clone Git configuration,
non-root UID 10001 and fixed memory/CPU/PID/fd/tmpfs limits. The adapter
checks the requested runtime restrictions before detectors, rejects source
special files, and has a whole-parser watchdog independent of per-file SIGALRM.
The parent bounds JSON/diagnostics/CLI I/O and explicitly removes failed
daemon-side workloads rather than killing only the CLI. These contracts have
unit/subprocess tests; Docker is unavailable in the local implementation lane.

This launcher uses the runtime's default seccomp profile; it does **not**
automatically activate `deterministic-services.json` or prove custom denylist
coverage. The opt-in real-container smoke test is in
`services/worker/tests/integration/test_static_parser_container_live.py`.
A skipped/mocked run is not positive proof. Supported-runtime and adversarial
burn-ins, daemon-loss cleanup and approved dispatcher/daemon access remain
operator prerequisites, not closed readiness categories.
