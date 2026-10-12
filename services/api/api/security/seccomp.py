"""Seccomp profile for the deterministic services (audit 81, round 36).

The deployment artifact is ``deploy/seccomp/deterministic-services.json``
(Docker/OCI default-seccomp format). This module is its contract:

* the profile must be structurally valid for the OCI seccomp schema,
* every syscall in the DANGEROUS set — the kernel-attack-surface and
  escape primitives — must resolve to ``SCMP_ACT_ERRNO``,
* the runtime-essential set (what a Python/uvicorn service needs to
  boot, serve, and read/write its workspace) must be allowed,
* ``execve`` stays allowed *deliberately*: the container runtime needs
  it to start the entrypoint under the profile. That is the honest
  limit of seccomp here — proving that no AI binary is *invoked* at
  runtime is eBPF execve tracing, which stays the open deployment item
  this report records. The application-layer egress guard (round 35)
  already blocks network egress; this profile removes the kernel
  primitives an escaped process would reach for (bpf, mount, ptrace,
  keyctl, module loading, namespace escapes, process-injection).

The validator runs in the test suite, so the artifact can never drift
from the contract silently. Loading the profile into a container
orchestrator remains a deployment action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: escape/attack primitives that must be denied under every circumstance
DANGEROUS_SYSCALLS: tuple[str, ...] = (
    "bpf", "kexec_load", "kexec_file_load", "keyctl", "add_key",
    "request_key", "mount", "umount2", "move_mount", "fsopen",
    "fsconfig", "fsmount", "fspick", "open_by_handle_at", "pivot_root",
    "ptrace", "process_vm_readv", "process_vm_writev", "perf_event_open",
    "reboot", "swapon", "swapoff", "setns", "unshare", "userfaultfd",
    "init_module", "finit_module", "delete_module", "iopl", "ioperm",
    "quotactl", "acct", "nfsservctl",
)

#: what a Python/uvicorn deterministic service needs to boot and serve
RUNTIME_ESSENTIAL_SYSCALLS: tuple[str, ...] = (
    "read", "write", "open", "openat", "close", "mmap", "mprotect",
    "munmap", "brk", "futex", "clone", "exit", "exit_group", "rt_sigaction",
    "rt_sigprocmask", "socket", "bind", "listen", "accept4", "connect",
    "getrandom", "stat", "newfstatat", "fstat", "lseek", "ioctl",
    "epoll_ctl", "epoll_pwait", "clock_gettime", "nanosleep",
)

PROFILE_PATH = Path(__file__).resolve().parents[4] / "deploy" / "seccomp" / "deterministic-services.json"


def load_profile(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or PROFILE_PATH).read_text())


def _syscall_action(profile: dict[str, Any]) -> dict[str, str]:
    """Resolve every syscall name → effective action (first rule wins)."""
    resolved: dict[str, str] = {}
    for rule in profile.get("syscalls") or []:
        action = rule.get("action")
        for name in rule.get("names") or []:
            resolved.setdefault(name, action)
    return resolved


def validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """Check the 81 contract. Returns a report; raises nothing."""
    problems: list[str] = []
    if profile.get("defaultAction") != "SCMP_ACT_ERRNO":
        problems.append("defaultAction must be SCMP_ACT_ERRNO (fail closed)")
    if not profile.get("archMap"):
        problems.append("archMap missing — profile must state its architectures")

    actions = _syscall_action(profile)
    for name in DANGEROUS_SYSCALLS:
        if actions.get(name) != "SCMP_ACT_ERRNO":
            problems.append(f"dangerous syscall not denied: {name}")
    for name in RUNTIME_ESSENTIAL_SYSCALLS:
        if actions.get(name) != "SCMP_ACT_ALLOW":
            problems.append(f"runtime-essential syscall not allowed: {name}")

    # a rule that both allows and denies the same syscall is ambiguous
    for rule in profile.get("syscalls") or []:
        for name in rule.get("names") or []:
            if actions.get(name) != rule.get("action"):
                problems.append(f"conflicting rules for syscall: {name}")
                break

    return {
        "model": "seccomp-profile/validation-v1",
        "profile": "deploy/seccomp/deterministic-services.json",
        "default_action": profile.get("defaultAction"),
        "allowed": sum(1 for a in actions.values() if a == "SCMP_ACT_ALLOW"),
        "denied": sum(1 for a in actions.values() if a == "SCMP_ACT_ERRNO"),
        "dangerous_denied": all(actions.get(n) == "SCMP_ACT_ERRNO"
                                for n in DANGEROUS_SYSCALLS),
        "runtime_essential_allowed": all(actions.get(n) == "SCMP_ACT_ALLOW"
                                         for n in RUNTIME_ESSENTIAL_SYSCALLS),
        "execve_note": (
            "execve stays allowed: the container runtime needs it to start "
            "the entrypoint. Runtime proof that no AI binary is invoked is "
            "eBPF execve tracing (open deployment item); this profile "
            "removes the kernel escape primitives."
        ),
        "problems": problems,
        "valid": not problems,
    }
