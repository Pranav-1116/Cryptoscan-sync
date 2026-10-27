"""Seccomp profile contract for deterministic services (81, round 36)."""

from __future__ import annotations

import copy

from api.security.seccomp import (
    DANGEROUS_SYSCALLS,
    PROFILE_PATH,
    load_profile,
    validate_profile,
)


def test_profile_file_exists_and_is_valid():
    assert PROFILE_PATH.exists(), PROFILE_PATH
    report = validate_profile(load_profile())
    assert report["valid"] is True, report["problems"]
    assert report["default_action"] == "SCMP_ACT_ERRNO"
    assert report["dangerous_denied"] is True
    assert report["runtime_essential_allowed"] is True
    assert report["allowed"] > 100  # a real allowlist, not a stub


def test_every_dangerous_syscall_resolves_to_errno():
    actions = {}
    for rule in load_profile()["syscalls"]:
        for name in rule["names"]:
            actions.setdefault(name, rule["action"])
    for name in DANGEROUS_SYSCALLS:
        assert actions[name] == "SCMP_ACT_ERRNO", name


def test_validator_catches_permissive_default():
    profile = copy.deepcopy(load_profile())
    profile["defaultAction"] = "SCMP_ACT_ALLOW"
    report = validate_profile(profile)
    assert report["valid"] is False
    assert any("defaultAction" in p for p in report["problems"])


def test_validator_catches_an_allowed_escape_primitive():
    for evil in ("bpf", "ptrace", "mount"):
        profile = copy.deepcopy(load_profile())
        # flip the syscall into the allow rule
        allow = profile["syscalls"][0]
        deny = profile["syscalls"][1]
        deny["names"] = [n for n in deny["names"] if n != evil]
        allow["names"].append(evil)
        report = validate_profile(profile)
        assert report["valid"] is False, evil
        assert any(evil in p for p in report["problems"]), evil


def test_validator_catches_missing_runtime_essential():
    profile = copy.deepcopy(load_profile())
    allow = profile["syscalls"][0]
    allow["names"] = [n for n in allow["names"] if n != "epoll_pwait"]
    report = validate_profile(profile)
    assert report["valid"] is False
    assert any("epoll_pwait" in p for p in report["problems"])


def test_execve_limit_is_stated_not_hidden():
    report = validate_profile(load_profile())
    assert "execve" in report["execve_note"]
    assert "eBPF" in report["execve_note"]
