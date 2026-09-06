"""Security tests for scan-target validation — SSRF / path-traversal guards."""

from __future__ import annotations

import os

import pytest

# ensure a known source root exists for the allow-list tests
os.environ.setdefault("CRYPTOSCAN_SOURCE_ROOTS", "/tmp/cryptoscan-test-sources")
os.makedirs("/tmp/cryptoscan-test-sources/repo", exist_ok=True)

from api.security.target_validation import (  # noqa: E402
    TargetValidationError,
    validate_network_target,
    validate_scan_targets,
    validate_source_target,
)


# -- network / SSRF ----------------------------------------------------------- #
@pytest.mark.parametrize("good", ["10.0.0.0/24", "192.168.1.0/28", "172.16.5.0/24", "8.8.8.8"])
def test_valid_internal_and_public_cidrs(good):
    assert validate_network_target(good)


@pytest.mark.parametrize("bad", [
    "127.0.0.1", "127.0.0.0/8",            # loopback
    "169.254.169.254/32", "169.254.0.0/16",  # cloud metadata / link-local
    "0.0.0.0/0", "0.0.0.0/8",              # unspecified / this network
    "224.0.0.0/4", "240.0.0.0/4",          # multicast / reserved
    "100.64.0.0/10",                        # carrier-grade NAT
    "::1/128", "fe80::1", "fc00::/7",      # IPv6 loopback / link-local / ULA
    "localhost", "metadata.google.internal",
])
def test_blocks_dangerous_ranges(bad):
    with pytest.raises(TargetValidationError):
        validate_network_target(bad)


@pytest.mark.parametrize("bad", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8031/health",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379",
    "8.8.8.8; curl http://evil",
    "8.8.8.8 && whoami",
    "$(whoami)",
])
def test_blocks_urls_schemes_and_shell_metacharacters(bad):
    with pytest.raises(TargetValidationError):
        validate_network_target(bad)


def test_rejects_internet_sized_sweep():
    with pytest.raises(TargetValidationError):
        validate_network_target("8.0.0.0/8")  # 16M addresses


# -- source / path traversal -------------------------------------------------- #
@pytest.mark.parametrize("bad", [
    "../../../../etc/passwd", "/etc/passwd", "/etc/shadow",
    "/root/.ssh/id_rsa", "/home/u/.aws/credentials",
    "/tmp/cryptoscan-test-sources/../etc/passwd",
    "$(whoami)", "/tmp;rm -rf /tmp/x", "a; cat /etc/passwd",
    "file:///etc/passwd", "gopher://x",
])
def test_blocks_traversal_and_secret_paths(bad):
    with pytest.raises(TargetValidationError):
        validate_source_target(bad)


def test_allows_path_within_source_root():
    out = validate_source_target("/tmp/cryptoscan-test-sources/repo")
    assert out.endswith("repo")


def test_allows_https_git_remote():
    assert validate_source_target("https://github.com/org/repo.git").endswith(".git")


def test_https_remote_rejects_metacharacters():
    with pytest.raises(TargetValidationError):
        validate_source_target("https://github.com/org/$(id).git")


# -- mixed targets dict ------------------------------------------------------- #
def test_validate_scan_targets_blocks_loopback_network():
    with pytest.raises(TargetValidationError) as ei:
        validate_scan_targets({"network": "127.0.0.1"})
    assert ei.value.field == "network_target"


def test_validate_scan_targets_passes_safe():
    out = validate_scan_targets({
        "network": "10.0.0.0/24",
        "source": "/tmp/cryptoscan-test-sources/repo",
    })
    assert out["network"] == "10.0.0.0/24"
    assert out["source"].endswith("repo")


def test_empty_targets_are_noop():
    assert validate_scan_targets({}) == {}


# -- active-probe target validator ------------------------------------------- #
from api.security.target_validation import (  # noqa: E402
    validate_probe_target,
    validate_probe_targets,
)

PROBE_BLOCK = [
    "127.0.0.1", "127.0.0.1:443", "[::1]:443", "169.254.169.254",
    "localhost", "localhost:8443", "metadata.google.internal",
    "0.0.0.0", "224.0.0.1", "100.64.0.1", "fe80::1",
    "http://evil.com/", "https://1.2.3.4", "host;cat /etc/passwd",
    "user:pass@internal", "169.254.169.254:443",
]

PROBE_ALLOW = [
    "mail.customer.com:443", "api.example.com", "10.0.0.5", "10.0.0.5:8443",
    "192.168.1.10", "172.16.0.1", "8.8.8.8:443", "[2001:db8::1]:443",
]


@pytest.mark.parametrize("t", PROBE_BLOCK)
def test_probe_blocks_ssrf_targets(t):
    with pytest.raises(TargetValidationError):
        validate_probe_target(t)


@pytest.mark.parametrize("t", PROBE_ALLOW)
def test_probe_allows_named_and_internal_hosts(t):
    assert validate_probe_target(t) == t


def test_probe_batch_returns_cleaned_list():
    out = validate_probe_targets(["a.com:443", "10.0.0.1"])
    assert out == ["a.com:443", "10.0.0.1"]


def test_probe_batch_empty_rejected():
    with pytest.raises(TargetValidationError):
        validate_probe_targets([])


def test_probe_batch_rejects_metadata_member():
    with pytest.raises(TargetValidationError) as ei:
        validate_probe_targets(["ok.com:443", "169.254.169.254"])
    assert "[1]" in ei.value.field
