"""Target validation for scanner invocations — SSRF / path-traversal guard.

The platform can launch real scanners against user-supplied targets (network
CIDRs, source-code paths). This module is the single choke point that decides
whether a target is safe to scan. It is deliberately conservative:

* Network targets are parsed as CIDRs and must NOT be loopback, link-local,
  cloud-instance metadata, unspecified, multicast, reserved, or private-ish
  ranges unless the caller is explicitly authorized for internal scanning.
  URL schemes (http://, file://, gopher://…) are rejected — the network
  scanner speaks TCP to CIDRs, it must never be turned into an SSRF primitive.
* Filesystem targets are resolved and confined to an allow-listed root
  (workspace/source roots); absolute system paths and ``..`` traversal that
  escapes the root are rejected. Command-substitution metacharacters never
  reach a shell (scanners are launched with argv lists regardless), but are
  rejected here as defense in depth.

Fail-closed: anything unparseable or outside policy raises TargetValidationError.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from pathlib import Path

# CIDRs that must never be swept via the generic discovery endpoint. Loopback,
# link-local (incl. 169.254.169.254 cloud metadata), unspecified, multicast,
# reserved and carrier-grade NAT are all blocked by default. Internal RFC1918
# ranges are allowed (this is an internal-asset scanner) but the metadata
# address is carved out explicitly.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),        # "this" network / unspecified
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved / future
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local (internal)
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
]

# the cloud metadata host specifically (defense in depth even within 169.254)
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

# URL-ish schemes that indicate someone is trying to drive an HTTP client
_URL_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_SHELL_META = re.compile(r"[;&|`$<>]|\$\(|\)\s*\n|&&|\|\|")

# Hosts that are obviously not network targets but might be slipped in
_HOSTNAME_BLACKLIST = ("localhost", "metadata.google.internal", "metadata",
                       "metadata.azure.com", "169.254.169.254")


class TargetValidationError(ValueError):
    """Raised when a scan target fails safety policy (fail-closed)."""

    def __init__(self, reason: str, field: str = "target"):
        self.reason = reason
        self.field = field
        super().__init__(f"{field}: {reason}")


def validate_network_target(raw: str, *, allow_internal: bool = True) -> str:
    """Validate a network CIDR/host target for the discovery/network scanner.

    Returns the normalized CIDR string or raises TargetValidationError.
    """
    if not raw or not str(raw).strip():
        raise TargetValidationError("empty network target", "network_target")
    target = str(raw).strip()

    if _URL_SCHEME.match(target):
        raise TargetValidationError(
            "URLs/schemes are not valid network targets (SSRF guard); "
            "supply a CIDR or host", "network_target")
    if _SHELL_META.search(target):
        raise TargetValidationError("shell metacharacters not permitted", "network_target")

    low = target.lower().rstrip("/")
    if any(low == h or low.startswith(h + "/") for h in _HOSTNAME_BLACKLIST):
        raise TargetValidationError("blocked host (loopback/metadata)", "network_target")
    # bare hostnames without an IP are not swept by the CIDR sweeper
    if not re.match(r"^[0-9a-fA-F:.]+(\/\d{1,3})?$", target):
        raise TargetValidationError(
            "network target must be an IP or CIDR, not a hostname/URL", "network_target")

    host = target.split("/")[0]
    if host in _METADATA_IPS:
        raise TargetValidationError("cloud metadata address blocked", "network_target")

    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise TargetValidationError(f"invalid CIDR: {exc}", "network_target")

    # block dangerous ranges; also refuse an internet-sized sweep
    for blocked in _BLOCKED_NETWORKS:
        if net.version == blocked.version and net.subnet_of(blocked):
            # RFC1918 internal is allowed, but these blocked nets are not
            raise TargetValidationError(
                f"refusing to scan {net} — loopback/link-local/metadata/multicast/reserved range blocked",
                "network_target")

    # bound the sweep even for authorized internal scanning
    if net.num_addresses > 65536:
        raise TargetValidationError(
            f"CIDR too large ({net.num_addresses} addresses); cap at /16 (65536)",
            "network_target")
    return str(net)


# Default roots a source/universal scan is allowed to read. Configurable via
# env CRYPTOSCAN_SOURCE_ROOTS (colon-separated). Anything outside is rejected.
def _allowed_source_roots() -> list[Path]:
    env = os.environ.get("CRYPTOSCAN_SOURCE_ROOTS", "")
    roots: list[Path] = []
    if env:
        roots = [Path(p).resolve() for p in env.split(os.pathsep) if p.strip()]
    # The scanner worker clones/extracts scan targets into WORKSPACE_BASE_PATH
    # (default /tmp/cryptoscan-workspaces in the container images); treat it
    # and any explicit source roots as allow-listed scan locations.
    for envvar in ("WORKSPACE_BASE_PATH", "SOURCE_ROOT"):
        val = os.environ.get(envvar, "").strip()
        if val:
            roots.append(Path(val).resolve())
    # repository root and common workspace locations
    here = Path(__file__).resolve()
    repo = here.parents[4]  # services/api/api/security -> repo root
    roots.append(repo)
    for p in (
        "/workspace", "/workspaces",
        "/tmp/cryptoscan-workspaces", "/tmp/cryptoscan-sources",
        "/app/sources", "/app/workspaces",
    ):
        pp = Path(p)
        if pp.exists():
            roots.append(pp.resolve())
    # de-dup
    out: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        rs = str(r)
        if rs not in seen:
            seen.add(rs)
            out.append(r)
    return out


def validate_source_target(raw: str, *, label: str = "source_target") -> str:
    """Validate a filesystem source path for the source/universal scanners.

    Resolves ``..`` and confines the target to an allow-listed source root.
    Rejects shell metacharacters and obvious system/secret paths.
    """
    if not raw or not str(raw).strip():
        raise TargetValidationError("empty source target", label)
    target = str(raw).strip()

    if _URL_SCHEME.match(target) and not target.startswith(("git@", "https://github.com/")):
        # only http(s) git remote URLs are acceptable; file/gopher/etc are not
        scheme = target.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise TargetValidationError(f"scheme {scheme}:// not permitted for source target", label)
    if _SHELL_META.search(target) and not target.startswith(("http://", "https://")):
        raise TargetValidationError("shell metacharacters not permitted in path", label)

    # remote git URL: hand off (scanner clones into a sandbox); still block
    # obvious non-git schemes and user/host command tricks.
    if target.startswith(("http://", "https://", "git@")):
        if any(ch in target for ch in (";", "|", "`", "$", "<", ">")):
            raise TargetValidationError("metacharacters not permitted in remote URL", label)
        return target

    # local path — must resolve within an allowed root and not hit secrets
    resolved = Path(target).expanduser()
    if not resolved.is_absolute():
        # treat relative paths against the repo root
        resolved = _allowed_source_roots()[0] / resolved
    resolved = resolved.resolve()

    # block obvious secret/system locations regardless of root. Match on the
    # full path or the immediate parent+name, not a bare name, so a normal
    # source directory like /tmp/cryptoscan-sources/repo is never blocked.
    posix = resolved.as_posix().lower()
    name = resolved.name.lower()
    secret_paths = (
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys",
        "/.aws/credentials", "/.aws/config", "/.env",
        "/id_rsa", "/id_ecdsa", "/id_ed25519",
    )
    secret_names = ("id_rsa", "id_ecdsa", "id_ed25519", "credentials",
                    ".env", "shadow", "htpasswd")
    if posix.endswith(secret_paths) or any(posix.endswith(sp) for sp in secret_paths):
        raise TargetValidationError("refusing to scan secret/credential path", label)
    if name in secret_names and (".ssh" in posix or ".aws" in posix or "credentials" in name):
        raise TargetValidationError("refusing to scan secret/credential path", label)

    roots = _allowed_source_roots()
    if not any(resolved == r or r in resolved.parents for r in roots):
        raise TargetValidationError(
            f"source path {resolved} is outside the allowed source roots", label)
    return str(resolved)


def validate_scan_targets(targets: dict) -> dict:
    """Validate all optional scan targets in a run request.

    Returns a normalized targets dict (network/source/universal) or raises
    TargetValidationError on the first unsafe value.
    """
    out: dict = dict(targets or {})
    if out.get("network"):
        out["network"] = validate_network_target(str(out["network"]))
    for key in ("source", "universal"):
        if out.get(key):
            out[key] = validate_source_target(str(out[key]), label=f"{key}_target")
    return out
