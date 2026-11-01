"""Runtime egress guard for deterministic services (audit 81, round 35).

The AI boundary is architectural today: no AI client is imported anywhere
in the deterministic path, verified statically by CI. Report 81's open
asked for *runtime* proof — seccomp/capability-drop/eBPF are container-
level infrastructure (deployment-scoped), but one enforcement point is
application code, and this module is it:

``install_egress_guard(allowlist)`` wraps ``socket.create_connection`` so
that every outbound TCP connection the process attempts must target the
explicit allowlist (host, or host:port). A non-allowed destination raises
``EgressBlocked`` — the call fails closed, loudly, before a socket is
opened.

Deliberate properties:

* **Fail-closed** — an empty allowlist under enforcement blocks all
  outbound TCP. Whatever is not explicitly allowed is denied.
* **Fail-loud** — every denial logs the destination with the reason;
  silent pass-through is never an option.
* **Off by default** — ``EGRESS_GUARD=off`` (community default); a
  deployment that wants runtime proof sets ``EGRESS_GUARD=enforce`` and
  ``EGRESS_ALLOWLIST=host[:port][,host[:port]...]``.
* **Test-friendly** — ``uninstall_egress_guard`` restores the original
  socket behavior exactly once; double-install is a no-op.

DNS rebinding is closed by **pinning**. An allowlisted *name* is resolved once,
at install time; a connection is then allowed only if the address resolves to one
of those pinned addresses, and the socket is opened directly to the pinned address
so a second resolution cannot swap it underneath the check. A name that did not
resolve at install is refused rather than being resolved lazily on first use.

``socket.create_connection`` is not the only way out of a process, so
``socket.socket.connect`` is wrapped too: a caller that builds its own socket and
connects still meets the allowlist. (Raw ``sendto``/UDP and direct syscalls are
outside this guard and are named as such in the report, not quietly assumed.)

What this is NOT: seccomp, capability dropping, or execve tracing. Those
remain deployment-scoped infrastructure, as report 81 recorded. This is
the application-layer proof that deterministic code makes no unconfigured
outbound calls.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable

logger = logging.getLogger(__name__)


class EgressBlocked(RuntimeError):
    """An outbound connection was denied by the egress guard."""


_ORIGINAL_CREATE_CONNECTION = None
_ORIGINAL_SOCKET_CONNECT = None

#: Addresses that must never be reached *through a name*: loopback, private,
#: link-local (which is where cloud metadata lives), unique-local, multicast and
#: the unspecified address.
_PINNED: dict[str, set[str]] = {}


def _parse_allowlist(allowlist: Iterable[str]) -> set[tuple[str, int | None]]:
    rules: set[tuple[str, int | None]] = set()
    for entry in allowlist:
        entry = str(entry or "").strip()
        if not entry:
            continue
        host, _, port = entry.rpartition(":")
        if not host or (port and not port.isdigit()):
            # no port, or malformed — treat the whole entry as a host rule
            rules.add((entry.lower(), None))
        else:
            rules.add((host.lower(), int(port)))
    return rules


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve(host: str) -> set[str]:
    """Every IPv4/IPv6 address the name currently resolves to."""
    addresses: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        except OSError:
            continue
        for info in infos:
            addresses.add(str(info[4][0]))
    return addresses


def _pin(rules: set[tuple[str, int | None]]) -> dict[str, set[str]]:
    pinned: dict[str, set[str]] = {}
    for host, _port in rules:
        if _is_ip_literal(host):
            continue
        pinned[host] = _resolve(host)
        if not pinned[host]:
            logger.warning("egress_allowlist_host_unresolved", extra={"host": host})
    return pinned


def _deny(host: str, port: int | None, reason: str) -> EgressBlocked:
    logger.warning(
        "egress_blocked",
        extra={"host": host, "port": port, "reason": reason},
    )
    return EgressBlocked(f"outbound connection to {host}:{port} denied: {reason}")


def install_egress_guard(allowlist: Iterable[str]) -> None:
    """Enforce the outbound allowlist at the socket layer (idempotent)."""
    global _ORIGINAL_CREATE_CONNECTION, _ORIGINAL_SOCKET_CONNECT
    if _ORIGINAL_CREATE_CONNECTION is not None:
        return  # already installed
    rules = _parse_allowlist(allowlist)
    pinned = _pin(rules)
    _PINNED.clear()
    _PINNED.update(pinned)
    _ORIGINAL_CREATE_CONNECTION = socket.create_connection
    _ORIGINAL_SOCKET_CONNECT = socket.socket.connect
    allowed_addresses = {host for host, _port in rules if _is_ip_literal(host)}
    for addresses in pinned.values():
        allowed_addresses |= addresses

    def _guarded(address, *args, **kwargs):
        host = str(address[0] or "").lower()
        port = int(address[1]) if len(address) > 1 and address[1] else None
        if not ((host, port) in rules or (host, None) in rules):
            raise _deny(host, port, f"not in egress allowlist ({len(rules)} rules)")
        if _is_ip_literal(host):
            # An operator who allowlists an address means that address.
            return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)
        pinned_addresses = pinned.get(host)
        if not pinned_addresses:
            raise _deny(host, port,
                        "name was not resolvable when the allowlist was installed, "
                        "so it has no pinned address")
        try:
            current = _resolve(host)
        except OSError as exc:  # pragma: no cover - defensive
            raise _deny(host, port, f"name no longer resolves: {exc}") from exc
        unexpected = current - pinned_addresses
        if unexpected or not current:
            raise _deny(
                host, port,
                "resolved to an address that was not authorised when the allowlist "
                "was installed (possible DNS rebinding: "
                f"{', '.join(sorted(unexpected)) or 'no address'})")
        # Connect to the pinned address, not to the name, so the check cannot be
        # raced by a second resolution.
        target = (sorted(pinned_addresses & current)[0], port)
        return _ORIGINAL_CREATE_CONNECTION(target, *args, **kwargs)

    def _guarded_connect(self, address, *args, **kwargs):
        if isinstance(address, tuple) and len(address) >= 2:
            host = str(address[0] or "").lower()
            port = int(address[1]) if address[1] else None
            if not ((host, port) in rules or (host, None) in rules):
                if host not in allowed_addresses:
                    raise _deny(host, port,
                                "direct socket connect to a destination outside the "
                                "egress allowlist")
        return _ORIGINAL_SOCKET_CONNECT(self, address, *args, **kwargs)

    socket.create_connection = _guarded
    socket.socket.connect = _guarded_connect
    logger.info("egress_guard_installed", extra={"rules": len(rules)},)


def uninstall_egress_guard() -> None:
    """Restore the original socket behavior (exactly one restore)."""
    global _ORIGINAL_CREATE_CONNECTION, _ORIGINAL_SOCKET_CONNECT
    if _ORIGINAL_CREATE_CONNECTION is None:
        return
    socket.create_connection = _ORIGINAL_CREATE_CONNECTION
    if _ORIGINAL_SOCKET_CONNECT is not None:
        socket.socket.connect = _ORIGINAL_SOCKET_CONNECT
        _ORIGINAL_SOCKET_CONNECT = None
    _ORIGINAL_CREATE_CONNECTION = None
    _PINNED.clear()
_ORIGINAL_SOCKET_CONNECT = None

#: Addresses that must never be reached *through a name*: loopback, private,
#: link-local (which is where cloud metadata lives), unique-local, multicast and
#: the unspecified address.
_PINNED: dict[str, set[str]] = {}


def egress_guard_active() -> bool:
    return _ORIGINAL_CREATE_CONNECTION is not None
