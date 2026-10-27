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

What this is NOT: seccomp, capability dropping, or execve tracing. Those
remain deployment-scoped infrastructure, as report 81 recorded. This is
the application-layer proof that deterministic code makes no unconfigured
outbound calls.
"""

from __future__ import annotations

import logging
import socket
from typing import Iterable

logger = logging.getLogger(__name__)


class EgressBlocked(RuntimeError):
    """An outbound connection was denied by the egress guard."""


_ORIGINAL_CREATE_CONNECTION = None


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


def install_egress_guard(allowlist: Iterable[str]) -> None:
    """Enforce the outbound allowlist at the socket layer (idempotent)."""
    global _ORIGINAL_CREATE_CONNECTION
    if _ORIGINAL_CREATE_CONNECTION is not None:
        return  # already installed
    rules = _parse_allowlist(allowlist)
    _ORIGINAL_CREATE_CONNECTION = socket.create_connection

    def _guarded(address, *args, **kwargs):
        host = str(address[0] or "").lower()
        port = int(address[1]) if len(address) > 1 and address[1] else None
        allowed = (host, port) in rules or (host, None) in rules
        if not allowed:
            logger.warning(
                "egress_blocked",
                extra={"host": host, "port": port,
                       "reason": "destination not in egress allowlist"},
            )
            raise EgressBlocked(
                f"outbound connection to {host}:{port} denied: "
                f"not in egress allowlist ({len(rules)} rules)")
        return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)

    socket.create_connection = _guarded
    logger.info("egress_guard_installed", extra={"rules": len(rules)})


def uninstall_egress_guard() -> None:
    """Restore the original socket behavior (exactly one restore)."""
    global _ORIGINAL_CREATE_CONNECTION
    if _ORIGINAL_CREATE_CONNECTION is None:
        return
    socket.create_connection = _ORIGINAL_CREATE_CONNECTION
    _ORIGINAL_CREATE_CONNECTION = None


def egress_guard_active() -> bool:
    return _ORIGINAL_CREATE_CONNECTION is not None
