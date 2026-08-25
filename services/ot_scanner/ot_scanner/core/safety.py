"""OT safety guardrails. The scanner must never emit a packet onto an OT network."""

from __future__ import annotations

FORBIDDEN = ("port_scan", "service_enumeration", "packet_injection", "arp_spoofing", "protocol_fuzzing")


class OtSafetyError(RuntimeError):
    """Raised when code attempts an active OT action."""


def send_packet(*_args, **_kwargs) -> None:
    raise OtSafetyError("OT scanner is read-only. Packet injection is forbidden.")


def forbid(action: str) -> None:
    if action in FORBIDDEN:
        raise OtSafetyError(f"OT scanner forbids {action}")
