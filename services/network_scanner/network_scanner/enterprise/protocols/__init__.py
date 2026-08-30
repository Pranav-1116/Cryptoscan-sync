"""Protocol discovery — engine + safe probes.

Statuses are strictly ordered and never equivalent:
PROTOCOL_PRESENT < CRYPTOGRAPHY_OBSERVED < CRYPTOGRAPHY_CONFIGURED <
CRYPTOGRAPHY_VERIFIED.
"""

from network_scanner.enterprise.protocols.engine import (
    ALL_PROTOCOLS,
    STATUSES,
    ProtocolDetectionEngine,
    ProtocolObservation,
    merge_status,
    status_from_findings,
)
from network_scanner.enterprise.protocols.probes import (
    probe_tcp_banners,
    probe_udp_protocols,
)

__all__ = [
    "ALL_PROTOCOLS",
    "STATUSES",
    "ProtocolDetectionEngine",
    "ProtocolObservation",
    "merge_status",
    "status_from_findings",
    "probe_tcp_banners",
    "probe_udp_protocols",
]
