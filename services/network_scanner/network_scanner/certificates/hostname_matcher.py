"""Hostname vs certificate SAN / CN matching."""

from __future__ import annotations

from typing import Any

from network_scanner.certificates.cert_parser import hostname_matches
from network_scanner.certificates.san_extractor import extract_dns_names


def matches(hostname: str, cert: dict[str, Any]) -> bool:
    if hostname_matches(hostname, cert):
        return True
    host = (hostname or "").lower().split(":")[0]
    for name in extract_dns_names(cert):
        if name == host:
            return True
        if name.startswith("*.") and host.endswith(name[1:]) and host.count(".") >= name.count("."):
            return True
    return False
