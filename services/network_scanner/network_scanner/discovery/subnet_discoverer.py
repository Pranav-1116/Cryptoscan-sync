"""Subnet/port-sweep discovery — find TLS endpoints an estate forgot about.

Iterates a CIDR's host addresses, TCP-connects each candidate port on a
bounded pool, and returns the open endpoints as scan targets. Guarded
against accidental /8 sweeps: the address×port product is capped.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

DEFAULT_PORTS = (443, 8443)


def _max_targets() -> int:
    try:
        return max(1, int(os.environ.get("CRYPTOSCAN_TLS_MAX_DISCOVERY_TARGETS") or 4096))
    except ValueError:
        return 4096


def discover_subnet(
    cidr: str,
    ports: list[int] | tuple[int, ...] = DEFAULT_PORTS,
    *,
    timeout: float = 1.5,
    workers: int = 64,
    max_targets: int | None = None,
) -> dict[str, Any]:
    """TCP-connect sweep of ``cidr`` x ``ports`` -> open endpoints.

    candidates counts the host:port pairs queued for probing (hosts x
    ports); hosts_checked counts distinct IPs, and only endpoints whose
    TCP connect succeeded land in endpoints/open_count.
    """
    try:
        network = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError as exc:
        return {"cidr": cidr, "error": f"invalid CIDR: {exc}", "endpoints": []}
    if network.version != 4:
        return {"cidr": cidr, "error": "only IPv4 ranges are supported", "endpoints": []}

    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    if not port_list:
        return {"cidr": cidr, "error": "no valid ports supplied", "endpoints": []}

    hosts = [str(ip) for ip in network.hosts()]
    cap = max_targets or _max_targets()
    total = len(hosts) * len(port_list)
    truncated = total > cap
    if truncated:
        allowed_hosts = cap // len(port_list)
        hosts = hosts[:allowed_hosts]

    candidates = [f"{host}:{port}" for host in hosts for port in port_list]
    open_endpoints: list[str] = []
    if candidates:
        worker_count = max(1, min(workers, len(candidates)))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            for endpoint, is_open in pool.map(lambda candidate: (candidate, _tcp_open(candidate, timeout)), candidates):
                if is_open:
                    open_endpoints.append(endpoint)

    return {
        "cidr": cidr,
        "ports": port_list,
        "hosts_checked": len(hosts),
        "candidates": len(candidates),
        "truncated": truncated,
        "endpoints": open_endpoints,
        "open_count": len(open_endpoints),
    }


def _tcp_open(endpoint: str, timeout: float) -> bool:
    host, _, port_s = endpoint.rpartition(":")
    try:
        with socket.create_connection((host, int(port_s)), timeout=timeout):
            return True
    except OSError:
        return False
