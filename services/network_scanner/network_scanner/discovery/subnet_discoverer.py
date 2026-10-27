"""Subnet/port-sweep discovery — find TLS endpoints an estate forgot about.

Iterates a CIDR's host addresses, TCP-connects each candidate port on a
bounded pool, and returns the open endpoints as scan targets. Guarded
against accidental /8 sweeps: the address×port product is capped.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

try:  # shared canonical protocol registry (single source of truth)
    from shared_models.network_registry import classify_endpoint, risk_severity
except Exception:  # pragma: no cover - registry always present in this repo
    classify_endpoint = None  # type: ignore[assignment]
    risk_severity = None  # type: ignore[assignment]

# Crypto-relevant service ports an estate may have forgotten: HTTPS,
# STARTTLS mail (SMTP/IMAP/POP3), LDAPS, FTPS, SMTPS/IMAPS/POP3S, SSH,
# secure LDAP, plus high-risk OT/ICS, DB, cache, remote-admin and legacy
# cleartext ports so an exposed service is named and risk-scored.
DEFAULT_PORTS = (
    443, 8443, 80, 8080,
    25, 465, 587, 143, 993, 110, 995, 21, 990, 636, 989, 22, 3269,
    23, 2375, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5672, 9092, 1883, 8883,
    445, 139, 2049, 5900, 3389, 5985, 5986, 161, 53, 389, 88, 502, 102,
)


def _classify_endpoint(endpoint: str) -> dict[str, Any]:
    """Passively name+verdict an open ``host:port`` endpoint using the shared
    network registry. Pure classification of an already-observed open port —
    it never initiates another probe (OT/SIS/ESD stay untouched)."""
    if classify_endpoint is None:
        return {}
    info = classify_endpoint(endpoint)
    if not info.recognized:
        return {
            "port": info.port,
            "protocol": None,
            "category": "unknown",
            "status": "UNKNOWN",
            "encrypted": False,
            "exposure": "unknown",
            "severity": risk_severity(info) if risk_severity else "MEDIUM",
            "recognized": False,
            "notes": "unrecognized service — human review",
        }
    return {
        "port": info.port,
        "protocol": info.canonical,
        "category": info.category,
        "status": info.status,
        "encrypted": info.encrypted,
        "cleartext": info.cleartext,
        "exposure": info.exposure,
        "severity": risk_severity(info) if risk_severity else "MEDIUM",
        "recognized": True,
        "notes": info.notes,
        "risk_reason": info.risk_reason,
    }


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
    # A host counts as reachable the moment any probe gets an explicit TCP
    # answer (open OR refused). Every probe timing out means the host is
    # silent — typically Wi-Fi AP/client isolation, a host firewall dropping
    # packets, or no host at all.
    reachable_hosts: set[str] = set()
    probes_open = probes_closed = probes_filtered = 0
    if candidates:
        worker_count = max(1, min(workers, len(candidates)))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            for endpoint, state in pool.map(
                lambda candidate: (candidate, _tcp_probe(candidate, timeout)),
                candidates,
            ):
                host = endpoint.rpartition(":")[0]
                if state == "open":
                    open_endpoints.append(endpoint)
                    reachable_hosts.add(host)
                    probes_open += 1
                elif state == "closed":
                    reachable_hosts.add(host)
                    probes_closed += 1
                else:
                    probes_filtered += 1

    reachable = len(reachable_hosts)
    # Passively name + risk-score every open endpoint (no extra probes).
    services = [
        {"endpoint": ep, "host": ep.rpartition(":")[0], **_classify_endpoint(ep)}
        for ep in open_endpoints
    ]
    risk_counts: dict[str, int] = {}
    cleartext_services = 0
    ot_services = 0
    for svc in services:
        sev = str(svc.get("severity", "INFO"))
        risk_counts[sev] = risk_counts.get(sev, 0) + 1
        if svc.get("cleartext") or svc.get("status") == "DISALLOWED":
            cleartext_services += 1
        if svc.get("exposure") == "ot-safety" or svc.get("category") == "ot-ics":
            ot_services += 1
    return {
        "cidr": cidr,
        "ports": port_list,
        "hosts_checked": len(hosts),
        "hosts_reachable": reachable,
        "hosts_silent": len(hosts) - reachable,
        "candidates": len(candidates),
        "tcp_probes": {
            "open": probes_open,
            "closed": probes_closed,
            "filtered_timeout": probes_filtered,
        },
        "truncated": truncated,
        "endpoints": open_endpoints,
        "open_count": len(open_endpoints),
        "services": services,
        "risk_counts": risk_counts,
        "cleartext_or_disallowed": cleartext_services,
        "ot_services": ot_services,
    }


def _tcp_probe(endpoint: str, timeout: float) -> str:
    """Classify one host:port probe.

    Returns ``"open"`` when the TCP handshake completes, ``"closed"`` when the
    host explicitly refuses (RST / ECONNREFUSED — the host IS reachable but
    nothing listens), or ``"filtered"`` on a timeout/network-unreachable (the
    host is silent: AP isolation, a drop-all firewall, or absent).
    """
    host, _, port_s = endpoint.rpartition(":")
    try:
        with socket.create_connection((host, int(port_s)), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except TimeoutError:
        return "filtered"
    except OSError as exc:
        # Only an explicit refusal proves a closed listener. Local permission,
        # routing and unknown socket errors do not prove the host answered.
        return "closed" if exc.errno == errno.ECONNREFUSED else "filtered"
