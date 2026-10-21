"""Explicit, bounded IPv4 TCP discovery; never enterprise/plugin expansion.

Range permission and whole-plan policy precede execution. Each range gets a
fresh committed receipt. Results are confined to admitted literal socket pairs;
port classification is not TLS or crypto evidence.
"""

from __future__ import annotations

import ipaddress

from fastapi import HTTPException

from api.security.scan_admission import authorize_network_sweep
from api.security.target_validation import TargetValidationError, validate_network_target

MAX_CANDIDATES = 256


def prepare_scope(config):
    """Return canonical inputs, a range policy spec and exact socket units."""
    if config.get("scope_profile") != "bounded-tcp":
        raise HTTPException(
            409,
            detail="Monitor scope requires explicit scope_profile='bounded-tcp'; enterprise/plugins remain unqualified",
        )
    raw_scopes = config["scope"]
    if isinstance(raw_scopes, str):
        raw_scopes = [raw_scopes]
    if (
        not isinstance(raw_scopes, list)
        or not 1 <= len(raw_scopes) <= MAX_CANDIDATES
        or any(not isinstance(s, str) or not s.strip() for s in raw_scopes)
    ):
        raise HTTPException(422, detail="scope must contain 1-256 IPv4 hosts/CIDRs")
    ports = config.get("scope_ports")
    if (
        not isinstance(ports, list)
        or not 1 <= len(ports) <= 64
        or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
    ):
        raise HTTPException(422, detail="scope_ports must explicitly list 1-64 valid integer TCP ports")
    ports = sorted(set(ports))
    networks = []
    count = 0
    for raw in raw_scopes:
        try:
            network = ipaddress.ip_network(validate_network_target(raw), strict=False)
        except TargetValidationError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        if network.version != 4:
            raise HTTPException(422, detail="Bounded monitor scope supports IPv4 only")
        if network in networks:
            continue
        if any(network.overlaps(other) for other in networks):
            raise HTTPException(422, detail="Overlapping monitor scopes are not admitted")
        hosts = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
        count += hosts * len(ports)
        # Check before enumerating hosts, never materialize an unbounded CIDR.
        if count > MAX_CANDIDATES:
            raise HTTPException(422, detail="Bounded scope exceeds 256 TCP socket candidates")
        networks.append(network)
    scopes = [str(n) for n in networks]
    units = [f"{host}:{port}" for n in networks for host in n.hosts() for port in ports]
    clean = {"scope_profile": "bounded-tcp", "scope": scopes, "scope_ports": ports}
    spec = {
        "targets": scopes,
        "ports": ports,
        "protocol": "tcp",
        "transport": "tcp",
        "purpose": "bounded-tcp-discovery",
    }
    return clean, spec, units


def authorize_scopes(config):
    for cidr in config["scope"]:
        allowed, _ = authorize_network_sweep(cidr)
        if not allowed:
            raise HTTPException(409, detail="Monitor discovery range is outside the authorized network scope")


def _accepted_result(cidr, ports, result):
    """Validate known collector output; retain no arbitrary SDK metadata."""
    network = ipaddress.ip_network(cidr)
    candidates = {f"{host}:{port}" for host in network.hosts() for port in ports}
    hosts = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
    if not isinstance(result, dict) or result.get("error") or result.get("truncated") is not False:
        raise RuntimeError("Monitor scope discovery failed or returned incomplete coverage")
    if (
        result.get("cidr") != cidr
        or result.get("ports") != ports
        or any(type(p) is not int for p in result.get("ports", []))
    ):
        raise RuntimeError("Monitor scope result does not match the admitted range/ports")
    for key, expected in [("hosts_checked", hosts), ("candidates", len(candidates))]:
        if type(result.get(key)) is not int or result[key] != expected:
            raise RuntimeError("Monitor scope returned inconsistent candidate coverage")
    endpoints = result.get("endpoints")
    if (
        not isinstance(endpoints, list)
        or len(endpoints) > len(candidates)
        or any(not isinstance(ep, str) or ep not in candidates for ep in endpoints)
        or len(set(endpoints)) != len(endpoints)
    ):
        raise RuntimeError("Monitor scope returned endpoints outside admitted socket candidates")
    counts = result.get("tcp_probes")
    if (
        not isinstance(counts, dict)
        or any(type(counts.get(k)) is not int or counts[k] < 0 for k in ("open", "closed", "filtered_timeout"))
        or sum(counts[k] for k in ("open", "closed", "filtered_timeout")) != len(candidates)
        or counts["open"] != len(endpoints)
        or type(result.get("open_count")) is not int
        or result["open_count"] != len(endpoints)
    ):
        raise RuntimeError("Monitor scope returned inconsistent TCP outcome counts")
    return {
        "cidr": cidr,
        "ports": list(ports),
        "hosts_checked": hosts,
        "candidates": len(candidates),
        "truncated": False,
        "endpoints": list(endpoints),
        "open_count": len(endpoints),
        "tcp_probes": {k: counts[k] for k in ("open", "closed", "filtered_timeout")},
        "evidence_kind": "TCP_CONNECT_ONLY",
        "tls_status": "NOT_EVALUATED",
    }


def collect(execution):
    from network_scanner.discovery.subnet_discoverer import discover_subnet

    config = execution.plan.config
    results = []
    for cidr in config["scope"]:
        execution.before_phase("scope", execution_range=cidr)
        raw = discover_subnet(
            cidr,
            config["scope_ports"],
            timeout=config["timeout"],
            workers=config["workers"],
            max_targets=MAX_CANDIDATES,
        )
        results.append(_accepted_result(cidr, config["scope_ports"], raw))
    return results
