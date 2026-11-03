"""The adapter registry: every control type, every dialect, one addressable surface.

The registry exists so the layer can be *interrogated* rather than trusted: a reviewer (or
the guide harness) can ask which adapters exist, what each one reads, which operations it
declares, and which values it refuses. Nothing registers itself at import time and nothing is
discovered by scanning — an adapter the registry does not name cannot be used, which is how a
new vendor gets reviewed instead of appearing.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import (api_gateway, firewall, ids, ips, load_balancer, rate_limit, siem, vpn, waf)
from .base import CONTROL_TYPES, ControlRefused, _norm

#: control type → the package that speaks it
PACKAGES: dict[str, Any] = {
    "FIREWALL": firewall,
    "IDS": ids,
    "IPS": ips,
    "WAF": waf,
    "LOAD_BALANCER": load_balancer,
    "API_GATEWAY": api_gateway,
    "RATE_LIMIT": rate_limit,
    "VPN": vpn,
    "SIEM": siem,
}

#: the controls whose collectors live in a sibling service (key assurance) — named here so
#: the catalogue can say "not in this release" instead of pretending they do not exist
DEFERRED: dict[str, str] = {
    "HSM": "cbom.hsm_pkcs11 + keyassure (read-only key metadata already exists)",
    "KMS": "cbom.kms_collectors + cbom.kmip (read-only key metadata already exists)",
    "PKI": "cbom.certificate_chain (chain and validity already exist)",
    "NETWORK": "cbom.nbom_graph (passive observation already exists)",
}


def controls() -> dict[str, Any]:
    """Every control type, and what speaks it."""
    out: dict[str, Any] = {}
    for control in CONTROL_TYPES:
        package = PACKAGES.get(control)
        if package is None:
            out[control] = {"implemented": False, "reason": DEFERRED.get(control),
                            "adapters": {}}
            continue
        out[control] = {
            "implemented": True,
            "collects": list(getattr(package, "COLLECTS", ())),
            "must_not": list(getattr(package, "MUST_NOT", ())),
            "adapters": package.dialects(),
        }
    return out


def adapters() -> dict[str, Any]:
    return {key: spec.capabilities() for key, spec in _specs().items()}


def _specs() -> dict[str, Any]:
    specs: dict[str, Any] = {}
    for package in PACKAGES.values():
        for name, spec in package.SPECS.items():
            specs[f"{package.CONTROL.lower()}:{name}"] = spec
    return specs


def spec_for(control: Any, vendor: Any) -> Any:
    control_text = _norm(control).upper()
    package = PACKAGES.get(control_text)
    if package is None:
        if control_text in DEFERRED:
            raise ControlRefused(
                "CONTROL_DEFERRED",
                f"{control_text} is collected by {DEFERRED[control_text]}; this layer does "
                "not re-collect it, it correlates what that path already produces")
        raise ControlRefused("UNKNOWN_CONTROL",
                             f"{control_text or '(none)'} is not a control type with an "
                             f"adapter; the registry has {', '.join(sorted(PACKAGES))}")
    return package.spec_for(vendor)


def collector(control: Any, vendor: Any, feed: Mapping[str, Any] | None = None) -> Any:
    """Build a collector for one control and vendor, with that vendor's vocabulary."""
    control_text = _norm(control).upper()
    spec_for(control_text, vendor)  # validates vendor before anything is constructed
    package = PACKAGES[control_text]
    return package.collector(vendor, feed)


def fleet(entries: list[Mapping[str, Any]]) -> list[Any]:
    """Build many collectors from ``[{"control", "vendor", "feed"}, …]``."""
    made: list[Any] = []
    for entry in entries or []:
        made.append(collector(entry.get("control"), entry.get("vendor"),
                              entry.get("feed") or {}))
    return made


def read_only_audit() -> dict[str, Any]:
    """The whole declared surface, checked for a write. The harness runs this as one probe."""
    offending: list[dict[str, Any]] = []
    operations: set[str] = set()
    for key, spec in _specs().items():
        capabilities = spec.capabilities()
        operations.update(capabilities["read_operations"])
        if capabilities["write_operations"]:
            offending.append({"adapter": key,
                              "writes": capabilities["write_operations"]})
    return {
        "adapters": len(_specs()),
        "controls": sorted(PACKAGES),
        "deferred": sorted(DEFERRED),
        "read_operations": sorted(operations),
        "adapters_with_writes": offending,
        "read_only": not offending,
    }
