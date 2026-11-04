"""The adapter registry: every control type, every dialect, one addressable surface.

The registry exists so the layer can be *interrogated* rather than trusted: a reviewer (or
the guide harness) can ask which adapters exist, what each one reads, which operations it
declares, and which values it refuses. Nothing registers itself at import time and nothing is
discovered by scanning — an adapter the registry does not name cannot be used, which is how a
new vendor gets reviewed instead of appearing.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import (api_gateway, firewall, facade, ids, ips, load_balancer, rate_limit, siem, vpn,
               waf)
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

#: controls read through a **facade** over an existing collector (guide 182). They were
#: ``DEFERRED`` in guide 181; the facade gives them the six-verb shape without re-reading a
#: device, which is the difference between coverage and a second ingestion path.
FACADE_CONTROLS: dict[str, str] = {
    "HSM": "cbom.hsm_pkcs11",
    "KMS": "cbom.kms_collectors + cbom.kmip",
    "PKI": "cbom.certificate_chain",
    "NETWORK": "cbom.nbom_graph",
}

#: kept for callers that still want to know which module owns a control's analysis
DEFERRED: dict[str, str] = dict(FACADE_CONTROLS)


def controls() -> dict[str, Any]:
    """Every control type, and what speaks it."""
    out: dict[str, Any] = {}
    for control in CONTROL_TYPES:
        if control in FACADE_CONTROLS:
            cls = facade.FACADES[control]
            out[control] = {
                "implemented": True,
                "facade": True,
                "delegates_to": list(cls.delegates),
                "reason": f"re-shapes {FACADE_CONTROLS[control]}; it reads no device itself",
                "collects": list(facade.FACADE_CONTRACT[control]["collects"]),
                "must_not": list(facade.FACADE_CONTRACT[control]["must_not"]),
                "adapters": {f"{control.lower()}.existing-collectors":
                             facade.facade_spec(control).capabilities()},
            }
            continue
        package = PACKAGES.get(control)
        if package is None:
            out[control] = {"implemented": False, "reason": None, "adapters": {}}
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
    for control in FACADE_CONTROLS:
        spec = facade.facade_spec(control)
        specs[f"{control.lower()}:existing-collectors"] = spec
    return specs


def spec_for(control: Any, vendor: Any) -> Any:
    control_text = _norm(control).upper()
    if control_text in FACADE_CONTROLS:
        wanted = _norm(vendor).lower()
        if wanted in {"existing-collectors", "existing", "(the platform's own collectors)",
                      "", "facade"}:
            return facade.facade_spec(control_text)
        raise ControlRefused(
            "FACADE_HAS_NO_VENDOR",
            f"{control_text} is read through a facade over {FACADE_CONTROLS[control_text]}; "
            "it has no vendor dialect of its own, so asking for "
            f"{_norm(vendor) or '(none)'} names an integration that does not exist")
    package = PACKAGES.get(control_text)
    if package is None:
        raise ControlRefused("UNKNOWN_CONTROL",
                             f"{control_text or '(none)'} is not a control type with an "
                             f"adapter; the registry has "
                             f"{', '.join(sorted([*PACKAGES, *FACADE_CONTROLS]))}")
    return package.spec_for(vendor)


def collector(control: Any, vendor: Any, feed: Mapping[str, Any] | None = None) -> Any:
    """Build a collector for one control and vendor, with that vendor's vocabulary."""
    control_text = _norm(control).upper()
    spec = spec_for(control_text, vendor)  # validates vendor before anything is constructed
    if control_text in FACADE_CONTROLS:
        return facade.FACADES[control_text](spec, feed)
    return PACKAGES[control_text].collector(vendor, feed)


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
        "controls": sorted([*PACKAGES, *FACADE_CONTROLS]),
        "device_controls": sorted(PACKAGES),
        "facade_controls": sorted(FACADE_CONTROLS),
        "deferred": [],
        "read_operations": sorted(operations),
        "adapters_with_writes": offending,
        "read_only": not offending,
    }
