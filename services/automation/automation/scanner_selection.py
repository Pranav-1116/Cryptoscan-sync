"""Deterministic automatic scanner selection (no AI/ML).

For every discovered asset the automation engine decides which scanners are
applicable from the asset's explicit classification and observed capabilities
(no administrator picks scanners by hand). Selection is pure rule evaluation:
an asset type contributes a base scanner set; observed attributes
(vendors, platforms, protocols, cloud tags, HSM/TPM markers, certificates,
container/repo flags) add scanners on top. The result is deterministic — the same
asset always selects the same scanner set — and explainable via returned reasons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class Scanner(str, Enum):
    NETWORK = "network_scanner"
    CLOUD = "cloud_scanner"
    CONTAINER = "container_scanner"
    HOST = "host_scanner"
    CRYPTO = "crypto_scanner"
    VENDOR = "vendor_scanner"
    PROTOCOL = "protocol_scanner"
    CERTIFICATE = "certificate_scanner"
    OT = "ot_scanner"
    LIBRARY = "library_scanner"
    APPLICATION = "application_scanner"
    HARDWARE = "hardware_scanner"
    PAYMENT = "payment_scanner"


#: base scanners that almost always apply to a networked asset (observability)
COMMON_SCOPES = frozenset({Scanner.CRYPTO, Scanner.LIBRARY})


#: asset kind -> base scanner set (the minimum that always applies).
BASE_SCOPERS: dict[str, frozenset[Scanner]] = {
    "network_device": frozenset({Scanner.NETWORK, Scanner.VENDOR, Scanner.PROTOCOL,
                                 Scanner.CRYPTO, Scanner.CERTIFICATE}),
    "router": frozenset({Scanner.NETWORK, Scanner.VENDOR, Scanner.PROTOCOL,
                         Scanner.CRYPTO, Scanner.CERTIFICATE}),
    "firewall": frozenset({Scanner.NETWORK, Scanner.VENDOR, Scanner.CRYPTO,
                           Scanner.CERTIFICATE}),
    "load_balancer": frozenset({Scanner.NETWORK, Scanner.CERTIFICATE, Scanner.CRYPTO}),
    "cloud_instance": frozenset({Scanner.CLOUD, Scanner.HOST, Scanner.APPLICATION,
                                 Scanner.CRYPTO, Scanner.CERTIFICATE}),
    "cloud_resource": frozenset({Scanner.CLOUD, Scanner.CRYPTO, Scanner.CERTIFICATE}),
    "cloud_storage": frozenset({Scanner.CLOUD}),
    "container_image": frozenset({Scanner.CONTAINER, Scanner.CRYPTO, Scanner.LIBRARY}),
    "container_registry": frozenset({Scanner.CONTAINER, Scanner.CLOUD}),
    "application": frozenset({Scanner.APPLICATION, Scanner.CRYPTO, Scanner.LIBRARY,
                              Scanner.CERTIFICATE}),
    "source_repo": frozenset({Scanner.APPLICATION, Scanner.CRYPTO, Scanner.LIBRARY}),
    "ot_device": frozenset({Scanner.OT, Scanner.PROTOCOL, Scanner.HARDWARE,
                            Scanner.CRYPTO}),
    "plc": frozenset({Scanner.OT, Scanner.PROTOCOL, Scanner.HARDWARE, Scanner.CRYPTO}),
    "hsm": frozenset({Scanner.HARDWARE, Scanner.CRYPTO, Scanner.CERTIFICATE,
                      Scanner.VENDOR}),
    "hardware_module": frozenset({Scanner.HARDWARE, Scanner.VENDOR, Scanner.CRYPTO}),
    "certificate": frozenset({Scanner.CERTIFICATE}),
    "host": frozenset({Scanner.HOST, Scanner.CRYPTO, Scanner.LIBRARY,
                       Scanner.APPLICATION}),
    "database": frozenset({Scanner.HOST, Scanner.CRYPTO, Scanner.APPLICATION}),
    "payment_system": frozenset({Scanner.PAYMENT, Scanner.CRYPTO, Scanner.HARDWARE,
                                 Scanner.CERTIFICATE}),
}

#: keyword markers on observed attributes that imply a capability -> scanner.
_MARKER_RULES: tuple[tuple[str, Scanner], ...] = (
    ("aws", Scanner.CLOUD), ("azure", Scanner.CLOUD), ("gcp", Scanner.CLOUD),
    ("ec2", Scanner.CLOUD), ("s3", Scanner.CLOUD), ("amazon", Scanner.CLOUD),
    ("docker", Scanner.CONTAINER), ("container", Scanner.CONTAINER),
    ("kubernetes", Scanner.CONTAINER), ("registry", Scanner.CONTAINER),
    ("tls", Scanner.CERTIFICATE), ("ssl", Scanner.CERTIFICATE),
    ("x509", Scanner.CERTIFICATE), ("certificate", Scanner.CERTIFICATE),
    ("hsm", Scanner.HARDWARE), ("tpm", Scanner.HARDWARE),
    ("modbus", Scanner.PROTOCOL), ("dnp3", Scanner.PROTOCOL), ("opc-ua", Scanner.OT),
    ("cisco", Scanner.VENDOR), ("juniper", Scanner.VENDOR), ("fortinet", Scanner.VENDOR),
    ("paloalto", Scanner.VENDOR), ("f5", Scanner.VENDOR),
)


@dataclass
class SelectionResult:
    asset_id: str
    asset_kind: str
    scanners: list[str]
    reasons: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_kind": self.asset_kind,
            "scanners": self.scanners,
            "reasons": self.reasons,
            "scanner_count": len(self.scanners),
        }


def _norm_kind(asset: dict[str, Any]) -> str:
    kind = str(asset.get("asset_kind") or asset.get("kind")
               or asset.get("type") or asset.get("resource_type") or "host")
    return kind.strip().lower().replace(" ", "_").replace("-", "_")


def _attribute_text(asset: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("vendor", "vendor_name", "manufacturer", "platform", "cloud_provider",
                "device_type", "service", "protocols", "tags", "name", "os",
                "resource_type", "asset_kind"):
        v = asset.get(key)
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            parts.extend(str(x) for x in v)
        else:
            parts.append(str(v))
    return " ".join(parts).lower()


def select_scanners(asset: dict[str, Any]) -> SelectionResult:
    """Deterministically choose the applicable scanners for one asset."""
    asset_id = str(asset.get("id") or asset.get("asset_id") or "?")
    kind = _norm_kind(asset)
    reasons: dict[str, str] = {}
    chosen: set[Scanner] = set()

    base = BASE_SCOPERS.get(kind)
    if base is None:
        base = COMMON_SCOPES
        reasons.setdefault(Scanner.CRYPTO.value, f"unknown asset kind '{kind}': default crypto scan")
    else:
        reasons.setdefault("base", f"asset kind '{kind}' implies {len(base)} base scanners")
    chosen |= base

    text = _attribute_text(asset)
    for marker, scanner in _MARKER_RULES:
        if marker in text and scanner not in chosen:
            chosen.add(scanner)
            reasons.setdefault(scanner.value, f"observed capability marker '{marker}'")

    # explicit capability flags
    if asset.get("is_ot") or asset.get("operational_technology"):
        chosen.add(Scanner.OT)
    if asset.get("has_certificates") or asset.get("exposes_tls"):
        chosen.add(Scanner.CERTIFICATE)
    if asset.get("has_hsm") or asset.get("has_tpm"):
        chosen.add(Scanner.HARDWARE)
    if asset.get("is_payment") or asset.get("payment_card"):
        chosen.add(Scanner.PAYMENT)

    # order deterministically for stable, diff-able output
    ordered = sorted(s.value for s in chosen)
    return SelectionResult(asset_id=asset_id, asset_kind=kind,
                           scanners=ordered, reasons=reasons)


def select_for_many(assets: Iterable[dict[str, Any]]) -> list[SelectionResult]:
    return [select_scanners(a) for a in assets]
