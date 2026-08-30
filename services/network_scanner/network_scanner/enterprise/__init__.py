"""Enterprise network discovery architecture.

Global Network Target Discovery → Active/Passive/Vendor/Controller Discovery
→ Asset Registry → Protocol Detection → CryptoObservation → Evidence Layer →
Dependency Graph → CBOM → PQC Risk & Simulation.
"""

from network_scanner.enterprise.engine import GlobalNetworkDiscoveryEngine, run_network_discovery
from network_scanner.enterprise.target_spec import (
    SCOPES,
    TargetSpec,
    classify_target,
    parse_many,
    parse_scope_spec,
    parse_target_spec,
)
from network_scanner.enterprise.assets import NetworkAsset, AssetRegistry
from network_scanner.enterprise.scan_modes import MODES, ScanMode, ScanAuthorization
from network_scanner.enterprise.credentials import CredentialRef, CredentialVault, scrub_secrets
from network_scanner.enterprise.topology import NetworkGraph, RELATIONSHIPS

__all__ = [
    "GlobalNetworkDiscoveryEngine",
    "run_network_discovery",
    "SCOPES",
    "TargetSpec",
    "classify_target",
    "parse_many",
    "parse_scope_spec",
    "parse_target_spec",
    "NetworkAsset",
    "AssetRegistry",
    "MODES",
    "ScanMode",
    "ScanAuthorization",
    "CredentialRef",
    "CredentialVault",
    "scrub_secrets",
    "NetworkGraph",
    "RELATIONSHIPS",
]
