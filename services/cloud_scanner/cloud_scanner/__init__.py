"""Cloud and IaC cryptographic configuration scanner."""

from __future__ import annotations

__all__ = ["CloudScanner", "ZelixCloudDiscoveryEngine"]


def __getattr__(name: str):
    if name == "CloudScanner":
        from cloud_scanner.core.scanner import CloudScanner

        return CloudScanner
    if name == "ZelixCloudDiscoveryEngine":
        from cloud_scanner.enterprise import ZelixCloudDiscoveryEngine

        return ZelixCloudDiscoveryEngine
    raise AttributeError(name)
