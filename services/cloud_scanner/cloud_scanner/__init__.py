"""Cloud and IaC cryptographic configuration scanner."""

from __future__ import annotations

__all__ = ["CloudScanner"]


def __getattr__(name: str):
    if name == "CloudScanner":
        from cloud_scanner.core.scanner import CloudScanner

        return CloudScanner
    raise AttributeError(name)
