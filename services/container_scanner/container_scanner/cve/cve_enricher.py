"""Alias for the NVD/OSV vulnerability resolver."""

from container_scanner.cve.resolver import VulnerabilityResolver

CveEnricher = VulnerabilityResolver

__all__ = ["CveEnricher", "VulnerabilityResolver"]
