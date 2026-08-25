"""Build a CycloneDX cryptographic-asset component from an evidence record."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator


def build_component(record: Any) -> dict[str, Any]:
    return CbomGenerator()._component(record)
