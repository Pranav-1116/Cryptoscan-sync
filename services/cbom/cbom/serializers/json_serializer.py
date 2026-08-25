"""Serialize a CBOM dict to CycloneDX JSON."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator


def to_json(bom: dict[str, Any]) -> str:
    return CbomGenerator().to_json(bom)
