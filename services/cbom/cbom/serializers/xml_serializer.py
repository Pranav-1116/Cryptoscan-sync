"""Serialize a CBOM dict to CycloneDX 1.5 XML."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator


def to_xml(bom: dict[str, Any]) -> str:
    return CbomGenerator().to_xml(bom)
