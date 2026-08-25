"""Validate a CycloneDX 1.5 CBOM document."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator


def validate_cbom(bom: dict[str, Any]) -> dict[str, Any]:
    return CbomGenerator().validate(bom)
