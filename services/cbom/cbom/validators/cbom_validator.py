"""Named CycloneDX CBOM validator."""

from __future__ import annotations

from typing import Any

from cbom.validator import validate_cbom


class CbomValidator:
    def validate(self, bom: dict[str, Any]) -> dict[str, Any]:
        return validate_cbom(bom)


def validate(bom: dict[str, Any]) -> dict[str, Any]:
    return CbomValidator().validate(bom)
