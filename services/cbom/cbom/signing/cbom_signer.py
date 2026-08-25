"""HMAC-SHA256 CBOM signatures stored as CycloneDX metadata properties."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator


def sign_cbom(bom: dict[str, Any], secret: str) -> dict[str, Any]:
    return CbomGenerator().sign(bom, secret)


def verify_cbom(bom: dict[str, Any], secret: str) -> bool:
    return CbomGenerator().verify(bom, secret)
