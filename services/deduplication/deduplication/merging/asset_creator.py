"""Create a new crypto_asset from a single evidence finding."""

from __future__ import annotations

from typing import Any

from deduplication.core.engine import DeduplicationEngine


def create_asset(finding: dict[str, Any]) -> dict[str, Any]:
    assets = DeduplicationEngine().merge([finding])
    if not assets:
        raise ValueError("finding did not produce an asset")
    asset = dict(assets[0])
    asset.setdefault("asset_type", "ALGORITHM_USE")
    return asset


def create_assets(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return DeduplicationEngine().merge(findings)
