"""Spec-named CRUD wrapper for crypto_assets."""

from __future__ import annotations

from db.repositories.asset_repository import AssetRepository

CryptoAssetRepository = AssetRepository

__all__ = ["AssetRepository", "CryptoAssetRepository"]
