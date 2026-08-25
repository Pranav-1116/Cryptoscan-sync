"""Spec-named alias of the system_assets join table."""

from db.models.system_asset import SystemAsset

AssetSystemLink = SystemAsset

__all__ = ["AssetSystemLink", "SystemAsset"]
