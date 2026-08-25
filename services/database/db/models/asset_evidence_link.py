"""Spec-named alias of the crypto_asset_evidence join table."""

from db.models.crypto_asset_evidence import CryptoAssetEvidence

AssetEvidenceLink = CryptoAssetEvidence

__all__ = ["AssetEvidenceLink", "CryptoAssetEvidence"]
