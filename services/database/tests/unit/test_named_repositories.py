from db.models.crypto_asset import CryptoAsset
from db.repositories.asset_evidence_link_repository import AssetEvidenceLinkRepository
from db.repositories.business_owner_repository import BusinessOwnerRepository
from db.repositories.cloud_account_repository import CloudAccountRepository
from db.repositories.crypto_asset_repository import CryptoAssetRepository
from db.repositories.fingerprint_repository import FingerprintRepository
from db.repositories.network_scan_target_repository import NetworkScanTargetRepository
from db.repositories.vendor_repository import VendorRepository


def test_crypto_asset_and_evidence_link(db_session):
    assets = CryptoAssetRepository(db_session)
    row = assets.create(
        CryptoAsset(algorithm="AES", purpose="ENCRYPTION", file_path="Pay.java", line_number=10, confidence="HIGH")
    )
    links = AssetEvidenceLinkRepository(db_session)
    links.link(row.id, "evidence-1")
    assert links.evidence_ids_for(row.id) == ["evidence-1"]
    listed, total = assets.list_assets(algorithm="AES")
    assert total == 1
    assert listed[0].algorithm == "AES"


def test_intelligence_named_repos(db_session):
    owners = BusinessOwnerRepository(db_session).create_owner(name="Alice", email="alice@example.com")
    assert owners.email == "alice@example.com"
    account = CloudAccountRepository(db_session).create_account(
        cloud_provider="AWS", account_identifier="123456789012"
    )
    assert account.cloud_provider == "AWS"
    target = NetworkScanTargetRepository(db_session).upsert("api.example.com:443")
    assert target.endpoint == "api.example.com:443"
    vendor = VendorRepository(db_session).create_vendor("Acme", criticality="HIGH")
    assert vendor.name == "Acme"
    catalog = FingerprintRepository(db_session)
    assert catalog.canonical("libssl3") == "openssl"
