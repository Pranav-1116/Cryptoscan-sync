from deduplication.confidence.confidence_matrix import merged_confidence_from_sources
from deduplication.fingerprinting.location_normalizer import normalize_file_path
from deduplication.merging.asset_creator import create_asset
from deduplication.models.crypto_asset import CryptoAsset


def test_location_normalizer_and_asset_creator():
    assert normalize_file_path("/repo/src/Pay.java", repo_root="/repo") == "src/Pay.java"
    assert normalize_file_path("/var/lib/app", source_type="CONTAINER_IMAGE") == "CONTAINER"
    finding = {
        "finding_id": "e1",
        "scanner_id": "static-java-scanner-v1.0",
        "source": {"file_path": "Pay.java", "line_number": 10, "language": "JAVA"},
        "crypto": {"algorithm": "AES", "purpose": "ENCRYPTION", "mode": "GCM"},
        "metadata": {"confidence": "HIGH"},
    }
    asset = create_asset(finding)
    assert asset["algorithm"] == "AES"
    assert asset["primary_evidence_id"] == "e1"
    model = CryptoAsset.from_dict(asset)
    assert model.to_dict()["algorithm"] == "AES"
    assert (
        merged_confidence_from_sources(
            [
                {"scanner_id": "static-java-scanner-v1.0", "confidence": "HIGH"},
                {"scanner_id": "container-scanner-v1.0", "confidence": "MEDIUM"},
            ]
        )
        == "VERIFIED"
    )
