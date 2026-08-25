from shared_models.crypto_asset import CryptoAsset
from shared_models.vulnerability import Vulnerability


def test_shared_crypto_asset_and_vulnerability_dtos():
    asset = CryptoAsset(algorithm="AES", file_path="Pay.java", line_number=10, key_size=256)
    assert asset.to_dict()["algorithm"] == "AES"
    vuln = Vulnerability(cve="CVE-2013-1445", package="pycrypto", severity="MEDIUM")
    assert vuln.to_dict()["cve"] == "CVE-2013-1445"
