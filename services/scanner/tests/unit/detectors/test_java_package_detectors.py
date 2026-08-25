from pathlib import Path

from scanner.detectors.java.cipher_detector import CipherDetector
from scanner.detectors.java.hardcoded_key_detector import HardcodedKeyDetector
from scanner.detectors.java.key_generator_detector import KeyGeneratorDetector
from scanner.detectors.java.message_digest_detector import MessageDigestDetector
from scanner.detectors.java.signature_detector import SignatureDetector


def test_java_package_detectors_split_by_api(tmp_path: Path):
    java = tmp_path / "Pay.java"
    java.write_text(
        """
class Pay {
    void t() throws Exception {
        javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        java.security.MessageDigest.getInstance("MD5");
        javax.crypto.KeyGenerator.getInstance("AES");
        java.security.Signature.getInstance("SHA256withRSA");
        new javax.crypto.spec.SecretKeySpec("secret12".getBytes(), "AES");
    }
}
""",
        encoding="utf-8",
    )
    assert any(f.crypto.algorithm == "DES" for f in CipherDetector().detect(java, repo_root=tmp_path))
    assert any(f.crypto.algorithm == "MD5" for f in MessageDigestDetector().detect(java, repo_root=tmp_path))
    assert KeyGeneratorDetector().detect(java, repo_root=tmp_path)
    assert SignatureDetector().detect(java, repo_root=tmp_path)
    assert any(f.metadata.is_hardcoded_key for f in HardcodedKeyDetector().detect(java, repo_root=tmp_path))
