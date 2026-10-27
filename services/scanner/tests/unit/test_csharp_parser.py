from scanner.parsers.csharp_parser import parse_csharp_file


def test_csharp_parser_finds_des_and_rsa(temp_workspace):
    path = temp_workspace / "CryptoUtil.cs"
    path.write_text(
        """
using System.Security.Cryptography;
class C {
  void Run() {
    DES.Create();
    Aes.Create();
    MD5.Create();
    RSA.Create(2048);
    var aes = Aes.Create();
    aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  }
}
"""
    )
    findings = parse_csharp_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "DES" in algos
    assert "AES" in algos
    assert "MD5" in algos
    rsa = next(f for f in findings if f.crypto.algorithm == "RSA")
    assert rsa.crypto.key_size == 2048
    assert any(f.metadata.is_hardcoded_key for f in findings)


def test_csharp_parser_finds_nsec(temp_workspace):
    path = temp_workspace / "NsecUtil.cs"
    path.write_text(
        """
using NSec.Cryptography;
class C {
  void Run() {
    var aead = AeadAlgorithm.ChaCha20Poly1305;
    var mac = NSec.Cryptography.HmacSha256;
    var sig = Ed25519;
  }
}
"""
    )
    findings = parse_csharp_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "ChaCha20-Poly1305" in algos
    assert "HMAC-SHA256" in algos
    assert "Ed25519" in algos
    assert all(f.metadata.library == "NSec" for f in findings)


def test_csharp_ignores_commented_aes(temp_workspace):
    path = temp_workspace / "Comments.cs"
    path.write_text(
        """
using System.Security.Cryptography;
class C {
  void Run() {
    // Aes.Create();
    /* DES.Create(); */
    SHA256.Create();
  }
}
"""
    )
    findings = parse_csharp_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "SHA-256" in algos
    assert "AES" not in algos
    assert "DES" not in algos
