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


# --- vendored / forked crypto implementations ---------------------------- #
# A .NET estate that ships its own BouncyCastle fork implements the primitive
# rather than calling it. bc-csharp's own AesEngine.cs reported no AES at all
# until these rules existed (see docs/accuracy/EXTERNAL-VALIDATION.md round 2).

def test_csharp_engine_class_implementing_interface_is_an_aes_implementation(temp_workspace):
    path = temp_workspace / "AesEngine.cs"
    path.write_text(
        """
namespace Org.BouncyCastle.Crypto.Engines {
  public sealed class AesEngine
      : IBlockCipher
  {
    public string AlgorithmName => "AES";
  }
}
"""
    )
    findings = parse_csharp_file(path, temp_workspace)
    assert "AES" in {f.crypto.algorithm for f in findings}
    assert any(f.crypto.purpose == "ALGORITHM_IMPLEMENTATION" for f in findings)


def test_csharp_engine_extending_another_engine_is_detected(temp_workspace):
    """DesEdeEngine extends DesEngine, not an interface."""
    path = temp_workspace / "DesEdeEngine.cs"
    path.write_text("public class DesEdeEngine\n    : DesEngine\n{\n}\n")
    findings = parse_csharp_file(path, temp_workspace)
    assert "3DES" in {f.crypto.algorithm for f in findings}


def test_csharp_digest_class_is_detected(temp_workspace):
    path = temp_workspace / "Sha256Digest.cs"
    path.write_text("public class Sha256Digest : GeneralDigest, IDigest\n{\n}\n")
    findings = parse_csharp_file(path, temp_workspace)
    assert "SHA-256" in {f.crypto.algorithm for f in findings}


def test_csharp_non_crypto_class_named_like_an_engine_is_not_reported(temp_workspace):
    """Precision guard: the stem must resolve to a known algorithm."""
    path = temp_workspace / "TemplateEngine.cs"
    path.write_text("public class TemplateEngine : IRenderEngine\n{\n}\n")
    findings = parse_csharp_file(path, temp_workspace)
    assert not [f for f in findings if f.crypto.purpose == "ALGORITHM_IMPLEMENTATION"]
