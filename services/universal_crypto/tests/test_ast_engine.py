"""§4/§5 AST engine — semantic detection, precision rules, 18 languages."""

from __future__ import annotations


from universal_crypto.ast_engine import CryptoAstEngine, LANGUAGES
from universal_crypto.models import Operation

ENGINE = CryptoAstEngine()


def _algorithms(language: str, text: str) -> list[dict]:
    return ENGINE.detect_file(language=language, text=text, location="app")


def test_python_semantic_detection():
    hits = _algorithms("python", "import hashlib\nh = hashlib.sha256(data).hexdigest()")
    assert hits[0]["algorithm"] == "SHA-256"
    assert hits[0]["operation"] == Operation.HASH
    assert hits[0]["library"] == "hashlib"


def test_python_crypto_kit_detection():
    hits = _algorithms("python", "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                                  "aesgcm = AESGCM(key)")
    assert {h["algorithm"] for h in hits} == {"AES-GCM"}


def test_java_jce_detection():
    hits = _algorithms("java", "Signature sig = Signature.getInstance(\"SHA256withRSA\");")
    assert hits[0]["algorithm"] == "RSA-PSS"
    assert hits[0]["library"] == "JCA-JCE"


def test_go_import_and_call_on_separate_lines():
    hits = _algorithms("go", "import \"crypto/sha256\"\nh := sha256.Sum256(data)")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}


def test_tls_config_detection_go():
    hits = _algorithms("go", "import \"crypto/tls\"\ncfg := &tls.Config{MinVersion: tls.VersionTLS12}")
    assert {h["algorithm"] for h in hits} == {"TLS"}


def test_c_openssl_detection():
    hits = _algorithms("c", "#include <openssl/evp.h>\nEVP_DigestInit_ex(ctx, EVP_sha256(), NULL);")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}


def test_csharp_detection():
    hits = _algorithms("csharp", "using System.Security.Cryptography;\nvar sha = SHA256.Create();")
    assert hits[0]["algorithm"] == "SHA-256"
    assert hits[0]["library"] == ".NET cryptography"


def test_solidity_detection():
    hits = _algorithms("solidity", "bytes32 h = keccak256(abi.encodePacked(a, b));")
    assert {h["algorithm"] for h in hits} == {"Keccak-256"}


def test_precision_rule_custom_hash_never_classified():
    # §5: custom code near "sha" text must NOT become SHA-256
    hits = _algorithms("python", "def custom_hash(data):\n    return data % 97")
    assert hits == []
    hits = _algorithms("python", "def sha256(x):\n    return my_impl(x)")
    assert hits == []


def test_comments_are_never_detections():
    hits = _algorithms("python", "# hashlib.sha256(data) is used by the data team")
    assert hits == []
    hits = _algorithms("java", "// MessageDigest.getInstance(\"SHA-256\") — doc only")
    assert hits == []


def test_doc_mention_is_not_detection():
    hits = _algorithms("python", "result = \"RSA\" in report_text")
    assert hits == []


def test_whitespace_tolerance():
    hits = _algorithms("python", "h = hashlib . sha256 ( data )")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}


def test_eighteen_languages_registered():
    assert len(LANGUAGES) == 18
    assert set(LANGUAGES) == {
        "python", "java", "javascript", "typescript", "c", "c++", "csharp",
        "go", "rust", "swift", "kotlin", "php", "ruby", "scala", "haskell",
        "solidity", "vyper", "dart",
    }


def test_unknown_language_is_noop():
    assert ENGINE.detect_file(language="brainfuck", text="sha256") == []


def test_dedupes_same_call():
    hits = _algorithms("python", "hashlib.sha256(a)\nhashlib.sha256(b)")
    assert len(hits) == 1


def test_typescript_node_crypto():
    hits = _algorithms("typescript",
                       "import * as crypto from 'crypto'\n"
                       "const h = crypto.createHash('sha256').update(data).digest('hex');")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}


def test_typescript_double_quotes():
    hits = _algorithms("typescript",
                       'const h = crypto.createHash("sha256").digest("hex");')
    assert {h["algorithm"] for h in hits} == {"SHA-256"}


def test_typescript_destructured_import():
    hits = _algorithms("typescript",
                       "import { createHash } from 'node:crypto';\n"
                       "const h = createHash('sha256', data).digest('hex');")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}
    hits = _algorithms("typescript",
                       "import { createCipheriv } from 'crypto';\n"
                       "createCipheriv('aes-256-gcm', key, iv)")
    assert {h["algorithm"] for h in hits} == {"AES-GCM"}


def test_cpp_openssl():
    hits = _algorithms("c++", "#include <openssl/evp.h>\nEVP_DigestInit_ex(ctx, EVP_sha256(), NULL);")
    assert hits[0]["algorithm"] == "SHA-256"
    assert hits[0]["library"] == "OpenSSL"


def test_kotlin_and_scala_jca():
    hits = _algorithms("kotlin", "MessageDigest.getInstance(\"SHA-256\")")
    assert hits[0]["algorithm"] == "SHA-256"
    assert hits[0]["library"] == "JCA-JCE"
    hits = _algorithms("scala", "MessageDigest.getInstance(\"SHA-256\")")
    assert hits[0]["algorithm"] == "SHA-256"


def test_haskell_cryptonite_digest():
    hits = _algorithms("haskell",
                       "import qualified Crypto.Hash as H\n"
                       "let d = H.hash x :: H.Digest H.SHA256")
    assert hits[0]["algorithm"] == "SHA-256"
    assert hits[0]["library"] == "cryptonite"


def test_superset_language_comments_still_ignored():
    assert _algorithms("typescript", "// crypto.createHash('sha256') doc only") == []
    assert _algorithms("c++", "/* EVP_sha256() */") == []
    assert _algorithms("haskell", "-- H.Digest H.SHA256 in a comment") == []


def test_composite_enrichment_padding_and_digest():
    # §3 shape: RSA-PSS with padding + digest from the JCA composite name
    hits = _algorithms("java",
                       'Signature sig = Signature.getInstance("SHA384withRSA");')
    assert hits[0]["algorithm"] == "RSA-PSS"
    assert hits[0]["padding"] == "RSA-PSS"
    assert hits[0]["digest"] == "SHA-384"


def test_ecdsa_digest_extraction():
    hits = _algorithms("java",
                       'Signature.getInstance("SHA256withECDSA")')
    assert hits[0]["algorithm"] == "ECDSA"
    assert hits[0]["digest"] == "SHA-256"


def test_oaep_digest_extraction():
    hits = _algorithms("java",
                       'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")')
    assert hits[0]["algorithm"] == "RSA-OAEP"
    assert hits[0]["padding"] == "RSA-OAEP"
    assert hits[0]["digest"] == "SHA-256"


def test_pbkdf2_digest_extraction():
    hits = _algorithms("python",
                       "dk = hashlib.pbkdf2_hmac('sha512', password, salt, 100_000)")
    assert hits[0]["algorithm"] == "PBKDF2"
    assert hits[0]["digest"] == "SHA-512"


# ── Dart (the 18th §4 language) ────────────────────────────────────────

def test_dart_crypto_package_detection():
    hits = _algorithms("dart", "import 'package:crypto/crypto.dart';\n"
                               "final h = sha256.convert(data).toString();")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}
    assert hits[0]["library"] == "crypto"


def test_dart_hmac_and_csprng():
    hits = _algorithms("dart", "final mac = Hmac(sha512, key);\n"
                               "final r = Random.secure();")
    assert {h["algorithm"] for h in hits} == {"HMAC", "CSPRNG"}


def test_dart_pointycastle_detection():
    hits = _algorithms(
        "dart", "final cipher = GCMBlockCipher(AESEngine());\n"
                "final signer = Ed25519Signer();")
    # AESEngine() is constructed inside GCMBlockCipher(...), so both the
    # AES primitive and the AES-GCM mode are legitimate evidence
    assert {h["algorithm"] for h in hits} == {"AES", "AES-GCM", "Ed25519"}
    assert {h["library"] for h in hits} == {"pointycastle"}


def test_dart_whitespace_tolerance():
    hits = _algorithms("dart", "h = sha256 . convert ( data )")
    assert {h["algorithm"] for h in hits} == {"SHA-256"}
