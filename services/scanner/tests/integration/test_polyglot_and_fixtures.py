from pathlib import Path

from scanner.core.language_detector import detect_languages_in_repo
from scanner.core.scanner import Scanner
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.parsers.python_parser import parse_python_file

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_bundled_python_fixture_detects_legacy_and_modern():
    findings = parse_python_file(ROOT / "python_samples" / "HashlibSamples.py", ROOT)
    algos = {f.crypto.algorithm for f in findings}
    assert {"MD5", "SHA-256", "SHA-1", "AES", "DES", "RSA"} <= algos
    assert any(f.crypto.mode == "GCM" for f in findings)
    assert any(f.crypto.mode == "ECB" for f in findings)


def test_bundled_js_and_ts_fixtures():
    js = parse_javascript_file(ROOT / "javascript_samples" / "NodeCryptoSamples.js", ROOT)
    ts = parse_javascript_file(ROOT / "javascript_samples" / "TypeScriptSamples.ts", ROOT)
    assert any(f.crypto.algorithm == "AES" and f.crypto.mode == "GCM" for f in js)
    assert any(f.crypto.algorithm == "MD5" for f in js)
    assert any(f.crypto.algorithm == "HS256" for f in js)
    assert any(f.source.language == "TYPESCRIPT" and f.crypto.algorithm == "AES" for f in ts)


def test_bundled_csharp_bouncycastle_and_des():
    findings = parse_csharp_file(ROOT / "csharp_samples" / "SystemCryptoSamples.cs", ROOT)
    algos = {f.crypto.algorithm for f in findings}
    assert "DES" in algos
    assert "MD5" in algos
    assert any(f.metadata.library == "BouncyCastle" and f.crypto.algorithm == "AES" for f in findings)
    assert any(f.metadata.is_hardcoded_key for f in findings)


def test_java_tls_and_provider_fixture():
    findings = parse_java_file(ROOT / "java_samples" / "TlsAndProviderSamples.java", ROOT)
    algos = {f.crypto.algorithm for f in findings}
    assert "TLS1.2" in algos
    assert "ECDH" in algos
    assert "PBKDF2" in algos
    assert any(f.metadata.library == "BouncyCastle" for f in findings)


def test_polyglot_repo_runs_all_scanners(temp_workspace):
    (temp_workspace / "Pay.java").write_text(
        'class Pay { void t() throws Exception { javax.crypto.Cipher.getInstance("DES"); } }\n'
    )
    (temp_workspace / "util.py").write_text("from hashlib import md5\nmd5(b'x')\n")
    (temp_workspace / "web.js").write_text("crypto.createHash('sha1');\n")
    (temp_workspace / "Win.cs").write_text("class C { void T() { DES.Create(); } }\n")
    langs = detect_languages_in_repo(temp_workspace)
    assert {"JAVA", "PYTHON", "JAVASCRIPT", "CSHARP"} <= set(langs)
    result = Scanner().scan(temp_workspace)
    algos = {f.crypto.algorithm for f in result.findings}
    assert {"DES", "MD5", "SHA-1"} <= algos
    assert result.scanner_id == "static-multi-scanner-v1.0"
