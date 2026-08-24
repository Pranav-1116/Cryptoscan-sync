from scanner.core.multi_language_runner import run_language_detectors
from scanner.detectors.csharp.aes_detector import detect as detect_aes
from scanner.detectors.javascript.node_crypto_detector import detect as detect_node
from scanner.detectors.python.hashlib_detector import detect as detect_hashlib


def test_hashlib_detector(temp_workspace):
    path = temp_workspace / "h.py"
    path.write_text("import hashlib\nhashlib.md5(b'x')\n")
    findings = detect_hashlib(path, temp_workspace)
    assert any(f.crypto.algorithm == "MD5" for f in findings)


def test_node_crypto_detector(temp_workspace):
    path = temp_workspace / "c.js"
    path.write_text("const crypto = require('crypto');\ncrypto.createHash('md5');\n")
    findings = detect_node(path, temp_workspace)
    assert findings


def test_aes_detector(temp_workspace):
    path = temp_workspace / "A.cs"
    path.write_text("using System.Security.Cryptography;\nvar aes = Aes.Create();\n")
    findings = detect_aes(path, temp_workspace)
    assert any(f.crypto.algorithm == "AES" for f in findings)


def test_multi_language_runner(temp_workspace):
    (temp_workspace / "a.py").write_text("import hashlib\nhashlib.sha256()\n")
    findings, errors, languages = run_language_detectors(temp_workspace)
    assert "PYTHON" in languages
    assert findings
    assert errors == []
