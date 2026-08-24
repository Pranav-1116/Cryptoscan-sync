from pathlib import Path

from scanner.detectors.hmac_detector import HmacDetector
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.python_parser import parse_python_file


def test_java_mac_get_instance(tmp_path: Path):
    java = tmp_path / "MacUtil.java"
    java.write_text(
        'class MacUtil { void t() throws Exception { javax.crypto.Mac.getInstance("HmacSHA256"); } }\n'
    )
    findings = parse_java_file(java, tmp_path)
    assert any(f.crypto.api_type == "MAC" for f in findings)
    hmac_findings = HmacDetector(tmp_path).detect(java)
    assert hmac_findings


def test_python_hmac_and_cipher(tmp_path: Path):
    path = tmp_path / "crypto_extra.py"
    path.write_text(
        """
import hmac
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def pycrypto(key):
    return AES.new(key, AES.MODE_ECB)

def modern(key, iv):
    return Cipher(algorithms.AES(key), modes.GCM(iv))
"""
    )
    findings = parse_python_file(path, tmp_path)
    algos = {f.crypto.algorithm for f in findings}
    assert "HMAC-SHA-256" in algos or "HMAC-SHA256" in algos
    aes = [f for f in findings if f.crypto.algorithm == "AES"]
    modes = {f.crypto.mode for f in aes}
    assert "ECB" in modes
    assert "GCM" in modes


def test_csharp_hmacsha1(tmp_path: Path):
    path = tmp_path / "H.cs"
    path.write_text("class C { void T() { HMACSHA1.Create(); new HMACSHA256(); } }\n")
    findings = parse_csharp_file(path, tmp_path)
    algos = {f.crypto.algorithm for f in findings}
    assert "HMAC-SHA1" in algos
    assert "HMAC-SHA256" in algos
