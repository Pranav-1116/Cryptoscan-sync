from scanner.core.scanner import Scanner
from scanner.parsers.python_parser import parse_python_file


def test_python_parser_finds_md5_and_rsa(temp_workspace):
    path = temp_workspace / "crypto_util.py"
    path.write_text(
        """
from hashlib import md5, sha256
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

def weak(data):
    return md5(data).digest()

def strong(data):
    return sha256(data).digest()

def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)

def token():
    return jwt.encode({"a": 1}, "x", algorithm="HS256")

secret = "s3cretKeyValue!!"
"""
    )
    findings = parse_python_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "MD5" in algos
    assert "SHA-256" in algos
    assert "RSA" in algos
    assert any(f.crypto.algorithm == "HS256" for f in findings)
    assert any(f.metadata.is_hardcoded_key for f in findings)


def test_python_parser_flags_insecure_random_for_keys(temp_workspace):
    path = temp_workspace / "tokens.py"
    path.write_text(
        """
import random

def make_secret_key():
    return random.getrandbits(128)
"""
    )
    findings = parse_python_file(path, temp_workspace)
    assert any(f.crypto.algorithm == "PRNG" and f.metadata.library == "random" for f in findings)


def test_python_resolves_hashlib_new_local(temp_workspace):
    path = temp_workspace / "dyn.py"
    path.write_text(
        """
import hashlib

def digest(data):
    name = "md5"
    return hashlib.new(name, data).digest()
"""
    )
    findings = parse_python_file(path, temp_workspace)
    assert any(f.crypto.algorithm == "MD5" for f in findings)


def test_scanner_runs_python(temp_workspace):
    (temp_workspace / "app.py").write_text("from hashlib import md5\nmd5(b'x')\n")
    result = Scanner().scan(temp_workspace)
    assert any(f.crypto.algorithm == "MD5" for f in result.findings)
    assert result.scanner_id == "static-multi-scanner-v1.0"
