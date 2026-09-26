"""Idioms found by scanning real third-party packages in site-packages."""
from pathlib import Path

from scanner.parsers.python_parser import parse_python_file


def _algos(tmp_path: Path, code: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(code)
    return {f.crypto.algorithm for f in parse_python_file(p, tmp_path)}


def test_getattr_hashlib_table(tmp_path):  # setuptools/_distutils/command/upload.py
    code = 'import hashlib\n_FILE_CONTENT_DIGESTS = {"md5_digest": getattr(hashlib, "md5", None), "sha256_digest": getattr(hashlib, "sha256", None)}\n'
    assert {"MD5", "SHA-256"} <= _algos(tmp_path, code)


def test_hashlib_new_dynamic_is_unknown(tmp_path):  # setuptools/package_index.py
    code = "import hashlib\ndef f(hash_name):\n    return hashlib.new(hash_name)\n"
    assert _algos(tmp_path, code) == {"UNKNOWN"}


def test_vendored_implementation_classes(tmp_path):  # cryptography/hazmat/primitives/*
    code = (
        "from cryptography.hazmat.primitives.hashes import HashAlgorithm\n"
        "from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm\n"
        "class MD5(HashAlgorithm):\n    name = 'md5'\n"
        "class TripleDES(BlockCipherAlgorithm):\n    name = 'des-ede3'\n"
        "class Widget(object):\n    pass\n"
    )
    assert _algos(tmp_path, code) == {"MD5", "3DES"}


def test_plain_class_named_like_algorithm_is_not_reported(tmp_path):
    code = "class AES:\n    '''Association of Electrical Suppliers record'''\n    region = 'north'\n"
    assert _algos(tmp_path, code) == set()
