from scanner.parsers.c_like import strip_c_like_comments


def test_strip_c_like_comments_preserves_newlines_and_strings():
    source = """
const crypto = require('crypto');
// crypto.createHash('md5');
const url = "https://example.com";
const algo = 'aes-256-gcm';
/* DES.Create(); */
crypto.createCipheriv(algo, key, iv);
"""
    stripped = strip_c_like_comments(source)
    assert "createHash" not in stripped
    assert "DES.Create" not in stripped
    assert "https://example.com" in stripped
    assert "aes-256-gcm" in stripped
    assert "createCipheriv" in stripped
    assert stripped.count("\n") == source.count("\n")
