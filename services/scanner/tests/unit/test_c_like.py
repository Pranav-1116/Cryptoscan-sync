from scanner.parsers.c_like import strip_c_like_comments, strip_php_comments, strip_ruby_comments


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


def test_strip_php_and_ruby_hash_comments():
    php = """<?php
$cipher = 'AES-256-CBC';
# md5($password);
// hash('sha1', $x);
openssl_encrypt($data, $cipher, $key);
"""
    stripped = strip_php_comments(php)
    assert "md5" not in stripped
    assert "sha1" not in stripped
    assert "AES-256-CBC" in stripped
    assert "openssl_encrypt" in stripped

    ruby = """
# Digest::MD5.hexdigest(x)
=begin
OpenSSL::PKey::RSA.new(1024)
=end
OpenSSL::Cipher.new('AES-256-GCM')
url = "http://example.com/#md5"
"""
    stripped = strip_ruby_comments(ruby)
    assert "Digest::MD5" not in stripped
    assert "RSA.new" not in stripped
    assert "AES-256-GCM" in stripped
    assert "#md5" in stripped
