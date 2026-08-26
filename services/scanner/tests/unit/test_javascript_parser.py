from scanner.parsers.javascript_parser import parse_javascript_file


def test_javascript_parser_finds_node_crypto(temp_workspace):
    path = temp_workspace / "crypto.js"
    path.write_text(
        """
const crypto = require('crypto');
crypto.createCipheriv('aes-256-gcm', key, iv);
crypto.createHash('md5');
jwt.sign({}, 's', { algorithm: 'HS256' });
bcrypt.hash('pw', 10);
const secret = "s3cretKeyValue!!";
"""
    )
    findings = parse_javascript_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "AES" in algos
    assert "MD5" in algos
    assert "HS256" in algos
    assert "BCRYPT" in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "GCM"
    assert aes.crypto.key_size == 256


def test_javascript_parser_finds_webcrypto_and_forge(temp_workspace):
    path = temp_workspace / "subtle.js"
    path.write_text(
        """
await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, data);
await crypto.subtle.digest('SHA-256', data);
forge.md.md5.create();
forge.cipher.createCipher('AES-CBC', key);
forge.pki.rsa.generateKeyPair({bits: 2048});
"""
    )
    findings = parse_javascript_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    libs = {f.metadata.library for f in findings}
    assert "AES" in algos
    assert "SHA-256" in algos
    assert "MD5" in algos
    assert "RSA" in algos
    assert "Web Crypto API" in libs
    assert "node-forge" in libs
    aes = next(f for f in findings if f.crypto.algorithm == "AES" and f.metadata.library == "Web Crypto API")
    assert aes.crypto.mode == "GCM"


def test_javascript_ignores_commented_crypto_and_resolves_locals(temp_workspace):
    path = temp_workspace / "locals.js"
    path.write_text(
        """
const crypto = require('crypto');
// crypto.createHash('md5');
const algo = 'aes-256-gcm';
crypto.createCipheriv(algo, key, iv);
"""
    )
    findings = parse_javascript_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "AES" in algos
    assert "MD5" not in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "GCM"
    assert aes.crypto.key_size == 256
