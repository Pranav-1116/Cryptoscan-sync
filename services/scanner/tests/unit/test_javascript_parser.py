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
