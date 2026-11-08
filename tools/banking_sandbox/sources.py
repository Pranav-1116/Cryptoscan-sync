"""Executable-looking source inputs, never executed by the fixture generator."""

from tools.banking_sandbox.catalog import EXPRESSIONS

PYTHON_CASES = {
    "direct-aes": ("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CBC, iv)", ["AES"]),
    "explicit-aes256-gcm": (
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nkey = AESGCM.generate_key(bit_length=256)\ncipher = AESGCM(key)",
        ["AES"],
    ),
    "config-key-size": (
        'from cryptography.hazmat.primitives.ciphers import algorithms\nkey = load_config()["key"]\ncipher = algorithms.AES(key)',
        ["AES"],
    ),
    "rsa-generation": (
        "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        ["RSA"],
    ),
    "rsa-pss": (
        "from cryptography.hazmat.primitives.asymmetric import padding\nfrom cryptography.hazmat.primitives import hashes\nsignature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())",
        ["RSA", "SHA-256"],
    ),
    "ecdsa": (
        "from cryptography.hazmat.primitives.asymmetric import ec\nkey = ec.generate_private_key(ec.SECP256R1())",
        ["ECDSA"],
    ),
    "ecdh": (
        "from cryptography.hazmat.primitives.asymmetric import ec\nshared = private_key.exchange(ec.ECDH(), peer_public_key)",
        ["ECDH"],
    ),
    "hkdf": (
        'from cryptography.hazmat.primitives.kdf.hkdf import HKDF\nfrom cryptography.hazmat.primitives import hashes\nkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"LAB")',
        ["HKDF", "SHA-256"],
    ),
    "hmac": ('import hmac\nimport hashlib\ntag = hmac.new(key, b"LAB", hashlib.sha256).digest()', ["HMAC", "SHA-256"]),
    "sha256": ('import hashlib\ndigest = hashlib.sha256(b"LAB").hexdigest()', ["SHA-256"]),
    "sha1": ('import hashlib\ndigest = hashlib.sha1(b"LAB").hexdigest()', ["SHA-1"]),
    "md5": ('import hashlib\ndigest = hashlib.md5(b"LAB", usedforsecurity=False).hexdigest()', ["MD5"]),
    "wrapper": (
        'import hashlib\ndef shield(data):\n    return hashlib.sha256(data).digest()\nvalue = shield(b"LAB")',
        ["SHA-256"],
    ),
    "helper": (
        "from hashlib import sha256 as checksum_helper\ndef transform(data):\n    return checksum_helper(data).digest()",
        ["SHA-256"],
    ),
    "config-selection": (
        'from Crypto.Cipher import AES\nselected = settings["algorithm"]\ncipher = providers[selected](key)',
        [],
    ),
    "environment-selection": (
        'import os\nimport hashlib\nselected = os.environ.get("LAB_DIGEST")\ndigest = hashlib.new(selected, b"LAB")',
        [],
    ),
    "database-selection": (
        'import hashlib\nselected = database.fetch_setting("digest")\ndigest = hashlib.new(selected, b"LAB")',
        [],
    ),
    "dependency-only": ("import optional_crypto_library\ndef price(x):\n    return x * 2", []),
    "dead-code": ('import hashlib\ndef never_called():\n    return hashlib.sha1(b"LAB").digest()', ["SHA-1"]),
    "unreachable-code": ('import hashlib\nif False:\n    value = hashlib.md5(b"LAB").digest()', ["MD5"]),
    "test-only": (
        'import hashlib\ndef test_digest():\n    assert len(hashlib.sha256(b"LAB").digest()) == 32',
        ["SHA-256"],
    ),
    "production-code": (
        "import hashlib\ndef process_payment(data):\n    return hashlib.sha256(data).digest()",
        ["SHA-256"],
    ),
    "misleading-name": (
        'def rsa_aes_md5_price(amount):\n    return amount * 2\nsha256_inventory = "not cryptography"',
        [],
    ),
    "native-library": (
        'import ctypes\nprovider = ctypes.CDLL("SYNTHETIC-libshield.so")\nprovider.encrypt_payload(data)',
        [],
    ),
    "provider-switch": (
        'import importlib\nprovider = importlib.import_module(settings["provider"])\nprovider.encrypt(data)',
        [],
    ),
    "negative-lookalike": (
        'import base64\nmessage = base64.b64encode(b"LAB")\n# Documentation mentions RSA, AES and MD5; no crypto API executed.',
        [],
    ),
}


def source(language, scenario, variant):
    if language == "Python":
        text, expected = PYTHON_CASES[scenario]
    else:
        text, algorithm = EXPRESSIONS[language][variant % len(EXPRESSIONS[language])]
        expected = [algorithm]
        # These structural cases are explicitly Python-only, never mislabeled as
        # successfully materialized Java/C/etc wrapper/obfuscation cases.
        scenario = "direct-api"
    prefix = (
        "<!-- SYNTHETIC LAB source fixture -->\n"
        if language == ".NET-config"
        else (
            "      * SYNTHETIC LAB source fixture\n"
            if language == "COBOL-like"
            else (
                "# SYNTHETIC LAB source fixture\n"
                if language in ("Python", "Ruby")
                else ("" if language == "PHP" else "// SYNTHETIC LAB source fixture\n")
            )
        )
    )
    return prefix + text + "\n", expected, scenario
