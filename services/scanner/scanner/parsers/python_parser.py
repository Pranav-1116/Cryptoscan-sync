"""Python cryptographic API parser (stdlib ast)."""

from __future__ import annotations

import ast
import re
import logging
from pathlib import Path
from typing import Optional

from scanner.extractors.entropy_calculator import looks_like_secret
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

logger = logging.getLogger(__name__)

SCANNER_ID = "static-python-scanner-v1.0"

HASHLIB_ALGOS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
}

CRYPTOGRAPHY_HASH = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384",
    "SHA3_512": "SHA3-512",
    "SHA224": "SHA-224",
    "BLAKE2b": "BLAKE2b",
    "BLAKE2s": "BLAKE2s",
    "SM3": "SM3",
}

WEAK_SECRET_NAMES = {
    "password",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "aes_key",
    "encryption_key",
}

# Suffix table for library APIs whose *fully-resolved* dotted name (after import
# alias expansion) identifies the primitive.  Matched with endswith on the
# resolved name, longest suffix first.  Entries: suffix -> (algorithm, api_type,
# purpose, library, mode).
_API_TABLE: dict[str, tuple[str, str, str, str, Optional[str]]] = {
    # cryptography.hazmat asymmetric
    "asymmetric.ec.generate_private_key": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.ec.ECDSA": ("ECDSA", "SIGNATURE", "SIGNING", "cryptography", None),
    "asymmetric.ec.ECDH": ("ECDH", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.ec.derive_private_key": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.ed25519.Ed25519PrivateKey.generate": ("Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes": ("Ed25519", "SIGNATURE", "SIGNING", "cryptography", None),
    "asymmetric.ed25519.Ed25519PublicKey.from_public_bytes": ("Ed25519", "SIGNATURE", "VERIFICATION", "cryptography", None),
    "asymmetric.ed448.Ed448PrivateKey.generate": ("Ed448", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.x25519.X25519PrivateKey.generate": ("X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.x25519.X25519PrivateKey.from_private_bytes": ("X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.x25519.X25519PublicKey.from_public_bytes": ("X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.x448.X448PrivateKey.generate": ("X448", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.dsa.generate_private_key": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.dsa.generate_parameters": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.dh.generate_parameters": ("DH", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.dh.DHParameterNumbers": ("DH", "KEY_AGREEMENT", "KEY_EXCHANGE", "cryptography", None),
    "asymmetric.rsa.RSAPrivateNumbers": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.rsa.RSAPublicNumbers": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "asymmetric.padding.OAEP": ("RSA", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "asymmetric.padding.PSS": ("RSA", "SIGNATURE", "SIGNING", "cryptography", None),
    "asymmetric.padding.PKCS1v15": ("RSA", "SIGNATURE", "SIGNING", "cryptography", None),
    # cryptography.hazmat symmetric / aead / mac / kdf
    "ciphers.aead.AESGCM": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", "GCM"),
    "ciphers.aead.AESGCMSIV": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", "GCM-SIV"),
    "ciphers.aead.AESCCM": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", "CCM"),
    "ciphers.aead.AESOCB3": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", "OCB"),
    "ciphers.aead.AESSIV": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", "SIV"),
    "ciphers.aead.ChaCha20Poly1305": ("ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.AES": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.AES128": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.AES256": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.Camellia": ("Camellia", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.TripleDES": ("3DES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.Blowfish": ("Blowfish", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.CAST5": ("CAST5", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.ARC4": ("RC4", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.IDEA": ("IDEA", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.SEED": ("SEED", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.SM4": ("SM4", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "ciphers.algorithms.ChaCha20": ("ChaCha20", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography", None),
    "primitives.hmac.HMAC": ("HMAC", "MAC", "MAC_GENERATION", "cryptography", None),
    "primitives.cmac.CMAC": ("CMAC", "MAC", "MAC_GENERATION", "cryptography", None),
    "primitives.poly1305.Poly1305": ("Poly1305", "MAC", "MAC_GENERATION", "cryptography", None),
    "kdf.hkdf.HKDF": ("HKDF", "KEY_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "kdf.hkdf.HKDFExpand": ("HKDF", "KEY_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "kdf.pbkdf2.PBKDF2HMAC": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "cryptography", None),
    "kdf.scrypt.Scrypt": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "cryptography", None),
    "kdf.argon2.Argon2id": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "cryptography", None),
    "kdf.concatkdf.ConcatKDFHash": ("ConcatKDF", "KEY_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "kdf.x963kdf.X963KDF": ("X963KDF", "KEY_GENERATOR", "KEY_GENERATION", "cryptography", None),
    "keywrap.aes_key_wrap": ("AES", "CIPHER_INSTANCE", "KEY_WRAPPING", "cryptography", "KW"),
    "keywrap.aes_key_unwrap": ("AES", "CIPHER_INSTANCE", "KEY_WRAPPING", "cryptography", "KW"),
    "primitives.hashes.SHA1": ("SHA-1", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.MD5": ("MD5", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA224": ("SHA-224", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA256": ("SHA-256", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA384": ("SHA-384", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA512": ("SHA-512", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA3_256": ("SHA3-256", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SHA3_512": ("SHA3-512", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.BLAKE2b": ("BLAKE2b", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.BLAKE2s": ("BLAKE2s", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "primitives.hashes.SM3": ("SM3", "MESSAGE_DIGEST", "HASHING", "cryptography", None),
    "cryptography.fernet.Fernet": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography.fernet", "CBC"),
    "cryptography.fernet.MultiFernet": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "cryptography.fernet", "CBC"),
    "cryptography.x509.CertificateBuilder": ("X509", "SIGNATURE", "SIGNING", "cryptography.x509", None),
    "cryptography.x509.load_pem_x509_certificate": ("X509", "SIGNATURE", "VERIFICATION", "cryptography.x509", None),
    "cryptography.x509.load_der_x509_certificate": ("X509", "SIGNATURE", "VERIFICATION", "cryptography.x509", None),
    # pycryptodome / pycrypto
    "Crypto.Cipher.AES.new": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.DES.new": ("DES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.DES3.new": ("3DES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.ARC4.new": ("RC4", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.ARC2.new": ("RC2", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.Blowfish.new": ("Blowfish", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.CAST.new": ("CAST5", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.ChaCha20.new": ("ChaCha20", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.ChaCha20_Poly1305.new": ("ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.Salsa20.new": ("Salsa20", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.PKCS1_OAEP.new": ("RSA", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Cipher.PKCS1_v1_5.new": ("RSA", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodome", None),
    "Crypto.Signature.pkcs1_15.new": ("RSA", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.Signature.PKCS1_v1_5.new": ("RSA", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.Signature.pss.new": ("RSA", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.Signature.PKCS1_PSS.new": ("RSA", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.Signature.DSS.new": ("ECDSA", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.Signature.eddsa.new": ("Ed25519", "SIGNATURE", "SIGNING", "pycryptodome", None),
    "Crypto.PublicKey.RSA.generate": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.RSA.import_key": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.RSA.importKey": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.RSA.construct": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.DSA.generate": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.DSA.import_key": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.ECC.generate": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.ECC.import_key": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.PublicKey.ElGamal.generate": ("ElGamal", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.Hash.MD2.new": ("MD2", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.MD4.new": ("MD4", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.MD5.new": ("MD5", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA.new": ("SHA-1", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA1.new": ("SHA-1", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA224.new": ("SHA-224", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA256.new": ("SHA-256", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA384.new": ("SHA-384", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA512.new": ("SHA-512", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA3_256.new": ("SHA3-256", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.SHA3_512.new": ("SHA3-512", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.BLAKE2b.new": ("BLAKE2b", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.BLAKE2s.new": ("BLAKE2s", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.RIPEMD160.new": ("RIPEMD-160", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.RIPEMD.new": ("RIPEMD-160", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.keccak.new": ("SHA3-256", "MESSAGE_DIGEST", "HASHING", "pycryptodome", None),
    "Crypto.Hash.HMAC.new": ("HMAC", "MAC", "MAC_GENERATION", "pycryptodome", None),
    "Crypto.Hash.CMAC.new": ("CMAC", "MAC", "MAC_GENERATION", "pycryptodome", None),
    "Crypto.Hash.Poly1305.new": ("Poly1305", "MAC", "MAC_GENERATION", "pycryptodome", None),
    "Crypto.Protocol.KDF.PBKDF2": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "pycryptodome", None),
    "Crypto.Protocol.KDF.PBKDF1": ("PBKDF1", "KEY_GENERATOR", "PASSWORD_HASHING", "pycryptodome", None),
    "Crypto.Protocol.KDF.scrypt": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "pycryptodome", None),
    "Crypto.Protocol.KDF.bcrypt": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "pycryptodome", None),
    "Crypto.Protocol.KDF.HKDF": ("HKDF", "KEY_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.Random.get_random_bytes": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    "Crypto.Random.new": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "pycryptodome", None),
    # PyNaCl
    "nacl.secret.SecretBox": ("XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "pynacl", None),
    "nacl.secret.Aead": ("XChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "pynacl", None),
    "nacl.public.PrivateKey.generate": ("X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "pynacl", None),
    "nacl.public.PrivateKey": ("X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "pynacl", None),
    "nacl.public.Box": ("XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "pynacl", None),
    "nacl.public.SealedBox": ("XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "pynacl", None),
    "nacl.signing.SigningKey.generate": ("Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pynacl", None),
    "nacl.signing.SigningKey": ("Ed25519", "SIGNATURE", "SIGNING", "pynacl", None),
    "nacl.signing.VerifyKey": ("Ed25519", "SIGNATURE", "VERIFICATION", "pynacl", None),
    "nacl.pwhash.argon2id.kdf": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.pwhash.argon2id.str": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.pwhash.argon2i.kdf": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.pwhash.scryptsalsa208sha256.kdf": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.pwhash.str": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.pwhash.kdf": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "pynacl", None),
    "nacl.hash.sha256": ("SHA-256", "MESSAGE_DIGEST", "HASHING", "pynacl", None),
    "nacl.hash.sha512": ("SHA-512", "MESSAGE_DIGEST", "HASHING", "pynacl", None),
    "nacl.hash.blake2b": ("BLAKE2b", "MESSAGE_DIGEST", "HASHING", "pynacl", None),
    "nacl.utils.random": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "pynacl", None),
    # paramiko / ssh
    "paramiko.RSAKey.generate": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.RSAKey.from_private_key_file": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.RSAKey": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.DSSKey.generate": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.DSSKey": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.ECDSAKey.generate": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.ECDSAKey": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.Ed25519Key": ("Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.Ed25519Key.from_private_key_file": ("Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.Ed25519Key.from_private_key": ("Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.ECDSAKey.from_private_key_file": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.ECDSAKey.from_private_key": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.DSSKey.from_private_key_file": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.RSAKey.from_private_key": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "paramiko", None),
    "paramiko.SSHClient": ("SSH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "paramiko", None),
    "paramiko.Transport": ("SSH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "paramiko", None),
    "asyncssh.connect": ("SSH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "asyncssh", None),
    "asyncssh.generate_private_key": ("SSH", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "asyncssh", None),
    # password hashing libraries
    "argon2.PasswordHasher": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-cffi", None),
    "argon2.hash_password": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-cffi", None),
    "argon2.hash_password_raw": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-cffi", None),
    "argon2.low_level.hash_secret": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-cffi", None),
    "argon2.low_level.hash_secret_raw": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-cffi", None),
    "bcrypt.hashpw": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt", None),
    "bcrypt.checkpw": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt", None),
    "bcrypt.kdf": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt", None),
    "passlib.hash.bcrypt.hash": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.bcrypt.verify": ("BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.argon2.hash": ("ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.pbkdf2_sha256.hash": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.pbkdf2_sha512.hash": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.sha256_crypt.hash": ("SHA-256", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.sha512_crypt.hash": ("SHA-512", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.md5_crypt.hash": ("MD5", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.des_crypt.hash": ("DES", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "passlib.hash.scrypt.hash": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "passlib", None),
    "django.contrib.auth.hashers.make_password": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "django", None),
    "werkzeug.security.generate_password_hash": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "werkzeug", None),
    # stdlib randomness
    "secrets.token_bytes": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "secrets.token_hex": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "secrets.token_urlsafe": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "secrets.randbits": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "secrets.choice": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "secrets.SystemRandom": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "secrets", None),
    "random.SystemRandom": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "random", None),
    "os.urandom": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "os", None),
    "os.getrandom": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "os", None),
    # jose / authlib / itsdangerous / other JWT stacks
    "jose.jwt.encode": ("JWT", "SIGNATURE", "SIGNING", "python-jose", None),
    "jose.jwt.decode": ("JWT", "SIGNATURE", "VERIFICATION", "python-jose", None),
    "jose.jws.sign": ("JWT", "SIGNATURE", "SIGNING", "python-jose", None),
    "authlib.jose.jwt.encode": ("JWT", "SIGNATURE", "SIGNING", "authlib", None),
    "authlib.jose.JsonWebSignature": ("JWT", "SIGNATURE", "SIGNING", "authlib", None),
    "itsdangerous.URLSafeTimedSerializer": ("HMAC-SHA-1", "MAC", "MAC_GENERATION", "itsdangerous", None),
    "itsdangerous.TimestampSigner": ("HMAC-SHA-1", "MAC", "MAC_GENERATION", "itsdangerous", None),
    "itsdangerous.Signer": ("HMAC-SHA-1", "MAC", "MAC_GENERATION", "itsdangerous", None),
    # TLS stacks
    "ssl.create_default_context": ("TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ssl", None),
    "OpenSSL.SSL.Context": ("TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "pyOpenSSL", None),
    "M2Crypto.RSA.load_key": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.RSA.load_key_string": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.RSA.load_pub_key": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.RSA.gen_key": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.DSA.gen_params": ("DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.EC.gen_params": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "M2Crypto", None),
    "M2Crypto.EVP.HMAC": ("HMAC", "MAC", "MAC_GENERATION", "M2Crypto", None),
    "M2Crypto.EVP.pbkdf2": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "M2Crypto", None),
    "M2Crypto.SSL.Context": ("TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "M2Crypto", None),
    "asyncssh.connect": ("SSH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "asyncssh", None),
    "asyncssh.listen": ("SSH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "asyncssh", None),
    "asyncssh.generate_private_key": ("UNKNOWN", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "asyncssh", None),
    "OpenSSL.crypto.PKey": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pyOpenSSL", None),
    "OpenSSL.crypto.X509": ("X509", "SIGNATURE", "SIGNING", "pyOpenSSL", None),
    "OpenSSL.crypto.load_certificate": ("X509", "SIGNATURE", "VERIFICATION", "pyOpenSSL", None),
    # gnupg / age / misc
    "gnupg.GPG": ("PGP", "CIPHER_INSTANCE", "ENCRYPTION", "python-gnupg", None),
    "pgpy.PGPKey.new": ("PGP", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pgpy", None),
    "Cryptodome.Cipher.AES.new": ("AES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodomex", None),
    "Cryptodome.Cipher.DES3.new": ("3DES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodomex", None),
    "Cryptodome.Cipher.DES.new": ("DES", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodomex", None),
    "Cryptodome.Cipher.ARC4.new": ("RC4", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodomex", None),
    "Cryptodome.Cipher.Blowfish.new": ("Blowfish", "CIPHER_INSTANCE", "ENCRYPTION", "pycryptodomex", None),
    "Cryptodome.Hash.MD5.new": ("MD5", "MESSAGE_DIGEST", "HASHING", "pycryptodomex", None),
    "Cryptodome.Hash.SHA1.new": ("SHA-1", "MESSAGE_DIGEST", "HASHING", "pycryptodomex", None),
    "Cryptodome.Hash.SHA256.new": ("SHA-256", "MESSAGE_DIGEST", "HASHING", "pycryptodomex", None),
    "Cryptodome.PublicKey.RSA.generate": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodomex", None),
    "Cryptodome.PublicKey.ECC.generate": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "pycryptodomex", None),
    "ecdsa.SigningKey.generate": ("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "python-ecdsa", None),
    "ecdsa.SigningKey.from_string": ("ECDSA", "SIGNATURE", "SIGNING", "python-ecdsa", None),
    "ecdsa.VerifyingKey.from_string": ("ECDSA", "SIGNATURE", "VERIFICATION", "python-ecdsa", None),
    "rsa.newkeys": ("RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "python-rsa", None),
    "rsa.encrypt": ("RSA", "CIPHER_INSTANCE", "ENCRYPTION", "python-rsa", None),
    "rsa.sign": ("RSA", "SIGNATURE", "SIGNING", "python-rsa", None),
    "Cryptodome.Random.get_random_bytes": ("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "pycryptodomex", None),
    "hashlib.pbkdf2_hmac": ("PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "hashlib", None),
    "hashlib.scrypt": ("SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "hashlib", None),
    "hashlib.blake2b": ("BLAKE2b", "MESSAGE_DIGEST", "HASHING", "hashlib", None),
    "hashlib.blake2s": ("BLAKE2s", "MESSAGE_DIGEST", "HASHING", "hashlib", None),
    "hashlib.shake_128": ("SHAKE128", "MESSAGE_DIGEST", "HASHING", "hashlib", None),
    "hashlib.shake_256": ("SHAKE256", "MESSAGE_DIGEST", "HASHING", "hashlib", None),
    "hashlib.file_digest": ("UNKNOWN", "MESSAGE_DIGEST", "HASHING", "hashlib", None),
    "zlib.crc32": ("CRC32", "CHECKSUM", "INTEGRITY", "zlib", None),
}
# CRC is a checksum, not crypto — listed so we consciously *skip* it.
_NON_CRYPTO_ALGOS = {"CRC32"}
_API_SUFFIXES = sorted(_API_TABLE, key=len, reverse=True)

# Additional hashlib spellings accepted by hashlib.new()/getattr(hashlib, ...)
_HASHLIB_NEW_EXTRA = {
    "md4": "MD4",
    "ripemd160": "RIPEMD-160",
    "whirlpool": "WHIRLPOOL",
    "sha3-256": "SHA3-256",
    "sha3-512": "SHA3-512",
    "sha512_256": "SHA-512",
    "sha512-256": "SHA-512",
    "shake_128": "SHAKE128",
    "shake_256": "SHAKE256",
    "sm3": "SM3",
}
_MODULE_ATTR_DIGEST = {**HASHLIB_ALGOS, **_HASHLIB_NEW_EXTRA}


_PASSLIB_SCHEME = {
    "bcrypt": "BCRYPT", "bcrypt_sha256": "BCRYPT", "argon2": "ARGON2", "scrypt": "SCRYPT",
    "pbkdf2_sha256": "PBKDF2-SHA256", "pbkdf2_sha512": "PBKDF2-SHA512", "pbkdf2_sha1": "PBKDF2-SHA1",
    "sha256_crypt": "SHA-256", "sha512_crypt": "SHA-512", "sha1_crypt": "SHA-1", "md5_crypt": "MD5",
    "des_crypt": "DES", "bsdi_crypt": "DES", "nthash": "MD4", "ldap_md5": "MD5", "ldap_sha1": "SHA-1",
    "django_pbkdf2_sha256": "PBKDF2-SHA256", "django_bcrypt": "BCRYPT", "plaintext": "PLAINTEXT",
}


_CRYPTO_BASE_CLASSES = {
    "HashAlgorithm", "ExtendableOutputFunction", "BlockCipherAlgorithm", "CipherAlgorithm", "EllipticCurve",
    "KeyDerivationFunction", "AsymmetricPadding", "EllipticCurveSignatureAlgorithm", "AEADCipher", "AEADEncryptionContext",
}
_IMPL_CIPHERS = {
    "aes": "AES", "aes128": "AES", "aes256": "AES", "camellia": "Camellia", "sm4": "SM4", "chacha20": "ChaCha20-Poly1305",
    "arc4": "RC4", "rc4": "RC4", "tripledes": "3DES", "des": "DES", "blowfish": "Blowfish", "cast5": "CAST5", "idea": "IDEA", "seed": "SEED",
}


_M2_CIPHERS = [
    ("des_ede3", "3DES"), ("des_ede", "3DES"), ("des3", "3DES"), ("des", "DES"), ("aes", "AES"), ("bf", "Blowfish"),
    ("blowfish", "Blowfish"), ("rc4", "RC4"), ("rc2", "RC2"), ("cast5", "CAST5"), ("idea", "IDEA"), ("camellia", "Camellia"), ("seed", "SEED"), ("chacha20", "ChaCha20-Poly1305"),
]


def _m2_cipher(alg: str) -> Optional[str]:
    low = alg.lower().replace("-", "_")
    for prefix, algo in _M2_CIPHERS:
        if low == prefix or low.startswith(prefix + "_"):
            return algo
    return None


_AWS_SPECS = [
    ("RSA_", "RSA"), ("RSAES_", "RSA"), ("RSASSA_", "RSA"), ("ECC_", "ECDSA"), ("ECDSA_", "ECDSA"), ("AES_", "AES"), ("AES256", "AES"),
    ("SYMMETRIC_DEFAULT", "AES"), ("aws:kms", "AES"), ("HMAC_", "HMAC"), ("SM2", "SM2"), ("ML_DSA", "ML-DSA"),
]


def _aws_spec(val: str) -> Optional[str]:
    for prefix, algo in _AWS_SPECS:
        if val.upper().startswith(prefix.upper()):
            return algo
    return None


def _django_hasher_families(dotted: str) -> list[str]:
    cls = dotted.rsplit(".", 1)[-1]
    low = cls.lower()
    out: list[str] = []
    if "pbkdf2" in low:
        out.append("PBKDF2")
        out.append("SHA-1" if "sha1" in low else "SHA-256")
    if "bcrypt" in low:
        out.append("BCRYPT")
        if "sha256" in low:
            out.append("SHA-256")
    if "argon2" in low:
        out.append("ARGON2")
    if "scrypt" in low:
        out.append("SCRYPT")
    if "md5" in low:
        out.append("MD5")
    if "sha1" in low and "pbkdf2" not in low:
        out.append("SHA-1")
    if low in {"cryptpasswordhasher"}:
        out.append("DES")
    return out


def parse_python_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except OSError as exc:
        logger.warning("python_read_failed", extra={"file": str(file_path), "error": str(exc)})
        return []
    except SyntaxError as exc:
        # Python 2 code, Jinja-templated .py, or a fragment: the AST is unavailable but
        # the crypto calls are still literal text. Fall back to a conservative regex pass.
        logger.info("python_parse_failed_regex_fallback", extra={"file": str(file_path), "error": str(exc)})
        return _regex_fallback(file_path, repo_root, source)
    visitor = _PythonCryptoVisitor(file_path, repo_root)
    visitor.visit(tree)
    return visitor.findings


_GPG_CIPHERS = {"aes": "AES", "aes128": "AES", "aes192": "AES", "aes256": "AES", "twofish": "Twofish", "camellia128": "Camellia", "camellia192": "Camellia",
                "camellia256": "Camellia", "3des": "3DES", "cast5": "CAST5", "blowfish": "Blowfish", "idea": "IDEA"}
_GPG_DIGESTS = {"sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5", "ripemd160": "RIPEMD-160"}
_FALLBACK_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_FALLBACK_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_FALLBACK_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_FALLBACK_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_FALLBACK_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_FALLBACK_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_FALLBACK_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_FALLBACK_RULES = None


def _build_fallback_rules():
    def _r(pattern, spec, library, **kw):
        return (re.compile(pattern), {**spec, "library": library, **kw})

    hashes = "|".join(HASHLIB_ALGOS)
    return [
        _r(rf"(?<![\w.])(?:hashlib\.)?({hashes})\s*\(", _FALLBACK_D, "hashlib", algo_from_group=1, algo_map=HASHLIB_ALGOS, confidence="MEDIUM"),
        _r(rf"\bhashlib\.new\s*\(\s*['\"]({hashes})['\"]", _FALLBACK_D, "hashlib", algo_from_group=1, algo_map=HASHLIB_ALGOS),
        _r(rf"\bhmac\.new\s*\([^)]*?(?:hashlib\.|['\"])({hashes})\b", _FALLBACK_M, "hmac", algorithm="HMAC", emit_digest_group=1),
        _r(r"\bhmac\.new\s*\(", _FALLBACK_M, "hmac", algorithm="HMAC", confidence="MEDIUM"),
        _r(r"\bhashlib\.pbkdf2_hmac\s*\(", _FALLBACK_KDF, "hashlib", algorithm="PBKDF2"),
        _r(r"\bhashlib\.scrypt\s*\(", _FALLBACK_KDF, "hashlib", algorithm="SCRYPT"),
        _r(r"\bbcrypt\.(?:hashpw|gensalt|checkpw)\s*\(", _FALLBACK_KDF, "bcrypt", algorithm="BCRYPT"),
        _r(r"\bssl\.PROTOCOL_TLSv1_2\b", _FALLBACK_TLS, "ssl", algorithm="TLS1.2"),
        _r(r"\bssl\.PROTOCOL_TLSv1_1\b", _FALLBACK_TLS, "ssl", algorithm="TLS1.1"),
        _r(r"\bssl\.PROTOCOL_TLSv1\b", _FALLBACK_TLS, "ssl", algorithm="TLS1.0"),
        _r(r"\bssl\.PROTOCOL_SSLv3\b", _FALLBACK_TLS, "ssl", algorithm="SSLv3"),
        _r(r"\bssl\.PROTOCOL_SSLv23\b", _FALLBACK_TLS, "ssl", algorithm="SSLv23"),
        _r(r"\bssl\.PROTOCOL_TLS(?:_CLIENT|_SERVER)?\b|\bssl\.create_default_context\s*\(|\bssl\.SSLContext\s*\(|\bssl\.wrap_socket\s*\(", _FALLBACK_TLS, "ssl", algorithm="TLS"),
        _r(r"\bssl\.CERT_NONE\b", _FALLBACK_TLS, "ssl", algorithm="TLS-CERT-NONE"),
        _r(r"\bos\.urandom\s*\(|\bsecrets\.(?:token_bytes|token_hex|token_urlsafe|choice|randbelow)\s*\(|\bSystemRandom\s*\(", _FALLBACK_RNG, "os", algorithm="CSPRNG", confidence="MEDIUM"),
        _r(r"\bAES\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="AES"),
        _r(r"\bDES3\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="3DES"),
        _r(r"\bDES\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="DES"),
        _r(r"\bARC4\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="RC4"),
        _r(r"\bBlowfish\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="Blowfish"),
        _r(r"\bChaCha20_Poly1305\.new\s*\(", _FALLBACK_C, "pycryptodome", algorithm="ChaCha20-Poly1305"),
        _r(r"\bRSA\.(?:generate|import_key|importKey)\s*\(|\brsa\.generate_private_key\s*\(", _FALLBACK_K, "pycryptodome/cryptography", algorithm="RSA"),
        _r(r"\bECC\.generate\s*\(|\bec\.generate_private_key\s*\(", _FALLBACK_K, "pycryptodome/cryptography", algorithm="ECDSA"),
        _r(r"\bFernet\s*\(|\bFernet\.generate_key\s*\(", _FALLBACK_C, "cryptography", algorithm="AES", mode="CBC"),
        _r(r"\bjwt\.(?:encode|decode)\s*\(", {"api_type": "SIGNATURE", "purpose": "SIGNING"}, "pyjwt", algorithm="JWT", confidence="MEDIUM"),
    ]


def _regex_fallback(file_path: Path, repo_root: Path | None, source: str) -> list[RawFinding]:
    global _FALLBACK_RULES
    from scanner.parsers.rule_engine import run_rules
    from scanner.parsers.c_like import strip_hash_line_comments

    if _FALLBACK_RULES is None:
        _FALLBACK_RULES = _build_fallback_rules()
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=strip_hash_line_comments(source),
        rules=_FALLBACK_RULES,
        language="PYTHON",
        scanner_id=SCANNER_ID,
        confidence_reason="regex-fallback: file did not parse as Python 3",
        strip_comments=False,
    )


class _PythonCryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, repo_root: Path | None):
        self.file_path = file_path
        self.repo_root = repo_root
        self.findings: list[RawFinding] = []
        self._aliases: dict[str, str] = {}
        self._locals: dict[str, str] = {}
        self._seen: set[tuple] = set()
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[-1]
            self._aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self._aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self._algorithm_implementation(node)
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_function
        prev_locals = self._locals
        self._current_function = node.name
        self._locals = dict(prev_locals)
        self.generic_visit(node)
        self._current_function = prev
        self._locals = prev_locals

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        value = self._fold_string(node.value)
        self._settings_assignment(node, value)
        self._stored_hash_constructor(node)
        # importlib.import_module("Crypto.Cipher.ARC4") / __import__("hashlib")
        if isinstance(node.value, ast.Call):
            callee = self._resolve(_call_name(node.value))
            if callee in {"importlib.import_module", "__import__"} and node.value.args:
                module = self._fold_string(node.value.args[0])
                if module:
                    for target in node.targets:
                        name = _name_of(target)
                        if name:
                            self._aliases[name] = module
        if value is None and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int) and not isinstance(node.value.value, bool):
            for target in node.targets:
                name = _name_of(target)
                if name:
                    self._locals[name] = str(node.value.value)
        if value:
            for target in node.targets:
                name = _name_of(target)
                if name:
                    self._locals[name] = value
                if name and name.lower() in WEAK_SECRET_NAMES and looks_like_secret(value):
                    self._add(
                        node,
                        api_type="HARDCODED_KEY",
                        algorithm="UNKNOWN",
                        purpose="KEY_GENERATION",
                        library="python-literal",
                        is_hardcoded_key=True,
                        hardcoded_key_length=len(value),
                        confidence="MEDIUM",
                        confidence_reason="high-entropy assignment to secret-named variable",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = _call_name(node)
        if not func:
            # getattr(hashlib, "md5")(data) / getattr(hashlib, algo)(data)
            self._dynamic_call(node)
            self.generic_visit(node)
            return

        if func == "getattr" and len(node.args) >= 2:
            # getattr(hashlib, "md5", None) stored for later use (setuptools upload, table-driven digests)
            module = self._resolve(_dotted(node.args[0]))
            attr = self._fold_string(node.args[1])
            if module.endswith("hashlib") and attr:
                algo = _MODULE_ATTR_DIGEST.get(attr.lower())
                if algo:
                    self._hash(node, algo)
        resolved = self._resolve(func)
        if self._api_table(node, func, resolved):
            pass  # table hit; still fall through for mode/key-size enrichers below
        if resolved != func:
            # run the legacy suffix rules against the resolved name too so that
            # `import hashlib as hl; hl.sha1()` is treated like hashlib.sha1()
            func = resolved

        lowered = func.lower()
        if lowered.endswith("hashlib.md5") or func.endswith("hashlib.md5") or func == "md5":
            if self._is_hashlib("md5", func):
                self._hash(node, "MD5")
        elif lowered.endswith("hashlib.sha1") or func == "sha1":
            if self._is_hashlib("sha1", func):
                self._hash(node, "SHA-1")
        elif any(func.endswith(f"hashlib.{name}") or func == name for name in HASHLIB_ALGOS):
            for name, algo in HASHLIB_ALGOS.items():
                if func.endswith(f"hashlib.{name}") or func == name:
                    if self._is_hashlib(name, func):
                        self._hash(node, algo)
                    break

        if "hashlib.new" in func:
            algo = None
            if node.args:
                algo = self._fold_string(node.args[0])
            for kw in node.keywords:
                if kw.arg == "name":
                    algo = self._fold_string(kw.value)
            if algo:
                mapped = _MODULE_ATTR_DIGEST.get(algo.lower(), algo.upper())
                self._hash(node, mapped)
            elif node.args or node.keywords:
                self._add(node, api_type="MESSAGE_DIGEST", algorithm="UNKNOWN", purpose="HASHING", library="hashlib",
                          confidence="LOW", confidence_reason="hashlib.new with a runtime-selected digest name")

        if "gpg" in func.lower() or "gnupg" in func.lower():
            # python-gnupg: extra_args=["--cipher-algo", "AES256", "--digest-algo", "SHA256"] / passphrase-encrypted files
            lits = [self._fold_string(e) for kw in node.keywords if kw.arg == "extra_args" and isinstance(kw.value, (ast.List, ast.Tuple)) for e in kw.value.elts]
            for flag, val in zip(lits, lits[1:]):
                if not flag or not val:
                    continue
                low = val.lower()
                if flag == "--cipher-algo" and low in _GPG_CIPHERS:
                    self._add(node, api_type="CIPHER_INSTANCE", algorithm=_GPG_CIPHERS[low], purpose="ENCRYPTION", library="python-gnupg", raw_transformation=f"--cipher-algo {val}")
                elif flag == "--digest-algo" and low in _GPG_DIGESTS:
                    self._add(node, api_type="MESSAGE_DIGEST", algorithm=_GPG_DIGESTS[low], purpose="HASHING", library="python-gnupg", raw_transformation=f"--digest-algo {val}")
                elif flag == "--s2k-digest-algo" and low in _GPG_DIGESTS:
                    self._add(node, api_type="KEY_GENERATOR", algorithm=_GPG_DIGESTS[low], purpose="PASSWORD_HASHING", library="python-gnupg", raw_transformation=f"--s2k-digest-algo {val}")

        if self._is_hmac_call(func):
            digest = self._hmac_digest(node)
            self._add(
                node,
                api_type="MAC",
                algorithm=f"HMAC-{digest}" if digest else "HMAC",
                purpose="MAC_GENERATION",
                library="hmac",
                raw_transformation=func,
            )

        if self._is_cipher_ctor(func):
            algo, mode = self._cryptography_cipher(node)
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm=algo,
                mode=mode,
                purpose="ENCRYPTION",
                library="cryptography",
                raw_transformation=func,
            )

        if func.endswith("Fernet.generate_key") or func.endswith("Fernet"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="AES",
                mode="CBC",
                purpose="ENCRYPTION",
                library="cryptography.fernet",
                raw_transformation="Fernet",
            )
            self._add(
                node,
                api_type="MAC",
                algorithm="HMAC-SHA-256",
                purpose="MAC_GENERATION",
                library="cryptography.fernet",
                raw_transformation="Fernet",
            )
        if func.endswith("AES.new") or func.endswith("AESGCM"):
            mode = "GCM" if "AESGCM" in func else _mode_from_node(node)
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="AES",
                mode=mode,
                purpose="ENCRYPTION",
                library="pycryptodome" if func.endswith("AES.new") else "cryptography",
            )
        if func.endswith("DES.new") or "algorithms.TripleDES" in func:
            algo = "3DES" if "Triple" in func or "DES3" in func else "DES"
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm=algo,
                purpose="ENCRYPTION",
                library="pycryptodome" if func.endswith("DES.new") else "cryptography",
            )
        if func.endswith("DES3.new"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="3DES",
                purpose="ENCRYPTION",
                library="pycryptodome",
            )
        if func.endswith("RSA.generate") or func.endswith("rsa.generate_private_key"):
            bits = _int_arg(node, 0) or _kwint(node, "key_size") or _kwint(node, "bits")
            self._add(
                node,
                api_type="KEY_PAIR_GENERATOR",
                algorithm="RSA",
                purpose="KEY_GENERATION",
                library="cryptography" if "generate_private_key" in func else "pycryptodome",
                key_size=bits,
            )
        if any(func.endswith(name) for name in ("pbkdf2_hmac", "PBKDF2HMAC", "scrypt", "argon2.PasswordHasher")):
            algo = "PBKDF2" if "pbkdf2" in func.lower() else ("SCRYPT" if "scrypt" in func.lower() else "ARGON2")
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm=algo,
                purpose="PASSWORD_HASHING",
                library="hashlib" if "pbkdf2_hmac" in func or func.endswith("scrypt") else "cryptography",
            )
            if func.endswith("pbkdf2_hmac") and node.args:
                digest = self._fold_string(node.args[0])
                if digest and digest.lower() in _MODULE_ATTR_DIGEST:
                    self._hash(node, _MODULE_ATTR_DIGEST[digest.lower()])
        if func.endswith("bcrypt.hashpw") or func.endswith("bcrypt.hash"):
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm="BCRYPT",
                purpose="PASSWORD_HASHING",
                library="bcrypt",
            )
        if func.endswith("jwt.encode") or func.endswith("jwt.decode"):
            alg = _dict_kw(node, "algorithm") or _nested_algorithm(node)
            self._add(
                node,
                api_type="SIGNATURE",
                algorithm=alg or "HS256",
                purpose="SIGNING" if func.endswith("encode") else "VERIFICATION",
                library="PyJWT",
                raw_transformation=alg,
            )
        if func.endswith("nacl.secret.SecretBox") or func.endswith("SecretBox"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="XSalsa20-Poly1305",
                purpose="ENCRYPTION",
                library="pynacl",
            )
        if func.endswith("ssl.wrap_socket") or func.endswith("SSLContext"):
            self._add(
                node,
                api_type="KEY_AGREEMENT",
                algorithm="TLS",
                purpose="NETWORK_ENCRYPTION",
                library="ssl",
                confidence="MEDIUM",
                confidence_reason="TLS context construction",
            )
        if func.endswith("_create_unverified_context") or func.endswith("create_unverified_context"):
            self._add(
                node,
                api_type="KEY_AGREEMENT",
                algorithm="TLS-UNVERIFIED",
                purpose="NETWORK_ENCRYPTION",
                library="ssl",
                confidence="HIGH",
                confidence_reason="unverified-tls-context",
            )
        if func.endswith(("set_cipher_list", "set_ciphers", "set_ciphersuites")) and node.args:
            first = node.args[0]
            raw = first.value.decode("ascii", "ignore") if isinstance(first, ast.Constant) and isinstance(first.value, bytes) else _string_literal(first)
            if raw:
                self._add(
                    node,
                    api_type="KEY_AGREEMENT",
                    algorithm="TLS-CIPHERS",
                    purpose="NETWORK_ENCRYPTION",
                    library="ssl",
                    confidence="MEDIUM",
                    confidence_reason="cipher-suite-list",
                    raw_transformation=raw[:80],
                )
        if func.endswith(("EVP.Cipher", "M2Crypto.EVP.Cipher")):
            alg = _dict_kw(node, "alg") or _string_arg(node, 0)
            algo = _m2_cipher(alg) if alg else None
            if algo:
                self._add(node, api_type="CIPHER_INSTANCE", algorithm=algo, purpose="ENCRYPTION", library="M2Crypto",
                          mode=_mode_from_name(alg or ""), raw_transformation=alg)
        if func.endswith(("EVP.MessageDigest", "M2Crypto.EVP.MessageDigest")):
            alg = _string_arg(node, 0)
            if alg and alg.lower() in _MODULE_ATTR_DIGEST:
                self._hash(node, _MODULE_ATTR_DIGEST[alg.lower()], library="M2Crypto")
        if func.endswith((".sign", ".verify", ".sign_rsassa_pss", ".verify_rsassa_pss")) and len(node.args) >= 2:
            alg = _string_literal(node.args[1]) or _dict_kw(node, "algo")
            if alg and alg.lower() in _MODULE_ATTR_DIGEST:
                self._hash(node, _MODULE_ATTR_DIGEST[alg.lower()], library="M2Crypto")
        if func.endswith("asyncssh.connect"):
            for kw in node.keywords:
                if kw.arg == "known_hosts" and isinstance(kw.value, ast.Constant) and kw.value.value is None:
                    self._add(node, api_type="KEY_AGREEMENT", algorithm="SSH-HOSTKEY-NONE", purpose="NETWORK_ENCRYPTION",
                              library="asyncssh", confidence="HIGH", confidence_reason="SSH host key verification disabled")
        for kw in node.keywords:  # AWS SDK (boto3) key / SSE specs
            if kw.arg in {"KeySpec", "CustomerMasterKeySpec", "ServerSideEncryption", "SSEAlgorithm", "SigningAlgorithm", "EncryptionAlgorithm", "KeyPairSpec"}:
                val = _string_literal(kw.value)
                algo = _aws_spec(val) if val else None
                if algo:
                    self._add(node, api_type="KEY_GENERATOR" if kw.arg != "SigningAlgorithm" else "SIGNATURE", algorithm=algo,
                              purpose="ENCRYPTION" if kw.arg != "SigningAlgorithm" else "SIGNING", library="boto3",
                              confidence="MEDIUM", confidence_reason="aws-key-spec", raw_transformation=val)
        if self._verify_disabled(node, func):
            self._add(
                node,
                api_type="KEY_AGREEMENT",
                algorithm="TLS-CERT-NONE",
                purpose="NETWORK_ENCRYPTION",
                library=func.split(".")[0] or "requests",
                confidence="HIGH",
                confidence_reason="certificate-verification-disabled",
            )
        if func.endswith("CryptContext") or func.endswith("passlib.context.CryptContext"):
            for kw in node.keywords:
                if kw.arg in {"schemes", "default", "deprecated"} :
                    values = kw.value.elts if isinstance(kw.value, (ast.List, ast.Tuple)) else [kw.value]
                    for v in values:
                        scheme = _string_literal(v)
                        algo = _PASSLIB_SCHEME.get((scheme or "").lower())
                        if algo:
                            self._add(node, api_type="KEY_GENERATOR", algorithm=algo, purpose="PASSWORD_HASHING", library="passlib", confidence_reason="passlib-scheme")
        if self._is_insecure_random(func) and self._looks_like_key_context(node):
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm="PRNG",
                purpose="KEY_GENERATION",
                library="random",
                confidence="MEDIUM",
                confidence_reason="non-CSPRNG used in a key/token/nonce context; use secrets or os.urandom",
            )
        for attr, algo in CRYPTOGRAPHY_HASH.items():
            if func.endswith(f"hashes.{attr}"):
                self._hash(node, algo, library="cryptography")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = _dotted(node)
        tls_map = (
            ("PROTOCOL_TLSv1_2", "TLS1.2"),
            ("PROTOCOL_TLSv1_1", "TLS1.1"),
            ("PROTOCOL_TLSv1", "TLS1.0"),
            ("PROTOCOL_SSLv3", "SSLv3"),
            ("PROTOCOL_SSLv23", "SSLv23"),
            ("CERT_NONE", "TLS-CERT-NONE"),
        )
        for suffix, algo in tls_map:
            if name.endswith(suffix):
                self._add(
                    node,
                    api_type="KEY_AGREEMENT",
                    algorithm=algo,
                    purpose="NETWORK_ENCRYPTION",
                    library="ssl",
                    raw_transformation=suffix,
                )
                break
        self.generic_visit(node)

    def _stored_hash_constructor(self, node: ast.Assign) -> None:
        """``digest = hashlib.sha256`` (no call) — the constructor is stored and
        invoked later (Django hashers, pbkdf2 wrappers). Report the digest here."""
        # also dispatch tables: HASHERS = {"legacy": hashlib.md5, "current": hashlib.sha256} / [hashlib.sha1]
        candidates: list[ast.AST]
        if isinstance(node.value, ast.Attribute):
            candidates = [node.value]
        elif isinstance(node.value, ast.Dict):
            candidates = [v for v in node.value.values if isinstance(v, ast.Attribute)]
        elif isinstance(node.value, (ast.List, ast.Tuple)):
            candidates = [v for v in node.value.elts if isinstance(v, ast.Attribute)]
        else:
            return
        seen: set[str] = set()
        for cand in candidates:
            dotted = self._resolve(_dotted(cand))
            if not dotted.startswith("hashlib.") or dotted in seen:
                continue
            seen.add(dotted)
            name = dotted.split(".")[-1].lower()
            algo = _MODULE_ATTR_DIGEST.get(name)
            if not algo:
                continue
            self._add(
                cand if hasattr(cand, "lineno") else node,
                api_type="MESSAGE_DIGEST",
                algorithm=algo,
                purpose="HASHING",
                library="hashlib",
                raw_transformation=dotted,
                confidence="MEDIUM",
                confidence_reason="hash constructor stored in a variable and called later",
            )

    def _is_hmac_call(self, func: str) -> bool:
        if func.endswith("hmac.new") or func.endswith("hmac.digest") or func.endswith("hmac.compare_digest"):
            return func.endswith("hmac.new") or func.endswith("hmac.digest")
        imported = self._aliases.get(func.split(".")[0], "")
        return imported.startswith("hmac") and func.endswith(("new", "digest"))

    def _hmac_digest(self, node: ast.Call) -> str:
        digest = None
        if len(node.args) >= 3:
            digest = _dotted(node.args[2]) or _string_literal(node.args[2])
        for kw in node.keywords:
            if kw.arg in {"digestmod", "digest"}:
                digest = _dotted(kw.value) or _string_literal(kw.value)
        if digest is None:
            for kw in node.keywords:
                if kw.arg in {"digestmod", "digest"}:
                    digest = self._fold_string(kw.value)
            if digest is None and len(node.args) >= 3:
                digest = self._fold_string(node.args[2])
        if digest is None:
            return ""
        name = digest.split(".")[-1].lower()
        if name in _MODULE_ATTR_DIGEST:
            return _MODULE_ATTR_DIGEST[name]
        if "." not in digest and name not in HASHLIB_ALGOS:
            # digestmod=hasher — a runtime-selected digest (django.utils.crypto.salted_hmac)
            return ""
        return name.upper().replace("_", "-")

    def _is_cipher_ctor(self, func: str) -> bool:
        if func.endswith("Cipher") or func == "Cipher":
            imported = self._aliases.get("Cipher", "")
            return "cryptography" in imported or func.endswith("Cipher")
        return False

    def _cryptography_cipher(self, node: ast.Call) -> tuple[str, str | None]:
        algo = "UNKNOWN"
        mode = None
        if node.args:
            first = node.args[0]
            first_name = _dotted(first.func if isinstance(first, ast.Call) else first)
            if "AES" in first_name:
                algo = "AES"
            elif "TripleDES" in first_name or "DES3" in first_name:
                algo = "3DES"
            elif first_name.endswith("DES") or ".DES" in first_name:
                algo = "DES"
            elif "ChaCha20" in first_name:
                algo = "ChaCha20"
        if len(node.args) > 1:
            second = node.args[1]
            second_name = _dotted(second.func if isinstance(second, ast.Call) else second)
            mode = _mode_from_name(second_name)
        return algo, mode

    def _is_hashlib(self, name: str, func: str) -> bool:
        if func.endswith(f"hashlib.{name}"):
            return True
        imported = self._aliases.get(name, "")
        return imported.endswith(f"hashlib.{name}") or imported == f"hashlib.{name}"


    def _algorithm_implementation(self, node: ast.ClassDef) -> None:
        """``class AES(BlockCipherAlgorithm)`` / ``class SHA1(HashAlgorithm)``: a
        crypto *implementation* (vendored library) rather than a call site. Only
        fires when a base class is one of the well-known crypto ABCs."""
        bases = {(_dotted(b) or "").split(".")[-1] for b in node.bases}
        if not bases & _CRYPTO_BASE_CLASSES:
            return
        name = node.name
        low = name.lower()
        algo = _MODULE_ATTR_DIGEST.get(low) or _IMPL_CIPHERS.get(low)
        if algo is None and re.fullmatch(r"(?:secp\d{3}[rk]1|brainpoolp\d{3}[rt]1|prime\d{3}v1)", low):
            algo = "ECDSA"
        if algo is None and low.startswith(("aes", "camellia", "sm4", "chacha20", "arc4", "rc4", "tripledes", "des", "blowfish", "cast5", "idea", "seed")):
            algo = _IMPL_CIPHERS.get(re.sub(r"\d+$", "", low))
        if algo is None:
            return
        api_type = "MESSAGE_DIGEST" if algo in set(_MODULE_ATTR_DIGEST.values()) else "KEY_PAIR_GENERATOR" if algo == "ECDSA" else "CIPHER_INSTANCE"
        self._add(node, api_type=api_type, algorithm=algo, purpose="ALGORITHM_IMPLEMENTATION", library="vendored-implementation",
                  confidence="MEDIUM", confidence_reason=f"class {name} implements a cryptographic primitive (base {', '.join(sorted(bases & _CRYPTO_BASE_CLASSES))})")

    def _settings_assignment(self, node: ast.Assign, value: Optional[str]) -> None:
        """Django/Flask/FastAPI settings modules: algorithms named by constants."""
        names = [(_name_of(t) or "").upper() for t in node.targets]
        names = [n.split(".")[-1] for n in names if n]
        if not names:
            return
        strings: list[str] = []
        if value:
            strings.append(value)
        elif isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            strings = [s for s in (_string_literal(e) for e in node.value.elts) if s]
        elif isinstance(node.value, ast.Dict):
            strings = [s for s in (_string_literal(v) for v in node.value.values) if s]
        for name in names:
            if name == "PASSWORD_HASHERS":
                for s in strings:
                    for algo in _django_hasher_families(s):
                        self._add(node, api_type="KEY_GENERATOR", algorithm=algo, purpose="PASSWORD_HASHING", library="django",
                                  confidence_reason="django-password-hasher", raw_transformation=s.rsplit(".", 1)[-1])
            elif name in {"JWT_ALGORITHM", "JWT_ALGORITHMS", "JWT_ALGO", "ALGORITHM", "JWT_SIGNING_ALGORITHM", "OIDC_RP_SIGN_ALGO", "SIMPLE_JWT_ALGORITHM"}:
                for s in strings:
                    if re.fullmatch(r"(?:HS|RS|PS|ES)(?:256|384|512)|EdDSA|none", s):
                        self._add(node, api_type="SIGNATURE", algorithm="JWT", purpose="SIGNING", library="jwt-settings",
                                  confidence="MEDIUM", confidence_reason="jwt-algorithm-setting", raw_transformation=s)
                        self._add(node, api_type="SIGNATURE", algorithm=s, purpose="SIGNING", library="jwt-settings",
                                  confidence="MEDIUM", confidence_reason="jwt-algorithm-setting", raw_transformation=s)
            elif name in {"SECURITY_PASSWORD_HASH", "PASSWORD_HASH", "PASSWORD_SCHEMES", "PASSWORD_HASH_SCHEME", "SECURITY_PASSWORD_SCHEMES"}:
                for s in strings:
                    algo = _PASSLIB_SCHEME.get(s.lower())
                    if algo:
                        self._add(node, api_type="KEY_GENERATOR", algorithm=algo, purpose="PASSWORD_HASHING", library="passlib",
                                  confidence_reason="password-hash-setting", raw_transformation=s)
            elif name in {"DEFAULT_HASHING_ALGORITHM", "HASH_ALGORITHM", "DIGEST_ALGORITHM", "CSRF_HASH_ALGORITHM"}:
                for s in strings:
                    if s.lower() in _MODULE_ATTR_DIGEST:
                        self._hash(node, _MODULE_ATTR_DIGEST[s.lower()], library="settings")
            elif name in {"SSL_MINIMUM_VERSION", "TLS_MIN_VERSION", "MIN_TLS_VERSION", "SSL_VERSION"}:
                for s in strings:
                    self._add(node, api_type="KEY_AGREEMENT", algorithm="TLS", purpose="NETWORK_ENCRYPTION", library="settings",
                              confidence="MEDIUM", confidence_reason="tls-version-setting", raw_transformation=s)
        for s in strings:
            if re.search(r"\bsslmode=(?:disable|allow|prefer)\b|\bssl=false\b|\bssl-mode=DISABLED\b|\buseSSL=false\b", s):
                self._add(node, api_type="KEY_AGREEMENT", algorithm="TLS-DISABLED", purpose="NETWORK_ENCRYPTION", library="database-url",
                          confidence="MEDIUM", confidence_reason="database connection without TLS", raw_transformation=s[-80:])

    def _verify_disabled(self, node: ast.Call, func: str) -> bool:
        """requests/httpx/aiohttp/urllib3 style ``verify=False`` / ``ssl=False``."""
        head = func.split(".")[0]
        root = self._aliases.get(head, head)
        http_like = any(t in (func + " " + root).lower() for t in ("requests", "httpx", "aiohttp", "urllib3", "session", "client", "http"))
        if not http_like:
            return False
        for kw in node.keywords:
            if kw.arg in {"verify", "verify_ssl", "ssl"} and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False

    def _is_insecure_random(self, func: str) -> bool:
        tail = func.split(".")[-1]
        if tail not in {"random", "randint", "randrange", "choice", "getrandbits", "randbytes"}:
            return False
        if func.startswith("secrets.") or ".secrets." in func:
            return False
        imported = self._aliases.get(func.split(".")[0], "")
        if imported.startswith("secrets"):
            return False
        return func.startswith("random.") or imported.startswith("random") or func in {
            "random",
            "randint",
            "getrandbits",
            "randbytes",
        }

    def _looks_like_key_context(self, node: ast.AST) -> bool:
        hay = " ".join(
            part.lower()
            for part in (
                self._current_function or "",
                self._current_class or "",
            )
            if part
        )
        markers = ("key", "token", "secret", "password", "nonce", "iv", "salt", "seed")
        return any(marker in hay for marker in markers)

    # ------------------------------------------------------------------ resolution helpers
    def _resolve(self, dotted: str) -> str:
        """Expand the import alias at the head of a dotted name.

        ``hl.sha1`` with ``import hashlib as hl`` -> ``hashlib.sha1``;
        ``_A.new`` with ``from Crypto.Cipher import AES as _A`` -> ``Crypto.Cipher.AES.new``.
        """
        if not dotted:
            return dotted
        head, _, rest = dotted.partition(".")
        target = self._aliases.get(head)
        if not target:
            return dotted
        return f"{target}.{rest}" if rest else target

    def _fold_string(self, node: ast.AST) -> Optional[str]:
        """Best-effort constant folding for string arguments.

        Handles literals, ``"md" + "5"``, names bound to literals earlier in
        scope, ``"sha256".upper()``/``.lower()`` and ``mapping.get(k, "sha512")``
        (the default is the only statically known value).
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return str(node.value)  # bits = 384 → f"sha{bits}"
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                folded = self._fold_string(v)
                if folded is None:
                    return None
                parts.append(folded)
            return "".join(parts)
        if isinstance(node, ast.FormattedValue):
            return self._fold_string(node.value)
        if isinstance(node, ast.Name):
            return self._locals.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._fold_string(node.left)
            right = self._fold_string(node.right)
            if left is not None and right is not None:
                return left + right
            return None
        if isinstance(node, ast.Call):
            callee = node.func
            if isinstance(callee, ast.Attribute):
                if callee.attr in {"lower", "upper", "strip", "casefold"} and not node.args:
                    inner = self._fold_string(callee.value)
                    return getattr(inner, callee.attr)() if inner is not None else None
                if callee.attr in {"get", "getenv", "getattr"} and len(node.args) >= 2:
                    return self._fold_string(node.args[1])
                if callee.attr == "get" and len(node.args) == 1:
                    return None
            if isinstance(callee, ast.Name) and callee.id == "str" and len(node.args) == 1:
                return self._fold_string(node.args[0])
        if isinstance(node, ast.Subscript):
            # CONFIG["digest"] style lookups on a dict literal bound in scope are
            # out of reach; give up rather than guess.
            return None
        return None

    def _dynamic_call(self, node: ast.Call) -> None:
        """``getattr(<module>, <name>)(...)`` where name folds to a constant."""
        inner = node.func
        if not (isinstance(inner, ast.Call) and _call_name(inner) == "getattr" and len(inner.args) >= 2):
            return
        module = self._resolve(_dotted(inner.args[0]))
        attr = self._fold_string(inner.args[1])
        if not attr:
            return
        if module.endswith("hashlib"):
            algo = _MODULE_ATTR_DIGEST.get(attr.lower())
            if algo:
                self._hash(node, algo)
            elif attr == "new" and node.args:
                folded = self._fold_string(node.args[0])
                if folded and folded.lower() in _MODULE_ATTR_DIGEST:
                    self._hash(node, _MODULE_ATTR_DIGEST[folded.lower()])
            return
        synthetic = f"{module}.{attr}"
        self._api_table(node, synthetic, synthetic)

    def _api_table(self, node: ast.Call, func: str, resolved: str) -> bool:
        """Match the resolved dotted call name against ``_API_TABLE``."""
        candidates = (resolved, func) if resolved != func else (resolved,)
        for cand in candidates:
            for suffix in _API_SUFFIXES:
                if cand == suffix or cand.endswith("." + suffix):
                    algorithm, api_type, purpose, library, mode = _API_TABLE[suffix]
                    if algorithm in _NON_CRYPTO_ALGOS:
                        return True
                    if mode is None and api_type == "CIPHER_INSTANCE":
                        mode = _mode_from_node(node)
                    key_size = _int_arg(node, 0) or _kwint(node, "key_size") or _kwint(node, "bits") or _kwint(node, "bit_length")
                    if api_type not in {"KEY_PAIR_GENERATOR", "CIPHER_INSTANCE"}:
                        key_size = None
                    self._add(
                        node,
                        api_type=api_type,
                        algorithm=algorithm,
                        mode=mode,
                        purpose=purpose,
                        library=library,
                        key_size=key_size,
                        raw_transformation=cand[-80:],
                        confidence="HIGH" if api_type != "KEY_GENERATOR" or algorithm != "CSPRNG" else "MEDIUM",
                    )
                    # cryptography HMAC/HKDF/PBKDF2HMAC carry the digest as an argument
                    if algorithm in {"HMAC", "HKDF", "PBKDF2", "CMAC", "ECDSA", "RSA"} or api_type in {"MAC", "KEY_GENERATOR"}:
                        self._emit_nested_hash(node)
                    return True
        return False

    def _emit_nested_hash(self, node: ast.Call) -> None:
        """Emit the digest named by an argument such as ``hashes.SHA256()``."""
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            inner = arg.func if isinstance(arg, ast.Call) else arg
            name = self._resolve(_dotted(inner))
            for attr, algo in CRYPTOGRAPHY_HASH.items():
                if name.endswith(f"hashes.{attr}"):
                    self._hash(node, algo, library="cryptography")
                    break
            else:
                folded = self._fold_string(arg) if not isinstance(arg, ast.Call) else None
                if folded and folded.lower() in _MODULE_ATTR_DIGEST:
                    self._hash(node, _MODULE_ATTR_DIGEST[folded.lower()])

    def _resolve_name(self, node: ast.Call, index: int) -> Optional[str]:
        if len(node.args) <= index:
            return None
        arg = node.args[index]
        if isinstance(arg, ast.Name):
            return self._locals.get(arg.id)
        return None

    def _hash(self, node: ast.AST, algorithm: str, library: str = "hashlib") -> None:
        self._add(
            node,
            api_type="MESSAGE_DIGEST",
            algorithm=algorithm,
            purpose="HASHING",
            library=library,
        )

    def _add(self, node: ast.AST, **kwargs) -> None:
        key = (getattr(node, "lineno", 1), str(kwargs.get("algorithm")).upper(), kwargs.get("api_type"))
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            make_finding(
                file_path=self.file_path,
                repo_root=self.repo_root,
                line_number=getattr(node, "lineno", 1),
                language="PYTHON",
                scanner_id=SCANNER_ID,
                method_name=self._current_function,
                class_name=self._current_class,
                **kwargs,
            )
        )


def _call_name(node: ast.Call) -> str:
    return _dotted(node.func)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _name_of(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _string_literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_arg(node: ast.Call, index: int) -> Optional[str]:
    if len(node.args) > index:
        return _string_literal(node.args[index])
    return None


def _int_arg(node: ast.Call, index: int) -> Optional[int]:
    if len(node.args) > index and isinstance(node.args[index], ast.Constant) and isinstance(node.args[index].value, int):
        return node.args[index].value
    return None


def _kwint(node: ast.Call, name: str) -> Optional[int]:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def _dict_kw(node: ast.Call, name: str) -> Optional[str]:
    for kw in node.keywords:
        if kw.arg == name:
            return _string_literal(kw.value)
        if kw.arg == "algorithm":
            return _string_literal(kw.value)
    return None


def _mode_from_name(name: str) -> Optional[str]:
    upper = (name or "").upper()
    for mode in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB"):
        if mode in upper:
            return mode
    return None


def _mode_from_node(node: ast.Call) -> Optional[str]:
    if len(node.args) > 1:
        return _mode_from_name(_dotted(node.args[1]) or _string_literal(node.args[1]) or "")
    for kw in node.keywords:
        if kw.arg in {"mode", "MODE"}:
            return _mode_from_name(_dotted(kw.value) or _string_literal(kw.value) or "")
    return None


def _nested_algorithm(node: ast.Call) -> Optional[str]:
    for kw in node.keywords:
        if kw.arg in {"algorithm", "algorithms"}:
            value = _string_literal(kw.value)
            if value:
                return value
        if isinstance(kw.value, ast.Dict):
            for key, val in zip(kw.value.keys, kw.value.values):
                if isinstance(key, ast.Constant) and key.value == "algorithm":
                    return _string_literal(val)
    return None
