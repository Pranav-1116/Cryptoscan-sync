import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES, DES


def weak_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def strong_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def dynamic_hash(data: bytes) -> bytes:
    return hashlib.new("sha1", data).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def aes_gcm(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    return cipher.encryptor().update(data)


def pycrypto_ecb(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def des_legacy(key: bytes, data: bytes) -> bytes:
    return DES.new(key, DES.MODE_ECB).encrypt(data)


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


secret = "s3cretKeyValue!!"
