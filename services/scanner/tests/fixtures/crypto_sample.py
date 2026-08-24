import hashlib
from cryptography.hazmat.primitives.ciphers import algorithms

def digest(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def algo():
    return algorithms.AES
