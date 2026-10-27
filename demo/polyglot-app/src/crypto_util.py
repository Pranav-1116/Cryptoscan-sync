"""Intentionally weak Python cryptography for scanner tests."""

from hashlib import md5, sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import bcrypt


def weak_hash(payload: bytes) -> bytes:
    return md5(payload).digest()


def strong_hash(payload: bytes) -> bytes:
    return sha256(payload).digest()


def session_token() -> bytes:
    return Fernet.generate_key()


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def sign_session(user: str) -> str:
    return jwt.encode({"sub": user}, "dev-secret", algorithm="HS256")


def hash_password(password: bytes) -> bytes:
    return bcrypt.hashpw(password, bcrypt.gensalt())


secret = "s3cretKeyValue!!"
