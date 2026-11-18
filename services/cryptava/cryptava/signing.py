"""Ed25519 signatures over an observation, in exactly the platform's format.

The platform verifies ``signature`` against ``canonical_bytes(signed_document(body))``
(see ``services/api/api/routers/ingestion.py`` and
``shared_models/release_signature.py``). This module produces that block without any
third-party dependency: when the ``cryptography`` package is importable it is used;
otherwise a compact RFC 8032 implementation in pure Python signs (one signature per
cycle, a few milliseconds). Keys are stored as standard PKCS#8 PEM, so ``openssl pkey``
reads them too.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "cryptoscan.signature/1"
OBSERVATION_SCHEMA = "cryptoscan.live-observation/1"
SIGNED_FIELDS = ("estate", "scope", "inventory_id", "observed_at", "assets", "evidence",
                 "relationships", "collectors", "coverage")
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


# --------------------------------------------------------------------------- #
# canonical form (byte-identical to shared_models.release_signature)
# --------------------------------------------------------------------------- #

def canonical_bytes(document: Mapping[str, Any], *, exclude: str = "signature") -> bytes:
    body = {key: value for key, value in document.items() if key != exclude}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def signed_document(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The exact document the platform verifies — mirrors ``ingestion.signed_document``."""
    document: dict[str, Any] = {"schema": OBSERVATION_SCHEMA}
    defaults = {"estate": "default", "scope": None, "inventory_id": "default", "observed_at": None,
                "assets": [], "evidence": [], "relationships": [], "collectors": [], "coverage": []}
    for key in SIGNED_FIELDS:
        document[key] = payload.get(key, defaults[key])
    if payload.get("contributor"):
        document["contributor"] = payload["contributor"]
    return document


def key_id(public_raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# RFC 8032 Ed25519 (pure Python fallback)
# --------------------------------------------------------------------------- #

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _equal(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _expand(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _public_from_seed(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_mul(a, _G))


def _sign_pure(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    public = _encode(_mul(a, _G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    R = _encode(_mul(r, _G))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return R + int.to_bytes(s, 32, "little")


def verify(public_raw: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 verification (used by tests and ``cryptava status``)."""
    if len(signature) != 64:
        return False
    A = _decode(public_raw)
    R = _decode(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_raw + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(R, _mul(k, A)))


# --------------------------------------------------------------------------- #
# key files
# --------------------------------------------------------------------------- #

class SigningKey:
    """An Ed25519 private key held only in memory and in a 0600 PEM file."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self._seed = seed
        self.public_raw = self._public()

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(os.urandom(32))

    @classmethod
    def load(cls, path: str | Path) -> "SigningKey":
        text = Path(path).read_text()
        body = "".join(line for line in text.splitlines() if line and not line.startswith("-----"))
        der = base64.b64decode(body)
        if not der.startswith(_PKCS8_PREFIX) or len(der) != len(_PKCS8_PREFIX) + 32:
            raise ValueError(f"{path} is not an unencrypted PKCS#8 Ed25519 private key")
        return cls(der[len(_PKCS8_PREFIX):])

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        b64 = base64.b64encode(_PKCS8_PREFIX + self._seed).decode()
        pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n"
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(pem)
        os.chmod(target, 0o600)

    def _public(self) -> bytes:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.from_private_bytes(self._seed)
            return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except ImportError:
            return _public_from_seed(self._seed)

    @property
    def public_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode("ascii")

    @property
    def key_id(self) -> str:
        return key_id(self.public_raw)

    def sign(self, message: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            return Ed25519PrivateKey.from_private_bytes(self._seed).sign(message)
        except ImportError:
            return _sign_pure(self._seed, message)

    def signature_block(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """The ``signature`` member for an observation payload."""
        signature = self.sign(canonical_bytes(signed_document(payload)))
        return {
            "schema": SCHEMA,
            "alg": "Ed25519",
            "key_id": self.key_id,
            "public_key": self.public_b64,
            "signature": base64.b64encode(signature).decode("ascii"),
            "covers": "every member except `signature`, as canonical JSON (sorted keys, no whitespace)",
        }
