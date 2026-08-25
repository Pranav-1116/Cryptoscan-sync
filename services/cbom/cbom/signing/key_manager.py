"""Resolve the HMAC secret used to sign CycloneDX CBOMs."""

from __future__ import annotations

import os
import secrets
from typing import Any

from cbom.signing.cbom_signer import sign_cbom, verify_cbom


class KeyManager:
    def __init__(self, secret: str | None = None) -> None:
        self._secret = secret if secret is not None else os.environ.get("CRYPTOSCAN_CBOM_SECRET") or ""
        self._ephemeral = False
        if not self._secret:
            self._secret = secrets.token_hex(32)
            self._ephemeral = True

    @property
    def secret(self) -> str:
        return self._secret

    @property
    def ephemeral(self) -> bool:
        return self._ephemeral

    def sign(self, bom: dict[str, Any], secret: str | None = None) -> dict[str, Any]:
        return sign_cbom(bom, secret if secret is not None else self._secret)

    def verify(self, bom: dict[str, Any], secret: str | None = None) -> bool:
        return verify_cbom(bom, secret if secret is not None else self._secret)
