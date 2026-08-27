"""Enterprise signing-key management for CycloneDX CBOMs.

Rules:
- the active key is ``CRYPTOSCAN_CBOM_SECRET`` (or an explicit secret);
- the active ``kid`` (``CRYPTOSCAN_CBOM_KEY_ID``) is embedded in every JWS
  header so verification is rotation-aware;
- retired keys (``CRYPTOSCAN_CBOM_RETIRED_SECRETS`` as ``kid:secret`` pairs)
  keep verifying CBOMs signed before rotation;
- **fail closed**: in production an unconfigured key raises instead of
  silently generating an ephemeral one (ephemeral signatures become
  unverifiable after restart and would poison audit trails);
- outside production an ephemeral key is allowed but loudly flagged once.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from cbom.generator import CbomGenerator

logger = logging.getLogger(__name__)

_EPHEMERAL_WARNED = False


def sign_cbom(
    bom: dict[str, Any], secret: str, *, key_id: str | None = None
) -> dict[str, Any]:
    return CbomGenerator().sign(bom, secret, key_id=key_id)


def verify_cbom(bom: dict[str, Any], secret: str | dict[str, str]) -> bool:
    return CbomGenerator().verify(bom, secret)


class KeyManager:
    """Resolves the HMAC key(s) used to sign and verify CBOMs."""

    def __init__(
        self,
        secret: str | None = None,
        *,
        key_id: str | None = None,
        retired: dict[str, str] | None = None,
        environment: str | None = None,
    ) -> None:
        import os

        self._secret = secret if secret is not None else os.environ.get("CRYPTOSCAN_CBOM_SECRET") or ""
        self._key_id = key_id if key_id is not None else os.environ.get("CRYPTOSCAN_CBOM_KEY_ID") or ""
        self._retired: dict[str, str] = dict(retired or {})
        self._environment = (
            environment if environment is not None else os.environ.get("ENVIRONMENT", "development")
        )
        self._ephemeral = False

        if not self._secret:
            if self.is_production:
                from shared_config.base_settings import ConfigurationError

                raise ConfigurationError(
                    "CBOM signing requested in production without CRYPTOSCAN_CBOM_SECRET — "
                    "refusing to sign with an ephemeral key"
                )
            self._secret = secrets.token_hex(32)
            self._ephemeral = True
            global _EPHEMERAL_WARNED
            if not _EPHEMERAL_WARNED:
                _EPHEMERAL_WARNED = True
                logger.warning(
                    "cbom_signing_key_ephemeral",
                    extra={
                        "detail": "CRYPTOSCAN_CBOM_SECRET not set; generated an ephemeral key — "
                        "signatures will NOT verify after restart"
                    },
                )

    @property
    def is_production(self) -> bool:
        return self._environment.strip().lower() == "production"

    @property
    def secret(self) -> str:
        return self._secret

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def ephemeral(self) -> bool:
        return self._ephemeral

    def keyring(self) -> dict[str, str]:
        """All accepted verification keys: retired kids plus the active key.

        When a ``kid`` is configured it names the active key; verification
        tries the kid-named key first and falls back to the primary.
        """
        ring = dict(self._retired)
        if self._key_id:
            ring.setdefault(self._key_id, self._secret)
        else:
            ring.setdefault("primary", self._secret)
        return ring

    def sign(self, bom: dict[str, Any], secret: str | None = None) -> dict[str, Any]:
        key = secret if secret is not None else self._secret
        kid = None if secret is not None else (self._key_id or None)
        return sign_cbom(bom, key, key_id=kid)

    def verify(self, bom: dict[str, Any], secret: str | dict[str, str] | None = None) -> bool:
        return verify_cbom(bom, secret if secret is not None else self.keyring())

    def verify_report(self, bom: dict[str, Any]) -> dict[str, Any]:
        return CbomGenerator().verify_report(bom, self.keyring())
