"""§24 Custom crypto detection.

Classify an implementation as
KNOWN_LIBRARY / KNOWN_IMPLEMENTATION / MODIFIED_IMPLEMENTATION /
CUSTOM_IMPLEMENTATION / UNKNOWN.

Never automatically call unknown crypto "secure" or "insecure" — UNKNOWN
stays UNKNOWN and flows to deep analysis (§31) instead.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from universal_crypto.models import ImplementationClass

#: implementation → known-library mapping for custom-classification
_KNOWN_LIBRARIES: dict[str, str] = {
    "openssl": "OpenSSL", "libressl": "LibreSSL", "boringssl": "BoringSSL",
    "wolfsll": "wolfSSL", "wolfssl": "wolfSSL", "mbedtls": "mbedTLS",
    "botan": "Botan", "libsodium": "libsodium", "cryptopp": "Crypto++",
    "bouncycastle": "BouncyCastle", "bcprov": "BouncyCastle",
    "gnutls": "GnuTLS",
}

#: known-implementation fingerprint markers (name → known implementation)
_KNOWN_IMPLEMENTATIONS: dict[str, str] = {
    "EVP_": "OpenSSL EVP", "mbedtls_": "mbedTLS", "sodium_": "libsodium",
    "CryptoPP::": "Crypto++", "Botan::": "Botan", "wolfSSL_": "wolfSSL",
}

#: modified-implementation markers: standard name + non-standard structure
_MODIFIED_MARKERS = ("custom_", "_custom", "modified", "tweaked", "rolled_own")


class CustomCryptoClassifier:
    """§24 deterministic custom-crypto classification."""

    def classify(
        self,
        *,
        implementation_name: str = "",
        symbols: Optional[Iterable[str]] = None,
        library_hint: str = "",
        api_names: Optional[Iterable[str]] = None,
    ) -> dict[str, Any]:
        name = implementation_name.lower()
        symbols = list(symbols or [])
        api_names = list(api_names or [])

        # 1. KNOWN_LIBRARY — the implementation IS a known crypto library
        if library_hint:
            canonical = _KNOWN_LIBRARIES.get(library_hint.lower())
            if canonical:
                return self._result(ImplementationClass.KNOWN_LIBRARY,
                                    canonical, reason="declared known library")
        for marker, canonical in _KNOWN_LIBRARIES.items():
            if marker in name or marker in " ".join(symbols).lower():
                return self._result(ImplementationClass.KNOWN_LIBRARY, canonical,
                                    reason=f"known library marker {marker!r}")

        # 2. KNOWN_IMPLEMENTATION — known function/API fingerprints
        for marker, known in _KNOWN_IMPLEMENTATIONS.items():
            if any(marker in s for s in symbols + api_names):
                return self._result(ImplementationClass.KNOWN_IMPLEMENTATION, known,
                                    reason=f"known implementation fingerprint {marker!r}")

        # 3. MODIFIED_IMPLEMENTATION — known name + custom structure
        if any(m in name for m in _MODIFIED_MARKERS) and (
                "aes" in name or "rsa" in name or "sha" in name
                or "hash" in name or "cipher" in name):
            return self._result(ImplementationClass.MODIFIED_IMPLEMENTATION,
                                implementation_name or "unknown",
                                reason="known algorithm name with custom structure")

        # 4. CUSTOM_IMPLEMENTATION — crypto-looking API, no known fingerprint
        if implementation_name or api_names:
            return self._result(ImplementationClass.CUSTOM_IMPLEMENTATION,
                                implementation_name or "unknown",
                                reason="crypto operations without known library fingerprint")

        # 5. UNKNOWN — never auto-labeled secure or insecure
        return self._result(ImplementationClass.UNKNOWN, "",
                            reason="insufficient evidence; do not label secure/insecure")

    def _result(self, cls: ImplementationClass, detail: str,
                reason: str) -> dict[str, Any]:
        return {
            "classification": cls.value,
            "detail": detail,
            "reason": reason,
            "security_label": None,  # never auto-label unknown crypto
        }
