"""UniversalVendorPlugin — the common vendor plugin interface (spec §1).

Every vendor plugin implements the same contract and produces the same
canonical output. Plugins are *artifact-driven*: they parse configuration
text, banners, API metadata blobs and OIDC documents that an operator
provides (read-only). Nothing is modified; key material is never emitted.
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from typing import Any, Iterable, Optional

from universal_vendor.models import (
    ConnectionResult,
    CryptoObservation,
    DetectionResult,
    PluginStatus,
    UniversalObservation,
    VendorCapabilities,
    VendorCategory,
)

_SECRET_KEYS = (
    "password", "secret", "token", "apikey", "api_key", "private_key",
    "privatekey", "preshared", "key_material", "passphrase", "presharedkey",
    "credential",
)


def scrub_secrets(value: Any) -> Any:
    """Recursively replace known secret-bearing fields with '<REDACTED>'."""

    def _scrub(item: Any) -> Any:
        if isinstance(item, dict):
            out = {}
            for key, val in item.items():
                lowered = str(key).lower()
                if any(tok in lowered for tok in _SECRET_KEYS):
                    out[key] = "<REDACTED>"
                else:
                    out[key] = _scrub(val)
            return out
        if isinstance(item, list):
            return [_scrub(v) for v in item]
        return item

    return _scrub(value)


class UniversalVendorPlugin(ABC):
    """Common plugin contract. Subclasses set class attributes and implement
    the discovery/normalize methods."""

    plugin_id: str = ""
    vendor: str = ""
    product: str = ""
    category: VendorCategory = VendorCategory.GENERIC
    supported_products: list[str] = []
    version: str = "1.0.0"
    status: PluginStatus = PluginStatus.STABLE
    supported_features: list[str] = []
    minimum_version: str = ""
    api_requirements: list[str] = []
    auth_methods: list[str] = []
    trusted: bool = False  # untrusted plugins cannot auto-run (spec §18)

    # ── Detection (spec §16) ──────────────────────────────────────────

    @abstractmethod
    def detect(self, context: dict[str, Any]) -> DetectionResult:
        """Return a DetectionResult with vendor/product/version/confidence."""

    # ── Connection (spec §1) ───────────────────────────────────────────

    @abstractmethod
    def validate_connection(self, context: dict[str, Any]) -> ConnectionResult:
        """Verify the artifact/credentials are usable. Read-only."""

    # ── Discovery (spec §1) ───────────────────────────────────────────

    def discover_inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw inventory records (assets, versions, licenses)."""
        return []

    def discover_configuration(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw crypto-relevant configuration records (metadata only)."""
        return []

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw crypto observations (algorithms, key sizes, protocols)."""
        return []

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw certificate observations (public metadata only)."""
        return []

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw dependency observations (graph edges)."""
        return []

    def discover_cryptographic_metadata(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Common structured crypto metadata shared by all vendor plugins."""
        from universal_vendor.common_discovery import discover_common_crypto

        return discover_common_crypto(self, context)

    def discover_common_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Dependency edges from common structured dependency fields."""
        from universal_vendor.common_discovery import discover_common_dependencies

        return discover_common_dependencies(self, context)

    def collect_evidence(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Full raw evidence: inventory + config + crypto + certs + metadata."""
        raw: list[dict[str, Any]] = []
        raw.extend(self.discover_inventory(context))
        raw.extend(self.discover_configuration(context))
        raw.extend(self.discover_crypto(context))
        raw.extend(self.discover_certificates(context))
        raw.extend(self.discover_cryptographic_metadata(context))
        raw.extend(self.discover_dependencies(context))
        raw.extend(self.discover_common_dependencies(context))
        return raw

    # ── Normalization (spec §1, §20) ──────────────────────────────────

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        """Normalize one raw observation into the canonical shape."""

    def normalize_all(self, raw_items: Iterable[dict[str, Any]]) -> list[UniversalObservation]:
        return [self.normalize(item) for item in raw_items]

    # ── Health (spec §1) ──────────────────────────────────────────────

    def health_check(self, context: dict[str, Any]) -> ConnectionResult:
        return self.validate_connection(context)

    # ── Capabilities (spec §17) ───────────────────────────────────────

    def capabilities(self) -> VendorCapabilities:
        return VendorCapabilities(
            vendor=self.vendor,
            product=self.product,
            capabilities=list(self.supported_features),
            unsupported=[],
        )

    # ── Shared helpers ────────────────────────────────────────────────

    def _raw_observation(
        self,
        *,
        crypto_type: str,
        algorithm: Optional[str] = None,
        asset_id: Optional[str] = None,
        **extra: Any,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "vendor": self.vendor,
            "product": self.product,
            "product_version": extra.pop("product_version", None),
            "crypto_type": crypto_type,
            "algorithm": algorithm,
            "asset_id": asset_id or extra.pop("asset_id", None),
            "source": self.plugin_id,
        }
        item.update(extra)
        return item

    def _detect_banner(
        self,
        context: dict[str, Any],
        *,
        banner_fields: Iterable[str] = ("banner", "ssh_banner", "server_header", "config"),
        patterns: Iterable[tuple[str, str, str, float]],
    ) -> DetectionResult:
        """Run regex patterns over banner-ish context fields.

        patterns: list of (regex, vendor, product, weight)
        Confidence = highest single matched weight (bounded 0.55–0.97).
        """
        haystacks: list[tuple[str, str]] = []
        seen_fields: set[str] = set()
        for field in banner_fields:
            if field in seen_fields:
                continue
            seen_fields.add(field)
            value = context.get(field)
            if isinstance(value, str) and value.strip():
                haystacks.append((field, value))
        for field in ("vendor", "product", "manufacturer", "model"):
            value = context.get(field)
            if isinstance(value, str) and value.strip():
                haystacks.append((field, value))
        joined = "\n".join(value for _source, value in haystacks)
        best: tuple[float, str, str, str] = (0.0, "", "", "")
        matched_signals: list[dict[str, Any]] = []
        matched_keys: set[tuple[str, str]] = set()
        for regex, vendor, product, weight in patterns:
            for source, value in haystacks:
                if not re.search(regex, value, re.IGNORECASE):
                    continue
                key = (regex, source)
                if key in matched_keys:
                    continue
                matched_keys.add(key)
                if weight > best[0]:
                    best = (weight, vendor, product, regex)
                matched_signals.append({
                    "regex": regex, "vendor": vendor, "product": product,
                    "source": source,
                })
        if best[0] == 0.0:
            return DetectionResult(confidence=0.0)
        version = self._version_from(context, joined)
        return DetectionResult(
            detected_vendor=best[1],
            detected_product=best[2],
            detected_version=version,
            detection_method="multi-signal",
            confidence=min(best[0] + 0.02 * len(matched_signals), 0.99),
            signals=matched_signals,
        )

    @staticmethod
    def _version_from(context: dict[str, Any], joined: str) -> Optional[str]:
        if isinstance(context.get("version"), str) and context["version"].strip():
            return context["version"].strip()
        match = re.search(r"(?:version|release)\s*[:=]?\s*([0-9][0-9A-Za-z._\-]*)", joined)
        return match.group(1) if match else None

    @staticmethod
    def _find_version(raw: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, raw)
        return match.group(1) if match else None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def observations_to_crypto(
    observations: Iterable[UniversalObservation],
) -> list[CryptoObservation]:
    """Normalize UniversalObservations into CryptoObservations (spec §1)."""
    from universal_vendor.normalizer import normalize_to_crypto

    return [normalize_to_crypto(obs) for obs in observations]
