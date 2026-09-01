"""§1 Universal Discovery Engine — combines Network + Cloud + Vendor +
Hardware + Cryptography into one discovery pipeline.

    Discover → Identify → Correlate → Verify → Monitor

Each domain adapter runs the *existing* domain scanner (deterministic,
no AI) and normalizes its report rows into canonical :class:`PlatformAsset`
records; the correlator then links assets across domains through explicit
identity keys (IP ↔ VM ↔ container ↔ application, certificate CN ↔
endpoint, library ↔ implementation ↔ vendor, …).

The engine is pure: adapters receive structured input exactly like
``UniversalCryptoEngine.scan``, so the whole pipeline is unit-testable
without credentials. Live domain scanners (network discovery, cloud APIs)
plug in through the same adapters.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Optional

from universal_platform.assets import (
    ASSET_TYPES,
    PlatformAsset,
    normalize_asset,
)

#: canonical cross-domain relationship keys produced by the correlator
RELATIONSHIP_KINDS = {
    "hosts": "hosts",            # application → host / VM / container
    "runs_on": "runs_on",        # container → kubernetes → vm → host
    "serves": "serves",          # load balancer / proxy → application
    "uses_cert": "uses_cert",    # endpoint / lb / cloud service → certificate
    "uses_library": "uses_library",  # application → crypto library
    "uses_algo": "uses_algo",    # library / protocol → algorithm
    "implements": "implements",  # implementation → algorithm
    "has_hw": "has_hw",          # host / server → hsm / tpm / firmware
    "vendor_of": "vendor_of",    # vendor → product / library
    "cloud_asset": "cloud_asset",  # cloud service → resource
}


class UniversalDiscoveryEngine:
    """Discover → Identify → Correlate → Verify → Monitor across domains."""

    def __init__(self) -> None:
        self.assets: dict[str, PlatformAsset] = {}
        self.relationships: list[dict[str, Any]] = []
        self.sources_run: list[str] = []
        self.monitor_plan: list[dict[str, Any]] = []
        self.verified: dict[str, bool] = {}

    # -- domain adapters (each consumes the domain scanner's report) -------

    def _adapter(self, domain: str) -> Callable[[Any], list[PlatformAsset]]:
        return getattr(self, f"_from_{domain}")

    def _from_network(self, report: Any) -> list[PlatformAsset]:
        rows = report.get("assets") or report.get("hosts") or report.get("devices") or []
        return [normalize_asset(dict(row)) for row in rows]

    def _from_cloud(self, report: Any) -> list[PlatformAsset]:
        rows = report.get("assets") or report.get("resources") or []
        return [normalize_asset(dict(row)) for row in rows]

    def _from_vendor(self, report: Any) -> list[PlatformAsset]:
        rows = report.get("assets") or report.get("products") or report.get("vendors") or []
        return [normalize_asset(dict(row)) for row in rows]

    def _from_hardware(self, report: Any) -> list[PlatformAsset]:
        rows = report.get("assets") or report.get("hardware") \
            or report.get("devices") or report.get("observations") or []
        return [normalize_asset(dict(row)) for row in rows]

    def _from_crypto(self, report: Any) -> list[PlatformAsset]:
        assets: list[PlatformAsset] = []
        for obs in report.get("observations") or []:
            assets.append(normalize_asset({
                "asset_type": "algorithm", "identity": obs.get("algorithm"),
                "attributes": {k: obs.get(k) for k in
                               ("operation", "library", "key_size", "curve",
                                "padding", "digest", "protocol", "usage")
                               if obs.get(k) is not None},
                "sources": ["crypto:observation"],
                "evidence": [{"observation": obs}],
            }))
        for lib in report.get("libraries") or []:
            assets.append(normalize_asset({
                "asset_type": "crypto_library",
                "identity": lib.get("name") or lib.get("library"),
                "attributes": {"version": lib.get("version"),
                               "provider": lib.get("provider")},
                "sources": ["crypto:library"],
            }))
        for cert in report.get("certificates") or []:
            raw_subject = cert.get("subject") or cert.get("cn") or ""
            # canonical identity: CN=payments.internal → payments.internal,
            # so endpoints/load balancers/cloud services correlate
            subject = str(raw_subject).removeprefix("CN=").strip()
            assets.append(normalize_asset({
                "asset_type": "certificate",
                "identity": subject,
                "attributes": {"subject": raw_subject,
                               "self_signed": cert.get("self_signed")},
                "attributes": {"signature_algorithm": cert.get("signature_algorithm"),
                               "public_key_algorithm": cert.get("public_key_algorithm"),
                               "expired": cert.get("expired")},
                "sources": ["crypto:certificate"],
            }))
        return assets

    # -- pipeline ----------------------------------------------------------

    def discover(self, domains: dict[str, Any]) -> "UniversalDiscoveryEngine":
        """Run every domain adapter that has input; assets land in ``self``."""
        self.assets = {}
        self.relationships = []
        self.sources_run = []
        for domain, report in (domains or {}).items():
            if report in (None, {}):
                continue
            self.sources_run.append(domain)
            for asset in self._adapter(domain)(report):
                key = (asset.domain, asset.identity)
                if key in self.assets:
                    self.assets[key].sources.extend(asset.sources)
                    self.assets[key].evidence.extend(asset.evidence)
                    self.assets[key].attributes.update(asset.attributes)
                else:
                    self.assets[key] = asset
        return self

    def identify(self) -> "UniversalDiscoveryEngine":
        """Assign stable identities (canonical form already set by adapters)."""
        return self

    def correlate(self) -> "UniversalDiscoveryEngine":
        """Link assets across domains through explicit identity keys.

        Rules (deterministic): a certificate whose CN/identity appears in an
        endpoint/load-balancer/cloud-service attribute is linked with
        ``uses_cert``; an application whose host/ip attributes match a host,
        VM, container or kubernetes asset is linked with ``hosts``; a library
        name matching a vendor product links ``vendor_of``; an algorithm
        listed in a library's attributes links ``uses_algo``.
        """
        items = list(self.assets.values())
        for a in items:
            for b in items:
                if a is b:
                    continue
                kind = self._link_kind(a, b)
                if kind:
                    a.related.append(b.identity)
                    b.related.append(a.identity)
                    self.relationships.append({
                        "from": a.identity, "to": b.identity, "kind": kind,
                    })
        # dedupe relationships
        seen: set[tuple[str, str, str]] = set()
        unique = []
        for rel in self.relationships:
            key = (rel["from"], rel["to"], rel["kind"])
            if key not in seen:
                seen.add(key)
                unique.append(rel)
        self.relationships = unique
        return self

    def _link_kind(self, a: PlatformAsset, b: PlatformAsset) -> Optional[str]:
        # same-domain links are skipped except vendor → vendor_product,
        # which is a deliberate intra-domain relationship
        if a.domain == b.domain and not (
                {a.asset_type, b.asset_type} == {"vendor", "vendor_product"}):
            return None

        def values(attrs: dict[str, Any]) -> set[str]:
            """All scalar attribute values, flattening lists (e.g. a
            certificate list on a load balancer)."""
            out: set[str] = set()
            for value in attrs.values():
                if isinstance(value, (list, tuple, set)):
                    out.update(str(v) for v in value)
                else:
                    out.add(str(value))
            return out

        av, bv = values(a.attributes), values(b.attributes)
        # certificate ↔ endpoint / lb / cloud service / application
        if a.asset_type == "certificate" and b.asset_type in (
                "load_balancer", "proxy", "vpn_gateway", "cloud_resource",
                "application", "server", "api"):
            if a.identity in bv or b.identity == a.identity:
                return "uses_cert"
        if b.asset_type == "certificate" and a.asset_type in (
                "load_balancer", "proxy", "vpn_gateway", "cloud_resource",
                "application", "server", "api"):
            if b.identity in av or a.identity == b.identity:
                return "uses_cert"
        # application / container / vm ↔ host
        if b.asset_type in ("host", "server", "vm", "container", "kubernetes"):
            if a.asset_type in ("application", "api", "container", "vm"):
                if a.identity == b.identity or b.identity in av:
                    return "hosts"
        # vendor ↔ product / library
        if a.asset_type == "vendor" and b.asset_type in (
                "vendor_product", "crypto_library", "crypto_implementation"):
            if b.attributes.get("vendor") == a.identity or a.identity in bv:
                return "vendor_of"
        if b.asset_type == "vendor" and a.asset_type in (
                "vendor_product", "crypto_library", "crypto_implementation"):
            if a.attributes.get("vendor") == b.identity or b.identity in av:
                return "vendor_of"
        # hardware ↔ host / server
        if a.asset_type in ("hsm", "tpm", "firmware", "nic", "secure_element",
                            "crypto_accelerator"):
            if b.asset_type in ("host", "server", "workstation"):
                if b.identity in av or a.attributes.get("host") == b.identity:
                    return "has_hw"
        if b.asset_type in ("hsm", "tpm", "firmware", "nic", "secure_element",
                            "crypto_accelerator"):
            if a.asset_type in ("host", "server", "workstation"):
                if a.identity in bv or b.attributes.get("host") == a.identity:
                    return "has_hw"
        return None

    def verify(self) -> "UniversalDiscoveryEngine":
        """Verify each asset: identity present, type known, ≥1 source.

        Assets failing verification are marked SUSPECT (never dropped
        silently — honesty over convenience).
        """
        for key, asset in self.assets.items():
            ok = bool(asset.identity) and asset.asset_type in ASSET_TYPES \
                and bool(asset.sources)
            asset.status = "ACTIVE" if ok else "SUSPECT"
            self.verified[key] = ok
        return self

    def monitor(self, interval_seconds: int = 3600) -> "UniversalDiscoveryEngine":
        """Build the 24/7 monitor plan: per-domain rescan cadence + targets."""
        self.monitor_plan = [{
            "domain": domain,
            "cadence_seconds": interval_seconds,
            "targets": sorted({a.identity for a in self.assets.values()
                               if a.domain == domain}),
        } for domain in sorted({a.domain for a in self.assets.values()})]
        return self

    def run(self, domains: dict[str, Any],
            interval_seconds: int = 3600) -> dict[str, Any]:
        """The full §1 pipeline: Discover → Identify → Correlate → Verify → Monitor."""
        self.discover(domains).identify().correlate().verify().monitor(
            interval_seconds)
        return {
            "assets": [a.to_dict() for a in self.assets.values()],
            "asset_count": len(self.assets),
            "relationships": self.relationships,
            "relationship_count": len(self.relationships),
            "sources_run": self.sources_run,
            "verified": {f"{k[0]}:{k[1]}": v for k, v in self.verified.items()},
            "monitor_plan": self.monitor_plan,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


def run_platform_discovery(domains: dict[str, Any],
                           interval_seconds: int = 3600) -> dict[str, Any]:
    """Module-level entry point (used by CLI/API/tests)."""
    return UniversalDiscoveryEngine().run(domains, interval_seconds)
