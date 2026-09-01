"""Universal Platform — the control plane that combines Network + Cloud +
Vendor + Hardware + Cryptography into one system (§32).

    CONTROL PLANE
      ├─ UniversalDiscoveryEngine   (§1  discover/identify/correlate/verify/monitor)
      ├─ PlatformEventBus           (§18/§19 live events, state, targeted rescan)
      ├─ DriftEngine                (§20 baseline vs live)
      ├─ CombinedBomProducer        (§21/§22 CycloneDX CBOM + HBOM)
      ├─ PlatformRiskEngine         (§29 eight-factor risk)
      ├─ BlastRadiusAnalyzer        (§30 impact queries)
      ├─ PlatformWhatIfEngine       (§31 what-if + migration plan)
      ├─ SecurityControls           (§33 enforcement)
      └─ EvidenceChain              (§23 hash-chained evidence)

Deterministic and no-AI: every stage is a pure function of evidence and
explicit catalogs. Unknown stays unknown.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_platform.assets import PlatformAsset
from universal_platform.blast_radius import blast_radius
from universal_platform.bom import produce_combined_bom
from universal_platform.discovery import UniversalDiscoveryEngine
from universal_platform.drift import DriftEngine
from universal_platform.evidence import EvidenceChain
from universal_platform.events import PlatformEventBus
from universal_platform.risk import estate_risk, risk_score
from universal_platform.security import SecurityControls
from universal_platform.whatif import what_if


class UniversalPlatform:
    """One entry point for the combined platform pipeline."""

    def __init__(self, security: Optional[SecurityControls] = None,
                 crypto_oids: Optional[dict[str, str]] = None) -> None:
        self.security = security or SecurityControls()
        self.crypto_oids = crypto_oids or {}
        self.discovery = UniversalDiscoveryEngine()
        self.bus = PlatformEventBus()
        self.drift = DriftEngine()
        self.evidence = EvidenceChain()

    # -- discovery ----------------------------------------------------------

    def discover(self, domains: dict[str, Any],
                 interval_seconds: int = 3600) -> dict[str, Any]:
        report = self.discovery.run(domains, interval_seconds)
        self.evidence.append(
            asset="platform", source="universal_discovery",
            observation="platform discovery completed",
            evidence={"asset_count": report["asset_count"],
                      "relationship_count": report["relationship_count"]},
            method="observation",
            current_state={"asset_count": report["asset_count"]})
        return report

    # -- risk ---------------------------------------------------------------

    def risk(self, seed: Optional[str] = None) -> dict[str, Any]:
        assets = [a.to_dict() for a in self.discovery.assets.values()]
        if seed:
            for asset in assets:
                if asset["identity"] == seed:
                    return risk_score(asset)
            return {"score": 0.0, "level": "LOW", "error": f"asset {seed!r} unknown"}
        return estate_risk(assets)

    # -- blast radius -------------------------------------------------------

    def blast(self, seed: str, max_depth: int = 10) -> dict[str, Any]:
        assets = {a.identity: {"asset_type": a.asset_type, "domain": a.domain}
                  for a in self.discovery.assets.values()}
        return blast_radius(seed, assets, self.discovery.relationships,
                            max_depth)

    # -- what-if ------------------------------------------------------------

    def what_if(self, current: str, target: str,
                protocols: Optional[list[str]] = None) -> dict[str, Any]:
        assets = list(self.discovery.assets.values())
        libraries = [dict(a.attributes, identity=a.identity)
                     for a in assets if a.asset_type == "crypto_library"]
        hardware = [a.to_dict() for a in assets
                    if a.domain == "hardware"]
        vendors = [dict(a.attributes, identity=a.identity)
                   for a in assets
                   if a.asset_type in ("vendor", "vendor_product")]
        cloud = [a.to_dict() for a in assets if a.domain == "cloud"]
        return what_if(current, target, libraries=libraries,
                       hardware=hardware, vendors=vendors, cloud=cloud,
                       protocols=protocols)

    # -- BOM ----------------------------------------------------------------

    def bom(self) -> dict[str, Any]:
        return produce_combined_bom(self.discovery.assets,
                                    self.discovery.relationships,
                                    self.crypto_oids)

    # -- drift --------------------------------------------------------------

    def drift_check(self, live: dict[str, Any]) -> dict[str, Any]:
        return self.drift.evaluate(live)

    # -- live events --------------------------------------------------------

    def ingest_event(self, event: Any) -> dict[str, Any]:
        entry = self.bus.emit(event)
        self.evidence.append(
            asset=event.asset_identity, source=f"live:{event.domain}",
            observation=f"event {event.event_type.value}",
            evidence=event.payload,
            method="runtime" if event.domain == "crypto" else "observation",
            previous_state=event.previous_state,
            current_state=event.payload)
        return entry

    # -- security -----------------------------------------------------------

    def enforce(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.security.enforce(request)


def platform_pipeline(domains: dict[str, Any], *,
                      baseline: Optional[dict[str, Any]] = None,
                      security: Optional[SecurityControls] = None,
                      request: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """One-shot §32 pipeline: security check → discover → correlate →
    risk → BOM → drift."""
    platform = UniversalPlatform(security=security)
    if request is not None:
        decision = platform.enforce(request)
        if not decision["allowed"]:
            return {"allowed": False, "security": decision}
    discovery = platform.discover(domains)
    result = {
        "allowed": True,
        "discovery": discovery,
        "risk": platform.risk(),
        "bom": platform.bom(),
        "evidence_chain_valid": platform.evidence.verify()["valid"],
    }
    if baseline is not None:
        result["drift"] = platform.drift_check(
            {d: [a["identity"] for a in discovery["assets"]
                 if a["domain"] == d]
             for d in ("network", "cloud", "vendor", "hardware", "crypto")})
    return result
