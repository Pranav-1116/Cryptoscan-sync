"""UniversalHardwareScanner — the full hardware pipeline.

    Hardware Discovery (agent/network/api) → Fingerprinting →
    Identity Resolver → Capability Discovery → Cryptographic Hardware Scan →
    Evidence Collection → Hardware State Engine → HBOM/CBOM →
    Crypto Dependency Graph → PQC Readiness → Lifecycle/Risk/Compliance

Every hardware observation produces evidence (content hash + chain hash)
via the shared evidence module (§20).
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.hardware.capabilities import CryptoCapabilityEngine
from universal_vendor.hardware.correlation import HardwareCorrelationEngine
from universal_vendor.hardware.discovery import HardwareDiscoveryOrchestrator
from universal_vendor.hardware.fingerprint import fingerprint_hardware
from universal_vendor.hardware.hbom import HbomGenerator
from universal_vendor.hardware.identity import HardwareIdentityResolver
from universal_vendor.hardware.lifecycle import HardwareLifecycleDatabase
from universal_vendor.hardware.models import HardwareObservation
from universal_vendor.hardware.plugin import HardwarePluginRegistry
from universal_vendor.hardware.risk import HardwareRiskEngine
from universal_vendor.pqc_readiness import PqcReadinessDatabase


class UniversalHardwareScanner:
    def __init__(
        self,
        *,
        plugins: Optional[HardwarePluginRegistry] = None,
        discovery: Optional[HardwareDiscoveryOrchestrator] = None,
        identity: Optional[HardwareIdentityResolver] = None,
        capabilities: Optional[CryptoCapabilityEngine] = None,
        hbom: Optional[HbomGenerator] = None,
        correlation: Optional[HardwareCorrelationEngine] = None,
        lifecycle: Optional[HardwareLifecycleDatabase] = None,
        risk: Optional[HardwareRiskEngine] = None,
        pqc_db: Optional[PqcReadinessDatabase] = None,
    ) -> None:
        self.plugins = plugins or HardwarePluginRegistry()
        self.discovery = discovery or HardwareDiscoveryOrchestrator()
        self.identity = identity or HardwareIdentityResolver()
        self.capabilities = capabilities or CryptoCapabilityEngine()
        self.hbom = hbom or HbomGenerator()
        self.correlation = correlation or HardwareCorrelationEngine()
        self.lifecycle = lifecycle or HardwareLifecycleDatabase()
        self.risk = risk or HardwareRiskEngine()
        self.pqc_db = pqc_db or PqcReadinessDatabase()

    def scan(self, context: dict[str, Any], *, scan_id: str = "hw-scan") -> dict[str, Any]:
        """Run the full hardware pipeline over one discovery context."""
        # 1. discovery (all three methods)
        observations = self.discovery.discover([context])

        # 2. fingerprinting (multi-signal confidence)
        fingerprints = []
        for obs in observations:
            fingerprint = fingerprint_hardware({
                "manufacturer": obs.manufacturer, "model": obs.model,
                "serial": obs.serial_reference, "firmware": obs.firmware,
                "dmi": (obs.vendor_specific or {}).get("dmi"),
                "snmp": (obs.vendor_specific or {}).get("snmp_sysdescr"),
                "device_banner": (obs.vendor_specific or {}).get("passive"),
                "mac_oui": (obs.vendor_specific or {}).get("mac_oui"),
            })
            fingerprints.append(fingerprint.to_dict())

        # 3. evidence (content hash + chain hash)
        raw_obs = [obs.to_dict() for obs in observations]
        evidence = build_evidence_chain(raw_obs, scan_id=scan_id)
        verification = verify_evidence_chain(evidence, scan_id=scan_id)

        # 4. state + HBOM + graph
        for obs in observations:
            self.hbom.add(obs)
            self.correlation.graph.add_node(
                obs.asset_id, vendor=obs.manufacturer, product=obs.model,
                asset_type=obs.device_type,
                region=obs.region or "", environment=obs.environment or "",
            )

        # 5. PQC readiness (evidence-backed, honest UNKNOWN)
        pqc = []
        for obs in observations:
            verdict = self.pqc_db.verdict(obs.manufacturer, obs.model,
                                          obs.firmware)
            pqc.append(verdict)

        # 6. lifecycle + risk
        lifecycle = [self.lifecycle.status(obs.manufacturer, obs.model)
                     for obs in observations]
        risks = [
            self.risk.assess(
                asset_id=obs.asset_id,
                hardware_criticality=_criticality(obs.device_type),
                pqc_capability=verdict.get("pqc_capability", "UNKNOWN"),
            ).to_dict()
            for obs, verdict in zip(observations, pqc)
        ]

        return {
            "scan_id": scan_id,
            "observations": raw_obs,
            "fingerprints": fingerprints,
            "evidence": evidence,
            "evidence_verification": verification,
            "hbom": self.hbom.to_document(),
            "graph": self.correlation.graph.to_dict(),
            "pqc": pqc,
            "lifecycle": lifecycle,
            "risks": risks,
        }


def _criticality(device_type: str) -> str:
    if device_type in ("hsm", "tpm", "secure_element", "firewall"):
        return "critical"
    if device_type in ("san", "nas", "plc", "industrial_controller"):
        return "high"
    if device_type in ("server", "switch", "router", "load_balancer"):
        return "medium"
    return "low"
