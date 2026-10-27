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

    def _apply_plugins(
        self,
        context: dict[str, Any],
        observations: list[HardwareObservation],
    ) -> tuple[list[HardwareObservation], dict[str, Any]]:
        """Use plugin detections as corroboration, never as unqualified truth.

        Plugins may agree on a category (safe enrichment) or disagree (an
        explicit ambiguity). The latter must not silently turn a generic TPM
        observation into an Intel, AMD, or vendor-specific claim.
        """
        detected: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        raw_by_plugin: dict[str, list[dict[str, Any]]] = {}
        for plugin_cls in self.plugins.all():
            plugin = plugin_cls()
            try:
                result = plugin.detect(context) or {}
            except Exception as exc:  # one optional plugin cannot sink inventory
                errors.append({"plugin_id": plugin_cls.plugin_id,
                               "error_type": type(exc).__name__})
                continue
            if not result.get("detected"):
                continue
            try:
                raw_items = list(plugin.collect_evidence(context) or [])
            except Exception as exc:
                raw_items = []
                errors.append({"plugin_id": plugin_cls.plugin_id,
                               "error_type": type(exc).__name__})
            raw_by_plugin[plugin_cls.plugin_id] = raw_items
            detected.append({
                "plugin_id": plugin_cls.plugin_id,
                "category": plugin_cls.category.value,
                "manufacturer": result.get("manufacturer") or plugin_cls.manufacturer,
                "model": result.get("model") or plugin_cls.product,
                "confidence": result.get("confidence", "LOW"),
                "evidence_count": len(raw_items),
                "read_only": bool(plugin.read_only),
            })

        by_category: dict[str, list[dict[str, Any]]] = {}
        for row in detected:
            by_category.setdefault(row["category"], []).append(row)
        selected: dict[str, dict[str, Any]] = {}
        ambiguous: list[dict[str, Any]] = []
        for category, rows in by_category.items():
            identities = {(str(row.get("manufacturer") or "").lower(),
                           str(row.get("model") or "").lower()) for row in rows}
            if len(identities) == 1:
                selected[category] = sorted(rows, key=lambda row: row["plugin_id"])[0]
            else:
                ambiguous.append({"category": category,
                                  "plugin_ids": sorted(row["plugin_id"] for row in rows),
                                  "candidates": [{"manufacturer": row["manufacturer"],
                                                  "model": row["model"]} for row in rows],
                                  "reason": "multiple plugin identities matched; canonical identity unchanged"})

        asset_id = str(context.get("asset_id") or "")
        # Some API/network contexts carry only a vendor banner and asset id,
        # with no DMI/SNMP record for the orchestrator. A unique plugin match
        # is sufficient to create a clearly provenance-labelled observation;
        # ambiguous matches remain report-only and never create an identity.
        if not observations and asset_id:
            for row in sorted(selected.values(), key=lambda item: item["plugin_id"]):
                observations.append(HardwareObservation(
                    asset_id=asset_id,
                    manufacturer=str(row.get("manufacturer") or ""),
                    model=str(row.get("model") or ""),
                    device_type=str(row.get("category") or "other"),
                    source=f"plugin:{row['plugin_id']}",
                    confidence=str(row.get("confidence") or "LOW"),
                    discovery_sources=[f"plugin:{row['plugin_id']}"],
                ))

        default_plugin_assets = {
            "server", "tpm", "hsm", "gpu", "plc", "storage", "iot-gateway",
            "hypervisor", "network", "firewall",
        }
        enriched: list[HardwareObservation] = []
        for observation in observations:
            payload = observation.to_dict()
            candidates = [selected.get(observation.device_type)]
            if asset_id and observation.asset_id == asset_id:
                candidates.extend(row for category, row in selected.items()
                                  if category != observation.device_type)
            candidates = [row for row in candidates if row]
            if candidates:
                row = candidates[0]
                detected_manufacturer = str(row.get("manufacturer") or "")
                detected_model = str(row.get("model") or "")
                conflicts = dict(payload.get("identity_conflicts") or {})
                for field, value in (("manufacturer", detected_manufacturer),
                                     ("model", detected_model)):
                    current = str(payload.get(field) or "")
                    current_folded = current.casefold()
                    value_folded = value.casefold()
                    compatible_specificity = (
                        field == "model"
                        and current_folded
                        and value_folded
                        and (current_folded.startswith(value_folded)
                             or value_folded.startswith(current_folded))
                    )
                    if (current and value and current_folded != value_folded
                            and not compatible_specificity):
                        conflicts.setdefault(field, []).append({
                            "source": row["plugin_id"], "value": value,
                        })
                    elif not current and value:
                        payload[field] = value
                sources = set(payload.get("discovery_sources") or [])
                sources.add(f"plugin:{row['plugin_id']}")
                payload["discovery_sources"] = sorted(sources)
                payload["identity_conflicts"] = conflicts
            # Fold only structured, metadata-only plugin evidence into the
            # matching observation; raw plugin payloads are not returned.
            for plugin_id, raw_items in raw_by_plugin.items():
                for raw in raw_items:
                    raw_asset = str(raw.get("asset_id") or "")
                    same_asset = raw_asset == observation.asset_id
                    default_asset = (not asset_id and len(observations) == 1
                                     and raw_asset in default_plugin_assets)
                    if not same_asset and not default_asset:
                        continue
                    if raw.get("serial_reference") and not payload.get("serial_reference"):
                        payload["serial_reference"] = str(raw["serial_reference"])
                    if raw.get("firmware") and not payload.get("firmware"):
                        payload["firmware"] = str(raw["firmware"])
                    if raw.get("cpu") is not None and payload.get("cpu") is None:
                        payload["cpu"] = raw["cpu"]
                    cpu = raw.get("cpu")
                    if isinstance(cpu, dict):
                        self.capabilities.record_hardware_from_dict(
                            observation.asset_id, {
                                "aes": cpu.get("aes_acceleration", False),
                                "sha2": cpu.get("sha_acceleration", False),
                                "rng": cpu.get("hardware_rng", False),
                            })
                    if raw.get("tpm") is not None and payload.get("tpm") is None:
                        payload["tpm"] = raw["tpm"]
                    if raw.get("capabilities") is not None and payload.get("capabilities") is None:
                        if isinstance(raw["capabilities"], dict):
                            payload["capabilities"] = raw["capabilities"]
                    if raw.get("supported_algorithms"):
                        hsm = dict(payload.get("hsm") or {})
                        hsm["supported_algorithms"] = sorted(set(
                            hsm.get("supported_algorithms") or [])
                            | {str(item) for item in raw["supported_algorithms"]})
                        if raw.get("pqc_capability"):
                            hsm["pqc_capability"] = raw["pqc_capability"]
                        payload["hsm"] = hsm
                        self.capabilities.record_hardware_from_dict(
                            observation.asset_id,
                            {"supported_algorithms": hsm["supported_algorithms"]})
                    if raw.get("crypto_capabilities"):
                        hsm = dict(payload.get("hsm") or {})
                        hsm["crypto_capabilities"] = sorted(set(
                            hsm.get("crypto_capabilities") or [])
                            | {str(item) for item in raw["crypto_capabilities"]})
                        payload["hsm"] = hsm
                    if raw.get("partition_metadata") is not None:
                        hsm = dict(payload.get("hsm") or {})
                        hsm["partition_metadata"] = raw["partition_metadata"]
                        payload["hsm"] = hsm
                    component = raw.get("firmware_component")
                    version = raw.get("version")
                    if component and version:
                        components = dict(payload.get("firmware_components") or {})
                        components[str(component)] = str(version)
                        payload["firmware_components"] = components
                    if isinstance(raw.get("vendor_specific"), dict):
                        clean_vendor_evidence = {
                            key: value for key, value in raw["vendor_specific"].items()
                            if value not in (None, "", [], {})
                        }
                        if clean_vendor_evidence:
                            vendor_specific = dict(payload.get("vendor_specific") or {})
                            plugin_evidence = dict(vendor_specific.get("plugin_evidence") or {})
                            plugin_evidence.setdefault(plugin_id, []).append(clean_vendor_evidence)
                            vendor_specific["plugin_evidence"] = plugin_evidence
                            payload["vendor_specific"] = vendor_specific
                    if isinstance(raw.get("capabilities"), dict):
                        self.capabilities.record_hardware_from_dict(
                            observation.asset_id, raw["capabilities"])
            enriched.append(HardwareObservation(**payload))

        direct_capabilities = context.get("capabilities")
        if asset_id and isinstance(direct_capabilities, dict):
            self.capabilities.record_hardware_from_dict(asset_id, direct_capabilities)
        used = context.get("used_algorithms") or []
        if asset_id and isinstance(used, (list, tuple, set)):
            self.capabilities.record_usage(asset_id, [str(item) for item in used])
        return enriched, {"detected": detected, "ambiguous": ambiguous, "errors": errors}

    def scan(self, context: dict[str, Any], *, scan_id: str = "hw-scan") -> dict[str, Any]:
        """Run the full hardware pipeline over one discovery context."""
        # 1. discovery (all three methods)
        observations = self.discovery.discover([context])
        observations, plugin_report = self._apply_plugins(context, observations)

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
        capability_asset_ids = sorted({obs.asset_id for obs in observations}
                                      | set(self.capabilities.assets()))
        capabilities = [self.capabilities.summary(asset_id)
                        for asset_id in capability_asset_ids]
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
            "plugin_detection": plugin_report,
            "capabilities": capabilities,
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
