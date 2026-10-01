"""Universal vendor scan modes (spec §24).

AUTO_DETECT → Identify vendor → Select compatible plugin → Validate scope
→ Discover capabilities → Collect evidence → Normalize.

Modes:
- AUTO_DETECT: detect vendor/product from signals, then run the best plugin
- INVENTORY_ONLY: plugin inventory + dependency discovery only
- CRYPTO_DISCOVERY: crypto + certificate observations
- CONFIGURATION_DISCOVERY: configuration observations
- DEEP_DISCOVERY: everything (inventory + config + crypto + certs + deps)
- CONTINUOUS_MONITORING: deep discovery + readiness/lifecycle assessment
  (the same run an operator would schedule on an interval)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from universal_vendor.plugin import canonical_json

from universal_vendor.detection import UniversalVendorDetectionEngine
from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.graph import build_graph
from universal_vendor.lifecycle import VendorLifecycleDatabase
from universal_vendor.models import ScanMode, UniversalObservation
from universal_vendor.pqc_readiness import PqcReadinessDatabase
from universal_vendor.registry import PluginRegistry

_COMMON_CRYPTO_TYPES = {
    "algorithm", "protocol", "library", "key", "key_material", "service", "rng", "secret",
}


def _raw_identity(record: dict[str, Any]) -> str:
    """Identity for merging common metadata without dropping policy detail."""
    entity = record.get("key_id") or record.get("asset_id")
    if record.get("crypto_type") == "certificate" and isinstance(record.get("certificate"), dict):
        certificate = record["certificate"]
        entity = (certificate.get("fingerprint") or certificate.get("serial_number")
                  or certificate.get("serial") or certificate.get("name")
                  or certificate.get("id") or certificate.get("arn") or entity)
    identity = {
        "crypto_type": record.get("crypto_type"),
        "entity": entity,
        "algorithm": None if record.get("crypto_type") == "certificate" else record.get("algorithm"),
        "protocol": record.get("protocol"),
        "protocol_version": record.get("protocol_version"),
        "library": record.get("library"),
        "library_version": record.get("library_version"),
        "material_type": record.get("material_type"),
        "certificate_chain": record.get("certificate_chain") or None,
    }
    return canonical_json(identity)


def _merge_raw_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    positions: dict[str, int] = {}
    for record in records:
        identity = _raw_identity(record)
        if identity not in positions:
            positions[identity] = len(merged)
            merged.append(dict(record))
            continue
        current = merged[positions[identity]]
        for key, value in record.items():
            if value in (None, "", [], {}):
                continue
            if key == "configuration" and isinstance(current.get(key), dict) and isinstance(value, dict):
                current[key] = {**current[key], **value}
            elif key == "source":
                sources = list(current.get("evidence_sources") or [current.get(key)])
                if value not in sources:
                    sources.append(value)
                current["evidence_sources"] = sources
            elif key == "confidence":
                current[key] = max(float(current.get(key, 0.0)), float(value))
            elif current.get(key) in (None, "", [], {}):
                current[key] = value
    return merged


_MODE_STAGES: dict[ScanMode, list[str]] = {
    ScanMode.AUTO_DETECT: ["detect", "select", "validate", "capabilities",
                           "collect", "normalize"],
    ScanMode.INVENTORY_ONLY: ["select", "validate", "inventory", "dependencies"],
    ScanMode.CRYPTO_DISCOVERY: ["select", "validate", "crypto", "certificates"],
    ScanMode.CONFIGURATION_DISCOVERY: ["select", "validate", "configuration"],
    ScanMode.DEEP_DISCOVERY: ["select", "validate", "inventory", "configuration",
                              "crypto", "certificates", "dependencies"],
    ScanMode.CONTINUOUS_MONITORING: ["select", "validate", "inventory",
                                     "configuration", "crypto", "certificates",
                                     "dependencies", "readiness", "lifecycle"],
}


@dataclass
class ScanReport:
    scan_id: str
    mode: str
    plugin_id: Optional[str] = None
    detection: dict[str, Any] = field(default_factory=dict)
    connection: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    observations: list[UniversalObservation] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_verification: dict[str, Any] = field(default_factory=dict)
    graph: dict[str, Any] = field(default_factory=dict)
    pqc: list[dict[str, Any]] = field(default_factory=list)
    lifecycle: list[dict[str, Any]] = field(default_factory=list)
    stages_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "mode": self.mode,
            "plugin_id": self.plugin_id,
            "detection": self.detection,
            "connection": self.connection,
            "capabilities": self.capabilities,
            "observations": [obs.model_dump(mode="json") for obs in self.observations],
            "evidence": self.evidence,
            "evidence_verification": self.evidence_verification,
            "graph": self.graph,
            "pqc": self.pqc,
            "lifecycle": self.lifecycle,
            "stages_run": self.stages_run,
        }


class UniversalVendorScanner:
    """Drives plugins by mode; outputs canonical observations + evidence."""

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        detection: UniversalVendorDetectionEngine | None = None,
        pqc: PqcReadinessDatabase | None = None,
        lifecycle: VendorLifecycleDatabase | None = None,
    ) -> None:
        self.registry = registry or PluginRegistry()
        self.detection = detection or UniversalVendorDetectionEngine()
        self.pqc = pqc or PqcReadinessDatabase()
        self.lifecycle = lifecycle or VendorLifecycleDatabase()

    # ── plugin selection ───────────────────────────────────────────────

    def select_plugin(
        self,
        detection: Any,
        *,
        category: Optional[str] = None,
        trusted_only: bool = True,
    ) -> type | None:
        """Pick the best registered plugin for a detection result."""
        vendor = detection.get("detected_vendor")
        product = detection.get("detected_product")
        if not vendor:
            return None
        candidates = self.registry.by_vendor(vendor)
        if category:
            candidates = [cls for cls in candidates if cls.category.value == category]
        candidates = [cls for cls in candidates if not trusted_only or cls.trusted]
        if not candidates:
            return None
        # product-aware preference: exact product match first
        for cls in candidates:
            if product and cls.product.lower() == str(product).lower():
                return cls
        return candidates[0]

    # ── run ───────────────────────────────────────────────────────────

    def run(
        self,
        context: dict[str, Any],
        *,
        scan_id: str,
        mode: ScanMode | str = ScanMode.AUTO_DETECT,
        plugin_id: Optional[str] = None,
        trusted_only: bool = True,
        include_readiness: bool = True,
    ) -> ScanReport:
        mode = ScanMode(mode) if isinstance(mode, str) else mode
        stages = list(_MODE_STAGES[mode])
        report = ScanReport(scan_id=scan_id, mode=mode.value)

        if mode == ScanMode.AUTO_DETECT:
            detection = self.detection.detect(context)
            report.detection = detection.model_dump(mode="json")
            report.stages_run.append("detect")
            if not detection.detected:
                report.stages_run.append("no-plugin-matched")
                return report
            plugin_cls = self.select_plugin(detection.model_dump(mode="json"),
                                            trusted_only=trusted_only)
        elif plugin_id:
            plugin_cls = self.registry.get(plugin_id, trusted_only=trusted_only)
        else:
            raise ValueError("plugin_id required for non-AUTO_DETECT modes")

        if plugin_cls is None:
            report.stages_run.append("no-plugin-matched")
            return report

        plugin = plugin_cls()
        report.plugin_id = plugin.plugin_id
        report.stages_run.append("select")

        # Explicit plugin scans still expose their detector result. Selection
        # is operator-directed in these modes, so a low-confidence detector
        # result must not silently abort the requested scan.
        if not report.detection:
            report.detection = plugin.detect(context).model_dump(mode="json")

        connection = plugin.validate_connection(context)
        report.connection = connection.model_dump(mode="json")
        report.stages_run.append("validate")
        if not connection.connected:
            return report

        if mode in (ScanMode.AUTO_DETECT, ScanMode.DEEP_DISCOVERY,
                    ScanMode.CONTINUOUS_MONITORING):
            report.capabilities = plugin.capabilities().model_dump(mode="json")
            report.stages_run.append("capabilities")

        # collect by mode
        raw: list[dict[str, Any]] = []
        dependencies: list[dict[str, Any]] = []
        common = plugin.discover_cryptographic_metadata(context)

        def dependencies_for_scan() -> list[dict[str, Any]]:
            explicit = plugin.discover_dependencies(context)
            supplemental = plugin.discover_common_dependencies(context)
            explicit_pairs = {
                (str(row.get("asset_id") or row.get("source_asset") or ""),
                 str(row.get("target_asset") or ""))
                for row in explicit
            }
            return explicit + [
                row for row in supplemental
                if (str(row.get("asset_id") or row.get("source_asset") or ""),
                    str(row.get("target_asset") or "")) not in explicit_pairs
            ]

        def common_for_mode() -> list[dict[str, Any]]:
            if "collect" in stages:
                return common
            allowed: set[str] = set()
            if "crypto" in stages:
                allowed.update(_COMMON_CRYPTO_TYPES)
            if "configuration" in stages:
                # Configuration mode includes protocol/version policy metadata.
                allowed.add("protocol")
            if "certificates" in stages:
                allowed.add("certificate")
            return [record for record in common
                    if record.get("crypto_type") in allowed]
        if "inventory" in stages:
            raw.extend(plugin.discover_inventory(context))
            report.stages_run.append("inventory")
        if "configuration" in stages:
            raw.extend(plugin.discover_configuration(context))
            report.stages_run.append("configuration")
        if "crypto" in stages:
            raw.extend(plugin.discover_crypto(context))
            report.stages_run.append("crypto")
        if "certificates" in stages:
            raw.extend(plugin.discover_certificates(context))
            report.stages_run.append("certificates")
        if "dependencies" in stages:
            # Dependency records are graph edges, not crypto observations.
            # Keeping them out of normalization prevents phantom assets while
            # preserving their source/target attribution in the graph.
            dependencies = [
                {**dependency, "source_vendor": plugin.vendor,
                 "source_product": plugin.product}
                for dependency in dependencies_for_scan()
            ]
            report.stages_run.append("dependencies")

        if "collect" in stages:
            # Collect explicitly so the dependency rows used in the graph are
            # the same rows that were included in evidence, avoiding a second
            # potentially time-varying API call.
            raw = []
            raw.extend(plugin.discover_inventory(context))
            raw.extend(plugin.discover_configuration(context))
            raw.extend(plugin.discover_crypto(context))
            raw.extend(plugin.discover_certificates(context))
            dependencies = [
                {**dependency, "source_vendor": plugin.vendor,
                 "source_product": plugin.product}
                for dependency in dependencies_for_scan()
            ]
            report.stages_run.append("collect")

        raw = _merge_raw_records(raw + common_for_mode())
        observations = plugin.normalize_all(raw)
        # Normalizers keep the canonical fields concise, so attach the raw
        # record's provenance at the orchestration boundary. This preserves
        # source field/location and discovery method without exposing secrets.
        for observation, source_record in zip(observations, raw):
            # Most existing vendor normalizers predate the shared library/key
            # fields. Project the newly discovered metadata into the canonical
            # model here while keeping their vendor-specific payload intact.
            for field_name in (
                "product_version", "algorithm_type", "algorithm_mode", "padding_scheme",
                "algorithm_oid", "algorithm_parameters", "quantum_safe_status",
                "protocol", "protocol_version", "cipher_suites", "protocol_configuration",
                "implementation", "implementation_version", "library", "library_version",
                "library_dependencies", "fips_certification", "key_id", "key_role",
                "key_type", "key_size", "curve", "key_storage_location",
                "key_lifecycle_state", "public_material_present", "private_material_present",
                "initialization_vector", "salt", "material_type", "material_metadata",
                "secret_type", "secret_storage_location", "certificate_chain",
                "certificate_serial_number", "certificate_issuer", "certificate_subject",
                "certificate_valid_from", "certificate_valid_to", "certificate_public_key_type",
                "certificate_public_key_size", "certificate_public_key_curve",
                "certificate_signature_algorithm", "observed_usage", "rng_name", "rng_type",
                "rng_source", "component_usage",
                "related_vulnerabilities", "compliance", "authenticated_encryption",
                "forward_secrecy", "side_channel_resistance", "crypto_service_type",
                "crypto_service_provider", "crypto_service_name", "crypto_service_version",
                "quantum_vulnerability", "migration_priority", "pqc_alternatives",
                "migration_status",
            ):
                value = source_record.get(field_name)
                if value is not None:
                    setattr(observation, field_name, value)
            if source_record.get("certificate") is not None and observation.certificate is None:
                observation.certificate = source_record["certificate"]
            if source_record.get("configuration") is not None and observation.configuration is None:
                observation.configuration = source_record["configuration"]
            if source_record.get("confidence") is not None:
                observation.confidence = source_record["confidence"]
            if source_record.get("visibility") is not None:
                observation.visibility = source_record["visibility"]
            evidence = dict(observation.evidence)
            evidence.setdefault("source", source_record.get("source", plugin.plugin_id))
            if source_record.get("evidence_sources"):
                evidence["sources"] = sorted(set(source_record["evidence_sources"]))
            evidence.setdefault("field", source_record.get("evidence_field")
                                or source_record.get("crypto_type", "observation"))
            evidence.setdefault("discovery_method", source_record.get(
                "discovery_method", "artifact"))
            evidence.setdefault("visibility", observation.visibility)
            observation.evidence = evidence
        report.observations = observations
        report.stages_run.append("normalize")

        # evidence chain (spec §1)
        raw_obs = [obs.model_dump(mode="json") for obs in observations]
        report.evidence = build_evidence_chain(raw_obs, scan_id=scan_id)
        report.evidence_verification = verify_evidence_chain(report.evidence, scan_id=scan_id)
        report.stages_run.append("evidence")

        # dependency graph (spec §21). Reuse the collected dependency rows;
        # the previous implementation passed an empty list for DEEP discovery,
        # silently dropping the very edges that mode promised to collect.
        if "dependencies" not in stages:
            dependencies = [
                {**dependency, "source_vendor": plugin.vendor,
                 "source_product": plugin.product}
                for dependency in dependencies_for_scan()
            ]
        graph = build_graph(observations, dependencies=dependencies)
        report.graph = graph.to_dict()
        report.stages_run.append("graph")

        # readiness + lifecycle (spec §22, §23) — only when requested
        if include_readiness and mode in (ScanMode.CONTINUOUS_MONITORING,
                                          ScanMode.DEEP_DISCOVERY):
            report.pqc = [
                self.pqc.verdict(obs.vendor, obs.product, obs.product_version)
                for obs in observations
            ]
            report.lifecycle = [
                self.lifecycle.status(obs.vendor, obs.product, obs.product_version)
                for obs in observations
            ]
            report.stages_run.extend(["readiness", "lifecycle"])

        return report
