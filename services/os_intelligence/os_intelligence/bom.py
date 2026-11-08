"""SBOM/CBOM/HBOM/TechBOM integration
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 6) — feeds
the existing six-BOM ecosystem, never a seventh disconnected BOM.

The CycloneDX provides/uses distinction is central: the kernel
PROVIDES a registered implementation; the engine NEVER emits a `uses`
edge. No application↔kernel relationship is ever inferred from
same-host co-location (§8) — such a relationship needs evidence of its
own. Component versions the sources do not report are unknown, never
guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BOM_SCHEMA = "cryptoscan.os-bom/1"

BOM_KINDS = ("sbom", "cbom", "hbom", "techbom")


class RelationshipProvenance:
    """Digital-twin relationship provenance (same vocabulary as the
    binary BOM, §8)."""
    DIRECTLY_OBSERVED = "directly_observed"
    STATIC_DEPENDENCY = "static_dependency"
    CONFIGURATION_DERIVED = "configuration_derived"
    RUNTIME_CONFIRMED = "runtime_confirmed"
    INFERRED = "inferred"
    UNRESOLVED = "unresolved"


@dataclass
class BomComponent:
    component_type: str    # "os" | "kernel" | "kernel_module" |
                           # "crypto_provider" | "crypto_implementation"
                           # | "hardware_trust" | "crypto_hardware"
    name: str
    version: str = ""      # "" = unknown — never guessed
    properties: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": self.component_type,
            "name": self.name,
            # an empty version is RENDERED as unknown by consumers; the
            # property says so explicitly
            "version": self.version,
            "properties": self.properties,
        }


@dataclass
class BomRelationship:
    source: str
    relationship: str      # "provides" | "contains" | "anchors"
    target: str
    provenance: str
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "relationship": self.relationship,
            "target": self.target,
            "provenance": self.provenance,
            "limitations": self.limitations,
        }


@dataclass
class OSBom:
    kind: str
    subject: str
    components: List[BomComponent] = field(default_factory=list)
    relationships: List[BomRelationship] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    schema_name: str = BOM_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema_name,
            "kind": self.kind,
            "subject": self.subject,
            "components": [c.as_dict() for c in self.components],
            "relationships": [r.as_dict() for r in self.relationships],
            "coverage": self.coverage,
            "note": "a projection of ONE read-only OS collection into "
                    "the shared BOM ecosystem — components are "
                    "registrations and metadata, never proof of "
                    "runtime use (§2.2); relationship vocabulary is "
                    "provides/contains/anchors only: this engine "
                    "emits NO 'uses' edge, and never infers "
                    "application↔kernel relationships from same-host "
                    "co-location (§8)",
        }


def _limit_base() -> List[str]:
    return [
        "registered capability or collected metadata — never proof of "
        "runtime use (§2.2)",
    ]


def _kernel_component(inventory: Dict[str, Any]) -> BomComponent:
    identity = inventory.get("identity", {}) or {}
    release = str(identity.get("kernel_release", "unknown"))
    version = "" if release in ("", "unknown") else release
    return BomComponent(
        component_type="kernel",
        name=f"{identity.get('kernel_name', 'Linux')} kernel",
        version=version,
        properties={
            "evidence_source": "uname / /proc/version",
            "observation_type": "metadata_extraction",
            "runtime_usage_confirmed": False,
            "kernel_version_raw": identity.get("kernel_version")
                                 or "unknown",
            "limitations": _limit_base() + [
                "kernel version strings are collected metadata — they "
                "are not a vulnerability assessment (OS-CRYPTO-011 is "
                "not evaluated)"] if version else _limit_base() + [
                "kernel release unavailable — version unknown, never "
                "guessed (§2.1)"],
        })


def build_sbom(inventory: Dict[str, Any]) -> OSBom:
    """Software view: OS, kernel, loaded modules, provider modules.
    Module versions are NOT reported by /proc/modules — they stay
    unknown, never guessed."""
    subject = str(inventory.get("host_id", "unknown"))
    bom = OSBom(kind="sbom", subject=subject,
                coverage=dict(inventory.get("coverage", {}) or {}))
    identity = inventory.get("identity", {}) or {}
    if identity:
        pretty = str(identity.get("os_pretty_name", "unknown"))
        bom.components.append(BomComponent(
            component_type="os",
            name=pretty if pretty != "unknown" else "unknown OS",
            version=str(identity.get("os_version_id", "") or ""),
            properties={
                "evidence_source": "/etc/os-release",
                "observation_type": "metadata_extraction",
                "runtime_usage_confirmed": False,
                "limitations": _limit_base() + ([
                    "os-release unavailable — distribution unknown, "
                    "never guessed (§2.1)"] if pretty == "unknown" else []),
            }))
    bom.components.append(_kernel_component(inventory))
    bom.relationships.append(BomRelationship(
        source="os", relationship="contains", target="kernel",
        provenance=RelationshipProvenance.DIRECTLY_OBSERVED))
    for mod in inventory.get("modules", []) or []:
        name = str(mod.get("name", ""))
        if not name:
            continue
        bom.components.append(BomComponent(
            component_type="kernel_module",
            name=name,
            version="",  # /proc/modules reports no version — unknown
            properties={
                "evidence_source": "/proc/modules",
                "observation_type": "loaded_module",
                "runtime_usage_confirmed": False,
                "state": mod.get("state") or "unknown",
                "used_by_modules": mod.get("used_by") or [],
                "limitations": _limit_base() + [
                    "module version is not reported by /proc/modules "
                    "— unknown, never guessed",
                    "a module's used_by list is KERNEL-internal module "
                    "dependencies — it is never evidence of which "
                    "application uses this module"],
            }))
        bom.relationships.append(BomRelationship(
            source="kernel", relationship="contains", target=name,
            provenance=RelationshipProvenance.DIRECTLY_OBSERVED))
    for entry in inventory.get("crypto_api", []) or []:
        module = str(entry.get("module", "") or "").strip()
        if module and module not in ("kernel", "(built-in or unknown)"):
            if not any(c.name == module for c in bom.components):
                bom.components.append(BomComponent(
                    component_type="crypto_provider",
                    name=module,
                    version="",
                    properties={
                        "evidence_source": "/proc/crypto (module field)",
                        "observation_type": "registered_capability",
                        "runtime_usage_confirmed": False,
                        "limitations": _limit_base() + [
                            "provider module version is not reported "
                            "— unknown, never guessed"],
                    }))
                bom.relationships.append(BomRelationship(
                    source="kernel", relationship="contains",
                    target=module,
                    provenance=RelationshipProvenance.DIRECTLY_OBSERVED))
    return bom


def build_cbom(inventory: Dict[str, Any]) -> OSBom:
    """Cryptographic view: every registered implementation is a
    component. The generic algorithm name and the implementation
    driver are distinct names on the component. NO 'uses' edge is ever
    emitted — the kernel PROVIDES implementations; which application
    uses them is not established by this engine (§2.2/§8)."""
    subject = str(inventory.get("host_id", "unknown"))
    bom = OSBom(kind="cbom", subject=subject,
                coverage=dict(inventory.get("coverage", {}) or {}))
    bom.components.append(_kernel_component(inventory))
    seen = set()
    for entry in inventory.get("crypto_api", []) or []:
        algorithm = str(entry.get("algorithm", ""))
        driver = str(entry.get("driver", ""))
        key = (algorithm, driver)
        if not algorithm or key in seen:
            continue
        seen.add(key)
        key_range = entry.get("key_size_range")
        properties: Dict[str, Any] = {
            "evidence_source": "Linux Kernel Crypto API (/proc/crypto)",
            "observation_type": "registered_capability",
            "runtime_usage_confirmed": False,
            "implementation_driver": driver or "unreported",
            "generic_algorithm_name": algorithm,
            "implementation_type": entry.get("type") or "unreported",
            "selftest": entry.get("selftest") or "unreported",
            "hardware_accelerated_indicator":
                entry.get("hardware_accelerated"),
            "limitations": _limit_base() + [
                "the generic algorithm name and the implementation "
                "driver are distinct (§2.2)"],
        }
        if key_range:
            properties["key_size_bits"] = key_range
        else:
            properties["key_size_bits"] = None
            properties["limitations"].append(
                "key size unknown — never guessed")
        bom.components.append(BomComponent(
            component_type="crypto_implementation",
            name=f"{algorithm} ({driver or 'unreported'})",
            version="",
            properties=properties))
        # provides, never uses
        bom.relationships.append(BomRelationship(
            source="kernel", relationship="provides",
            target=f"{algorithm} ({driver or 'unreported'})",
            provenance=RelationshipProvenance.DIRECTLY_OBSERVED,
            limitations=[
                "'provides' means the implementation is registered — "
                "it is NOT a 'uses' claim about any application (§2.2); "
                "this engine emits no uses edges at all (§8)"]))
    return bom


def build_hbom(inventory: Dict[str, Any]) -> OSBom:
    """Hardware view: hardware trust facts and hardware-accelerated
    implementation indicators. Device presence is metadata, never a
    trust verdict (§12)."""
    subject = str(inventory.get("host_id", "unknown"))
    bom = OSBom(kind="hbom", subject=subject,
                coverage=dict(inventory.get("coverage", {}) or {}))
    for fact in inventory.get("hardware_trust", []) or []:
        name = str(fact.get("subject", ""))
        if not name:
            continue
        bom.components.append(BomComponent(
            component_type="hardware_trust",
            name=name,
            version="",
            properties={
                "evidence_source": "device presence (/dev)",
                "observation_type": "device_presence",
                "runtime_usage_confirmed": False,
                "state": fact.get("state") or "unknown",
                "evidence_class": fact.get("evidence_class") or "unknown",
                "limitations": _limit_base() + [
                    "device presence is metadata, never a trust "
                    "verdict (§12)",
                    "an unavailable source is never proof of absence "
                    "(§2.1)"],
            }))
        bom.relationships.append(BomRelationship(
            source="host", relationship="anchors", target=name,
            provenance=RelationshipProvenance.DIRECTLY_OBSERVED,
            limitations=["'anchors' records a hardware trust FACTOR "
                         "observed on this host — not a trust rating"]))
    for entry in inventory.get("crypto_api", []) or []:
        if entry.get("hardware_accelerated") is True:
            driver = str(entry.get("driver", ""))
            algorithm = str(entry.get("algorithm", ""))
            bom.components.append(BomComponent(
                component_type="crypto_hardware",
                name=f"{algorithm} ({driver})",
                version="",
                properties={
                    "evidence_source": "Linux Kernel Crypto API "
                                       "(/proc/crypto) driver-name "
                                       "heuristic",
                    "observation_type": "registered_capability",
                    "runtime_usage_confirmed": False,
                    "indicator_only": True,
                    "limitations": _limit_base() + [
                        "hardware acceleration here is an INDICATOR "
                        "from the driver name — it is not a hardware "
                        "attestation and never names a physical "
                        "device"],
                }))
    return bom


def build_techbom(inventory: Dict[str, Any]) -> OSBom:
    """The union view: software + cryptographic + hardware components
    under one schema, with the per-source coverage preserved."""
    subject = str(inventory.get("host_id", "unknown"))
    bom = OSBom(kind="techbom", subject=subject,
                coverage=dict(inventory.get("coverage", {}) or {}))
    for builder in (build_sbom, build_cbom, build_hbom):
        sub = builder(inventory)
        bom.components.extend(sub.components)
        bom.relationships.extend(sub.relationships)
    # de-duplicate components by (type, name, version)
    seen = set()
    unique: List[BomComponent] = []
    for c in bom.components:
        key = (c.component_type, c.name, c.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    bom.components = unique
    bom.coverage["projections"] = ["sbom", "cbom", "hbom"]
    return bom


_BUILDERS = {
    "sbom": build_sbom,
    "cbom": build_cbom,
    "hbom": build_hbom,
    "techbom": build_techbom,
}


def build_bom(kind: str, inventory: Dict[str, Any]) -> OSBom:
    """Build one BOM projection. An unknown kind is refused, never
    guessed."""
    if kind not in _BUILDERS:
        raise ValueError(
            f"unknown BOM kind {kind!r} — expected one of {BOM_KINDS}")
    return _BUILDERS[kind](inventory)
