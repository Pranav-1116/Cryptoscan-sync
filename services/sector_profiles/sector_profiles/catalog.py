"""Sector Profile catalog — the Sector Layer of the ZELNX architecture.

The platform runs ONE universal scanning engine; sectors do not get separate
scanners. A ``SectorProfile`` is *context and decision layer only*: it changes
which assets matter most, which policy packs apply, which compliance
frameworks findings map to, how business criticality is weighted, what
evidence is required, and which scan modes are recommended.

    Universal Scanner + Sector Profile + Policy Pack + Criticality Model

Everything here is deterministic data and pure functions (no AI, no network)
— the engine discovers facts, this catalog only contextualizes them.

Sectors mirror the ZELNX sector set: banking, healthcare, energy, telecom,
government, manufacturing, automotive, pharmaceutical, retail, cloud_saas —
plus ``generic`` for an unprofiled estate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# Criticality tiers
# --------------------------------------------------------------------------- #

CRITICALITY_TIERS = ("VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH", "MISSION_CRITICAL")

TIER_RANK = {name: i for i, name in enumerate(CRITICALITY_TIERS)}


@dataclass(frozen=True)
class SectorProfile:
    """Context for one regulated sector. None of this changes the scanner;
    it changes how findings are prioritized, mapped and evidenced."""

    id: str
    name: str
    description: str
    #: regulated data/asset classes the sector cares most about
    critical_asset_classes: tuple[str, ...]
    #: policy packs (services/policy/rule_definitions) to apply by default
    policy_packs: tuple[str, ...]
    #: compliance frameworks findings are mapped onto
    compliance_frameworks: tuple[str, ...]
    #: domain scan modes recommended for this sector (see scan_modes.py)
    recommended_modes: tuple[str, ...]
    #: asset-type keyword -> tier, used by the criticality scorer
    asset_criticality: dict[str, str]
    #: extra evidence required beyond the default hash-chained observation
    required_evidence: tuple[str, ...] = ()
    #: integration connectors this sector typically enables
    integrations: tuple[str, ...] = ()
    #: operational notes (e.g. passive-only for OT)
    scanning_notes: tuple[str, ...] = ()
    #: environment separation emphasis (e.g. IT/OT for industrial sectors)
    environment_separation: tuple[str, ...] = ()

    def criticality_for(self, asset_type: str, **signals: Any) -> str:
        from sector_profiles.criticality import score_criticality

        return score_criticality(self, asset_type, **signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "critical_asset_classes": list(self.critical_asset_classes),
            "policy_packs": list(self.policy_packs),
            "compliance_frameworks": list(self.compliance_frameworks),
            "recommended_modes": list(self.recommended_modes),
            "asset_criticality": dict(self.asset_criticality),
            "required_evidence": list(self.required_evidence),
            "integrations": list(self.integrations),
            "scanning_notes": list(self.scanning_notes),
            "environment_separation": list(self.environment_separation),
        }


# --------------------------------------------------------------------------- #
# The catalog
# --------------------------------------------------------------------------- #

_OT_NOTES = (
    "Passive/low-impact discovery preferred for OT; avoid aggressive active probing",
    "Read-only collection; never write to PLCs/RTUs or control networks",
)

SECTOR_PROFILES: dict[str, SectorProfile] = {
    "banking": SectorProfile(
        id="banking",
        name="Banking & Financial Services",
        description="Core banking, payments, SWIFT, cards, HSM/PKI, digital channels.",
        critical_asset_classes=(
            "payment_hsm", "pki", "core_banking", "payment_system", "swift",
            "atm", "online_banking", "mobile_banking", "api_gateway", "kms",
        ),
        policy_packs=("nist", "pci_dss", "fips", "baseline"),
        compliance_frameworks=("PCI-DSS", "NIST-CSF", "GLBA", "SWIFT-CSCF", "EBA-GL", "ISO-27001"),
        recommended_modes=("discovery", "standard", "deep", "compliance", "continuous"),
        asset_criticality={
            "hsm": "MISSION_CRITICAL",
            "payment": "MISSION_CRITICAL",
            "swift": "MISSION_CRITICAL",
            "pki": "VERY_HIGH",
            "core": "VERY_HIGH",
            "atm": "VERY_HIGH",
            "gateway": "HIGH",
            "online": "HIGH",
            "mobile": "HIGH",
            "workstation": "LOW",
            "dev": "LOW",
        },
        required_evidence=("hsm_ceremony_provenance", "key_management_metadata", "dual_control_records"),
        integrations=("smtp", "siem_cef", "webhook_alert", "github"),
        scanning_notes=("Payment HSM ceremony provenance must accompany any key inventory finding",),
    ),
    "healthcare": SectorProfile(
        id="healthcare",
        name="Healthcare & Medical",
        description="EHR, medical devices, imaging, laboratory, patient APIs, identity.",
        critical_asset_classes=(
            "ehr", "medical_device", "patient_api", "imaging", "laboratory",
            "identity_system", "hsm", "certificate",
        ),
        policy_packs=("hipaa", "nist", "fips", "baseline"),
        compliance_frameworks=("HIPAA", "HITECH", "NIST-CSF", "FDA-Premarket", "ISO-27799", "GDPR"),
        recommended_modes=("discovery", "standard", "passive", "compliance", "continuous"),
        asset_criticality={
            "medical": "MISSION_CRITICAL",
            "patient": "MISSION_CRITICAL",
            "ehr": "MISSION_CRITICAL",
            "imaging": "HIGH",
            "laboratory": "HIGH",
            "identity": "VERY_HIGH",
            "hsm": "VERY_HIGH",
            "certificate": "HIGH",
        },
        required_evidence=("phi_flow_metadata", "access_control_evidence"),
        integrations=("smtp", "siem_cef", "webhook_alert"),
        scanning_notes=("Patient-safety systems: passive discovery; never disrupt device sessions",),
    ),
    "energy": SectorProfile(
        id="energy",
        name="Energy & Utilities",
        description="Generation, transmission, distribution; SCADA/ICS/PLC/RTU, substations.",
        critical_asset_classes=(
            "scada", "ics", "plc", "rtu", "substation", "control_system",
            "remote_access", "hsm", "certificate",
        ),
        policy_packs=("nist", "fips", "baseline"),
        compliance_frameworks=("NERC-CIP", "NIST-CSF", "NIST-800-82", "IEC-62443", "ISO-27001"),
        recommended_modes=("discovery", "passive", "standard", "targeted", "continuous"),
        asset_criticality={
            "scada": "MISSION_CRITICAL",
            "ics": "MISSION_CRITICAL",
            "plc": "MISSION_CRITICAL",
            "rtu": "VERY_HIGH",
            "substation": "MISSION_CRITICAL",
            "control": "MISSION_CRITICAL",
            "remote": "VERY_HIGH",
            "hsm": "HIGH",
        },
        required_evidence=("it_ot_segregation_evidence", "passive_capture_record"),
        integrations=("siem_cef", "webhook_alert", "smtp"),
        scanning_notes=_OT_NOTES,
        environment_separation=("IT", "OT"),
    ),
    "telecom": SectorProfile(
        id="telecom",
        name="Telecommunications",
        description="Core network, RAN, 5G, IMS, network functions, edge, IPsec/TLS.",
        critical_asset_classes=(
            "core_network", "ran", "5g", "ims", "network_function", "edge",
            "subscriber_system", "ipsec", "tls_gateway",
        ),
        policy_packs=("nist", "fips", "cnsa", "baseline"),
        compliance_frameworks=("NIST-CSF", "3GPP-Security", "GDPR", "ISO-27001", "CNSA-2.0"),
        recommended_modes=("discovery", "standard", "deep", "continuous", "pqc"),
        asset_criticality={
            "core": "MISSION_CRITICAL",
            "5g": "MISSION_CRITICAL",
            "ran": "VERY_HIGH",
            "ims": "VERY_HIGH",
            "network_function": "HIGH",
            "edge": "HIGH",
            "subscriber": "VERY_HIGH",
            "ipsec": "HIGH",
        },
        required_evidence=("network_function_crypto_map",),
        integrations=("siem_cef", "webhook_alert"),
        scanning_notes=("PQC exposure of long-lived IPsec/TLS associations is high priority",),
    ),
    "government": SectorProfile(
        id="government",
        name="Government & Public Sector",
        description="Federal/national systems, classified zones, PQC mandates, smart cards.",
        critical_asset_classes=(
            "classified_system", "identity_system", "pki", "hsm", "smart_card",
            "secure_gateway", "citizen_api",
        ),
        policy_packs=("cnsa", "fips", "nist", "baseline"),
        compliance_frameworks=("FIPS-140-3", "CNSA-2.0", "FedRAMP", "NIST-800-53", "NIST-CSF"),
        recommended_modes=("discovery", "standard", "deep", "compliance", "pqc"),
        asset_criticality={
            "classified": "MISSION_CRITICAL",
            "pki": "MISSION_CRITICAL",
            "hsm": "MISSION_CRITICAL",
            "identity": "VERY_HIGH",
            "smart_card": "HIGH",
            "gateway": "VERY_HIGH",
            "citizen": "HIGH",
        },
        required_evidence=("fips_module_validation", "cnsa_algorithm_inventory"),
        integrations=("siem_cef", "webhook_alert", "smtp"),
        scanning_notes=("CNSA 2.0 transition posture is a primary reporting metric",),
    ),
    "manufacturing": SectorProfile(
        id="manufacturing",
        name="Manufacturing & Industrial",
        description="Factories, robots, industrial controllers, MES/ERP, firmware, OT.",
        critical_asset_classes=(
            "plc", "robot", "industrial_controller", "scada", "mes", "erp",
            "firmware", "ot_network",
        ),
        policy_packs=("nist", "fips", "baseline"),
        compliance_frameworks=("IEC-62443", "NIST-800-82", "NIST-CSF", "ISO-27001"),
        recommended_modes=("discovery", "passive", "standard", "targeted", "continuous"),
        asset_criticality={
            "plc": "VERY_HIGH",
            "robot": "VERY_HIGH",
            "scada": "MISSION_CRITICAL",
            "controller": "VERY_HIGH",
            "mes": "HIGH",
            "erp": "HIGH",
            "firmware": "HIGH",
        },
        required_evidence=("firmware_crypto_inventory", "it_ot_segregation_evidence"),
        integrations=("webhook_alert", "siem_cef"),
        scanning_notes=_OT_NOTES,
        environment_separation=("IT", "OT"),
    ),
    "automotive": SectorProfile(
        id="automotive",
        name="Automotive",
        description="Vehicles, V2X, ECUs, firmware, connected-car cloud, supply chain.",
        critical_asset_classes=(
            "v2x", "ecu", "vehicle_firmware", "connected_car_cloud", "key_management",
            "ota_update", "supply_chain",
        ),
        policy_packs=("nist", "fips", "baseline"),
        compliance_frameworks=("ISO-21434", "UNECE-R155/R156", "NIST-CSF", "IEC-62443"),
        recommended_modes=("discovery", "deep", "standard", "pqc", "compliance"),
        asset_criticality={
            "v2x": "MISSION_CRITICAL",
            "ecu": "VERY_HIGH",
            "firmware": "VERY_HIGH",
            "ota": "VERY_HIGH",
            "cloud": "HIGH",
            "supply_chain": "HIGH",
            "key": "VERY_HIGH",
        },
        required_evidence=("firmware_signing_evidence", "supply_chain_crypto_bom"),
        integrations=("webhook_alert", "github"),
        scanning_notes=("Firmware signing and OTA key protection are crown jewels",),
    ),
    "pharmaceutical": SectorProfile(
        id="pharmaceutical",
        name="Pharmaceutical & Life Sciences",
        description="R&D, clinical trials, GxP systems, lab data, manufacturing (OT).",
        critical_asset_classes=(
            "clinical_trial", "gxp_system", "lab_system", "r_and_d", "manufacturing_ot",
            "hsm", "patient_data",
        ),
        policy_packs=("hipaa", "nist", "fips", "baseline"),
        compliance_frameworks=("GxP", "FDA-21-CFR-Part-11", "HIPAA", "GDP", "ISO-27001", "NIST-CSF"),
        recommended_modes=("discovery", "standard", "compliance", "continuous", "passive"),
        asset_criticality={
            "clinical": "MISSION_CRITICAL",
            "gxp": "VERY_HIGH",
            "lab": "HIGH",
            "r_and_d": "VERY_HIGH",
            "manufacturing": "VERY_HIGH",
            "hsm": "HIGH",
            "patient": "VERY_HIGH",
        },
        required_evidence=("data_integrity_evidence", "electronic_signature_records"),
        integrations=("smtp", "webhook_alert", "siem_cef"),
        scanning_notes=("GxP data-integrity (ALCOA+) framing applies to crypto control evidence",),
    ),
    "retail": SectorProfile(
        id="retail",
        name="Retail & E-commerce",
        description="POS, e-commerce, payment processing, loyalty, customer PII.",
        critical_asset_classes=(
            "pos", "payment_terminal", "ecommerce", "payment_processor", "loyalty",
            "customer_pii", "kms",
        ),
        policy_packs=("pci_dss", "nist", "baseline"),
        compliance_frameworks=("PCI-DSS", "NIST-CSF", "GDPR", "CCPA", "ISO-27001"),
        recommended_modes=("discovery", "standard", "deep", "continuous", "compliance"),
        asset_criticality={
            "pos": "VERY_HIGH",
            "payment": "MISSION_CRITICAL",
            "ecommerce": "HIGH",
            "processor": "MISSION_CRITICAL",
            "loyalty": "MEDIUM",
            "customer": "HIGH",
            "kms": "VERY_HIGH",
        },
        required_evidence=("cardholder_data_boundary", "key_management_metadata"),
        integrations=("smtp", "webhook_alert", "github"),
        scanning_notes=("Cardholder data environment boundary drives scope",),
    ),
    "cloud_saas": SectorProfile(
        id="cloud_saas",
        name="Cloud / SaaS-native",
        description="Multi-cloud SaaS, KMS/Key Vault, containers, serverless, APIs.",
        critical_asset_classes=(
            "kms", "key_vault", "container", "serverless", "api", "load_balancer",
            "service_mesh", "certificate",
        ),
        policy_packs=("nist", "fips", "cnsa", "baseline"),
        compliance_frameworks=("SOC2", "ISO-27001", "NIST-CSF", "FedRAMP", "CSA-CCM", "GDPR"),
        recommended_modes=("discovery", "standard", "deep", "continuous", "pqc"),
        asset_criticality={
            "kms": "MISSION_CRITICAL",
            "vault": "MISSION_CRITICAL",
            "container": "MEDIUM",
            "serverless": "MEDIUM",
            "api": "HIGH",
            "load_balancer": "HIGH",
            "mesh": "HIGH",
            "certificate": "HIGH",
        },
        required_evidence=("cloud_key_inventory", "container_crypto_bom"),
        integrations=("github", "webhook_alert", "siem_cef"),
        scanning_notes=("Provider-managed KMS normalized to CryptoKeyManagementService",),
    ),
    "generic": SectorProfile(
        id="generic",
        name="Generic Enterprise",
        description="Sector-neutral defaults: universal crypto controls without vertical mapping.",
        critical_asset_classes=("pki", "kms", "certificate", "hsm", "load_balancer", "api"),
        policy_packs=("nist", "baseline"),
        compliance_frameworks=("NIST-CSF", "ISO-27001"),
        recommended_modes=("discovery", "standard", "deep", "continuous"),
        asset_criticality={
            "hsm": "VERY_HIGH",
            "kms": "VERY_HIGH",
            "pki": "VERY_HIGH",
            "certificate": "MEDIUM",
            "load_balancer": "MEDIUM",
            "api": "MEDIUM",
        },
        required_evidence=(),
        integrations=("webhook_alert",),
        scanning_notes=(),
    ),
}

#: aliases users might type -> canonical sector id
SECTOR_ALIASES: dict[str, str] = {
    "bank": "banking",
    "banking": "banking",
    "financial": "banking",
    "finance": "banking",
    "fs": "banking",
    "health": "healthcare",
    "healthcare": "healthcare",
    "medical": "healthcare",
    "hospital": "healthcare",
    "energy": "energy",
    "utilities": "energy",
    "utility": "energy",
    "oil_gas": "energy",
    "power": "energy",
    "telecom": "telecom",
    "telecommunications": "telecom",
    "telco": "telecom",
    "government": "government",
    "gov": "government",
    "public_sector": "government",
    "manufacturing": "manufacturing",
    "industrial": "manufacturing",
    "factory": "manufacturing",
    "automotive": "automotive",
    "auto": "automotive",
    "vehicle": "automotive",
    "pharma": "pharmaceutical",
    "pharmaceutical": "pharmaceutical",
    "life_sciences": "pharmaceutical",
    "retail": "retail",
    "ecommerce": "retail",
    "saas": "cloud_saas",
    "cloud": "cloud_saas",
    "cloud_saas": "cloud_saas",
}


def normalize_sector(value: str | None) -> str:
    """Resolve a user-supplied sector string to a catalog id (default generic).

    Accepts exact ids, common aliases, and loose phrasing — the first
    recognized token in a string like 'Banking & Financial Services' wins.
    """
    if not value:
        return "generic"
    key = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if key in SECTOR_PROFILES:
        return key
    if key in SECTOR_ALIASES:
        return SECTOR_ALIASES[key]
    # loose phrasing: try the whole key, then each alphabetic token
    for token in key.replace("&", "_").split("_"):
        token = "".join(ch for ch in token if ch.isalpha())
        if token in SECTOR_PROFILES:
            return token
        if token in SECTOR_ALIASES:
            return SECTOR_ALIASES[token]
    return "generic"


def get_profile(sector: str | None) -> SectorProfile:
    """Return the SectorProfile for a sector (unknown -> generic)."""
    return SECTOR_PROFILES[normalize_sector(sector)]


def list_sectors() -> list[SectorProfile]:
    """All catalog profiles, with `generic` last."""
    ordered = [p for pid, p in SECTOR_PROFILES.items() if pid != "generic"]
    ordered.sort(key=lambda p: p.name)
    ordered.append(SECTOR_PROFILES["generic"])
    return ordered
