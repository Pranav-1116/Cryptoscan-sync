"""Universal Hardware Scanner — shared data models (§1–§25).

Canonical hardware shapes every hardware plugin must produce:
HardwareIdentity (multi-signal, never serial-only), HardwareObservation
(evidence-bearing), CryptoCapability (supported-by-hardware vs
actually-used-by-software), hardware state, and the OBSERVED /
PROVIDER_DECLARED / INFERRED / UNKNOWN cloud-visibility ladder (§13).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Hardware categories (§1) ────────────────────────────────────────────

class HardwareType(str, Enum):
    # compute
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    BLADE_SERVER = "blade_server"
    RACK_SERVER = "rack_server"
    HYPERVISOR_HOST = "hypervisor_host"
    VIRTUALIZATION = "virtualization"
    GPU = "gpu"
    ACCELERATOR = "accelerator"
    # network
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    WIRELESS_CONTROLLER = "wireless_controller"
    ACCESS_POINT = "access_point"
    LOAD_BALANCER = "load_balancer"
    NETWORK_APPLIANCE = "network_appliance"
    # security
    HSM = "hsm"
    TPM = "tpm"
    SMART_CARD = "smart_card"
    SECURE_ELEMENT = "secure_element"
    SECURITY_APPLIANCE = "security_appliance"
    # storage
    SAN = "san"
    NAS = "nas"
    RAID_CONTROLLER = "raid_controller"
    STORAGE_APPLIANCE = "storage_appliance"
    DISK_ENCRYPTION_CONTROLLER = "disk_encryption_controller"
    # industrial / IoT
    IOT_GATEWAY = "iot_gateway"
    INDUSTRIAL_CONTROLLER = "industrial_controller"
    PLC = "plc"
    OT_APPLIANCE = "ot_appliance"
    EMBEDDED = "embedded"
    OTHER = "other"


class DiscoveryMethod(str, Enum):
    """§2 — never rely on one discovery method."""
    AGENT = "agent"       # OS/BMC, PCI/USB, DMI/SMBIOS
    NETWORK = "network"   # SNMP, SSH, LLDP, CDP, passive observation
    API = "api"           # management/virtualization/storage/cloud APIs


class HardwareConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CloudVisibility(str, Enum):
    """§13 — do not claim physical host knowledge the provider hides."""
    OBSERVED = "OBSERVED"                  # we saw the physical device
    PROVIDER_DECLARED = "PROVIDER_DECLARED"  # cloud provider documented it
    INFERRED = "INFERRED"                  # deduced from instance type
    UNKNOWN = "UNKNOWN"


class FirmwareComponent(str, Enum):
    BIOS = "BIOS"
    UEFI = "UEFI"
    BMC = "BMC"
    NIC = "NIC"
    RAID = "RAID"
    HBA = "HBA"
    TPM = "TPM"
    HSM = "HSM"
    STORAGE = "STORAGE"
    NETWORK_APPLIANCE = "NETWORK_APPLIANCE"
    GPU = "GPU"
    OTHER = "OTHER"


class HardwareDriftType(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    UNEXPECTED_DEVICE = "UNEXPECTED_DEVICE"
    UNEXPECTED_REPLACEMENT = "UNEXPECTED_REPLACEMENT"
    FIRMWARE_DRIFT = "FIRMWARE_DRIFT"
    BIOS_DRIFT = "BIOS_DRIFT"
    NIC_DRIFT = "NIC_DRIFT"
    TPM_DRIFT = "TPM_DRIFT"
    HSM_DRIFT = "HSM_DRIFT"
    CRYPTO_CAPABILITY_DRIFT = "CRYPTO_CAPABILITY_DRIFT"
    SECURITY_HARDWARE_DRIFT = "SECURITY_HARDWARE_DRIFT"


# ── Hardware identity (§3) ──────────────────────────────────────────────

class HardwareIdentity(BaseModel):
    """Canonical identity. Never depends exclusively on serial numbers —
    virtualized/network environments expose incomplete or duplicated
    identifiers, so identity resolution uses multiple signals."""

    asset_id: str
    manufacturer: str = ""
    model: str = ""
    serial_reference: Optional[str] = None   # one signal among many
    device_type: str = HardwareType.OTHER.value
    firmware: Optional[str] = None
    hardware_revision: Optional[str] = None
    location_reference: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    source: str = "unknown"                  # agent | network | api
    confidence: str = HardwareConfidence.LOW.value
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── Crypto capability (§10) ─────────────────────────────────────────────

class CryptoCapability(BaseModel):
    """Universal hardware crypto capability model.

    Critically, 'supported by hardware' and 'actually used by software' are
    SEPARATE — presence of AES-NI does not mean an app uses it (§5, §10).
    """

    aes: bool = False
    sha2: bool = False
    sha3: bool = False
    rsa: bool = False
    ecc: bool = False
    ecdsa: bool = False
    ecdh: bool = False
    rng: bool = False
    secure_key_storage: bool = False
    pqc_hybrid: bool = False

    # supported_by_hardware vs used_by_software (both optional lists)
    supported_algorithms: list[str] = Field(default_factory=list)
    used_algorithms: list[str] = Field(default_factory=list)

    def supported(self, name: str) -> bool:
        return getattr(self, name, False)

    def used(self, name: str) -> bool:
        if not getattr(self, name, False):
            return False
        wanted = name.lower()
        return any(item.lower() == wanted for item in self.used_algorithms)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── CPU (§5) ────────────────────────────────────────────────────────────

class CpuInfo(BaseModel):
    vendor: Optional[str] = None
    family: Optional[str] = None
    model: Optional[str] = None
    architecture: Optional[str] = None
    instruction_extensions: list[str] = Field(default_factory=list)
    core_count: Optional[int] = None
    thread_count: Optional[int] = None
    microcode_version: Optional[str] = None

    # crypto-relevant capabilities — presence ≠ usage (§5)
    aes_acceleration: bool = False
    sha_acceleration: bool = False
    hardware_rng: bool = False
    trusted_execution: bool = False

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── TPM (§6) ────────────────────────────────────────────────────────────

class TpmInfo(BaseModel):
    present: bool = False
    version: Optional[str] = None            # "1.2" | "2.0"
    manufacturer: Optional[str] = None
    firmware: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)
    supported_algorithms: list[str] = Field(default_factory=list)  # e.g. SHA-256, RSA, ECC
    pcr_capabilities: list[str] = Field(default_factory=list)
    secure_boot_relationship: Optional[str] = None   # "enabled" | "disabled" | "unknown"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── Firmware state (§9, §16) ────────────────────────────────────────────

@dataclass
class FirmwareState:
    asset_id: str
    component: str = FirmwareComponent.OTHER.value
    current: Optional[str] = None
    previous: Optional[str] = None
    changed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "component": self.component,
                "current": self.current, "previous": self.previous,
                "changed_at": self.changed_at}


# ── 24/7 hardware state (§16) ───────────────────────────────────────────

@dataclass
class HardwareState:
    """Live 24/7 hardware state (§3 of the live spec).

    The database row built from this is the current truth of the observed
    environment; ``previous_state`` preserves the prior snapshot so every
    change is reconstructable (and the timeline engine can replay it).
    """

    asset_id: str
    manufacturer: str = ""
    model: str = ""
    device_type: str = HardwareType.OTHER.value
    serial_reference: Optional[str] = None
    hardware_revision: Optional[str] = None
    agent_id: Optional[str] = None
    current_fingerprint: Optional[str] = None
    previous_fingerprint: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_verified: Optional[str] = None
    last_firmware_check: Optional[str] = None
    last_crypto_check: Optional[str] = None
    last_change: Optional[str] = None
    evidence_history: list[str] = field(default_factory=list)
    firmware: dict[str, str] = field(default_factory=dict)   # component -> version
    tpm: Optional[dict[str, Any]] = None
    hsm: Optional[dict[str, Any]] = None
    capabilities: Optional[dict[str, Any]] = None
    crypto_capabilities: Optional[dict[str, Any]] = None
    previous_state: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "manufacturer": self.manufacturer,
                "model": self.model, "device_type": self.device_type,
                "serial_reference": self.serial_reference,
                "hardware_revision": self.hardware_revision,
                "agent_id": self.agent_id,
                "current_fingerprint": self.current_fingerprint,
                "previous_fingerprint": self.previous_fingerprint,
                "first_seen": self.first_seen, "last_seen": self.last_seen,
                "last_verified": self.last_verified,
                "last_firmware_check": self.last_firmware_check,
                "last_crypto_check": self.last_crypto_check,
                "last_change": self.last_change,
                "evidence_history": list(self.evidence_history),
                "firmware": dict(self.firmware),
                "tpm": self.tpm, "hsm": self.hsm,
                "capabilities": self.capabilities,
                "crypto_capabilities": self.crypto_capabilities,
                "previous_state": self.previous_state}


# ── Canonical hardware observation ─────────────────────────────────────

class HardwareObservation(BaseModel):
    """Canonical, evidence-bearing hardware observation."""

    asset_id: str
    manufacturer: str
    model: str
    serial_reference: Optional[str] = None
    device_type: str = HardwareType.OTHER.value
    firmware: Optional[str] = None
    hardware_revision: Optional[str] = None
    environment: Optional[str] = None
    region: Optional[str] = None
    source: str = "unknown"                 # discovery method used
    confidence: str = HardwareConfidence.LOW.value
    visibility: str = CloudVisibility.OBSERVED.value

    cpu: Optional[dict[str, Any]] = None
    tpm: Optional[dict[str, Any]] = None
    hsm: Optional[dict[str, Any]] = None
    capabilities: Optional[dict[str, Any]] = None
    firmware_components: dict[str, str] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)

    # vendor/hardware-specific data preserved verbatim
    vendor_specific: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
