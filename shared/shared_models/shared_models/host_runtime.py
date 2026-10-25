"""Typed passive runtime metadata. Mapping/listening is NOT cryptographic use."""

from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict


class RuntimeFact(Strict):
    kind: Literal["PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["HOST_RUNTIME_METADATA"] = "HOST_RUNTIME_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    interface: Literal["LINUX_PROCFS", "LINUX_SYSFS", "SYSTEMD_READ_ONLY", "WINDOWS_SCM"]
    interface_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    identity_key: str = Field(min_length=1, max_length=300, pattern=r"^[^\x00-\x1f\x7f]+$")
    pid: int | None = Field(default=None, ge=1, le=2147483647)
    process_start_ticks: int | None = Field(default=None, ge=1)
    boot_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    process_name: str | None = Field(default=None, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    library_path: str | None = Field(default=None, max_length=1024, pattern=r"^/[^\x00-\x1f\x7f]+$")
    mapped_file_deleted: bool | None = None
    mapping_basis: Literal["SHARED_OBJECT_PATH_SUFFIX_ONLY"] | None = None
    service_name: str | None = Field(default=None, max_length=120, pattern=r"^[A-Za-z0-9_.@:-]+$")
    service_state: (
        Literal[
            "active",
            "inactive",
            "activating",
            "deactivating",
            "failed",
            "reloading",
            "maintenance",
            "refreshing",
            "RUNNING",
            "STOPPED",
            "START_PENDING",
            "STOP_PENDING",
            "CONTINUE_PENDING",
            "PAUSE_PENDING",
            "PAUSED",
        ]
        | None
    ) = None
    network_namespace: str | None = Field(default=None, max_length=80, pattern=r"^net:\[[0-9]+\]$")
    address: str | None = Field(default=None, max_length=80)
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal["TCP", "TCP6"] | None = None
    socket_inode: int | None = Field(default=None, ge=1)
    hardware_type: Literal["SYSTEM_DMI", "TPM", "CPU_TOPOLOGY"] | None = None
    cpu_index: int | None = Field(default=None, ge=0, le=9999)
    core_id: int | None = Field(default=None, ge=0, le=2147483647)
    package_id: int | None = Field(default=None, ge=0, le=2147483647)
    manufacturer: str | None = Field(default=None, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    model: str | None = Field(default=None, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    firmware_version: str | None = Field(default=None, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    tpm_major_version: Literal[1, 2] | None = None
    capabilities_observed: Literal[False] = False
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def coherence(self):
        groups = {
            "PROCESS": {"pid", "process_start_ticks", "boot_id", "process_name", "service_name"},
            "LOADED_LIBRARY": {
                "pid",
                "process_start_ticks",
                "boot_id",
                "library_path",
                "mapped_file_deleted",
                "mapping_basis",
            },
            "LISTENER": {"network_namespace", "boot_id", "address", "port", "transport", "socket_inode"},
            "SERVICE": {"service_name", "service_state", "pid"},
            "HARDWARE": {
                "hardware_type",
                "manufacturer",
                "model",
                "firmware_version",
                "tpm_major_version",
                "cpu_index",
                "core_id",
                "package_id",
            },
        }
        fields = set().union(*groups.values())
        if any(getattr(self, k) is not None for k in fields - groups[self.kind]):
            raise ValueError("Runtime metadata fields do not belong to this fact kind")
        required = {
            "PROCESS": ["pid", "process_start_ticks", "boot_id", "process_name"],
            "LOADED_LIBRARY": [
                "pid",
                "process_start_ticks",
                "boot_id",
                "library_path",
                "mapped_file_deleted",
                "mapping_basis",
            ],
            "LISTENER": ["network_namespace", "boot_id", "address", "port", "transport", "socket_inode"],
            "SERVICE": ["service_name", "service_state"],
            "HARDWARE": ["hardware_type"],
        }
        if any(getattr(self, k) is None for k in required[self.kind]):
            raise ValueError("Incomplete runtime metadata")
        if self.kind == "LISTENER":
            import ipaddress

            address = ipaddress.ip_address(self.address)
            if (address.version == 6) != (self.transport == "TCP6"):
                raise ValueError("Address family mismatch")
        if self.kind in {"PROCESS", "LOADED_LIBRARY", "LISTENER"} and self.interface != "LINUX_PROCFS":
            raise ValueError("Unsupported runtime evidence interface")
        if self.kind == "SERVICE" and self.interface not in {"SYSTEMD_READ_ONLY", "WINDOWS_SCM"}:
            raise ValueError("Service state requires a supported native interface")
        if self.kind == "HARDWARE" and self.interface != "LINUX_SYSFS":
            raise ValueError("Hardware requires sysfs")
        if self.kind == "PROCESS":
            expected = f"{self.boot_id}:{self.pid}:{self.process_start_ticks}"
        elif self.kind == "LOADED_LIBRARY":
            import hashlib

            expected = f"{self.boot_id}:{self.pid}:{self.process_start_ticks}:{hashlib.sha256(self.library_path.encode()).hexdigest()}:{int(self.mapped_file_deleted)}"
        elif self.kind == "LISTENER":
            expected = f"{self.boot_id}:{self.network_namespace}:{self.socket_inode}"
        elif self.kind == "SERVICE":
            expected = self.service_name
            if self.service_state.isupper() != (self.interface == "WINDOWS_SCM"):
                raise ValueError("Service state belongs to another native interface")
        else:
            expected = self.identity_key
            cpu = [self.cpu_index, self.core_id, self.package_id]
            if self.hardware_type == "CPU_TOPOLOGY":
                if (
                    any(v is None for v in cpu)
                    or any([self.manufacturer, self.model, self.firmware_version, self.tpm_major_version])
                    or self.identity_key != f"cpu{self.cpu_index}"
                ):
                    raise ValueError("CPU topology requires only explicit observed indexes")
            elif any(v is not None for v in cpu):
                raise ValueError("CPU fields require CPU topology")
            elif self.hardware_type == "SYSTEM_DMI":
                if (
                    not any([self.manufacturer, self.model, self.firmware_version])
                    or self.tpm_major_version is not None
                ):
                    raise ValueError("DMI requires actual non-TPM metadata")
            elif self.tpm_major_version is None or any([self.manufacturer, self.model, self.firmware_version]):
                raise ValueError("TPM profile exposes version only")
        if self.identity_key != expected:
            raise ValueError("Runtime identity does not match observed subject")
        return self


def domains(fact):
    if fact.kind in {"CERTIFICATE", "TLS_CONFIGURATION"}:
        return ["CBOM", "TechBOM"]
    if fact.kind in {"BINARY", "SOFTWARE", "LOADED_LIBRARY", "WINDOWS_MODULE"}:
        return ["SBOM", "TechBOM"]
    if fact.kind in {"LISTENER", "WINDOWS_TCP_LISTENER_TABLE"}:
        return ["NBOM", "TechBOM"]
    if fact.kind in {"HARDWARE", "WINDOWS_TPM_METADATA"}:
        return ["HBOM", "TechBOM"]
    return ["TechBOM"]
