"""Explicit read-only resource measurements; imported counters are not host attestation."""

from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated, Literal
from pydantic import Field, StringConstraints, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostManifest, Token, digest
from shared_models.oci_intake import Identifier

Interface = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")]
Counter = Annotated[int, Field(ge=0, le=18446744073709551615)]


class ResourceScope(Strict):
    system_id: Token
    environment: Token
    host_label: Token
    interfaces: list[Interface] = Field(min_length=1, max_length=16)
    mount_paths: list[str] = Field(min_length=1, max_length=16)
    interval_seconds: int = Field(default=5, ge=1, le=30)
    not_before: datetime
    expires_at: datetime

    @field_validator("not_before", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def bounded(self):
        if len(set(self.interfaces)) != len(self.interfaces) or len(set(self.mount_paths)) != len(self.mount_paths):
            raise ValueError("Duplicate interface/path")
        for path in self.mount_paths:
            p = PurePosixPath(path)
            if (
                not p.is_absolute()
                or str(p) != path
                or path.startswith("//")
                or ".." in p.parts
                or len(path) > 1024
                or len(p.parts) > 64
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
            ):
                raise ValueError("Canonical absolute directory paths required")
        if not self.interval_seconds < (self.expires_at - self.not_before).total_seconds() <= 3600:
            raise ValueError("Capture scope must have a positive window of at most one hour")
        return self


class ResourceDecision(Strict):
    expected_revision: int = Field(ge=1, le=2)
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500)


class ResourceAuthorization(Strict):
    schema_version: Literal["cryptoscan.resource-authorization/v1"] = "cryptoscan.resource-authorization/v1"
    plan_id: Identifier
    plan_record_sha256: Digest
    scope_sha256: Digest
    nonce: Digest
    scope: ResourceScope
    authorizes_remote_execution: Literal[False] = False
    authorizes_packet_capture: Literal[False] = False
    authorizes_configuration_change: Literal[False] = False

    @model_validator(mode="after")
    def commitment(self):
        if digest(self.scope) != self.scope_sha256:
            raise ValueError("Scope commitment mismatch")
        return self


class NetworkCounters(Strict):
    rx_bytes: Counter
    tx_bytes: Counter
    rx_packets: Counter
    tx_packets: Counter
    rx_errors: Counter
    tx_errors: Counter
    rx_dropped: Counter
    tx_dropped: Counter


class NetworkReading(Strict):
    interface: Interface
    status: Literal["MEASURED", "UNAVAILABLE", "DENIED", "INVALID", "COUNTER_RESET", "IDENTITY_CHANGED"]
    first: NetworkCounters | None = None
    second: NetworkCounters | None = None
    first_ifindex: int | None = Field(default=None, ge=1, le=2147483647)
    second_ifindex: int | None = Field(default=None, ge=1, le=2147483647)

    @model_validator(mode="after")
    def disposition(self):
        complete = all(v is not None for v in (self.first, self.second, self.first_ifindex, self.second_ifindex))
        if self.status in {"MEASURED", "COUNTER_RESET", "IDENTITY_CHANGED"}:
            if not complete:
                raise ValueError("Counter pairs and interface indices required")
            reset = any(getattr(self.second, k) < getattr(self.first, k) for k in NetworkCounters.model_fields)
            expected = (
                "IDENTITY_CHANGED"
                if self.first_ifindex != self.second_ifindex
                else "COUNTER_RESET"
                if reset
                else "MEASURED"
            )
            if expected != self.status:
                raise ValueError("Counter/identity disposition mismatch")
        elif any(v is not None for v in (self.first, self.second, self.first_ifindex, self.second_ifindex)):
            raise ValueError("Unavailable observations cannot carry positive counters")
        return self


class StorageReading(Strict):
    path: str = Field(min_length=1, max_length=1024)
    status: Literal["MEASURED", "UNAVAILABLE", "DENIED", "UNSUPPORTED", "INVALID"]
    total_bytes: Counter | None = None
    free_bytes: Counter | None = None
    available_bytes: Counter | None = None
    filesystem_device: str | None = Field(default=None, max_length=40, pattern=r"^[0-9]+:[0-9]+$")

    @model_validator(mode="after")
    def disposition(self):
        fields = (self.total_bytes, self.free_bytes, self.available_bytes, self.filesystem_device)
        if self.status == "MEASURED":
            if any(v is None for v in fields) or not self.available_bytes <= self.free_bytes <= self.total_bytes:
                raise ValueError("Filesystem counters inconsistent")
        elif any(v is not None for v in fields):
            raise ValueError("Unavailable filesystem cannot carry capacity claims")
        return self


class ResourceCapture(Strict):
    schema_version: Literal["cryptoscan.resource-capture/v1"] = "cryptoscan.resource-capture/v1"
    capture_id: Identifier
    authorization: ResourceAuthorization
    started_at: datetime
    finished_at: datetime
    elapsed_ns: int = Field(ge=100000000, le=120000000000)
    boot_id: Identifier
    network_namespace_inode: int = Field(ge=1, le=18446744073709551615)
    mount_namespace_inode: int = Field(ge=1, le=18446744073709551615)
    network: list[NetworkReading] = Field(min_length=1, max_length=16)
    storage: list[StorageReading] = Field(min_length=1, max_length=16)
    provenance: Literal["IMPORTED"] = "IMPORTED"
    producer_authenticity_verified: Literal[False] = False
    whole_host_or_network_complete: Literal[False] = False
    packet_payload_captured: Literal[False] = False
    configuration_changed: Literal[False] = False

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def scope(self):
        scope = self.authorization.scope
        if self.elapsed_ns < scope.interval_seconds * 1000000000:
            raise ValueError("Sample interval shorter than approved interval")
        if not scope.not_before <= self.started_at < self.finished_at < scope.expires_at:
            raise ValueError("Measurement must fit the approved scope window")
        if [n.interface for n in self.network] != scope.interfaces or [
            s.path for s in self.storage
        ] != scope.mount_paths:
            raise ValueError("Every approved interface/path must have exactly one ordered disposition")
        return self


class ResourceIntake(Strict):
    capture: ResourceCapture
    expected_capture_sha256: Digest


class TrafficProposal(Strict):
    capture_id: Identifier
    interface: Interface
    egress_limit_mbps: int = Field(ge=1, le=100000)
    reason: str = Field(min_length=20, max_length=500)
    direction: Literal["EGRESS"] = "EGRESS"


def resource_report(capture: ResourceCapture):
    capture = ResourceCapture.model_validate(capture.model_dump())
    seconds = capture.elapsed_ns / 1e9
    network = []
    for item in capture.network:
        delta = (
            {k: getattr(item.second, k) - getattr(item.first, k) for k in NetworkCounters.model_fields}
            if item.status == "MEASURED"
            else None
        )
        network.append(
            {
                "interface": item.interface,
                "status": item.status,
                "delta": delta,
                "rx_mbps": delta["rx_bytes"] * 8 / seconds / 1e6 if delta else None,
                "tx_mbps": delta["tx_bytes"] * 8 / seconds / 1e6 if delta else None,
                "link_capacity_mbps": None,
                "link_utilization_percent": None,
                "traffic_classification": "UNKNOWN",
                "packet_loss_verified": False,
            }
        )
    storage = []
    for item in capture.storage:
        measured = item.status == "MEASURED"
        used = item.total_bytes - item.free_bytes if measured else None
        storage.append(
            {
                **item.model_dump(mode="json"),
                "used_bytes": used,
                "reserved_free_bytes": item.free_bytes - item.available_bytes if measured else None,
                "used_percent": used / item.total_bytes * 100 if measured and item.total_bytes else None,
                "scope": "PATH_FILESYSTEM_NOT_PHYSICAL_DEVICE_OR_STORAGE_POOL",
            }
        )
    return {
        "schema_version": "cryptoscan.resource-report/v1",
        "capture_sha256": digest(capture),
        "sample_seconds": seconds,
        "network": network,
        "storage": storage,
        "storage_totals_additive": False,
        "provenance": "IMPORTED",
        "runtime_control_applied": False,
        "live_monitoring_active": False,
        "whole_host_or_network_complete": False,
    }
