"""Linux preflight and isolated validation contracts; never real-host execution authority."""

import ipaddress
from datetime import datetime
from typing import Annotated, Literal
from pydantic import Field, StringConstraints, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostManifest, Token, digest
from shared_models.oci_intake import Identifier
from shared_models.resource_monitoring import Interface

Positive = Annotated[int, Field(ge=1, le=18446744073709551615)]
Kind = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,40}$")]
Handle = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{1,4}:[0-9a-f]{0,4}$")]
Status = Literal["MEASURED", "UNAVAILABLE", "DENIED", "INVALID"]


def canonical_ips(values):
    if len(set(values)) != len(values):
        raise ValueError("Duplicate declared management IP")
    for value in values:
        address = ipaddress.ip_address(value)
        if str(address) != value or address.is_unspecified or address.is_multicast or "%" in value:
            raise ValueError("Canonical unicast management IP required")
    return values


class PreflightRequest(Strict):
    expected_proposal_record_sha256: Digest
    management_ips: list[str] = Field(min_length=1, max_length=8)

    @field_validator("management_ips")
    @classmethod
    def ips(cls, values):
        return canonical_ips(values)


class PreflightSpec(Strict):
    schema_version: Literal["cryptoscan.linux-traffic-preflight-spec/v1"] = "cryptoscan.linux-traffic-preflight-spec/v1"
    request_id: Identifier
    proposal_id: Identifier
    proposal_record_sha256: Digest
    source_capture_sha256: Digest
    nonce: Digest
    system_id: Token
    host_label: Token
    interface: Interface
    expected_ifindex: int = Field(ge=1, le=2147483647)
    expected_boot_id: Identifier
    expected_network_namespace_inode: Positive
    expected_mount_namespace_inode: Positive
    egress_limit_mbps: int = Field(ge=1, le=100000)
    management_ips: list[str] = Field(min_length=1, max_length=8)
    issued_at: datetime
    expires_at: datetime
    read_only: Literal[True] = True
    authorizes_real_host_change: Literal[False] = False

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @field_validator("management_ips")
    @classmethod
    def ips(cls, values):
        return canonical_ips(values)

    @model_validator(mode="after")
    def window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 300:
            raise ValueError("Preflight window must be at most five minutes")
        return self


class ToolPin(Strict):
    tool: Literal["ip", "tc"]
    sha256: Digest


class LinkReading(Strict):
    status: Status
    source_sha256: Digest | None = None
    ifindex: int | None = Field(default=None, ge=1, le=2147483647)
    interface: Interface | None = None
    kind: Kind | None = None

    @model_validator(mode="after")
    def consistent(self):
        fields = (self.source_sha256, self.ifindex, self.interface, self.kind)
        if (self.status == "MEASURED") != all(v is not None for v in fields):
            raise ValueError("Measured link needs exact source and identity")
        if self.status != "MEASURED" and any(v is not None for v in fields):
            raise ValueError("Failed link cannot assert identity")
        return self


class Qdisc(Strict):
    kind: Kind
    handle: Handle
    root: bool
    options_sha256: Digest


class QdiscReading(Strict):
    status: Status
    source_sha256: Digest | None = None
    entries: list[Qdisc] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def consistent(self):
        if self.status == "MEASURED":
            if self.source_sha256 is None or not self.entries:
                raise ValueError("Measured policy source must not be empty")
        elif self.source_sha256 is not None or self.entries:
            raise ValueError("Failed policy source cannot prove absence")
        return self


class RouteReading(Strict):
    destination: str = Field(max_length=45)
    status: Status
    source_sha256: Digest | None = None
    interface: Interface | None = None

    @model_validator(mode="after")
    def consistent(self):
        canonical_ips([self.destination])
        if self.status == "MEASURED":
            if self.source_sha256 is None or self.interface is None:
                raise ValueError("Measured route needs source and device")
        elif self.source_sha256 is not None or self.interface is not None:
            raise ValueError("Unresolved route cannot assert a safe path")
        return self


class TrafficPreflight(Strict):
    schema_version: Literal["cryptoscan.linux-traffic-preflight/v1"] = "cryptoscan.linux-traffic-preflight/v1"
    spec: PreflightSpec
    started_at: datetime
    finished_at: datetime
    boot_id: Identifier
    network_namespace_inode: Positive
    mount_namespace_inode: Positive
    tools: list[ToolPin] = Field(min_length=2, max_length=2)
    link: LinkReading
    qdiscs: QdiscReading
    routes: list[RouteReading] = Field(min_length=1, max_length=8)
    provenance: Literal["IMPORTED"] = "IMPORTED"
    source_authenticity_verified: Literal[False] = False
    configuration_changed: Literal[False] = False

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def closure(self):
        if not self.spec.issued_at <= self.started_at <= self.finished_at < self.spec.expires_at:
            raise ValueError("Preflight must fit the request window")
        if [r.destination for r in self.routes] != self.spec.management_ips or [p.tool for p in self.tools] != [
            "ip",
            "tc",
        ]:
            raise ValueError("Exact ordered tool/management denominator required")
        if self.link.status == "MEASURED" and self.link.interface != self.spec.interface:
            raise ValueError("Link source is not the requested interface")
        return self


class PreflightIntake(Strict):
    capture: TrafficPreflight
    expected_preflight_sha256: Digest


class ValidationChange(Strict):
    preflight_id: Identifier
    expected_preflight_record_sha256: Digest
    reviewer_user_id: Identifier
    duration_seconds: int = Field(ge=1, le=5)
    reason: str = Field(min_length=20, max_length=500)


class ValidationDecision(Strict):
    expected_revision: Literal[1] = 1
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500)


class DrillAuthorization(Strict):
    schema_version: Literal["cryptoscan.linux-traffic-drill-authorization/v1"] = (
        "cryptoscan.linux-traffic-drill-authorization/v1"
    )
    change_id: Identifier
    reviewed_record_sha256: Digest
    preflight_sha256: Digest
    proposal_id: Identifier
    egress_limit_mbps: int = Field(ge=1, le=100000)
    duration_seconds: int = Field(ge=1, le=5)
    expected_parent_boot_id: Identifier
    expected_parent_network_namespace_inode: Positive
    expected_parent_mount_namespace_inode: Positive
    issued_at: datetime
    expires_at: datetime
    target_interface: Literal["lo"] = "lo"
    profile: Literal["FRESH_USER_AND_NETWORK_NAMESPACE_ONLY"] = "FRESH_USER_AND_NETWORK_NAMESPACE_ONLY"
    authorizes_real_host_change: Literal[False] = False
    source_authenticity_verified: Literal[False] = False

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 300:
            raise ValueError("Drill export window must be at most five minutes")
        return self


class DrillResult(Strict):
    schema_version: Literal["cryptoscan.linux-traffic-drill/v1"] = "cryptoscan.linux-traffic-drill/v1"
    authorization_sha256: Digest
    verdict: Literal["APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE", "REFUSED_OR_FAILED"]
    parent_namespace_unchanged: bool
    child_namespace_distinct: bool
    qdisc_applied_in_child: bool
    rollback_verified_in_child: bool
    parent_network_namespace_inode: Positive
    child_network_namespace_inode: Positive | None = None
    egress_limit_mbps: int = Field(ge=1, le=100000)
    duration_seconds: int = Field(ge=1, le=5)
    before_qdisc_sha256: Digest | None = None
    applied_qdisc_sha256: Digest | None = None
    after_qdisc_sha256: Digest | None = None
    failure: Literal[
        "NONE", "UNSHARE_OR_KERNEL_UNAVAILABLE", "CHILD_REFUSED_OR_FAILED", "TIMEOUT", "PARENT_CONTEXT_CHANGED"
    ]
    real_host_interface_changed: Literal[False] = False
    throughput_enforcement_measured: Literal[False] = False
    production_execution_qualified: Literal[False] = False

    @model_validator(mode="after")
    def verdict_consistent(self):
        success = self.verdict == "APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE"
        flags = all(
            (
                self.parent_namespace_unchanged,
                self.child_namespace_distinct,
                self.qdisc_applied_in_child,
                self.rollback_verified_in_child,
            )
        )
        hashes = all((self.before_qdisc_sha256, self.applied_qdisc_sha256, self.after_qdisc_sha256))
        if success and (
            not flags
            or not hashes
            or self.failure != "NONE"
            or self.child_network_namespace_inode is None
            or self.before_qdisc_sha256 != self.after_qdisc_sha256
            or self.child_network_namespace_inode == self.parent_network_namespace_inode
        ):
            raise ValueError("Isolated success requires actual apply, rollback and distinct namespace")
        if not success and self.failure == "NONE":
            raise ValueError("Failed drill needs explicit failure status")
        return self


def preflight_report(capture: TrafficPreflight):
    capture = TrafficPreflight.model_validate(capture.model_dump())
    spec = capture.spec
    blockers = []
    same_context = (
        capture.boot_id == spec.expected_boot_id
        and capture.network_namespace_inode == spec.expected_network_namespace_inode
        and capture.mount_namespace_inode == spec.expected_mount_namespace_inode
        and capture.link.status == "MEASURED"
        and capture.link.ifindex == spec.expected_ifindex
    )
    if not same_context:
        blockers.append("SOURCE_CONTEXT_OR_INTERFACE_CHANGED")
    if capture.qdiscs.status != "MEASURED":
        blockers.append("QDISC_SOURCE_UNRESOLVED")
    if any(r.status != "MEASURED" for r in capture.routes):
        blockers.append("DECLARED_MANAGEMENT_ROUTE_UNRESOLVED")
    roots = [q for q in capture.qdiscs.entries if q.root]
    host_blockers = [
        "DEVICE_IDENTITY_NOT_ENROLLED",
        "SOURCE_AUTHENTICITY_UNVERIFIED",
        "MANAGEMENT_INVENTORY_NOT_VERIFIED_COMPLETE",
        "REAL_HOST_EXECUTOR_NOT_IMPLEMENTED",
        *blockers,
    ]
    if len(roots) != 1 or roots[0].kind != "noqueue" or roots[0].handle != "0:":
        host_blockers.append("EXISTING_ROOT_POLICY_OR_UNKNOWN")
    if any(r.interface == spec.interface for r in capture.routes if r.status == "MEASURED"):
        host_blockers.append("DECLARED_MANAGEMENT_PATH_USES_TARGET")
    return {
        "schema_version": "cryptoscan.linux-traffic-preflight-report/v1",
        "preflight_sha256": digest(capture),
        "isolated_validation_blockers": blockers,
        "recorded_checks_complete": not blockers,
        "host_change_blockers": host_blockers,
        "declared_management_destinations": len(capture.routes),
        "source_context_matched": same_context,
        "host_enforcement_authorized": False,
        "existing_policy_will_be_replaced": False,
        "management_inventory_complete": False,
        "production_execution_qualified": False,
    }
