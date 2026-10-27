"""Scoped engineering fixture contracts; no real-host or production authorization."""

from datetime import datetime
from typing import Annotated, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0, le=1000000000000)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Scope(Strict):
    schema_version: Literal["cryptoscan.disposable-tbf-scope/v1"] = "cryptoscan.disposable-tbf-scope/v1"
    target_label: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    nonce: Digest
    bundle_sha256: Digest
    issued_at: datetime
    expires_at: datetime
    profile: Literal["DISKLESS_TCG_NO_NIC_V1"] = "DISKLESS_TCG_NO_NIC_V1"
    authorizes_real_host_change: Literal[False] = False
    independent_change_approval_verified: Literal[False] = False

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone-aware window required")
        return value

    @model_validator(mode="after")
    def window(self):
        if not 30 <= (self.expires_at - self.issued_at).total_seconds() <= 600:
            raise ValueError("bounded local engineering scope required")
        return self


class Measurement(Strict):
    received_packets: Count
    received_bytes: Count
    elapsed_ns: int = Field(ge=3800000000, le=6000000000)
    sent_packets_total: Count  # includes the separate warmup; not an offered-rate measurement
    send_backpressure: Count
    attempted_packets_total: Count
    send_errors: Count
    receive_errors: Count
    invalid_packets: Count
    payload_bytes: Literal[1200]
    warmup_seconds: Literal[1]

    @model_validator(mode="after")
    def denominator(self):
        if (
            self.received_bytes != self.received_packets * self.payload_bytes
            or self.sent_packets_total < self.received_packets
        ):
            raise ValueError("receive byte/packet denominator mismatch")
        if self.attempted_packets_total != self.sent_packets_total + self.send_errors + self.send_backpressure:
            raise ValueError("attempted packet denominator mismatch")
        return self

    @property
    def mbps(self):
        return self.received_bytes * 8000 / self.elapsed_ns


def clean(row):
    return row.get("root") is True and row.get("kind") == "noqueue" and row.get("handle") == "0:"


def owned(row, rate):
    return (
        row.get("root") is True
        and row.get("kind") == "tbf"
        and row.get("handle") == "7e01:"
        and isinstance(row.get("options"), dict)
        and type(row["options"].get("rate")) is int
        and row["options"]["rate"] == rate * 125000
    )


def policy(row):
    return {key: row.get(key) for key in ("kind", "handle", "root", "options")}


class CappedTrial(Strict):
    rate_mbps: Literal[10, 5]
    applied: dict[str, Any]
    after_measurement: dict[str, Any]
    measurement: Measurement
    restored_policy: dict[str, Any]


class GuestCapture(Strict):
    schema_version: Literal["cryptoscan.disposable-tbf-guest/v1"]
    nonce: Digest
    kernel_release: str = Field(min_length=1, max_length=100)
    interface: Literal["lo"]
    baseline_policy: dict[str, Any]
    baseline: Measurement
    caps: list[CappedTrial] = Field(min_length=2, max_length=2)
    restored: Measurement
    final_policy: dict[str, Any]
    rollback_verified: bool
    guest_monotonic_finished_ns: int = Field(ge=1, le=18446744073709551615)


def report(value: GuestCapture):
    """Recompute every gate; receipt flags or low traffic alone cannot qualify the cap."""
    value = GuestCapture.model_validate(value.model_dump())
    blockers = []
    if [v.rate_mbps for v in value.caps] != [10, 5]:
        blockers.append("EXACT_ORDERED_RATE_DENOMINATOR_REQUIRED")
    if not clean(value.baseline_policy):
        blockers.append("INITIAL_POLICY_NOT_DEFAULT")
    if (
        not value.rollback_verified
        or not clean(value.final_policy)
        or policy(value.final_policy) != policy(value.baseline_policy)
    ):
        blockers.append("FINAL_ROLLBACK_NOT_VERIFIED")
    if value.baseline.mbps < 30:
        blockers.append("INSUFFICIENT_UNSHAPED_HEADROOM")
    if value.restored.mbps < max(30, value.baseline.mbps * 0.8):
        blockers.append("POST_ROLLBACK_THROUGHPUT_NOT_RECOVERED")
    if value.baseline.send_backpressure or value.restored.send_backpressure:
        blockers.append("UNSHAPED_SENDER_BACKPRESSURE")
    required_ns = sum(
        s.elapsed_ns + 1000000000 for s in [value.baseline, *(t.measurement for t in value.caps), value.restored]
    )
    if value.guest_monotonic_finished_ns < required_ns:
        blockers.append("GUEST_MONOTONIC_TIMELINE_INCONSISTENT")
    for index, trial in enumerate(value.caps):
        if (
            not owned(trial.applied, trial.rate_mbps)
            or not owned(trial.after_measurement, trial.rate_mbps)
            or policy(trial.applied) != policy(trial.after_measurement)
        ):
            blockers.append(f"CAP_{index}_READBACK_OR_STABILITY_FAILED")
        if not clean(trial.restored_policy) or policy(trial.restored_policy) != policy(value.baseline_policy):
            blockers.append(f"CAP_{index}_ROLLBACK_FAILED")
        if not trial.rate_mbps * 0.8 <= trial.measurement.mbps <= trial.rate_mbps * 1.1:
            blockers.append(f"CAP_{index}_RECEIVED_PAYLOAD_OUTSIDE_PREDECLARED_BAND")
        for key in ("bytes", "packets", "overlimits"):
            first, second = trial.applied.get(key), trial.after_measurement.get(key)
            if type(first) is not int or type(second) is not int or not 0 <= first < second:
                blockers.append(f"CAP_{index}_KERNEL_COUNTER_{key.upper()}_NOT_ADVANCING")
        first, second = trial.applied.get("bytes"), trial.after_measurement.get("bytes")
        if type(first) is int and type(second) is int and second - first < trial.measurement.received_bytes:
            blockers.append(f"CAP_{index}_KERNEL_BYTES_BELOW_RECEIVED_PAYLOAD")
        packet_first, packet_last = trial.applied.get("packets"), trial.after_measurement.get("packets")
        if (
            type(packet_first) is int
            and type(packet_last) is int
            and packet_last - packet_first < trial.measurement.received_packets
        ):
            blockers.append(f"CAP_{index}_KERNEL_PACKETS_BELOW_RECEIVED_PAYLOAD")
    for index, sample in enumerate([value.baseline, *(v.measurement for v in value.caps), value.restored]):
        if sample.send_errors or sample.receive_errors or sample.invalid_packets:
            blockers.append(f"SAMPLE_{index}_SOCKET_OR_PAYLOAD_ERRORS")
    return {
        "schema_version": "cryptoscan.disposable-tbf-report/v1",
        "verdict": "VERIFIED_IN_DISPOSABLE_VM" if not blockers else "INCONCLUSIVE_OR_FAILED",
        "blockers": blockers,
        "baseline_payload_mbps": value.baseline.mbps,
        "capped_payload_mbps": [t.measurement.mbps for t in value.caps],
        "restored_payload_mbps": value.restored.mbps,
        "scope": "SYNTHETIC_UDP_GUEST_LOOPBACK_ONLY",
        "management_network_present": False,
        "real_host_change_authorized": False,
        "source_authenticity_verified": False,
        "production_execution_qualified": False,
    }


class ParentContext(Strict):
    boot_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    network_namespace_inode: int = Field(ge=1, le=18446744073709551615)
    mount_namespace_inode: int = Field(ge=1, le=18446744073709551615)


class RunReceipt(Strict):
    schema_version: Literal["cryptoscan.disposable-tbf-run/v1"]
    scope: Scope
    scope_sha256: Digest
    bundle_sha256: Digest
    serial_sha256: Digest
    host_wall_seconds: float = Field(gt=0, le=181, allow_inf_nan=False)
    parent_before: ParentContext
    parent_after: ParentContext
    guest: GuestCapture | None
    report: dict[str, Any] | None
    failure: str | None = Field(max_length=80)
    production_execution_qualified: Literal[False]
    verdict: Literal["VERIFIED_IN_DISPOSABLE_VM", "INCONCLUSIVE_OR_FAILED"]

    @model_validator(mode="after")
    def closure(self):
        import hashlib
        import json

        expected = hashlib.sha256(
            json.dumps(
                self.scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
        if self.scope_sha256 != expected or self.bundle_sha256 != self.scope.bundle_sha256:
            raise ValueError("scope/bundle commitments changed")
        if self.guest is None:
            if self.report is not None or self.verdict != "INCONCLUSIVE_OR_FAILED":
                raise ValueError("missing measurements cannot qualify")
        else:
            computed = report(self.guest)
            if self.report != computed or self.guest.nonce != self.scope.nonce:
                raise ValueError("guest scope/report closure changed")
            minimum = (
                sum(
                    s.elapsed_ns / 1e9 + 1
                    for s in [self.guest.baseline, *(t.measurement for t in self.guest.caps), self.guest.restored]
                )
                - 2
            )
            eligible = (
                self.failure is None
                and self.parent_before == self.parent_after
                and minimum <= self.host_wall_seconds <= 180
                and computed["verdict"] == "VERIFIED_IN_DISPOSABLE_VM"
            )
            if (self.verdict == "VERIFIED_IN_DISPOSABLE_VM") != eligible:
                raise ValueError("qualification verdict differs from observed gates")
        return self
