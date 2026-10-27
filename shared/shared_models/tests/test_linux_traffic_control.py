"""Synthetic contract fixtures; no device attestation or kernel qualification."""

from datetime import datetime, timedelta, timezone
import pytest
from shared_models.linux_traffic_control import (
    PreflightSpec,
    TrafficPreflight,
    DrillAuthorization,
    DrillResult,
    preflight_report,
)

ID = "11111111-1111-1111-1111-111111111111"


def spec():
    now = datetime.now(timezone.utc)
    return PreflightSpec(
        request_id=ID,
        proposal_id=ID,
        proposal_record_sha256="a" * 64,
        source_capture_sha256="b" * 64,
        nonce="c" * 64,
        system_id="system-a",
        host_label="synthetic-host",
        interface="lo",
        expected_ifindex=1,
        expected_boot_id=ID,
        expected_network_namespace_inode=1,
        expected_mount_namespace_inode=2,
        egress_limit_mbps=10,
        management_ips=["127.0.0.1"],
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=2),
    )


def capture(value=None):
    value = value or spec()
    now = value.issued_at + timedelta(milliseconds=10)
    return TrafficPreflight(
        spec=value,
        started_at=now,
        finished_at=now + timedelta(milliseconds=10),
        boot_id=value.expected_boot_id,
        network_namespace_inode=value.expected_network_namespace_inode,
        mount_namespace_inode=value.expected_mount_namespace_inode,
        tools=[{"tool": "ip", "sha256": "d" * 64}, {"tool": "tc", "sha256": "e" * 64}],
        link={
            "status": "MEASURED",
            "source_sha256": "a" * 64,
            "ifindex": value.expected_ifindex,
            "interface": value.interface,
            "kind": "loopback",
        },
        qdiscs={
            "status": "MEASURED",
            "source_sha256": "a" * 64,
            "entries": [{"kind": "noqueue", "handle": "0:", "root": True, "options_sha256": "b" * 64}],
        },
        routes=[
            {"destination": ip, "status": "MEASURED", "source_sha256": "f" * 64, "interface": "lo"}
            for ip in value.management_ips
        ],
    )


def authorization():
    value = spec()
    return DrillAuthorization(
        change_id=ID,
        reviewed_record_sha256="a" * 64,
        preflight_sha256="b" * 64,
        proposal_id=ID,
        egress_limit_mbps=10,
        duration_seconds=1,
        expected_parent_boot_id=value.expected_boot_id,
        expected_parent_network_namespace_inode=1,
        expected_parent_mount_namespace_inode=2,
        issued_at=value.issued_at,
        expires_at=value.expires_at,
    )


def test_no_positive_preflight_authorizes_host():
    report = preflight_report(capture())
    assert report["recorded_checks_complete"]
    assert not report["host_enforcement_authorized"]
    assert "DECLARED_MANAGEMENT_PATH_USES_TARGET" in report["host_change_blockers"]
    assert "MANAGEMENT_INVENTORY_NOT_VERIFIED_COMPLETE" in report["host_change_blockers"]


@pytest.mark.parametrize(
    "ips", [["localhost"], ["127.0.0.1", "127.0.0.1"], ["0.0.0.0"], ["224.0.0.1"], ["fe80::1%lo"], ["2001:0db8::1"]]
)
def test_management_addresses_are_exact(ips):
    data = spec().model_dump()
    data["management_ips"] = ips
    with pytest.raises(ValueError):
        PreflightSpec.model_validate(data)


@pytest.mark.parametrize(
    "field,value", [("network_namespace_inode", 9), ("boot_id", "22222222-2222-2222-2222-222222222222")]
)
def test_context_changes_block_validation(field, value):
    data = capture().model_dump()
    data[field] = value
    report = preflight_report(TrafficPreflight.model_validate(data))
    assert not report["recorded_checks_complete"]


def test_failed_read_is_not_absence():
    data = capture().model_dump()
    data["qdiscs"] = {"status": "DENIED"}
    report = preflight_report(TrafficPreflight.model_validate(data))
    assert "QDISC_SOURCE_UNRESOLVED" in report["isolated_validation_blockers"]
    data["qdiscs"] = {"status": "MEASURED", "source_sha256": "a" * 64, "entries": []}
    with pytest.raises(ValueError):
        TrafficPreflight.model_validate(data)


def test_existing_root_policy_preserved_and_host_blocked():
    data = capture().model_dump()
    data["qdiscs"]["entries"][0]["kind"] = "pfifo_fast"
    report = preflight_report(TrafficPreflight.model_validate(data))
    assert report["recorded_checks_complete"]  # isolated lo test does not replace source policy
    assert "EXISTING_ROOT_POLICY_OR_UNKNOWN" in report["host_change_blockers"]
    assert not report["existing_policy_will_be_replaced"]


def test_cannot_claim_success_without_readback():
    with pytest.raises(ValueError):
        DrillResult(
            authorization_sha256="a" * 64,
            verdict="APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE",
            parent_namespace_unchanged=True,
            child_namespace_distinct=True,
            qdisc_applied_in_child=True,
            rollback_verified_in_child=True,
            parent_network_namespace_inode=1,
            child_network_namespace_inode=1,
            egress_limit_mbps=10,
            duration_seconds=1,
            failure="NONE",
        )
