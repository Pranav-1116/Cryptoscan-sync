"""Exact units, unknowns, scope closure and non-enforcement using synthetic counters."""

from datetime import datetime, timedelta, timezone
import pytest
from shared_models.host_collection import digest
from shared_models.resource_monitoring import ResourceAuthorization, ResourceCapture, ResourceScope, resource_report

ID = "11111111-1111-1111-1111-111111111111"


def authorization(now=None):
    now = now or datetime.now(timezone.utc)
    scope = ResourceScope(
        system_id="system-a",
        environment="prod",
        host_label="synthetic-host",
        interfaces=["lo"],
        mount_paths=["/"],
        interval_seconds=1,
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=10),
    )
    return ResourceAuthorization(
        plan_id=ID, plan_record_sha256="a" * 64, scope_sha256=digest(scope), nonce="b" * 64, scope=scope
    )


def capture(auth=None, now=None):
    now = now or datetime.now(timezone.utc)
    auth = auth or authorization(now)
    counters = {
        k: 10
        for k in (
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "rx_errors",
            "tx_errors",
            "rx_dropped",
            "tx_dropped",
        )
    }
    second = {**counters, "rx_bytes": 1000010, "tx_bytes": 2000010, "rx_packets": 110}
    return ResourceCapture(
        capture_id=ID,
        authorization=auth,
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        elapsed_ns=1000000000,
        boot_id=ID,
        network_namespace_inode=42,
        mount_namespace_inode=43,
        network=[
            {
                "interface": "lo",
                "status": "MEASURED",
                "first": counters,
                "second": second,
                "first_ifindex": 1,
                "second_ifindex": 1,
            }
        ],
        storage=[
            {
                "path": "/",
                "status": "MEASURED",
                "total_bytes": 1000,
                "free_bytes": 400,
                "available_bytes": 300,
                "filesystem_device": "8:1",
            }
        ],
    )


def test_exact_rate_units_and_reserved_space_are_not_used_space():
    report = resource_report(capture())
    assert report["network"][0]["rx_mbps"] == 8 and report["network"][0]["tx_mbps"] == 16
    disk = report["storage"][0]
    assert disk["used_bytes"] == 600 and disk["reserved_free_bytes"] == 100 and disk["used_percent"] == 60
    assert not report["storage_totals_additive"] and not report["runtime_control_applied"]
    assert report["network"][0]["link_utilization_percent"] is None


@pytest.mark.parametrize("status", ["COUNTER_RESET", "IDENTITY_CHANGED", "UNAVAILABLE", "DENIED", "INVALID"])
def test_network_gaps_never_become_zero_traffic(status):
    value = capture().model_dump(mode="json")
    n = value["network"][0]
    n["status"] = status
    if status == "COUNTER_RESET":
        n["second"]["rx_bytes"] = 0
    elif status == "IDENTITY_CHANGED":
        n["second_ifindex"] = 2
    else:
        for k in ("first", "second", "first_ifindex", "second_ifindex"):
            n[k] = None
    report = resource_report(ResourceCapture.model_validate(value))
    assert report["network"][0]["rx_mbps"] is report["network"][0]["tx_mbps"] is None
    assert report["network"][0]["delta"] is None


def test_idle_valid_counter_pair_is_actual_zero_not_unknown():
    value = capture().model_dump()
    value["network"][0]["second"] = value["network"][0]["first"]
    assert resource_report(ResourceCapture.model_validate(value))["network"][0]["tx_mbps"] == 0


@pytest.mark.parametrize("status", ["DENIED", "UNAVAILABLE", "UNSUPPORTED", "INVALID"])
def test_failed_storage_does_not_report_zero_capacity(status):
    value = capture().model_dump()
    value["storage"] = [{"path": "/", "status": status}]
    disk = resource_report(ResourceCapture.model_validate(value))["storage"][0]
    assert disk["total_bytes"] is disk["used_bytes"] is disk["available_bytes"] is disk["used_percent"] is None


@pytest.mark.parametrize(
    "case",
    [
        "extra",
        "scope",
        "negative",
        "bool",
        "overflow",
        "false_status",
        "positive_gap",
        "space",
        "time",
        "short",
        "naive",
        "promote",
    ],
)
def test_invalid_or_promoted_measurements_refused(case):
    value = capture().model_dump(mode="json")
    if case == "extra":
        value["raw_packet"] = "not-accepted"
    elif case == "scope":
        value["network"][0]["interface"] = "eth0"
    elif case == "negative":
        value["network"][0]["first"]["rx_bytes"] = -1
    elif case == "bool":
        value["network"][0]["first"]["rx_bytes"] = True
    elif case == "overflow":
        value["network"][0]["first"]["rx_bytes"] = 2**64
    elif case == "false_status":
        value["network"][0]["second"]["rx_bytes"] = 0
    elif case == "positive_gap":
        value["network"][0]["status"] = "DENIED"
    elif case == "space":
        value["storage"][0]["available_bytes"] = 500
    elif case == "time":
        value["finished_at"] = value["started_at"]
    elif case == "short":
        value["elapsed_ns"] = 100000000
    elif case == "naive":
        value["started_at"] = "2026-10-26T00:00:00"
    else:
        value["configuration_changed"] = True
    with pytest.raises(ValueError):
        ResourceCapture.model_validate(value)


@pytest.mark.parametrize("path", ["/tmp/../etc", "relative", "//etc", "/tmp/", "/a\nb"])
def test_noncanonical_paths_refused(path):
    value = authorization().scope.model_dump()
    value["mount_paths"] = [path]
    with pytest.raises(ValueError):
        ResourceScope.model_validate(value)


@pytest.mark.parametrize("interface", ["eth0;id", "../eth0", "*", "-bad", "long-interface-name"])
def test_interfaces_are_exact_names_not_commands_or_globs(interface):
    value = authorization().scope.model_dump()
    value["interfaces"] = [interface]
    with pytest.raises(ValueError):
        ResourceScope.model_validate(value)


def test_mutated_nested_models_are_revalidated():
    value = capture()
    value.network[0].__dict__["status"] = "COUNTER_RESET"
    with pytest.raises(ValueError):
        resource_report(value)
