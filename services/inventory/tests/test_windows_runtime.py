"""Portable Windows candidate contracts do NOT qualify native Windows execution."""

import ctypes
import sys
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from inventory.windows_runtime import ServiceStatusProcess, status_fact, query_status
from inventory.collection import OfflineWindowsCollector
from inventory.host import collect, elevated
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostManifest, HostInput
from shared_models.host_runtime import RuntimeFact


def target(unit="EventLog"):
    return TargetSpec(
        target_key="windows-candidate",
        system_id="system-a",
        owner="Payments",
        environment="test",
        collection_method="offline_host",
        address="windows-local",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(seconds=1),
        manifest=HostManifest(
            approval_reference="change/windows-candidate",
            host_id="windows-candidate",
            environment="test",
            platform="windows",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            inputs=[HostInput(input_id="service", kind="WINDOWS_SERVICE", path="windows-service://" + unit)],
        ),
    )


@pytest.mark.parametrize(
    "state,expected",
    [
        (1, "STOPPED"),
        (2, "START_PENDING"),
        (3, "STOP_PENDING"),
        (4, "RUNNING"),
        (5, "CONTINUE_PENDING"),
        (6, "PAUSE_PENDING"),
        (7, "PAUSED"),
    ],
)
def test_scm_fixed_width_layout_and_state_truth(state, expected):
    assert ctypes.sizeof(ServiceStatusProcess) == 36
    status = ServiceStatusProcess()
    status.state = state
    status.pid = 42
    fact = status_fact("EventLog", status)
    assert fact.service_state == expected and fact.pid == (42 if state in {4, 5, 6, 7} else None)
    assert fact.algorithm == fact.runtime_use == fact.operation_use == "UNKNOWN"
    assert fact.interface == "WINDOWS_SCM" and fact.interface_sha256
    with pytest.raises(ValidationError):
        RuntimeFact.model_validate({**fact.model_dump(mode="json"), "interface": "SYSTEMD_READ_ONLY"})


def test_unknown_scm_state_is_not_security_grade():
    with pytest.raises(ValueError):
        status_fact("EventLog", ServiceStatusProcess())


def test_windows_candidate_is_explicitly_unqualified_and_not_linux_emulation():
    assert not OfflineWindowsCollector().health()["windows_execution_qualified"]
    assert not OfflineWindowsCollector().health()["remote_execution"]
    if sys.platform != "win32":
        with pytest.raises(ValueError):
            OfflineWindowsCollector().collect(target())
        with pytest.raises(ValueError):
            query_status("EventLog")
        snapshot = collect(target().manifest)
        assert snapshot.receipts[0].status == "UNSUPPORTED" and not snapshot.receipts[0].facts


@pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows SCM witness unavailable on Linux; qualification remains FALSE"
)
def test_native_windows_ordinary_user_named_service_and_nonexistent_receipts():
    assert not elevated(), "Do not disable privilege guard; run as ordinary Windows user"
    snapshot = OfflineWindowsCollector().collect(target())
    assert snapshot.receipts[0].status == "PARSED", snapshot.receipts[0]
    assert snapshot.receipts[0].facts[0].service_name == "EventLog"
    assert not snapshot.windows_execution_qualified and not snapshot.production_execution_qualified
    missing = OfflineWindowsCollector().collect(target("CryptoScanNonexistentWitnessService"))
    assert missing.receipts[0].status == "UNAVAILABLE" and not missing.receipts[0].facts
