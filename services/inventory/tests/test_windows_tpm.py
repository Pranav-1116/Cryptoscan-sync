"""Portable TBS fixtures, not native Windows or hardware attestation evidence."""

import ctypes as c
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import os, sys, hashlib
import pytest
from pydantic import ValidationError
from inventory import windows_tpm as tpm
from inventory.host import collect, Refused, elevated
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot
from shared_models.windows_tpm import RESOURCE


def item():
    return HostInput(input_id="tpm", kind="WINDOWS_TPM_DEVICE_INFO", path=RESOURCE)


def manifest():
    return HostManifest(
        approval_reference="change/windows-tpm",
        host_id="synthetic-windows",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[item()],
    )


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *a):
        return self.call(*a)


class FakeTbs:
    def __init__(self, version=2, structure=1, status=0, reserved=0xFFFFFFFF):
        self.version = version
        self.structure = structure
        self.status = status
        self.reserved = reserved
        self.calls = []
        self.Tbsi_GetDeviceInfo = Function(self.query)

    def query(self, size, pointer):
        assert size == 16
        output = c.cast(pointer, c.POINTER(tpm.DeviceInfo)).contents
        assert bytes(output) == b"\0" * 16  # Output, not an invented context-version input.
        self.calls.append("device-info")
        output.structure_version = self.structure
        output.tpm_version = self.version
        output.reserved_interface = self.reserved
        output.reserved_revision = self.reserved
        return self.status


def install(monkeypatch, fake):
    monkeypatch.setattr(tpm, "_api", lambda: fake)


def snapshot(monkeypatch, fake=None):
    import inventory.host as host

    install(monkeypatch, fake or FakeTbs())
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    return collect(manifest())


def test_fixed_abi_system32_and_result_not_boolean(monkeypatch):
    assert c.sizeof(tpm.DeviceInfo) == 16 and tpm.DeviceInfo.tpm_version.offset == 4
    fake = FakeTbs()

    def dll(name, **kwargs):
        assert name == "tbs.dll" and kwargs == {"use_last_error": True, "winmode": 0x800}
        return fake

    monkeypatch.setattr(tpm, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(c, "WinDLL", dll, raising=False)
    assert tpm._api() is fake and fake.Tbsi_GetDeviceInfo.argtypes == [c.c_uint32, c.c_void_p]
    assert fake.Tbsi_GetDeviceInfo.restype is c.c_uint32


@pytest.mark.parametrize("version,specification", [(1, "1.2"), (2, "2.0")])
def test_only_os_reported_specification_not_reserved_hardware_claims(monkeypatch, version, specification):
    from shared_models.host_runtime import domains

    fake = FakeTbs(version=version)
    install(monkeypatch, fake)
    charged = []
    raw, facts = tpm.collect_device(item(), 1000, charged.append)
    fact = facts[0]
    assert fake.calls == ["device-info"] and sum(charged) == 16 + len(raw)
    assert fact.tpm_specification == specification and fact.interface_sha256 == hashlib.sha256(raw).hexdigest()
    assert fact.runtime_use == fact.operation_use == fact.algorithm == fact.pqc_assessment == "UNKNOWN"
    assert fact.capabilities_observed is False and fact.key_size is None
    assert domains(fact) == ["HBOM", "TechBOM"]
    assert (
        "reserved" not in raw.decode()
        and "firmware" not in fact.model_dump()
        and "manufacturer" not in fact.model_dump()
    )
    other = FakeTbs(version=version, reserved=0)
    install(monkeypatch, other)
    assert tpm.collect_device(item(), 1000, lambda n: None)[0] == raw


@pytest.mark.parametrize(
    "status,expected",
    [
        (0x8028400F, "UNAVAILABLE"),
        (0x80284008, "UNAVAILABLE"),
        (0x80284010, "UNAVAILABLE"),
        (0x80284002, "UNAVAILABLE"),
        (0xDEADBEEF, "UNAVAILABLE"),
        (1, "UNAVAILABLE"),
    ],
)
def test_failure_never_becomes_absence_or_hardware_success(monkeypatch, status, expected):
    result = snapshot(monkeypatch, FakeTbs(status=status))
    receipt = result.receipts[0]
    assert (
        receipt.status == expected
        and receipt.facts == []
        and receipt.content_sha256 is None
        and receipt.byte_count == 16
    )


@pytest.mark.parametrize(
    "options", [{"version": 0}, {"version": 3}, {"structure": 0}, {"structure": 2}, {"structure": 0xFFFFFFFF}]
)
def test_unknown_structure_or_tpm_version_refuses(monkeypatch, options):
    result = snapshot(monkeypatch, FakeTbs(**options))
    assert result.receipts[0].status == "UNSUPPORTED" and result.receipts[0].facts == []


def test_prequery_and_postquery_byte_limits(monkeypatch):
    fake = FakeTbs()
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        tpm.collect_device(item(), 15, lambda n: None)
    assert fake.calls == []
    with pytest.raises(Refused):
        tpm.collect_device(item(), 16, lambda n: None)
    assert fake.calls == ["device-info"]


@pytest.mark.parametrize(
    "path",
    [
        "windows-tpm://remote/device-info",
        "windows-tpm://local/device-info?keys=true",
        "windows-tpm://local/device-info/",
        "windows-tpm://local/tpm0",
        "windows-tpm://LOCAL/device-info",
    ],
)
def test_exact_scope_no_keys_commands_remote_or_enumeration(path):
    with pytest.raises(ValidationError):
        HostInput(input_id="tpm", kind="WINDOWS_TPM_DEVICE_INFO", path=path)


@pytest.mark.parametrize(
    "change",
    [
        "digest",
        "receipt",
        "specification",
        "structure",
        "algorithm",
        "runtime",
        "capability",
        "firmware",
        "identity",
        "platform",
        "duplicate",
    ],
)
def test_snapshot_binding_and_no_promoted_assertions(monkeypatch, change):
    raw = snapshot(monkeypatch).model_dump(mode="json")
    fact = raw["receipts"][0]["facts"][0]
    if change == "digest":
        fact["interface_sha256"] = "0" * 64
    elif change == "receipt":
        raw["receipts"][0]["content_sha256"] = "0" * 64
    elif change == "specification":
        fact["tpm_specification"] = "1.2"
    elif change == "structure":
        fact["api_structure_version"] = 2
    elif change == "algorithm":
        fact["algorithm"] = "RSA"
    elif change == "runtime":
        fact["runtime_use"] = "OBSERVED"
    elif change == "capability":
        fact["capabilities_observed"] = True
    elif change == "firmware":
        fact["firmware_version"] = "7.2"
    elif change == "identity":
        fact["identity_key"] = "physical-tpm-123"
    elif change == "platform":
        raw["execution_platform"] = "linux"
    else:
        raw["receipts"][0]["facts"].append(dict(fact))
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(raw)


@pytest.mark.parametrize("missing", ["dll", "export"])
def test_unavailable_binding_explicit_gap(monkeypatch, missing):
    monkeypatch.setattr(tpm, "sys", SimpleNamespace(platform="win32"))

    def dll(*a, **k):
        if missing == "dll":
            raise OSError("synthetic missing library")
        return SimpleNamespace()

    monkeypatch.setattr(c, "WinDLL", dll, raising=False)
    with pytest.raises(Refused) as caught:
        tpm._api()
    assert caught.value.reason == "INTERFACE_UNAVAILABLE"


def test_wrong_platform_expired_or_elevated_does_not_query(monkeypatch):
    if sys.platform != "win32":
        with pytest.raises(ValueError):
            tpm._api()
        assert collect(manifest()).receipts[0].status == "UNSUPPORTED"
    import inventory.host as host

    fake = FakeTbs()
    install(monkeypatch, fake)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: True)
    assert collect(manifest()).receipts[0].reason == "LEAST_PRIVILEGE_UNPROVEN" and fake.calls == []
    monkeypatch.setattr(host, "elevated", lambda: False)
    expired = manifest().model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    assert collect(expired).receipts[0].reason == "EXPIRED" and fake.calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="Actual ordinary-user Windows TPM fixture required")
def test_native_operator_selected_device_info():
    scope = os.getenv("CRYPTOSCAN_WINDOWS_TPM_RESOURCE")
    if not scope:
        pytest.skip("Reviewed existing OS-selected TPM scope required; no setup or keys created")
    assert not elevated()
    target = manifest().model_copy(
        update={"inputs": [HostInput(input_id="tpm", kind="WINDOWS_TPM_DEVICE_INFO", path=scope)]}
    )
    result = collect(target)
    assert result.receipts[0].status == "PARSED", result.receipts[0]
    assert not result.windows_execution_qualified and result.receipts[0].facts[0].capabilities_observed is False


def test_selected_tpm_truth_existing_fixture_runner(monkeypatch):
    from shared_models.collection import TargetSpec
    from shared_models.host_collection import digest
    from shared_models.collection_coverage import SURFACES
    from shared_models.host_runtime import domains
    from qualify_host_profile import FixturePlan, ExpectedInput, validate_plan, evaluate

    original = snapshot(monkeypatch)
    target = TargetSpec(
        target_key="reviewed-tpm",
        system_id="synthetic-system",
        owner="Fixture owner",
        environment="test",
        collection_method="offline_host",
        address="synthetic-windows",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
        manifest=original.manifest,
    )
    # Hand-authored portable truth; no independent operator approval/native witness.
    assertion = {
        "kind": "WINDOWS_TPM_METADATA",
        "api_structure_version": 1,
        "tpm_specification": "2.0",
        "hardware_type": "TPM",
        "capabilities_observed": False,
        "runtime_use": "UNKNOWN",
        "capture_basis": "OS_REPORTED_NOT_ATTESTED_OR_INVOKED",
    }
    plan = FixturePlan(
        schema_version="cryptoscan.native-fixture/v1",
        target_sha256=digest(target),
        expected=[ExpectedInput(input_id="tpm", facts=[assertion])],
        reviewer_reference="synthetic-review",
    )
    validate_plan(target, plan)
    assert evaluate(target, plan, original)["verdict"] == "PASS_SCOPED_FIXTURE"
    for field, value in [
        ("tpm_specification", "1.2"),
        ("api_structure_version", 2),
        ("capabilities_observed", True),
        ("firmware_version", "invented"),
    ]:
        wrong = plan.model_copy(
            update={"expected": [ExpectedInput(input_id="tpm", facts=[{**assertion, field: value}])]}
        )
        assert evaluate(target, wrong, original)["verdict"] == "FAIL_GAPS_OR_TRUTH_MISMATCH"
    invalid = plan.model_copy(
        update={"expected": [ExpectedInput(input_id="tpm", facts=[{**assertion, "unreviewed_tpm_claim": "invented"}])]}
    )
    with pytest.raises(ValueError, match="Invalid fixture assertion"):
        validate_plan(target, invalid)
    assert domains(original.receipts[0].facts[0]) == ["HBOM", "TechBOM"]
    assert {surface for surface, kinds in SURFACES.items() if item().kind in kinds} == {"hardware_metadata"}
