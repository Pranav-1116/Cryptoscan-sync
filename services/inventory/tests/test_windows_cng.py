"""Portable CNG registration ABI fixtures, not real Windows qualification."""

import ctypes as c
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import os
import sys
import hashlib
import pytest
from pydantic import ValidationError
from inventory import windows_cng as cng
from inventory.host import Refused, collect, elevated
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot
from shared_models.windows_cng import registration_bytes, unsupported_expected_value


def item(interface="cipher"):
    return HostInput(
        input_id="registration",
        kind="WINDOWS_CNG_REGISTRATION",
        path=f"windows-cng://local/microsoft-primitive/{interface}-registration",
    )


def manifest(interface="cipher"):
    return HostManifest(
        approval_reference="change/windows-cng",
        host_id="synthetic-windows",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[item(interface)],
    )


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class FakeBcrypt:
    def __init__(self, *, mode="success", first_status=None, second_status=None, capacity=2048, functions=None):
        self.mode = mode
        self.first_status = first_status
        self.second_status = second_status
        self.capacity = capacity
        self.functions = functions if functions is not None else ["AES", "3DES"]
        self.calls = []
        self.BCryptQueryProviderRegistration = Function(self.query)

    def query(self, provider, mode, interface, size, pointer):
        assert mode == 1 and interface in (1, 2)
        units = []
        for value in provider:
            if value == 0:
                break
            units.append(value)
        assert b"".join(v.to_bytes(2, "little") for v in units).decode("utf-16-le") == "Microsoft Primitive Provider"
        n = c.cast(size, c.POINTER(c.c_uint32)).contents
        if pointer is None:
            self.calls.append("size")
            assert n.value == 0
            n.value = self.capacity
            return cng.BUFFER_TOO_SMALL if self.first_status is None else self.first_status
        self.calls.append("read")
        assert n.value == self.capacity
        if self.second_status is not None:
            return self.second_status
        result = c.cast(pointer, c.POINTER(c.c_void_p))
        base = result.contents.value

        def put(offset, cls):
            return cls.from_address(base + offset)

        root = put(0, cng.ProviderReg)
        image = put(64, cng.ImageReg)
        reg = put(128, cng.InterfaceReg)
        root.user = base + 64
        image.count = 1
        image.interfaces = base + 192
        put(192, c.c_void_p).value = base + 128
        reg.interface = interface
        reg.flags = 0
        reg.count = len(self.functions)
        reg.functions = base + 256
        for i, name in enumerate(self.functions[:64]):
            address = base + 800 + i * 128
            # A larger malformed count is refused before traversal; only valid-sized fixture writes.
            if address + 128 > base + self.capacity:
                break
            raw = name.encode("utf-16-le") + b"\0\0"
            c.memmove(address, raw, min(len(raw), 132))
            put(256 + i * c.sizeof(c.c_void_p), c.c_void_p).value = address
        if self.mode == "user-null":
            root.user = 0
        elif self.mode == "kernel":
            root.kernel = base + 64
        elif self.mode == "root-oob":
            root.user = base + self.capacity
        elif self.mode == "root-unaligned":
            root.user = base + 65
        elif self.mode == "interfaces-oob":
            image.interfaces = base + self.capacity - 1
        elif self.mode == "interface-null":
            put(192, c.c_void_p).value = 0
        elif self.mode == "wrong-interface":
            reg.interface = 3
        elif self.mode == "extra-interface":
            image.count = 2
        elif self.mode == "zero-functions":
            reg.count = 0
        elif self.mode == "overflow-count":
            reg.count = 0xFFFFFFFF
        elif self.mode == "functions-oob":
            reg.functions = base + self.capacity
        elif self.mode == "label-oob":
            put(256, c.c_void_p).value = base + self.capacity
        elif self.mode == "label-null":
            put(256, c.c_void_p).value = 0
        elif self.mode == "label-unaligned":
            put(256, c.c_void_p).value = base + 801
        elif self.mode == "unterminated":
            c.memset(base + 800, 65, 128)
        elif self.mode == "surrogate":
            c.memmove(base + 800, b"\x00\xd8\0\0", 4)
        elif self.mode == "oversize-return":
            n.value = self.capacity + 1
        elif self.mode == "undersize-return":
            n.value = 1
        elif self.mode == "replaced":
            result.contents.value = base + 64
        return 0


def install(monkeypatch, fake):
    monkeypatch.setattr(cng, "_api", lambda: fake)


def test_fixed_width_layout_and_system32_prototypes(monkeypatch):
    ptr = c.sizeof(c.c_void_p)
    assert c.sizeof(cng.ProviderReg) == (32 if ptr == 8 else 16)
    assert c.sizeof(cng.ImageReg) == (24 if ptr == 8 else 12)
    assert c.sizeof(cng.InterfaceReg) == (24 if ptr == 8 else 16)
    fake = FakeBcrypt()

    def dll(name, **kwargs):
        assert name == "bcrypt.dll" and kwargs == {"use_last_error": True, "winmode": 0x800}
        return fake

    monkeypatch.setattr(cng, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(c, "WinDLL", dll, raising=False)
    assert cng._api() is fake and fake.BCryptQueryProviderRegistration.restype is c.c_int32
    assert fake.BCryptQueryProviderRegistration.argtypes[-1] is c.POINTER(c.c_void_p)


@pytest.mark.parametrize("interface", ["cipher", "hash"])
def test_caller_owned_registration_is_not_capability_or_invocation(monkeypatch, interface):
    fake = FakeBcrypt()
    install(monkeypatch, fake)
    charges = []
    raw, facts = cng.collect_registration(item(interface), 1048576, charges.append)
    fact = facts[0]
    assert fake.calls == ["size", "read"]
    assert fact.registered_functions == ["3DES", "AES"] and fact.registration_interface == interface
    assert fact.algorithm == fact.runtime_use == fact.operation_use == fact.pqc_assessment == "UNKNOWN"
    assert fact.key_size is None and fact.software_version is None and fact.capabilities_observed is False
    assert fact.interface_sha256 == hashlib.sha256(raw).hexdigest() and sum(charges) > len(raw) + fake.capacity
    from shared_models.host_runtime import domains

    assert domains(fact) == ["TechBOM"]
    assert not any(
        name in fake.__dict__ for name in ("BCryptOpenAlgorithmProvider", "BCryptFreeBuffer", "NCryptOpenKey")
    )


@pytest.mark.parametrize("phase", ["size", "read"])
@pytest.mark.parametrize(
    "status,exception",
    [(0xC0000022, PermissionError), (0xC0000225, FileNotFoundError), (0xC000000D, Refused), (0x40000000, Refused)],
)
def test_ntstatus_not_get_last_error_or_boolean(monkeypatch, phase, status, exception):
    fake = FakeBcrypt(**{"first_status" if phase == "size" else "second_status": status})
    install(monkeypatch, fake)
    with pytest.raises(exception):
        cng.collect_registration(item(), 1048576, lambda n: None)
    assert fake.calls == (["size"] if phase == "size" else ["size", "read"])


@pytest.mark.parametrize(
    "mode",
    [
        "user-null",
        "kernel",
        "root-oob",
        "root-unaligned",
        "interfaces-oob",
        "interface-null",
        "wrong-interface",
        "extra-interface",
        "zero-functions",
        "overflow-count",
        "functions-oob",
        "label-oob",
        "label-null",
        "label-unaligned",
        "unterminated",
        "surrogate",
        "oversize-return",
        "undersize-return",
        "replaced",
    ],
)
def test_malformed_pointer_graph_is_refused_before_unbounded_dereference(monkeypatch, mode):
    fake = FakeBcrypt(mode=mode)
    install(monkeypatch, fake)
    with pytest.raises(ValueError):
        cng.collect_registration(item(), 1048576, lambda n: None)


@pytest.mark.parametrize("functions", [["AES", "AES"], ["AES", "aes"], ["contains spaces"], ["../AES"], ["A" * 65], []])
def test_ambiguous_or_unsupported_labels_do_not_become_algorithms(monkeypatch, functions):
    fake = FakeBcrypt(functions=functions)
    install(monkeypatch, fake)
    with pytest.raises(ValueError):
        cng.collect_registration(item(), 1048576, lambda n: None)


def test_size_query_growth_and_budget_refusals_never_request_native_allocation(monkeypatch):
    fake = FakeBcrypt()
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        cng.collect_registration(item(), 1, lambda n: None)
    assert fake.calls == []
    for capacity in [65537, 2048]:
        fake = FakeBcrypt(capacity=capacity)
        install(monkeypatch, fake)
        with pytest.raises(Refused):
            cng.collect_registration(item(), 1000, lambda n: None)
        assert fake.calls == ["size"]
    fake = FakeBcrypt(second_status=cng.BUFFER_TOO_SMALL)
    install(monkeypatch, fake)
    with pytest.raises(Refused) as caught:
        cng.collect_registration(item(), 1048576, lambda n: None)
    assert caught.value.reason == "INPUT_CHANGED" and fake.calls == ["size", "read"]


@pytest.mark.parametrize("options", [{"capacity": 1}, {"first_status": 0}])
def test_invalid_size_query_does_not_read(monkeypatch, options):
    fake = FakeBcrypt(**options)
    install(monkeypatch, fake)
    with pytest.raises(ValueError):
        cng.collect_registration(item(), 1048576, lambda n: None)
    assert fake.calls == ["size"]


@pytest.mark.parametrize(
    "path",
    [
        "windows-cng://remote/microsoft-primitive/cipher-registration",
        "windows-cng://local/third-party/cipher-registration",
        "windows-cng://local/microsoft-primitive/signature-registration",
        "windows-cng://local/microsoft-primitive/cipher-registration?keys=true",
        "windows-cng://local/microsoft-primitive/cipher-registration/",
        "windows-cng://local/microsoft-primitive/CIPHER-registration",
    ],
)
def test_canonical_fixed_scope_only(path):
    with pytest.raises(ValidationError):
        HostInput(input_id="registration", kind="WINDOWS_CNG_REGISTRATION", path=path)


def snapshot(monkeypatch):
    import inventory.host as host

    install(monkeypatch, FakeBcrypt())
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    value = collect(manifest())
    assert value.receipts[0].status == "PARSED"
    return value


@pytest.mark.parametrize(
    "change",
    [
        "interface",
        "digest",
        "receipt-digest",
        "names",
        "capability",
        "algorithm",
        "runtime",
        "version",
        "provider",
        "mode",
        "platform",
        "duplicate",
        "identity",
    ],
)
def test_snapshot_scope_commitment_and_unknowns_cannot_be_promoted(monkeypatch, change):
    value = snapshot(monkeypatch).model_dump(mode="json")
    fact = value["receipts"][0]["facts"][0]
    if change == "interface":
        fact["registration_interface"] = "hash"
        fact["identity_key"] = "microsoft-primitive:user:hash"
        fact["interface_sha256"] = hashlib.sha256(
            registration_bytes("hash", 0, fact["registered_functions"])
        ).hexdigest()
        value["receipts"][0]["content_sha256"] = fact["interface_sha256"]
    elif change == "digest":
        fact["interface_sha256"] = "0" * 64
    elif change == "receipt-digest":
        value["receipts"][0]["content_sha256"] = "0" * 64
    elif change == "names":
        fact["registered_functions"] = ["RSA"]
    elif change == "capability":
        fact["capabilities_observed"] = True
    elif change == "algorithm":
        fact["algorithm"] = "AES"
    elif change == "runtime":
        fact["runtime_use"] = "OBSERVED"
    elif change == "version":
        fact["software_version"] = "1.0"
    elif change == "provider":
        fact["provider_name"] = "Other provider"
    elif change == "mode":
        fact["registration_mode"] = "KERNEL"
    elif change == "platform":
        value["execution_platform"] = "linux"
    elif change == "duplicate":
        value["receipts"][0]["facts"].append(dict(fact))
    else:
        fact["identity_key"] = "global-provider"
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(value)


def test_platform_expiry_and_privilege_precede_native_query(monkeypatch):
    if sys.platform != "win32":
        with pytest.raises(ValueError):
            cng._api()
        assert collect(manifest()).receipts[0].status == "UNSUPPORTED"
    import inventory.host as host

    fake = FakeBcrypt()
    install(monkeypatch, fake)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: True)
    assert collect(manifest()).receipts[0].reason == "LEAST_PRIVILEGE_UNPROVEN" and fake.calls == []
    monkeypatch.setattr(host, "elevated", lambda: False)
    expired = manifest().model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    assert collect(expired).receipts[0].reason == "EXPIRED" and fake.calls == []


@pytest.mark.parametrize(
    "key,value,invalid",
    [
        ("registered_functions", ["3DES", "AES"], False),
        ("registered_functions", [{"AES": True}], True),
        ("registered_functions", ["AES", "AES"], True),
        ("registered_functions", ["AES", "3DES"], True),
        ("registered_functions", ["A"] * 65, True),
        ("registered_functions", ["has spaces"], True),
        ("unrelated", ["AES"], True),
        ("registered_functions", {"AES": True}, True),
        ("algorithm", "UNKNOWN", False),
    ],
)
def test_expected_truth_allows_only_bounded_canonical_new_label_list(key, value, invalid):
    assert unsupported_expected_value(key, value) == invalid


@pytest.mark.skipif(sys.platform != "win32", reason="Actual ordinary-user Windows CNG fixture required")
def test_native_operator_reviewed_registration():
    scope = os.getenv("CRYPTOSCAN_WINDOWS_CNG_RESOURCE")
    if not scope:
        pytest.skip("Exact pre-approved registration resource required")
    assert not elevated()
    value = manifest().model_copy(
        update={"inputs": [HostInput(input_id="registration", kind="WINDOWS_CNG_REGISTRATION", path=scope)]}
    )
    result = collect(value)
    assert result.receipts[0].status == "PARSED", result.receipts[0]
    assert result.receipts[0].facts[0].capabilities_observed is False and not result.windows_execution_qualified


def test_approved_flat_registration_truth_roundtrips_existing_fixture_runner(monkeypatch):
    from shared_models.collection import TargetSpec
    from shared_models.host_collection import digest
    from qualify_host_profile import FixturePlan, ExpectedInput, validate_plan, evaluate

    original = snapshot(monkeypatch)
    target = TargetSpec(
        target_key="reviewed-cng",
        system_id="synthetic-system",
        owner="Fixture owner",
        environment="test",
        collection_method="offline_host",
        address="synthetic-windows",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
        manifest=original.manifest,
    )
    # Hand-authored portable fixture truth, not an operator approval/native witness.
    expected = ExpectedInput(
        input_id="registration",
        facts=[
            {
                "kind": "WINDOWS_CNG_REGISTRATION",
                "registration_interface": "cipher",
                "registered_functions": ["3DES", "AES"],
                "capabilities_observed": False,
            }
        ],
    )
    plan = FixturePlan(
        schema_version="cryptoscan.native-fixture/v1",
        target_sha256=digest(target),
        expected=[expected],
        reviewer_reference="synthetic-review",
    )
    validate_plan(target, plan)
    assert evaluate(target, plan, original)["verdict"] == "PASS_SCOPED_FIXTURE"
    wrong = plan.model_copy(
        update={
            "expected": [
                ExpectedInput(
                    input_id="registration",
                    facts=[{"kind": "WINDOWS_CNG_REGISTRATION", "registered_functions": ["AES"]}],
                )
            ]
        }
    )
    assert evaluate(target, wrong, original)["verdict"] != "PASS_SCOPED_FIXTURE"
    invalid = plan.model_copy(
        update={
            "expected": [
                ExpectedInput(
                    input_id="registration",
                    facts=[{"kind": "WINDOWS_CNG_REGISTRATION", "registered_functions": [{"AES": True}]}],
                )
            ]
        }
    )
    with pytest.raises(ValueError):
        validate_plan(target, invalid)


@pytest.mark.parametrize("missing", ["dll", "export"])
def test_missing_native_binding_is_an_explicit_interface_gap(monkeypatch, missing):
    monkeypatch.setattr(cng, "sys", SimpleNamespace(platform="win32"))

    def dll(*args, **kwargs):
        if missing == "dll":
            raise OSError("synthetic unavailable System32 library")
        return SimpleNamespace()

    monkeypatch.setattr(c, "WinDLL", dll, raising=False)
    with pytest.raises(Refused) as caught:
        cng._api()
    assert (caught.value.status, caught.value.reason) == ("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
