"""Portable CAPI/TCP fixtures. Never real Windows, TLS or device qualification."""

import ctypes as c
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import os
import sys
import pytest
from pydantic import ValidationError
from inventory import windows_capi as capi, windows_listeners as tcp
from inventory.host import collect, elevated, Refused
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot
from shared_models.host_runtime import domains


RESOURCES = {
    "capi": ("WINDOWS_CAPI_DEFAULT_PROVIDER", "windows-capi://local/current-user/rsa-aes/default-provider"),
    "ipv4": ("WINDOWS_TCP_LISTENERS", "windows-sockets://local/ipv4/tcp-listeners"),
    "ipv6": ("WINDOWS_TCP_LISTENERS", "windows-sockets://local/ipv6/tcp-listeners"),
}


def manifest(which="capi"):
    kind, path = RESOURCES[which]
    return HostManifest(
        approval_reference="change/windows-metadata",
        host_id="synthetic-windows",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[HostInput(input_id="metadata", kind=kind, path=path)],
    )


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class FakeCapi:
    def __init__(self, mode="success"):
        self.mode = mode
        self.calls = []
        self.CryptGetDefaultProviderW = Function(self.query)

    def query(self, provider_type, reserved, flags, buffer, size):
        assert provider_type in {1, 2, 3, 13, 24} and reserved is None and flags == 2
        n = c.cast(size, c.POINTER(c.c_uint32)).contents
        name = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        if self.mode == "changed" and len(self.calls) >= 2:
            name = "Another Provider"
        raw = (name + "\0").encode("utf-16-le")
        self.calls.append("size" if buffer is None else "read")
        if buffer is None:
            assert n.value == 0
            n.value = 1024 if self.mode == "oversized" else 3 if self.mode == "odd" else len(raw)
            return 0 if self.mode in {"denied", "missing", "unknown"} else 1
        assert n.value == len(raw)
        c.memmove(buffer, raw, len(raw))
        if self.mode == "grow":
            n.value += 2
        elif self.mode == "unterminated":
            c.cast(buffer, c.POINTER(c.c_uint16))[len(raw) // 2 - 1] = 65
        elif self.mode == "embedded":
            c.cast(buffer, c.POINTER(c.c_uint16))[2] = 0
        elif self.mode == "utf16":
            c.cast(buffer, c.POINTER(c.c_uint16))[2] = 0xD800
        elif self.mode == "control":
            c.cast(buffer, c.POINTER(c.c_uint16))[2] = 10
        return 0 if self.mode == "more-data" else 1


class FakeTcp:
    def __init__(self, mode="success"):
        self.mode = mode
        self.calls = []
        self.GetExtendedTcpTable = Function(self.query)

    def query(self, buffer, size, order, family, table_class, reserved):
        assert order == 0 and family in {2, 23} and table_class == 3 and reserved == 0
        cls = tcp.Row4 if family == 2 else tcp.Row6
        n = c.cast(size, c.POINTER(c.c_uint32)).contents
        self.calls.append("size" if buffer is None else "read")
        if buffer is None:
            assert n.value == 0
            n.value = 65537 if self.mode == "oversized" else 3 if self.mode == "small" else 4 + c.sizeof(cls)
            return (
                5
                if self.mode == "denied"
                else 87
                if self.mode == "unknown"
                else 0
                if self.mode == "null-success"
                else 122
            )
        if self.mode == "growing":
            return 122
        base = c.addressof(buffer)
        c.c_uint32.from_address(base).value = (
            0 if self.mode == "empty" else 257 if self.mode == "count" else 2 if self.mode == "truncated" else 1
        )
        row = cls.from_address(base + 4)
        row.state = 5 if self.mode == "connection" else 2
        address = b"\x7f\0\0\1" if family == 2 else b"\0" * 15 + b"\1"
        c.memmove(c.addressof(row) + cls.local_address.offset, address, len(address))
        row.local_port = 0xABCD0000 | int.from_bytes((443).to_bytes(2, "big"), "little")
        row.pid = 1235 if self.mode == "changed" and len(self.calls) > 2 else 1234
        if family == 23:
            row.local_scope = 0
        if self.mode == "bad-length":
            n.value += 1
        return 0


def snapshot(monkeypatch, which="capi", mode="success", scope=None):
    import inventory.host as host

    fake = FakeCapi(mode) if which == "capi" else FakeTcp(mode)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    monkeypatch.setattr(capi if which == "capi" else tcp, "_api", lambda: fake)
    codes = {"denied": 5, "missing": 2, "unknown": 123456, "more-data": 234}
    monkeypatch.setattr(c, "get_last_error", lambda: codes.get(mode, 0), raising=False)
    return collect(scope or manifest(which)), fake


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_metadata_canonical_commitment_and_no_use(monkeypatch, which):
    result, fake = snapshot(monkeypatch, which)
    receipt = result.receipts[0]
    assert receipt.status == "PARSED", receipt
    fact = receipt.facts[0]
    assert fact.interface_sha256 == receipt.content_sha256
    assert fact.algorithm == fact.runtime_use == fact.operation_use == fact.pqc_assessment == "UNKNOWN"
    assert fact.capabilities_observed is False and not result.windows_execution_qualified
    assert fake.calls == ["size", "read", "size", "read"]
    if which == "capi":
        assert fact.provider_type == 24 and fact.provider_context == "CURRENT_USER" and domains(fact) == ["TechBOM"]
    else:
        assert fact.listeners[0].port == 443 and fact.listeners[0].owning_pid == 1234
        assert fact.address_family == which and domains(fact) == ["NBOM", "TechBOM"]
        assert fact.tls_observed is fact.process_identity_verified is fact.asset_absence_proven is False
    HostSnapshot.model_validate(result.model_dump(mode="json"))


@pytest.mark.parametrize(
    "which,mode,status",
    [
        ("capi", "denied", "DENIED"),
        ("capi", "missing", "UNAVAILABLE"),
        ("capi", "unknown", "UNAVAILABLE"),
        ("capi", "more-data", "INVALID"),
        ("capi", "changed", "INVALID"),
        ("capi", "grow", "INVALID"),
        ("capi", "odd", "INVALID"),
        ("capi", "oversized", "BUDGET_EXCEEDED"),
        ("capi", "unterminated", "INVALID"),
        ("capi", "embedded", "INVALID"),
        ("capi", "utf16", "INVALID"),
        ("capi", "control", "INVALID"),
        ("ipv4", "denied", "DENIED"),
        ("ipv4", "unknown", "UNAVAILABLE"),
        ("ipv4", "growing", "INVALID"),
        ("ipv4", "small", "INVALID"),
        ("ipv4", "oversized", "BUDGET_EXCEEDED"),
        ("ipv4", "count", "BUDGET_EXCEEDED"),
        ("ipv4", "truncated", "INVALID"),
        ("ipv4", "connection", "INVALID"),
        ("ipv4", "changed", "INVALID"),
        ("ipv4", "bad-length", "INVALID"),
        ("ipv4", "null-success", "INVALID"),
    ],
)
def test_native_gaps_never_become_positive_or_absence(monkeypatch, which, mode, status):
    result, _ = snapshot(monkeypatch, which, mode)
    receipt = result.receipts[0]
    assert receipt.status == status and not receipt.facts and receipt.content_sha256 is None, receipt


@pytest.mark.parametrize("which", ["ipv4", "ipv6"])
def test_empty_table_is_a_query_observation_not_asset_absence(monkeypatch, which):
    result, _ = snapshot(monkeypatch, which, "empty")
    fact = result.receipts[0].facts[0]
    assert fact.listener_count == 0 and fact.listeners == [] and fact.asset_absence_proven is False


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_limits_and_platform_guards_before_native_calls(monkeypatch, which):
    result, fake = snapshot(monkeypatch, which)
    import inventory.host as host

    fake.calls.clear()
    scope = manifest(which).model_copy(update={"max_file_bytes": 1})
    assert collect(scope).receipts[0].status == "BUDGET_EXCEEDED" and not fake.calls
    monkeypatch.setattr(host, "elevated", lambda: True)
    assert collect(manifest(which)).receipts[0].status == "DENIED" and not fake.calls
    monkeypatch.setattr(host, "elevated", lambda: False)
    scope = manifest(which).model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    assert collect(scope).receipts[0].reason == "EXPIRED" and not fake.calls
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="linux"))
    assert collect(manifest(which)).receipts[0].status == "UNSUPPORTED" and not fake.calls


@pytest.mark.parametrize("which", ["capi", "ipv4"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("interface_sha256", "0" * 64),
        ("algorithm", "RSA"),
        ("runtime_use", "OBSERVED"),
        ("capabilities_observed", True),
        ("identity_key", "attested-device"),
        ("firmware_version", "invented"),
    ],
)
def test_tampered_or_promoted_fact_refuses(monkeypatch, which, field, value):
    result, _ = snapshot(monkeypatch, which)
    raw = result.model_dump(mode="json")
    raw["receipts"][0]["facts"][0][field] = value
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(raw)


@pytest.mark.parametrize("which", ["capi", "ipv4"])
@pytest.mark.parametrize("change", ["receipt", "duplicate", "platform", "scope"])
def test_receipt_scope_cardinality_platform(monkeypatch, which, change):
    result, _ = snapshot(monkeypatch, which)
    raw = result.model_dump(mode="json")
    receipt = raw["receipts"][0]
    fact = receipt["facts"][0]
    if change == "receipt":
        receipt["content_sha256"] = "0" * 64
    elif change == "duplicate":
        receipt["facts"].append(fact.copy())
    elif change == "platform":
        raw["execution_platform"] = "linux"
    elif which == "capi":
        from shared_models.windows_capi import provider_bytes

        fact["provider_type"] = 1
        fact["identity_key"] = "windows-capi:current-user:1:default-provider"
        fact["interface_sha256"] = hashlib.sha256(provider_bytes(1, fact["provider_name"])).hexdigest()
        receipt["content_sha256"] = fact["interface_sha256"]
    else:
        from shared_models.windows_listeners import listener_bytes

        fact["address_family"] = "ipv6"
        fact["identity_key"] = "windows-tcp-table:ipv6:owner-pid-listener"
        fact["listeners"] = []
        fact["listener_count"] = 0
        fact["interface_sha256"] = hashlib.sha256(listener_bytes("ipv6", [])).hexdigest()
        receipt["content_sha256"] = fact["interface_sha256"]
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(raw)


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
@pytest.mark.parametrize("suffix", ["/", "?all=1", "/keys", "%2F", "*"])
def test_only_exact_resources(which, suffix):
    kind, path = RESOURCES[which]
    with pytest.raises(ValidationError):
        HostInput(input_id="metadata", kind=kind, path=path + suffix)


def test_fixed_width_abi_and_system32(monkeypatch):
    assert c.sizeof(tcp.Row4) == 24 and c.sizeof(tcp.Row6) == 56
    assert tcp.Row6.state.offset == 48 and tcp.Row6.pid.offset == 52
    for module, dll, fake, method, restype in [
        (capi, "advapi32.dll", FakeCapi(), "CryptGetDefaultProviderW", c.c_int32),
        (tcp, "iphlpapi.dll", FakeTcp(), "GetExtendedTcpTable", c.c_uint32),
    ]:

        def load(name, **kw):
            assert name == dll and kw == {"use_last_error": True, "winmode": 0x800}
            return fake

        monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))
        monkeypatch.setattr(c, "WinDLL", load, raising=False)
        assert module._api() is fake and getattr(fake, method).restype is restype


@pytest.mark.parametrize("which", ["capi", "ipv4"])
@pytest.mark.parametrize("missing", ["dll", "export"])
def test_missing_binding_is_gap(monkeypatch, which, missing):
    module = capi if which == "capi" else tcp
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32"))

    def load(*a, **kw):
        if missing == "dll":
            raise OSError("unavailable")
        return SimpleNamespace()

    monkeypatch.setattr(c, "WinDLL", load, raising=False)
    with pytest.raises(Refused) as exc:
        module._api()
    assert (exc.value.status, exc.value.reason) == ("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


@pytest.mark.skipif(sys.platform != "win32", reason="Actual approved ordinary-user Windows required")
@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_native_operator_reviewed_resource(which):
    resource = os.getenv("CRYPTOSCAN_WINDOWS_METADATA_RESOURCE")
    if resource != RESOURCES[which][1]:
        pytest.skip("Exact reviewed existing resource required; no setup")
    assert not elevated()
    result = collect(manifest(which))
    assert result.receipts[0].status == "PARSED", result.receipts[0]
    assert not result.windows_execution_qualified


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_postquery_and_total_budget_no_positive_truncation(monkeypatch, which):
    value, fake = snapshot(monkeypatch, which)
    used = value.receipts[0].byte_count
    fake.calls.clear()
    scope = manifest(which).model_copy(update={"max_file_bytes": used - 1})
    result = collect(scope)
    assert result.receipts[0].status == "BUDGET_EXCEEDED" and not result.receipts[0].facts
    assert fake.calls == ["size", "read", "size", "read"]
    scope = manifest(which).model_copy(update={"max_total_bytes": used - 1})
    assert collect(scope).receipts[0].status == "BUDGET_EXCEEDED"


@pytest.mark.parametrize(
    "selection,provider_type", [("rsa-full", 1), ("rsa-signature", 2), ("dss", 3), ("dss-dh", 13), ("rsa-aes", 24)]
)
def test_exact_legacy_provider_type_mapping(monkeypatch, selection, provider_type):
    _, fake = snapshot(monkeypatch, "capi")
    scope = manifest("capi").model_copy(
        update={
            "inputs": [
                HostInput(
                    input_id="metadata",
                    kind="WINDOWS_CAPI_DEFAULT_PROVIDER",
                    path=f"windows-capi://local/current-user/{selection}/default-provider",
                )
            ]
        }
    )
    value = collect(scope)
    assert value.receipts[0].status == "PARSED" and value.receipts[0].facts[0].provider_type == provider_type
