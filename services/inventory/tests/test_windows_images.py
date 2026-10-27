"""Portable toolhelp fixtures; never a substitute for native Windows execution."""

import ctypes as c
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import sys, os
import pytest
from pydantic import ValidationError
from inventory import windows_images as images
from inventory.host import collect, Refused, elevated
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot

PID = 71
CREATED = "133800000000000001"  # Deliberately above JavaScript exact-number range.
EXE = r"C:\Reviewed\payments.exe"
DLL = r"C:\Reviewed\libcrypto.dll"


def item(pid=PID, created=CREATED):
    return HostInput(
        input_id="images", kind="WINDOWS_PROCESS_MODULES", path=f"windows-process://{pid}/created/{created}/modules"
    )


def manifest():
    return HostManifest(
        approval_reference="change/windows-images",
        host_id="synthetic-windows",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[item()],
    )


def utf16(buffer, text):
    raw = text.encode("utf-16-le")
    units = [int.from_bytes(raw[n : n + 2], "little") for n in range(0, len(raw), 2)]
    for n, value in enumerate(units):
        buffer[n] = value
    buffer[len(units)] = 0
    return len(units)


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class FakeKernel:
    def __init__(
        self, *, rows=None, changed=False, error_at=None, error=5, creation=CREATED, exit_code=259, signaled=False
    ):
        self.rows = rows if rows is not None else [("payments.exe", EXE), ("libcrypto.dll", DLL)]
        self.changed = changed
        self.error_at = error_at
        self.error = error
        self.creation = creation
        self.exit_code = exit_code
        self.signaled = signaled
        self.calls = []
        self.pass_no = 0
        self.index = 0
        self.last = 0
        for name in [
            "OpenProcess",
            "GetProcessTimes",
            "GetExitCodeProcess",
            "QueryFullProcessImageNameW",
            "CreateToolhelp32Snapshot",
            "Module32FirstW",
            "Module32NextW",
            "CloseHandle",
            "WaitForSingleObject",
        ]:
            setattr(self, name, Function(getattr(self, "_" + name)))

    def fail(self, name):
        self.calls.append(name)
        if self.error_at == name:
            self.last = self.error
            return True
        return False

    def _OpenProcess(self, rights, inherit, pid):
        assert rights == 0x00101000 and inherit is False and pid == PID
        return None if self.fail("open") else 11

    def _GetProcessTimes(self, handle, created, *rest):
        assert handle == 11
        if self.fail("time"):
            return False
        value = int(self.creation)
        v = c.cast(created, c.POINTER(images.FileTime)).contents
        v.low = value & 0xFFFFFFFF
        v.high = value >> 32
        return True

    def _GetExitCodeProcess(self, handle, code):
        if self.fail("exit"):
            return False
        c.cast(code, c.POINTER(c.c_uint32)).contents.value = self.exit_code
        return True

    def _WaitForSingleObject(self, handle, timeout):
        assert handle == 11 and timeout == 0
        if self.fail("wait"):
            return 0xFFFFFFFF
        return 0 if self.signaled else 258

    def _QueryFullProcessImageNameW(self, handle, flags, buffer, size):
        assert handle == 11 and flags == 0
        if self.fail("image"):
            return False
        c.cast(size, c.POINTER(c.c_uint32)).contents.value = utf16(buffer, EXE)
        return True

    def _CreateToolhelp32Snapshot(self, flags, pid):
        assert flags == 0x18 and pid == PID
        if self.fail("snapshot"):
            return images.INVALID_HANDLE
        self.pass_no += 1
        return 20 + self.pass_no

    def entry(self, pointer):
        entry = c.cast(pointer, c.POINTER(images.ModuleEntry)).contents
        assert entry.size == c.sizeof(entry)
        name, path = self.rows[self.index]
        entry.pid = PID
        if self.changed and self.pass_no == 2 and self.index == 1:
            name, path = "changed.dll", r"C:\Reviewed\changed.dll"
        utf16(entry.name, name)
        utf16(entry.path, path)

    def _Module32FirstW(self, handle, pointer):
        if self.fail("first"):
            return False
        self.index = 0
        if not self.rows:
            self.last = 18
            return False
        self.entry(pointer)
        return True

    def _Module32NextW(self, handle, pointer):
        if self.fail("next"):
            return False
        self.index += 1
        if self.index == len(self.rows):
            self.last = 18
            return False
        self.entry(pointer)
        return True

    def _CloseHandle(self, handle):
        self.calls.append(("close", handle))
        return self.error_at != "close"


def install(monkeypatch, fake):
    monkeypatch.setattr(images, "_api", lambda: fake)
    monkeypatch.setattr(c, "get_last_error", lambda: fake.last, raising=False)


def test_fixed_width_layout_and_system32_function_prototypes(monkeypatch):
    ptr = c.sizeof(c.c_void_p)
    assert c.sizeof(images.FileTime) == 8 and c.sizeof(images.ModuleEntry) == (1080 if ptr == 8 else 1064)
    assert images.ModuleEntry.name.offset == (48 if ptr == 8 else 32)
    fake = FakeKernel()

    def dll(name, **kwargs):
        assert name == "kernel32.dll" and kwargs == {"use_last_error": True, "winmode": 0x800}
        return fake

    monkeypatch.setattr(images, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(c, "WinDLL", dll, raising=False)
    assert images._api() is fake
    assert fake.OpenProcess.restype is c.c_void_p and fake.Module32FirstW.argtypes[1] is c.POINTER(images.ModuleEntry)


def test_exact_process_and_repeated_module_metadata_not_invocation(monkeypatch):
    fake = FakeKernel()
    install(monkeypatch, fake)
    charged = []
    raw, facts = images.collect_images(item(), 1048576, charged.append)
    assert len(facts) == 3 and facts[0].kind == "WINDOWS_PROCESS_IMAGE" and facts[0].image_path == EXE
    assert [f.module_name for f in facts[1:]] == ["libcrypto.dll", "payments.exe"]
    assert all(
        f.creation_filetime == CREATED and f.runtime_use == f.operation_use == f.algorithm == "UNKNOWN" for f in facts
    )
    assert all(f.software_version is None and not f.capabilities_observed for f in facts)
    assert fake.pass_no == 2 and fake.calls[-1] == ("close", 11)
    assert [v for v in fake.calls if isinstance(v, tuple)] == [("close", 21), ("close", 22), ("close", 11)]
    assert sum(charged) > len(raw)
    assert b"base_size" not in raw and b"address" not in raw


@pytest.mark.parametrize("stage", ["open", "time", "exit", "image", "snapshot", "first", "next", "wait"])
@pytest.mark.parametrize("error,expected", [(5, PermissionError), (299, Refused), (24, Refused)])
def test_native_failures_clean_up_without_positive_facts(monkeypatch, stage, error, expected):
    fake = FakeKernel(error_at=stage, error=error)
    install(monkeypatch, fake)
    with pytest.raises(expected):
        images.collect_images(item(), 1048576, lambda n: None)
    if stage != "open":
        assert fake.calls[-1] == ("close", 11)
    if stage in {"first", "next"}:
        assert ("close", 21) in fake.calls


@pytest.mark.parametrize(
    "fault",
    [
        "pid-reused",
        "exited",
        "exited-259",
        "modules-changed",
        "duplicates",
        "empty",
        "over-count",
        "bad-path",
        "name-mismatch",
        "close",
    ],
)
def test_changed_or_ambiguous_metadata_never_becomes_stable_usage(monkeypatch, fault):
    options = {}
    if fault == "pid-reused":
        options["creation"] = str(int(CREATED) + 1)
    elif fault == "exited":
        options["exit_code"] = 0
    elif fault == "exited-259":
        options["signaled"] = True
    elif fault == "modules-changed":
        options["changed"] = True
    elif fault == "duplicates":
        options["rows"] = [("payments.exe", EXE), ("payments.exe", EXE)]
    elif fault == "empty":
        options["rows"] = []
    elif fault == "over-count":
        options["rows"] = [(f"a{i}.dll", f"C:\\Reviewed\\a{i}.dll") for i in range(257)]
    elif fault == "bad-path":
        options["rows"] = [("network.dll", r"\\remote\share\network.dll")]
    elif fault == "name-mismatch":
        options["rows"] = [("other.dll", DLL)]
    else:
        options["error_at"] = "close"
    fake = FakeKernel(**options)
    install(monkeypatch, fake)
    with pytest.raises((Refused, ValueError)):
        images.collect_images(item(), 1048576, lambda n: None)
    assert fake.calls[-1] == ("close", 11)


def test_preopen_and_midloop_budgets_close_handles(monkeypatch):
    fake = FakeKernel()
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        images.collect_images(item(), 10, lambda n: None)
    assert fake.calls == []
    with pytest.raises(Refused):
        images.collect_images(item(), 3300, lambda n: None)
    assert fake.calls[-2:] == [("close", 21), ("close", 11)]


@pytest.mark.parametrize(
    "path",
    [
        "windows-process://0/created/1/modules",
        "windows-process://01/created/1/modules",
        "windows-process://4294967296/created/1/modules",
        "windows-process://71/created/01/modules",
        "windows-process://71/created/18446744073709551616/modules",
        "windows-process://remote/created/1/modules",
        "windows-process://71/created/1/modules?all=true",
    ],
)
def test_canonical_scope_required(path):
    with pytest.raises(ValidationError):
        HostInput(input_id="images", kind="WINDOWS_PROCESS_MODULES", path=path)


@pytest.mark.parametrize(
    "change",
    [
        "creation-number",
        "pid",
        "digest",
        "identity",
        "algorithm",
        "runtime",
        "platform",
        "missing-process",
        "duplicate-module",
    ],
)
def test_snapshot_contract_keeps_incarnation_digest_and_unknowns_bound(monkeypatch, change):
    import inventory.host as host

    install(monkeypatch, FakeKernel())
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    result = collect(manifest())
    assert result.receipts[0].status == "PARSED"
    raw = result.model_dump(mode="json")
    fact = raw["receipts"][0]["facts"][1]
    if change == "creation-number":
        fact["creation_filetime"] = int(CREATED)
    elif change == "pid":
        fact["pid"] = PID + 1
    elif change == "digest":
        fact["interface_sha256"] = "0" * 64
    elif change == "identity":
        fact["identity_key"] = "invented"
    elif change == "algorithm":
        fact["algorithm"] = "RSA"
    elif change == "runtime":
        fact["runtime_use"] = "OBSERVED"
    elif change == "platform":
        raw["execution_platform"] = "linux"
    elif change == "missing-process":
        raw["receipts"][0]["facts"] = raw["receipts"][0]["facts"][1:]
    else:
        raw["receipts"][0]["facts"].append(dict(fact))
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(raw)


def test_windows_reader_does_not_emulate_linux_or_bypass_expiry_or_elevation(monkeypatch):
    if sys.platform != "win32":
        with pytest.raises(ValueError):
            images._api()
        result = collect(manifest())
        assert result.receipts[0].status == "UNSUPPORTED"
    import inventory.host as host

    fake = FakeKernel()
    install(monkeypatch, fake)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: True)
    assert collect(manifest()).receipts[0].reason == "LEAST_PRIVILEGE_UNPROVEN" and not fake.calls
    monkeypatch.setattr(host, "elevated", lambda: False)
    expired = manifest().model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    assert collect(expired).receipts[0].reason == "EXPIRED" and not fake.calls


@pytest.mark.skipif(sys.platform != "win32", reason="Actual ordinary-user Windows process/module fixture required")
def test_native_operator_selected_process_image_fixture():
    scope = os.getenv("CRYPTOSCAN_WINDOWS_PROCESS_RESOURCE")
    if not scope:
        pytest.skip("Reviewed existing process PID/creation resource required; no process launched")
    assert not elevated()
    target = manifest().model_copy(
        update={"inputs": [HostInput(input_id="images", kind="WINDOWS_PROCESS_MODULES", path=scope)]}
    )
    snapshot = collect(target)
    assert snapshot.receipts[0].status == "PARSED", snapshot.receipts[0]
    assert any(f.kind == "WINDOWS_MODULE" for f in snapshot.receipts[0].facts)
    assert not snapshot.windows_execution_qualified


@pytest.mark.parametrize("change", ["end-time", "end-path", "end-exit-259"])
def test_final_handle_bound_identity_must_still_match(monkeypatch, change):
    fake = FakeKernel()
    install(monkeypatch, fake)
    original = fake.GetProcessTimes.call

    def times(*args):
        if fake.pass_no == 2:
            if change == "end-time":
                fake.creation = str(int(CREATED) + 1)
            elif change == "end-exit-259":
                fake.signaled = True
        return original(*args)

    fake.GetProcessTimes.call = times
    original_image = fake.QueryFullProcessImageNameW.call

    def path(*args):
        result = original_image(*args)
        if fake.pass_no == 2 and change == "end-path":
            c.cast(args[-1], c.POINTER(c.c_uint32)).contents.value = utf16(args[-2], r"C:\Reviewed\other.exe")
        return result

    fake.QueryFullProcessImageNameW.call = path
    with pytest.raises(Refused) as caught:
        images.collect_images(item(), 1048576, lambda n: None)
    assert caught.value.reason == "INPUT_CHANGED" and fake.calls[-1] == ("close", 11)


def test_module_mutation_cannot_reuse_selected_metadata_commitment(monkeypatch):
    import hashlib
    import inventory.host as host

    install(monkeypatch, FakeKernel())
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    raw = collect(manifest()).model_dump(mode="json")
    fact = raw["receipts"][0]["facts"][1]
    fact["image_path"] = r"C:\Reviewed\other.dll"
    fact["module_name"] = "other.dll"
    fact["identity_key"] = (
        f"pid:{PID}:created:{CREATED}:path-sha256:" + hashlib.sha256(fact["image_path"].encode()).hexdigest()
    )
    with pytest.raises(ValidationError, match="commitment mismatch"):
        HostSnapshot.model_validate(raw)


def test_metadata_domains_do_not_turn_crypto_named_dll_into_cbom(monkeypatch):
    from shared_models.host_runtime import domains
    from shared_models.collection_coverage import SURFACES

    install(monkeypatch, FakeKernel())
    _, facts = images.collect_images(item(), 1048576, lambda n: None)
    assert domains(facts[0]) == ["TechBOM"] and domains(facts[1]) == ["SBOM", "TechBOM"]
    assert "WINDOWS_PROCESS_MODULES" in SURFACES["processes_and_libraries"]
