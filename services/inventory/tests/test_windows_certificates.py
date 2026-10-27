"""Portable ABI/ownership fixtures, NOT native Windows qualification."""

import ctypes
from datetime import datetime, timedelta, timezone
from hashlib import sha1, sha256
from types import SimpleNamespace
import sys
import os
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pydantic import ValidationError
from inventory import windows_certificates as certs
from inventory.host import Refused, collect, elevated
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot
from services.inventory.tests.test_host import certificate


def der():
    return x509.load_pem_x509_certificate(certificate()).public_bytes(Encoding.DER)


def resource(data, location="current-user", store="MY"):
    return f"windows-cert://{location}/{store}/sha1/{sha1(data).hexdigest()}/sha256/{sha256(data).hexdigest()}"


def manifest(data):
    return HostManifest(
        approval_reference="change/windows-cert-candidate",
        host_id="synthetic-windows",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[HostInput(input_id="cert", kind="WINDOWS_CERTIFICATE", path=resource(data))],
    )


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class FakeCrypt32:
    """Own native-like buffers until fake close; simulates documented prev ownership."""

    def __init__(self, data, *, second="missing", open_error=None, first_error=None, close_ok=True, free_ok=True):
        self.data = data
        self.second = second
        self.open_error = open_error
        self.first_error = first_error
        self.close_ok = close_ok
        self.free_ok = free_ok
        self.error = 0
        self.calls = []
        self.finds = 0
        self.buffers = [(ctypes.c_ubyte * len(data)).from_buffer_copy(data) for _ in range(2)]
        self.contexts = [certs.CertificateContext(1, b, len(data), None, 71) for b in self.buffers]
        self.pointers = [ctypes.pointer(c) for c in self.contexts]
        self.CertOpenStore = Function(self.open)
        self.CertFindCertificateInStore = Function(self.find)
        self.CertFreeCertificateContext = Function(self.free)
        self.CertCloseStore = Function(self.close)

    def open(self, provider, encoding, crypto, flags, name):
        self.calls.append(("open", provider, encoding, crypto, flags, ctypes.wstring_at(name)))
        if self.open_error is not None:
            self.error = self.open_error
            return None
        return 71

    def find(self, store, encoding, flags, find_type, parameter, previous):
        assert store == 71 and encoding == 0x10001 and flags == 0 and find_type == 0x10000
        blob = ctypes.cast(parameter, ctypes.POINTER(certs.HashBlob)).contents
        assert blob.cbData == 20
        self.calls.append(("find", bytes(blob.pbData[:20]).hex(), bool(previous)))
        self.finds += 1
        if self.finds == 1:
            assert not previous
            if self.first_error is not None:
                self.error = self.first_error
                return None
            return self.pointers[0]
        assert ctypes.addressof(previous.contents) == ctypes.addressof(self.contexts[0])
        self.calls.append(("auto-free-first",))
        if self.second == "duplicate":
            return self.pointers[1]
        self.error = certs.CRYPT_E_NOT_FOUND if self.second == "missing" else 5 if self.second == "denied" else 87
        return None

    def free(self, context):
        index = next(
            i for i, c in enumerate(self.contexts) if ctypes.addressof(context.contents) == ctypes.addressof(c)
        )
        self.calls.append(("free", index))
        return self.free_ok

    def close(self, store, flags):
        assert store == 71 and flags == 0
        self.calls.append(("close",))
        return self.close_ok


def install(monkeypatch, fake):
    monkeypatch.setattr(certs, "_api", lambda: fake)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: fake.error, raising=False)


def test_fixed_width_native_layout_and_function_prototypes(monkeypatch):
    pointer = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(certs.HashBlob) == (16 if pointer == 8 else 8)
    assert ctypes.sizeof(certs.CertificateContext) == (40 if pointer == 8 else 20)
    assert certs.CertificateContext.cbCertEncoded.offset == (16 if pointer == 8 else 8)
    fake = FakeCrypt32(der())
    monkeypatch.setattr(certs, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **kw: fake, raising=False)
    assert certs._api() is fake
    assert fake.CertOpenStore.restype is ctypes.c_void_p
    assert fake.CertFindCertificateInStore.restype is ctypes.POINTER(certs.CertificateContext)
    assert fake.CertOpenStore.argtypes[2] is ctypes.c_size_t


@pytest.mark.parametrize(
    "location,store",
    [("current-user", "MY"), ("local-machine", "MY"), ("current-user", "ROOT"), ("current-user", "CA")],
)
def test_exact_read_only_query_emits_public_metadata_and_closes(monkeypatch, location, store):
    data = der()
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    charged = []
    item = HostInput(input_id="cert", kind="WINDOWS_CERTIFICATE", path=resource(data, location, store))
    copied, facts = certs.collect_certificate(item, 1048576, charged.append)
    assert copied == data and len(facts) == 1 and facts[0].fingerprint_sha256 == sha256(data).hexdigest()
    assert facts[0].kind == "CERTIFICATE" and facts[0].algorithm == "RSA" and facts[0].local_basis == "OBSERVED"
    assert facts[0].runtime_use == "UNKNOWN" and facts[0].pqc_assessment == "UNKNOWN"
    opened = fake.calls[0]
    assert opened[1:4] == (10, 0, 0) and opened[4] == 0x4000 | 0x8000 | certs.LOCATIONS[location] and opened[5] == store
    assert fake.finds == 2 and ("auto-free-first",) in fake.calls and not any(c[0] == "free" for c in fake.calls)
    assert fake.calls[-1] == ("close",) and sum(charged) > len(data)


@pytest.mark.parametrize(
    "which,error,exception",
    [
        (which, error, exception)
        for which in ("open", "first", "second")
        for error, exception in ((5, PermissionError), (certs.CRYPT_E_NOT_FOUND, FileNotFoundError), (87, Refused))
        if not (which == "second" and error == certs.CRYPT_E_NOT_FOUND)
    ],
)
def test_native_failures_never_emit_positive_metadata(monkeypatch, which, error, exception):
    data = der()
    if which == "second":
        fake = FakeCrypt32(data, second="denied" if error == 5 else "other")
    else:
        fake = FakeCrypt32(data, **{("open_error" if which == "open" else "first_error"): error})
    install(monkeypatch, fake)
    with pytest.raises(exception):
        certs.collect_certificate(manifest(data).inputs[0], 1048576, lambda n: None)
    assert bool(any(c[0] == "close" for c in fake.calls)) == (which != "open")


def test_duplicate_locator_refuses_and_frees_second_context_exactly_once(monkeypatch):
    data = der()
    fake = FakeCrypt32(data, second="duplicate")
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        certs.read_certificate(resource(data), 1048576, lambda n: None)
    assert fake.calls[-3:] == [("auto-free-first",), ("free", 1), ("close",)]


@pytest.mark.parametrize("field", ["sha1", "sha256"])
def test_mismatched_approved_binding_refuses_before_second_query(monkeypatch, field):
    data = der()
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    path = (
        resource(data).replace(sha1(data).hexdigest(), "0" * 40)
        if field == "sha1"
        else resource(data).replace(sha256(data).hexdigest(), "0" * 64)
    )
    with pytest.raises(Refused) as error:
        certs.read_certificate(path, 1048576, lambda n: None)
    assert error.value.reason == "INPUT_CHANGED" and fake.finds == 1
    assert fake.calls[-2:] == [("free", 0), ("close",)]


@pytest.mark.parametrize("fault", ["oversize", "empty", "null", "encoding"])
def test_native_length_and_pointer_checks_precede_copy(monkeypatch, fault):
    data = der()
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    if fault == "oversize":
        fake.contexts[0].cbCertEncoded = 2000000
    elif fault == "empty":
        fake.contexts[0].cbCertEncoded = 0
    elif fault == "null":
        fake.contexts[0].pbCertEncoded = None
    else:
        fake.contexts[0].dwCertEncodingType = 999
    monkeypatch.setattr(ctypes, "string_at", lambda *args: pytest.fail("Copy must not happen"))
    with pytest.raises(Refused):
        certs.read_certificate(resource(data), 1048576, lambda n: None)
    assert fake.calls[-2:] == [("free", 0), ("close",)]


def test_budget_refuses_before_native_open_and_cleanup_failures_refuse(monkeypatch):
    data = der()
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        certs.read_certificate(resource(data), 1, lambda n: None)
    assert not fake.calls
    fake = FakeCrypt32(data, close_ok=False)
    install(monkeypatch, fake)
    with pytest.raises(Refused):
        certs.read_certificate(resource(data), 1048576, lambda n: None)
    assert fake.calls[-1] == ("close",)


@pytest.mark.parametrize(
    "path",
    [
        "windows-cert://remote/MY/sha1/" + "a" * 40 + "/sha256/" + "b" * 64,
        "windows-cert://current-user/ALL/sha1/" + "a" * 40 + "/sha256/" + "b" * 64,
        "windows-cert://current-user/my/sha1/" + "a" * 40 + "/sha256/" + "b" * 64,
        "windows-cert://current-user/MY/sha1/" + "A" * 40 + "/sha256/" + "b" * 64,
        "windows-cert://current-user/MY/sha1/" + "a" * 40,
        "windows-cert://current-user/MY/sha1/" + "a" * 40 + "/sha256/" + "b" * 64 + "?remote=1",
    ],
)
def test_noncanonical_remote_or_incomplete_scope_refuses(path):
    with pytest.raises(ValidationError):
        HostInput(input_id="cert", kind="WINDOWS_CERTIFICATE", path=path)


def test_linux_cannot_execute_candidate_and_snapshot_must_match_platform_and_fingerprint(monkeypatch):
    data = der()
    m = manifest(data)
    if sys.platform != "win32":
        with pytest.raises(ValueError):
            certs._api()
        result = collect(m)
        assert result.receipts[0].status == "UNSUPPORTED" and not result.receipts[0].facts
    # Explicit portable integration injection, never represented as native truth.
    import inventory.host as host

    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    result = collect(m)
    assert result.receipts[0].status == "PARSED"
    assert not result.windows_execution_qualified and not result.production_execution_qualified
    wrong = result.model_dump(mode="json")
    wrong["receipts"][0]["facts"][0]["fingerprint_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(wrong)
    wrong = result.model_dump(mode="json")
    wrong["receipts"][0]["content_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(wrong)
    wrong = result.model_dump(mode="json")
    wrong["execution_platform"] = "linux"
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(wrong)


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows certificate store unavailable on Linux")
def test_native_windows_exact_operator_fixture_read_only():
    path = os.getenv("CRYPTOSCAN_WINDOWS_CERTIFICATE_RESOURCE")
    if not path:
        pytest.skip("Operator-selected existing public certificate resource required; no store mutation")
    assert not elevated(), "Actual ordinary Windows user required"
    m = manifest(b"unused-scope-seed").model_copy(
        update={"inputs": [HostInput(input_id="cert", kind="WINDOWS_CERTIFICATE", path=path)]}
    )
    snapshot = collect(m)
    assert snapshot.receipts[0].status == "PARSED", snapshot.receipts[0]
    assert snapshot.receipts[0].facts[0].fingerprint_sha256 == path.rsplit("/", 1)[1]
    assert not snapshot.windows_execution_qualified and not snapshot.production_execution_qualified


def test_oversize_fixed_budget_and_expired_elevated_scope_do_not_open_store(monkeypatch):
    import inventory.host as host

    data = der()
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    scope = manifest(data).model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    snapshot = collect(scope)
    assert snapshot.receipts[0].status == "DENIED" and snapshot.receipts[0].reason == "EXPIRED" and not fake.calls
    monkeypatch.setattr(host, "elevated", lambda: True)
    snapshot = collect(manifest(data))
    assert snapshot.receipts[0].reason == "LEAST_PRIVILEGE_UNPROVEN" and not fake.calls


def test_free_failure_still_closes_store_and_refuses(monkeypatch):
    data = der()
    fake = FakeCrypt32(data, second="duplicate", free_ok=False)
    install(monkeypatch, fake)
    with pytest.raises(Refused) as error:
        certs.read_certificate(resource(data), 1048576, lambda n: None)
    assert error.value.reason == "INTERFACE_UNAVAILABLE" and fake.calls[-1] == ("close",)


def test_malformed_bound_bytes_do_not_emit_a_certificate_fact(monkeypatch):
    import inventory.host as host

    data = b"not public DER"
    fake = FakeCrypt32(data)
    install(monkeypatch, fake)
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: False)
    snapshot = collect(manifest(data))
    assert snapshot.receipts[0].status == "INVALID" and not snapshot.receipts[0].facts
    assert fake.calls[-1] == ("close",)
