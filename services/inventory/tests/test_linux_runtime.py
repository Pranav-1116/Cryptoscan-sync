"""Native ordinary-user witnesses plus adversarial pure-interface/format tests."""

import os
import socket
import sys
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from inventory.host import collect, elevated
from inventory import linux_runtime as live
from shared_models.host_collection import HostManifest, HostInput, HostSnapshot, digest
from shared_models.host_runtime import RuntimeFact, domains

BOOT = "12345678-1234-1234-1234-123456789abc"


def manifest(kind, path, **kwargs):
    return HostManifest(
        approval_reference="change/runtime",
        host_id="sandbox-ordinary-user",
        environment="test",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        inputs=[HostInput(input_id="approved", kind=kind, path=path)],
        **kwargs,
    )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Native Linux only")
def test_native_explicit_self_process_and_shared_object_mappings():
    assert not elevated(), "Native witness requires ordinary user, not a patched privilege check"
    for kind, uri in [("LINUX_PROCESS", "linux-proc://self/process"), ("LINUX_PROCESS_MAPS", "linux-proc://self/maps")]:
        snapshot = collect(manifest(kind, uri))
        receipt = snapshot.receipts[0]
        assert receipt.status == "PARSED", receipt
        assert all(f.pid == os.getpid() and f.process_start_ticks > 0 and f.interface_sha256 for f in receipt.facts)
        assert all(f.runtime_use == "UNKNOWN" and f.operation_use == "UNKNOWN" for f in receipt.facts)
        assert not snapshot.host_identity_attested
        if kind == "LINUX_PROCESS_MAPS":
            assert any(".so" in f.library_path for f in receipt.facts)
            assert all(f.mapping_basis == "SHARED_OBJECT_PATH_SUFFIX_ONLY" for f in receipt.facts)
            assert all(domains(f) == ["SBOM", "TechBOM"] for f in receipt.facts)
        HostSnapshot.model_validate(snapshot.model_dump(mode="json"))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Native Linux only")
def test_native_owned_listening_socket_is_metadata_not_tls_or_remote_reachability():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        snapshot = collect(manifest("LINUX_LISTENERS", "linux-sockets://self/tcp"))
        receipt = snapshot.receipts[0]
        assert receipt.status == "PARSED", receipt
        found = [f for f in receipt.facts if f.port == port and f.address == "127.0.0.1"]
        assert len(found) == 1 and found[0].pid is None and found[0].algorithm == "UNKNOWN"
        assert domains(found[0]) == ["NBOM", "TechBOM"]
        HostSnapshot.model_validate(snapshot.model_dump(mode="json"))


def test_kernel_filesystem_check_rejects_regular_fixture_even_with_valid_looking_bytes(tmp_path):
    path = tmp_path / "stat"
    path.write_text("kernel-shaped fixture")
    with pytest.raises(live.ProbeError) as error:
        live.kernel_bytes(str(path), 1000, 0x9FA0)
    assert error.value.status == "UNSUPPORTED"
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        live.kernel_bytes(str(alias), 1000, 0x9FA0)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Native Linux only")
def test_native_dmi_or_explicit_hardware_gap_without_serials_or_mechanism_claims():
    receipt = collect(manifest("LINUX_HARDWARE", "linux-hardware://dmi")).receipts[0]
    if receipt.status == "PARSED":
        assert receipt.facts[0].hardware_type == "SYSTEM_DMI"
        assert domains(receipt.facts[0]) == ["HBOM", "TechBOM"]
        assert "serial" not in receipt.model_dump_json().lower() and not receipt.facts[0].capabilities_observed
    else:
        assert receipt.status in {"DENIED", "UNAVAILABLE", "UNSUPPORTED"} and not receipt.facts


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Native Linux only")
def test_native_named_systemd_and_unavailable_tpm_do_not_become_absence():
    service = collect(manifest("LINUX_SERVICE", "systemd://cryptoscan-nonexistent-witness.service")).receipts[0]
    assert service.status in {"UNAVAILABLE", "UNSUPPORTED", "DENIED"} and not service.facts
    tpm = collect(manifest("LINUX_HARDWARE", "linux-hardware://tpm999")).receipts[0]
    assert tpm.status in {"UNAVAILABLE", "UNSUPPORTED", "DENIED"} and not tpm.facts


@pytest.mark.parametrize(
    "kind,path",
    [
        ("LINUX_PROCESS", "linux-proc://*/process"),
        ("LINUX_PROCESS", "linux-proc://0/process"),
        ("LINUX_PROCESS_MAPS", "linux-proc://1/environ"),
        ("LINUX_PROCESS_MAPS", "/proc/1/maps"),
        ("LINUX_LISTENERS", "linux-sockets://other/tcp"),
        ("LINUX_LISTENERS", "linux-sockets://self/udp"),
        ("LINUX_SERVICE", "systemd://--help.service"),
        ("LINUX_SERVICE", "systemd://foo.service;id"),
        ("LINUX_HARDWARE", "linux-hardware://../../etc"),
        ("LINUX_HARDWARE", "linux-hardware://dmi/serial"),
        ("WINDOWS_SERVICE", "windows-service://remote/service"),
    ],
)
def test_only_canonical_explicit_interface_resources_are_approvable(kind, path):
    with pytest.raises(ValidationError):
        manifest(kind, path)


def table(address="0100007F", port="01BB", state="0A", inode=42):
    return f" sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n 0: {address}:{port} 00000000:0000 {state} 0:0 0:0 0 1001 0 {inode}\n".encode()


@pytest.mark.parametrize(
    "family,address,expected",
    [
        ("tcp", "0100007F" if sys.byteorder == "little" else "7F000001", "127.0.0.1"),
        (
            "tcp6",
            "00000000000000000000000001000000" if sys.byteorder == "little" else "00000000000000000000000000000001",
            "::1",
        ),
        ("tcp", "00000000", "0.0.0.0"),
    ],
)
def test_native_endian_listener_parser_without_port_to_tls_inference(family, address, expected):
    facts = live.parse_listeners(table(address), family, "net:[123]", BOOT)
    assert len(facts) == 1 and facts[0].address == expected and facts[0].port == 443
    assert facts[0].algorithm == facts[0].runtime_use == "UNKNOWN" and facts[0].pid is None
    assert not live.parse_listeners(table(address, state="01"), family, "net:[123]", BOOT)


@pytest.mark.parametrize("raw", [b"bad", table("garbage"), table(port="FFFFF"), table(inode=0)])
def test_malformed_listener_data_never_produces_positive_facts(raw):
    with pytest.raises((ValueError, ValidationError)):
        live.parse_listeners(raw, "tcp", "net:[123]", BOOT)


def test_process_stat_parentheses_do_not_shift_start_tick():
    raw = b"42 (strange ) process) " + b" ".join([b"S"] + [b"0"] * 18 + [b"123"] + [b"0"] * 3)
    assert live.process_start(raw, 42) == 123
    with pytest.raises(ValueError):
        live.process_start(raw, 43)


@pytest.mark.parametrize("failure", [PermissionError, FileNotFoundError])
def test_kernel_access_failures_remain_receipts(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(live, "kernel_bytes", fail)
    receipt = collect(manifest("LINUX_PROCESS", "linux-proc://self/process")).receipts[0]
    assert receipt.status == ("DENIED" if failure is PermissionError else "UNAVAILABLE")
    assert not receipt.facts and receipt.content_sha256 is None


def test_pid_reuse_is_detected_not_merged(monkeypatch):
    starts = iter([12, 13])
    monkeypatch.setattr(live, "process_start", lambda *args: next(starts))
    receipt = collect(manifest("LINUX_PROCESS", "linux-proc://self/process")).receipts[0]
    assert receipt.status == "INVALID" and receipt.reason == "INPUT_CHANGED" and not receipt.facts


def test_changed_socket_table_is_rejected(monkeypatch):
    original = live.Reader.read
    reads = 0

    def read(self, path, magic=0x9FA0):
        nonlocal reads
        if path.endswith("/net/tcp"):
            reads += 1
            return self.add(table(inode=reads))
        return original(self, path, magic)

    monkeypatch.setattr(live.Reader, "read", read)
    receipt = collect(manifest("LINUX_LISTENERS", "linux-sockets://self/tcp")).receipts[0]
    assert receipt.reason == "INPUT_CHANGED" and not receipt.facts


def test_source_and_projection_bytes_share_existing_hard_budgets():
    snapshot = collect(manifest("LINUX_PROCESS", "linux-proc://self/process", max_file_bytes=10, max_total_bytes=10))
    assert snapshot.receipts[0].status == "BUDGET_EXCEEDED" and snapshot.receipts[0].byte_count <= 10
    assert not snapshot.receipts[0].facts


@pytest.mark.parametrize(
    "raw",
    [b"LoadState=loaded\nActiveState=active\nMainPID=99\n", b"LoadState=loaded\nActiveState=inactive\nMainPID=0\n"],
)
def test_systemd_parser_reports_state_not_config_or_crypto(raw):
    fact = live.parse_service(raw, "approved.service")[0]
    assert fact.service_name == "approved.service" and fact.service_state in {"active", "inactive"}
    assert fact.algorithm == "UNKNOWN"


@pytest.mark.parametrize(
    "raw",
    [
        b"LoadState=not-found\nActiveState=inactive\nMainPID=0\n",
        b"LoadState=loaded\nActiveState=active\nActiveState=failed\nMainPID=1\n",
        b"LoadState=loaded\nActiveState=invented\nMainPID=1\n",
        b"LoadState=loaded\nActiveState=active\nMainPID=-1\n",
    ],
)
def test_service_unknown_malformed_or_duplicate_status_is_not_positive(raw):
    with pytest.raises((ValueError, live.ProbeError)):
        live.parse_service(raw, "approved.service")


def test_runtime_fact_cannot_be_promoted_or_crossed_into_other_domains():
    fact = live.parse_listeners(table(), "tcp", "net:[123]", BOOT)[0].model_dump(mode="json")
    for update in [
        {"runtime_use": "OBSERVED"},
        {"algorithm": "RSA"},
        {"pqc_assessment": "PASS"},
        {"pid": 42},
        {"interface": "WINDOWS_SCM"},
        {"identity_key": "invented"},
        {"mapping_basis": "SHARED_OBJECT_PATH_SUFFIX_ONLY"},
    ]:
        with pytest.raises(ValidationError):
            RuntimeFact.model_validate({**fact, **update})


def test_imported_runtime_facts_are_tied_to_input_family_and_interface_commitment():
    snapshot = collect(manifest("LINUX_PROCESS", f"linux-proc://{os.getpid()}/process")).model_dump(mode="json")
    assert snapshot["receipts"][0]["status"] == "PARSED"
    changed = dict(snapshot["manifest"])
    changed["inputs"] = [
        {"input_id": "approved", "kind": "LINUX_PROCESS", "path": f"linux-proc://{os.getpid() + 1}/process"}
    ]
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate({**snapshot, "manifest": changed, "manifest_sha256": digest(changed)})
    snapshot["receipts"][0]["facts"][0]["interface_sha256"] = None
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(snapshot)


def test_systemd_command_is_fixed_sanitized_read_only_and_never_shell(monkeypatch):
    original = live.subprocess.Popen
    seen = []

    def capture(command, **kwargs):
        seen.append((command, kwargs))
        return original(command, **kwargs)

    monkeypatch.setattr(live.subprocess, "Popen", capture)
    collect(manifest("LINUX_SERVICE", "systemd://cryptoscan-nonexistent-witness.service"))
    if not seen:
        pytest.skip("Trusted systemctl executable unavailable: positive systemd gate still open")
    command, kwargs = seen[0]
    assert command[-1] == "cryptoscan-nonexistent-witness.service" and "show" in command and "--" in command
    assert "shell" not in kwargs and kwargs["env"] == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "SYSTEMD_BUS_TIMEOUT": "2s",
    }
    assert kwargs["start_new_session"] and kwargs["pass_fds"]
    assert not any(word in command for word in ["start", "stop", "restart", "reload", "enable"])


def test_alpine_installed_profile_expected_truth_and_ignored_metadata(tmp_path):
    path = tmp_path / "installed"
    path.write_text("P:openssl\nV:3.3.2-r1\nA:x86_64\nT:secret description not exported\n\nP:musl\nV:1.2.5-r3\n")
    result = collect(manifest("APK_INSTALLED", str(path)))
    assert result.receipts[0].status == "PARSED"
    assert [(f.software_name, f.software_version) for f in result.receipts[0].facts] == [
        ("openssl", "3.3.2-r1"),
        ("musl", "1.2.5-r3"),
    ]
    assert "secret" not in result.model_dump_json()


@pytest.mark.parametrize("text", ["", "P:openssl\n", "P:a\nP:b\nV:1\n", "P:a\nV:1\n\nP:a\nV:2\n", "P:$(id)\nV:1\n"])
def test_invalid_alpine_database_never_executes_or_claims_missing_packages(tmp_path, text):
    path = tmp_path / "installed"
    path.write_text(text)
    receipt = collect(manifest("APK_INSTALLED", str(path))).receipts[0]
    assert receipt.status == "INVALID" and not receipt.facts


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Native Linux only")
def test_native_explicit_cpu_topology_is_hardware_metadata_not_tpm_or_hsm_use():
    snapshot = collect(manifest("LINUX_HARDWARE", "linux-hardware://cpu0"))
    receipt = snapshot.receipts[0]
    assert receipt.status == "PARSED", receipt
    fact = receipt.facts[0]
    assert fact.hardware_type == "CPU_TOPOLOGY" and fact.cpu_index == 0 and fact.core_id >= 0 and fact.package_id >= 0
    assert fact.operation_use == "UNKNOWN" and not fact.capabilities_observed and domains(fact) == ["HBOM", "TechBOM"]
    HostSnapshot.model_validate(snapshot.model_dump(mode="json"))


def test_systemd_timeout_and_oversize_cleanup_leave_no_child(monkeypatch):
    original = live.subprocess.Popen
    children = []

    def spawn(command, **kwargs):
        proc = original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(proc)
        return proc

    monkeypatch.setattr(live.subprocess, "Popen", spawn)
    receipt = collect(manifest("LINUX_SERVICE", "systemd://approved.service")).receipts[0]
    assert receipt.status == "UNAVAILABLE" and children and all(p.poll() is not None for p in children)

    def oversized(command, **kwargs):
        proc = original([sys.executable, "-c", 'import os; os.write(1,b"x"*8192)'], **kwargs)
        children.append(proc)
        return proc

    monkeypatch.setattr(live.subprocess, "Popen", oversized)
    receipt = collect(
        manifest("LINUX_SERVICE", "systemd://approved.service", max_file_bytes=100, max_total_bytes=100)
    ).receipts[0]
    assert receipt.status == "BUDGET_EXCEEDED" and receipt.byte_count <= 100
    assert all(p.poll() is not None for p in children)


def test_interface_unavailable_reason_survives_flat_evidence_reference():
    from shared_models.host_collection import snapshot_findings, HostReceipt

    approved = manifest("LINUX_SERVICE", "systemd://approved.service")
    now = datetime.now(timezone.utc)
    snapshot = HostSnapshot(
        manifest=approved,
        manifest_sha256=digest(approved),
        started_at=now,
        finished_at=now,
        execution_platform="linux",
        receipts=[HostReceipt(input_id="approved", status="UNAVAILABLE", reason="INTERFACE_UNAVAILABLE")],
    )
    findings = snapshot_findings(snapshot, "12345678-1234-1234-1234-123456789abc", "system-a")
    assert findings and "INTERFACE_UNAVAILABLE" in str(findings)
