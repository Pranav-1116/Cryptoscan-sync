"""Synthetic negative contracts and actual local sandbox denials, not production acceptance."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import subprocess
import sys
import tarfile
import pytest
from tools.disposable_tbf import build, contracts as c, runner


ID = "11111111-1111-1111-1111-111111111111"


def scope():
    now = datetime.now(timezone.utc)
    return c.Scope(
        target_label="synthetic-test",
        nonce="a" * 64,
        bundle_sha256="b" * 64,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def measurement(mbps):
    packets = int(mbps * 4e6 / (8 * 1200))
    return dict(
        received_packets=packets,
        received_bytes=packets * 1200,
        elapsed_ns=4000000000,
        sent_packets_total=25000,
        attempted_packets_total=25000,
        send_backpressure=0,
        send_errors=0,
        receive_errors=0,
        invalid_packets=0,
        payload_bytes=1200,
        warmup_seconds=1,
    )


def capture():
    clean = {"kind": "noqueue", "handle": "0:", "root": True, "options": {}}
    caps = []
    for rate in (10, 5):
        initial = dict(
            kind="tbf", handle="7e01:", root=True, options={"rate": rate * 125000}, bytes=0, packets=0, overlimits=0
        )
        after = {**initial, "bytes": rate * 1000000, "packets": 10000, "overlimits": 10000}
        caps.append(
            dict(
                rate_mbps=rate,
                applied=initial,
                after_measurement=after,
                measurement=measurement(rate),
                restored_policy=deepcopy(clean),
            )
        )
    return c.GuestCapture(
        schema_version="cryptoscan.disposable-tbf-guest/v1",
        nonce="a" * 64,
        kernel_release="synthetic-fixture-not-a-native-run",
        interface="lo",
        baseline_policy=clean,
        baseline=measurement(40),
        caps=caps,
        restored=measurement(40),
        final_policy=deepcopy(clean),
        rollback_verified=True,
        guest_monotonic_finished_ns=25000000000,
    )


def test_received_payload_denominators_and_qualification_are_recomputed():
    value = capture()
    report = c.report(value)
    assert report["verdict"] == "VERIFIED_IN_DISPOSABLE_VM"
    assert report["baseline_payload_mbps"] == value.baseline.received_bytes * 8 / 4e6
    assert not report["production_execution_qualified"] and not report["real_host_change_authorized"]


@pytest.mark.parametrize(
    "mutation,blocker",
    [
        (lambda d: d.update(baseline=measurement(9)), "INSUFFICIENT_UNSHAPED_HEADROOM"),
        (lambda d: d.update(restored=measurement(10)), "POST_ROLLBACK_THROUGHPUT_NOT_RECOVERED"),
        (lambda d: d.update(rollback_verified=False), "FINAL_ROLLBACK_NOT_VERIFIED"),
        (lambda d: d["caps"][0].update(measurement=measurement(15)), "CAP_0_RECEIVED_PAYLOAD_OUTSIDE_PREDECLARED_BAND"),
        (
            lambda d: d["caps"][1]["after_measurement"].update(overlimits=0),
            "CAP_1_KERNEL_COUNTER_OVERLIMITS_NOT_ADVANCING",
        ),
        (lambda d: d["caps"][0]["after_measurement"].update(bytes=1), "CAP_0_KERNEL_BYTES_BELOW_RECEIVED_PAYLOAD"),
        (lambda d: d["caps"][0]["applied"].update(handle="9999:"), "CAP_0_READBACK_OR_STABILITY_FAILED"),
        (lambda d: d["caps"][0]["applied"].update(options=None), "CAP_0_READBACK_OR_STABILITY_FAILED"),
        (lambda d: d["caps"][0]["restored_policy"].update(kind="tbf"), "CAP_0_ROLLBACK_FAILED"),
        (lambda d: d["caps"].reverse(), "EXACT_ORDERED_RATE_DENOMINATOR_REQUIRED"),
    ],
)
def test_no_qualification_from_incomplete_or_conflicting_observations(mutation, blocker):
    data = capture().model_dump()
    mutation(data)
    result = c.report(c.GuestCapture.model_validate(data))
    assert result["verdict"] == "INCONCLUSIVE_OR_FAILED" and blocker in result["blockers"]


def test_expected_shaping_backpressure_is_not_hidden_or_a_fatal_error():
    data = capture().model_dump()
    m = data["caps"][0]["measurement"]
    m.update(send_backpressure=1000, attempted_packets_total=26000)
    assert c.report(c.GuestCapture.model_validate(data))["verdict"] == "VERIFIED_IN_DISPOSABLE_VM"
    m.update(send_errors=1, attempted_packets_total=26001)
    assert "SAMPLE_1_SOCKET_OR_PAYLOAD_ERRORS" in c.report(c.GuestCapture.model_validate(data))["blockers"]


def test_unshaped_backpressure_blocks_qualification():
    data = capture().model_dump()
    data["baseline"].update(send_backpressure=1, attempted_packets_total=25001)
    assert "UNSHAPED_SENDER_BACKPRESSURE" in c.report(c.GuestCapture.model_validate(data))["blockers"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("received_bytes", 1),
        ("attempted_packets_total", 1),
        ("received_packets", True),
        ("payload_bytes", 1400),
        ("elapsed_ns", 1),
    ],
)
def test_invalid_measurement_cannot_enter_a_report(field, value):
    data = measurement(40)
    data[field] = value
    with pytest.raises(ValueError):
        c.Measurement.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("expires_at", datetime.now(timezone.utc) + timedelta(hours=1)),
        ("issued_at", datetime.now()),
        ("authorizes_real_host_change", True),
        ("profile", "HOST_ETH0"),
    ],
)
def test_scope_never_becomes_host_authority(field, value):
    data = scope().model_dump()
    data[field] = value
    with pytest.raises(ValueError):
        c.Scope.model_validate(data)


@pytest.mark.parametrize("data", [b'{"x":1,"x":2}', b"NaN", b"Infinity"])
def test_duplicate_or_nonfinite_json_refused(data):
    with pytest.raises(ValueError):
        runner.strict_json(data)


def frame():
    return (
        b"CRYPTOSCAN_TBF_SANDBOX=LANDLOCK_SECCOMP_ACTIVE\nCRYPTOSCAN_TBF_RESULT="
        + capture().model_dump_json().encode()
        + b"\n"
    )


def test_frame_needs_sandbox_marker_exact_nonce_and_single_denominator():
    assert runner.parse_capture(frame(), "a" * 64) == capture()
    for raw, nonce in [
        (frame(), "b" * 64),
        (frame() + frame(), "a" * 64),
        (frame().split(b"\n", 1)[1], "a" * 64),
        (frame() + b"CRYPTOSCAN_TBF_FAILURE=x", "a" * 64),
    ]:
        with pytest.raises(ValueError):
            runner.parse_capture(raw, nonce)


def test_vm_deadline_output_budget_and_reaping():
    raw, failure = runner.bounded_vm([sys.executable, "-c", "print('x'*200000)"], timeout=2)
    assert failure == "VM_SERIAL_BUDGET" and len(raw) <= runner.MAX_SERIAL
    _, failure = runner.bounded_vm([sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.05)
    assert failure == "VM_TIMEOUT"


def test_parent_root_and_capability_refusal_before_exec(monkeypatch):
    monkeypatch.setattr(runner.os, "getuid", lambda: 0)
    with pytest.raises(ValueError):
        runner.ordinary_parent()


def bundle(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    for name in ("kernel", "kernel.config", "initramfs.cpio.gz", "emulator/libc.so", "emulator/qemu", "launcher"):
        p = root / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(b"fixture")
    (root / "kernel.config").write_text("CONFIG_NET_SCH_TBF=y\n")
    data = dict(
        schema_version="cryptoscan.disposable-tbf-bundle/v1",
        profile="DISKLESS_TCG_NO_NIC_V1",
        assets_lock_sha256=build.sha(build.HERE / "assets.lock.json"),
        guest_source_sha256=build.sha(build.HERE / "guest.py"),
        probe_source_sha256=build.sha(build.HERE / "probe.c"),
        launcher_source_sha256=build.sha(build.HERE / "sandbox.c"),
        builder_source_sha256=build.sha(build.HERE / "build.py"),
        kernel_profile_sha256=build.sha(build.HERE / "kernel.config"),
        files=[
            dict(path=str(p.relative_to(root)), sha256=build.sha(p), bytes=p.stat().st_size)
            for p in root.rglob("*")
            if p.is_file()
        ],
    )
    (root / "bundle.json").write_text(json.dumps(data))
    return root, build.sha(root / "bundle.json")


@pytest.mark.parametrize("change", ["bytes", "extra", "symlink", "manifest", "traversal"])
def test_exact_boot_bundle_closure(tmp_path, change):
    root, sha = bundle(tmp_path)
    assert runner.verify_bundle(root, sha) == root
    if change == "bytes":
        (root / "kernel").write_bytes(b"changed")
    if change == "extra":
        (root / "unlisted").write_bytes(b"unlisted")
    if change == "symlink":
        (root / "alias").symlink_to(root / "kernel")
    if change == "manifest":
        (root / "bundle.json").write_text("{}")
    if change == "traversal":
        data = json.loads((root / "bundle.json").read_text())
        data["files"][0]["path"] = "../outside"
        (root / "bundle.json").write_text(json.dumps(data))
        sha = build.sha(root / "bundle.json")
    with pytest.raises(ValueError):
        runner.verify_bundle(root, sha)


@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink", "device", "hardlink"])
def test_source_archive_cannot_escape_owned_work(tmp_path, kind):
    path = tmp_path / "malicious.tar.gz"
    member = tarfile.TarInfo("/absolute" if kind == "absolute" else "../outside" if kind == "traversal" else "entry")
    if kind == "symlink":
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
    if kind == "device":
        member.type = tarfile.CHRTYPE
    if kind == "hardlink":
        member.type = tarfile.LNKTYPE
        member.linkname = "/etc/passwd"
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(b""))
    with pytest.raises(ValueError):
        build.unpack(path, tmp_path / "work")


def test_initramfs_is_deterministic_without_host_device_nodes(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "dev").mkdir()
    (root / "fixture").write_text("fixture")
    a = tmp_path / "a.gz"
    b = tmp_path / "b.gz"
    build.initramfs(root, a)
    build.initramfs(root, b)
    assert a.read_bytes() == b.read_bytes() and not (root / "dev/console").exists()


def test_c_probe_refuses_host_execution_before_sockets(tmp_path):
    binary = tmp_path / "probe"
    subprocess.run(
        [
            "/usr/bin/gcc",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(build.HERE / "probe.c"),
            "-o",
            str(binary),
        ],
        check=True,
    )
    result = subprocess.run([str(binary), "a" * 32], capture_output=True, timeout=5)
    assert result.returncode == 64 and not result.stdout


def test_real_landlock_and_seccomp_deny_host_effects(tmp_path):
    source = tmp_path / "deny.c"
    binary = tmp_path / "deny"
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source.write_text(
        "#define main fixture_main\n#include "
        + json.dumps(str(build.HERE / "sandbox.c"))
        + """\n#undef main
#include <sys/socket.h>
int main(int argc,char **argv) {
 if(argc!=3 || restrict_fs(argv[1]) || restrict_syscalls()) return 77;
 if(open("/etc/passwd",O_RDONLY)>=0) return 1;
 if(open(argv[2],O_WRONLY|O_TRUNC)>=0) return 2;
 if(truncate(argv[2],0)>=0) return 7;
 if(chmod(argv[2],0777)>=0) return 8;
 if(utimensat(AT_FDCWD,argv[2],NULL,0)>=0) return 9;
 if(syscall(SYS_setxattr,argv[2],"user.fixture","x",1,0)>=0) return 10;
 if(socket(AF_INET,SOCK_DGRAM,0)>=0) return 3;
 if(fork()>=0) return 4;
 if(syscall(SYS_unshare,CLONE_NEWNET)>=0) return 5;
 char *args[]={"/bin/true",NULL};execve("/bin/true",args,NULL);
 if(errno!=EACCES) return 6;
 return 0;
}
"""
    )
    subprocess.run(
        ["/usr/bin/gcc", "-O2", "-static", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True
    )
    result = subprocess.run([str(binary), str(allowed), str(outside)], capture_output=True, timeout=5)
    if result.returncode == 77:
        pytest.skip("Landlock ABI2/seccomp unavailable on this test host")
    assert result.returncode == 0, result.stderr
    assert outside.read_text() == "preserve"


def test_receipt_cannot_promote_missing_measurements():
    s = scope()
    context = dict(boot_id=ID, network_namespace_inode=1, mount_namespace_inode=2)
    value = dict(
        schema_version="cryptoscan.disposable-tbf-run/v1",
        scope=s.model_dump(mode="json"),
        scope_sha256=runner.digest(s),
        bundle_sha256=s.bundle_sha256,
        serial_sha256="c" * 64,
        host_wall_seconds=25.0,
        parent_before=context,
        parent_after=context,
        guest=None,
        report=None,
        failure=None,
        production_execution_qualified=False,
        verdict="VERIFIED_IN_DISPOSABLE_VM",
    )
    with pytest.raises(ValueError):
        c.RunReceipt.model_validate_json(json.dumps(value))


def test_kernel_packet_denominator_cannot_be_smaller_than_received():
    value = capture().model_dump()
    value["caps"][0]["after_measurement"]["packets"] = 1
    assert "CAP_0_KERNEL_PACKETS_BELOW_RECEIVED_PAYLOAD" in c.report(c.GuestCapture.model_validate(value))["blockers"]


def test_impossible_guest_clock_timeline_does_not_qualify():
    value = capture().model_dump()
    value["guest_monotonic_finished_ns"] = 1
    assert "GUEST_MONOTONIC_TIMELINE_INCONSISTENT" in c.report(c.GuestCapture.model_validate(value))["blockers"]


def test_private_runtime_signal_patch_is_exact_and_fails_closed(tmp_path):
    names = ("src/thread/pthread_kill.c", "src/thread/pthread_cancel.c", "src/thread/synccall.c", "src/signal/raise.c")
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("__syscall(SYS_tkill, tid, sig);")
    build.harden_musl_signals(tmp_path)
    for name in names:
        assert "SYS_tgkill, __syscall(SYS_getpid)," in (tmp_path / name).read_text()
    with pytest.raises(ValueError):
        build.harden_musl_signals(tmp_path)


@pytest.mark.parametrize("change", ["scope_hash", "bundle_hash", "report", "timing", "context", "production"])
def test_receipt_recomputes_scope_context_timing_report_and_qualification(change):
    s = scope()
    value = capture()
    context = dict(boot_id=ID, network_namespace_inode=1, mount_namespace_inode=2)
    data = dict(
        schema_version="cryptoscan.disposable-tbf-run/v1",
        scope=s.model_dump(mode="json"),
        scope_sha256=runner.digest(s),
        bundle_sha256=s.bundle_sha256,
        serial_sha256="c" * 64,
        host_wall_seconds=25.0,
        parent_before=context,
        parent_after=deepcopy(context),
        guest=value.model_dump(mode="json"),
        report=c.report(value),
        failure=None,
        production_execution_qualified=False,
        verdict="VERIFIED_IN_DISPOSABLE_VM",
    )
    assert c.RunReceipt.model_validate_json(json.dumps(data)).verdict == "VERIFIED_IN_DISPOSABLE_VM"
    if change == "scope_hash":
        data["scope_sha256"] = "d" * 64
    if change == "bundle_hash":
        data["bundle_sha256"] = "d" * 64
    if change == "report":
        data["report"]["baseline_payload_mbps"] = 100
    if change == "timing":
        data["host_wall_seconds"] = 1.0
    if change == "context":
        data["parent_after"]["network_namespace_inode"] = 7
    if change == "production":
        data["production_execution_qualified"] = True
    with pytest.raises(ValueError):
        c.RunReceipt.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("name,model", [("scope", c.Scope), ("guest", c.GuestCapture), ("run", c.RunReceipt)])
def test_committed_json_schema_matches_the_strict_contract(name, model):
    from jsonschema import Draft202012Validator

    schema = json.loads((build.HERE / "schemas" / f"{name}-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    assert {k: v for k, v in schema.items() if k != "$schema"} == model.model_json_schema()


def test_capability_bearing_parent_is_refused(monkeypatch):
    monkeypatch.setattr(runner.os, "getuid", lambda: 1001)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(type(build.HERE), "read_text", lambda *a, **kw: "CapEff:\t0000000000000001\n")
    with pytest.raises(ValueError, match="capability-bearing"):
        runner.ordinary_parent()
