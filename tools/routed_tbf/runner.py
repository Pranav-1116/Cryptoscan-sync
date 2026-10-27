"""Bounded, non-root local adapter. No sockets or customer execution endpoint."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from tools.disposable_tbf.runner import ordinary_parent, parent_context, strict_json, canonical
from tools.disposable_tbf.build import sha
from tools.routed_tbf import build
from tools.routed_tbf.authority import verify
from tools.routed_tbf.report import Capture, report, GATES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_PATHS = [
    str(p.relative_to(ROOT))
    for p in sorted(HERE.iterdir())
    if p.suffix in (".py", ".c", ".json", ".config") and not p.name.startswith("test_")
]
SOURCE_PATHS += ["tools/disposable_tbf/" + name for name in ("build.py", "runner.py", "contracts.py")]
SOURCE_PATHS += ["scripts/qualify_routed_tbf.py"]


def source_bindings():
    return {p: sha(ROOT / p) for p in SOURCE_PATHS}


def verify_bundle(bundle, expected):
    bundle = Path(bundle).resolve(strict=True)
    p = bundle / "bundle.json"
    if p.is_symlink() or p.stat().st_size > 262144 or sha(p) != expected:
        raise ValueError("exact manifest commitment required")
    manifest = strict_json(p.read_bytes())
    if (
        manifest["profile"] != "DISKLESS_TCG_ROUTED_NETNS_V1"
        or manifest["routed_sources"] != {n: sha(HERE / n) for n in build.SOURCES}
        or manifest["reused_builder_sha256"] != sha(build.V1 / "build.py")
    ):
        raise ValueError("routed source profile changed")
    names = set()
    for record in manifest["files"]:
        rel = Path(record["path"])
        if rel.is_absolute() or ".." in rel.parts or str(rel) != record["path"] or str(rel) in names:
            raise ValueError("unsafe or duplicate bundle file")
        names.add(str(rel))
        f = bundle / rel
        if (
            f.is_symlink()
            or not f.is_file()
            or not f.resolve().is_relative_to(bundle)
            or not 0 <= f.stat().st_size == record["bytes"] <= 134217728
            or sha(f) != record["sha256"]
        ):
            raise ValueError("bundle file changed")
    actual = set()
    for f in bundle.rglob("*"):
        if f.is_symlink():
            raise ValueError("bundle symlink")
        if f.is_file() and f != p:
            actual.add(str(f.relative_to(bundle)))
    if (
        not 5 <= len(names) <= 300
        or actual != names
        or not {"kernel", "kernel.config", "initramfs.cpio.gz", "launcher", "emulator/libc.so", "emulator/qemu"}
        <= names
    ):
        raise ValueError("boot file closure")
    config = (bundle / "kernel.config").read_text().splitlines()
    for item in ("CONFIG_NET_NS=y", "CONFIG_VETH=y", "CONFIG_NET_SCH_TBF=y", "CONFIG_IP_MULTIPLE_TABLES=y"):
        if item not in config:
            raise ValueError("routed kernel required")
    if "CONFIG_MODULES=y" in config or "CONFIG_PCI=y" in config or "CONFIG_NETFILTER=y" in config:
        raise ValueError("module/PCI/firewall-free laboratory kernel required")
    return bundle


def bounded_vm(args, active, timeout=300):
    p = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        start_new_session=True,
        close_fds=True,
    )
    output, failure = bytearray(), None
    selector = selectors.DefaultSelector()
    start = time.monotonic()
    try:
        selector.register(p.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() - start >= timeout:
                failure = "VM_TIMEOUT"
                break
            if not active():
                failure = "LEASE_REVOKED_OR_EXPIRED_VM_TERMINATED"
                break
            for key, _ in selector.select(0.1):
                data = os.read(key.fd, 8192)
                if not data:
                    selector.unregister(key.fileobj)
                elif len(data) + len(output) > 524288:
                    failure = "VM_SERIAL_BUDGET"
                    break
                else:
                    output.extend(data)
            if failure:
                break
        if failure is None:
            try:
                if p.wait(timeout=max(0.01, timeout - (time.monotonic() - start))):
                    failure = "VM_EXIT_FAILURE"
            except subprocess.TimeoutExpired:
                failure = "VM_TIMEOUT"
    finally:
        selector.close()
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        p.stdout.close()
    return bytes(output), failure


def capture(raw, nonce):
    frames = [line.split(b"=", 1)[1] for line in raw.splitlines() if line.startswith(b"CRYPTOSCAN_ROUTED_RESULT=")]
    if (
        len(frames) != 1
        or b"CRYPTOSCAN_ROUTED_FAILURE=" in raw
        or raw.splitlines().count(b"CRYPTOSCAN_TBF_SANDBOX=LANDLOCK_SECCOMP_ACTIVE") != 1
    ):
        raise ValueError("one final successful guest capture and mandatory sandbox marker required")
    value = Capture.model_validate(strict_json(frames[0])).model_dump()
    if value["nonce"] != nonce:
        raise ValueError("guest nonce mismatch")
    return value


def parent_policy():
    p = subprocess.run(
        ["/usr/sbin/tc", "-j", "qdisc", "show"],
        check=True,
        capture_output=True,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if len(p.stdout) > 65536:
        raise ValueError("parent read-only policy budget")
    return strict_json(p.stdout)


def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)


def run(bundle, expected, authority, grant, tenant, device, output):
    ordinary_parent()
    bundle = verify_bundle(bundle, expected)
    p = grant["lease"]["payload"]
    if output.resolve().is_relative_to(bundle) or output.exists():
        raise ValueError("fresh evidence directory outside bundle required")
    bindings = source_bindings()
    proof = authority.redeem(grant, tenant, device, expected, sha(HERE / "acceptance.json"))
    output.mkdir(mode=0o700)
    receipt = {
        "version": "ROUTED_LAB_RECEIPT_V1",
        "grant": grant,
        "adapter_proof": proof,
        "sources": bindings,
        "acceptance": GATES,
        "parent_before": parent_context(),
        "parent_policy_before": parent_policy(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "guest": None,
        "report": None,
        "failure": None,
        "production_execution_qualified": False,
        "independent_review_complete": False,
        "physical_device_identity_verified": False,
    }
    start = time.monotonic()
    raw, receipt["failure"] = bounded_vm(
        [str(bundle / "launcher"), str(bundle), p["nonce"]], lambda: authority.active(p["id"])
    )
    receipt["wall_seconds"] = time.monotonic() - start
    receipt["serial_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt["parent_after"], receipt["parent_policy_after"] = parent_context(), parent_policy()
    if receipt["failure"] is None:
        try:
            receipt["guest"] = capture(raw, p["nonce"])
            receipt["report"] = report(receipt["guest"])
        except (ValueError, KeyError, TypeError):
            receipt["failure"] = "INVALID_GUEST_CAPTURE"
    if (
        receipt["parent_before"] != receipt["parent_after"]
        or receipt["parent_policy_before"] != receipt["parent_policy_after"]
    ):
        receipt["failure"] = "PARENT_CONTEXT_OR_POLICY_CHANGED"
    if not authority.active(p["id"]):
        receipt["failure"] = "LEASE_REVOKED_OR_EXPIRED_VM_TERMINATED"
    try:
        verify_bundle(bundle, expected)
        if source_bindings() != bindings:
            raise ValueError("source mutation")
    except (OSError, ValueError, KeyError):
        receipt["failure"] = "BOOT_OR_SOURCE_INPUT_CHANGED"
    receipt["verdict"] = (
        receipt["report"]["verdict"] if receipt["failure"] is None and receipt["report"] else "INCONCLUSIVE_OR_FAILED"
    )
    signed = authority.sign_receipt(receipt)
    exclusive(output / "serial.log", raw)
    exclusive(output / "result.json", json.dumps(signed, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")
    exclusive(output / "grant.json", canonical(grant) + b"\n")
    return signed


def verify_receipt(path, expected_sha256, trusted_adapter_public_key):
    if path.is_symlink() or path.stat().st_size > 1048576 or sha(path) != expected_sha256:
        raise ValueError("receipt byte commitment required")
    signed = strict_json(path.read_bytes())
    if signed["adapter_public_key"] != trusted_adapter_public_key:
        raise ValueError("unexpected enrolled adapter key")
    value = signed["payload"]
    verify(trusted_adapter_public_key, signed["adapter_signature"], value)
    raw = (path.parent / "serial.log").read_bytes()
    guest = capture(raw, value["grant"]["lease"]["payload"]["nonce"])
    if (
        hashlib.sha256(raw).hexdigest() != value["serial_sha256"]
        or guest != value["guest"]
        or report(guest) != value["report"]
        or value["sources"] != source_bindings()
        or value["acceptance"] != GATES
        or value["parent_before"] != value["parent_after"]
        or value["parent_policy_before"] != value["parent_policy_after"]
        or value["failure"] is not None
        or value["production_execution_qualified"] is not False
        or value["independent_review_complete"] is not False
        or value["physical_device_identity_verified"] is not False
        or value["wall_seconds"] < (guest["phases"][-1]["finished_ns"] - guest["phases"][0]["started_ns"]) / 1e9
        or value["wall_seconds"] > GATES["vm_deadline_seconds"] + 5
        or value["verdict"] != value["report"]["verdict"]
    ):
        raise ValueError("receipt/serial/report/source closure failed")
    if value["verdict"] == "INCONCLUSIVE_OR_FAILED":
        raise ValueError("retained run did not pass gates")
    return value["verdict"]
