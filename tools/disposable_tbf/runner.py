"""Fixed TCG invocation: no NIC, disks, mounts, monitor, host ports or privileged fallback."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from tools.disposable_tbf.build import HERE, sha
from tools.disposable_tbf.contracts import Scope, GuestCapture, RunReceipt, report

MAX_SERIAL = 131072


def canonical(value):
    data = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def finite(_):
        raise ValueError("nonfinite JSON")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite)


def parent_context():
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
        "mount_namespace_inode": os.stat("/proc/self/ns/mnt").st_ino,
    }


def ordinary_parent():
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64" or os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("ordinary-user x86_64 Linux parent required")
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.split(":", 1)[0] in ("CapInh", "CapPrm", "CapEff", "CapAmb") and int(line.split()[1], 16):
            raise ValueError("capability-bearing parent refused")


def verify_bundle(bundle, expected):
    bundle = bundle.resolve(strict=True)
    manifest_path = bundle / "bundle.json"
    if manifest_path.stat().st_size > 262144 or manifest_path.is_symlink() or sha(manifest_path) != expected:
        raise ValueError("bundle commitment mismatch")
    manifest = strict_json(manifest_path.read_bytes())
    if (
        manifest.get("schema_version") != "cryptoscan.disposable-tbf-bundle/v1"
        or manifest.get("profile") != "DISKLESS_TCG_NO_NIC_V1"
        or manifest.get("assets_lock_sha256") != sha(HERE / "assets.lock.json")
        or manifest.get("guest_source_sha256") != sha(HERE / "guest.py")
        or manifest.get("probe_source_sha256") != sha(HERE / "probe.c")
        or manifest.get("launcher_source_sha256") != sha(HERE / "sandbox.c")
        or manifest.get("builder_source_sha256") != sha(HERE / "build.py")
        or manifest.get("kernel_profile_sha256") != sha(HERE / "kernel.config")
    ):
        raise ValueError("bundle is not the reviewed local fixture profile")
    records = manifest.get("files")
    if not isinstance(records, list) or not 5 <= len(records) <= 300:
        raise ValueError("bundle file budget")
    names = set()
    for entry in records:
        path = Path(entry["path"])
        if path.is_absolute() or ".." in path.parts or str(path) != entry["path"] or str(path) in names:
            raise ValueError("unsafe or duplicate bundle path")
        names.add(str(path))
        source = bundle / path
        if (
            source.is_symlink()
            or not source.is_file()
            or not source.resolve().is_relative_to(bundle)
            or source.stat().st_size != entry["bytes"]
            or source.stat().st_size > 134217728
            or sha(source) != entry["sha256"]
        ):
            raise ValueError("bundle input changed")
    actual = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle symlink refused")
        if path.is_file() and path != manifest_path:
            actual.add(str(path.relative_to(bundle)))
    required = {"kernel", "kernel.config", "initramfs.cpio.gz", "emulator/libc.so", "emulator/qemu", "launcher"}
    if actual != names or not required <= names:
        raise ValueError("exact boot/runtime file closure required")
    config = (bundle / "kernel.config").read_text().splitlines()
    if "CONFIG_NET_SCH_TBF=y" not in config or "CONFIG_MODULES=y" in config:
        raise ValueError("built-in TBF/module-free profile required")
    return bundle


def argv(bundle, scope):
    # The pinned C launcher owns every QEMU flag and enforces Landlock+seccomp before exec.
    return [str(bundle / "launcher"), str(bundle), scope.nonce]


def bounded_vm(args, timeout=180):
    process = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        start_new_session=True,
        close_fds=True,
    )
    raw = bytearray()
    failure = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "VM_TIMEOUT"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(raw) + len(chunk) > MAX_SERIAL:
                    failure = "VM_SERIAL_BUDGET"
                    break
                raw.extend(chunk)
            if failure:
                break
        if failure is None:
            try:
                if process.wait(timeout=max(0.01, deadline - time.monotonic())):
                    failure = "VM_EXIT_FAILURE"
            except subprocess.TimeoutExpired:
                failure = "VM_TIMEOUT"
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
    return bytes(raw), failure


def parse_capture(raw, nonce):
    lines = [
        line[len(b"CRYPTOSCAN_TBF_RESULT=") :]
        for line in raw.splitlines()
        if line.startswith(b"CRYPTOSCAN_TBF_RESULT=")
    ]
    if (
        len(lines) != 1
        or b"CRYPTOSCAN_TBF_FAILURE=" in raw
        or raw.splitlines().count(b"CRYPTOSCAN_TBF_SANDBOX=LANDLOCK_SECCOMP_ACTIVE") != 1
    ):
        raise ValueError("one successful guest frame required")
    value = GuestCapture.model_validate(strict_json(lines[0]))
    if value.nonce != nonce:
        raise ValueError("guest scope nonce mismatch")
    return value


def qualify(bundle, scope, expected_scope, output):
    ordinary_parent()
    scope = Scope.model_validate(scope.model_dump())
    now = datetime.now(timezone.utc)
    if digest(scope) != expected_scope or not scope.issued_at <= now or (scope.expires_at - now).total_seconds() < 180:
        raise ValueError("current exact scope with full bounded execution window required")
    bundle = verify_bundle(bundle, scope.bundle_sha256)
    if output.resolve().is_relative_to(bundle):
        raise ValueError("output must be outside the sealed bundle")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    before = parent_context()
    start = time.monotonic()
    raw, failure = bounded_vm(argv(bundle, scope))
    wall = time.monotonic() - start
    result = {
        "schema_version": "cryptoscan.disposable-tbf-run/v1",
        "scope": scope.model_dump(mode="json"),
        "scope_sha256": digest(scope),
        "serial_sha256": hashlib.sha256(raw).hexdigest(),
        "bundle_sha256": scope.bundle_sha256,
        "host_wall_seconds": wall,
        "parent_before": before,
        "parent_after": parent_context(),
        "guest": None,
        "report": None,
        "failure": failure,
        "production_execution_qualified": False,
    }
    if failure is None:
        try:
            value = parse_capture(raw, scope.nonce)
            result["guest"] = value.model_dump(mode="json")
            result["report"] = report(value)
            minimum = (
                sum(
                    s.elapsed_ns / 1e9 + 1
                    for s in [value.baseline, *(t.measurement for t in value.caps), value.restored]
                )
                - 2
            )
            if wall < minimum:
                result["failure"] = "GUEST_AND_HOST_TIMING_INCONSISTENT"
        except (ValueError, KeyError, TypeError, RecursionError):
            result["failure"] = "GUEST_CAPTURE_INVALID"
    if result["parent_before"] != result["parent_after"]:
        result["failure"] = "PARENT_CONTEXT_CHANGED"
    if datetime.now(timezone.utc) >= scope.expires_at:
        result["failure"] = "SCOPE_EXPIRED_DURING_EXECUTION"
    try:
        verify_bundle(bundle, scope.bundle_sha256)
    except (OSError, ValueError, KeyError, TypeError):
        result["failure"] = "BOOT_INPUT_CHANGED_DURING_EXECUTION"
    result["verdict"] = (
        "VERIFIED_IN_DISPOSABLE_VM"
        if result["failure"] is None and result["report"] and result["report"]["verdict"] == "VERIFIED_IN_DISPOSABLE_VM"
        else "INCONCLUSIVE_OR_FAILED"
    )
    result = RunReceipt.model_validate_json(json.dumps(result)).model_dump(mode="json")
    for name, contents in (
        ("scope.json", scope.model_dump_json(indent=2).encode() + b"\n"),
        ("serial.log", raw),
        ("result.json", json.dumps(result, sort_keys=True, indent=2).encode() + b"\n"),
    ):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
    return result
