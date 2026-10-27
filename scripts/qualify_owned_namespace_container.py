#!/usr/bin/env python3
"""Real owned rootless namespace-container fixture. NOT Docker/Windows/production qualification."""

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import sys
import tarfile
from _bootstrap import bootstrap

bootstrap()
from shared_models.tpm_quote_verification import canonical, sha

PROBE = Path(__file__).parent / "fixtures/container_namespace_probe.c"
DB = b"Package: owned-namespace-probe\nStatus: install ok installed\nVersion: 1\n\n"
NAMES = ("user", "mnt", "pid", "net", "ipc", "uts")


def fixture_plan():
    return {
        "schema_version": "cryptoscan.owned-namespace-container-plan/v1",
        "scope": "ONLY_NEW_DISPOSABLE_OWNED_ROOTFS_NO_CUSTOMER_TARGET",
        "probe_source_sha256": hashlib.sha256(PROBE.read_bytes()).hexdigest(),
        "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "expected_database_sha256": hashlib.sha256(DB).hexdigest(),
        "expected_package": ["owned-namespace-probe", "1"],
        "required_namespaces": list(NAMES),
        "rootfs_readonly": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "memory_bytes": 134217728,
        "max_file_descriptors": 32,
        "output_bytes": 65536,
        "cpu_seconds": 2,
        "wall_seconds": 3,
        "expected_cancellation": "SIGKILL_OWNED_NAMESPACE_INIT_ONLY",
    }


def image_snapshot(root, binary):
    from inventory.collection import OfflineContainerCollector
    from shared_models.host_collection import HostManifest, HostInput
    from shared_models.collection import TargetSpec

    root.mkdir()
    blobs = root / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(data):
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return {"digest": "sha256:" + digest, "size": len(data)}

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [("probe", binary), ("var/lib/dpkg/status", DB)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o555 if name == "probe" else 0o444
            tar.addfile(info, io.BytesIO(data))
    layer = out.getvalue()
    desc = blob(layer)
    config = blob(
        canonical(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {},
                "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
            }
        )
    )
    config["mediaType"] = "application/vnd.oci.image.config.v1+json"
    desc["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
    manifest = blob(
        canonical(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": config,
                "layers": [desc],
            }
        )
    )
    manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    manifest["platform"] = {"os": "linux", "architecture": "amd64"}
    (root / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
    (root / "index.json").write_bytes(canonical({"schemaVersion": 2, "manifests": [manifest]}))
    now = datetime.now(timezone.utc)
    scope = HostManifest(
        approval_reference="owned-namespace-fixture/predefined-only",
        host_id="owned-namespace-fixture",
        environment="test",
        platform="linux",
        expires_at=now + timedelta(minutes=2),
        inputs=[
            HostInput(
                input_id="image",
                kind="OCI_IMAGE_CONTENT",
                path=f"oci-content://local/linux/amd64/manifest/sha256/{manifest['digest'][7:]}/root{root}",
            )
        ],
    )
    # Same explicit operator-owned candidate wrapper; no server admission.
    target = TargetSpec(
        target_key="owned-namespace-image",
        system_id="owned-fixture",
        owner="owned-agent",
        address="owned-namespace-fixture",
        environment="test",
        collection_method="container",
        not_before=now - timedelta(seconds=1),
        allowed_operations=["READ_APPROVED_METADATA"],
        manifest=scope,
    )
    snapshot = OfflineContainerCollector().collect(target)
    if snapshot.receipts[0].status != "PARSED":
        raise ValueError("Owned image did not pass product content collection")
    fact = snapshot.receipts[0].facts[0]
    if [(p.name, p.version) for p in fact.packages] != [("owned-namespace-probe", "1")]:
        raise ValueError("Image truth mismatch")
    return snapshot, fact


def run_owned(approved_plan_sha256):
    plan = fixture_plan()
    if sha(plan) != approved_plan_sha256:
        raise ValueError("Fixture source/plan changed")
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise ValueError("Ordinary-user x86_64 Linux required")
    for tool in ["gcc", "unshare", "mount"]:
        if not shutil.which(tool):
            raise ValueError("Required local tool absent")
    host_ns = {name: os.stat("/proc/self/ns/" + name).st_ino for name in NAMES}
    with tempfile.TemporaryDirectory(prefix="cryptoscan-owned-container-", dir=Path.home()) as directory:
        work = Path(directory)
        root = work / "root"
        root.mkdir(mode=0o700)
        (root / "proc").mkdir()
        (root / "var/lib/dpkg").mkdir(parents=True)
        sentinel = work / "outside-sentinel"
        sentinel.write_text("owned-only-not-readable-inside-rootfs")
        source = work / "probe.c"
        source.write_bytes(PROBE.read_bytes())
        if hashlib.sha256(source.read_bytes()).hexdigest() != plan["probe_source_sha256"]:
            raise ValueError("Probe source changed")
        subprocess.run(
            [
                "gcc",
                "-static",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--build-id=none",
                str(source),
                "-o",
                str(root / "probe"),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        binary = (root / "probe").read_bytes()
        (root / "var/lib/dpkg/status").write_bytes(DB)
        snapshot, image = image_snapshot(work / "image", binary)
        command = [
            "unshare",
            "-Urmpnifu",
            "--mount-proc=" + str(root / "proc"),
            "/bin/sh",
            "-c",
            'mount --rbind "$1" "$1" && mount -o remount,bind,ro "$1" && exec /usr/sbin/chroot "$1" /probe "$2" "$3"',
            "owned-namespace",
            str(root),
            str(sentinel),
        ]

        def execute(hold):
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(
                    [*command, "hold" if hold else ""],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=errors,
                    start_new_session=True,
                )
                cancelled = False
                child_pids = []
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
                    child_pids = [int(p) for p in children.read_text().split()]
                    if not hold or not child_pids:
                        raise ValueError("Unexpected fixture timeout")
                    for pid in child_pids:
                        # Pin the process before rechecking ancestry: never signal a recycled PID.
                        descriptor = os.pidfd_open(pid)
                        try:
                            if str(pid) not in children.read_text().split():
                                raise ValueError("Owned child changed")
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        finally:
                            os.close(descriptor)
                    process.wait(timeout=2)
                    cancelled = True
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
                output.seek(0)
                data = output.read(65537)
                if len(data) > 65536 or (not hold and process.returncode != 0) or (hold and not cancelled):
                    raise ValueError("Native fixture failed or cancellation not exercised")
                result = json.loads(data)
                # Kernel observations must differ from the host, not invented namespace labels.
                if (
                    result["pid"] != 1
                    or any(result["namespaces"][n] == host_ns[n] for n in NAMES)
                    or result["executable_inode"] != (root / "probe").stat().st_ino
                    or bytes.fromhex(result["database_hex"]) != DB
                    or not all(
                        result[k] is True
                        for k in [
                            "outside_denied",
                            "readonly_root",
                            "socket_denied",
                            "mount_denied",
                            "memory_limit_exercised",
                            "fd_limit_exercised",
                            "effective_caps_zero",
                            "no_new_privileges",
                        ]
                    )
                ):
                    raise ValueError("Runtime isolation/rootfs/expected truth mismatch")
                if any(Path(f"/proc/{pid}").exists() for pid in child_pids):
                    raise ValueError("Owned child not reaped")
                return result, cancelled

        normal, _ = execute(False)
        held, cancelled = execute(True)
        result = {
            "schema_version": "cryptoscan.owned-namespace-container-result/v1",
            "plan_sha256": sha(plan),
            "plan": plan,
            "snapshot": snapshot.model_dump(mode="json"),
            "scope": plan["scope"],
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "actual_native_namespace_execution": True,
            "actual_image_package_records_matched": True,
            "snapshot_sha256": sha(snapshot),
            "image_manifest_sha256": image.image.manifest_sha256,
            "binary_sha256": hashlib.sha256(binary).hexdigest(),
            "normal_run": normal,
            "cancellation_run": held,
            "cancellation_exercised": cancelled,
            "runtime": "LINUX_UNSHARE_CHROOT_OWNED_FIXTURE_NOT_DOCKER",
            "source_basis": "LOCAL_ENGINEERING_OBSERVATION",
            "independent_expected_truth_reviewed": False,
            "docker_or_kubernetes_qualified": False,
            "windows_qualified": False,
            "customer_container_qualified": False,
            "production_execution_qualified": False,
        }
    result["owned_work_directory_removed"] = not work.exists()
    if not result["owned_work_directory_removed"]:
        raise ValueError("Cleanup failed")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--describe-plan", action="store_true")
    p.add_argument("--approved-plan-sha256")
    p.add_argument("--acknowledge-owned-container", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    try:
        if a.describe_plan:
            print(json.dumps({"plan": fixture_plan(), "plan_sha256": sha(fixture_plan())}, indent=2))
            return 0
        if not a.acknowledge_owned_container or not a.output or not a.approved_plan_sha256:
            raise ValueError("Explicit fixture acknowledgement and reviewed plan required")
        # Reserve output before even compiling or creating a namespace.
        with os.fdopen(os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
            result = run_owned(a.approved_plan_sha256)
            output.write(canonical(result))
            output.flush()
            os.fsync(output.fileno())
        return 0
    except Exception:
        print(
            "OWNED_CONTAINER_QUALIFICATION_REFUSED: unsupported runtime, scope, native control, truth or cleanup; never skip-to-PASS",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
