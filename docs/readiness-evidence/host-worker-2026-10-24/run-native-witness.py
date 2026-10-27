"""Actual ordinary-user interfaces; no external private keys or bank acceptance."""

import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from services.inventory.tests.test_collection_linux import spec
from inventory.isolation import collect_isolated
from shared_models.host_collection import HostInput


def main():
    with tempfile.TemporaryDirectory(prefix="cryptoscan-worker-native-") as tmp:
        tmp = Path(tmp)
        target = spec(tmp, b"ID=debian\n")
        inputs = [
            HostInput(input_id="process", kind="LINUX_PROCESS", path="linux-proc://self/process"),
            HostInput(input_id="maps", kind="LINUX_PROCESS_MAPS", path="linux-proc://self/maps"),
            HostInput(input_id="cpu", kind="LINUX_HARDWARE", path="linux-hardware://cpu0"),
            HostInput(input_id="tcp", kind="LINUX_LISTENERS", path="linux-sockets://self/tcp"),
        ]
        target = target.model_copy(update={"manifest": target.manifest.model_copy(update={"inputs": inputs})})
        with socket.socket() as owned:
            owned.bind(("127.0.0.1", 0))
            owned.listen(1)
            snapshot, isolation = collect_isolated(target)
            assert all(r.status == "PARSED" and r.byte_count > 0 and r.content_sha256 for r in snapshot.receipts)
            assert any(f.port == owned.getsockname()[1] for f in snapshot.receipts[-1].facts)
        # Native parent-death kernel witness. A dedicated supervisor's fake
        # sleeping stage tests launcher cleanup only, not native observations.
        # Subreaper lets this owned probe reap the orphan instead of PID 1.
        libc = ctypes.CDLL(None)
        assert libc.prctl(36, 1, 0, 0, 0) == 0
        stage = tmp / "death-stage"
        (stage / "scripts").mkdir(parents=True)
        ready = tmp / "ready"
        (stage / "scripts/_isolated_host_stage.py").write_text(
            f"import os,time,json\nfrom pathlib import Path\nr=Path({str(ready)!r})\np=r.with_suffix('.tmp')\np.write_text(json.dumps(dict(pid=os.getpid(),cwd=os.getcwd())))\nos.rename(p,r)\nprint('READY',flush=True)\ntime.sleep(60)\n"
        )
        parent_code = f"""import sys
sys.path.insert(0,{str(ROOT / "scripts")!r})
from _bootstrap import bootstrap
bootstrap()
from shared_models.collection import TargetSpec
from inventory.isolation import collect_isolated
import time
collect_isolated(TargetSpec.model_validate_json({spec(tmp, b"ID=debian").model_dump_json()!r}),timeout=30,stage_root={str(stage)!r},checkpoint=lambda:None)
"""
        # Fake-stage READY goes through the collector's result pipe; observing
        # the pid file is bounded here using a separate deadline-owning helper.
        parent = subprocess.Popen(
            [sys.executable, "-c", parent_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        import time

        try:
            deadline = time.monotonic() + 5
            while not ready.exists():
                if time.monotonic() > deadline:
                    raise AssertionError("Parent-death witness did not start")
                time.sleep(0.02)
            record = json.loads(ready.read_text())
            child = record["pid"]
            child_cwd = Path(record["cwd"])
            parent.kill()
            parent.wait(timeout=5)
            _, status = os.waitpid(child, 0)
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            assert (
                child_cwd.parent == Path(tempfile.gettempdir())
                and child_cwd.name.startswith("cryptoscan-isolated-")
                and not child_cwd.is_symlink()
            )
            child_cwd.rmdir()  # only this recorded, empty, owned crash leftover
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait()
        from inventory.host import collect

        gaps = target.model_copy(
            update={
                "manifest": target.manifest.model_copy(
                    update={
                        "inputs": [
                            HostInput(input_id="systemd", kind="LINUX_SERVICE", path="systemd://dbus.service"),
                            HostInput(input_id="dmi", kind="LINUX_HARDWARE", path="linux-hardware://dmi"),
                            HostInput(input_id="tpm0", kind="LINUX_HARDWARE", path="linux-hardware://tpm0"),
                        ]
                    }
                )
            }
        )
        diagnostics = collect(gaps.manifest)
        result = {
            "standalone_native_diagnostic_not_worker_fallback": [
                {"input_id": r.input_id, "status": r.status, "reason": r.reason, "facts": len(r.facts)}
                for r in diagnostics.receipts
            ],
            "native_receipts": [
                {
                    "input_id": r.input_id,
                    "status": r.status,
                    "reason": r.reason,
                    "facts": len(r.facts),
                    "byte_count_positive": r.byte_count > 0,
                }
                for r in snapshot.receipts
            ],
            "owned_tcp_seen": True,
            "isolation": isolation,
            "supervisor_death_child_sigkill_and_reaped": True,
            "recorded_crash_cwd_removed_after_reap": True,
            "temporary_native_fixture_removed_on_exit": True,
            "host_attested": False,
            "systemd_dmi_tpm_positive_qualified": False,
            "windows_executed": False,
            "production_execution_qualified": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
