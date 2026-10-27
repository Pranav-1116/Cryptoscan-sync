"""Real unprivileged Linux kernel policy witnesses, no mocked sandbox success."""

import json
from pathlib import Path
import subprocess
import sys
import pytest
from services.inventory.tests.test_collection_linux import spec
from inventory.isolation import collect_isolated, IsolationUnavailable
from shared_models.host_collection import HostInput


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux Landlock/seccomp witness")
def test_native_isolated_collection_has_same_metadata_and_no_fallback(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\nVERSION_ID=24.04\n")
    snapshot, report = collect_isolated(target)
    assert snapshot.receipts[0].status == "PARSED" and snapshot.receipts[0].facts[0].software_name == "ubuntu"
    assert report["network"] == "DENIED" and report["landlock_abi"] >= 1
    assert not snapshot.production_execution_qualified
    unsupported = target.model_copy(
        update={
            "manifest": target.manifest.model_copy(
                update={
                    "inputs": [HostInput(input_id="service", kind="LINUX_SERVICE", path="systemd://approved.service")]
                }
            )
        }
    )
    with pytest.raises(IsolationUnavailable):
        collect_isolated(unsupported)


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux Landlock/seccomp witness")
def test_native_policy_denies_unapproved_reads_mutations_network_exec_and_escape(tmp_path):
    approved = tmp_path / "approved"
    approved.write_bytes(b"public-metadata")
    secret = tmp_path / "unapproved"
    secret.write_bytes(b"not-in-scope")
    root = Path(__file__).resolve().parents[3]
    code = f"""
import sys,os,json,socket,ctypes
sys.path.insert(0,{str(root / "scripts")!r})
from _bootstrap import bootstrap
bootstrap()
from inventory.isolation import install
report=install([{str(approved)!r}])
results={{}}
def denied(name,fn):
 try:fn();results[name]=False
 except PermissionError:results[name]=True
fd=os.open({str(approved)!r},os.O_RDONLY);results['approved_read']=os.read(fd,100)==b'public-metadata';os.close(fd)
denied('unapproved_read',lambda:os.open({str(secret)!r},os.O_RDONLY))
denied('write_open',lambda:os.open({str(approved)!r},os.O_WRONLY))
denied('readonly_truncate',lambda:os.open({str(approved)!r},os.O_RDONLY|os.O_TRUNC))
denied('unlink',lambda:os.unlink({str(approved)!r}))
denied('socket',lambda:socket.socket())
denied('fork',lambda:os.fork())
denied('exec',lambda:os.execv('/bin/true',['true']))
libc=ctypes.CDLL(None,use_errno=True)
results['io_uring']=libc.syscall(425,1,0)==-1 and ctypes.get_errno()==1
results['cross_process_prlimit']=libc.syscall(302,os.getppid(),0,0,0)==-1 and ctypes.get_errno()==1
os.write(1,json.dumps(results).encode())
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, timeout=15, close_fds=True)
    assert result.returncode == 0, result.stderr
    assert all(json.loads(result.stdout).values()), result.stdout
    assert approved.read_bytes() == b"public-metadata" and secret.read_bytes() == b"not-in-scope"


def test_isolated_deadline_validation_before_process(tmp_path):
    target = spec(tmp_path, b"ID=ubuntu\n")
    for timeout in [0, 31, "15"]:
        with pytest.raises(ValueError):
            collect_isolated(target, timeout)


def test_parent_deadline_and_overflow_kill_and_reap(tmp_path, monkeypatch):
    target = spec(tmp_path, b"ID=ubuntu\n")
    original = subprocess.Popen
    children = []

    def sleep_child(command, **kwargs):
        child = original([sys.executable, "-c", "import time;time.sleep(30)"], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", sleep_child)
    with pytest.raises(IsolationUnavailable):
        collect_isolated(target, timeout=1)
    assert children and all(p.poll() is not None for p in children)

    def overflow(command, **kwargs):
        child = original([sys.executable, "-c", 'import os;os.write(1,b"x"*1500001)'], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", overflow)
    with pytest.raises(IsolationUnavailable):
        collect_isolated(target)
    assert all(p.poll() is not None for p in children)


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux runtime interfaces")
def test_isolated_runtime_actual_process_maps_cpu_and_owned_socket(tmp_path):
    import socket

    target = spec(tmp_path, b"ID=debian\n")
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
        snapshot, report = collect_isolated(target)
        assert [r.status for r in snapshot.receipts] == ["PARSED"] * 4
        assert any(f.port == owned.getsockname()[1] for f in snapshot.receipts[-1].facts)
        assert report["network"] == "DENIED" and not snapshot.host_identity_attested
        assert all(r.byte_count > 0 and r.content_sha256 for r in snapshot.receipts)


def test_checkpoint_refusal_kills_and_reaps_actual_child(tmp_path, monkeypatch):
    import subprocess
    from inventory import isolation

    target = spec(tmp_path, b"ID=debian\n")
    observed = []
    original = subprocess.Popen

    def spawned(*a, **kw):
        child = original(*a, **kw)
        observed.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", spawned)
    calls = []

    def checkpoint():
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("authority revoked")

    with pytest.raises(RuntimeError, match="authority revoked"):
        isolation.collect_isolated(target, checkpoint=checkpoint)
    assert observed and observed[0].poll() is not None and observed[0].stdout.closed


def test_pinned_network_capability_does_not_grant_broad_proc_reads(tmp_path):
    root = Path(__file__).resolve().parents[3]
    code = f"""
import sys,os
sys.path.insert(0,{str(root / "scripts")!r})
from _bootstrap import bootstrap
bootstrap()
from inventory.linux_runtime import pinned_network_tables,kernel_bytes
from inventory.isolation import install
with pinned_network_tables(['/proc/self/net/tcp']):
 install([],{{'/proc/self/net/tcp':0x9fa0}})
 assert kernel_bytes('/proc/self/net/tcp',1000000,0x9fa0)
 for path in ['/proc/self/environ','/proc/self/cmdline','/proc/self/net/udp','/proc/self/maps','/etc/passwd']:
  try:os.open(path,os.O_RDONLY)
  except PermissionError:pass
  else:raise AssertionError('broad source escape')
print('PINNED_SCOPE_OK')
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b"PINNED_SCOPE_OK"
