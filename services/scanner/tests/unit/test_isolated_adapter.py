"""Protocol and guard tests, not evidence of a running container boundary."""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner import isolated


@pytest.fixture(autouse=True)
def restore_logging():
    import structlog

    config = structlog.get_config().copy()
    yield
    structlog.configure(**config)


def _request():
    return {"schema": isolated.SCHEMA, "scan_id": "s1", "exclude_test_dirs": False, "timeout_s": 1,
            "source_marker": ".cryptoscan-scan-" + "a" * 32, "source_token": "a" * 64}


@pytest.mark.parametrize("change", [{"source_marker": "../../etc/passwd"}, {"source_token": "x"},
                                    {"scan_id": ""}, {"scan_id": "x" * 129}, {"timeout_s": True},
                                    {"timeout_s": float("nan")}, {"timeout_s": 3601}])
def test_invalid_requests_are_rejected(change):
    request = _request()
    request.update(change)
    with pytest.raises(ValueError):
        isolated.validate_request(request)


def test_fixed_input_and_resource_policy_are_used(monkeypatch):
    from scanner.core import sandbox
    from scanner.core.scanner import Scanner
    from scanner.models.scan_result import ScanResult

    observed = {}
    monkeypatch.setattr(isolated, "verify_runtime", lambda: {"mock_runtime": True})
    monkeypatch.setattr(isolated, "verify_source_types", lambda root: observed.update(input_root=root))
    monkeypatch.setattr(Path, "read_text", lambda _path, **_k: _request()["source_token"])
    monkeypatch.setattr(sandbox, "apply_child_limits", lambda **kwargs: observed.update(limits=kwargs))

    def scan(_self, **kwargs):
        observed.update(scan=kwargs)
        result = ScanResult(scan_id=kwargs["scan_id"])
        result.finalize()
        return result

    monkeypatch.setattr(Scanner, "scan", scan)
    response = isolated.scan_request(_request())
    assert observed["limits"] == {"install_seccomp": False}
    assert observed["scan"] == {"root_path": Path("/scan"), "scan_id": "s1", "target_location": "/scan"}
    assert response["result"]["status"] == "COMPLETED"


def test_wrong_daemon_mount_never_reaches_the_parser(monkeypatch):
    monkeypatch.setattr(isolated, "verify_runtime", lambda: {"mock_runtime": True})
    monkeypatch.setattr(Path, "read_text", lambda _path, **_k: "wrong checkout")
    with pytest.raises(RuntimeError, match="admitted checkout"):
        isolated.scan_request(_request())


@pytest.mark.parametrize("fault", [None, "uid", "caps", "privileges", "seccomp", "rootfs", "input", "network", "git-metadata"])
def test_runtime_check_fails_closed(monkeypatch, fault):
    monkeypatch.setattr(isolated.os.path, "lexists", lambda _path: fault == "git-metadata")
    monkeypatch.setattr(isolated.os, "access", lambda *_a: fault == "git-metadata")
    status = {"CapEff": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2"}
    if fault in ("caps", "privileges", "seccomp"):
        status[{"caps": "CapEff", "privileges": "NoNewPrivs", "seccomp": "Seccomp"}[fault]] = "0" if fault != "caps" else "1"
    monkeypatch.setattr(Path, "read_text", lambda _path: "\n".join(f"{key}:\t{value}" for key, value in status.items()))
    monkeypatch.setattr(isolated.os, "geteuid", lambda: 0 if fault == "uid" else 10001)
    monkeypatch.setattr(isolated.os, "listdir", lambda _path: ["lo", "eth0"] if fault == "network" else ["lo"])
    monkeypatch.setattr(isolated.os, "statvfs", lambda path: SimpleNamespace(f_flag=0 if (
        (fault == "rootfs" and path == "/") or (fault == "input" and path == "/scan")) else isolated.os.ST_RDONLY))
    if fault:
        with pytest.raises(RuntimeError, match="policy was not applied"):
            isolated.verify_runtime()
    else:
        assert all(isolated.verify_runtime().values())


def test_main_sanitizes_failure_and_cancels_watchdog(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(isolated.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(_request()).encode())))
    monkeypatch.setattr(isolated.threading, "Timer", lambda *_a: SimpleNamespace(
        start=lambda: calls.append("started"), cancel=lambda: calls.append("cancelled")))
    monkeypatch.setattr(isolated, "scan_request", lambda _r: (_ for _ in ()).throw(RuntimeError("private-source-sentinel")))
    assert isolated.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-source-sentinel" not in captured.err
    assert "no findings accepted" in captured.err
    assert calls == ["started", "cancelled"]


def test_main_keeps_stdout_a_single_json_document(monkeypatch, capsys):
    monkeypatch.setattr(isolated.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(_request()).encode())))

    def fake_scan(_request):
        print("detector diagnostic")
        return {"schema": isolated.SCHEMA, "result": {}}

    monkeypatch.setattr(isolated, "scan_request", fake_scan)
    assert isolated.main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["schema"] == isolated.SCHEMA
    assert "detector diagnostic" in captured.err


def test_main_bounds_request_size(monkeypatch, capsys):
    monkeypatch.setattr(isolated.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"x" * 65537)))
    assert isolated.main() == 1
    assert capsys.readouterr().out == ""


def test_independent_watchdog_exits_a_stuck_adapter():
    # Deliberately bypass the runtime in this subprocess harness to test only
    # the watchdog. No claim about Docker, network or filesystem isolation.
    code = "from scanner import isolated; import time; isolated.scan_request=lambda r: time.sleep(30); isolated.main()"
    process = subprocess.run([sys.executable, "-c", code], input=json.dumps(_request()).encode(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
    assert process.returncode == 124
    assert process.stdout == b""


def test_source_types_accepts_regular_files_and_does_not_follow_links(tmp_path):
    (tmp_path / "file.py").write_text("print(1)")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "outside").symlink_to("/does-not-exist")
    (tmp_path / "loop").symlink_to(tmp_path)
    isolated.verify_source_types(tmp_path)


def test_source_types_refuses_fifo_before_detectors_can_open_it(tmp_path):
    import os

    os.mkfifo(tmp_path / "host-special-file")
    with pytest.raises(RuntimeError, match="special files"):
        isolated.verify_source_types(tmp_path)


def test_source_types_refuses_unix_socket_metadata(tmp_path, monkeypatch):
    import stat

    entry = SimpleNamespace(name="host-socket", stat=lambda **kwargs: SimpleNamespace(st_mode=stat.S_IFSOCK))
    class Entries:
        def __enter__(self):
            return iter([entry])
        def __exit__(self, *_args):
            return None
    monkeypatch.setattr(isolated.os, "scandir", lambda _path: Entries())
    with pytest.raises(RuntimeError, match="special files"):
        isolated.verify_source_types(tmp_path)
