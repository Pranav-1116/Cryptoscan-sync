"""Hostile acquisition staging contracts; no Docker/escape-resistance claim."""
import os
import pytest
from worker.core import controlled_source as source
from db.repositories.execution_control import ExecutionDenied


@pytest.fixture()
def staged(tmp_path, monkeypatch):
    root = tmp_path / "input"
    root.mkdir()
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setattr(source, "checkpoint", lambda *_a, **_kw: None)
    monkeypatch.setattr(source, "CHECKPOINT_INTERVAL", 0)
    return root, tmp_path / "workspace" / "repo"


def test_staging_copies_only_regular_source_without_git_or_credential_directories(staged):
    root, dest = staged
    (root / "source.py").write_text("print('source')\n")
    for name in (".git", ".ssh", ".aws", ".kube"):
        (root / name).mkdir()
        (root / name / "credential").write_text("must-not-cross-boundary")
    (root / ".env").write_text("SECRET=must-not-cross-boundary")
    assert source.stage("local://" + str(root), dest) == str(dest)
    assert sorted(p.name for p in dest.iterdir()) == ["source.py"]
    assert (dest / "source.py").read_bytes() == (root / "source.py").read_bytes()


@pytest.mark.parametrize("kind", ["symlink", "directory_symlink", "hardlink", "fifo", "file_size", "total_size", "entries", "depth"])
def test_hostile_staging_refuses_without_leaving_partial_inputs(staged, monkeypatch, kind):
    root, dest = staged
    file = root / "first.py"
    file.write_text("benign first file")
    if kind == "symlink":
        (root / "escape").symlink_to("/etc/passwd")
    elif kind == "directory_symlink":
        (root / "escape").symlink_to(root.parent, target_is_directory=True)
    elif kind == "hardlink":
        os.link(file, root / "second.py")
    elif kind == "fifo":
        os.mkfifo(root / "pipe")
    elif kind == "file_size":
        monkeypatch.setattr(source, "MAX_FILE_BYTES", 1)
    elif kind == "total_size":
        monkeypatch.setattr(source, "MAX_BYTES", 1)
    elif kind == "entries":
        monkeypatch.setattr(source, "MAX_FILES", 0)
    else:
        current = root
        for _ in range(66):
            current = current / "nested"
            current.mkdir()
    with pytest.raises((ExecutionDenied, OSError)):
        source.stage(str(root), dest)
    assert not dest.exists()
    assert file.exists()  # Cleanup never deletes the original input.


def test_existing_destination_is_never_deleted_on_refusal(staged):
    root, dest = staged
    dest.mkdir(parents=True)
    existing = dest / "keep"
    existing.write_text("untouched")
    with pytest.raises(FileExistsError):
        source.stage(str(root), dest)
    assert existing.read_text() == "untouched"


def test_source_path_component_symlink_is_refused(staged):
    root, dest = staged
    link = root.parent / "linked-root"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        source.stage(str(link), dest)
    assert not dest.exists()


def test_stop_during_copy_cleans_staging_and_never_runs_parser(staged, monkeypatch):
    root, dest = staged
    (root / "large.py").write_bytes(b"a" * 131072)
    calls = []
    def stop(stage):
        calls.append(stage)
        if len(calls) >= 3:
            raise ExecutionDenied("stopped")
    monkeypatch.setattr(source, "checkpoint", stop)
    with pytest.raises(ExecutionDenied, match="stopped"):
        source.stage(str(root), dest)
    assert not dest.exists()


def test_controlled_standalone_parser_and_pipeline_cannot_bypass_lease(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_CONTROLS", "true")
    from worker.core.static_scan_isolation import scan_static
    from worker.pipeline.pipeline_runner import PipelineRunner
    with pytest.raises(ExecutionDenied, match="lease"):
        scan_static(root_path=tmp_path)
    with pytest.raises(ExecutionDenied, match="lease"):
        PipelineRunner().run(target_repo=str(tmp_path))


def test_unprovisioned_or_inline_runtime_has_no_fallback(monkeypatch):
    from types import SimpleNamespace
    from worker.core import static_scan_isolation
    monkeypatch.setattr(static_scan_isolation, "_configuration", lambda: SimpleNamespace(
        ENVIRONMENT="test", CRYPTOSCAN_STATIC_SCAN_MODE="inline", CRYPTOSCAN_SCANNER_IMAGE="mutable:latest"))
    with pytest.raises(ExecutionDenied, match="container"):
        source.preflight()


def test_live_launcher_poll_stops_child_on_checkpoint_denial(monkeypatch):
    import subprocess
    import sys
    import time
    from db.repositories import execution_control
    from worker.core import static_scan_isolation as isolation
    children = []
    original = subprocess.Popen
    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child
    checks = []
    def check(_stage):
        checks.append(time.monotonic())
        if len(checks) == 2:
            raise ExecutionDenied("stop engaged")
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(execution_control, "active_execution", lambda: {"test": True})
    monkeypatch.setattr(execution_control, "checkpoint", check)
    started = time.monotonic()
    with pytest.raises(ExecutionDenied, match="stop engaged"):
        isolation._exchange([sys.executable, "-c", "import time; time.sleep(30)"], {}, timeout=10)
    assert len(checks) == 2 and time.monotonic() - started < 3
    assert children[0].poll() is not None  # Actual child, not a mocked kill.


def test_strict_workspace_cleanup_refuses_outside_and_does_not_swallow_errors(tmp_path, monkeypatch):
    base = tmp_path / "workspaces"
    workspace = base / "job-test"
    workspace.mkdir(parents=True)
    (workspace / "private-source").write_text("private")
    with pytest.raises(ExecutionDenied):
        source.cleanup_workspace(tmp_path, base)
    source.cleanup_workspace(workspace, base)
    assert not workspace.exists()
    workspace.mkdir()
    def fail(_path):
        raise OSError("removal unavailable")
    fail.avoids_symlink_attacks = True
    monkeypatch.setattr(source.shutil, "rmtree", fail)
    with pytest.raises(OSError):
        source.cleanup_workspace(workspace, base)


@pytest.mark.parametrize("deadline", [0, -1, float("nan"), float("inf"), "tomorrow", True])
def test_child_protocol_refuses_missing_usable_approval_deadline(deadline):
    from scanner.isolated import SCHEMA, validate_request
    request = {"schema": SCHEMA, "scan_id": "controlled", "exclude_test_dirs": False, "timeout_s": 60,
               "source_marker": ".cryptoscan-scan-" + "a" * 32, "source_token": "b" * 64, "deadline_unix": deadline}
    with pytest.raises(ValueError, match="deadline"):
        validate_request(request)


def test_child_watchdog_is_capped_by_absolute_approval_deadline():
    import time
    from scanner.isolated import parser_budget
    budget = parser_budget({"timeout_s": 600, "deadline_unix": time.time() + 5})
    assert 0 < budget <= 5
