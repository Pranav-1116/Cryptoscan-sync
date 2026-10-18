"""Parser boundary contracts. Mock-runtime tests are NOT Docker qualification."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from worker.core import static_scan_isolation as isolation
from scanner.isolated import SCHEMA, validate_request
from scanner.models.scan_result import ScanResult

IMAGE = "example.invalid/cryptoscan-scanner@sha256:" + "a" * 64
CHECKS = {key: True for key in ("non_root", "no_new_privileges", "capabilities_dropped", "seccomp_filter",
                               "root_read_only", "input_read_only", "network_interfaces_only_loopback", "git_metadata_hidden")}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("CRYPTOSCAN_STATIC_SCAN_MODE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SCANNER_IMAGE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S", raising=False)


def _container(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_MODE", "container")
    monkeypatch.setenv("CRYPTOSCAN_SCANNER_IMAGE", IMAGE)
    monkeypatch.setattr(isolation.shutil, "which", lambda _name: "/usr/bin/docker")


def _response(request):
    result = ScanResult(scan_id=request["scan_id"])
    result.finalize()
    return json.dumps({"schema": SCHEMA, "runtime_checks": CHECKS, "result": result.model_dump(mode="json")}).encode()


def test_production_defaults_to_container_and_cannot_disable_it(monkeypatch):
    assert isolation.execution_mode() == "inline"
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert isolation.execution_mode() == "container"
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_MODE", "inline")
    with pytest.raises(isolation.StaticScanIsolationError, match="requires container"):
        isolation.execution_mode()


def test_invalid_mode_is_not_a_fallback(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_MODE", "typo")
    with pytest.raises(isolation.StaticScanIsolationError, match="must be"):
        isolation.execution_mode()


def test_inline_is_explicitly_reported_as_not_isolated(tmp_path):
    (tmp_path / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    result = isolation.scan_static(root_path=tmp_path, scan_id="inline-1")
    assert result.findings
    assert result.isolation == {"mode": "inline", "isolated": False}


def test_container_command_minimizes_authority_and_keeps_provenance_in_parent(tmp_path, monkeypatch):
    _container(monkeypatch)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "worker-secret-sentinel")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///worker-credential-sentinel.db")
    seen = {}

    def exchange(command, request, **kwargs):
        seen.update(command=command, request=request)
        return _response(request)

    monkeypatch.setattr(isolation, "_exchange", exchange)
    result = isolation.scan_static(root_path=tmp_path, scan_id="scan-1", target_location="https://token@repo.invalid/x",
                                   target_branch="private-branch", target_commit="commit-1")
    command = seen["command"]
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--user=10001:10001", "--pull=never", "--pids-limit=64", "--memory=1g", "--cpus=1"):
        assert flag in command
    assert f"type=bind,src={tmp_path},dst=/scan,readonly,bind-recursive=disabled" in command
    assert "scanner.isolated" in command and "-I" in command
    assert IMAGE in command
    outbound = json.dumps(seen)
    for secret in ("worker-secret-sentinel", "worker-credential-sentinel", "private-branch", "token@repo"):
        assert secret not in outbound
    assert result.scan_target.location == "https://token@repo.invalid/x"
    assert result.scan_target.commit == "commit-1"
    assert result.isolation["scope"] == "static-source-parser-only"
    assert result.isolation["runtime_checks"] == CHECKS


@pytest.mark.parametrize("image", ["scanner:latest", "scanner:v1", "scanner@sha256:abc", "", "-bad@sha256:" + "a" * 64])
def test_mutable_or_invalid_image_refused_before_launch(tmp_path, monkeypatch, image):
    _container(monkeypatch)
    monkeypatch.setenv("CRYPTOSCAN_SCANNER_IMAGE", image)
    monkeypatch.setattr(isolation, "_exchange", lambda *_a, **_k: pytest.fail("must not launch"))
    with pytest.raises(isolation.StaticScanIsolationError, match="immutable"):
        isolation.scan_static(root_path=tmp_path)


def test_missing_runtime_refused_without_inline_fallback(tmp_path, monkeypatch):
    _container(monkeypatch)
    monkeypatch.setattr(isolation.shutil, "which", lambda _name: None)
    with pytest.raises(isolation.StaticScanIsolationError, match="not started"):
        isolation.scan_static(root_path=tmp_path)


@pytest.mark.parametrize("budget", ["0", "-1", "nan", "inf", "3601", "invalid"])
def test_invalid_budgets_fail_closed(tmp_path, monkeypatch, budget):
    _container(monkeypatch)
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S", budget)
    with pytest.raises(isolation.StaticScanIsolationError, match="timeout"):
        isolation.scan_static(root_path=tmp_path)


def test_mount_option_injection_is_refused(tmp_path, monkeypatch):
    _container(monkeypatch)
    path = tmp_path / "source,readonly=false"
    path.mkdir()
    with pytest.raises(isolation.StaticScanIsolationError, match="bind mount"):
        isolation.scan_static(root_path=path)


@pytest.mark.parametrize("fault", ["bad-json", "schema", "scan-id", "status", "runtime-checks"])
def test_invalid_results_are_not_accepted_and_named_container_is_removed(tmp_path, monkeypatch, fault):
    _container(monkeypatch)
    removed = []

    def exchange(_command, request, **_kwargs):
        if fault == "bad-json":
            return b"source-secret-sentinel"
        envelope = json.loads(_response(request))
        if fault == "schema":
            envelope["schema"] = "other"
        elif fault == "scan-id":
            envelope["result"]["scan_id"] = "unrelated-scan"
        elif fault == "status":
            envelope["result"]["status"] = "FAILED"
        else:
            envelope["runtime_checks"]["input_read_only"] = False
        return json.dumps(envelope).encode()

    def remove(command, **_kwargs):
        removed.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(isolation, "_exchange", exchange)
    monkeypatch.setattr(isolation.subprocess, "run", remove)
    with pytest.raises(isolation.StaticScanIsolationError) as caught:
        isolation.scan_static(root_path=tmp_path, scan_id="scan-1")
    assert "source-secret-sentinel" not in str(caught.value)
    assert len(removed) == 1 and removed[0][:3] == ["/usr/bin/docker", "rm", "--force"]
    assert removed[0][3].startswith("cryptoscan-static-")


def test_timeout_refusal_does_not_silently_leave_a_daemon_workload(tmp_path, monkeypatch):
    _container(monkeypatch)
    monkeypatch.setattr(isolation, "_exchange", lambda *_a, **_k: (_ for _ in ()).throw(
        isolation.StaticScanIsolationError("wall-clock budget")))
    monkeypatch.setattr(isolation.subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=1))
    with pytest.raises(isolation.StaticScanIsolationError, match="cleanup could not be confirmed"):
        isolation.scan_static(root_path=tmp_path)


def test_protocol_output_limit_is_enforced_by_real_subprocess():
    command = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.write('x'*1000000)"]
    with pytest.raises(isolation.StaticScanIsolationError, match="protocol limit"):
        isolation._exchange(command, {}, timeout=5, limit=4096)


def test_runtime_failure_never_reflects_source_or_credentials():
    command = [sys.executable, "-c", "import sys; sys.stderr.write('private-source-sentinel'); sys.exit(7)"]
    with pytest.raises(isolation.StaticScanIsolationError) as caught:
        isolation._exchange(command, {}, timeout=5)
    assert "private-source-sentinel" not in str(caught.value)


def test_real_subprocess_wall_clock_is_bounded():
    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    with pytest.raises(isolation.StaticScanIsolationError, match="wall-clock"):
        isolation._exchange(command, {}, timeout=0.1)


def test_valid_exchange_is_json_not_pickle():
    command = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.write('{\"ok\":true}')"]
    assert json.loads(isolation._exchange(command, {}, timeout=5)) == {"ok": True}


@pytest.mark.parametrize("change", [{"root_path": "/etc"}, {"env": {"SECRET_KEY": "x"}},
                                    {"timeout_s": float("inf")}, {"exclude_test_dirs": "false"},
                                    {"scan_id": None}, {"schema": "old"}])
def test_child_request_cannot_expand_its_authority(change):
    request = {"schema": SCHEMA, "scan_id": "s1", "exclude_test_dirs": False, "timeout_s": 5,
               "source_marker": ".cryptoscan-scan-" + "a" * 32, "source_token": "a" * 64}
    request.update(change)
    with pytest.raises(ValueError):
        validate_request(request)


def test_both_live_pipeline_paths_use_the_same_execution_policy():
    from worker.pipeline.pipeline_runner import PipelineRunner
    from worker.pipeline import stage_scan
    import inspect

    assert "scan_static(" in inspect.getsource(PipelineRunner._scan)
    assert "scan_static(" in inspect.getsource(stage_scan.execute)
    assert "static_scan_execution" in inspect.getsource(PipelineRunner._scan)
    assert "static_scan_execution" in inspect.getsource(stage_scan.execute)


def test_source_binding_marker_is_present_only_for_the_launch(tmp_path, monkeypatch):
    _container(monkeypatch)

    def exchange(_command, request, **_kwargs):
        marker = tmp_path / request["source_marker"]
        assert marker.read_text() == request["source_token"]
        assert marker.stat().st_mode & 0o444 == 0o444
        return _response(request)

    monkeypatch.setattr(isolation, "_exchange", exchange)
    isolation.scan_static(root_path=tmp_path)
    assert list(tmp_path.glob(".cryptoscan-scan-*")) == []


def test_already_auto_removed_container_is_confirmed_without_claiming_daemon_failure(tmp_path, monkeypatch):
    _container(monkeypatch)
    calls = []
    monkeypatch.setattr(isolation, "_exchange", lambda *_a, **_k: b"invalid")

    def cleanup(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1) if command[1] == "rm" else SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(isolation.subprocess, "run", cleanup)
    with pytest.raises(isolation.StaticScanIsolationError, match="invalid or unavailable result"):
        isolation.scan_static(root_path=tmp_path)
    assert [c[1] for c in calls] == ["rm", "ps"]
    assert list(tmp_path.glob(".cryptoscan-scan-*")) == []


@pytest.mark.parametrize("path", ["runner", "stage"])
def test_pipeline_records_the_actual_execution_policy(tmp_path, monkeypatch, path):
    from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner
    from worker.pipeline import stage_scan

    seen = []

    def fake(**kwargs):
        seen.append(kwargs)
        result = ScanResult(scan_id="bound-id")
        result.isolation = {"mode": "container", "isolated": True, "image": IMAGE}
        return result

    monkeypatch.setattr(isolation, "scan_static", fake)
    ctx = PipelineContext(job_id="j1", target_repo="local://input", target_branch="main",
                          triggered_by="operator", workspace_dir=str(tmp_path), repo_path=str(tmp_path))
    if path == "stage":
        stage_scan.execute(ctx)
    else:
        runner = PipelineRunner.__new__(PipelineRunner)
        for name in ("_container", "_tls", "_cloud", "_ot_findings"):
            monkeypatch.setattr(runner, name, lambda _ctx: None)
        runner._scan(ctx)
    assert len(seen) == 1
    assert seen[0]["root_path"] == str(tmp_path)
    assert ctx.scan_meta["statistics"]["static_scan_execution"]["mode"] == "container"


def test_runtime_output_drain_cannot_flood_diagnostics():
    command = [sys.executable, "-c", "import sys; sys.stderr.write('x'*1000000)"]
    with pytest.raises(isolation.StaticScanIsolationError, match="protocol limit"):
        isolation._exchange(command, {}, timeout=5)


def test_child_cannot_inherit_an_unrelated_open_file_descriptor(tmp_path):
    import fcntl
    import os

    with (tmp_path / "worker-private").open("w") as stream:
        fd = fcntl.fcntl(stream.fileno(), fcntl.F_DUPFD, 100)
        os.set_inheritable(fd, True)
        try:
            code = f"import os,sys; sys.stdin.read();\ntry: os.fstat({fd}); sys.stdout.write('leaked')\nexcept OSError: sys.stdout.write('closed')"
            assert isolation._exchange([sys.executable, "-c", code], {}, timeout=5) == b"closed"
        finally:
            os.close(fd)


def test_clone_authentication_is_hidden_from_parser_without_mutating_git_config(tmp_path, monkeypatch):
    _container(monkeypatch)
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text("[remote \"origin\"]\nurl = https://clone-credential-sentinel@repo.invalid/x\n")

    def exchange(command, request, **_kwargs):
        assert "/scan/.git:ro,noexec,nosuid,nodev,size=1m,mode=000" in command
        assert "clone-credential-sentinel" not in json.dumps([command, request])
        return _response(request)

    monkeypatch.setattr(isolation, "_exchange", exchange)
    isolation.scan_static(root_path=tmp_path)
    assert "clone-credential-sentinel" in (git / "config").read_text()


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_linked_git_metadata_refused_before_start(tmp_path, monkeypatch, kind):
    _container(monkeypatch)
    if kind == "file":
        (tmp_path / ".git").write_text("gitdir: /worker/private")
    else:
        (tmp_path / ".git").symlink_to("/worker/private")
    with pytest.raises(isolation.StaticScanIsolationError, match="Git metadata"):
        isolation.scan_static(root_path=tmp_path)


def test_blocked_stdin_is_also_subject_to_wall_clock_budget():
    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    with pytest.raises(isolation.StaticScanIsolationError, match="wall-clock"):
        isolation._exchange(command, {"padding": "x" * 60000}, timeout=0.1)


def test_protocol_request_limit_is_checked_before_spawning(monkeypatch):
    monkeypatch.setattr(isolation.subprocess, "Popen", lambda *_a, **_k: pytest.fail("must not spawn"))
    with pytest.raises(isolation.StaticScanIsolationError, match="request exceeds"):
        isolation._exchange(["unused"], {"padding": "x" * 65536}, timeout=1)


def test_timeout_terminates_cli_process_group_not_just_its_leader(tmp_path):
    import time

    marker = tmp_path / "orphan-was-alive"
    descendant = f"import time; from pathlib import Path; time.sleep(0.5); Path({str(marker)!r}).write_text('alive')"
    leader = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{descendant!r}]); time.sleep(30)"
    with pytest.raises(isolation.StaticScanIsolationError, match="wall-clock"):
        isolation._exchange([sys.executable, "-c", leader], {}, timeout=0.15)
    time.sleep(0.6)
    assert not marker.exists()


def test_finding_identity_is_parent_owned_not_masked_git_placeholder(tmp_path, monkeypatch):
    from scanner.models.raw_finding import RawFinding

    _container(monkeypatch)

    def exchange(_command, request, **_kwargs):
        response = json.loads(_response(request))
        finding = RawFinding(algorithm="MD5", file_path="crypto.py", git_context={"commit_hash": "unknown", "branch": "unknown"})
        response["result"]["findings"] = [finding.model_dump(mode="json")]
        return json.dumps(response).encode()

    monkeypatch.setattr(isolation, "_exchange", exchange)
    result = isolation.scan_static(root_path=tmp_path, target_commit="parent-commit", target_branch="parent-branch")
    context = result.findings[0].git_context
    assert context.commit_hash == "parent-commit" and context.branch == "parent-branch"
    assert context.commit_author is None and context.commit_timestamp is None


def test_production_alias_cannot_enable_inline(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "prod")
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_MODE", "inline")
    with pytest.raises(isolation.StaticScanIsolationError, match="requires container"):
        isolation.execution_mode()


def test_dotenv_production_policy_cannot_be_bypassed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ENVIRONMENT")
    (tmp_path / ".env").write_text("ENVIRONMENT=production\nCRYPTOSCAN_STATIC_SCAN_MODE=inline\n")
    with pytest.raises(isolation.StaticScanIsolationError, match="requires container"):
        isolation.execution_mode()
