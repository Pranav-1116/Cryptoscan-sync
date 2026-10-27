"""Real CLI children + injected runtime faults; NOT Docker/escape qualification."""
import asyncio
import os
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

from worker.core import static_scan_isolation as isolation

CANARY = "private-runtime-credential-canary"
IMAGE = "example.invalid/scanner@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def nonproduction(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_CONTROLS", "false")


@pytest.fixture()
def children(monkeypatch):
    original = subprocess.Popen
    seen = []

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        seen.append(child)
        return child

    monkeypatch.setattr(isolation.subprocess, "Popen", launch)
    try:
        yield seen
    finally:
        # Test-only safety net for intentionally failed cleanup and pre-fix leaks.
        for child in seen:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            for name in ("stdin", "stdout", "stderr"):
                getattr(child, name).close()


def sleeper():
    return [sys.executable, "-c", "import time; time.sleep(30)"]


def assert_closed(child):
    assert all(getattr(child, name).closed for name in ("stdin", "stdout", "stderr"))


@pytest.mark.parametrize("error", [OSError, PermissionError, FileNotFoundError])
def test_launch_errors_are_safe_and_never_fall_back(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error(CANARY)

    monkeypatch.setattr(isolation.subprocess, "Popen", fail)
    with pytest.raises(isolation.StaticScanIsolationError, match="communicate") as caught:
        isolation._exchange(["private-path/" + CANARY], {}, timeout=1)
    assert CANARY not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("point", ["construct", "register", "nonblocking"])
def test_setup_failures_reap_the_actual_child_and_close_all_pipes(monkeypatch, children, point):
    original = isolation.selectors.DefaultSelector

    def fail(*args, **kwargs):
        raise OSError(CANARY)

    if point == "construct":
        monkeypatch.setattr(isolation.selectors, "DefaultSelector", fail)
    elif point == "register":
        def selector():
            selected = original()
            monkeypatch.setattr(selected, "register", fail)
            return selected
        monkeypatch.setattr(isolation.selectors, "DefaultSelector", selector)
    else:
        monkeypatch.setattr(isolation.os, "set_blocking", fail)
    with pytest.raises(isolation.StaticScanIsolationError, match="communicate") as caught:
        isolation._exchange(sleeper(), {}, timeout=1)
    assert CANARY not in str(caught.value)
    assert len(children) == 1 and children[0].poll() is not None
    assert_closed(children[0])


@pytest.mark.parametrize("error", ["timeout", "os-error"])
def test_uncertain_process_cleanup_is_safe_and_still_closes_handles(monkeypatch, children, error):
    def fail(child):
        if error == "timeout":
            raise subprocess.TimeoutExpired(CANARY, 5)
        raise OSError(CANARY)

    monkeypatch.setattr(isolation, "_kill", fail)
    with pytest.raises(isolation.StaticScanIsolationError, match="cleanup could not be confirmed") as caught:
        isolation._exchange(sleeper(), {}, timeout=0.1)
    assert CANARY not in str(caught.value)
    assert len(children) == 1
    assert_closed(children[0])
    # Do not assert that the child stopped: the injected kill failure is unknown.


def test_selector_cleanup_failure_does_not_skip_pipe_cleanup(monkeypatch, children):
    original = isolation.selectors.DefaultSelector

    def selector():
        selected = original()
        close = selected.close

        def fail():
            close()
            raise OSError(CANARY)

        monkeypatch.setattr(selected, "close", fail)
        return selected

    monkeypatch.setattr(isolation.selectors, "DefaultSelector", selector)
    with pytest.raises(isolation.StaticScanIsolationError, match="cleanup could not be confirmed") as caught:
        isolation._exchange(sleeper(), {}, timeout=0.1)
    assert CANARY not in str(caught.value)
    assert len(children) == 1 and children[0].poll() is not None
    assert_closed(children[0])


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, asyncio.CancelledError, GeneratorExit])
def test_confirmed_container_cleanup_preserves_original_cancellation(tmp_path, monkeypatch, interruption):
    monkeypatch.setattr(isolation, "_configuration", lambda: SimpleNamespace(
        ENVIRONMENT="test", CRYPTOSCAN_STATIC_SCAN_MODE="container",
        CRYPTOSCAN_SCANNER_IMAGE=IMAGE, CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S=30))
    monkeypatch.setattr(isolation.shutil, "which", lambda name: "/usr/bin/docker")
    original = interruption("synthetic interruption")
    removed = []

    def exchange(*args, **kwargs):
        raise original

    def cleanup(command, **kwargs):
        removed.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(isolation, "_exchange", exchange)
    monkeypatch.setattr(isolation.subprocess, "run", cleanup)
    with pytest.raises(interruption) as caught:
        isolation.scan_static(root_path=tmp_path, scan_id="cancelled")
    assert caught.value is original
    assert len(removed) == 1 and removed[0][1:3] == ["rm", "--force"]
    assert list(tmp_path.glob(".cryptoscan-scan-*")) == []


def test_success_closes_all_handles_and_preserves_bounded_output(children):
    command = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.write('bounded-result')"]
    assert isolation._exchange(command, {}, timeout=5) == b"bounded-result"
    assert len(children) == 1 and children[0].poll() == 0
    assert_closed(children[0])
