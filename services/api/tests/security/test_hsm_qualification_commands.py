"""HSM qualification wrappers must not become shell injection paths."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "hsm_qualification.py"


def _module():
    spec = importlib.util.spec_from_file_location("hsm_qualification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_wrapper_runs_without_a_shell():
    module = _module()
    status, detail = module.run_operator_command("python --version")
    assert status == "PASS", detail


def test_operator_wrapper_rejects_shell_syntax():
    module = _module()
    status, detail = module.run_operator_command("echo qualification-ok; touch should-not-exist")
    assert status == "FAIL"
    assert "shell metacharacters" in detail


def test_empty_operator_wrapper_is_explicit_skip():
    module = _module()
    status, detail = module.run_operator_command("")
    assert status == "SKIP"
    assert "empty" in detail
