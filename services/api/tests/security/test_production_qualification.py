"""The production qualification coordinator must fail closed and redact secrets."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "production_qualification.py"


def _module():
    spec = importlib.util.spec_from_file_location("production_qualification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_external_artifact_is_skip(tmp_path):
    module = _module()
    args = type("Args", (), {})()
    qualification = module.Qualification(tmp_path, args)

    qualification.artifact("postgresql-dr", tmp_path / "missing.json")

    assert qualification.rows[0]["status"] == "SKIP"
    assert "not supplied" in qualification.rows[0]["detail"]


def test_command_output_redacts_credentials(tmp_path):
    module = _module()
    args = type("Args", (), {})()
    qualification = module.Qualification(tmp_path, args)

    qualification.record(
        "redaction",
        "FAIL",
        "postgresql://operator:super-secret@db.example/password=also-secret token=private",
    )

    detail = qualification.rows[0]["detail"]
    assert "super-secret" not in detail
    assert "also-secret" not in detail
    assert "private" not in detail
    assert "[redacted]" in detail
