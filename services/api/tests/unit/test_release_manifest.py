"""The release manifest and its verifier have to loop: one makes, the other checks.

A manifest generator that emits an empty map would let ``cryptoscan verify-installation``
report MATCH for an installation that contains nothing — the cheapest possible false green.
So the generator refuses to emit an empty manifest, and the two halves are tested against
each other rather than each against a fixture.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from api import cli_remote
import release_manifest


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    root = tmp_path / "install"
    (root / "services" / "api" / "api").mkdir(parents=True)
    (root / "services" / "api" / "api" / "cli.py").write_text("print('cli')\n")
    (root / "services" / "api" / "api" / "__pycache__").mkdir()
    (root / "services" / "api" / "api" / "__pycache__" / "cli.cpython-311.pyc").write_bytes(b"\x00")
    (root / "VERSION").write_text("1.2.3\n")
    return root


def test_manifest_carries_every_shipped_file_and_no_bytecode(installed: Path):
    manifest = release_manifest.build_manifest(installed, [Path("services/api/api"), Path("VERSION")])
    assert manifest["version"] == "1.2.3"
    assert "services/api/api/cli.py" in manifest["files"]
    assert not any("__pycache__" in name for name in manifest["files"])
    assert manifest["signature"] is None
    assert any("MANIFEST_UNSIGNED" in limit for limit in manifest["limits"])
    expected = hashlib.sha256((installed / "services/api/api/cli.py").read_bytes()).hexdigest()
    assert manifest["files"]["services/api/api/cli.py"] == expected


def test_generator_refuses_an_empty_manifest(tmp_path: Path, capsys):
    code = release_manifest.main(["--root", str(tmp_path), "--path", "nothing-here"])
    assert code == 2
    assert "empty manifest" in capsys.readouterr().err


def test_verify_installation_accepts_what_the_generator_produced(installed: Path, tmp_path: Path,
                                                                 monkeypatch, capsys):
    manifest = release_manifest.build_manifest(installed, [Path("services/api/api"), Path("VERSION")])
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(cli_remote, "TRANSPORT", None)
    from api.cli import main

    code = main(["verify-installation", "--manifest", str(path), "--root", str(installed)])
    assert code == 0
    out = capsys.readouterr().out
    assert "verdict    MATCH" in out
    assert "MANIFEST_UNSIGNED" in out


def test_tampering_after_the_manifest_is_detected(installed: Path, tmp_path: Path, capsys):
    manifest = release_manifest.build_manifest(installed, [Path("services/api/api")])
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    (installed / "services" / "api" / "api" / "cli.py").write_text("print('tampered')\n")
    from api.cli import main

    assert main(["verify-installation", "--manifest", str(path), "--root", str(installed)]) == 2
    out = capsys.readouterr().out
    assert "mismatch   services/api/api/cli.py" in out
    assert "does not verify that the manifest itself is authentic" in out
