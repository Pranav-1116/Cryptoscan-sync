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
    assert "authentic only if the key you passed" in out


# --- signatures: the half that was missing -------------------------------------------


def _signed_manifest(installed: Path, tmp_path: Path, name: str = "keys"):
    from shared_models import release_signature as signing

    keys = signing.generate_keypair(tmp_path / name)
    manifest_path = tmp_path / f"{name}-manifest.json"
    code = release_manifest.main([
        "--root", str(installed), "--path", "services/api/api", "--path", "VERSION",
        "--output", str(manifest_path), "--sign-key", keys["private_key"],
    ])
    assert code == 0
    return keys, manifest_path, json.loads(manifest_path.read_text())


def test_a_signed_manifest_verifies_against_the_trusted_key(installed: Path, tmp_path: Path, capsys):
    keys, manifest_path, manifest = _signed_manifest(installed, tmp_path)
    assert manifest["signature"]["alg"] == "Ed25519"
    assert "signature is null" not in " ".join(manifest["limits"])
    from api.cli import main

    assert main(["verify-installation", "--manifest", str(manifest_path),
                 "--root", str(installed), "--public-key", keys["public_key"]]) == 0
    out = capsys.readouterr().out
    assert "signature  VALID" in out


def test_a_signature_without_a_trusted_key_is_not_called_valid(installed: Path, tmp_path: Path, capsys):
    _keys, manifest_path, _manifest = _signed_manifest(installed, tmp_path)
    from api.cli import main

    assert main(["verify-installation", "--manifest", str(manifest_path),
                 "--root", str(installed)]) == 0
    out = capsys.readouterr().out
    assert "SIGNED_UNVERIFIED" in out
    assert "signature  VALID" not in out
    assert "no --public-key was given" in out


def test_editing_a_signed_manifest_breaks_the_signature(installed: Path, tmp_path: Path, capsys):
    """The whole point: a rewritten hash list must not verify."""
    keys, manifest_path, manifest = _signed_manifest(installed, tmp_path)
    manifest["files"]["services/api/api/cli.py"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    from api.cli import main

    assert main(["verify-installation", "--manifest", str(manifest_path),
                 "--root", str(installed), "--public-key", keys["public_key"]]) == 1
    out = capsys.readouterr().out
    assert "signature  INVALID" in out


def test_signing_with_a_different_key_is_a_mismatch_not_a_pass(installed: Path, tmp_path: Path, capsys):
    _keys, manifest_path, _manifest = _signed_manifest(installed, tmp_path)
    other, _path, _doc = _signed_manifest(installed, tmp_path, name="other")
    from api.cli import main

    assert main(["verify-installation", "--manifest", str(manifest_path),
                 "--root", str(installed), "--public-key", other["public_key"]]) == 1
    assert "SIGNATURE_KEY_MISMATCH" in capsys.readouterr().out


def test_the_signature_covers_every_member_except_itself():
    from shared_models import release_signature as signing

    key = signing.generate_keypair(Path("/tmp") / "sig-canonical")
    private = signing.load_private_key(key["private_key"])
    document = {"schema": "x", "files": {"a": "b"}, "limits": ["l"]}
    signature = signing.sign_document(document, private)
    signed = {**document, "signature": signature}
    trusted = signing.load_public_key(key["public_key"])

    assert signing.verify_document(signed, trusted_key=trusted)["status"] == signing.VALID
    for field in ("files", "limits", "schema"):
        tampered = {**signed, field: "different" if field == "schema" else {}}
        verdict = signing.verify_document(tampered, trusted_key=trusted)
        assert verdict["status"] == signing.INVALID, (field, verdict)
