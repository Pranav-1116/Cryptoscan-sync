"""Reference capture signer — qualification aid contracts.

The signer exists so a bank integrator can build a signing pipeline against the
exact attestation schema; keys it generates are TEST keys and the tool owns no
network client or database. These tests pin the round trip (keygen -> sign ->
verify), the refusals (tamper, wrong key, untrusted key_id, naive timestamps),
and the request-body shape the import route accepts.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "capture_signer.py"


def _cli():
    spec = importlib.util.spec_from_file_location("capture_signer", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _keygen(cli, tmp_path: Path, key_id: str = "bank-test-1") -> dict:
    out = tmp_path / "keys"
    assert cli.main(["keygen", "--out-dir", str(out), "--key-id", key_id]) == 0
    return {"key": str(out / f"{key_id}.key.pem"),
            "pub": str(out / f"{key_id}.pub.pem"),
            "keyset": str(out / f"{key_id}.keyset.json")}


def _sign_args(paths: dict, payload_path: Path, key_id: str = "bank-test-1") -> list:
    return ["sign", "--key", paths["key"], "--key-id", key_id,
            "--issuer", "bank-collector-1", "--tenant-id", "tenant-a",
            "--asset-ref", "app:svc-pay", "--source-id", "node-1",
            "--source-type", "node_exporter", "--authorization-ref", "AUTH-77",
            "--observed-at", "2026-10-16T12:00:00+00:00",
            "--payload", str(payload_path)]


def test_keygen_writes_test_keypair_and_keyset_fragment(tmp_path: Path, capsys):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    assert Path(paths["key"]).exists()
    assert Path(paths["pub"]).exists()
    fragment = json.loads(Path(paths["keyset"]).read_text(encoding="utf-8"))
    assert fragment["keys"][0]["key_id"] == "bank-test-1"
    assert "BEGIN PUBLIC KEY" in fragment["keys"][0]["public_key_pem"]
    # the private key is owner-only and the warning is loud
    assert oct(Path(paths["key"]).stat().st_mode)[-3:] == "600"
    assert "TEST KEY" in capsys.readouterr().err
    # never silently overwrite an existing key
    assert cli.main(["keygen", "--out-dir", str(tmp_path / "keys"),
                     "--key-id", "bank-test-1"]) == 2


def test_sign_emits_the_import_body_shape_and_verifies(tmp_path: Path, capsys):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"metrics": [
        {"family": "node_cpu_seconds_total", "samples": [
            {"labels": {"mode": "idle"}, "value": 4000.0}]}]}), encoding="utf-8")
    out = tmp_path / "capture.json"
    assert cli.main(_sign_args(paths, payload_path) + ["--out", str(out)]) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert set(body) == {"tenant_id", "asset_ref", "source_id", "source_type",
                         "authorization_ref", "observed_at", "payload", "attestation"}
    attestation = body["attestation"]
    assert set(attestation) == {"schema", "algorithm", "key_id", "issuer", "signature"}
    assert attestation["algorithm"] == "Ed25519"
    assert cli.main(["verify", "--public-key", paths["pub"], "--capture", str(out)]) == 0
    # and against the keyset form of the same anchor
    assert cli.main(["verify", "--public-key", paths["keyset"], "--capture", str(out)]) == 0


def test_verify_refuses_a_tampered_payload(tmp_path: Path, capsys):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"metrics": []}), encoding="utf-8")
    out = tmp_path / "capture.json"
    assert cli.main(_sign_args(paths, payload_path) + ["--out", str(out)]) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    body["payload"] = {"metrics": [{"family": "injected", "samples": []}]}
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(body), encoding="utf-8")
    assert cli.main(["verify", "--public-key", paths["pub"],
                     "--capture", str(tampered)]) == 1
    assert "does not bind" in capsys.readouterr().err


def test_verify_refuses_an_untrusted_key_id_in_a_keyset(tmp_path: Path):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    other = _keygen(cli, tmp_path, key_id="bank-test-2")
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"metrics": []}), encoding="utf-8")
    out = tmp_path / "capture.json"
    # signed under bank-test-1 but the anchor only trusts bank-test-2
    assert cli.main(_sign_args(paths, payload_path) + ["--out", str(out)]) == 0
    assert cli.main(["verify", "--public-key", other["keyset"],
                     "--capture", str(out)]) == 1


def test_verify_refuses_the_wrong_signing_key(tmp_path: Path):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    other = _keygen(cli, tmp_path, key_id="bank-test-2")
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"metrics": []}), encoding="utf-8")
    out = tmp_path / "capture.json"
    assert cli.main(_sign_args(paths, payload_path) + ["--out", str(out)]) == 0
    assert cli.main(["verify", "--public-key", other["pub"],
                     "--capture", str(out)]) == 1


def test_sign_requires_aware_timestamps_and_paired_previous(tmp_path: Path):
    cli = _cli()
    paths = _keygen(cli, tmp_path)
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"metrics": []}), encoding="utf-8")
    naive = _sign_args(paths, payload_path)
    naive[naive.index("--observed-at") + 1] = "2026-10-16T12:00:00"
    with pytest.raises(SystemExit):
        cli.main(naive)
    unpaired = _sign_args(paths, payload_path) + ["--previous", str(payload_path)]
    with pytest.raises(SystemExit):
        cli.main(unpaired)
