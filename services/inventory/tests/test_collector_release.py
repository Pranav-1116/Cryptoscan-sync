"""Disposable external release signatures, actual verified staging and kernel IO."""

import base64
import hashlib
from pathlib import Path
import shutil
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from inventory.host import Refused
from inventory.collector_release import build_lock, verified_stage
from inventory.isolation import collect_isolated
from services.inventory.tests.test_collection_linux import spec

ROOT = Path(__file__).resolve().parents[3]


def release(root=ROOT):
    raw = build_lock(root).model_dump_json(indent=2).encode()
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return raw, base64.b64encode(private.sign(raw)).decode(), public, hashlib.sha256(raw).hexdigest()


def test_signed_stage_runs_from_exact_copy_and_cleans(tmp_path):
    raw, sig, pub, digest = release()
    with verified_stage(ROOT, raw, sig, pub, digest) as (staging, report):
        assert (
            report["verified_source_files"] > 30 and not report["host_attested"] and not report["dependencies_attested"]
        )
        assert (staging / "services/inventory/inventory/host.py").read_bytes() == (
            ROOT / "services/inventory/inventory/host.py"
        ).read_bytes()
        result, _ = collect_isolated(spec(tmp_path, b"ID=debian\n"), stage_root=staging)
        assert result.receipts[0].facts[0].software_name == "debian"
    assert not staging.exists()


@pytest.mark.parametrize(
    "change", ["lock", "signature", "key", "source", "symlink", "path", "interpreter", "duplicate-json"]
)
def test_release_changes_refuse_without_collecting(tmp_path, change):
    source = tmp_path / "install"
    source.mkdir()
    for p in ["services/inventory/inventory", "shared/shared_models/shared_models", "scripts"]:
        (source / p).parent.mkdir(parents=True, exist_ok=True)
        if p == "scripts":
            (source / p).mkdir()
            for name in ["_bootstrap.py", "_isolated_host_stage.py"]:
                shutil.copyfile(ROOT / p / name, source / p / name)
        else:
            shutil.copytree(ROOT / p, source / p, ignore=shutil.ignore_patterns("__pycache__"))
    raw, sig, pub, digest = release(source)
    if change == "lock":
        raw += b" "
    elif change == "signature":
        sig = base64.b64encode(b"X" * 64).decode()
    elif change == "key":
        pub = release()[2]
    elif change == "source":
        (source / "services/inventory/inventory/host.py").write_text("#tampered")
    elif change == "symlink":
        p = source / "services/inventory/inventory/host.py"
        p.unlink()
        p.symlink_to(ROOT / "services/inventory/inventory/host.py")
    else:
        import json

        data = json.loads(raw)
        if change == "path":
            data["files"]["../../escape.py"] = "a" * 64
        elif change == "interpreter":
            data["interpreter_sha256"] = "a" * 64
        raw = json.dumps(data).encode()
        if change == "duplicate-json":
            raw = raw[:-1] + b',"schema_version":"cryptoscan.collector-source-lock/v1"}'
        private = Ed25519PrivateKey.generate()
        pub = base64.b64encode(
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode()
        sig = base64.b64encode(private.sign(raw)).decode()
        digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises((ValueError, OSError, Refused)) as error:
        with verified_stage(source, raw, sig, pub, digest):
            pytest.fail("Untrusted release was staged")
    assert not isinstance(error.value, pytest.fail.Exception)
