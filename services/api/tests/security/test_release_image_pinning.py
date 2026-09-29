"""Release image rendering must be immutable and non-destructive."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "pin_release_images.py"
DIGESTS = {
    "--api-digest": "a" * 64,
    "--worker-digest": "b" * 64,
    "--neo4j-digest": "c" * 64,
}


def _pin():
    spec = importlib.util.spec_from_file_location("pin_release_images", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source(root: Path) -> Path:
    source = root / "k8s"
    (source / "app").mkdir(parents=True)
    (source / "neo4j").mkdir()
    (source / "app" / "deployment.yaml").write_text(
        """containers:
  - name: api
    image: cryptoscan-api:v1.0.0
  - name: worker
    image: cryptoscan-worker:v1.0.0
""",
        encoding="utf-8",
    )
    (source / "neo4j" / "statefulset.yaml").write_text(
        """containers:
  - name: neo4j
    image: neo4j:5.26-community
""",
        encoding="utf-8",
    )
    return source


def _args(source: Path, output: Path, registry: str = "registry.example/bank") -> list[str]:
    args = ["--registry", registry, "--source", str(source), "--out", str(output)]
    for name, digest in DIGESTS.items():
        args.extend((name, digest))
    return args


def test_render_replaces_every_production_image_with_a_digest(tmp_path):
    pin = _pin()
    source = _source(tmp_path)
    output = tmp_path / "release" / "k8s"

    assert pin.main(_args(source, output)) == 0

    rendered = "\n".join(p.read_text(encoding="utf-8") for p in output.rglob("*.yaml"))
    assert "registry.example/bank/cryptoscan-api@sha256:" + "a" * 64 in rendered
    assert "registry.example/bank/cryptoscan-worker@sha256:" + "b" * 64 in rendered
    assert "registry.example/bank/neo4j@sha256:" + "c" * 64 in rendered
    assert ":v1.0.0" not in rendered
    assert ":5.26-community" not in rendered

    lock = json.loads((output / "release-image-lock.json").read_text(encoding="utf-8"))
    assert lock["registry"] == "registry.example/bank"
    assert lock["digests"]["api"] == "a" * 64
    assert (source / "app" / "deployment.yaml").read_text(encoding="utf-8").find("v1.0.0") >= 0


def test_render_refuses_output_inside_source_before_deleting_anything(tmp_path):
    pin = _pin()
    source = _source(tmp_path)
    source_file = source / "app" / "deployment.yaml"

    with pytest.raises(SystemExit):
        pin.main(_args(source, source / "rendered"))

    assert source_file.exists()
    assert "cryptoscan-api:v1.0.0" in source_file.read_text(encoding="utf-8")


@pytest.mark.parametrize("registry", ["registry.example/bank:latest", "https://registry.example/bank", "registry.example/bank@sha256:" + "a" * 64])
def test_render_refuses_ambiguous_registry_prefix(tmp_path, registry):
    pin = _pin()
    source = _source(tmp_path)

    with pytest.raises(SystemExit):
        pin.main(_args(source, tmp_path / "release", registry))
