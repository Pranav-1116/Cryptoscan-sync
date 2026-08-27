"""Layer attribution: which image layer introduced each artifact."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.archive import extract_image_archive
from container_scanner.image.layer_attribution import (
    attribute_artifacts,
    attribute_rel_path,
    find_layer_dirs,
    layer_commands,
)


def _layer_dirs(root: Path, layers: dict[int, dict[str, str]]) -> list[Path]:
    base = root.parent / "layers"
    for index, files in layers.items():
        dest = base / f"{index:03d}"
        dest.mkdir(parents=True, exist_ok=True)  # layers exist even when empty
        for name, content in files.items():
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
    return find_layer_dirs(root)


def _root_with_layers(tmp_path: Path) -> Path:
    root = tmp_path / "work" / "rootfs"
    root.mkdir(parents=True)
    return root


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #

def test_find_layer_dirs_sorted_and_absent(tmp_path):
    root = _root_with_layers(tmp_path)
    assert find_layer_dirs(root) == []  # no layers dir -> honest empty
    dirs = _layer_dirs(root, {2: {"a": "1"}, 0: {"b": "1"}, 1: {}})
    assert [d.name for d in dirs] == ["000", "001", "002"]


def test_attribute_topmost_writer_wins(tmp_path):
    root = _root_with_layers(tmp_path)
    dirs = _layer_dirs(root, {0: {"requirements.txt": "old"}, 1: {"requirements.txt": "new"}})
    assert attribute_rel_path("requirements.txt", dirs) == 1  # overlay: last writer
    assert attribute_rel_path("only/here.txt", _layer_dirs(root, {0: {"only/here.txt": "x"}})) == 0
    assert attribute_rel_path("missing.txt", dirs) is None
    assert attribute_rel_path("", dirs) is None


def test_layer_commands_aligned_bottom_up():
    config = {
        "history": [
            {"created_by": "COPY base /", "empty_layer": False},
            {"created_by": "ENV X=1", "empty_layer": True},  # metadata-only: no layer
            {"created_by": "RUN pip install pycrypto", "empty_layer": False},
        ]
    }
    assert layer_commands(config, 2) == ["COPY base /", "RUN pip install pycrypto"]
    assert layer_commands(config, 3)[2] is None  # more layers than history
    assert layer_commands({}, 2) is None
    assert layer_commands(None, 2) is None


def test_attribute_artifacts_none_without_layers(tmp_path):
    plain = tmp_path / "plainroot"
    plain.mkdir()
    (plain / "requirements.txt").write_text("x==1\n")
    assert attribute_artifacts(plain, packages=[{"name": "x", "manifest": str(plain / "requirements.txt")}]) is None


def test_attribute_artifacts_annotation(tmp_path):
    root = _root_with_layers(tmp_path)
    _layer_dirs(root, {0: {"requirements.txt": "cryptography==41.0.7"}, 1: {".env": "-----BEGIN RSA PRIVATE KEY-----"}})
    packages = [{"name": "cryptography", "manifest": str(root / "requirements.txt")}]
    secrets = [{"kind": "pem-private-key", "path": ".env", "line_number": 1}]
    binaries = [{"name": "libcrypto.so.3", "path": "usr/lib/libcrypto.so.3"}]  # in NO layer
    report = attribute_artifacts(root, packages=packages, binaries=binaries, secrets=secrets, layer_ids=["aaa", "bbb"])
    assert packages[0]["introduced_by_layer"] == 0
    assert secrets[0]["introduced_by_layer"] == 1
    assert binaries[0]["introduced_by_layer"] is None
    assert report["unattributed_artifacts"] == 1
    assert report["layers"][0]["packages"] == ["cryptography"]
    assert report["layers"][1]["secrets"] == ["pem-private-key:.env"]
    assert report["layers"][0]["layer"] == "aaa"
    assert report["layer_count"] == 2


# --------------------------------------------------------------------------- #
# end-to-end through a real docker-save archive
# --------------------------------------------------------------------------- #

def _write_layer_tar(path: Path, files: dict[str, str]) -> None:
    staging = path.parent / f"{path.stem}-src"
    for name, content in files.items():
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    with tarfile.open(path, "w") as handle:
        handle.add(staging, arcname=".")


def _make_archive(tmp_path: Path) -> Path:
    layer0 = tmp_path / "layer0.tar"
    layer1 = tmp_path / "layer1.tar"
    layer2 = tmp_path / "layer2.tar"
    _write_layer_tar(layer0, {"usr/lib/libssl.so.3": "base-ssl", "etc/os-release": 'ID=debian\nVERSION_ID="12"\n'})
    _write_layer_tar(
        layer1,
        {"requirements.txt": "cryptography==41.0.7\n", "usr/lib/libcrypto.so.3": "crypto-lib"},
    )
    _write_layer_tar(
        layer2,
        {".env": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n",
         "requirements.txt": "pycrypto==2.6.1\ncryptography==41.0.7\n"},
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "architecture": "amd64",
                "os": "linux",
                "history": [
                    {"created_by": "base image debian:12", "empty_layer": False},
                    {"created_by": "ENV PYTHONDONTWRITEBYTECODE=1", "empty_layer": True},
                    {"created_by": "RUN pip install cryptography", "empty_layer": False},
                    {"created_by": "COPY secrets .", "empty_layer": False},
                ],
            }
        )
    )
    archive = tmp_path / "image.tar"
    manifest = [{"Config": "config.json", "RepoTags": ["local/app:1"], "Layers": ["layer0.tar", "layer1.tar", "layer2.tar"]}]
    with tarfile.open(archive, "w") as handle:
        handle.add(config, arcname="config.json")
        handle.add(layer0, arcname="layer0.tar")
        handle.add(layer1, arcname="layer1.tar")
        handle.add(layer2, arcname="layer2.tar")
        info = tarfile.TarInfo("manifest.json")
        blob = json.dumps(manifest).encode()
        info.size = len(blob)
        handle.addfile(info, __import__("io").BytesIO(blob))
    return archive


def test_scan_image_attributes_layers_end_to_end(tmp_path):
    archive = _make_archive(tmp_path)
    extracted = extract_image_archive(archive, tmp_path / "work")
    scanner = ContainerScanner()
    result = scanner.scan_filesystem(extracted.root)  # artifacts via the normal path
    from container_scanner.image.layer_attribution import attribute_artifacts

    report = attribute_artifacts(
        extracted.root,
        packages=result["packages"],
        binaries=result["binaries"],
        secrets=result["secrets"],
        layer_ids=extracted.layers,
        config=extracted.config,
    )
    assert report is not None and report["layer_count"] == 3
    by_name = {pkg["name"]: pkg for pkg in result["packages"]}
    # requirements.txt rewritten in layer 2 -> all pip packages credit layer 2
    assert by_name["pycrypto"]["introduced_by_layer"] == 2
    assert by_name["cryptography"]["introduced_by_layer"] == 2
    # libssl from the base layer, libgcrypt from layer 1
    by_path = {binary["path"]: binary for binary in result["binaries"]}
    assert by_path["usr/lib/libssl.so.3"]["introduced_by_layer"] == 0
    assert by_path["usr/lib/libcrypto.so.3"]["introduced_by_layer"] == 1
    # the secret came with the last COPY
    assert result["secrets"][0]["introduced_by_layer"] == 2
    # build commands mapped bottom-up, metadata-only history entry skipped
    commands = [layer["command"] for layer in report["layers"]]
    assert commands == ["base image debian:12", "RUN pip install cryptography", "COPY secrets ."]


def test_scan_image_exposes_attribution(tmp_path):
    archive = _make_archive(tmp_path)
    result = ContainerScanner().scan_image(str(archive))
    assert result["target_kind"] == "docker-archive"
    attribution = result["layer_attribution"]
    assert attribution["layer_count"] == 3
    assert attribution["layers"][2]["secrets"]
    assert all("introduced_by_layer" in pkg for pkg in result["packages"])


def test_filesystem_scan_has_no_attribution(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==41.0.7\n")
    result = ContainerScanner().scan_filesystem(tmp_path)
    assert "layer_attribution" not in result  # unknowable for a plain rootfs
