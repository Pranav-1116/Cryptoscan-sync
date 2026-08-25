from __future__ import annotations

import json
import tarfile
from pathlib import Path

from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.archive import extract_image_archive
from container_scanner.image.puller import ImagePullError, resolve_image


def _write_layer(path: Path, files: dict[str, str]) -> None:
    staging = path.parent / f"{path.stem}-src"
    for name, content in files.items():
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    with tarfile.open(path, "w") as handle:
        handle.add(staging, arcname=".")


def make_docker_save(tmp: Path) -> Path:
    layer0 = tmp / "layer0.tar"
    layer1 = tmp / "layer1.tar"
    _write_layer(
        layer0,
        {
            "usr/lib/libssl.so.3": "old",
            "etc/passwd": "root",
            "requirements.txt": "cryptography==41.0.7\n",
        },
    )
    _write_layer(
        layer1,
        {
            "usr/lib/libssl.so.3": "new",
            "etc/.wh.passwd": "",
            "requirements.txt": "pycrypto==2.6.1\ncryptography==41.0.7\n",
        },
    )
    config = tmp / "config.json"
    config.write_text(json.dumps({"architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/bin"]}}))
    archive = tmp / "image.tar"
    manifest = [
        {
            "Config": "config.json",
            "RepoTags": ["cryptoscan/demo:latest"],
            "Layers": ["layer0.tar", "layer1.tar"],
        }
    ]
    with tarfile.open(archive, "w") as handle:
        handle.add(layer0, arcname="layer0.tar")
        handle.add(layer1, arcname="layer1.tar")
        handle.add(config, arcname="config.json")
        manifest_path = tmp / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        handle.add(manifest_path, arcname="manifest.json")
    return archive


def test_extract_docker_save_applies_whiteouts(tmp_path: Path):
    archive = make_docker_save(tmp_path / "src")
    extracted = extract_image_archive(archive, tmp_path / "out")
    assert (extracted.root / "usr/lib/libssl.so.3").read_text() == "new"
    assert not (extracted.root / "etc/passwd").exists()
    assert extracted.tags == ["cryptoscan/demo:latest"]
    assert extracted.config["os"] == "linux"


def test_scan_image_from_archive_finds_local_cves(tmp_path: Path):
    archive = make_docker_save(tmp_path / "src")
    result = ContainerScanner(live_cve=False).scan_image(str(archive), workdir=tmp_path / "work")
    names = {pkg["name"] for pkg in result["packages"]}
    assert "pycrypto" in names
    cves = {item["cve"] for item in result["vulnerabilities"]}
    assert "CVE-2013-1445" in cves
    assert result["image"]["source"] == "docker-archive"


def test_resolve_missing_image_is_explicit(tmp_path: Path):
    try:
        resolve_image("ghcr.io/cryptoscan/does-not-exist:latest", workdir=tmp_path, timeout=3)
    except ImagePullError as exc:
        assert "cannot pull" in str(exc) or "not found" in str(exc).lower() or "failed" in str(exc).lower()
    else:
        raise AssertionError("expected ImagePullError")
