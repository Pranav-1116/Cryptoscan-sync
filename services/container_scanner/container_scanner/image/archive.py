"""Extract Docker-save and OCI image archives into a merged rootfs."""

from __future__ import annotations

import json
import logging
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from container_scanner.image.layer_merger import merge_layers

logger = logging.getLogger(__name__)


@dataclass
class ExtractedImage:
    root: Path
    source: str
    reference: str
    tags: list[str] = field(default_factory=list)
    layers: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "source": self.source,
            "reference": self.reference,
            "tags": list(self.tags),
            "layers": list(self.layers),
            "config": self.config,
        }


def extract_image_archive(archive: str | Path, dest: str | Path) -> ExtractedImage:
    """
    Unpack a `docker save` tarball or an OCI image layout archive.

    Layers are applied bottom-to-top with Docker whiteout semantics.
    Path-traversal members are skipped.
    """
    archive_path = Path(archive)
    if not archive_path.is_file():
        raise FileNotFoundError(f"image archive not found: {archive_path}")

    work = Path(dest)
    work.mkdir(parents=True, exist_ok=True)
    unpacked = work / "archive"
    layers_dir = work / "layers"
    rootfs = work / "rootfs"
    unpacked.mkdir(exist_ok=True)
    layers_dir.mkdir(exist_ok=True)

    with tarfile.open(archive_path, mode="r:*") as handle:
        _safe_extract(handle, unpacked)

    manifest_path = unpacked / "manifest.json"
    index_path = unpacked / "index.json"
    if manifest_path.is_file():
        return _extract_docker_save(unpacked, layers_dir, rootfs, archive_path)
    if index_path.is_file():
        return _extract_oci_layout(unpacked, layers_dir, rootfs, archive_path)
    raise ValueError(f"{archive_path} is not a docker-save or OCI image archive")


def _extract_docker_save(
    unpacked: Path, layers_dir: Path, rootfs: Path, archive_path: Path
) -> ExtractedImage:
    manifests = json.loads((unpacked / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("docker-save manifest.json is empty")
    entry = manifests[0]
    layer_names = [str(item) for item in (entry.get("Layers") or [])]
    if not layer_names:
        raise ValueError("docker-save archive has no layers")

    extracted_layers: list[Path] = []
    for index, name in enumerate(layer_names):
        layer_src = unpacked / name
        if not layer_src.exists():
            raise FileNotFoundError(f"missing layer {name}")
        dest = layers_dir / f"{index:03d}"
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(layer_src, mode="r:*") as handle:
            _safe_extract(handle, dest)
        extracted_layers.append(dest)

    merge_layers(extracted_layers, rootfs)
    config: dict[str, Any] = {}
    config_name = entry.get("Config")
    if config_name and (unpacked / str(config_name)).is_file():
        try:
            config = json.loads((unpacked / str(config_name)).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}
    tags = [str(tag) for tag in (entry.get("RepoTags") or []) if tag]
    return ExtractedImage(
        root=rootfs,
        source="docker-archive",
        reference=tags[0] if tags else archive_path.name,
        tags=tags,
        layers=layer_names,
        config=_public_config(config),
    )


def _extract_oci_layout(
    unpacked: Path, layers_dir: Path, rootfs: Path, archive_path: Path
) -> ExtractedImage:
    index = json.loads((unpacked / "index.json").read_text(encoding="utf-8"))
    manifests = index.get("manifests") or []
    if not manifests:
        raise ValueError("OCI index.json has no manifests")
    digest = str((manifests[0].get("digest") or "").split(":", 1)[-1])
    manifest_path = unpacked / "blobs" / "sha256" / digest
    if not manifest_path.is_file():
        raise FileNotFoundError(f"OCI manifest blob missing: {digest}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    extracted_layers: list[Path] = []
    layer_ids: list[str] = []
    for index, layer in enumerate(manifest.get("layers") or []):
        layer_digest = str((layer.get("digest") or "").split(":", 1)[-1])
        blob = unpacked / "blobs" / "sha256" / layer_digest
        if not blob.is_file():
            raise FileNotFoundError(f"OCI layer blob missing: {layer_digest}")
        dest = layers_dir / f"{index:03d}"
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(blob, mode="r:*") as handle:
            _safe_extract(handle, dest)
        extracted_layers.append(dest)
        layer_ids.append(layer_digest)
    if not extracted_layers:
        raise ValueError("OCI manifest has no layers")
    merge_layers(extracted_layers, rootfs)
    config: dict[str, Any] = {}
    config_digest = str(((manifest.get("config") or {}).get("digest") or "").split(":", 1)[-1])
    config_blob = unpacked / "blobs" / "sha256" / config_digest
    if config_blob.is_file():
        try:
            config = json.loads(config_blob.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}
    tags = []
    annotations = manifests[0].get("annotations") or {}
    if annotations.get("org.opencontainers.image.ref.name"):
        tags.append(str(annotations["org.opencontainers.image.ref.name"]))
    return ExtractedImage(
        root=rootfs,
        source="oci-archive",
        reference=tags[0] if tags else archive_path.name,
        tags=tags,
        layers=layer_ids,
        config=_public_config(config),
    )


def _public_config(config: dict[str, Any]) -> dict[str, Any]:
    cfg = config.get("config") if isinstance(config.get("config"), dict) else {}
    history = [
        {"created_by": str(entry.get("created_by") or "")[:200], "empty_layer": bool(entry.get("empty_layer"))}
        for entry in (config.get("history") or [])
        if isinstance(entry, dict)
    ]
    return {
        "architecture": config.get("architecture"),
        "os": config.get("os"),
        "env": list(cfg.get("Env") or []),
        "entrypoint": list(cfg.get("Entrypoint") or []),
        "cmd": list(cfg.get("Cmd") or []),
        "working_dir": cfg.get("WorkingDir"),
        "user": cfg.get("User"),
        "history": history,
    }


def _safe_extract(handle: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in handle.getmembers():
        name = member.name.lstrip("/")
        if not name or name.startswith("..") or "/../" in f"/{name}/":
            logger.warning("skipping_unsafe_tar_member", extra={"name": member.name})
            continue
        target = (dest / name).resolve()
        try:
            target.relative_to(dest)
        except ValueError:
            logger.warning("skipping_tar_slip", extra={"name": member.name})
            continue
        try:
            handle.extract(member, dest, set_attrs=False)
        except TypeError:
            handle.extract(member, dest)


def iter_layer_paths(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.iterdir() if path.is_dir())
