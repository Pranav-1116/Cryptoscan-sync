"""Extract Docker-save and OCI image archives into a merged rootfs.

Hostile-input hardening (§4.1): operator-supplied archives are untrusted
input. Extraction is BOUNDED (member count, per-member bytes, total bytes)
and FAIL-CLOSED — a member that tries to escape the extraction root, a
symlink pointing outside it, a device/FIFO member or an archive that exceeds
a resource limit refuses the WHOLE archive. The previous behavior (skip the
unsafe member, keep extracting) could silently produce a partial rootfs that
was then scanned as if complete.
"""

from __future__ import annotations

import json
import logging
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from container_scanner.image.layer_merger import merge_layers

logger = logging.getLogger(__name__)


class HostileArchiveError(ValueError):
    """The archive violates extraction safety rules or resource bounds.

    Raised instead of extracting a partial rootfs: the caller reports a
    refused scan, never a silently-incomplete one.
    """


#: pre-check on the archive file itself before any member is read
MAX_ARCHIVE_BYTES = 32 * 1024**3


@dataclass(frozen=True)
class ExtractionLimits:
    """Resource bounds for one extraction (defense against archive bombs)."""

    max_members: int = 20_000
    max_member_bytes: int = 8 * 1024**3
    max_total_bytes: int = 16 * 1024**3


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


def extract_image_archive(
    archive: str | Path,
    dest: str | Path,
    *,
    limits: ExtractionLimits | None = None,
) -> ExtractedImage:
    """
    Unpack a `docker save` tarball or an OCI image layout archive.

    Layers are applied bottom-to-top with Docker whiteout semantics. A
    hostile archive (path traversal, escaping symlinks, special files,
    member/size flood) is refused whole with :class:`HostileArchiveError`.
    """
    archive_path = Path(archive)
    if not archive_path.is_file():
        raise FileNotFoundError(f"image archive not found: {archive_path}")
    archive_bytes = archive_path.stat().st_size
    if archive_bytes > MAX_ARCHIVE_BYTES:
        raise HostileArchiveError(f"archive is {archive_bytes} bytes (limit {MAX_ARCHIVE_BYTES})")

    work = Path(dest)
    work.mkdir(parents=True, exist_ok=True)
    unpacked = work / "archive"
    layers_dir = work / "layers"
    rootfs = work / "rootfs"
    unpacked.mkdir(exist_ok=True)
    layers_dir.mkdir(exist_ok=True)

    with tarfile.open(archive_path, mode="r:*") as handle:
        _safe_extract(handle, unpacked, limits=limits)

    manifest_path = unpacked / "manifest.json"
    index_path = unpacked / "index.json"
    if manifest_path.is_file():
        return _extract_docker_save(unpacked, layers_dir, rootfs, archive_path)
    if index_path.is_file():
        return _extract_oci_layout(unpacked, layers_dir, rootfs, archive_path)
    raise ValueError(f"{archive_path} is not a docker-save or OCI image archive")


def _extract_docker_save(unpacked: Path, layers_dir: Path, rootfs: Path, archive_path: Path) -> ExtractedImage:
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


def _extract_oci_layout(unpacked: Path, layers_dir: Path, rootfs: Path, archive_path: Path) -> ExtractedImage:
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


def _confined(dest: Path, name: str, *, what: str = "member") -> Path:
    """Normalize a member name to a path strictly under ``dest``.

    Absolute names and any ``..`` component refuse the archive. The final
    ``resolve()`` also follows symlinks created by EARLIER members of the
    same archive, so a write through a planted link cannot land outside the
    extraction root.
    """
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts:
        raise HostileArchiveError(f"unsafe {what} path: {name!r}")
    rel = Path(*parts) if parts else Path(".")
    target = dest / rel
    try:
        target.resolve().relative_to(dest)
    except (ValueError, OSError):
        raise HostileArchiveError(f"{what} resolves outside the extraction root: {name!r}") from None
    # a path whose PARENT components pass through a symlink (planted by an
    # earlier member) is an escape vector — refuse instead of writing through
    for parent in rel.parents:
        if (dest / parent).is_symlink():
            raise HostileArchiveError(f"{what} writes through a symlinked directory: {name!r}")
    return target


def _safe_extract(handle: tarfile.TarFile, dest: Path, *, limits: ExtractionLimits | None = None) -> None:
    """Bounded, fail-closed extraction of one tar stream.

    Refuses (never skips) anything hostile: traversal, escaping symlinks,
    device/FIFO members, member floods and size bombs. Byte caps are enforced
    while STREAMING member content, so a compressed bomb is stopped mid-write
    instead of after filling the disk.
    """
    limits = limits or ExtractionLimits()
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()

    members = handle.getmembers()
    if len(members) > limits.max_members:
        raise HostileArchiveError(f"archive has {len(members)} members (limit {limits.max_members})")

    total = 0
    for member in members:
        target = _confined(dest, member.name)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if member.issym():
            # image-root-absolute link targets (e.g. "/usr/bin") are the
            # docker convention; they are re-anchored inside the root.
            link = member.linkname.lstrip("/")
            if ".." in PurePosixPath(link).parts:
                raise HostileArchiveError(
                    f"symlink escapes the extraction root: {member.name!r} -> {member.linkname!r}"
                )
            if target.exists() or target.is_symlink():
                target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(link, target)
            continue
        if member.islnk():
            link_target = _confined(dest, member.linkname, what="hardlink target")
            if not link_target.exists():
                raise HostileArchiveError(f"hardlink to missing member: {member.name!r} -> {member.linkname!r}")
            if target.exists() or target.is_symlink():
                target.unlink()
            os.link(link_target, target)
            continue
        if not member.isfile():
            raise HostileArchiveError(f"refusing special member: {member.name!r} (type {member.type!r})")
        if member.size > limits.max_member_bytes:
            raise HostileArchiveError(
                f"member exceeds per-member limit: {member.name!r} ({member.size} bytes > {limits.max_member_bytes})"
            )
        total += member.size
        if total > limits.max_total_bytes:
            raise HostileArchiveError(
                f"archive exceeds total extraction limit ({limits.max_total_bytes} bytes) at {member.name!r}"
            )
        src = handle.extractfile(member)
        if src is None:  # pragma: no cover - member listed but unreadable
            raise HostileArchiveError(f"cannot read member: {member.name!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(target, "wb") as out:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > limits.max_member_bytes:  # header lied about size
                    raise HostileArchiveError(f"member wrote beyond its declared size: {member.name!r}")
                out.write(chunk)
        if member.mode:
            try:
                os.chmod(target, member.mode & 0o777)
            except OSError:  # pragma: no cover - mode is best-effort
                pass


def iter_layer_paths(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.iterdir() if path.is_dir())
