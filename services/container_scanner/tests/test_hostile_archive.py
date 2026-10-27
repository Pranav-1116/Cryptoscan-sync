"""Hostile-archive hardening (§4.1): extraction is bounded and fail-closed.

An operator-supplied image archive is untrusted input. Traversal members,
escaping symlinks, device/FIFO members, member floods and compressed size
bombs refuse the WHOLE archive — never a silently-partial rootfs that would
then be scanned as if complete.
"""

from __future__ import annotations

import io
import os
import tarfile
import time
from pathlib import Path

import pytest

from container_scanner.image.archive import (
    ExtractionLimits,
    HostileArchiveError,
    _safe_extract,
    extract_image_archive,
)


def _tar_bytes(members: list[tuple[str, bytes]], *, mode: str = "w") -> bytes:
    """Build an in-memory tar with the given (name, content) regular files."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as handle:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            handle.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _add_symlink(handle: tarfile.TarFile, name: str, linkname: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = linkname
    handle.addfile(info)


def _add_special(handle: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.CHRTYPE
    info.devmajor = 1
    info.devminor = 3
    handle.addfile(info)


def _open_tar(raw: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")


def test_path_traversal_refuses_the_whole_archive(tmp_path: Path):
    raw = _tar_bytes([("../../etc/evil.conf", b"owned")])
    dest = tmp_path / "out"
    with pytest.raises(HostileArchiveError, match="unsafe member path"):
        _safe_extract(_open_tar(raw), dest)
    # nothing was written, inside or outside the destination
    assert not (tmp_path / "etc" / "evil.conf").exists()
    assert not list(dest.rglob("*")) if dest.exists() else True


def test_write_through_symlink_refuses_the_archive(tmp_path: Path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as handle:
        _add_symlink(handle, "escape", "/tmp")
        info = tarfile.TarInfo("escape/pwned")
        payload = b"owned"
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    dest = tmp_path / "out"
    # the absolute link is re-anchored inside the root (docker convention),
    # but writing a member THROUGH a symlinked directory is refused outright
    with pytest.raises(HostileArchiveError, match="symlinked directory"):
        _safe_extract(_open_tar(buffer.getvalue()), dest)
    assert not Path("/tmp/pwned").exists()
    # and nothing landed inside the re-anchored target either
    assert not (dest / "tmp" / "pwned").exists()


def test_escaping_symlink_target_refuses_the_archive(tmp_path: Path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as handle:
        _add_symlink(handle, "evil", "../../etc/passwd")
    with pytest.raises(HostileArchiveError, match="symlink escapes"):
        _safe_extract(_open_tar(buffer.getvalue()), tmp_path / "out")


def test_device_member_refuses_the_archive(tmp_path: Path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as handle:
        _add_special(handle, "dev/mem")
    with pytest.raises(HostileArchiveError, match="special member"):
        _safe_extract(_open_tar(buffer.getvalue()), tmp_path / "out")


def test_image_root_symlink_is_allowed_and_reanchored(tmp_path: Path):
    """Legit docker pattern: absolute link targets are image-root-absolute."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as handle:
        info = tarfile.TarInfo("usr/bin/")
        info.type = tarfile.DIRTYPE
        handle.addfile(info)
        _add_symlink(handle, "bin", "/usr/bin")
    dest = tmp_path / "out"
    _safe_extract(_open_tar(buffer.getvalue()), dest)
    assert (dest / "bin").is_symlink()
    assert os.readlink(dest / "bin") == "usr/bin"


def test_compressed_size_bomb_is_stopped_mid_write(tmp_path: Path):
    """A gzip tar whose single member inflates far past the total cap."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        info = tarfile.TarInfo("bomb.bin")
        info.size = 200 * 1024 * 1024  # 200 MB of zeros inside a tiny .gz
        handle.addfile(info, io.BytesIO(bytes(200 * 1024 * 1024)))
    raw = buffer.getvalue()
    assert len(raw) < 5 * 1024 * 1024  # the bomb is small on disk

    dest = tmp_path / "out"
    limits = ExtractionLimits(max_members=100, max_member_bytes=64 * 1024 * 1024, max_total_bytes=64 * 1024 * 1024)
    started = time.monotonic()
    with pytest.raises(HostileArchiveError, match="per-member limit"):
        _safe_extract(_open_tar(raw), dest, limits=limits)
    # bounded in time AND in bytes written before the refusal
    assert time.monotonic() - started < 30
    assert not (dest / "bomb.bin").exists() or (dest / "bomb.bin").stat().st_size <= 64 * 1024 * 1024


def test_member_flood_refuses_the_archive(tmp_path: Path):
    raw = _tar_bytes([(f"f{i}.txt", b"x") for i in range(5)])
    limits = ExtractionLimits(max_members=2, max_member_bytes=1024, max_total_bytes=4096)
    with pytest.raises(HostileArchiveError, match="members"):
        _safe_extract(_open_tar(raw), tmp_path / "out", limits=limits)


def test_total_bytes_cap_refuses_the_archive(tmp_path: Path):
    raw = _tar_bytes([("a.bin", b"a" * 100), ("b.bin", b"b" * 100), ("c.bin", b"c" * 100)])
    limits = ExtractionLimits(max_members=10, max_member_bytes=1024, max_total_bytes=150)
    with pytest.raises(HostileArchiveError, match="total extraction limit"):
        _safe_extract(_open_tar(raw), tmp_path / "out", limits=limits)


def test_wellformed_archive_extracts_unchanged(tmp_path: Path):
    raw = _tar_bytes([("etc/motd", b"hello"), ("app/libcrypto.so", b"fake-so")])
    dest = tmp_path / "out"
    _safe_extract(_open_tar(raw), dest)
    assert (dest / "etc" / "motd").read_bytes() == b"hello"
    assert (dest / "app" / "libcrypto.so").read_bytes() == b"fake-so"


def test_full_image_extraction_still_works_and_hostile_layer_refuses(tmp_path: Path):
    """End to end: a well-formed docker-save archive extracts; the same
    archive with a traversal layer is refused before any scan happens."""
    import json

    def make_archive(hostile: bool) -> Path:
        layer = tmp_path / "layer.tar"
        with tarfile.open(layer, "w") as handle:
            if hostile:
                info = tarfile.TarInfo("../../escape.txt")
                payload = b"owned"
                info.size = len(payload)
                handle.addfile(info, io.BytesIO(payload))
            else:
                info = tarfile.TarInfo("usr/lib/libcrypto.so.3")
                payload = b"fake-libcrypto"
                info.size = len(payload)
                handle.addfile(info, io.BytesIO(payload))
        config = tmp_path / "config.json"
        config.write_text(json.dumps({"architecture": "amd64", "os": "linux"}))
        manifest = tmp_path / "manifest.json"
        manifest.write_text(
            json.dumps([{"Config": "config.json", "RepoTags": ["cryptoscan/hostile:latest"], "Layers": ["layer.tar"]}])
        )
        archive = tmp_path / ("hostile.tar" if hostile else "image.tar")
        with tarfile.open(archive, "w") as handle:
            for f in (layer, config, manifest):
                handle.add(f, arcname=f.name)
        return archive

    good = extract_image_archive(make_archive(hostile=False), tmp_path / "extract-good")
    assert (good.root / "usr" / "lib" / "libcrypto.so.3").exists()

    with pytest.raises(HostileArchiveError, match="unsafe member path"):
        extract_image_archive(make_archive(hostile=True), tmp_path / "extract-bad")
    assert not (tmp_path / "escape.txt").exists()
