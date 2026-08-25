"""Export a registry image to a docker-save tar archive."""

from __future__ import annotations

from pathlib import Path

from container_scanner.image.puller import DEFAULT_TIMEOUT, _pull_to_archive


def export_image(
    reference: str,
    dest: str | Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> Path:
    """Run docker/skopeo/podman save into `dest` and return the archive path."""
    archive = Path(dest)
    archive.parent.mkdir(parents=True, exist_ok=True)
    return _pull_to_archive(reference, archive, timeout=timeout)


def docker_save(reference: str, dest: str | Path, *, timeout: int = DEFAULT_TIMEOUT) -> Path:
    return export_image(reference, dest, timeout=timeout)
