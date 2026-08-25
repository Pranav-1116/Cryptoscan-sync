"""Extract Docker image layers from a save/export archive."""

from __future__ import annotations

from pathlib import Path

from container_scanner.image.archive import ExtractedImage, extract_image_archive


def extract_layers(archive: str | Path, dest: str | Path) -> ExtractedImage:
    return extract_image_archive(archive, dest)


def extract_and_merge(archive: str | Path, dest: str | Path) -> Path:
    extracted = extract_image_archive(archive, dest)
    return extracted.root
