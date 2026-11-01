"""Resolve a container image reference to a merged rootfs."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from container_scanner.image.archive import ExtractedImage, extract_image_archive

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = int(os.environ.get("CRYPTOSCAN_CONTAINER_PULL_TIMEOUT", "120"))


class ImagePullError(RuntimeError):
    """Raised when an image cannot be pulled or unpacked."""


def resolve_image(
    reference: str,
    *,
    workdir: str | Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ExtractedImage:
    """
    Turn an image reference into a merged filesystem.

    Accepts:
      - existing unpacked directory
      - docker-save / OCI `.tar` / `.tar.gz` archive
      - registry reference pulled via docker, skopeo, or podman when installed
    """
    raw = (reference or "").strip()
    if not raw:
        raise ImagePullError("image reference is empty")

    owns_workdir = workdir is None
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="cryptoscan-image-"))
    base.mkdir(parents=True, exist_ok=True)
    try:
        path = Path(raw)
        if path.is_dir():
            return ExtractedImage(root=path, source="filesystem", reference=str(path))
        if path.is_file():
            return extract_image_archive(path, base / "extracted")
        archive = _pull_to_archive(raw, base / "image.tar", timeout=timeout)
        return extract_image_archive(archive, base / "extracted")
    except Exception:
        if owns_workdir:
            shutil.rmtree(base, ignore_errors=True)
        raise


def _pull_to_archive(reference: str, archive: Path, *, timeout: int) -> Path:
    errors: list[str] = []
    for name, fn in (
        ("skopeo", _pull_skopeo),
        ("docker", _pull_docker),
        ("podman", _pull_podman),
    ):
        binary = shutil.which(name)
        if not binary:
            errors.append(f"{name} not installed")
            continue
        try:
            fn(binary, reference, archive, timeout)
            if archive.is_file() and archive.stat().st_size > 0:
                logger.info("image_pulled", extra={"tool": name, "reference": reference})
                return archive
            errors.append(f"{name} produced an empty archive")
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            logger.info("image_pull_tool_failed", extra={"tool": name, "error": str(exc)})
    raise ImagePullError(
        f"cannot pull {reference!r}; install docker, skopeo, or podman, "
        f"or pass a docker-save archive. Attempts: {'; '.join(errors)}"
    )


#: An image reference, per the distribution spec: lowercase path components,
#: optional registry:port, optional :tag or @digest. A reference that starts with
#: "-" is an *option* to docker/podman/skopeo (`--config`, `-a`), so the grammar
#: is enforced before any of them sees it.
_REFERENCE = re.compile(
    r"^(?:[a-z0-9][a-z0-9.\-]*(?::\d+)?/)?(?:[a-z0-9._\-/]+)(?::[\w.\-]{1,128})?"
    r"(?:@sha256:[0-9a-f]{64})?$"
)


def _validated(reference: str) -> str:
    if not _REFERENCE.match(reference or "") or reference.startswith("-"):
        raise ValueError(f"not an image reference: {reference[:80]!r}")
    return reference


def _pull_skopeo(binary: str, reference: str, archive: Path, timeout: int) -> None:
    reference = _validated(reference)
    src = reference if "://" in reference else f"docker://{reference}"
    _run([binary, "copy", "--quiet", src, f"docker-archive:{archive}"], timeout)


def _pull_docker(binary: str, reference: str, archive: Path, timeout: int) -> None:
    reference = _validated(reference)
    _run([binary, "pull", "--quiet", "--", reference], timeout)
    _run([binary, "save", "-o", str(archive), reference], timeout)


def _pull_podman(binary: str, reference: str, archive: Path, timeout: int) -> None:
    reference = _validated(reference)
    _run([binary, "pull", "--quiet", "--", reference], timeout)
    _run([binary, "save", "-o", str(archive), reference], timeout)


def _run(command: list[str], timeout: int) -> None:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:400]
        raise ImagePullError(f"{' '.join(command)} failed: {detail or result.returncode}")
