"""Merge extracted container layers into a single filesystem view."""

from __future__ import annotations

import shutil
from pathlib import Path


WHITEOUT_PREFIX = ".wh."
OPAQUE = ".wh..wh..opq"


def merge_layers(layer_dirs: list[Path | str], dest: Path | str) -> Path:
    """
    Overlay layers from bottom to top into dest.

    Docker whiteouts:
      - `.wh.<name>` deletes `<name>` from the merged tree
      - `.wh..wh..opq` makes the current directory opaque (clear previous files)
    """
    target = Path(dest)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    for layer in layer_dirs:
        _apply_layer(Path(layer), target)
    return target


def _apply_layer(layer: Path, dest: Path) -> None:
    if not layer.exists():
        return
    for src in layer.rglob("*"):
        rel = src.relative_to(layer)
        name = src.name
        parent = dest / rel.parent
        if name == OPAQUE:
            if parent.exists():
                for child in parent.iterdir():
                    if child.name.startswith(".wh."):
                        continue
                    if child.is_dir():
                        shutil.rmtree(child)
                    else:
                        child.unlink(missing_ok=True)
            continue
        if name.startswith(WHITEOUT_PREFIX):
            removed = parent / name[len(WHITEOUT_PREFIX) :]
            if removed.is_dir():
                shutil.rmtree(removed, ignore_errors=True)
            elif removed.exists():
                removed.unlink()
            continue
        parent.mkdir(parents=True, exist_ok=True)
        out = dest / rel
        if src.is_dir():
            out.mkdir(exist_ok=True)
        else:
            shutil.copy2(src, out)
