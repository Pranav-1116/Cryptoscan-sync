"""Attribute each discovered artifact to the image layer that introduced it.

``docker save`` / OCI extraction keeps every layer's own file tree (next to
the merged rootfs), so the question "which layer brought in the vulnerable
package?" is answerable without re-pulling anything.

Semantics follow Docker overlay: when several layers contain the same path,
the **topmost** layer contributes the content the container actually sees,
so attribution walks top-down and credits the highest writer.  Files removed
by whiteouts do not exist in the merged rootfs and are therefore never
attributed.  When no layer trees exist (plain filesystem scans) the whole
report is ``None`` — an honest absence, not a zero-filled guess.

Layer *commands* come from the image config's build history (the
``created_by`` of each non-``empty_layer`` history entry, aligned bottom-up
with the layer list); a missing config yields ``None`` commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def find_layer_dirs(root: Path) -> list[Path]:
    """Ordered per-layer trees (``layers/000``, ``001``, ...) beside the rootfs."""
    layers = Path(root).parent / "layers"
    if not layers.is_dir():
        return []
    return sorted(
        (item for item in layers.iterdir() if item.is_dir() and item.name.isdigit()),
        key=lambda item: item.name,
    )


def attribute_rel_path(rel: str, layer_dirs: list[Path]) -> int | None:
    """Index of the topmost layer containing ``rel`` (overlay: last writer wins)."""
    if not rel:
        return None
    for index in range(len(layer_dirs) - 1, -1, -1):
        if (layer_dirs[index] / rel).is_file():
            return index
    return None


def _rel_of(path_value: Any, root: Path) -> str | None:
    text = str(path_value or "")
    if not text:
        return None
    path = Path(text)
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()  # already relative


def layer_commands(config: dict[str, Any] | None, layer_count: int) -> list[str | None] | None:
    """Per-layer ``created_by`` from the build history, aligned bottom-up."""
    history = (config or {}).get("history")
    if not isinstance(history, list):
        return None
    real_entries = [entry for entry in history if isinstance(entry, dict) and not entry.get("empty_layer")]
    commands: list[str | None] = []
    for index in range(layer_count):
        if index < len(real_entries):
            created_by = str(real_entries[index].get("created_by") or "").strip()
            commands.append(created_by[:160] or None)
        else:
            commands.append(None)
    return commands


def attribute_artifacts(
    root: Path,
    *,
    packages: list[dict[str, Any]] | None = None,
    binaries: list[dict[str, Any]] | None = None,
    secrets: list[dict[str, Any]] | None = None,
    layer_ids: list[str] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Annotate artifacts with ``introduced_by_layer`` and build a layer history.

    Returns None when no layer trees exist (filesystem scans, merged-only
    layouts) — attribution is then unknowable, not empty.
    """
    root = Path(root)
    layer_dirs = find_layer_dirs(root)
    if not layer_dirs:
        return None
    packages = packages or []
    binaries = binaries or []
    secrets = secrets or []
    commands = layer_commands(config, len(layer_dirs))

    unattributed = 0

    def attribute(rel: str | None) -> int | None:
        nonlocal unattributed
        index = attribute_rel_path(rel, layer_dirs) if rel else None
        if index is None:
            unattributed += 1
        return index

    per_layer: list[dict[str, Any]] = [
        {"index": index, "layer": None, "command": commands[index] if commands else None,
         "packages": [], "binaries": [], "secrets": []}
        for index in range(len(layer_dirs))
    ]
    for index, layer in enumerate(per_layer):
        if layer_ids and index < len(layer_ids):
            layer["layer"] = str(layer_ids[index])

    for pkg in packages:
        rel = _rel_of(pkg.get("manifest") or pkg.get("name"), root)
        index = attribute(rel)
        pkg["introduced_by_layer"] = index
        if index is not None:
            per_layer[index]["packages"].append(str(pkg.get("name")))
    for binary in binaries:
        index = attribute(_rel_of(binary.get("path"), root))
        binary["introduced_by_layer"] = index
        if index is not None:
            per_layer[index]["binaries"].append(str(binary.get("path") or binary.get("name")))
    for secret in secrets:
        index = attribute(_rel_of(secret.get("path"), root))
        secret["introduced_by_layer"] = index
        if index is not None:
            per_layer[index]["secrets"].append(f"{secret.get('kind')}:{secret.get('path')}")

    return {
        "layer_count": len(layer_dirs),
        "layers": per_layer,
        "unattributed_artifacts": unattributed,
        "semantics": "topmost-writer (Docker overlay); whiteouted files never attribute",
    }
