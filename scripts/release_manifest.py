#!/usr/bin/env python3
"""Emit a release manifest: what shipped, and the sha256 of every file in it.

``cryptoscan verify-installation --manifest`` compares an installed tree against this
document. The loop has to close on both sides: a verifier with nothing to verify is a
command that prints a green tick for free.

Two things this script deliberately does **not** do:

* it does not sign. Signing is a release-key operation outside this repository, and a
  manifest that *said* it was signed because a field existed would be worse than one that
  says ``"signature": null``. ``verify-installation`` reports ``MANIFEST_UNSIGNED`` and
  exits accordingly;
* it does not hash the repository. It hashes the named paths under ``--root``, so the
  manifest describes a deployed installation rather than a developer's working tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "cryptoscan.release-manifest/1"

DEFAULT_PATHS = (
    "services/api/api",
    "shared/shared_models/shared_models",
    "services/database/db",
    "VERSION",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path, paths: list[Path], *, version: str | None = None) -> dict:
    files: dict[str, str] = {}
    missing: list[str] = []
    for entry in paths:
        candidate = (root / entry).resolve()
        if not candidate.exists():
            missing.append(str(entry))
            continue
        if candidate.is_file():
            files[str(entry)] = sha256_file(candidate)
            continue
        for child in sorted(candidate.rglob("*")):
            if not child.is_file() or "__pycache__" in child.parts or child.suffix in {".pyc", ".pyo"}:
                continue
            files[str(child.relative_to(root))] = sha256_file(child)
    if version is None:
        version_file = root / "VERSION"
        version = version_file.read_text().strip() if version_file.exists() else None
    return {
        "schema": SCHEMA,
        "product": "cryptoscan",
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": dict(sorted(files.items())),
        "missing": missing,
        "signature": None,
        "limits": [
            "signature is null: this manifest is not signed, so verify-installation reports "
            "MANIFEST_UNSIGNED and cannot claim the manifest itself is authentic",
            "file hashes prove what is on disk now, not who built it or how",
            "__pycache__ and bytecode are excluded; they are generated, not shipped",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit a signed-nothing, hashed release manifest")
    parser.add_argument("--root", default=".", help="installation root the manifest describes")
    parser.add_argument("--path", action="append", dest="paths",
                        help="repeatable path to include (default: the shipped packages)")
    parser.add_argument("--output", "-o", default=None, help="write here instead of stdout")
    parser.add_argument("--version", default=None, help="override the VERSION file")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    paths = [Path(p) for p in (args.paths or DEFAULT_PATHS)]
    manifest = build_manifest(root, paths, version=args.version)
    if not manifest["files"]:
        print("release-manifest: no files found under the given paths — refusing to emit an "
              "empty manifest that would verify anything", file=sys.stderr)
        return 2
    text = json.dumps(manifest, indent=2, sort_keys=False)
    if args.output:
        Path(args.output).write_text(text + "\n")
        print(f"wrote {args.output} ({len(manifest['files'])} files)")
    else:
        print(text)
    if manifest["missing"]:
        print("missing paths: " + ", ".join(manifest["missing"]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
