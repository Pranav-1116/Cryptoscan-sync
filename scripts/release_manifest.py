#!/usr/bin/env python3
"""Emit a release manifest: what shipped, and the sha256 of every file in it.

``cryptoscan verify-installation --manifest`` compares an installed tree against this
document. The loop has to close on both sides: a verifier with nothing to verify is a
command that prints a green tick for free.

What it does, and what it refuses to imply:

* **``--sign-key`` signs the manifest** with an Ed25519 key (``shared_models.release_signature``
  — canonical JSON over every member except ``signature``). Without the flag the manifest
  carries ``"signature": null`` and ``verify-installation`` reports ``MANIFEST_UNSIGNED``;
  a manifest that merely *said* it was signed because a field existed would be worse than
  an honest null. ``--generate-key DIR`` makes a local key pair so a deployment can sign its
  own releases; that is not a ceremony, and a release key that matters belongs in an HSM;
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
    parser.add_argument("--sign-key", dest="sign_key", default=None,
                        help="Ed25519 private key (PEM) to sign the manifest with")
    parser.add_argument("--generate-key", dest="generate_key", default=None, metavar="DIR",
                        help="create an Ed25519 key pair in DIR and exit")
    args = parser.parse_args(argv)

    if args.generate_key:
        from shared_models import release_signature

        created = release_signature.generate_keypair(args.generate_key)
        for key, value in created.items():
            print(f"{key:<12} {value}")
        return 0

    root = Path(args.root).resolve()
    paths = [Path(p) for p in (args.paths or DEFAULT_PATHS)]
    manifest = build_manifest(root, paths, version=args.version)
    if not manifest["files"]:
        print("release-manifest: no files found under the given paths — refusing to emit an "
              "empty manifest that would verify anything", file=sys.stderr)
        return 2
    if args.sign_key:
        from shared_models import release_signature

        try:
            key = release_signature.load_private_key(args.sign_key)
        except Exception as exc:  # noqa: BLE001 — an unreadable key is a refusal, not a crash
            print(f"release-manifest: cannot read signing key: {exc}", file=sys.stderr)
            return 2
        # every member except `signature` is covered, so the limits are rewritten *before*
        # signing; rewriting them afterwards would produce a manifest that fails its own check
        manifest["limits"] = [
            limit.replace(
                "signature is null: this manifest is not signed, so verify-installation reports "
                "MANIFEST_UNSIGNED and cannot claim the manifest itself is authentic",
                "signed by an Ed25519 key: the signature proves the holder of that key signed "
                "these bytes, and proves nothing about whether that key is the one you meant "
                "to trust",
            )
            for limit in manifest["limits"]
        ]
        manifest.pop("signature", None)
        manifest["signature"] = release_signature.sign_document(manifest, key)

    text = json.dumps(manifest, indent=2, sort_keys=False)
    if args.output:
        Path(args.output).write_text(text + "\n")
        print(f"wrote {args.output} ({len(manifest['files'])} files, "
              f"{'signed ' + manifest['signature']['key_id'] if manifest.get('signature') else 'unsigned'})")
    else:
        print(text)
    if manifest["missing"]:
        print("missing paths: " + ", ".join(manifest["missing"]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
