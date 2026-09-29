#!/usr/bin/env python3
"""Render Kubernetes release manifests with immutable OCI image digests.

The repository does not publish a release registry image, so it must not invent
a digest in the checked-in templates. This command is the release boundary:
operators supply the digests returned by the registry after the exact build,
and the rendered directory is the only directory approved for ``kubectl
apply``. It refuses tags, placeholders and short/non-hex values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def validate(name: str, value: str) -> str:
    if not DIGEST.fullmatch(value.lower()):
        raise ValueError(f"{name} must be exactly 64 lowercase/uppercase hex characters from an OCI sha256 digest")
    return value.lower()


def validate_registry(value: str) -> str:
    """Validate an image repository prefix, not a tag or digest.

    A registry may include a host port (``localhost:5000/team``), so only a
    colon in the final path component is treated as a tag. Schemes, digests,
    whitespace and a trailing slash are rejected because they produce an
    invalid or ambiguous rendered image reference.
    """
    value = value.strip()
    final_component = value.rsplit("/", 1)[-1]
    if (
        not value
        or value.startswith(("http://", "https://"))
        or "@" in value
        or any(character.isspace() for character in value)
        or value.endswith("/")
        or ":" in final_component
    ):
        raise ValueError("--registry must be an OCI repository prefix, not a URL, tag, digest or trailing slash")
    return value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--api-digest", required=True)
    ap.add_argument("--worker-digest", required=True)
    ap.add_argument("--neo4j-digest", required=True)
    ap.add_argument("--registry", required=True, help="immutable registry prefix, e.g. ghcr.io/org")
    ap.add_argument("--source", type=Path, default=ROOT / "k8s")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        digests = {
            "api": validate("--api-digest", args.api_digest),
            "worker": validate("--worker-digest", args.worker_digest),
            "neo4j": validate("--neo4j-digest", args.neo4j_digest),
        }
        registry = validate_registry(args.registry)
    except ValueError as exc:
        ap.error(str(exc))
    source = args.source.resolve()
    output = args.out.resolve()
    if not source.is_dir():
        ap.error(f"source directory does not exist or is not a directory: {args.source}")
    if output == source or source in output.parents:
        ap.error("--out must not be the source directory or a directory inside it; refusing destructive self-render")
    if args.out.exists():
        shutil.rmtree(args.out)
    shutil.copytree(source, args.out)

    replacements = {
        "cryptoscan-api": f"{registry}/cryptoscan-api@sha256:{digests['api']}",
        "cryptoscan-worker": f"{registry}/cryptoscan-worker@sha256:{digests['worker']}",
        "neo4j": f"{registry}/neo4j@sha256:{digests['neo4j']}",
    }
    mutable = []
    for path in args.out.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        for image, immutable in replacements.items():
            text = re.sub(rf"(?m)(^\s*image:\s*){re.escape(image)}(?::[^\s]+)?", rf"\g<1>{immutable}", text)
        path.write_text(text, encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            if re.match(r"^\s*image:\s*", line) and "@sha256:" not in line:
                mutable.append(f"{path.relative_to(args.out)}:{line_no}")
    if mutable:
        raise SystemExit("rendered manifests still contain mutable image references: " + ", ".join(mutable))
    manifest = {
        "schema": "cryptoscan.immutable-image-release/1",
        "rendered_at": datetime.now(timezone.utc).isoformat(),
        "registry": registry,
        "digests": digests,
        "source_sha256": hashlib.sha256("".join(sorted(str(p) + sha256(p) for p in args.source.rglob("*.yaml"))).encode()).hexdigest(),
    }
    (args.out / "release-image-lock.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Rendered immutable manifests: {args.out}")
    print(json.dumps(manifest, indent=2))
    return 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
