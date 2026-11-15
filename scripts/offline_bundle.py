#!/usr/bin/env python3
"""Build (and verify) the offline artifact manifest for a bank air-gap install.

An isolated bank network must be installable with NO permanent external
connection — every artifact that would otherwise be fetched from the
internet is staged up front and verified before installation. This script
makes that list mechanical instead of a memory exercise:

``manifest``  records what must be staged:
  * container images referenced by the compose stacks (external runtimes)
  * the first-party images this repo builds (``.docker/``)
  * the pinned Python dependency set (requirements.lock.txt)
  * the pinned frontend dependency set (frontend/package-lock.json)
  * the install-time files (k8s manifests, Helm chart, the air-gap runbook)

``verify``  proves a staged directory actually contains them: every
repo-owned file is checked by SHA-256 against the manifest. Missing or
tampered artifacts are REPORTED, never quietly skipped — an air-gap install
that half-succeeds is worse than one that refuses to start.

Usage::

    python3 scripts/offline_bundle.py manifest --out dist/offline-manifest.json
    python3 scripts/offline_bundle.py verify \
        --manifest dist/offline-manifest.json --staged /media/bank-usb

The runbook that consumes this: docs/admin-guide/air-gap-install.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "deploy/ha/docker-compose.yml",
]
LOCK_PY = "requirements.lock.txt"
LOCK_NPM = "frontend/package-lock.json"
AIR_GAP_RUNBOOK = "docs/admin-guide/air-gap-install.md"

_IMAGE = re.compile(r"^\s*image:\s*([^\s#]+)")
_PIN = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s#]+)")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def container_images() -> list[str]:
    """External runtime images the compose stacks pull."""
    found: set[str] = set()
    for rel in COMPOSE_FILES:
        p = ROOT / rel
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            m = _IMAGE.match(line)
            if m:
                found.add(m.group(1))
    return sorted(found)


def first_party_images() -> list[str]:
    """Images built from this repo's .docker/ tree (tagged at release)."""
    names = sorted(
        d.name for d in (ROOT / ".docker").iterdir()
        if d.is_dir() and (d / "Dockerfile").exists()
    )
    return [f"cryptoscan-{n}" for n in names]


def python_pins() -> list[str]:
    pins = []
    for line in (ROOT / LOCK_PY).read_text().splitlines():
        m = _PIN.match(line.strip())
        if m:
            pins.append(f"{m.group(1)}=={m.group(2)}")
    return pins


def repo_files() -> list[str]:
    """Install-time files shipped from the repo itself (hashed at verify)."""
    files = [LOCK_PY, LOCK_NPM, AIR_GAP_RUNBOOK]
    k8s = ROOT / "k8s"
    files += sorted(str(p.relative_to(ROOT)) for p in k8s.rglob("*.yaml"))
    chart = ROOT / "k8s" / "helm" / "cryptoscan" / "Chart.yaml"
    if chart.exists():
        files += sorted(str(p.relative_to(ROOT))
                        for p in (ROOT / "k8s" / "helm" / "cryptoscan").rglob("*")
                        if p.is_file())
    return sorted(set(files))


def manifest() -> dict:
    images = container_images()
    first = first_party_images()
    py = python_pins()
    npm_lock = json.loads((ROOT / LOCK_NPM).read_text())
    npm_count = len([k for k in npm_lock.get("packages", {}) if k])
    files = repo_files()
    return {
        "schema": "cryptoscan-offline-bundle/1",
        "note": ("Every artifact needed to install CryptoScan in an isolated "
                 "network. Repo-owned files are verified by sha256; images and "
                 "wheels are staged from the bank's mirrors — coordinates only, "
                 "never fetched by this tool."),
        "container_images_external": images,
        "container_images_first_party": first,
        "python_pins": py,
        "npm_package_count": npm_count,
        "repo_files": {
            rel: {"sha256": _sha256(ROOT / rel), "bytes": (ROOT / rel).stat().st_size}
            for rel in files
        },
    }


def verify(manifest_doc: dict, staged: Path) -> dict:
    """Check a staged directory against the manifest. Reports, never hides."""
    missing: list[str] = []
    tampered: list[dict] = []
    ok: list[str] = []
    for rel, meta in sorted(manifest_doc.get("repo_files", {}).items()):
        here = staged / rel
        if not here.exists():
            missing.append(rel)
            continue
        if _sha256(here) != meta["sha256"]:
            tampered.append({"file": rel, "expected_sha256": meta["sha256"],
                             "found_sha256": _sha256(here)})
            continue
        ok.append(rel)
    complete = not missing and not tampered
    return {
        "complete": complete,
        "verified": ok,
        "missing": missing,
        "tampered": tampered,
        "verdict": ("staged bundle matches the manifest" if complete else
                    "staged bundle is INCOMPLETE — refuse to install from it"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest", help="write the offline artifact manifest")
    m.add_argument("--out", default=str(ROOT / "dist" / "offline-manifest.json"))
    v = sub.add_parser("verify", help="verify a staged directory against a manifest")
    v.add_argument("--manifest", required=True)
    v.add_argument("--staged", required=True)
    args = ap.parse_args()

    if args.cmd == "manifest":
        doc = manifest()
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2))
        print(f"offline manifest written: {out}")
        print(f"  external images: {len(doc['container_images_external'])}")
        print(f"  first-party images: {len(doc['container_images_first_party'])}")
        print(f"  python pins: {len(doc['python_pins'])}")
        print(f"  repo files: {len(doc['repo_files'])}")
        return 0

    doc = json.loads(Path(args.manifest).read_text())
    report = verify(doc, Path(args.staged))
    print(json.dumps(report, indent=2))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
