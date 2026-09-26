#!/usr/bin/env python3
"""Generate the platform's own CycloneDX SBOM (practice what we ship).

Produces ``dist/cryptoscan-sbom.cdx.json`` covering:

- the Python dependency set (requirements.lock.txt when pinned, else the live
  environment via importlib.metadata),
- the frontend dependency set (frontend/package-lock.json),
- first-party components (the services this repo deploys).

The artifact is what procurement/security reviews ask for first — and the
platform that sells cryptographic transparency must publish its own.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CDX_SPEC = "1.5"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _purl(name: str, version: str, ns: str = "pypi") -> str:
    return f"pkg:{ns}/{re.sub(r'[^A-Za-z0-9._-]', '', name.lower())}@{version}"


def python_components() -> tuple[list[dict], bool]:
    """Python deps as CycloneDX components. Pinned lockfile preferred."""
    lock = ROOT / "requirements.lock.txt"
    pinned = False
    entries: list[tuple[str, str]] = []
    if lock.is_file():
        pinned = True
        for line in lock.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "==" in line:
                name, version = line.split("==", 1)
                entries.append((name, version))
    else:
        freeze = subprocess.run(
            [sys.executable, "-m", "pip", "freeze", "--exclude-editable"],
            capture_output=True, text=True, check=True).stdout
        for line in freeze.splitlines():
            if "==" in line:
                name, version = line.split("==", 1)
                entries.append((name, version))
    comps = [{
        "type": "library",
        "bom-ref": _purl(n, v),
        "name": n,
        "version": v,
        "purl": _purl(n, v),
    } for n, v in sorted(entries)]
    return comps, pinned


def node_components() -> list[dict]:
    """Frontend deps from package-lock.json (v2/v3 layout)."""
    lock = ROOT / "frontend" / "package-lock.json"
    if not lock.is_file():
        return []
    try:
        data = json.loads(lock.read_text())
    except json.JSONDecodeError:
        return []
    packages = data.get("packages") or {}
    comps: list[dict] = []
    for path, info in packages.items():
        if not path:  # "" is the root project
            continue
        name = path.removeprefix("node_modules/")
        version = info.get("version", "")
        comps.append({
            "type": "library",
            "bom-ref": _purl(name, version, "npm"),
            "name": name,
            "version": version,
            "purl": _purl(name, version, "npm"),
            "scope": "optional" if info.get("dev") else "required",
        })
    return comps


def first_party_components() -> list[dict]:
    """The deployable first-party units (Docker images / services)."""
    images = ["api", "worker", "monitor", "frontend", "nginx", "scanner"]
    return [{
        "type": "application",
        "bom-ref": f"pkg:cryptoscan/{name}@{version}" if (version := _version()) else f"pkg:cryptoscan/{name}",
        "name": f"cryptoscan-{name}",
        "version": _version(),
        "description": f"CryptoScan {name} runtime image",
    } for name in images]


def _version() -> str:
    version_file = ROOT / "VERSION"
    if version_file.is_file():
        return version_file.read_text().strip() or "dev"
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "dev"


def generate(out: Path) -> dict:
    py, pinned = python_components()
    node = node_components()
    first = first_party_components()
    deps = [{"ref": c["bom-ref"]} for c in py + node]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "component": {
                "type": "application",
                "bom-ref": "pkg:cryptoscan/platform",
                "name": "cryptoscan-platform",
                "version": _version(),
                "description": "ZELNX / CryptoScan — deterministic crypto intelligence platform",
            },
            "tools": [{"vendor": "CryptoScan", "name": "generate_own_sbom.py", "version": "1.0"}],
            "properties": [
                {"name": "cryptoscan:python-lockfile-pinned", "value": str(pinned).lower()},
                {"name": "cryptoscan:generator-note",
                 "value": "Regenerate per release: python3 scripts/generate_own_sbom.py"},
            ],
        },
        "components": first + py + node,
        "dependencies": [{"ref": "pkg:cryptoscan/platform", "dependsOn": [d["ref"] for d in deps[:4000]]}],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2))
    return sbom


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "dist" / "cryptoscan-sbom.cdx.json"))
    args = ap.parse_args()
    sbom = generate(Path(args.out))
    kinds: dict[str, int] = {}
    for c in sbom["components"]:
        m = re.match(r"pkg:([a-z]+)/", c["bom-ref"])
        ns = m.group(1) if m else "other"
        kinds[ns] = kinds.get(ns, 0) + 1
    print(f"SBOM written: {args.out}")
    print(f"  components: {len(sbom['components'])} — " +
          ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
