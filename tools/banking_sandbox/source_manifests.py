#!/usr/bin/env python3
"""Real manifests for the bank sandbox — what a dependency scanner needs to read.

The lab declares each application's dependencies in ``public/source/<bank>/manifests.jsonl``,
which is **data about manifests**, not a manifest. Nothing parses it: a scan of the
bank's source tree reports ``direct_package_dependencies: 0``, not because the bank
has no dependencies but because the tree contains no ``requirements.txt``,
``package.json``, ``pom.xml``, ``go.mod``, ``Cargo.toml``, ``composer.json``,
``Gemfile`` or ``packages.config`` to read.

This module writes those files, in each application's own ecosystem format, from
the lab's declared dependency list. The result is a tree a real scanner can walk:

    python -m tools.banking_sandbox.source_manifests \\
        --estate ~/.cache/bank-lab --out ~/.cache/bank-lab/public/source-manifests

then scan it like any other source root:

    POST /api/v1/scans/trigger {"repo_url": "local://<out>"}

What that establishes, stated once: the **declaration** is parsed by a real parser.
A package listed in a manifest is a package the application says it depends on;
it is not proof that the code imports it, and it is not proof the version is the
one installed. The scanner's own cascade report keeps those apart
(``libraries_declared_but_unused`` / ``libraries_used_but_undeclared``), and every
file written here is marked synthetic inside the manifest itself.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "cryptoscan.bank-source-manifests/1"
SYNTHETIC_MARKER = "SYNTHETIC-BANK-LAB"

#: language -> (manifest filename, package-manager ecosystem)
ECOSYSTEMS: dict[str, tuple[str, str]] = {
    "Python": ("requirements.txt", "pypi"),
    "JavaScript": ("package.json", "npm"),
    "TypeScript": ("package.json", "npm"),
    "Java": ("pom.xml", "maven"),
    "Kotlin": ("pom.xml", "maven"),
    "Go": ("go.mod", "go"),
    "Rust": ("Cargo.toml", "cargo"),
    "PHP": ("composer.json", "composer"),
    "Ruby": ("Gemfile", "gem"),
    "C#": ("packages.config", "nuget"),
    "CSharp": ("packages.config", "nuget"),
}

#: ecosystems whose formats this lab does not emit, stated rather than skipped
NO_MANIFEST = {
    "C": "no package manager in this lab",
    "C++": "no manifest format this lab emits (Conan/vcpkg are not modelled)",
    "Cpp": "no manifest format this lab emits",
}


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _slug(name: str) -> str:
    """A package name that is legal in every format we emit."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(name)).strip("-") or "unnamed"


def _version(value: Any) -> str:
    return str(value) if value not in (None, "") else "0.0.0-lab"


def _pypi(deps: dict[str, Any]) -> str:
    lines = [f"# {SYNTHETIC_MARKER}: declared lab dependencies, not an installed environment"]
    lines += [f"{_slug(name)}=={_version(version)}" for name, version in deps.items()]
    return "\n".join(lines) + "\n"


def _npm(deps: dict[str, Any], app: str) -> str:
    return json.dumps({
        "name": _slug(app),
        "version": "0.0.0-lab",
        "private": True,
        "description": f"{SYNTHETIC_MARKER} application",
        "dependencies": {_slug(name): _version(version) for name, version in deps.items()},
    }, indent=2) + "\n"


def _maven(deps: dict[str, Any], app: str) -> str:
    entries = "\n".join(
        "    <dependency>\n"
        f"      <groupId>{SYNTHETIC_MARKER.lower()}</groupId>\n"
        f"      <artifactId>{_slug(name)}</artifactId>\n"
        f"      <version>{_version(version)}</version>\n"
        "    </dependency>"
        for name, version in deps.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{SYNTHETIC_MARKER.lower()}</groupId>\n"
        f"  <artifactId>{_slug(app)}</artifactId>\n"
        "  <version>0.0.0-lab</version>\n"
        f"  <!-- {SYNTHETIC_MARKER} -->\n"
        "  <dependencies>\n"
        f"{entries}\n"
        "  </dependencies>\n"
        "</project>\n"
    )


def _gomod(deps: dict[str, Any], app: str) -> str:
    requires = "\n".join(
        f"\t{_slug(name)} v0.0.0-00010101000000-000000000000"
        for name in deps
    )
    return (
        f"// {SYNTHETIC_MARKER}\n"
        f"module example.invalid/{_slug(app)}\n\n"
        "go 1.22\n\n"
        "require (\n"
        f"{requires}\n"
        ")\n"
    )


def _cargo(deps: dict[str, Any], app: str) -> str:
    entries = "\n".join(f'{_slug(name)} = "0.0.0"' for name in deps)
    return (
        f"# {SYNTHETIC_MARKER}\n"
        "[package]\n"
        f'name = "{_slug(app)}"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f"{entries}\n"
    )


def _composer(deps: dict[str, Any], app: str) -> str:
    return json.dumps({
        "name": f"synthetic/{_slug(app)}",
        "description": f"{SYNTHETIC_MARKER} application",
        "require": {_slug(name): _version(version) for name, version in deps.items()},
    }, indent=2) + "\n"


def _gemfile(deps: dict[str, Any]) -> str:
    lines = [f"# {SYNTHETIC_MARKER}"]
    lines += [f'gem "{_slug(name)}", "{_version(version)}"' for name, version in deps.items()]
    return "\n".join(lines) + "\n"


def _nuget(deps: dict[str, Any]) -> str:
    entries = "\n".join(
        f'  <package id="{_slug(name)}" version="{_version(version)}" targetFramework="net8.0" />'
        for name, version in deps.items()
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f"<!-- {SYNTHETIC_MARKER} -->\n"
        "<packages>\n"
        f"{entries}\n"
        "</packages>\n"
    )


def render(language: str, deps: dict[str, Any], app: str) -> tuple[str, str] | None:
    """(filename, text) for one application, or None when the lab has no ecosystem."""
    entry = ECOSYSTEMS.get(language)
    if entry is None:
        return None
    filename = entry[0]
    if filename == "requirements.txt":
        return filename, _pypi(deps)
    if filename == "package.json":
        return filename, _npm(deps, app)
    if filename == "pom.xml":
        return filename, _maven(deps, app)
    if filename == "go.mod":
        return filename, _gomod(deps, app)
    if filename == "Cargo.toml":
        return filename, _cargo(deps, app)
    if filename == "composer.json":
        return filename, _composer(deps, app)
    if filename == "Gemfile":
        return filename, _gemfile(deps)
    if filename == "packages.config":
        return filename, _nuget(deps)
    return None


def build(estate: Path, out: Path) -> dict[str, Any]:
    """Write one manifest tree for every application the bank declares."""
    public = Path(estate) / "public"
    out = Path(out)
    written: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    declared = {row.get("app_id"): row for rows in
                (_rows(path) for path in sorted((public / "source").glob("*/manifests.jsonl")))
                for row in rows}

    for app in _rows_any(public / "applications"):
        app_id = str(app.get("app_id") or "")
        language = str(app.get("language") or "")
        manifest = declared.get(app_id) or {}
        deps = dict((manifest.get("manifest") or {}).get("dependencies") or {})
        rendered = render(language, deps, app_id) if deps else None
        if rendered is None:
            reason = NO_MANIFEST.get(language) or (
                "the lab declares no dependencies for this application" if not deps
                else f"no manifest format for {language or 'unknown language'}"
            )
            skipped.append({"app_id": app_id, "language": language, "reason": reason})
            continue
        filename, text = rendered
        target = out / str(app.get("bank_id") or "bank") / app_id / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append({
            "app_id": app_id,
            "language": language,
            "file": str(target),
            "ecosystem": ECOSYSTEMS[language][1],
            "dependencies": len(deps),
        })

    return {
        "schema": SCHEMA,
        "synthetic": True,
        "directory": str(out),
        "manifests": written,
        "skipped": skipped,
        "counts": {
            "applications": len(written) + len(skipped),
            "manifests": len(written),
            "dependencies": sum(row["dependencies"] for row in written),
        },
        "establishes": "DECLARED_DEPENDENCY",
        "note": (
            "each file is in its ecosystem's real format and is parsed by the real parser. A "
            "listed package is a declared dependency, not a proven import, and not proof of the "
            "installed version"
        ),
    }


def _rows_any(directory: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not directory.is_dir():
        return rows
    for path in sorted(directory.glob("*.jsonl")):
        rows.extend(_rows(path))
    return rows


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--estate", type=Path, required=True, help="generated bank estate root")
    parser.add_argument("--out", type=Path, required=True, help="directory to write the manifests into")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = build(args.estate, args.out)
    print(json.dumps(summary, indent=2))
    print(
        "\nScan this tree through the backend to see the dependency path run:\n"
        f"  POST /api/v1/scans/trigger  {{\"repo_url\": \"local://{summary['directory']}\"}}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
