"""Manifest and lockfile dependency inventory for cascade analysis.

The static cascade report historically recognized crypto-bearing manifests but
could not answer which direct and transitive package nodes were involved. This
module adds a bounded, metadata-only inventory. It never reads secret values;
references are content hashes and file paths. Parsers are intentionally
stdlib-only so qualification can run before optional service dependencies are
installed.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


_MANIFEST_NAMES = {
    "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "go.mod", "cargo.toml", "composer.json", "gemfile", "pom.xml",
    "packages.config", "package.swift",
}
_LOCK_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum", "gemfile.lock",
    "composer.lock", "packages.lock.json",
}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _reference(path: Path, text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _row(*, ecosystem: str, name: str, version: str | None, source: str,
         direct: bool, parent: str | None, evidence_type: str, evidence_reference: str,
         observed_at: str) -> dict[str, Any]:
    name = str(name or "").strip()
    if not name:
        return {}
    version = str(version or "").strip() or None
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "scope": "runtime",
        "dependency_type": "direct" if direct else "transitive",
        "direct": bool(direct),
        "parent": parent,
        "source": source,
        "evidence_type": evidence_type,
        "evidence_reference": evidence_reference,
        "observed_at": observed_at,
        "confidence": "HIGH" if version else "MEDIUM",
        "unresolved": False,
    }


def _spec_name_version(spec: str) -> tuple[str, str | None]:
    value = spec.strip().strip("'\"")
    value = value.split(" #", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.@/+:\-]+)\s*(?:[=<>~!]{1,2}\s*([^\s;]+))?", value)
    return (match.group(1), match.group(2) if match and match.group(2) else None) if match else (value, None)


def _manifest_records(path: Path, root: Path, now: str) -> tuple[list[dict[str, Any]], set[tuple[str, str]], str]:
    text = _read(path)
    if not text:
        return [], set(), ""
    source = _rel(path, root)
    ref = _reference(path, text)
    rows: list[dict[str, Any]] = []
    direct: set[tuple[str, str]] = set()
    name = path.name.lower()

    def add(eco: str, package: str, version: str | None) -> None:
        package = package.strip()
        if not package:
            return
        direct.add((eco, package.lower()))
        rows.append(_row(ecosystem=eco, name=package, version=version, source=source,
                         direct=True, parent=None, evidence_type="manifest", evidence_reference=ref, observed_at=now))

    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for package, version in (data.get(section) or {}).items():
                add("npm", package, str(version))
    elif name.startswith("requirements"):
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith(("#", "-")):
                continue
            package, version = _spec_name_version(line)
            add("pypi", package.split("[")[0], version)
    elif name == "pyproject.toml":
        for match in re.finditer(r"['\"]([A-Za-z0-9_.\-]+)\s*(?:[=<>~!]{1,2}\s*([\w.*+\-]+))?['\"]", text):
            add("pypi", match.group(1), match.group(2))
    elif name == "go.mod":
        in_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            if in_block or stripped.startswith("require "):
                parts = stripped.replace("require ", "", 1).split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    add("go", parts[0], parts[1])
    elif name == "cargo.toml":
        in_dependencies = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_dependencies = stripped in {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}
                continue
            if in_dependencies:
                match = re.match(r"([A-Za-z0-9_\-]+)\s*=\s*(?:\"([^\"]+)\"|.*version\s*=\s*\"([^\"]+)\")", stripped)
                if match:
                    add("cargo", match.group(1), match.group(2) or match.group(3))
    elif name == "composer.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("require", "require-dev"):
            for package, version in (data.get(section) or {}).items():
                add("packagist", package, str(version))
    elif name == "gemfile":
        for package, version in re.findall(r"gem\s+['\"]([\w\-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
            add("rubygems", package, version or None)
    elif name == "pom.xml":
        for group, artifact, version in re.findall(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", text, re.S):
            add("maven", f"{group.strip()}:{artifact.strip()}", version.strip() or None)
    elif name in {"packages.config", "package.swift"}:
        for package, version in re.findall(r"(?:id|Include)\s*=\s*['\"]([^'\"]+)['\"](?:\s+version\s*=\s*['\"]([^'\"]+)['\"])?", text, re.I):
            add("nuget", package, version or None)
    return rows, direct, ref


def _lock_records(path: Path, root: Path, direct_by_eco: dict[str, set[str]], now: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    text = _read(path)
    if not text:
        return [], [], ""
    source = _rel(path, root)
    ref = _reference(path, text)
    rows: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    name = path.name.lower()

    def add(eco: str, package: str, version: str | None, parent: str | None = None) -> None:
        key = package.lower()
        rows.append(_row(ecosystem=eco, name=package, version=version, source=source,
                         direct=key in direct_by_eco.get(eco, set()), parent=parent,
                         evidence_type="lockfile", evidence_reference=ref, observed_at=now))

    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        packages = data.get("packages") if isinstance(data, dict) else None
        if isinstance(packages, dict):
            for location, item in packages.items():
                if not location or location == "" or not isinstance(item, dict):
                    continue
                package = location.rsplit("node_modules/", 1)[-1]
                if not package or package == location:
                    continue
                parent = location.rsplit("node_modules/", 2)[-2].strip("/") if location.count("node_modules/") > 1 else None
                add("npm", package, item.get("version"), parent)
        elif isinstance(data, dict):
            def walk(items: dict[str, Any], parent: str | None = None) -> None:
                for package, item in items.items():
                    if not isinstance(item, dict):
                        continue
                    add("npm", package, item.get("version"), parent)
                    walk(item.get("dependencies") or {}, package)
            walk(data.get("dependencies") or {})
    elif name == "composer.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("packages", "packages-dev"):
            for item in data.get(section) or []:
                if isinstance(item, dict):
                    add("packagist", item.get("name", ""), item.get("version"))
    elif name == "cargo.lock":
        for block in re.split(r"(?:^|\n)\s*\[\[package\]\]\s*", text, flags=re.M):
            if not block.strip():
                continue
            package = re.search(r"^name\s*=\s*\"([^\"]+)\"", block, re.M)
            version = re.search(r"^version\s*=\s*\"([^\"]+)\"", block, re.M)
            if package:
                add("cargo", package.group(1), version.group(1) if version else None)
                deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", block, re.M | re.S)
                if deps:
                    for dependency in re.findall(r'"([^"]+)"', deps.group(1)):
                        dependency_name = dependency.split(" ", 1)[0]
                        if not dependency_name:
                            continue
                        unresolved.append({"source": source, "parent": package.group(1), "child": dependency_name,
                                           "evidence_type": "lockfile", "evidence_reference": ref, "observed_at": now})
    elif name == "go.sum":
        for line in text.splitlines():
            match = re.match(r"\s*([^\s]+)\s+(v[^\s/]+)", line)
            if match:
                add("go", match.group(1), match.group(2))
    elif name == "poetry.lock":
        for block in re.split(r"(?:^|\n)\s*\[\[package\]\]\s*", text, flags=re.M):
            if not block.strip():
                continue
            package = re.search(r"^name\s*=\s*['\"]([^'\"]+)", block, re.M)
            version = re.search(r"^version\s*=\s*['\"]([^'\"]+)", block, re.M)
            if package:
                add("pypi", package.group(1), version.group(1) if version else None)
    elif name == "gemfile.lock":
        in_specs = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and line and not line.startswith(" "):
                in_specs = False
            if in_specs:
                match = re.match(r"^\s{4}([\w\-]+) \(([^)]+)\)", line)
                if match:
                    add("rubygems", match.group(1), match.group(2))
    elif name == "pipfile.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("default", "develop"):
            for package, item in (data.get(section) or {}).items():
                add("pypi", package, item.get("version") if isinstance(item, dict) else item)
    elif name == "packages.lock.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for package in data.get("libraries") or []:
            if isinstance(package, dict):
                add("nuget", package.get("id", ""), package.get("resolved"))
    elif name in {"yarn.lock", "pnpm-lock.yaml"}:
        # A full YAML parser is optional. Keep the lockfile itself visible with
        # exact package/version pairs when the common text form is present.
        for package, version in re.findall(r"(?:^|\n)[\"']?(@?[A-Za-z0-9_.\-/]+)[\"']?[^\n]*\n\s+version\s+[\"']([^\"']+)", text):
            add("npm", package, version)
    return rows, unresolved, ref


def dependency_metadata_files(root: Path) -> list[Path]:
    """Discover manifests and lockfiles while excluding generated/vendor trees."""
    ignored = {".git", "node_modules", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.name.lower() in (_MANIFEST_NAMES | _LOCK_NAMES)
        and not ignored.intersection(path.relative_to(root).parts)
    )


def collect_package_dependencies(files: Iterable[Path], root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return deduplicated package nodes and unresolved lockfile relationships."""
    now = datetime.now(timezone.utc).isoformat()
    paths = [path for path in files if path.is_file()]
    manifests = [path for path in paths if path.name.lower() in _MANIFEST_NAMES]
    locks = [path for path in paths if path.name.lower() in _LOCK_NAMES]
    all_rows: list[dict[str, Any]] = []
    direct: dict[str, set[str]] = defaultdict(set)
    for path in manifests:
        rows, direct_rows, _ = _manifest_records(path, root, now)
        all_rows.extend(rows)
        for ecosystem, package in direct_rows:
            direct[ecosystem].add(package)
    unresolved: list[dict[str, Any]] = []
    for path in locks:
        rows, unresolved_rows, _ = _lock_records(path, root, direct, now)
        all_rows.extend(rows)
        unresolved.extend(unresolved_rows)

    merged: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for row in all_rows:
        if not row:
            continue
        key = (row["ecosystem"], row["name"].lower(), row.get("version"))
        prior = merged.get(key)
        if prior is None:
            merged[key] = row
        else:
            prior["direct"] = prior["direct"] or row["direct"]
            prior["dependency_type"] = "direct" if prior["direct"] else "transitive"
            prior["source"] = ";".join(sorted(set(str(prior["source"]).split(";") + [str(row["source"])])))
            prior["evidence_type"] = "manifest+lockfile" if prior["evidence_type"] != row["evidence_type"] else prior["evidence_type"]
    known = {(row["ecosystem"], row["name"].lower()) for row in merged.values()}
    observed_parents: dict[tuple[str, str], str] = {}
    for relation in unresolved:
        eco = "cargo" if relation.get("source", "").lower().endswith("cargo.lock") else ""
        if eco and (eco, str(relation["child"]).lower()) not in known:
            relation["status"] = "UNRESOLVED"
        else:
            relation["status"] = "OBSERVED"
            if eco:
                observed_parents.setdefault((eco, str(relation["child"]).lower()), str(relation["parent"]))
    for key, row in merged.items():
        parent = observed_parents.get((key[0], key[1]))
        if parent and not row.get("parent"):
            row["parent"] = parent
    rows = sorted(merged.values(), key=lambda row: (row["ecosystem"], not row["direct"], row["name"].lower(), row.get("version") or ""))
    return rows, [relation for relation in unresolved if relation.get("status") == "UNRESOLVED"]
