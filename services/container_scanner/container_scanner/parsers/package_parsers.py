"""Parse common language package manifests from a container filesystem."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

REQ = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.+-]*)")
NPM_DEP = re.compile(r"^[\^~>=<\s]*([0-9][0-9A-Za-z.+-]*)")


def parse_requirements(path: Path) -> list[dict[str, Any]]:
    packages = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = REQ.match(stripped)
        if not match:
            continue
        packages.append(
            {
                "name": match.group(1).lower(),
                "version": match.group(2) or None,
                "manager": "pip",
                "manifest": str(path),
            }
        )
    return packages


def parse_package_json(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    packages = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = None
            if isinstance(spec, str):
                match = NPM_DEP.search(spec)
                version = match.group(1) if match else spec.lstrip("^~>=< ")
            packages.append(
                {
                    "name": str(name).lower(),
                    "version": version,
                    "manager": "npm",
                    "manifest": str(path),
                    "section": section,
                }
            )
    return packages


def parse_pom(path: Path) -> list[dict[str, Any]]:
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError:
        return []
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    packages = []
    for dep in root.findall(f".//{ns}dependency"):
        group = (dep.findtext(f"{ns}groupId") or "").strip()
        artifact = (dep.findtext(f"{ns}artifactId") or "").strip()
        version = (dep.findtext(f"{ns}version") or "").strip() or None
        if not artifact:
            continue
        packages.append(
            {
                "name": artifact.lower(),
                "group": group,
                "version": version,
                "manager": "maven",
                "manifest": str(path),
            }
        )
    return packages


def parse_csproj(path: Path) -> list[dict[str, Any]]:
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError:
        return []
    packages = []
    for ref in root.findall(".//{*}PackageReference"):
        name = ref.attrib.get("Include") or ref.attrib.get("Update")
        version = ref.attrib.get("Version")
        if not name:
            continue
        packages.append(
            {
                "name": name.lower(),
                "version": version,
                "manager": "nuget",
                "manifest": str(path),
            }
        )
    return packages


def parse_gomod(path: Path) -> list[dict[str, Any]]:
    packages = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*([A-Za-z0-9./_-]+)\s+v([0-9][A-Za-z0-9.+-]*)", line)
        if match:
            packages.append(
                {
                    "name": match.group(1).lower(),
                    "version": match.group(2),
                    "manager": "go",
                    "manifest": str(path),
                }
            )
    return packages
