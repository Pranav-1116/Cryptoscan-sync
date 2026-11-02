"""Parse common language package manifests from a container filesystem."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older interpreters
    tomllib = None  # type: ignore[assignment]

REQ = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.+-]*)")
NPM_DEP = re.compile(r"^[\^~>=<\s]*([0-9][0-9A-Za-z.+-]*)")
#: A PEP 440 specifier as it appears in ``pyproject.toml`` or a ``Pipfile``.
PEP440_SPEC = re.compile(r"^\s*(===|==|~=|>=|<=|!=|>|<|\^|~)?\s*([0-9][0-9A-Za-z.*+!-]*)\s*$")


def classify_spec(spec: Any) -> tuple[str | None, str | None]:
    """Split a declared specifier into ``(version, constraint)``.

    ``"^42.0.5"`` and ``"42.0.5"`` are different statements — a range versus a
    pin — and a lockfile-less scan that reports only the coerced version cannot
    tell a reviewer which one the project declared. The constraint kind is
    ``EXACT``, ``RANGE``, ``ANY`` or ``NON_VERSION`` (a URL, a git ref, a path).
    """
    if spec is None:
        return None, None
    text = str(spec).strip()
    if not text:
        return None, None
    if text in {"*", "x", "X", "latest"}:
        return None, "ANY"
    if text.startswith(("git+", "hg+", "svn+", "bzr+", "file:", "http:", "https:", ".", "/", "~")):
        return None, "NON_VERSION"
    match = PEP440_SPEC.match(text)
    if not match:
        return None, "NON_VERSION"
    operator, version = match.group(1), match.group(2)
    if operator in {None, "==", "==="}:
        # A bare ``42.0.5`` is a pin: both PEP 508 and Poetry read it as "this
        # version", so classifying it as a range would overstate the freedom.
        return version, "EXACT"
    if version.endswith(".*"):
        return version[:-2], "RANGE"
    return version, "RANGE"


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
            raw_spec = spec if isinstance(spec, str) else None
            constraint = None
            if isinstance(spec, str):
                match = NPM_DEP.search(spec)
                if match:
                    version = match.group(1)
                    # ``^5.0.0`` and ``5.0.0`` are different statements: the first
                    # permits any 5.x, the second pins one build. The coerced
                    # version alone cannot tell them apart, so the raw spec and
                    # the constraint kind travel with the row.
                    constraint = "EXACT" if spec.strip() == version else "RANGE"
                elif re.match(r"^\s*[*xX]?\s*$", spec):
                    constraint = "ANY"
                else:
                    # git:, file:, link:, workspace:, npm: aliases — not a
                    # version at all, and inventing one from the string would
                    # put a URL in the version field.
                    version = None
                    constraint = "NON_VERSION"
            packages.append(
                {
                    "name": str(name).lower(),
                    "version": version,
                    "manager": "npm",
                    "manifest": str(path),
                    "section": section,
                    "raw_spec": raw_spec,
                    "version_constraint": constraint,
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


def parse_composer(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    packages = []
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if name == "php":
                continue
            packages.append(
                {
                    "name": str(name).lower(),
                    "version": str(spec).lstrip("^~>=< ") if spec else None,
                    "manager": "composer",
                    "manifest": str(path),
                    "section": section,
                }
            )
    return packages


def parse_gemfile(path: Path) -> list[dict[str, Any]]:
    packages = []
    gem = re.compile(r"""^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?""")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = gem.match(line)
        if match:
            packages.append(
                {
                    "name": match.group(1).lower(),
                    "version": match.group(2),
                    "manager": "bundler",
                    "manifest": str(path),
                }
            )
    return packages


def parse_cargo(path: Path) -> list[dict[str, Any]]:
    packages = []
    section = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section not in {"dependencies", "dev-dependencies", "build-dependencies"}:
            continue
        match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(?:\"([^\"]+)\"|\{[^}]*version\s*=\s*\"([^\"]+)\")", stripped)
        if match:
            packages.append(
                {
                    "name": match.group(1).lower(),
                    "version": match.group(2) or match.group(3),
                    "manager": "cargo",
                    "manifest": str(path),
                    "section": section,
                }
            )
    return packages


def _requirement_row(requirement: str, *, path: Path, manager: str = "pip",
                     section: str = "dependencies") -> dict[str, Any] | None:
    """One PEP 508 requirement string → a package row, extras and markers removed."""
    text = str(requirement or "").split(";", 1)[0].strip()  # drop the environment marker
    if not text:
        return None
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", text)
    if not match:
        return None
    name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    version, constraint = classify_spec(match.group(3) or None)
    return {
        "name": name,
        "version": version,
        "manager": manager,
        "manifest": str(path),
        "section": section,
        "raw_spec": (match.group(3) or "").strip() or None,
        "version_constraint": constraint,
    }


def _poetry_dependencies(data: dict[str, Any]) -> list[tuple[str, Any, str]]:
    rows: list[tuple[str, Any, str]] = []
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            rows.append((name, spec, section))
    for group, body in (poetry.get("group") or {}).items():
        for name, spec in ((body or {}).get("dependencies") or {}).items():
            rows.append((name, spec, f"group:{group}"))
    return rows


def parse_pyproject(path: Path) -> list[dict[str, Any]]:
    """PEP 621 ``[project]`` and Poetry ``[tool.poetry]`` dependencies.

    Before this reader existed, a project whose only manifest was
    ``pyproject.toml`` produced an empty SBOM: the file was recognised (the
    lockfile readers read it for direct-name attribution) but never parsed, so
    "no components" and "components we could not see" looked identical.
    """
    if tomllib is None:  # pragma: no cover - 3.10 and older
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError):
        return []

    packages: list[dict[str, Any]] = []
    project = data.get("project") or {}
    for requirement in project.get("dependencies") or []:
        row = _requirement_row(requirement, path=path, section="dependencies")
        if row:
            packages.append(row)
    for section, requirements in (project.get("optional-dependencies") or {}).items():
        for requirement in requirements or []:
            row = _requirement_row(requirement, path=path, section=f"optional:{section}")
            if row:
                packages.append(row)

    for name, spec, section in _poetry_dependencies(data):
        if str(name).lower() == "python":
            continue  # an interpreter constraint, not a dependency
        if isinstance(spec, dict):
            spec = spec.get("version")
        row = _requirement_row(f"{name}{spec}" if spec else str(name), path=path,
                              section=section)
        if row:
            packages.append(row)
    return packages


def parse_pipfile(path: Path) -> list[dict[str, Any]]:
    """``Pipfile`` ``[packages]`` and ``[dev-packages]`` declarations."""
    if tomllib is None:  # pragma: no cover - 3.10 and older
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError):
        return []
    packages: list[dict[str, Any]] = []
    for section in ("packages", "dev-packages"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, dict):
                spec = spec.get("version")
            row = _requirement_row(f"{name}{spec}" if spec else str(name),
                                  path=path, section=section)
            if row:
                packages.append(row)
    return packages
