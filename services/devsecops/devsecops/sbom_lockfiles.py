"""Lockfile parsers for the SBOM scanner — resolved dependency graphs.

Manifest parsers (package.json, requirements.txt, Cargo.toml, …) give what a
project *declares*; lockfiles give what was actually *resolved*, including
transitive dependencies. An SBOM built from declarations alone under-reports
the dependency tree — the usual reason a supplier SBOM gets rejected.

Every parser returns rows in the scanner's canonical shape::

    {"name", "version", "manager", "scope": "resolved",
     "direct": True|False|None,          # None when the lockfile cannot say
     "license": str|None,
     "integrity": str|None,              # h1:/sha512-…/contentHash when present
     "depends_on": ["name@version", …]}

``direct`` is resolved against the sibling manifest (package-lock's root
package, Cargo.toml, pyproject.toml, .NET ``type``, Gemfile DEPENDENCIES)
when that manifest is parseable; otherwise it stays ``None`` rather than
guessed. Unknown fields are omitted, never invented.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

# Lockfiles are keyed by exact filename (or suffix rule where noted).
LOCKFILES = (
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
    "packages.lock.json", "gradle.lockfile",
)

_MAX_LOCKFILE_BYTES = 8_000_000


def _row(name: str, version: str | None, manager: str, *, scope: str = "resolved",
         direct: bool | None = None, license: str | None = None,
         integrity: str | None = None, depends_on: list[str] | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "version": version or None,
                           "manager": manager, "scope": scope}
    if direct is not None:
        row["direct"] = direct
    if license:
        row["license"] = license
    if integrity:
        row["integrity"] = integrity
    if depends_on:
        row["depends_on"] = sorted(set(depends_on))
    return row


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------- package-lock -- #
def parse_package_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    """npm package-lock v2/v3 (``packages`` map) with a v1 (``dependencies``) fallback."""
    data = _read_json(path)
    rows: list[dict[str, Any]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        declared: set[str] = set()
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            declared |= {str(k).lower() for k in (root.get(section) or {})}
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue  # "" is the project itself
            if meta.get("link") or meta.get("inBundle"):
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            if not name:
                continue
            rows.append(_row(
                str(name).lower(), str(meta.get("version") or "") or None, "npm",
                direct=str(name).lower() in declared if declared else None,
                license=str(meta["license"]) if meta.get("license") else None,
                integrity=str(meta["integrity"]) if meta.get("integrity") else None,
                depends_on=[str(d) for d in (meta.get("dependencies") or {})],
            ))
        if rows:
            return rows
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        stack: list[tuple[dict[str, Any], int]] = [(deps, 0)]
        while stack:
            level, depth = stack.pop()
            for name, meta in level.items():
                if not isinstance(meta, dict):
                    continue
                rows.append(_row(
                    str(name).lower(), str(meta.get("version") or "") or None, "npm",
                    direct=depth == 0 if manifest_direct is None else str(name).lower() in manifest_direct,
                    integrity=str(meta["integrity"]) if meta.get("integrity") else None,
                    depends_on=[str(d) for d in (meta.get("requires") or {})],
                ))
                if isinstance(meta.get("dependencies"), dict):
                    stack.append((meta["dependencies"], depth + 1))
    return rows


# ---------------------------------------------------------------- yarn.lock -- #
_YARN_HEADER = re.compile(r"^((?:\"[^\"]+\"|'[^']+'|[^\"'\s:]+)(?:,\s*(?:\"[^\"]+\"|'[^']+'|[^\"'\s:]+))*):\s*$")
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')
_YARN_INTEGRITY = re.compile(r"^\s+integrity:?\s+(\S+)")


def _yarn_name(spec: str) -> str:
    """``"@scope/pkg@^1.0.0"`` -> ``@scope/pkg``; ``left-pad@^1`` -> ``left-pad``."""
    value = spec.strip().strip('"').strip("'")
    if value.startswith("@"):
        at = value.find("@", 1)
        return value[:at] if at > 0 else value
    return value.split("@", 1)[0]


def parse_yarn_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    """yarn v1 classic lockfile (berry v2+ shares the header/version layout for
    the fields we read; entries without a version are skipped, not invented)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    in_deps = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            # new entry header (one or more comma-separated specs)
            if current.get("name") and current.get("version"):
                rows.append(_row(**current))
            specs = [s for s in raw.rstrip(":").split(",") if s.strip()]
            name = _yarn_name(specs[0]) if specs else ""
            current = {"name": name.lower(), "version": None, "manager": "npm",
                       "direct": (name.lower() in manifest_direct) if manifest_direct else None,
                       "depends_on": []}
            in_deps = False
            continue
        m = _YARN_VERSION.match(raw)
        if m:
            current["version"] = m.group(1)
            continue
        m = _YARN_INTEGRITY.match(raw)
        if m:
            current["integrity"] = m.group(1)
            continue
        if re.match(r"^\s+dependencies:\s*$", raw):
            in_deps = True
            continue
        if in_deps:
            dep = raw.strip().split(" ", 1)[0].strip('"').strip("'")
            if dep:
                current.setdefault("depends_on", []).append(dep)
    if current.get("name") and current.get("version"):
        rows.append(_row(**current))
    return rows


# --------------------------------------------------------------- poetry.lock -- #
def _pyproject_direct_names(root: Path) -> set[str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return set()
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    names: set[str] = set()
    poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
    for section in ("dependencies", "dev-dependencies"):
        names |= {str(k).lower() for k in (poetry.get(section) or {})}
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            names |= {str(k).lower() for k in (group.get("dependencies") or {})}
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    names |= {str(d).lower() for d in (project.get("dependencies") or [])}
    return names


def parse_poetry_lock(path: Path, *, direct_names: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    direct = {n.lower() for n in (direct_names or ())}
    rows = []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        name = str(pkg["name"]).lower()
        files = pkg.get("files") or []
        digest = str(files[0]["hash"]) if files and isinstance(files[0], dict) and files[0].get("hash") else None
        rows.append(_row(
            name, str(pkg.get("version") or "") or None, "pip",
            direct=name in direct if direct else None, integrity=digest,
            depends_on=[str(d).lower() for d in (pkg.get("dependencies") or {})],
        ))
    return rows


# ------------------------------------------------------------- Pipfile.lock -- #
def _pipfile_direct(root: Path) -> set[str]:
    """Direct dependencies from a sibling Pipfile (default/dev-packages)."""
    pipfile = root / "Pipfile"
    if not pipfile.is_file():
        return set()
    try:
        data = tomllib.loads(pipfile.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    names = {str(k).lower() for k in (data.get("packages") or {})}
    names |= {str(k).lower() for k in (data.get("dev-packages") or {})}
    return names


def parse_pipfile_lock(path: Path, *, direct_names: set[str] | None = None) -> list[dict[str, Any]]:
    """Pipfile.lock ``default``/``develop`` sections hold direct *and*
    transitive packages, so ``direct`` comes from the Pipfile when present and
    stays unknown otherwise — never inferred from the section name."""
    data = _read_json(path)
    direct = {n.lower() for n in (direct_names or ())}
    rows: list[dict[str, Any]] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            hashes = meta.get("hashes") or []
            key = str(name).lower()
            rows.append(_row(
                key, str(meta.get("version") or "").lstrip("=") or None, "pip",
                direct=key in direct if direct else None,
                integrity=str(hashes[0]) if hashes else None,
            ))
    return rows


# --------------------------------------------------------------- Cargo.lock -- #
def _cargo_toml_direct(root: Path) -> set[str]:
    cargo = root / "Cargo.toml"
    if not cargo.is_file():
        return set()
    try:
        data = tomllib.loads(cargo.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    names: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        names |= {str(k).lower() for k in (data.get(section) or {})}
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                names |= {str(k).lower() for k in (target.get(section) or {})}
    return names


def _cargo_root_name(root: Path) -> str:
    cargo = root / "Cargo.toml"
    if not cargo.is_file():
        return ""
    try:
        data = tomllib.loads(cargo.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    package = data.get("package") if isinstance(data.get("package"), dict) else {}
    return str(package.get("name") or "").lower()


def parse_cargo_lock(path: Path, *, direct_names: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    direct = {n.lower() for n in (direct_names or ())}
    root_name = _cargo_root_name(path.parent)
    rows = []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        name = str(pkg["name"]).lower()
        if root_name and name == root_name and not pkg.get("source"):
            continue  # the workspace project itself is not a dependency
        deps = []
        for dep in pkg.get("dependencies") or []:
            spec = str(dep)
            # "name version" or "name" (same-version sibling)
            deps.append(spec.split(" ")[0].lower())
        version = str(pkg.get("version") or "") or None
        digest = None
        if pkg.get("checksum"):
            digest = f"sha256:{pkg['checksum']}"
        elif pkg.get("source"):
            digest = None
        rows.append(_row(name, version, "cargo",
                         direct=name in direct if direct else None,
                         integrity=digest, depends_on=deps))
    return rows


# ------------------------------------------------------------ composer.lock -- #
def parse_composer_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    data = _read_json(path)
    rows: list[dict[str, Any]] = []
    for section, direct in (("packages", True), ("packages-dev", False)):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict) or not pkg.get("name"):
                continue
            licenses = pkg.get("license")
            license_str = ", ".join(str(x) for x in licenses) if isinstance(licenses, list) else (str(licenses) if licenses else None)
            requires = [str(d).lower() for d in (pkg.get("require") or {})
                        if not str(d).startswith(("php", "ext-", "lib-"))]
            digest = pkg.get("dist") if isinstance(pkg.get("dist"), dict) else {}
            rows.append(_row(
                str(pkg["name"]).lower(), str(pkg.get("version") or "").lstrip("v") or None, "composer",
                direct=direct, license=license_str,
                integrity=str(digest.get("shasum") or digest.get("reference") or "") or None,
                depends_on=requires,
            ))
    return rows


# ------------------------------------------------------------- Gemfile.lock -- #
_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)")
_GEM_DEP = re.compile(r"^ {6}([A-Za-z0-9._-]+)")


def parse_gemfile_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    in_specs = False
    in_dependencies = False
    direct_names: set[str] = set()
    specs: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        if re.match(r"^(GEM|PATH|GIT|PLUGIN SOURCE)\s*$", raw):
            in_specs, in_dependencies = False, False
            current = None
            continue
        if raw.strip() == "specs:":
            in_specs, in_dependencies = True, False
            continue
        if raw.strip() == "DEPENDENCIES":
            in_specs, in_dependencies = False, True
            continue
        if raw.strip() in ("PLATFORMS", "BUNDLED WITH", "RUBY VERSION", "CHECKSUMS"):
            in_specs, in_dependencies = False, False
            continue
        if in_specs:
            m = _GEM_SPEC.match(raw)
            if m:
                current = {"name": m.group(1).lower(), "version": m.group(2).split()[0],
                           "manager": "bundler", "depends_on": []}
                specs.append(current)
                continue
            m = _GEM_DEP.match(raw)
            if m and current is not None:
                current["depends_on"].append(m.group(1).lower())
            continue
        if in_dependencies:
            stripped = raw.strip()
            if stripped and raw.startswith((" ", "\t")):
                direct_names.add(re.split(r"[ (]", stripped, 1)[0].lower())
    rows = []
    for spec in specs:
        rows.append(_row(spec["name"], spec["version"], "bundler",
                         direct=spec["name"] in direct_names if direct_names else None,
                         depends_on=spec["depends_on"]))
    return rows


# ------------------------------------------------------------------- go.sum -- #
def parse_go_sum(path: Path, *, direct_names: set[str] | None = None) -> list[dict[str, Any]]:
    """go.sum lists (module, version) pairs with h1: hashes. The same module
    appears twice — once for the module content, once for its go.mod file; only
    the content line carries the usable hash, so ``/go.mod`` lines are skipped."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    direct = {n.lower() for n in (direct_names or ())}
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        module, version, digest = parts[0], parts[1], parts[2]
        if version.endswith("/go.mod"):
            continue
        version = version.lstrip("v").replace("+incompatible", "")
        name = module.lower()
        key = (name, version)
        if key not in rows:
            rows[key] = _row(name, version, "go",
                             direct=name in direct if direct else None, integrity=digest)
    return list(rows.values())


# -------------------------------------------------------- packages.lock.json -- #
def parse_dotnet_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    data = _read_json(path)
    rows: list[dict[str, Any]] = []
    frameworks = data.get("dependencies")
    if not isinstance(frameworks, dict):
        return rows
    for _framework, deps in frameworks.items():
        if not isinstance(deps, dict):
            continue
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            kind = str(meta.get("type") or "").lower()
            rows.append(_row(
                str(name).lower(), str(meta.get("resolved") or "") or None, "nuget",
                direct=(kind == "direct") if kind else None,
                integrity=str(meta.get("contentHash") or "") or None,
                depends_on=[str(d).lower() for d in (meta.get("dependencies") or {})],
            ))
    return rows


# ----------------------------------------------------------- gradle.lockfile -- #
_GRADLE_LINE = re.compile(r"^([A-Za-z0-9._-]+):([A-Za-z0-9._-]+):([A-Za-z0-9._+@-]+)(?:=[^=]*)?$")


def parse_gradle_lock(path: Path, *, manifest_direct: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rows = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("empty="):
            continue
        m = _GRADLE_LINE.match(stripped)
        if not m:
            continue
        group, artifact, version = m.groups()
        rows.append(_row(f"{group.lower()}/{artifact.lower()}", version, "maven",
                         direct=None))
    return rows


# ------------------------------------------------------------------ dispatch -- #
def direct_names_for(lockfile: Path) -> set[str]:
    """Direct-dependency names from the manifest beside the lockfile."""
    root = lockfile.parent
    if lockfile.name == "Cargo.lock":
        return _cargo_toml_direct(root)
    if lockfile.name == "poetry.lock":
        return _pyproject_direct_names(root)
    if lockfile.name == "go.sum":
        return _go_mod_direct(root)
    if lockfile.name == "Pipfile.lock":
        return _pipfile_direct(root)
    return set()


def _go_mod_direct(root: Path) -> set[str]:
    gomod = root / "go.mod"
    if not gomod.is_file():
        return set()
    names: set[str] = set()
    try:
        lines = gomod.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return names
    in_block = False
    for line in lines:
        stripped = line.split("//", 1)[0].strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            stripped = stripped[len("require "):].strip()
        elif not in_block:
            continue
        parts = stripped.split()
        if parts:
            names.add(parts[0].lower())
    return names


_PARSERS: dict[str, Any] = {
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "go.sum": parse_go_sum,
    "packages.lock.json": parse_dotnet_lock,
    "gradle.lockfile": parse_gradle_lock,
}


def is_lockfile(name: str) -> bool:
    return name in _PARSERS


def parse_lockfile(path: Path) -> list[dict[str, Any]]:
    """Parse one lockfile into canonical resolved rows (never raises on a
    malformed file — a bad lockfile yields no rows, not a failed scan)."""
    parser = _PARSERS.get(path.name)
    if parser is None:
        return []
    try:
        if path.stat().st_size > _MAX_LOCKFILE_BYTES:
            return []
    except OSError:
        return []
    kwargs: dict[str, Any] = {}
    if path.name in ("Cargo.lock", "poetry.lock", "go.sum", "Pipfile.lock"):
        kwargs["direct_names"] = direct_names_for(path)
    try:
        rows = parser(path, **kwargs)
    except Exception:  # noqa: BLE001 — one bad lockfile must not kill the scan
        return []
    out = []
    for row in rows:
        if not row.get("name"):
            continue
        row.setdefault("scope", "resolved")
        out.append(row)
    return out
