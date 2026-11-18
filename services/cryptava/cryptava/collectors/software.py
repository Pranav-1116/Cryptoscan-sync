"""SBOM: what software is installed — read from the package databases, never by
running a package manager's maintainer code.

* Debian/Ubuntu: ``/var/lib/dpkg/status`` (+ ``info/*.list`` for which package owns
  which shared library);
* Alpine: ``/lib/apk/db/installed`` (file ownership is in the same file);
* RHEL/SUSE/Fedora: ``rpmdb.sqlite`` read with the standard-library sqlite3 and a
  header parser; the older BerkeleyDB format falls back to ``rpm -qa --qf`` (read-only
  query, allowlisted argv) when the agent runs on the host itself;
* Python: ``*.dist-info/METADATA`` under the system and ``/opt`` prefixes;
* Java: ``*.jar`` file names under the configured application directories.
"""

from __future__ import annotations

import re
import sqlite3
import struct
from typing import Any

from cryptava.collectors import Context
from cryptava.util import run_allowed, slug

DEFAULT_JAR_DIRS = ["/opt", "/usr/share/java", "/srv", "/app", "/usr/local/lib"]
PYTHON_GLOBS = ["usr/lib/python3*/site-packages", "usr/lib/python3*/dist-packages",
                "usr/lib/python3/dist-packages", "usr/local/lib/python3*/site-packages",
                "usr/local/lib/python3*/dist-packages", "usr/lib64/python3*/site-packages"]
JAR_NAME = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+?)-(?P<version>\d[\w.\-+]*)\.jar$")


# --------------------------------------------------------------------------- #
# package databases
# --------------------------------------------------------------------------- #

def parse_dpkg_status(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        last = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                continue  # continuation lines (descriptions, conffiles)
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            last = key.strip().lower()
            fields[last] = value.strip()
        name = fields.get("package")
        status = fields.get("status", "").split()
        if not name or len(status) < 3 or status[2] != "installed":
            continue
        out.append({"name": name, "version": fields.get("version"), "architecture": fields.get("architecture"),
                    "maintainer": fields.get("maintainer"), "source_package": (fields.get("source") or "").split(" ")[0] or None,
                    "homepage": fields.get("homepage"), "ecosystem": "deb"})
    return out


def parse_apk_installed(text: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    packages: list[dict[str, Any]] = []
    owners: dict[str, str] = {}
    for record in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        folder = ""
        name = None
        files: list[str] = []
        for line in record.splitlines():
            if len(line) < 2 or line[1] != ":":
                continue
            key, value = line[0], line[2:]
            if key == "P":
                name = value
            if key == "F":
                folder = value
            elif key == "R":
                files.append(f"/{folder}/{value}" if folder else f"/{value}")
            elif key not in fields:
                fields[key] = value
        if not name:
            continue
        packages.append({"name": name, "version": fields.get("V"), "architecture": fields.get("A"),
                         "maintainer": fields.get("m"), "source_package": fields.get("o"),
                         "homepage": fields.get("U"), "license": fields.get("L"), "ecosystem": "apk"})
        for path in files:
            if ".so" in path:
                owners[path] = name
    return packages, owners


def _rpm_header(blob: bytes) -> dict[int, Any]:
    """Tags of one rpm header blob (as stored in rpmdb.sqlite ``Packages.blob``)."""
    if len(blob) < 8:
        return {}
    il, dl = struct.unpack(">ii", blob[:8])
    if il <= 0 or il > 10000 or dl < 0:
        return {}
    index_end = 8 + il * 16
    data = blob[index_end:index_end + dl]
    wanted = {1000, 1001, 1002, 1003, 1011, 1014, 1015, 1020, 1022, 1044, 1116, 1117, 1118}
    tags: dict[int, Any] = {}
    for i in range(il):
        tag, kind, offset, count = struct.unpack(">iiii", blob[8 + i * 16: 24 + i * 16])
        if tag not in wanted or offset < 0 or offset >= len(data):
            continue
        if kind in (6, 9):  # STRING / I18NSTRING (first)
            end = data.find(b"\x00", offset)
            tags[tag] = data[offset:end if end >= 0 else None].decode("utf-8", "replace")
        elif kind == 8:  # STRING_ARRAY
            items, cursor = [], offset
            for _ in range(min(count, 100000)):
                end = data.find(b"\x00", cursor)
                if end < 0:
                    break
                items.append(data[cursor:end].decode("utf-8", "replace"))
                cursor = end + 1
            tags[tag] = items
        elif kind == 4:  # INT32
            values = [struct.unpack(">i", data[offset + 4 * j: offset + 4 * j + 4])[0]
                      for j in range(min(count, 100000)) if offset + 4 * j + 4 <= len(data)]
            tags[tag] = values
    return tags


def parse_rpm_sqlite(path: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    packages: list[dict[str, Any]] = []
    owners: dict[str, str] = {}
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        rows = connection.execute("SELECT blob FROM Packages").fetchall()
    finally:
        connection.close()
    for (blob,) in rows:
        tags = _rpm_header(bytes(blob))
        name = tags.get(1000)
        if not name or name == "gpg-pubkey":
            continue
        epoch = (tags.get(1003) or [None])[0]
        version = f"{tags.get(1001)}-{tags.get(1002)}"
        if epoch:
            version = f"{epoch}:{version}"
        packages.append({"name": name, "version": version, "architecture": tags.get(1022),
                         "maintainer": tags.get(1015), "vendor": tags.get(1011), "license": tags.get(1014),
                         "homepage": tags.get(1020), "source_package": tags.get(1044), "ecosystem": "rpm"})
        bases, dirs, indexes = tags.get(1117) or [], tags.get(1118) or [], tags.get(1116) or []
        for base, index in zip(bases, indexes):
            if ".so" in base and 0 <= index < len(dirs):
                owners[f"{dirs[index]}{base}"] = name
    return packages, owners


def _rpm_cli() -> list[dict[str, Any]]:
    result = run_allowed(["rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n"], timeout=60)
    if not result.ok:
        return []
    out = []
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] != "gpg-pubkey":
            version = parts[1][2:] if parts[1].startswith("0:") else parts[1]
            out.append({"name": parts[0], "version": version, "architecture": parts[2],
                        "vendor": parts[3] if len(parts) > 3 and parts[3] != "(none)" else None, "ecosystem": "rpm"})
    return out


def _dpkg_owners(ctx: Context, names: list[str]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for name in names:
        listing = None
        for candidate in (f"/var/lib/dpkg/info/{name}.list",):
            listing = ctx.view.read_text(candidate, limit=4 * 1024 * 1024)
            if listing:
                break
        if not listing:
            for match in ctx.view.glob("/var/lib/dpkg/info", f"{name}:*.list")[:1]:
                listing = ctx.view.read_text(match, limit=4 * 1024 * 1024)
        for path in (listing or "").splitlines():
            if ".so" in path or path.endswith(".dist-info"):
                owners[path.strip()] = name
    return owners


def _python(ctx: Context, owners: dict[str, str]) -> list[dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    directories: list[str] = []
    for pattern in PYTHON_GLOBS:
        directories.extend(ctx.view.glob("/", pattern))
    for extra in ctx.view.glob("/opt", "*/lib/python3*/site-packages") + ctx.view.glob("/opt", "*/*/lib/python3*/site-packages"):
        directories.append(extra)
    for directory in sorted(set(directories)):
        for info in ctx.view.glob(directory, "*.dist-info"):
            if info in owners:  # installed by the OS package manager: already in the SBOM
                continue
            meta = ctx.view.read_text(f"{info}/METADATA", limit=65536) or ""
            name = version = None
            for line in meta.splitlines()[:40]:
                if line.startswith("Name:"):
                    name = line[5:].strip()
                elif line.startswith("Version:"):
                    version = line[8:].strip()
            if name and version:
                found[(name.lower(), version)] = {"name": name, "version": version, "ecosystem": "pypi",
                                                   "location": directory}
    return list(found.values())


def _jars(ctx: Context) -> list[dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for directory in ctx.config.get("jar_dirs") or DEFAULT_JAR_DIRS:
        if not ctx.view.exists(directory):
            continue
        for path in ctx.view.walk_files(directory, max_depth=6, max_files=4000, suffixes=(".jar",)):
            match = JAR_NAME.match(path.rsplit("/", 1)[-1])
            if not match:
                continue
            key = (match.group("name"), match.group("version"))
            entry = found.setdefault(key, {"name": key[0], "version": key[1], "ecosystem": "maven", "paths": []})
            if len(entry["paths"]) < 5:
                entry["paths"].append(path)
    return list(found.values())


# --------------------------------------------------------------------------- #
# the plane
# --------------------------------------------------------------------------- #

def collect(ctx: Context) -> None:
    obs, view = ctx.obs, ctx.view
    sources: list[str] = []
    problems: list[str] = []
    packages: list[dict[str, Any]] = []

    dpkg = view.read_text("/var/lib/dpkg/status", limit=64 * 1024 * 1024)
    if dpkg:
        parsed = parse_dpkg_status(dpkg)
        packages.extend(parsed)
        ctx.file_owner.update(_dpkg_owners(ctx, [p["name"] for p in parsed]))
        sources.append(f"dpkg ({len(parsed)})")
    apk = view.read_text("/lib/apk/db/installed", limit=64 * 1024 * 1024)
    if apk:
        parsed, owners = parse_apk_installed(apk)
        packages.extend(parsed)
        ctx.file_owner.update(owners)
        sources.append(f"apk ({len(parsed)})")
    rpm_db = next((p for p in ("/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite") if view.exists(p)), None)
    if rpm_db:
        try:
            parsed, owners = parse_rpm_sqlite(str(view.host_path(rpm_db)))
            packages.extend(parsed)
            ctx.file_owner.update(owners)
            sources.append(f"rpm ({len(parsed)})")
        except sqlite3.Error as exc:
            problems.append(f"rpmdb.sqlite unreadable: {exc}")
    elif view.exists("/var/lib/rpm/Packages") and str(view.root) == "/":
        parsed = _rpm_cli()
        if parsed:
            packages.extend(parsed)
            sources.append(f"rpm -qa ({len(parsed)})")
        else:
            problems.append("BerkeleyDB rpm database present but `rpm -qa` failed")

    os_packages = len(packages)
    python = _python(ctx, ctx.file_owner) if ctx.config.get("python_packages", True) else []
    jars = _jars(ctx) if ctx.config.get("java_archives", True) else []
    if python:
        sources.append(f"python ({len(python)})")
    if jars:
        sources.append(f"jar ({len(jars)})")
    packages.extend(python)
    packages.extend(jars)

    limit = int(ctx.config.get("max_packages", 6000))
    if len(packages) > limit:
        problems.append(f"{len(packages)} packages found; only the first {limit} are reported (max_packages)")
        packages = packages[:limit]

    for package in packages:
        eco, name, version = package["ecosystem"], package["name"], package.get("version") or "unknown"
        ref = f"pkg:{eco}:{slug(name, limit=120)}:{slug(version, limit=60)}"
        obs.asset(ref, "PACKAGE", name, identity={"name": name, "version": version, "ecosystem": eco},
                  attributes={"version": version, "ecosystem": eco,
                              **{k: package.get(k) for k in ("architecture", "maintainer", "vendor", "source_package",
                                                              "homepage", "license", "location")},
                              "paths": package.get("paths")},
                  source=f"cryptava-{eco}")
        ev = obs.observe(ref, "STATIC_OBSERVED", {
            "installed_version": version, "ecosystem": eco, "architecture": package.get("architecture"),
            "host": ctx.fqdn, "source": {"deb": "/var/lib/dpkg/status", "apk": "/lib/apk/db/installed",
                                         "rpm": "rpm database", "pypi": "dist-info METADATA",
                                         "maven": "jar file name"}.get(eco, eco),
        }, layer="PLATFORM", source=f"cryptava-{eco}")
        obs.relate(ref, "part_of", ctx.host_ref, basis="DEPLOYMENT_CONFIG", evidence=[ev])
        ctx.packages.setdefault(name, {"version": version, "ecosystem": eco, "ref": ref,
                                       "maintainer": package.get("maintainer"), "vendor": package.get("vendor")})

    if not packages:
        obs.plane("SBOM · software", "FAILED",
                  "no package database found (dpkg, apk, rpm) and no Python/Java packages" +
                  (f"; {'; '.join(problems)}" if problems else ""), expected=1, collected=0)
        return
    status = "PARTIAL" if problems or not os_packages else "COMPLETE"
    obs.plane("SBOM · software", status, f"{len(packages)} packages from {', '.join(sources)}" +
              (f"; {'; '.join(problems)}" if problems else ""), expected=1, collected=1)
    obs.cover(f"{ctx.hostname} · package databases", max(1, len(sources)), len(sources))
