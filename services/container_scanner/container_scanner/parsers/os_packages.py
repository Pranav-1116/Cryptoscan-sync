"""Parse OS package databases found in an unpacked container filesystem."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

DPKG_PACKAGE = re.compile(r"^Package:\s*(\S+)", re.IGNORECASE)
DPKG_VERSION = re.compile(r"^Version:\s*(\S+)", re.IGNORECASE)
DPKG_STATUS = re.compile(r"^Status:\s*(.+)", re.IGNORECASE)
APK_NAME = re.compile(r"^P:(\S+)")
APK_VERSION = re.compile(r"^V:(\S+)")
RPM_LINE = re.compile(r"^(\S+)-([0-9][^\s]*)\.([^.]+)$")
DIST_NAME = re.compile(r"^Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
DIST_VERSION = re.compile(r"^Version:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# Map common OS package names onto the cryptographic library catalog.
def _split_rpm_nvr(nvr: str) -> tuple[str, str | None]:
    parts = nvr.split("-")
    index = next((i for i, part in enumerate(parts) if part and part[0].isdigit()), None)
    if index is None:
        return nvr, None
    return "-".join(parts[:index]), "-".join(parts[index:])


CANONICAL = {
    "libssl3": "openssl",
    "libssl1.1": "openssl",
    "libssl1.0.0": "openssl",
    "openssl": "openssl",
    "libcrypto3": "openssl",
    "libcrypto1.1": "openssl",
    "libsodium23": "libsodium",
    "libsodium18": "libsodium",
    "libsodium": "libsodium",
    "libmbedtls14": "mbedtls",
    "libmbedcrypto7": "mbedtls",
    "libmbedx509-1": "mbedtls",
    "mbedtls": "mbedtls",
    "libgnutls30": "gnutls",
    "libgnutls28": "gnutls",
    "gnutls-bin": "gnutls",
    "libwolfssl37": "wolfssl",
    "wolfssl": "wolfssl",
    "libgcrypt20": "libgcrypt",
    "libnss3": "nss",
}


def canonical_name(name: str) -> str:
    return CANONICAL.get(name.lower(), name.lower())


def parse_dpkg_status(path: Path) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            _flush_dpkg(current, packages, path)
            current = {}
            continue
        match = DPKG_PACKAGE.match(line)
        if match:
            current["name"] = match.group(1)
            continue
        match = DPKG_VERSION.match(line)
        if match:
            current["version"] = match.group(1)
            continue
        match = DPKG_STATUS.match(line)
        if match:
            current["status"] = match.group(1)
    _flush_dpkg(current, packages, path)
    return packages


def _flush_dpkg(current: dict[str, str], packages: list[dict[str, Any]], path: Path) -> None:
    name = current.get("name")
    if not name:
        return
    status = (current.get("status") or "").lower()
    if status and "installed" not in status:
        return
    packages.append(
        {
            "name": canonical_name(name),
            "original_name": name.lower(),
            "version": current.get("version"),
            "manager": "dpkg",
            "manifest": str(path),
        }
    )


def parse_apk_installed(path: Path) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            _flush_apk(current, packages, path)
            current = {}
            continue
        match = APK_NAME.match(line)
        if match:
            current["name"] = match.group(1)
            continue
        match = APK_VERSION.match(line)
        if match:
            current["version"] = match.group(1)
    _flush_apk(current, packages, path)
    return packages


def _flush_apk(current: dict[str, str], packages: list[dict[str, Any]], path: Path) -> None:
    name = current.get("name")
    if not name:
        return
    packages.append(
        {
            "name": canonical_name(name),
            "original_name": name.lower(),
            "version": current.get("version"),
            "manager": "apk",
            "manifest": str(path),
        }
    )


def parse_rpm_qa(path: Path) -> list[dict[str, Any]]:
    """Parse `rpm -qa` style text (one NVR per line). Binary RPM DBs are skipped."""
    packages: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, version = _split_rpm_nvr(stripped)
        packages.append(
            {
                "name": canonical_name(name),
                "original_name": name.lower(),
                "version": version,
                "manager": "rpm",
                "manifest": str(path),
            }
        )
    return packages


def parse_site_packages(root: Path) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for meta in root.rglob("METADATA"):
        if "dist-info" not in meta.parent.name and "egg-info" not in meta.parent.name:
            continue
        try:
            text = meta.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name_match = DIST_NAME.search(text)
        version_match = DIST_VERSION.search(text)
        if not name_match:
            continue
        name = name_match.group(1).strip()
        packages.append(
            {
                "name": canonical_name(name),
                "original_name": name.lower(),
                "version": version_match.group(1).strip() if version_match else None,
                "manager": "pip-site-packages",
                "manifest": str(meta),
            }
        )
    return packages
