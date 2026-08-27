"""Base-image fingerprinting: which distro is this, and is it end-of-life?

Scanners love to enumerate packages; nobody asks whether the base image
itself still receives security updates.  This module fingerprints the rootfs
OS from the standard sources — ``/etc/os-release`` (or ``/usr/lib/os-release``)
first, then the legacy per-distro release files — infers the expected
package-manager family, cross-checks that against the package databases
actually present on disk, and checks the version against a curated EOL table.

Honesty rules: an unparseable or missing identity yields ``None`` /
``UNKNOWN`` — never a guess; versions outside the table are ``UNKNOWN``
(``status`` carries the verdict, ``days_past_eol`` the arithmetic); the EOL
table only contains dates we can stand behind.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path
from typing import Any

# family -> expected package-manager databases on disk
FAMILY_MANAGERS = {
    "alpine": {"apk"},
    "debian": {"dpkg"},
    "rhel": {"rpm"},
}

_DISTRO_FAMILY = {
    "alpine": "alpine",
    "debian": "debian",
    "ubuntu": "debian",
    "raspbian": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "fedora": "rhel",
    "rocky": "rhel",
    "rockylinux": "rhel",
    "almalinux": "rhel",
    "amzn": "rhel",
    "ol": "rhel",
}

# end-of-standard-support dates (YYYY-MM-DD); only entries we can stand behind
EOL_TABLE: dict[str, dict[str, str]] = {
    "alpine": {
        "3.14": "2023-05-01",
        "3.15": "2023-11-01",
        "3.16": "2024-05-23",
        "3.17": "2024-11-22",
        "3.18": "2025-05-09",
        "3.19": "2025-11-01",
        "3.20": "2026-05-01",
    },
    "debian": {
        "9": "2022-06-30",
        "10": "2024-06-30",
        "11": "2026-08-31",
        "12": "2028-06-30",
    },
    "ubuntu": {
        "16.04": "2021-04-30",
        "18.04": "2023-05-31",
        "20.04": "2025-04-01",
        "22.04": "2027-04-01",
    },
    "centos": {
        "7": "2024-06-30",
        "8": "2021-12-31",
    },
}

_RHEL_RELEASE = re.compile(r"release\s+([\d.]+)", re.IGNORECASE)


def parse_os_release(text: str) -> dict[str, str]:
    """Pure: os-release KEY=VALUE lines -> dict (quotes stripped, comments skipped)."""
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        fields[key.strip()] = value
    return fields


def _from_os_release(fields: dict[str, str], source: str) -> dict[str, Any] | None:
    distro_id = (fields.get("ID") or "").strip().lower()
    if not distro_id:
        return None
    return {
        "id": distro_id,
        "name": fields.get("NAME") or distro_id,
        "version_id": (fields.get("VERSION_ID") or "").strip(),
        "id_like": [item.strip() for item in (fields.get("ID_LIKE") or "").split() if item.strip()],
        "family": _DISTRO_FAMILY.get(distro_id, ""),
        "source": source,
    }


def detect_distro(root: Path) -> dict[str, Any] | None:
    """Fingerprint the rootfs OS; None when nothing recognizable is present."""
    root = Path(root)
    for candidate in ("etc/os-release", "usr/lib/os-release"):
        path = root / candidate
        if path.is_file():
            try:
                parsed = _from_os_release(parse_os_release(path.read_text(encoding="utf-8")), candidate)
            except OSError:
                parsed = None
            if parsed:
                return parsed
    alpine = root / "etc/alpine-release"
    if alpine.is_file():
        try:
            version = alpine.read_text(encoding="utf-8").strip()
        except OSError:
            version = ""
        return {"id": "alpine", "name": "Alpine Linux", "version_id": version, "id_like": [], "family": "alpine", "source": "etc/alpine-release"}
    debian = root / "etc/debian_version"
    if debian.is_file():
        try:
            version = debian.read_text(encoding="utf-8").strip().splitlines()[0]
        except OSError:
            version = ""
        return {"id": "debian", "name": "Debian GNU/Linux", "version_id": version, "id_like": [], "family": "debian", "source": "etc/debian_version"}
    for name in ("etc/redhat-release", "etc/centos-release"):
        path = root / name
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            match = _RHEL_RELEASE.search(text)
            distro_id = "centos" if "centos" in name else "rhel"
            return {
                "id": distro_id,
                "name": text.strip().splitlines()[0][:80],
                "version_id": match.group(1) if match else "",
                "id_like": [],
                "family": "rhel",
                "source": name,
            }
    return None


def package_manager_evidence(root: Path) -> dict[str, bool]:
    """Which package-manager databases actually exist on disk."""
    root = Path(root)
    return {
        "dpkg": (root / "var/lib/dpkg/status").is_file(),
        "rpm": (root / "var/lib/rpm").is_dir() or (root / "usr/lib/sysimage/rpm").is_dir(),
        "apk": (root / "lib/apk/db/installed").is_file() or (root / "etc/apk").is_dir(),
    }


def eol_status(distro_id: str, version_id: str, *, today: date | None = None) -> dict[str, Any]:
    """EOL verdict for a distro/version; UNKNOWN for anything off the table."""
    table = EOL_TABLE.get(str(distro_id or "").lower())
    if not table or not version_id:
        return {"status": "UNKNOWN", "eol_date": None, "days_past_eol": None}
    parts = str(version_id).split(".")
    candidates = [str(version_id), ".".join(parts[:2]), parts[0]]
    eol_raw = next((table[candidate] for candidate in candidates if candidate in table), None)
    if eol_raw is None:
        return {"status": "UNKNOWN", "eol_date": None, "days_past_eol": None}
    eol_date = datetime.strptime(eol_raw, "%Y-%m-%d").date()
    now = today or date.today()
    days_past = (now - eol_date).days
    return {
        "status": "EOL" if days_past >= 0 else "SUPPORTED",
        "eol_date": eol_raw,
        "days_past_eol": max(0, days_past) if days_past >= 0 else 0,
    }


def fingerprint_base_image(root: Path, *, today: date | None = None) -> dict[str, Any] | None:
    """Distro + package-manager cross-check + EOL verdict in one payload."""
    distro = detect_distro(root)
    if distro is None:
        return None
    evidence = package_manager_evidence(root)
    expected = FAMILY_MANAGERS.get(distro["family"] or "", set())
    present = {manager for manager, found in evidence.items() if found}
    mismatch = bool(expected) and expected.isdisjoint(present)
    distro.update(
        {
            "package_managers_present": sorted(present),
            "package_managers_expected": sorted(expected),
            "manager_mismatch": mismatch,
            "eol": eol_status(distro["id"], distro["version_id"], today=today),
        }
    )
    return distro
