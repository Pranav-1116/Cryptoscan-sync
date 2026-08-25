"""Filesystem / image-root / registry-image container scanner."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from container_scanner.cve.resolver import VulnerabilityResolver
from container_scanner.fingerprints.repository import FingerprintRepository
from container_scanner.parsers.os_packages import (
    parse_apk_installed,
    parse_dpkg_status,
    parse_rpm_qa,
    parse_site_packages,
)
from container_scanner.parsers.package_parsers import (
    parse_csproj,
    parse_gomod,
    parse_package_json,
    parse_pom,
    parse_requirements,
)

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    "proc",
    "sys",
    "dev",
    "run",
}


def _load_json(name: str) -> dict[str, Any]:
    path = DATA_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


class ContainerScanner:
    def __init__(
        self,
        fingerprint_db: dict | None = None,
        cve_db: dict | None = None,
        *,
        live_cve: bool | None = None,
        resolver: VulnerabilityResolver | None = None,
    ):
        self.fingerprints = fingerprint_db or _load_json("fingerprint_db.json")
        self.cves = cve_db or _load_json("cve_db.json")
        self.catalog = FingerprintRepository(self.fingerprints)
        self.resolver = resolver or VulnerabilityResolver(self.cves, live=live_cve)

    def scan_filesystem(self, root: str | Path, *, scan_id: str | None = None) -> dict[str, Any]:
        root_path = Path(root)
        packages = list(self._discover_packages(root_path))
        libraries = [item for item in (self._fingerprint(pkg) for pkg in packages) if item]
        binaries = list(self._discover_binaries(root_path))
        vulns = self.resolver.lookup(packages)
        findings = self._to_findings(libraries, binaries, vulns)
        return {
            "scan_id": scan_id or str(uuid.uuid4()),
            "scanner_id": "container-scanner-v1.0",
            "scanner_version": "1.0.0",
            "target": str(root_path),
            "target_kind": "filesystem",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "packages": packages,
            "libraries": libraries,
            "binaries": binaries,
            "vulnerabilities": vulns,
            "findings": findings,
        }

    def scan_image(
        self,
        reference: str,
        *,
        scan_id: str | None = None,
        workdir: str | Path | None = None,
    ) -> dict[str, Any]:
        from container_scanner.image.puller import resolve_image

        extracted = resolve_image(reference, workdir=workdir)
        result = self.scan_filesystem(extracted.root, scan_id=scan_id)
        result["target"] = reference
        result["target_kind"] = extracted.source
        result["image"] = extracted.to_dict()
        return result

    def scan(
        self,
        *,
        path: str | Path | None = None,
        image: str | None = None,
        archive: str | None = None,
        scan_id: str | None = None,
        workdir: str | Path | None = None,
    ) -> dict[str, Any]:
        if archive:
            return self.scan_image(str(archive), scan_id=scan_id, workdir=workdir)
        if image:
            return self.scan_image(image, scan_id=scan_id, workdir=workdir)
        if path:
            return self.scan_filesystem(path, scan_id=scan_id)
        raise ValueError("path, image, or archive is required")

    def _discover_packages(self, root: Path) -> Iterable[dict[str, Any]]:
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            name = path.name.lower()
            posix = path.as_posix()
            if name == "requirements.txt":
                yield from parse_requirements(path)
            elif name == "package.json":
                yield from parse_package_json(path)
            elif name == "pom.xml":
                yield from parse_pom(path)
            elif name.endswith(".csproj"):
                yield from parse_csproj(path)
            elif name == "go.mod":
                yield from parse_gomod(path)
            elif posix.endswith("/var/lib/dpkg/status") or name == "dpkg-status":
                yield from parse_dpkg_status(path)
            elif posix.endswith("/lib/apk/db/installed") or name in {"apk-installed", "installed"}:
                if "apk" in posix or name == "apk-installed":
                    yield from parse_apk_installed(path)
            elif name in {"rpm-packages.txt", "rpm-qa.txt"}:
                yield from parse_rpm_qa(path)
        yield from parse_site_packages(root)

    def _discover_binaries(self, root: Path) -> Iterable[dict[str, Any]]:
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            suffix = path.suffix.lower()
            rel = str(path.relative_to(root))
            if suffix == ".jar":
                info = self.catalog.match_binary(path.name)
                yield {
                    "type": "jar",
                    "path": rel,
                    "name": path.stem.lower(),
                    "library": (info or {}).get("vendor") and self.catalog.canonical(path.name),
                    "algorithms": list((info or {}).get("algorithms") or []),
                }
            elif "site-packages" in path.parts and suffix == ".so":
                yield {"type": "native-extension", "path": rel, "name": path.stem.lower()}
            elif path.name.lower() in {"libcrypto.so", "libssl.so", "libcrypto.so.3", "libssl.so.3"}:
                info = self.catalog.match_binary(path.name)
                yield {
                    "type": "shared-library",
                    "path": rel,
                    "name": path.name.lower(),
                    "library": "openssl",
                    "algorithms": list((info or {}).get("algorithms") or ["AES", "RSA", "SHA-256"]),
                }

    def _fingerprint(self, package: dict[str, Any]) -> dict[str, Any] | None:
        name = self.catalog.canonical(package.get("name"))
        info = self.catalog.lookup(name)
        if info is None:
            return None
        return {
            "name": name,
            "version": package.get("version"),
            "manager": package.get("manager"),
            "manifest": package.get("manifest"),
            "algorithms": list(info.get("algorithms") or []),
            "vendor": info.get("vendor"),
            "deprecated": bool(info.get("deprecated")),
            "language": info.get("language"),
        }

    def _to_findings(
        self,
        libraries: list[dict[str, Any]],
        binaries: list[dict[str, Any]],
        vulns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for lib in libraries:
            for algorithm in lib.get("algorithms") or ["UNKNOWN"]:
                findings.append(
                    {
                        "finding_id": str(uuid.uuid4()),
                        "scanner_id": "container-scanner-v1.0",
                        "scanner_version": "1.0.0",
                        "source": {
                            "type": "CONTAINER_PACKAGE",
                            "language": lib.get("language") or "UNKNOWN",
                            "file_path": lib.get("manifest") or lib.get("name"),
                            "line_number": 0,
                            "class_name": lib.get("name"),
                        },
                        "crypto": {
                            "api_type": "CRYPTOGRAPHIC_LIBRARY",
                            "algorithm": algorithm,
                            "purpose": "UNKNOWN",
                        },
                        "metadata": {
                            "confidence": "MEDIUM",
                            "confidence_reason": "package-manager fingerprint",
                            "library": lib.get("name"),
                            "is_hardcoded_key": False,
                        },
                    }
                )
        for binary in binaries:
            findings.append(
                {
                    "finding_id": str(uuid.uuid4()),
                    "scanner_id": "container-scanner-v1.0",
                    "scanner_version": "1.0.0",
                    "source": {
                        "type": "CONTAINER_BINARY",
                        "language": "BINARY",
                        "file_path": binary.get("path"),
                        "line_number": 0,
                        "class_name": binary.get("name"),
                    },
                    "crypto": {
                        "api_type": "CRYPTOGRAPHIC_LIBRARY",
                        "algorithm": "UNKNOWN",
                        "purpose": "UNKNOWN",
                    },
                    "metadata": {
                        "confidence": "LOW",
                        "confidence_reason": "binary name fingerprint (no disassembly)",
                        "library": binary.get("name"),
                        "is_hardcoded_key": False,
                    },
                }
            )
        for vuln in vulns:
            findings.append(
                {
                    "finding_id": str(uuid.uuid4()),
                    "scanner_id": "container-scanner-v1.0",
                    "scanner_version": "1.0.0",
                    "source": {
                        "type": "CONTAINER_VULN",
                        "language": "UNKNOWN",
                        "file_path": vuln.get("manifest") or vuln.get("package"),
                        "line_number": 0,
                        "class_name": vuln.get("cve"),
                    },
                    "crypto": {
                        "api_type": "VULNERABLE_LIBRARY",
                        "algorithm": "UNKNOWN",
                        "purpose": "UNKNOWN",
                    },
                    "metadata": {
                        "confidence": "HIGH",
                        "confidence_reason": f"{vuln.get('source') or 'local'} CVE match {vuln.get('cve')}",
                        "library": vuln.get("package"),
                        "is_hardcoded_key": False,
                    },
                    "vulnerability": vuln,
                }
            )
        return findings
