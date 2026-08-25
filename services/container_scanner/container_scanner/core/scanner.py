"""Filesystem / image-root / registry-image container scanner."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from container_scanner.analyzers.analyzer_coordinator import AnalyzerCoordinator
from container_scanner.analyzers.binary.binary_fingerprinter import hash_file
from container_scanner.cve.resolver import VulnerabilityResolver
from container_scanner.fingerprints.repository import FingerprintRepository

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
        self.analyzers = AnalyzerCoordinator()

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
        return self.analyzers.discover_packages(root)

    def _hash_file(self, path: Path) -> str | None:
        return hash_file(path)

    def _fingerprint_binary(self, path: Path, rel: str, *, kind: str, default: dict[str, Any]) -> dict[str, Any]:
        payload = dict(default)
        digest = self._hash_file(path)
        if digest:
            payload["sha256"] = digest
            hit = self.catalog.lookup_hash(digest)
            if hit:
                payload["library"] = hit.get("library") or payload.get("library")
                payload["version"] = hit.get("version") or payload.get("version")
                payload["algorithms"] = list(hit.get("algorithms") or payload.get("algorithms") or [])
                payload["confidence"] = "HIGH"
                payload["detection_method"] = "BINARY_FINGERPRINT"
        payload.setdefault("type", kind)
        payload.setdefault("path", rel)
        payload.setdefault("name", path.name.lower())
        return payload

    def _discover_binaries(self, root: Path) -> Iterable[dict[str, Any]]:
        crypto_names = {
            "libcrypto.so",
            "libssl.so",
            "libcrypto.so.1.1",
            "libcrypto.so.3",
            "libssl.so.1.1",
            "libssl.so.3",
            "libbcprov.so",
        }
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            suffix = path.suffix.lower()
            rel = str(path.relative_to(root))
            name = path.name.lower()
            if suffix == ".jar":
                info = self.catalog.match_binary(path.name)
                yield self._fingerprint_binary(
                    path,
                    rel,
                    kind="jar",
                    default={
                        "name": path.stem.lower(),
                        "library": (info or {}).get("vendor") and self.catalog.canonical(path.name),
                        "algorithms": list((info or {}).get("algorithms") or []),
                    },
                )
            elif "site-packages" in path.parts and suffix == ".so":
                yield self._fingerprint_binary(
                    path,
                    rel,
                    kind="native-extension",
                    default={"name": path.stem.lower()},
                )
            elif name in crypto_names or name.startswith("libcrypto") or name.startswith("libssl"):
                info = self.catalog.match_binary(path.name)
                yield self._fingerprint_binary(
                    path,
                    rel,
                    kind="shared-library",
                    default={
                        "library": "openssl",
                        "algorithms": list((info or {}).get("algorithms") or ["AES", "RSA", "SHA-256"]),
                    },
                )

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
                        "confidence": binary.get("confidence") or "LOW",
                        "confidence_reason": binary.get("detection_method")
                        or "binary name fingerprint (no disassembly)",
                        "library": binary.get("library") or binary.get("name"),
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
