"""CycloneDX 1.5 SBOM export for container scan results.

Turns a scan's packages + crypto libraries + binaries + CVEs into a
CycloneDX JSON bill of materials:

* every package becomes a component with a purl (``pkg:pypi/...``,
  ``pkg:deb/...``, ``pkg:npm/@scope/...`` ...) typed from its manager;
* crypto-fingerprinted libraries carry their algorithms and vendor as
  CycloneDX properties, so the SBOM is also a crypto inventory;
* binaries with sha256 hashes become components with hash entries;
* CVEs land in the top-level ``vulnerabilities`` array with severity
  ratings and ``affects`` refs onto the matching components;
* ``metadata.component`` describes the scanned target (image or rootfs).

Unknown versions are omitted rather than invented (``@`` only when a
version exists); names are kept as-is except npm scopes, where the purl
spec requires the ``@scope/name`` form.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

PURL_TYPES = {
    "pip": "pypi",
    "pip-site-packages": "pypi",
    "npm": "npm",
    "maven": "maven",
    "dpkg": "deb",
    "nuget": "nuget",
    "go": "golang",
    "apk": "apk",
    "composer": "composer",
    "rpm": "rpm",
    "bundler": "gem",
    "cargo": "cargo",
}
_COMPONENT_TYPE = {
    "deb": "library",
    "rpm": "library",
    "apk": "library",
    "docker": "container",
}

_NPM_SCOPED = {"npm", "composer"}


def _purl(manager: str, name: str, version: str | None) -> str:
    purl_type = PURL_TYPES.get(manager, "generic")
    segments = [purl_type]
    if purl_type == "deb":
        segments.append("debian")  # conservative default distro namespace
    target = name.replace("@", "%40") if purl_type == "npm" and name.startswith("@") else name
    segments.append(target)
    purl = "pkg:" + "/".join(segments)
    if version:
        purl += f"@{version}"
    return purl


def _component_ref(manager: str, name: str, version: str | None) -> str:
    return _purl(manager, name, version)


def build_sbom(result: dict[str, Any] | None) -> dict[str, Any]:
    """Render a container scan result as a CycloneDX 1.5 JSON document."""
    result = result or {}
    packages = result.get("packages") or []
    libraries = result.get("libraries") or []
    binaries = result.get("binaries") or []
    vulnerabilities = result.get("vulnerabilities") or []
    lib_by_name = {str(lib.get("name")).lower(): lib for lib in libraries}

    components: list[dict[str, Any]] = []
    refs: dict[tuple[str, str], str] = {}

    def properties(pairs: list[tuple[str, str]]) -> list[dict[str, str]] | None:
        clean = [{"name": name, "value": value} for name, value in pairs if value not in (None, "")]
        return clean or None

    for pkg in packages:
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        manager = str(pkg.get("manager") or "generic")
        version = pkg.get("version") or None
        purl_type = PURL_TYPES.get(manager, "generic")
        ref = _component_ref(manager, name, version)
        refs[(manager, name.lower())] = ref
        component: dict[str, Any] = {
            "type": _COMPONENT_TYPE.get(purl_type, "library"),
            "name": name,
            "bom-ref": ref,
            "purl": _purl(manager, name, version),
        }
        if version:
            component["version"] = str(version)
        lib = lib_by_name.get(name.lower())
        if lib is not None:
            component["properties"] = properties(
                [
                    ("cryptoscan:crypto-library", "true"),
                    ("cryptoscan:vendor", str(lib.get("vendor") or "")),
                    ("cryptoscan:deprecated", "true" if lib.get("deprecated") else "false"),
                    ("cryptoscan:algorithms", ", ".join(str(a) for a in (lib.get("algorithms") or []))),
                ]
            )
        components.append(component)

    for binary in binaries:
        name = str(binary.get("name") or binary.get("path") or "").strip()
        if not name:
            continue
        ref = f"cryptoscan:binary/{binary.get('path') or name}"
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "bom-ref": ref,
        }
        if binary.get("version"):
            component["version"] = str(binary["version"])
        if binary.get("sha256"):
            component["hashes"] = [{"alg": "SHA-256", "content": str(binary["sha256"])}]
        component["properties"] = properties(
            [
                ("cryptoscan:binary-type", str(binary.get("type") or "")),
                ("cryptoscan:detection", str(binary.get("detection_method") or "name-match")),
                ("cryptoscan:algorithms", ", ".join(str(a) for a in (binary.get("algorithms") or []))),
            ]
        )
        components.append(component)

    vuln_entries: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        cve = str(vuln.get("cve") or "").strip()
        if not cve:
            continue
        severity = str(vuln.get("severity") or "unknown").upper()
        affects_ref = refs.get((str(vuln.get("manager") or ""), str(vuln.get("package") or "").lower()))
        if affects_ref is None:
            for (manager, name), ref in refs.items():
                if name == str(vuln.get("package") or "").lower():
                    affects_ref = ref
                    break
        entry: dict[str, Any] = {
            "bom-ref": f"cryptoscan:vuln/{cve}",
            "id": cve,
            "ratings": [{"severity": _cdx_severity(severity)}],
        }
        if vuln.get("summary"):
            entry["description"] = str(vuln["summary"])[:500]
        if affects_ref:
            entry["affects"] = [{"ref": affects_ref}]
        vuln_entries.append(entry)

    image = result.get("image") if isinstance(result.get("image"), dict) else {}
    target = str(result.get("target") or image.get("reference") or "unknown")
    kind = str(result.get("target_kind") or "filesystem")
    metadata_component = {
        "type": "container" if kind not in {"filesystem", ""} else "file",
        "name": target,
        "bom-ref": "cryptoscan:target",
    }
    if image.get("digest"):
        metadata_component["hashes"] = [{"alg": "SHA-256", "content": str(image["digest"]).removeprefix("sha256:")}]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "CryptoScan", "name": "container-scanner", "version": "1.0.0"}],
            "component": metadata_component,
        },
        "components": components,
        "vulnerabilities": vuln_entries,
    }


def _cdx_severity(severity: str) -> str:
    lowered = str(severity).lower()
    return lowered if lowered in {"critical", "high", "medium", "low", "info", "none", "unknown"} else "unknown"
