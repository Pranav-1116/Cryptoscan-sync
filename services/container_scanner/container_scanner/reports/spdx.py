"""SPDX 2.3 JSON export for container scan results.

A second SBOM dialect for consumers that standardize on SPDX instead of
CycloneDX.  Packages become SPDX packages with purl ``externalRefs``
(reusing the CycloneDX purl builder so the two bills agree), the scanned
target is described via a ``DESCRIBES`` relationship, and anything unknown
is ``NOASSERTION`` — SPDX's explicit "we do not claim to know" — rather
than an invented value.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from container_scanner.reports.sbom import _purl  # noqa: PLC2701 — shared purl contract


def _spdx_id(name: str, index: int) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", ".", "@"} else "-" for char in name)
    return f"SPDXRef-Package-{index}-{cleaned}"[:120]


def build_spdx(result: dict[str, Any] | None) -> dict[str, Any]:
    """Render a container scan result as an SPDX 2.3 JSON document."""
    result = result or {}
    packages_in = result.get("packages") or []
    spdx_packages: list[dict[str, Any]] = []
    for index, pkg in enumerate(packages_in, start=1):
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        version = pkg.get("version")
        entry: dict[str, Any] = {
            "name": name,
            "SPDXID": _spdx_id(name, index),
            "versionInfo": str(version) if version else "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl(str(pkg.get("manager") or "generic"), name, version or None),
                }
            ],
        }
        spdx_packages.append(entry)

    image = result.get("image") if isinstance(result.get("image"), dict) else {}
    target_name = str(result.get("target") or image.get("reference") or "unknown")
    kind = str(result.get("target_kind") or "filesystem")
    target_id = "SPDXRef-Container" if kind not in {"filesystem", ""} else "SPDXRef-Rootfs"
    target_package = {
        "name": target_name,
        "SPDXID": target_id,
        "versionInfo": str(image.get("digest") or "NOASSERTION"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    package_entries = list(spdx_packages)
    spdx_packages.insert(0, target_package)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": target_name,
        "documentNamespace": f"https://cryptoscan.local/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [f"Tool: CryptoScan-container-scanner-{result.get('scanner_version') or '1.0.0'}"],
        },
        "packages": spdx_packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": target_id,
            }
        ]
        + [
            {
                "spdxElementId": target_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": entry["SPDXID"],
            }
            for entry in package_entries
        ],
    }
