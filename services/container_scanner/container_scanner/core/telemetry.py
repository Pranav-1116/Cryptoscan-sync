"""Honest scan telemetry: what was actually scanned and how it was found.

Mirrors the network scanner's probe telemetry: counts you can trust about
coverage (files walked, manifests parsed) and detection quality (fingerprint
hit rate), with a coverage verdict that stays SKIPPED/FAILED/OK rather than
inventing success on an empty scan.
"""

from __future__ import annotations

from typing import Any


def build_scan_telemetry(
    *,
    packages: list[dict[str, Any]] | None = None,
    libraries: list[dict[str, Any]] | None = None,
    binaries: list[dict[str, Any]] | None = None,
    vulnerabilities: list[dict[str, Any]] | None = None,
    secrets: list[dict[str, Any]] | None = None,
    files_scanned: int | None = None,
) -> dict[str, Any]:
    packages = packages or []
    libraries = libraries or []
    binaries = binaries or []
    vulnerabilities = vulnerabilities or []
    secrets = secrets or []

    by_manager: dict[str, int] = {}
    manifests: set[str] = set()
    for pkg in packages:
        manager = str(pkg.get("manager") or "unknown")
        by_manager[manager] = by_manager.get(manager, 0) + 1
        if pkg.get("manifest"):
            manifests.add(str(pkg["manifest"]))

    binaries_by_type: dict[str, int] = {}
    fingerprinted = 0
    for binary in binaries:
        kind = str(binary.get("type") or "unknown")
        binaries_by_type[kind] = binaries_by_type.get(kind, 0) + 1
        if binary.get("detection_method") == "BINARY_FINGERPRINT":
            fingerprinted += 1

    secrets_by_kind: dict[str, int] = {}
    for secret in secrets:
        kind = str(secret.get("kind") or "unknown")
        secrets_by_kind[kind] = secrets_by_kind.get(kind, 0) + 1

    if not packages and not binaries:
        verdict = "SKIPPED" if files_scanned == 0 else "FAILED"
    elif libraries or fingerprinted:
        verdict = "OK"
    else:
        verdict = "PARTIAL"  # packages found but no crypto fingerprints matched

    return {
        "status": verdict,
        "packages": len(packages),
        "packages_by_manager": dict(sorted(by_manager.items())),
        "manifests_parsed": len(manifests),
        "libraries_fingerprinted": len(libraries),
        "binaries": len(binaries),
        "binaries_by_type": dict(sorted(binaries_by_type.items())),
        "binaries_fingerprinted": fingerprinted,
        "fingerprint_hit_rate": round(fingerprinted / len(binaries), 3) if binaries else None,
        "vulnerabilities": len(vulnerabilities),
        "secrets": len(secrets),
        "secrets_by_kind": dict(sorted(secrets_by_kind.items())),
        "files_scanned": files_scanned,
    }
