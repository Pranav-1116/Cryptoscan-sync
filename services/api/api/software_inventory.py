"""Software components a scan already found — the SBOM rows behind a real scan.

The scanner's cascade pass parses every manifest and lockfile in a target and
reports two things an SBOM is made of:

* the **crypto libraries** the code and the manifests name (``openssl``,
  ``javax.crypto``, ``python-cryptography`` …), with the manifests that declare
  them and the algorithms seen against them;
* the **package coordinates** those manifests declare (``pypi/cryptography==41.0.7``,
  ``npm/jsonwebtoken@9.0.2``, ``maven/org.bouncycastle:bcpkix-jdk18on@1.77``),
  with the manifest they came from and whether the scanner could see them used.

Until now those rows existed only inside one scan's response
(``GET /scans/{id}/cascade``). The SBOM layer of the Technology BOM counted
systems, so immediately after a scan had found ten dependencies the SBOM page
still said "1 component, 0 dependencies", and the estate discovery plane's SBOM
projection stayed empty. That is the gap this module closes — one place that
turns a stored scan into software rows, so the console, the Technology BOM and
the estate graph cannot disagree about what a scan found.

It invents nothing:

* a package row is what a manifest literally declares, and it is reported as
  *declared* — a declaration is a build fact, never proof that the library is
  installed, loaded or used;
* a library row keeps the scanner's own ``declared_but_unused`` /
  ``used_but_undeclared`` flags instead of guessing;
* an edge exists only where a lockfile stated a parent/child relationship, so an
  unresolved subtree shows zero edges rather than a plausible-looking tree.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

SCHEMA = "cryptoscan.software-inventory/1"

#: ecosystems whose coordinate convention needs a separator; kept here so the
#: SBOM component name and the dependency edge name are the same string
_COORD_SEPARATORS = {"maven": ":", "gradle": ":", "nuget": "/", "cargo": "::"}


def coordinate(ecosystem: str, name: str, version: str | None) -> str:
    """``ecosystem/name@version`` — one spelling for a component and for an edge."""
    base = f"{ecosystem}/{name}" if ecosystem else str(name)
    return f"{base}@{version}" if version else base


def _libraries(cascade: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in cascade.get("libraries") or []:
        name = str(row.get("library") or "").strip()
        if not name:
            continue
        versions = [str(item) for item in (row.get("versions") or []) if item]
        manifests = [str(item) for item in (row.get("manifests") or []) if item]
        if row.get("files_using") and manifests:
            origin = "CODE_AND_MANIFEST"
        elif row.get("files_using"):
            origin = "CODE_IMPORT"
        else:
            origin = "MANIFEST_DECLARED"
        rows.append(
            {
                "component_type": "library",
                "ecosystem": "",
                "name": name,
                "version": ", ".join(versions) or None,
                "versions": versions,
                "coordinate": f"library/{name}",
                "origin": origin,
                "declared_in": manifests[0] if manifests else None,
                "manifests": manifests,
                "algorithms": [str(item) for item in (row.get("algorithms") or []) if item],
                "crypto_bearing": bool(row.get("algorithms")),
                "declared_but_unused": bool(row.get("declared_but_unused")),
                "used_but_undeclared": bool(row.get("used_but_undeclared")),
                "files_using": int(row.get("files_using") or 0),
                "findings": int(row.get("findings") or 0),
                "direct": None,
                "dependency_type": None,
            }
        )
    return rows


def _packages(cascade: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in cascade.get("package_dependencies") or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        ecosystem = str(row.get("ecosystem") or "").strip()
        version = str(row.get("version") or "").strip() or None
        algorithms = [str(item) for item in (row.get("crypto_algorithms") or []) if item]
        rows.append(
            {
                "component_type": "package",
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "versions": [version] if version else [],
                "coordinate": coordinate(ecosystem, name, version),
                "origin": "MANIFEST_DECLARED",
                "declared_in": row.get("source"),
                "manifests": [row["source"]] if row.get("source") else [],
                "algorithms": algorithms,
                "crypto_bearing": bool(row.get("crypto_bearing")),
                "declared_but_unused": False,
                "used_but_undeclared": False,
                "files_using": 0,
                "findings": 0,
                "direct": bool(row.get("direct")),
                "dependency_type": row.get("dependency_type") or ("direct" if row.get("direct") else "transitive"),
                "parent": row.get("parent"),
                "confidence": row.get("confidence"),
                "evidence_type": row.get("evidence_type"),
                "unresolved": bool(row.get("unresolved")),
            }
        )
    return rows


def _edges(packages: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Parent → child edges, only where the scan resolved the parent."""
    by_name: dict[str, Mapping[str, Any]] = {}
    for row in packages:
        by_name.setdefault(str(row["name"]).lower(), row)
    edges: list[dict[str, str]] = []
    for row in packages:
        parent = str(row.get("parent") or "").strip()
        if not parent:
            continue
        owner = by_name.get(parent.lower())
        if owner is None or owner is row:
            continue
        edges.append(
            {
                "source": str(owner["coordinate"]),
                "target": str(row["coordinate"]),
                "type": "declared_dependency",
            }
        )
    return edges


def software_from_cascade(
    cascade: Mapping[str, Any],
    *,
    scan_id: str | None = None,
    target: str | None = None,
    completed_at: Any = None,
) -> dict[str, Any]:
    """One scan's cascade report as SBOM rows. Pure: no DB, no clock, no guesses."""
    if not cascade:
        return {
            "schema": SCHEMA,
            "state": "NO_CASCADE",
            "scan_id": scan_id,
            "target": target,
            "completed_at": completed_at,
            "components": [],
            "edges": [],
            "counts": {"components": 0, "libraries": 0, "packages": 0, "edges": 0},
            "note": (
                "this scan stored no cascade report (scanner older than 1.1, or "
                "CRYPTOSCAN_CASCADE=0), so it carries no software rows: absence of a report "
                "is not absence of dependencies"
            ),
        }
    libraries = _libraries(cascade)
    packages = _packages(cascade)
    components = libraries + packages
    edges = _edges(packages)
    ecosystems: dict[str, int] = {}
    for row in packages:
        key = str(row.get("ecosystem") or "unknown")
        ecosystems[key] = ecosystems.get(key, 0) + 1
    return {
        "schema": SCHEMA,
        "state": "OBSERVED",
        "scan_id": scan_id,
        "target": target,
        "completed_at": completed_at,
        "components": components,
        "edges": edges,
        "counts": {
            "components": len(components),
            "libraries": len(libraries),
            "packages": len(packages),
            "direct": sum(1 for row in packages if row.get("direct")),
            "transitive": sum(1 for row in packages if not row.get("direct")),
            "crypto_bearing": sum(1 for row in components if row.get("crypto_bearing")),
            "declared_but_unused": sum(1 for row in libraries if row.get("declared_but_unused")),
            "edges": len(edges),
            "ecosystems": ecosystems,
        },
        "note": (
            "a declared package is a build fact from the manifest that names it; it is not proof "
            "the library is installed, loaded or used. Edges exist only where a lockfile stated the "
            "parent/child relationship, so a package with no resolved parent shows none."
        ),
    }


def _cascade_of(scan: Any) -> Mapping[str, Any]:
    statistics = getattr(scan, "statistics", None) or {}
    if not isinstance(statistics, Mapping):
        return {}
    cascade = statistics.get("cascade")
    return cascade if isinstance(cascade, Mapping) else {}


def latest_scan_software(db: Any, *, max_scan_rows: int = 20) -> dict[str, Any]:
    """Software rows from the newest completed scan that stored a cascade report.

    Reads at most ``max_scan_rows`` newest completed scans: a deployment whose
    last twenty scans ran with the cascade pass disabled reports ``NO_CASCADE``
    rather than paying for an unbounded walk of the scan table.
    """
    from db.models import Scan

    rows = (
        db.query(Scan)
        .filter(Scan.status == "COMPLETED")
        .order_by(Scan.created_at.desc())
        .limit(max_scan_rows)
        .all()
    )
    for scan in rows:
        cascade = _cascade_of(scan)
        if not cascade:
            continue
        return software_from_cascade(
            cascade,
            scan_id=str(getattr(scan, "id", "") or ""),
            target=str(getattr(scan, "target_location", "") or ""),
            completed_at=getattr(scan, "scan_end", None),
        )
    return {
        "schema": SCHEMA,
        "state": "NO_SCAN",
        "scan_id": None,
        "target": None,
        "completed_at": None,
        "components": [],
        "edges": [],
        "counts": {"components": 0, "libraries": 0, "packages": 0, "edges": 0},
        "note": (
            f"no completed scan in the last {max_scan_rows} stored a cascade report, so no software "
            "row exists yet. An empty SBOM here means 'no scan has reported dependencies', never "
            "'this application has no dependencies'"
        ),
    }


__all__ = ["SCHEMA", "coordinate", "latest_scan_software", "software_from_cascade"]
