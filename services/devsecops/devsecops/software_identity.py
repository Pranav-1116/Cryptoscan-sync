"""Normalize stored SBOM components for explicit release binding."""
from shared_models.software_identity import MAX_COMPONENTS, package_identity


def sbom_components(doc: dict) -> list[dict]:
    """Preserve the existing CycloneDX/SPDX importer and exact document references."""
    from devsecops.sbom import import_sbom

    raw = doc.get("components") if doc.get("bomFormat") == "CycloneDX" else doc.get("packages")
    if not isinstance(raw, list):
        raise ValueError("expected CycloneDX components or SPDX packages")
    if doc.get("bomFormat") == "CycloneDX":
        flattened, stack = [], [(row, 1) for row in reversed(raw)]
        while stack:
            row, depth = stack.pop()
            if not isinstance(row, dict):
                raise ValueError("SBOM components must be objects")
            if depth > 32 or len(flattened) >= MAX_COMPONENTS:
                raise ValueError("SBOM nested component depth/count exceeds binding limit")
            flattened.append(row)
            children = row.get("components") or []
            if not isinstance(children, list):
                raise ValueError("nested components must be a list")
            stack.extend((child, depth + 1) for child in reversed(children))
        raw = flattened
        doc = {**doc, "components": raw}
    if len(raw) > MAX_COMPONENTS:
        raise ValueError(f"SBOM exceeds {MAX_COMPONENTS} components; refusing an incomplete binding")
    if any(not isinstance(row, dict) for row in raw):
        raise ValueError("SBOM components must be objects")
    normalized = import_sbom(doc)
    if len(normalized) != len(raw):
        raise ValueError("unsupported SBOM component projection")
    return [{**component,
             "bom_ref": source.get("bom-ref") or source.get("SPDXID"),
             "package_identity": package_identity(component.get("purl"), source.get("version") or source.get("versionInfo"))}
            for source, component in zip(raw, normalized)]
