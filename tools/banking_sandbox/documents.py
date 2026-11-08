"""Six BOM projections, official schema checks, no usage inferred from installed packages."""

import json
from pathlib import Path
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "services/cbom/cbom/validators/schema/cyclonedx-1.6"


def validators():
    registry = Registry()
    for name in ("bom-1.6.schema.json", "jsf-0.82.schema.json", "spdx.schema.json"):
        schema = json.loads((SCHEMAS / name).read_text())
        resource = Resource.from_contents(schema)
        registry = registry.with_resource("http://cyclonedx.org/schema/" + name, resource)
        registry = registry.with_resource("https://cyclonedx.org/schema/" + name, resource)
    cdx = Draft7Validator(json.loads((SCHEMAS / "bom-1.6.schema.json").read_text()), registry=registry)
    spdx = Draft7Validator(json.loads((Path(__file__).with_name("schemas") / "spdx-2.3.schema.json").read_text()))
    return cdx, spdx


def sbom(app, components, timestamp):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {"type": "application", "bom-ref": app["app_id"], "name": app["name"], "version": "1.0-LAB"},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": c["component_id"],
                "name": c["name"],
                **({"version": c["declared_version"]} if c["declared_version"] is not None else {}),
                "properties": [
                    {"name": "lab:synthetic", "value": "true"},
                    {"name": "lab:usage", "value": "UNKNOWN_NOT_PROVEN_BY_SBOM"},
                ],
            }
            for c in components
        ],
        "dependencies": [{"ref": app["app_id"], "dependsOn": [c["component_id"] for c in components]}],
    }


def spdx(app, components, timestamp):
    packages = []
    for i, c in enumerate(components):
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": c["name"],
                **({"versionInfo": c["declared_version"]} if c["declared_version"] is not None else {}),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": app["name"] + " SYNTHETIC SBOM",
        "documentNamespace": "https://lab.invalid/spdx/" + app["app_id"],
        "creationInfo": {"created": timestamp, "creators": ["Tool: ZELNX-SYNTHETIC-LAB"]},
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Package-{i}",
            }
            for i in range(len(packages))
        ],
    }


def cbom(app, algorithm, purpose):
    # Schema-valid algorithm declaration. This does NOT certify usage, execution,
    # FIPS status, PQC implementation or completeness of the CBOM.
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": app["app_id"] + "-crypto-declared",
                "name": algorithm,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "other"}},
                "properties": [
                    {"name": "lab:evidence", "value": "VENDOR_DECLARED"},
                    {"name": "lab:purpose", "value": purpose},
                    {"name": "lab:synthetic", "value": "true"},
                ],
            }
        ],
    }
