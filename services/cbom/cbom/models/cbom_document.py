"""Full CycloneDX CBOM document."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cbom.models.cbom_component import CbomComponent
from cbom.models.cbom_dependency import CbomDependency
from cbom.models.cbom_metadata import CbomMetadata
from cbom.models.cbom_vulnerability import CbomVulnerability


@dataclass
class CbomDocument:
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    version: int = 1
    serial_number: str | None = None
    metadata: CbomMetadata = field(default_factory=CbomMetadata)
    components: list[CbomComponent] = field(default_factory=list)
    dependencies: list[CbomDependency] = field(default_factory=list)
    vulnerabilities: list[CbomVulnerability] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "serialNumber": self.serial_number,
            "metadata": self.metadata.to_dict(),
            "components": [item.to_dict() for item in self.components],
        }
        if self.dependencies:
            payload["dependencies"] = [item.to_dict() for item in self.dependencies]
        if self.vulnerabilities:
            payload["vulnerabilities"] = [item.to_dict() for item in self.vulnerabilities]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CbomDocument":
        return cls(
            bom_format=str(payload.get("bomFormat") or "CycloneDX"),
            spec_version=str(payload.get("specVersion") or "1.5"),
            version=int(payload.get("version") or 1),
            serial_number=payload.get("serialNumber"),
            metadata=CbomMetadata.from_dict(payload.get("metadata")),
            components=[CbomComponent.from_dict(item) for item in payload.get("components") or []],
            dependencies=[CbomDependency.from_dict(item) for item in payload.get("dependencies") or []],
            vulnerabilities=[CbomVulnerability.from_dict(item) for item in payload.get("vulnerabilities") or []],
        )
