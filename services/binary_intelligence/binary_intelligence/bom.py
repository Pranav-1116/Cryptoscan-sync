"""SBOM/CBOM integration (§5, §8, §17 Phase 3) — feeds the existing
six-BOM ecosystem, never a seventh disconnected BOM.

The CycloneDX provides/uses distinction is central (§5): a library
PROVIDES an algorithm; an application USES it only when evidence
supports the claim. Co-occurrence in one binary or deployment never
creates a `uses` relationship — the strongest claim this static engine
emits is 'statically supported', and even that edge carries the
limitation that runtime use is unconfirmed.

Digital Twin relationship provenance (§8) is preserved on every edge:
directly_observed | static_dependency | configuration_derived |
runtime_confirmed | inferred | unresolved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from binary_intelligence.evidence import CryptoFinding, UsageStatus

BOM_SCHEMA = "cryptoscan.binary-bom/1"


class RelationshipProvenance:
    DIRECTLY_OBSERVED = "directly_observed"
    STATIC_DEPENDENCY = "static_dependency"
    CONFIGURATION_DERIVED = "configuration_derived"
    RUNTIME_CONFIRMED = "runtime_confirmed"
    INFERRED = "inferred"
    UNRESOLVED = "unresolved"


#: §5: a `uses` edge is emitted ONLY at this strength or above — and it
#: still carries 'runtime use unconfirmed'.
_USES_MIN_CLASS = "strongly_supported"


@dataclass
class BomComponent:
    component_type: str        # "library" | "application" | "algorithm"
    name: str
    version: str = ""
    purl: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": self.component_type, "name": self.name,
            "version": self.version, "purl": self.purl,
            "hashes": self.hashes, "properties": self.properties,
        }


@dataclass
class BomRelationship:
    source: str                # component name
    relationship_type: str     # "dependsOn" | "provides" | "uses"
    target: str
    provenance: str            # RelationshipProvenance.*
    evidence_class: str
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "relationship_type": self.relationship_type,
            "target": self.target, "provenance": self.provenance,
            "evidence_class": self.evidence_class,
            "limitations": self.limitations,
        }


@dataclass
class BinaryBom:
    schema: str
    artifact_id: str
    artifact_sha256: str
    subject: str
    components: List[BomComponent]
    relationships: List[BomRelationship]
    sbom_components: List[Dict[str, Any]]
    cbom_assets: List[Dict[str, Any]]
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "subject": self.subject,
            "components": [c.as_dict() for c in self.components],
            "relationships": [r.as_dict() for r in self.relationships],
            "sbom_components": self.sbom_components,
            "cbom_assets": self.cbom_assets,
            "limitations": self.limitations,
        }


def build_bom(*, artifact_id: str, artifact_sha256: str, subject: str,
              findings: List[CryptoFinding],
              dependencies: List[str],
              libraries: Optional[List[str]] = None,
              embedded_archives: Optional[List[str]] = None
              ) -> BinaryBom:
    """Derive SBOM components, CBOM cryptographic assets and the
    relationship graph from scan findings. The graph never claims more
    than the evidence supports."""
    components: List[BomComponent] = []
    relationships: List[BomRelationship] = []
    sbom_components: List[Dict[str, Any]] = []
    cbom_assets: List[Dict[str, Any]] = []
    limitations: List[str] = []

    app = BomComponent(
        component_type="application", name=subject,
        hashes={"SHA-256": artifact_sha256})
    components.append(app)

    # SBOM: dependencies are components; the app dependsOn them
    for dep in dependencies:
        components.append(BomComponent(
            component_type="library", name=dep,
            properties={"origin": "dynamic dependency"}))
        sbom_components.append({
            "type": "library", "name": dep,
            "evidence": "dynamic dependency table",
            "provenance": RelationshipProvenance.STATIC_DEPENDENCY,
        })
        relationships.append(BomRelationship(
            source=subject, relationship_type="dependsOn", target=dep,
            provenance=RelationshipProvenance.STATIC_DEPENDENCY,
            evidence_class="observed",
            limitations=[
                "a dependency relationship observed in the binary's "
                "dependency table (§5)"]))

    for archive in embedded_archives or []:
        components.append(BomComponent(
            component_type="library", name=archive,
            properties={"origin": "embedded archive", "extracted": False}))
        sbom_components.append({
            "type": "library", "name": archive,
            "evidence": "embedded archive inventoried, not extracted",
            "provenance": RelationshipProvenance.DIRECTLY_OBSERVED,
        })
        relationships.append(BomRelationship(
            source=subject, relationship_type="dependsOn", target=archive,
            provenance=RelationshipProvenance.DIRECTLY_OBSERVED,
            evidence_class="observed",
            limitations=["embedded archive inventoried within bounded "
                         "extraction — contents not unpacked (§14)"]))

    # CBOM: algorithm assets from findings; library PROVIDES algorithm
    for finding in findings:
        if finding.finding_type != "cryptographic_algorithm":
            continue
        asset_name = finding.variant or finding.algorithm
        cbom_assets.append({
            "algorithm": finding.algorithm,
            "variant": finding.variant or None,
            "operation": finding.operation or None,
            "mode_or_padding": finding.mode_or_padding or None,
            "key_size_bits": finding.key_size_bits,   # unknown stays null
            "evidence_class": finding.evidence_class.value,
            "usage_status": finding.usage_status.value,
            "runtime_confirmed": finding.runtime_confirmed,
            "finding_id": finding.finding_id,
            "limitations": list(finding.limitations),
        })
        if finding.library:
            # the library PROVIDES the algorithm — never `uses`
            relationships.append(BomRelationship(
                source=finding.library, relationship_type="provides",
                target=asset_name,
                provenance=RelationshipProvenance.INFERRED,
                evidence_class=finding.evidence_class.value,
                limitations=[
                    "a library provides cryptographic capability; it does "
                    "not follow that the application uses the algorithm "
                    "(§5)"]))
        # the app -> algorithm edge is claimed ONLY at strong static
        # support, and even then says runtime use is unconfirmed
        if (finding.evidence_class.value == _USES_MIN_CLASS
                and finding.usage_status == UsageStatus.STATICALLY_SUPPORTED):
            relationships.append(BomRelationship(
                source=subject, relationship_type="uses", target=asset_name,
                provenance=RelationshipProvenance.STATIC_DEPENDENCY,
                evidence_class=finding.evidence_class.value,
                limitations=[
                    "multiple independent static indicators support this "
                    "claim — runtime use is still unconfirmed (§5); "
                    "co-occurrence alone would not create this edge"]))
        elif finding.usage_status in (UsageStatus.STATICALLY_REFERENCED,
                                      UsageStatus.UNRESOLVED):
            relationships.append(BomRelationship(
                source=subject, relationship_type="indicates",
                target=asset_name,
                provenance=RelationshipProvenance.UNRESOLVED,
                evidence_class=finding.evidence_class.value,
                limitations=[
                    "an indicator only — no `uses` edge is created from "
                    "co-occurrence or a single reference (§5)"]))

    limitations.append(
        "relationships carry provenance; a business system is not a scan "
        "target and edges come from evidence, never from names or "
        "co-occurrence (§8)")
    return BinaryBom(
        schema=BOM_SCHEMA, artifact_id=artifact_id,
        artifact_sha256=artifact_sha256, subject=subject,
        components=components, relationships=relationships,
        sbom_components=sbom_components, cbom_assets=cbom_assets,
        limitations=limitations)
