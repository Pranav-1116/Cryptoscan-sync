"""Pure materialization of retained OCI evidence. No filesystem/network access."""

from typing import Literal
from pydantic import Field
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostFact, Token, digest
from shared_models.oci_collection import OciEvidence


class ImageFactRef(Strict):
    evidence_id: str
    input_id: Token
    ordinal: int = Field(ge=0, le=999)
    image_sha256: Digest
    content_sha256: Digest
    layer_sha256: Digest
    path: str
    provenance: Literal["IMPORTED"] = "IMPORTED"
    relationship: Literal["CONTAINS_METADATA_RECORD"] = "CONTAINS_METADATA_RECORD"
    fact: HostFact


class ImageView(Strict):
    state: Literal["SCOPED_METADATA", "DECLARED_ONLY", "UNKNOWN"]
    facts: list[ImageFactRef] = Field(default_factory=list, max_length=1000)
    declared_vendor: Token | None = None
    complete: Literal[False] = False


class OciProjection(Strict):
    schema_version: Literal["cryptoscan.oci-six-bom-projection/v1"] = "cryptoscan.oci-six-bom-projection/v1"
    evidence_sha256: Digest
    image_sha256: Digest
    system_id: Token
    SBOM: ImageView
    CBOM: ImageView
    NBOM: ImageView
    HBOM: ImageView
    VBOM: ImageView
    TechBOM: ImageView
    cyclonedx_export: Literal[False] = False
    graph_persisted: Literal[False] = False
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    pqc_readiness: Literal["UNKNOWN"] = "UNKNOWN"


def materialize_oci(evidence: OciEvidence, approved_evidence_sha256: str) -> OciProjection:
    # Revalidate even a caller-mutated nested object/model_construct instance.
    evidence = OciEvidence.model_validate(evidence.model_dump())
    evidence_sha = digest(evidence)
    if evidence_sha != approved_evidence_sha256:
        raise ValueError("Retained evidence commitment mismatch")
    refs = []
    for receipt in evidence.receipts:
        for ordinal, fact in enumerate(receipt.facts):
            identity = {"evidence_sha256": evidence_sha, "input_id": receipt.input_id, "ordinal": ordinal}
            refs.append(
                ImageFactRef(
                    evidence_id="oci-fact:" + digest(identity),
                    input_id=receipt.input_id,
                    ordinal=ordinal,
                    image_sha256=evidence.target.manifest_sha256,
                    content_sha256=receipt.content_sha256,
                    layer_sha256=receipt.layer_sha256,
                    path=receipt.path,
                    fact=fact,
                )
            )

    def view(facts):
        return ImageView(state="SCOPED_METADATA" if facts else "UNKNOWN", facts=facts)

    vendor = evidence.declarations.vendor
    return OciProjection(
        evidence_sha256=evidence_sha,
        image_sha256=evidence.target.manifest_sha256,
        system_id=evidence.target.system_id,
        SBOM=view([r for r in refs if r.fact.kind in {"SOFTWARE", "BINARY"}]),
        CBOM=view([r for r in refs if r.fact.kind in {"CERTIFICATE", "TLS_CONFIGURATION"}]),
        NBOM=view([]),
        HBOM=view([]),
        VBOM=ImageView(state="DECLARED_ONLY" if vendor else "UNKNOWN", declared_vendor=vendor),
        TechBOM=view(refs),
    )
