"""Precommitted OCI metadata truth. Human review is not source authenticity."""

from collections import Counter
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostFact, Token, digest
from shared_models.oci_collection import ImageInput, OciEvidence
from shared_models.oci_intake import Identifier


class ExpectedImageInput(Strict):
    source: ImageInput
    expected_content_sha256: Digest
    facts: list[HostFact] = Field(min_length=1, max_length=1000)


class OciTruthProposal(Strict):
    schema_version: Literal["cryptoscan.oci-truth-proposal/v1"] = "cryptoscan.oci-truth-proposal/v1"
    expected_job_revision: int = Field(default=1, ge=1, le=1)
    target_sha256: Digest
    target_record_sha256: Digest
    reviewer_user_id: Identifier
    source_reference: Token
    expected: list[ExpectedImageInput] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def unique(self):
        if (
            len({x.source.input_id for x in self.expected}) != len(self.expected)
            or len({x.source.path for x in self.expected}) != len(self.expected)
            or sum(len(x.facts) for x in self.expected) > 1000
        ):
            raise ValueError("Unique bounded truth denominator required")
        kinds = {
            "DPKG_STATUS": "SOFTWARE",
            "APK_INSTALLED": "SOFTWARE",
            "RPM_SQLITE": "SOFTWARE",
            "LINUX_OS_RELEASE": "OS_RELEASE",
            "PUBLIC_CERTIFICATE": "CERTIFICATE",
            "NGINX_TLS_CONFIG": "TLS_CONFIGURATION",
            "BINARY_METADATA": "BINARY",
        }
        if any(f.kind != kinds[x.source.kind] for x in self.expected for f in x.facts):
            raise ValueError("Expected truth kind must match its exact source")
        return self


class OciTruthDecision(Strict):
    expected_revision: int = Field(default=1, ge=1, le=1)
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500, pattern=r"^[^\x00-\x1f\x7f]+$")


def compare_image_truth(plan: OciTruthProposal, evidence: OciEvidence):
    """Pure exact multiset reconciliation, no collection or authenticity claim."""
    plan = OciTruthProposal.model_validate(plan.model_dump())
    evidence = OciEvidence.model_validate(evidence.model_dump())
    if plan.target_sha256 != evidence.target_sha256 or [x.source for x in plan.expected] != evidence.target.inputs:
        raise ValueError("Truth denominator does not match exact ordered target inputs")
    inputs = []
    for expected, receipt in zip(plan.expected, evidence.receipts):
        wanted = Counter(digest(f) for f in expected.facts)
        actual = Counter(digest(f) for f in receipt.facts)
        comparable = receipt.status == "PARSED" and receipt.content_sha256 == expected.expected_content_sha256
        inputs.append(
            {
                "input_id": receipt.input_id,
                "receipt_status": receipt.status,
                "source_commitment_matched": receipt.content_sha256 == expected.expected_content_sha256,
                "comparison_performed": comparable,
                "expected_records": sum(wanted.values()),
                "observed_records": sum(actual.values()) if receipt.status == "PARSED" else None,
                "missing_records": sum((wanted - actual).values()) if comparable else None,
                "unexpected_records": sum((actual - wanted).values()) if comparable else None,
                "exact_record_multiset_matched": comparable and wanted == actual,
                "asset_absence_proven": False,
            }
        )
    return {
        "plan_sha256": digest(plan),
        "evidence_sha256": digest(evidence),
        "inputs": inputs,
        "agreed_metadata_matched": all(x["exact_record_multiset_matched"] for x in inputs),
        "whole_image_software_complete": False,
        "whole_estate_complete": False,
        "source_authenticity_verified": False,
        "organizational_independence_verified": False,
        "runtime_use": "UNKNOWN",
        "bank_production_accepted": False,
        "production_execution_qualified": False,
    }
