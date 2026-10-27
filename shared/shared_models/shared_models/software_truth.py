"""Exact agreed package-record reconciliation, never a complete-host assertion."""

from collections import Counter
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token, Digest, HostSnapshot, digest


class ExpectedPackage(Strict):
    name: Token
    version: Token | None


class ExpectedSoftwareInput(Strict):
    input_id: Token
    kind: Literal["DPKG_STATUS", "APK_INSTALLED", "RPM_SQLITE"]
    expected_content_sha256: Digest
    records: list[ExpectedPackage] = Field(min_length=1, max_length=1000)


class SoftwareTruthPlan(Strict):
    schema_version: Literal["cryptoscan.software-truth-plan/v1"] = "cryptoscan.software-truth-plan/v1"
    manifest_sha256: Digest
    reviewer_reference: Token
    inputs: list[ExpectedSoftwareInput] = Field(min_length=1, max_length=100)
    truth_basis: Literal["OPERATOR_SUPPLIED_EXPECTED_REGISTER_NOT_INDEPENDENTLY_AUTHENTICATED"] = (
        "OPERATOR_SUPPLIED_EXPECTED_REGISTER_NOT_INDEPENDENTLY_AUTHENTICATED"
    )

    @model_validator(mode="after")
    def unique(self):
        if (
            len({i.input_id for i in self.inputs}) != len(self.inputs)
            or sum(len(i.records) for i in self.inputs) > 1000
        ):
            raise ValueError("Unique bounded expected package scope required")
        return self


def reconcile_software(plan: SoftwareTruthPlan, snapshot: HostSnapshot):
    if snapshot.manifest_sha256 != plan.manifest_sha256:
        raise ValueError("Expected truth belongs to another approved manifest")
    kinds = {i.input_id: i.kind for i in snapshot.manifest.inputs}
    package_ids = {key for key, kind in kinds.items() if kind in {"DPKG_STATUS", "APK_INSTALLED", "RPM_SQLITE"}}
    if package_ids != {i.input_id for i in plan.inputs}:
        raise ValueError("Every approved package input must be in the expected denominator")
    rows = {r.input_id: r for r in snapshot.receipts}
    results = []
    for expected in plan.inputs:
        if kinds[expected.input_id] != expected.kind:
            raise ValueError("Package source mismatch")
        r = rows[expected.input_id]
        observed = Counter((f.software_name, f.software_version) for f in r.facts if f.kind == "SOFTWARE")
        wanted = Counter((p.name, p.version) for p in expected.records)
        comparable = r.status == "PARSED" and r.content_sha256 == expected.expected_content_sha256
        match = comparable and observed == wanted

        def counts(delta):
            return [
                {"name": name, "version": version, "count": count}
                for (name, version), count in sorted(delta.items(), key=lambda x: (x[0][0], x[0][1] or ""))
            ]

        results.append(
            {
                "input_id": r.input_id,
                "kind": expected.kind,
                "status": r.status,
                "reason": r.reason,
                "expected_records": sum(wanted.values()),
                "observed_records": sum(observed.values()) if r.status == "PARSED" else None,
                "record_comparison_performed": comparable,
                "source_commitment_matched": r.content_sha256 == expected.expected_content_sha256,
                "missing": counts(wanted - observed) if comparable else [],
                "unexpected": counts(observed - wanted) if comparable else [],
                "exact_record_set_matched": match,
            }
        )
    matched = all(i["exact_record_set_matched"] for i in results)
    return {
        "schema_version": "cryptoscan.software-truth-reconciliation/v1",
        "plan_sha256": digest(plan),
        "snapshot_sha256": digest(snapshot),
        "manifest_sha256": plan.manifest_sha256,
        "verdict": "MATCHED_AGREED_PACKAGE_RECORD_SET" if matched else "BLOCKED_SOFTWARE_TRUTH_GAPS",
        "agreed_package_record_coverage_verified": matched,
        "inputs": results,
        "source_basis": "IMPORTED",
        "expected_truth_basis": plan.truth_basis,
        "independent_reviewer_identity_verified": False,
        "whole_host_software_inventory_complete": False,
        "application_crypto_use": "UNKNOWN",
        "unassessed_surfaces": [
            "language_dependencies",
            "unpackaged_binaries",
            "loaded_runtime_code",
            "container_images",
            "firmware",
        ],
        "production_execution_qualified": False,
        "materialized_without_collection": True,
    }
