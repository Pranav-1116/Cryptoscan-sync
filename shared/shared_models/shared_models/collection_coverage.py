"""Deterministic coverage projection over committed evidence; never a collector.

A parsed approved input is not complete software/host coverage or asset absence.
Imported transport provenance does not upgrade local declarations to observation.
"""

from typing import Literal, Annotated
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Kind, Token, Digest, digest
from shared_models.collection import CollectionResult, TargetSpec, offset_time
from shared_models.host_runtime import domains

SURFACES = {
    "os": {"LINUX_OS_RELEASE", "WINDOWS_OS_RELEASE"},
    "software": {
        "DPKG_STATUS",
        "APK_INSTALLED",
        "RPM_SQLITE",
        "WINDOWS_UNINSTALL",
        "BINARY_METADATA",
        "OCI_IMAGE_METADATA",
    },
    "certificates": {"PUBLIC_CERTIFICATE", "WINDOWS_CERTIFICATE"},
    "crypto_configuration": {"NGINX_TLS_CONFIG", "WINDOWS_CNG_REGISTRATION", "WINDOWS_CAPI_DEFAULT_PROVIDER"},
    "processes_and_libraries": {"LINUX_PROCESS", "LINUX_PROCESS_MAPS", "WINDOWS_PROCESS_MODULES"},
    "services": {"LINUX_SERVICE", "WINDOWS_SERVICE"},
    "network_listeners": {"LINUX_LISTENERS", "WINDOWS_TCP_LISTENERS"},
    "hardware_metadata": {"LINUX_HARDWARE", "WINDOWS_TPM_DEVICE_INFO"},
}
BOMS = ("SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM")


class InputCoverage(Strict):
    input_id: Token
    kind: Kind
    status: Literal["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"]
    reason: Token
    fact_count: int = Field(ge=0, le=1000)
    evidence_ids: list[str] = Field(max_length=1000)
    local_basis_counts: dict[Literal["OBSERVED", "DECLARED"], Annotated[int, Field(ge=0, le=1000)]]
    asset_absence_proven: Literal[False] = False

    @model_validator(mode="after")
    def reconcile(self):
        if (
            set(self.local_basis_counts) != {"OBSERVED", "DECLARED"}
            or sum(self.local_basis_counts.values()) != self.fact_count
        ):
            raise ValueError("Local provenance counts must reconcile to facts")
        if (
            len(self.evidence_ids) != len(set(self.evidence_ids))
            or len(self.evidence_ids) > self.fact_count
            or bool(self.evidence_ids) != bool(self.fact_count)
        ):
            raise ValueError("Facts require unique retained evidence references")
        if self.status != "PARSED" and self.fact_count:
            raise ValueError("Failed input cannot emit facts")
        return self


class SurfaceCoverage(Strict):
    approved_inputs: int = Field(ge=0, le=100)
    parsed_inputs: int = Field(ge=0, le=100)
    failed_inputs: int = Field(ge=0, le=100)
    fact_count: int = Field(ge=0, le=1000)
    outcome: Literal["NOT_REQUESTED", "PARSED_WITH_FACTS", "PARSED_NO_FACTS", "PARTIAL", "FAILED"]
    approved_input_parse_percent: float | None = Field(default=None, ge=0, le=100)
    inputs: list[InputCoverage] = Field(max_length=100)
    complete_surface_coverage_verified: Literal[False] = False

    @model_validator(mode="after")
    def reconcile(self):
        total, parsed = len(self.inputs), sum(i.status == "PARSED" for i in self.inputs)
        facts = sum(i.fact_count for i in self.inputs)
        expected = (
            "NOT_REQUESTED"
            if not total
            else "FAILED"
            if not parsed
            else "PARTIAL"
            if parsed < total
            else "PARSED_WITH_FACTS"
            if facts
            else "PARSED_NO_FACTS"
        )
        percent = round(100 * parsed / total, 2) if total else None
        if (
            self.approved_inputs,
            self.parsed_inputs,
            self.failed_inputs,
            self.fact_count,
            self.outcome,
            self.approved_input_parse_percent,
        ) != (total, parsed, total - parsed, facts, expected, percent):
            raise ValueError("Surface coverage must reconcile to original approved input outcomes")
        if len({i.input_id for i in self.inputs}) != total or any(
            i.status != "PARSED" and i.fact_count for i in self.inputs
        ):
            raise ValueError("Duplicate inputs or facts on failed input")
        return self


class CoverageReport(Strict):
    schema_version: Literal["cryptoscan.collection-surface-coverage/v1"] = "cryptoscan.collection-surface-coverage/v1"
    job_id: str
    target_id: str
    target_revision: int = Field(ge=1, le=100)
    target_sha256: Digest
    system_id: Token
    environment: Token
    started_at: str = Field(min_length=1, max_length=40)
    finished_at: str = Field(min_length=1, max_length=40)
    envelope_sha256: Digest
    provenance: Literal["IMPORTED"] = "IMPORTED"
    basis: Literal["EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY"] = (
        "EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY"
    )
    surfaces: dict[str, SurfaceCoverage]
    bom_observation_counts: dict[str, int]
    whole_host_percent: None = None
    whole_host_coverage_verified: Literal[False] = False
    asset_absence_proven: Literal[False] = False
    materialized_without_collection: Literal[True] = True
    production_execution_qualified: Literal[False] = False

    @model_validator(mode="after")
    def complete(self):
        if offset_time(self.finished_at) < offset_time(self.started_at):
            raise ValueError("Coverage must retain the ordered, offset-aware collection window")
        total_facts = sum(s.fact_count for s in self.surfaces.values())
        if self.bom_observation_counts.get("TechBOM") != total_facts or any(
            n > total_facts for n in self.bom_observation_counts.values()
        ):
            raise ValueError("BOM reference counts cannot manufacture facts")
        if set(self.surfaces) != set(SURFACES) or set(self.bom_observation_counts) != set(BOMS):
            raise ValueError("All surface states and all six BOM projections must be explicit")
        ids = [i.input_id for surface in self.surfaces.values() for i in surface.inputs]
        if (
            len(ids) > 100
            or len(ids) != len(set(ids))
            or any(not 0 <= n <= 1000 for n in self.bom_observation_counts.values())
        ):
            raise ValueError("Coverage identity/count bounds")
        return self


def project_coverage(result: CollectionResult, target: TargetSpec, envelope_sha256: str) -> CoverageReport:
    if (
        not target.manifest
        or result.system_id != target.system_id
        or result.environment != target.environment
        or digest(result) != envelope_sha256
    ):
        raise ValueError("Committed evidence envelope required")
    approved = {i.input_id: i for i in target.manifest.inputs}
    errors = {e.input_id: e for e in result.errors}
    if len(errors) != len(result.errors) or not set(errors) <= set(approved):
        raise ValueError("Errors do not belong to exact approved inputs")
    if result.coverage.approved_inputs != len(approved) or result.coverage.parsed_inputs != len(approved) - len(errors):
        raise ValueError("Approved denominator does not match evidence")
    facts = {key: [] for key in approved}
    seen, ordinals = set(), set()
    counts = {bom: 0 for bom in BOMS}
    for observation in result.observations:
        item = approved.get(observation.input_id)
        pair = (observation.input_id, observation.fact_ordinal)
        if (
            not item
            or item.input_id in errors
            or observation.observation_id in seen
            or pair in ordinals
            or observation.source.kind != item.kind
            or observation.source.path != item.path
            or observation.source.host_id != target.manifest.host_id
            or observation.fact_sha256 != digest(observation.fact)
            or observation.contributes_to != domains(observation.fact)
        ):
            raise ValueError("Observation identity/source/fact/domain binding invalid")
        seen.add(observation.observation_id)
        ordinals.add(pair)
        facts[item.input_id].append(observation)
        for bom in observation.contributes_to:
            counts[bom] += 1
    surfaces = {}
    for name, kinds in SURFACES.items():
        rows = []
        for item in target.manifest.inputs:
            if item.kind not in kinds:
                continue
            values = facts[item.input_id]
            error = errors.get(item.input_id)
            rows.append(
                InputCoverage(
                    input_id=item.input_id,
                    kind=item.kind,
                    status=error.status if error else "PARSED",
                    reason=error.reason if error else "PARSED_RECEIPT_NOT_ABSENCE_PROOF",
                    fact_count=len(values),
                    evidence_ids=sorted({v.evidence_id for v in values}),
                    local_basis_counts={
                        basis: sum(v.fact.local_basis == basis for v in values) for basis in ["OBSERVED", "DECLARED"]
                    },
                )
            )
        total, parsed, fact_count = len(rows), sum(i.status == "PARSED" for i in rows), sum(i.fact_count for i in rows)
        outcome = (
            "NOT_REQUESTED"
            if not total
            else "FAILED"
            if not parsed
            else "PARTIAL"
            if parsed < total
            else "PARSED_WITH_FACTS"
            if fact_count
            else "PARSED_NO_FACTS"
        )
        surfaces[name] = SurfaceCoverage(
            approved_inputs=total,
            parsed_inputs=parsed,
            failed_inputs=total - parsed,
            fact_count=fact_count,
            outcome=outcome,
            approved_input_parse_percent=round(100 * parsed / total, 2) if total else None,
            inputs=rows,
        )
    if sum(s.approved_inputs for s in surfaces.values()) != len(approved):
        raise ValueError("Input kind has no explicit surface mapping")
    return CoverageReport(
        job_id=result.job_id,
        target_id=result.target_id,
        target_revision=result.target_revision,
        target_sha256=result.target_sha256,
        system_id=result.system_id,
        environment=result.environment,
        started_at=result.started_at,
        finished_at=result.finished_at,
        envelope_sha256=envelope_sha256,
        surfaces=surfaces,
        bom_observation_counts=counts,
    )
