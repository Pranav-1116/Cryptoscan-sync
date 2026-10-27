"""Deterministic Linux metadata joins, never application/crypto usage assertions."""

from collections import defaultdict
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import digest, Digest
from shared_models.collection import CollectionResult, TargetSpec, Observation
from shared_models.collection_coverage import project_coverage, CoverageReport, BOMS
from shared_models.host_runtime import domains

Relation = Literal["PROCESS_HAS_MAPPED_PATH", "PROCESS_REPORTS_SERVICE_UNIT"]
UNSUPPORTED = (
    "SERVICE_MAINPID_TO_PROCESS_INCARNATION",
    "LISTENER_TO_PROCESS",
    "CONFIGURATION_TO_SERVICE",
    "CERTIFICATE_TO_LISTENER",
    "HARDWARE_TO_APPLICATION_OR_KEY",
    "PACKAGE_TO_BINARY_OR_LIBRARY",
)


class MetadataEdge(Strict):
    edge_id: Digest
    relation: Relation
    source_observation_id: str
    target_observation_id: str
    supporting_observation_ids: list[str] = Field(min_length=2, max_length=2)
    evidence_ids: list[str] = Field(min_length=1, max_length=2)
    basis: Literal["EXACT_CAPTURED_FIELDS_NOT_ATTESTED_USAGE"] = "EXACT_CAPTURED_FIELDS_NOT_ATTESTED_USAGE"
    local_basis: Literal["INFERRED"] = "INFERRED"
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    production_traffic_proven: Literal[False] = False


class UnresolvedJoin(Strict):
    observation_id: str
    relation: Relation
    reason: Literal["NO_MATCHING_OBSERVATION", "AMBIGUOUS_MATCH", "SERVICE_UNIT_NOT_RECORDED"]
    candidate_observation_ids: list[str] = Field(max_length=20)
    candidate_count: int = Field(ge=0, le=1000)
    candidate_list_truncated: bool
    asset_absence_proven: Literal[False] = False


def _joins(nodes, job_id):
    processes, services = defaultdict(list), defaultdict(list)
    for row in sorted(nodes, key=lambda n: n.observation_id):
        f = row.fact
        if f.kind == "PROCESS":
            processes[(f.boot_id, f.pid, f.process_start_ticks)].append(row)
        elif f.kind == "SERVICE":
            services[f.service_name].append(row)
    edges, unresolved = [], []
    for row in sorted(nodes, key=lambda n: n.observation_id):
        f = row.fact
        if f.kind == "LOADED_LIBRARY":
            relation = "PROCESS_HAS_MAPPED_PATH"
            matches = processes[(f.boot_id, f.pid, f.process_start_ticks)]
        elif f.kind == "PROCESS":
            relation = "PROCESS_REPORTS_SERVICE_UNIT"
            if not f.service_name:
                unresolved.append(
                    UnresolvedJoin(
                        observation_id=row.observation_id,
                        relation=relation,
                        reason="SERVICE_UNIT_NOT_RECORDED",
                        candidate_observation_ids=[],
                        candidate_count=0,
                        candidate_list_truncated=False,
                    )
                )
                continue
            matches = services[f.service_name]
        else:
            continue
        if len(matches) != 1:
            unresolved.append(
                UnresolvedJoin(
                    observation_id=row.observation_id,
                    relation=relation,
                    reason="NO_MATCHING_OBSERVATION" if not matches else "AMBIGUOUS_MATCH",
                    candidate_observation_ids=[n.observation_id for n in matches[:20]],
                    candidate_count=len(matches),
                    candidate_list_truncated=len(matches) > 20,
                )
            )
            continue
        source, target = (matches[0], row) if f.kind == "LOADED_LIBRARY" else (row, matches[0])
        support = [source.observation_id, target.observation_id]
        edges.append(
            MetadataEdge(
                edge_id=digest(["linux-metadata-edge/v1", job_id, relation, *support]),
                relation=relation,
                source_observation_id=support[0],
                target_observation_id=support[1],
                supporting_observation_ids=support,
                evidence_ids=sorted({source.evidence_id, target.evidence_id}),
            )
        )
    return sorted(edges, key=lambda e: e.edge_id), unresolved


class LinuxRelationships(Strict):
    schema_version: Literal["cryptoscan.linux-relationships/v1"] = "cryptoscan.linux-relationships/v1"
    coverage: CoverageReport
    nodes: list[Observation] = Field(max_length=1000)
    edges: list[MetadataEdge] = Field(max_length=1000)
    unresolved: list[UnresolvedJoin] = Field(max_length=1000)
    unsupported_relationships: list[str] = Field(default_factory=lambda: list(UNSUPPORTED))
    provenance: Literal["IMPORTED"] = "IMPORTED"
    identity_basis: Literal["SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"] = "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"
    relationship_completeness_proven: Literal[False] = False
    host_identity_attested: Literal[False] = False
    production_execution_qualified: Literal[False] = False
    materialized_without_collection: Literal[True] = True

    @model_validator(mode="after")
    def reconcile(self):
        if self.unsupported_relationships != list(UNSUPPORTED):
            raise ValueError("Unsupported relationships cannot be promoted")
        if len({n.observation_id for n in self.nodes}) != len(self.nodes):
            raise ValueError("Duplicate observation node")
        if len(self.nodes) != self.coverage.bom_observation_counts["TechBOM"]:
            raise ValueError("Every original fact must remain a separate node")
        inputs = {i.input_id: i for surface in self.coverage.surfaces.values() for i in surface.inputs}
        counts = defaultdict(int)
        bom_counts = {key: 0 for key in BOMS}
        ordinals = set()
        for row in self.nodes:
            item = inputs.get(row.input_id)
            if (
                not item
                or item.status != "PARSED"
                or row.source.kind != item.kind
                or row.evidence_id not in item.evidence_ids
                or row.fact_sha256 != digest(row.fact)
                or row.contributes_to != domains(row.fact)
            ):
                raise ValueError("Node evidence/source/fact binding mismatch")
            pair = (row.input_id, row.fact_ordinal)
            if pair in ordinals:
                raise ValueError("Duplicate input/fact ordinal")
            ordinals.add(pair)
            expected_source = {
                "PROCESS": "LINUX_PROCESS",
                "LOADED_LIBRARY": "LINUX_PROCESS_MAPS",
                "SERVICE": "LINUX_SERVICE",
            }.get(row.fact.kind)
            if expected_source and row.source.kind != expected_source:
                raise ValueError("Unsupported relationship source")
            for domain in row.contributes_to:
                bom_counts[domain] += 1
            counts[row.input_id] += 1
        if any(counts[key] != item.fact_count for key, item in inputs.items()):
            raise ValueError("Input node counts must reconcile")
        if bom_counts != self.coverage.bom_observation_counts:
            raise ValueError("All six BOM reference counts must reconcile")
        expected_edges, expected_unresolved = _joins(self.nodes, self.coverage.job_id)
        if self.edges != expected_edges or self.unresolved != expected_unresolved:
            raise ValueError("Only exact unambiguous captured-field joins are allowed")
        return self


def project_linux_relationships(result: CollectionResult, target: TargetSpec, envelope_sha256: str):
    if target.collection_method != "offline_host" or not target.manifest or target.manifest.platform != "linux":
        raise ValueError("Only approved offline Linux scope supported")
    coverage = project_coverage(result, target, envelope_sha256)
    nodes = sorted(result.observations, key=lambda n: n.observation_id)
    edges, unresolved = _joins(nodes, result.job_id)
    return LinuxRelationships(coverage=coverage, nodes=nodes, edges=edges, unresolved=unresolved)
