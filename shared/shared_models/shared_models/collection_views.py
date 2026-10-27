"""Shared stored-evidence views. Metadata identity is not physical asset identity."""

from collections import Counter
from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostManifest, Token, digest
from shared_models.oci_intake import Identifier

Family = Literal["host", "oci"]
Domain = Literal["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"]
DOMAINS = ("SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM")


class SnapshotRequest(Strict):
    family: Family
    job_id: Identifier
    expected_source_sha256: Digest


class SnapshotInput(Strict):
    input_id: Token
    kind: Token
    path: str = Field(min_length=1, max_length=1024)
    status: Literal["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"]
    reason: Token
    input_basis: Literal["APPROVED_INPUT", "PINNED_IMAGE_CONFIG"] = "APPROVED_INPUT"
    asset_absence_proven: Literal[False] = False


class SnapshotObservation(Strict):
    observation_id: str = Field(min_length=1, max_length=160)
    identity_slot: Identifier
    identity_basis: Literal["SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"] = "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"
    input_id: Token
    fact_kind: Token
    fact_sha256: Digest
    evidence_id: str = Field(min_length=1, max_length=160)
    provenance: Literal["IMPORTED"] = "IMPORTED"
    local_basis: Literal["OBSERVED", "DECLARED", "IMPORTED", "INFERRED", "UNKNOWN"]
    domains: list[Domain] = Field(min_length=1, max_length=6)

    @model_validator(mode="after")
    def scope(self):
        if len(set(self.domains)) != len(self.domains) or "TechBOM" not in self.domains:
            raise ValueError("Unique supported domains including TechBOM required")
        return self


class CollectionSnapshot(Strict):
    schema_version: Literal["cryptoscan.collection-snapshot/v1"] = "cryptoscan.collection-snapshot/v1"
    family: Family
    job_id: Identifier
    target_id: Identifier
    system_id: Token
    environment: Token
    source_sha256: Digest
    started_at: datetime
    finished_at: datetime
    inputs: list[SnapshotInput] = Field(min_length=1, max_length=101)
    observations: list[SnapshotObservation] = Field(max_length=1001)
    whole_asset_coverage_verified: Literal[False] = False
    source_authenticity_verified: Literal[False] = False
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    production_execution_qualified: Literal[False] = False

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def closure(self):
        ids = {i.input_id for i in self.inputs}
        if len(ids) != len(self.inputs) or len({o.observation_id for o in self.observations}) != len(self.observations):
            raise ValueError("Unique input and observation identities required")
        if len({(i.kind, i.path) for i in self.inputs}) != len(self.inputs):
            raise ValueError("Unique input locations required")
        locations = {i.input_id: (i.kind, i.path) for i in self.inputs}
        slots = {}
        for obs in self.observations:
            slots.setdefault(obs.identity_slot, set()).add((locations.get(obs.input_id), obs.fact_kind))
        if any(len(values) != 1 for values in slots.values()):
            raise ValueError("A metadata slot cannot merge different sources or fact kinds")
        states = {i.input_id: i.status for i in self.inputs}
        if any(o.input_id not in ids or states[o.input_id] != "PARSED" for o in self.observations):
            raise ValueError("Observations must reference parsed approved inputs")
        if self.finished_at < self.started_at:
            raise ValueError("Snapshot source clock ordering invalid")
        return self


class DriftRequest(Strict):
    baseline_snapshot_id: Identifier
    candidate_snapshot_id: Identifier

    @model_validator(mode="after")
    def distinct(self):
        if self.baseline_snapshot_id == self.candidate_snapshot_id:
            raise ValueError("Distinct committed snapshots required")
        return self


def snapshot_views(snapshot: CollectionSnapshot):
    """Pure six-domain references and metadata-only graph, not operational joins."""
    snapshot = CollectionSnapshot.model_validate(snapshot.model_dump())
    domains = {name: {"observation_ids": [], "complete": False} for name in DOMAINS}
    by_slot = {}
    for obs in snapshot.observations:
        for name in obs.domains:
            domains[name]["observation_ids"].append(obs.observation_id)
        by_slot.setdefault(obs.identity_slot, []).append(obs)
    root = "system-scope:" + digest(
        {k: getattr(snapshot, k) for k in ("family", "target_id", "system_id", "environment")}
    )
    nodes = [
        {
            "node_id": root,
            "kind": "SYSTEM_SCOPE",
            "system_id": snapshot.system_id,
            "environment": snapshot.environment,
            "physical_asset_attested": False,
        }
    ]
    edges = []
    for slot, observations in sorted(by_slot.items()):
        refs = sorted(o.observation_id for o in observations)
        node_id = "metadata-slot:" + slot
        nodes.append(
            {
                "node_id": node_id,
                "kind": "METADATA_SLOT",
                "identity_slot": slot,
                "identity_basis": "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET",
                "observation_ids": refs,
                "record_count": len(observations),
                "multiple_records_in_slot": len(observations) > 1,
            }
        )
        edges.append(
            {
                "edge_id": digest([root, node_id, "HAS_METADATA_REFERENCE"]),
                "source": root,
                "target": node_id,
                "relationship": "HAS_METADATA_REFERENCE",
                "provenance": "IMPORTED",
                "observation_ids": refs,
                "evidence_ids": sorted({o.evidence_id for o in observations}),
                "operational_use": "UNKNOWN",
            }
        )
    for name, view in domains.items():
        relevant = [o for o in snapshot.observations if name in o.domains]
        view["state"] = (
            "UNKNOWN"
            if not relevant
            else "DECLARED_ONLY"
            if all(o.local_basis == "DECLARED" for o in relevant)
            else "SCOPED_METADATA"
        )
    approved = [i for i in snapshot.inputs if i.input_basis == "APPROVED_INPUT"]
    return {
        "snapshot_sha256": digest(snapshot),
        "domains": domains,
        "coverage": {
            "basis": "APPROVED_INPUTS_ONLY",
            "approved_inputs": len(approved),
            "parsed_inputs": sum(i.status == "PARSED" for i in approved),
            "whole_asset_percent": None,
        },
        "metadata_graph": {"nodes": nodes, "edges": edges, "operational_relationships_inferred": False},
        "standard_document": False,
        "materialized_without_collection": True,
    }


def compare_snapshots(baseline: CollectionSnapshot, candidate: CollectionSnapshot):
    """Compare metadata multisets; collection failures never establish removal."""
    baseline = CollectionSnapshot.model_validate(baseline.model_dump())
    candidate = CollectionSnapshot.model_validate(candidate.model_dump())
    if any(getattr(baseline, k) != getattr(candidate, k) for k in ("family", "target_id", "system_id", "environment")):
        raise ValueError("Drift requires the same collector family and logical target/system/environment")
    if candidate.started_at < baseline.finished_at:
        raise ValueError("Candidate must start after baseline finishes")

    def index(snapshot):
        states = {(i.kind, i.path): i.status for i in snapshot.inputs}
        inputs = {i.input_id: (i.kind, i.path) for i in snapshot.inputs}
        slots = {}
        for o in snapshot.observations:
            slots.setdefault(o.identity_slot, []).append(o)
        return states, inputs, slots

    old_states, old_inputs, old = index(baseline)
    new_states, new_inputs, new = index(candidate)
    changes, unchanged = [], 0
    for slot in sorted(old.keys() | new.keys()):
        before, after = old.get(slot, []), new.get(slot, [])
        old_counts = Counter(o.fact_sha256 for o in before)
        new_counts = Counter(o.fact_sha256 for o in after)
        if before and after:
            if old_counts == new_counts:
                unchanged += 1
                continue
            state = "CHANGED_METADATA_RECORD"
        elif before:
            source = old_inputs[before[0].input_id]
            state = (
                "OUT_OF_COMPARISON_SCOPE"
                if source not in new_states
                else "UNRESOLVED_COLLECTION_GAP"
                if new_states[source] != "PARSED"
                else "NOT_REOBSERVED_IN_PARSED_INPUT"
            )
        else:
            source = new_inputs[after[0].input_id]
            state = "NEW_METADATA_RECORD" if old_states.get(source) == "PARSED" else "NEWLY_OBSERVABLE_METADATA"
        changes.append(
            {
                "identity_slot": slot,
                "state": state,
                "baseline_observation_ids": sorted(o.observation_id for o in before),
                "candidate_observation_ids": sorted(o.observation_id for o in after),
                "baseline_fact_counts": dict(sorted(old_counts.items())),
                "candidate_fact_counts": dict(sorted(new_counts.items())),
                "asset_absence_proven": False,
                "installation_or_removal_proven": False,
            }
        )
    return {
        "schema_version": "cryptoscan.collection-drift/v1",
        "baseline_sha256": digest(baseline),
        "candidate_sha256": digest(candidate),
        "unchanged_slots": unchanged,
        "changes": changes,
        "baseline_inputs": [i.model_dump(mode="json") for i in baseline.inputs],
        "candidate_inputs": [i.model_dump(mode="json") for i in candidate.inputs],
        "whole_asset_coverage_verified": False,
        "operational_use": "UNKNOWN",
        "materialized_without_collection": True,
    }
