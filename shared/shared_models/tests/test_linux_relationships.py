"""Synthetic metadata witnesses; no service, hardware or bank host execution."""

from copy import deepcopy
from collections import defaultdict
from hashlib import sha256
import pytest
from pydantic import ValidationError
from shared_models.host_collection import digest
from shared_models.host_runtime import RuntimeFact, domains
from shared_models.collection import Observation
from shared_models.collection_coverage import CoverageReport, SURFACES, BOMS
from shared_models.linux_relationships import LinuxRelationships, _joins, UNSUPPORTED

H = "a" * 64
BOOT = "12345678-1234-1234-1234-123456789abc"


def process(pid=77, start=99, boot=BOOT, service="payments.service"):
    return RuntimeFact(
        kind="PROCESS",
        interface="LINUX_PROCFS",
        interface_sha256=H,
        identity_key=f"{boot}:{pid}:{start}",
        pid=pid,
        process_start_ticks=start,
        boot_id=boot,
        process_name="payments",
        service_name=service,
    )


def library(pid=77, start=99, boot=BOOT, path="/usr/lib/libssl.so"):
    return RuntimeFact(
        kind="LOADED_LIBRARY",
        interface="LINUX_PROCFS",
        interface_sha256=H,
        identity_key=f"{boot}:{pid}:{start}:{sha256(path.encode()).hexdigest()}:0",
        pid=pid,
        process_start_ticks=start,
        boot_id=boot,
        library_path=path,
        mapped_file_deleted=False,
        mapping_basis="SHARED_OBJECT_PATH_SUFFIX_ONLY",
    )


def service(pid=77, name="payments.service"):
    return RuntimeFact(
        kind="SERVICE",
        interface="SYSTEMD_READ_ONLY",
        interface_sha256=H,
        identity_key=name,
        service_name=name,
        service_state="active",
        pid=pid,
    )


def packet(facts):
    """Build a typed synthetic projection, not an admitted original host snapshot."""
    sources = {"PROCESS": "LINUX_PROCESS", "LOADED_LIBRARY": "LINUX_PROCESS_MAPS", "SERVICE": "LINUX_SERVICE"}
    nodes = []
    by_kind = defaultdict(list)
    for n, fact in enumerate(facts):
        kind = sources[fact.kind]
        key = "input-" + kind
        row = Observation(
            observation_id=f"obs-{n}",
            identity_slot=f"slot-{n}",
            input_id=key,
            fact_ordinal=len(by_kind[kind]),
            fact=fact,
            source={
                "kind": kind,
                "path": f"synthetic://{kind}",
                "input_content_sha256": H,
                "host_id": "synthetic-host",
            },
            collected_at="2026-10-25T00:00:01Z",
            evidence_id=f"evidence-{n}",
            content_hash=H,
            fact_sha256=digest(fact),
            contributes_to=domains(fact),
        )
        nodes.append(row)
        by_kind[kind].append(row)
    surfaces = {}
    for name, kinds in SURFACES.items():
        inputs = [
            {
                "input_id": rows[0].input_id,
                "kind": kind,
                "status": "PARSED",
                "reason": "PARSED_RECEIPT_NOT_ABSENCE_PROOF",
                "fact_count": len(rows),
                "evidence_ids": [r.evidence_id for r in rows],
                "local_basis_counts": {"OBSERVED": len(rows), "DECLARED": 0},
            }
            for kind, rows in by_kind.items()
            if kind in kinds
        ]
        surfaces[name] = {
            "approved_inputs": len(inputs),
            "parsed_inputs": len(inputs),
            "failed_inputs": 0,
            "fact_count": sum(i["fact_count"] for i in inputs),
            "inputs": inputs,
            "outcome": "PARSED_WITH_FACTS" if inputs else "NOT_REQUESTED",
            "approved_input_parse_percent": 100.0 if inputs else None,
        }
    coverage = CoverageReport(
        job_id="synthetic-job",
        target_id="synthetic-target",
        target_revision=2,
        target_sha256=H,
        system_id="synthetic-system",
        environment="test",
        started_at="2026-10-25T00:00:00Z",
        finished_at="2026-10-25T00:00:01Z",
        envelope_sha256=H,
        surfaces=surfaces,
        bom_observation_counts={k: sum(k in r.contributes_to for r in nodes) for k in BOMS},
    )
    edges, unresolved = _joins(nodes, coverage.job_id)
    return LinuxRelationships(coverage=coverage, nodes=nodes, edges=edges, unresolved=unresolved)


def test_exact_incarnation_and_reported_unit_are_only_metadata_edges():
    value = packet([process(), library(), service()])
    assert {e.relation for e in value.edges} == {"PROCESS_HAS_MAPPED_PATH", "PROCESS_REPORTS_SERVICE_UNIT"}
    assert not value.unresolved and value.unsupported_relationships == list(UNSUPPORTED)
    assert all(e.runtime_use == "UNKNOWN" and not e.production_traffic_proven for e in value.edges)
    assert all(len(e.supporting_observation_ids) == 2 and len(e.evidence_ids) == 2 for e in value.edges)
    assert LinuxRelationships.model_validate(value.model_dump(mode="json")) == value


@pytest.mark.parametrize("change", ["pid-reused", "other-boot", "other-pid", "no-process"])
def test_process_identity_requires_boot_pid_and_start_not_just_pid(change):
    other = (
        process(start=100)
        if change == "pid-reused"
        else process(boot="22345678-1234-1234-1234-123456789abc")
        if change == "other-boot"
        else process(pid=78)
    )
    value = packet([library()] if change == "no-process" else [other, library()])
    assert not any(e.relation == "PROCESS_HAS_MAPPED_PATH" for e in value.edges)
    assert any(u.reason == "NO_MATCHING_OBSERVATION" for u in value.unresolved)


def test_mainpid_alone_cannot_link_service_to_process():
    value = packet([process(service=None), service()])
    assert not value.edges and value.unresolved[0].reason == "SERVICE_UNIT_NOT_RECORDED"


def test_ambiguous_subjects_never_choose_a_winner_and_candidate_output_is_bounded():
    value = packet([*[process() for _ in range(25)], library()])
    mapping = next(u for u in value.unresolved if u.relation == "PROCESS_HAS_MAPPED_PATH")
    assert mapping.reason == "AMBIGUOUS_MATCH" and mapping.candidate_count == 25
    assert len(mapping.candidate_observation_ids) == 20 and mapping.candidate_list_truncated
    assert not value.edges


def test_ambiguous_service_names_leave_membership_unresolved():
    value = packet([process(), service(), service(pid=78)])
    assert not value.edges and value.unresolved[0].reason == "AMBIGUOUS_MATCH"


@pytest.mark.parametrize(
    "change",
    [
        "edge-id",
        "endpoint",
        "support",
        "proof",
        "promotion",
        "remove-gap",
        "unsupported",
        "changed-fact",
        "counts",
        "duplicate-node",
        "observed-edge",
    ],
)
def test_public_graph_contract_refuses_fabricated_or_inconsistent_edges(change):
    raw = deepcopy(packet([process(), library(), service()]).model_dump(mode="json"))
    if change == "observed-edge":
        raw["edges"][0]["local_basis"] = "OBSERVED"
    elif change == "edge-id":
        raw["edges"][0]["edge_id"] = "b" * 64
    elif change == "endpoint":
        raw["edges"][0]["target_observation_id"] = "not-captured"
    elif change == "support":
        raw["edges"][0]["supporting_observation_ids"] = ["obs-0", "not-captured"]
    elif change == "proof":
        raw["edges"][0]["evidence_ids"] = ["forged"]
    elif change == "promotion":
        raw["relationship_completeness_proven"] = True
    elif change == "remove-gap":
        raw["edges"] = []
    elif change == "unsupported":
        raw["unsupported_relationships"] = []
    elif change == "changed-fact":
        raw["nodes"][0]["fact_sha256"] = "b" * 64
    elif change == "counts":
        raw["coverage"]["bom_observation_counts"]["SBOM"] = 0
    else:
        raw["nodes"].append(raw["nodes"][0])
    with pytest.raises(ValidationError):
        LinuxRelationships.model_validate(raw)
