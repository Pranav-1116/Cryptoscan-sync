"""Pure snapshot graph/drift contracts. Synthetic metadata is not qualification."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from shared_models.collection_views import CollectionSnapshot, DriftRequest, compare_snapshots, snapshot_views
from shared_models.host_collection import digest

ID = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


def snapshot(**updates):
    now = datetime(2026, 10, 26, tzinfo=timezone.utc)
    value = {
        "family": "host",
        "job_id": ID,
        "target_id": ID,
        "system_id": "payments",
        "environment": "prod",
        "source_sha256": "a" * 64,
        "started_at": now,
        "finished_at": now + timedelta(seconds=1),
        "inputs": [
            {
                "input_id": "packages",
                "kind": "DPKG_STATUS",
                "path": "/var/lib/dpkg/status",
                "status": "PARSED",
                "reason": "METADATA_ONLY",
            }
        ],
        "observations": [
            {
                "observation_id": "obs-1",
                "identity_slot": ID,
                "input_id": "packages",
                "fact_kind": "SOFTWARE",
                "fact_sha256": "b" * 64,
                "evidence_id": "evidence-1",
                "local_basis": "DECLARED",
                "domains": ["SBOM", "TechBOM"],
            }
        ],
    }
    value.update(updates)
    return CollectionSnapshot.model_validate(value)


def next_snapshot(old, **updates):
    value = old.model_dump(mode="json")
    value.update(
        job_id=OTHER,
        source_sha256="c" * 64,
        started_at=old.finished_at + timedelta(seconds=1),
        finished_at=old.finished_at + timedelta(seconds=2),
    )
    value.update(updates)
    return CollectionSnapshot.model_validate(value)


def test_six_views_share_retained_ids_and_closed_graph_without_use_edges():
    value = snapshot()
    result = snapshot_views(value)
    assert result["snapshot_sha256"] == digest(value)
    assert set(result["domains"]) == {"SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"}
    assert result["domains"]["SBOM"]["observation_ids"] == result["domains"]["TechBOM"]["observation_ids"] == ["obs-1"]
    assert result["domains"]["SBOM"]["state"] == "DECLARED_ONLY"
    assert result["domains"]["HBOM"]["state"] == "UNKNOWN"
    assert not any(v["complete"] for v in result["domains"].values())
    graph = result["metadata_graph"]
    ids = {n["node_id"] for n in graph["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
    assert {e["relationship"] for e in graph["edges"]} == {"HAS_METADATA_REFERENCE"}
    assert all(e["provenance"] == "IMPORTED" and e["operational_use"] == "UNKNOWN" for e in graph["edges"])
    assert graph["edges"][0]["evidence_ids"] == ["evidence-1"]
    assert result["coverage"]["whole_asset_percent"] is None
    assert not result["standard_document"]


def test_new_source_hash_time_and_observation_do_not_change_metadata_slot_or_edge():
    old = snapshot()
    observations = [old.observations[0].model_copy(update={"observation_id": "obs-2", "evidence_id": "evidence-2"})]
    new = next_snapshot(old, observations=observations)
    old_edge, new_edge = (snapshot_views(s)["metadata_graph"]["edges"][0] for s in (old, new))
    assert old_edge["edge_id"] == new_edge["edge_id"]
    report = compare_snapshots(old, new)
    assert report["unchanged_slots"] == 1 and not report["changes"]


@pytest.mark.parametrize(
    "status,reason",
    [
        ("DENIED", "ACCESS_DENIED"),
        ("UNAVAILABLE", "NOT_FOUND"),
        ("UNSUPPORTED", "LINK_OR_SPECIAL"),
        ("INVALID", "INVALID_FORMAT"),
        ("BUDGET_EXCEEDED", "LIMIT"),
    ],
)
def test_failed_source_is_gap_never_removed_asset(status, reason):
    old = snapshot()
    inputs = [old.inputs[0].model_copy(update={"status": status, "reason": reason})]
    new = next_snapshot(old, inputs=inputs, observations=[])
    change = compare_snapshots(old, new)["changes"][0]
    assert change["state"] == "UNRESOLVED_COLLECTION_GAP"
    assert not change["asset_absence_proven"] and not change["installation_or_removal_proven"]


def test_successful_input_missing_old_fact_is_only_not_reobserved():
    old = snapshot()
    new = next_snapshot(old, observations=[])
    assert compare_snapshots(old, new)["changes"][0]["state"] == "NOT_REOBSERVED_IN_PARSED_INPUT"


def test_changed_source_location_is_out_of_comparison_scope():
    old = snapshot()
    new = next_snapshot(old, inputs=[old.inputs[0].model_copy(update={"path": "/other/status"})], observations=[])
    assert compare_snapshots(old, new)["changes"][0]["state"] == "OUT_OF_COMPARISON_SCOPE"


def test_input_id_rename_does_not_fake_scope_change():
    old = snapshot()
    new = next_snapshot(old, inputs=[old.inputs[0].model_copy(update={"input_id": "renamed"})], observations=[])
    assert compare_snapshots(old, new)["changes"][0]["state"] == "NOT_REOBSERVED_IN_PARSED_INPUT"


@pytest.mark.parametrize("status", ["PARSED", "UNAVAILABLE"])
def test_newly_observable_is_not_proven_new_installation(status):
    original = snapshot()
    old = snapshot(inputs=[original.inputs[0].model_copy(update={"status": status})], observations=[])
    new = next_snapshot(original)
    event = compare_snapshots(old, new)["changes"][0]
    assert event["state"] == ("NEW_METADATA_RECORD" if status == "PARSED" else "NEWLY_OBSERVABLE_METADATA")
    assert not event["installation_or_removal_proven"]


def test_version_change_uses_same_slot_and_preserves_duplicate_multiplicity():
    old = snapshot()
    extra = old.observations[0].model_copy(update={"observation_id": "obs-2"})
    new = next_snapshot(old, observations=[old.observations[0], extra])
    event = compare_snapshots(old, new)["changes"][0]
    assert event["state"] == "CHANGED_METADATA_RECORD"
    assert event["baseline_fact_counts"] == {"b" * 64: 1}
    assert event["candidate_fact_counts"] == {"b" * 64: 2}
    assert snapshot_views(new)["metadata_graph"]["nodes"][1]["multiple_records_in_slot"]
    changed = next_snapshot(old, observations=[old.observations[0].model_copy(update={"fact_sha256": "d" * 64})])
    assert compare_snapshots(old, changed)["changes"][0]["identity_slot"] == ID


@pytest.mark.parametrize(
    "key,value", [("family", "oci"), ("target_id", OTHER), ("system_id", "other"), ("environment", "uat")]
)
def test_cross_scope_comparison_refused(key, value):
    old = snapshot()
    with pytest.raises(ValueError, match="same collector"):
        compare_snapshots(old, next_snapshot(old, **{key: value}))


@pytest.mark.parametrize("case", ["reversed", "overlapping"])
def test_clock_order_refused(case):
    old = snapshot()
    new = next_snapshot(old) if case == "reversed" else old
    with pytest.raises(ValueError, match="Candidate must start"):
        compare_snapshots(new, old)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_obs",
        "duplicate_input",
        "foreign_input",
        "failed_input",
        "slot_merge",
        "wrong_domain",
        "domain_duplicate",
        "no_techbom",
        "promote",
        "naive_time",
        "extra_field",
        "oversize",
        "reversed_clock",
    ],
)
def test_malformed_and_promoted_snapshots_refused(change):
    value = snapshot().model_dump(mode="json")
    if change == "duplicate_obs":
        value["observations"] *= 2
    elif change == "duplicate_input":
        value["inputs"] *= 2
    elif change == "foreign_input":
        value["observations"][0]["input_id"] = "foreign"
    elif change == "failed_input":
        value["inputs"][0]["status"] = "INVALID"
    elif change == "slot_merge":
        other = deepcopy(value["observations"][0])
        other.update(observation_id="obs-2", fact_kind="CERTIFICATE")
        value["observations"].append(other)
    elif change == "wrong_domain":
        value["observations"][0]["domains"] = ["FAKE", "TechBOM"]
    elif change == "domain_duplicate":
        value["observations"][0]["domains"] = ["TechBOM", "TechBOM"]
    elif change == "no_techbom":
        value["observations"][0]["domains"] = ["SBOM"]
    elif change == "promote":
        value["runtime_use"] = "OBSERVED"
    elif change == "naive_time":
        value["started_at"] = "2026-10-26T00:00:00"
    elif change == "extra_field":
        value["raw_key"] = "do-not-accept"
    elif change == "oversize":
        value["observations"] *= 1002
    else:
        value["finished_at"] = "2026-10-25T00:00:00Z"
    with pytest.raises(ValueError):
        CollectionSnapshot.model_validate(value)


def test_mutated_nested_model_is_revalidated_before_views_or_drift():
    old = snapshot()
    old.observations[0].__dict__["input_id"] = "foreign"
    with pytest.raises(ValueError):
        snapshot_views(old)
    with pytest.raises(ValueError):
        compare_snapshots(old, next_snapshot(snapshot()))


def test_same_snapshot_identifiers_refused():
    with pytest.raises(ValueError):
        DriftRequest(baseline_snapshot_id=ID, candidate_snapshot_id=ID)


def test_pinned_config_not_in_approved_input_denominator():
    value = snapshot()
    value.inputs.append(
        value.inputs[0].model_copy(
            update={
                "input_id": "config",
                "kind": "OCI_IMAGE_CONFIG",
                "path": "oci://image-config/config.json",
                "input_basis": "PINNED_IMAGE_CONFIG",
            }
        )
    )
    coverage = snapshot_views(value)["coverage"]
    assert coverage["approved_inputs"] == coverage["parsed_inputs"] == 1
