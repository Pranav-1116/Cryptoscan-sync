"""Cluster and CMDB collection: the collector is where honesty is cheapest.

An observation is a claim that somebody saw this digest running. These tests pin
the two refusals that keep the claim true — a tag-only image yields no
observation, and a workload two applications claim is attributed to neither — and
pin that correlation never upgrades "in the SBOM" to "in production" on its own.
"""

from __future__ import annotations

from datetime import date

import pytest

from devsecops import deployment_collectors as collectors
from devsecops import sbom_evidence as evidence

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _pod(*, name="api-1", namespace="payments", kind="Pod", image="ghcr.io/bank/api:2026.11.02",
         image_id=None, running=True, container="api"):
    state = {"running": {}} if running else {"waiting": {"reason": "ImagePullBackOff"}}
    return {
        "kind": kind,
        "metadata": {"namespace": namespace, "name": name},
        "spec": {"containers": [{"name": container, "image": image}]},
        "status": {"containerStatuses": [
            {"name": container,
             "imageID": image_id if image_id is not None
             else f"docker-pullable://{image.split(':')[0]}@{DIGEST}",
             "state": state}]},
    }


def _snapshot(*pods):
    return {"items": list(pods)}


def test_a_running_container_becomes_one_observation():
    result = collectors.observations_from_kubernetes(_snapshot(_pod()), observed_at=date(2026, 11, 2))
    assert result["schema"] == collectors.SCHEMA
    assert len(result["observations"]) == 1
    observation = result["observations"][0]
    assert observation["artifact"]["digest"] == DIGEST
    assert observation["deployment"] == "payments/api-1"
    assert observation["workload"] == "pod/payments/api-1"
    assert observation["environment"] == "PRODUCTION"
    assert observation["evidence_id"].startswith("K8S-")


def test_the_runtime_digest_wins_over_the_requested_tag():
    pod = _pod(image="ghcr.io/bank/api:2026.11.02")
    pod["status"]["containerStatuses"][0]["imageID"] = (
        f"docker-pullable://ghcr.io/bank/api@{OTHER_DIGEST}")
    result = collectors.observations_from_kubernetes(_snapshot(pod), observed_at=date(2026, 11, 2))
    # the tag is what was asked for; the digest is what is running
    assert result["observations"][0]["artifact"]["digest"] == OTHER_DIGEST


def test_a_tag_only_image_produces_no_observation_and_a_reason():
    pod = _pod(image="ghcr.io/bank/api:latest",
               image_id="docker-pullable://ghcr.io/bank/api:latest")
    result = collectors.observations_from_kubernetes(_snapshot(pod), observed_at=date(2026, 11, 2))
    assert result["observations"] == []
    assert result["refused"][0]["reason"].startswith("the runtime reports")
    assert "no immutable identity" in result["refused"][0]["reason"]
    assert "1 refused" in result["statement"]


def test_a_spec_that_already_carries_a_digest_is_enough():
    pod = _pod(image=f"ghcr.io/bank/api@{DIGEST}", image_id="")
    result = collectors.observations_from_kubernetes(_snapshot(pod), observed_at=date(2026, 11, 2))
    assert result["observations"][0]["artifact"]["digest"] == DIGEST


def test_a_container_that_is_not_running_is_not_deployed():
    pod = _pod(running=False)
    result = collectors.observations_from_kubernetes(_snapshot(pod), observed_at=date(2026, 11, 2))
    assert result["observations"] == []
    assert "not in a running state" in result["skipped"][0]["reason"]


def test_a_non_workload_kind_is_skipped():
    result = collectors.observations_from_kubernetes(
        _snapshot(_pod(kind="ConfigMap")), observed_at=date(2026, 11, 2))
    assert result["observations"] == []
    assert "does not run containers" in result["skipped"][0]["reason"]


def test_the_environment_and_cluster_are_recorded_on_each_observation():
    result = collectors.observations_from_kubernetes(
        _snapshot(_pod()), observed_at=date(2026, 11, 2), environment="staging", cluster="prod-eu")
    assert result["observations"][0]["environment"] == "STAGING"
    assert result["observations"][0]["source"] == "kubernetes:prod-eu"


def test_the_snapshot_digest_makes_the_input_reproducible():
    result = collectors.observations_from_kubernetes(_snapshot(_pod()), observed_at=date(2026, 11, 2))
    assert len(result["snapshot_sha256"]) == 64
    assert result["observed_at"] == "2026-11-02"


def test_a_listing_without_pods_is_an_error_not_an_empty_success():
    with pytest.raises(ValueError, match="items"):
        collectors.observations_from_kubernetes({"unexpected": []})


def test_observations_are_recordable_by_the_evidence_layer():
    payload = collectors.observations_from_kubernetes(_snapshot(_pod()),
                                                      observed_at=date(2026, 11, 2))
    rebuilt = collectors._observation_from_dict(payload["observations"][0])
    assert rebuilt.artifact.digest == DIGEST
    assert rebuilt.observed_at == date(2026, 11, 2)


def test_the_register_maps_workloads_to_applications():
    register = collectors.register_from_cmdb({"applications": [
        {"name": "payments-api", "business_system": "Card Processing", "owner": "Payments",
         "criticality": "Tier 1", "workloads": ["pod/payments/api-1"]}]})
    assert register["by_workload"]["pod/payments/api-1"] == ["payments-api"]
    assert register["conflicts"] == []


def test_a_workload_claimed_twice_is_a_conflict_not_a_first_match():
    register = collectors.register_from_cmdb({"applications": [
        {"name": "a", "workloads": ["pod/payments/api-1"]},
        {"name": "b", "workloads": ["pod/payments/api-1"]}]})
    assert register["conflicts"][0]["applications"] == ["a", "b"]
    assert "more than one application" in register["statement"]


def test_a_register_without_applications_is_an_error():
    with pytest.raises(ValueError, match="applications"):
        collectors.register_from_cmdb({"rows": []})


def _sbom(*, digest=DIGEST, name="ghcr.io/bank/api"):
    return evidence.SbomRecord(sbom_id="SBOM-1",
                               artifact=evidence.ArtifactIdentity(name, digest),
                               components=({"name": "openssl", "version": "3.0.13"},))


def _observed():
    return collectors.observations_from_kubernetes(_snapshot(_pod()),
                                                   observed_at=date(2026, 11, 2))["observations"]


def test_correlation_upgrades_to_deployed_only_on_a_matching_digest():
    report = collectors.correlate([_sbom()], _observed())
    assert report["rows"][0]["state"] == "PRESENT_IN_DEPLOYMENT"
    assert report["rows"][0]["environments"] == ["PRODUCTION"]
    assert report["counts"] == {"PRESENT_IN_DEPLOYMENT": 1, "PRESENT_IN_ARTIFACT": 0,
                                "PRESENT_IN_SBOM_ONLY": 0}


def test_an_unobserved_digest_stops_at_the_artifact():
    report = collectors.correlate([_sbom(digest=OTHER_DIGEST)], _observed())
    assert report["rows"][0]["state"] == "PRESENT_IN_ARTIFACT"
    assert report["deployed"] == 0


def test_an_sbom_bound_to_nothing_is_document_only():
    record = evidence.SbomRecord(sbom_id="SBOM-2", artifact=None,
                                 components=({"name": "openssl"},))
    report = collectors.correlate([record], _observed())
    assert report["rows"][0]["state"] == "PRESENT_IN_SBOM_ONLY"


def test_correlation_attributes_only_registered_workloads():
    register = collectors.register_from_cmdb({"applications": [
        {"name": "payments-api", "business_system": "Card Processing",
         "workloads": ["pod/payments/api-1"]}]})
    report = collectors.correlate([_sbom()], _observed(), register=register)
    row = report["rows"][0]
    assert row["applications"] == ["payments-api"]
    assert row["business_systems"] == ["Card Processing"]
    assert row["attribution"] == "REGISTERED"


def test_unregistered_observations_are_reported_as_unattributed():
    report = collectors.correlate([_sbom()], _observed())
    assert report["rows"][0]["attribution"] == "UNREGISTERED"
    assert report["unattributed"] == 1


def test_a_conflicted_workload_is_attributed_to_neither_application():
    register = collectors.register_from_cmdb({"applications": [
        {"name": "a", "workloads": ["pod/payments/api-1"]},
        {"name": "b", "workloads": ["pod/payments/api-1"]}]})
    report = collectors.correlate([_sbom()], _observed(), register=register)
    row = report["rows"][0]
    assert row["applications"] == []
    assert row["attribution"] == "CONFLICT"
    assert row["attribution_conflicts"][0]["workload"] == "pod/payments/api-1"


def test_a_component_absent_from_the_sbom_is_not_a_row():
    report = collectors.correlate([_sbom()], _observed(), components=["openssl", "nothere"])
    assert [row["component"] for row in report["rows"]] == ["openssl"]


def test_an_unreadable_observation_is_skipped_not_guessed():
    report = collectors.correlate([_sbom()], [{"deployment": "x"}])
    # no digest means nothing can match, so the component stops at the artifact
    assert report["rows"][0]["state"] == "PRESENT_IN_ARTIFACT"


def test_sbom_record_from_document_reads_cyclonedx_and_spdx():
    cdx = {"bomFormat": "CycloneDX", "components": [{"name": "openssl", "version": "3.0.13"}]}
    record = collectors.sbom_record_from_document(cdx, image_reference="ghcr.io/bank/api",
                                                  image_digest=DIGEST)
    assert record.artifact.digest == DIGEST
    assert record.names() == {"openssl"}

    spdx = {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": "openssl", "versionInfo": "3.0.13", "SPDXID": "SPDXRef-a"}]}
    assert collectors.sbom_record_from_document(spdx).names() == {"openssl"}


def test_an_sbom_without_an_image_digest_is_bound_to_nothing():
    record = collectors.sbom_record_from_document(
        {"bomFormat": "CycloneDX", "components": [{"name": "openssl"}]})
    assert record.artifact is None
