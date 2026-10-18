from copy import deepcopy
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def test_compact_endpoint_id_never_masquerades_as_provenance_source_and_replay_is_immutable():
    snapshot = {
        "systems": [{"id": s, "name": s} for s in ["mobile", "pay", "ledger", "backup"]],
        "dependencies": [
            {
                "id": "e1",
                "source": "mobile",
                "target": "pay",
                "type": "CALLS",
                "relationship_source": "manifest",
                "provenance": "DECLARED",
                "evidence_ref": "change:12",
                "last_confirmed_at": "2026-10-17",
            },
            {"source": "pay", "target": "ledger", "type": "IMPORTS"},
            {
                "source": "backup",
                "target": "pay",
                "type": "CALLS",
                "lifecycle_state": "STALE",
                "provenance": "SCANNER_DERIVED",
                "relationship_source": "mesh",
            },
        ],
    }
    original = deepcopy(snapshot)
    answer = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    explain = answer["traversal_evidence"]
    edge = explain["dependent_consumers"]["paths"][0]["edges"][0]
    assert edge["source"] == "manifest" and edge["from"] == "mobile" and edge["to"] == "pay"
    assert edge["provenance"] == "DECLARED" and edge["freshness"]["observation"]["status"] == "MISSING"
    context = explain["supporting_context"]["paths"][0]["edges"][0]
    assert context["provenance"] == "UNATTRIBUTED" and context["evidence_missing"] and "source" not in context
    potential = explain["potential"]["paths"][0]
    assert potential["scope"] == "potential" and potential["edges"][0]["freshness"]["eligibility"] == "STALE"
    assert answer["impact"]["system_classification"]["exposure_system_count"] == 2
    assert snapshot == original
    assert answer == unified_cascade(snapshot, target="pay", kind="system", now=NOW)


def test_package_seed_keeps_real_document_release_and_deployment_assertions():
    purl = "pkg:pypi/cryptography@44.0.0"
    snapshot = {
        "systems": [{"id": "pay", "name": "pay", "environment": "prod"}],
        "software_artifacts": [{"id": "release", "digest": "sha256:" + "a" * 64}],
        "software_sbom_bindings": [
            {
                "id": "binding",
                "artifact_id": "release",
                "sbom_artifact_id": "doc",
                "sbom_sha256": "b" * 64,
                "assertion_source": "supplier",
                "evidence_ref": "signed:manifest",
                "components": [{"package_identity": purl, "purl": purl}],
            }
        ],
        "software_deployments": [
            {
                "id": "deploy",
                "artifact_id": "release",
                "system_id": "pay",
                "environment": "prod",
                "deployment_key": "workload-1",
                "assertion_source": "operator",
                "evidence_ref": "change:deploy",
            }
        ],
    }
    answer = unified_cascade(snapshot, target=purl, kind="package", now=NOW)
    seed = answer["traversal_evidence"]["direct"][0]
    assert seed["path"]["nodes"] == ["package:" + purl, "artifact:release", "pay"]
    binding, deploy = seed["path"]["edges"]
    assert seed["path"]["available"] and binding["identity"]["sbom_sha256"] == "b" * 64
    assert binding["identity"]["digest"] == "sha256:" + "a" * 64
    assert [binding["record_id"], deploy["record_id"]] == ["binding", "deploy"]
    assert all(
        e["provenance"] == "DECLARED" and e["freshness"]["observation"]["status"] == "MISSING"
        for e in [binding, deploy]
    )


def test_old_algorithm_seed_is_explicitly_unverified_not_fabricated():
    snapshot = {
        "systems": [{"id": "pay", "name": "pay"}],
        "assets": [{"asset_id": "key", "system_ids": ["pay"], "algorithms": {"RSA": 1}}],
    }
    seed = unified_cascade(snapshot, target="RSA", kind="algorithm", now=NOW)["traversal_evidence"]["direct"][0]
    assert seed["record_count"] == 0 and not seed["complete_chain_verified"]
    assert "path" not in seed


def test_vendor_subtier_has_separate_declared_witness_not_runtime_calls():
    snapshot = {
        "vendors": [{"id": "v", "name": "Vendor"}, {"id": "chip", "name": "Chip"}],
        "vendor_dependencies": [
            {
                "id": "supply",
                "parent": "v",
                "child": "chip",
                "relation": "chip supplier",
                "provenance": "DECLARED",
                "source": "supplier register",
            }
        ],
    }
    answer = unified_cascade(snapshot, target="Vendor", kind="vendor", now=NOW)
    path = answer["traversal_evidence"]["vendor_subtiers"]["paths"][0]
    assert path["available"] and path["edges"][0]["source"] == "supplier register"
    assert path["edges"][0]["provenance"] == "DECLARED" and path["evidence_gap_count"] == 1
