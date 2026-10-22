from copy import deepcopy
from datetime import datetime, timezone
import pytest

from cbom.unified_cascade import unified_cascade

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
PURL = "pkg:pypi/cryptography@42.0.0"
DIGEST = "sha256:" + "a" * 64


def snapshot():
    return {
        "systems": [{"id": "pay", "name": "payments", "environment": "prod"},
                    {"id": "web", "name": "web"}, {"id": "db", "name": "db"}],
        "dependencies": [{"source": "web", "target": "pay", "type": "CALLS"},
                         {"source": "pay", "target": "db", "type": "DEPENDS_ON"}],
        "software_artifacts": [{"id": "release", "digest": DIGEST, "identity_source": "CONTENT_HASHED"}],
        "software_sbom_bindings": [{"id": "sbom-link", "artifact_id": "release", "sbom_artifact_id": "doc",
                                   "sbom_sha256": "b" * 64, "assertion_source": "SUPPLIER_DECLARED",
                                   "evidence_ref": "supplier-attestation/1",
                                   "components": [{"purl": PURL, "package_identity": PURL, "version": "42.0.0"}]}],
        "software_deployments": [{"id": "deploy", "artifact_id": "release", "system_id": "pay", "environment": "prod",
                                  "assertion_source": "OPERATOR_DECLARED", "evidence_ref": "change/1"}],
    }


def run(data, target=PURL, kind="package"):
    before = deepcopy(data)
    result = unified_cascade(data, target=target, kind=kind, now=NOW)
    assert data == before
    return result


def test_package_chain_seeds_deployed_application_not_all_installed_systems():
    result = run(snapshot())
    scope = result["impact"]["system_classification"]
    assert scope["direct_exposure"]["systems"] == ["pay"]
    assert scope["dependent_consumers"]["systems"] == ["web"]
    assert scope["supporting_context"]["systems"] == ["db"]
    chain = result["layers"]["software"]
    assert chain["sbom_bindings"][0]["sbom_sha256"] != chain["artifacts"][0]["digest"].split(":")[1]
    assert chain["deployments"][0]["evidence_ref"] == "change/1"
    assert "not independently observed" in chain["deployment_evidence"]


@pytest.mark.parametrize("target,kind", [(DIGEST, "artifact"), ("release", "artifact"), (PURL, None)])
def test_exact_artifact_and_automatic_purl_targets(target, kind):
    assert run(snapshot(), target, kind)["impact"]["affected_system_count"] == 3


@pytest.mark.parametrize("target", ["cryptography", "pkg:pypi/cryptography@41.0.0", "pkg:npm/cryptography@42.0.0", "PKG:pypi/cryptography@42.0.0"])
def test_names_other_versions_ecosystems_and_case_do_not_match(target):
    assert run(snapshot(), target)["verdict"] == "NOT_FOUND"


def test_unbound_release_is_insufficient_data_not_safe_or_a_guessed_deployment():
    data = snapshot()
    data["software_deployments"] = []
    result = run(data)
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert result["impact"]["affected_system_count"] == 0
    assert result["layers"]["software"]["unbound_artifact_ids"] == ["release"]
    assert any("consumers remain unknown" in u for u in result["honest_unknowns"])


def test_standalone_unbound_sbom_does_not_become_deployed_system_inventory():
    data = snapshot()
    data["software_sbom_bindings"] = []
    assert run(data)["verdict"] == "NOT_FOUND"
    assert run(data, DIGEST, "artifact")["verdict"] == "AFFECTED"  # explicit deployment still exists


@pytest.mark.parametrize("mutation", ["missing-system", "environment-conflict", "foreign-binding", "foreign-deployment"])
def test_incomplete_or_conflicting_join_cannot_seed_exposure(mutation):
    data = snapshot()
    if mutation == "missing-system":
        data["software_deployments"][0]["system_id"] = "ghost"
    elif mutation == "environment-conflict":
        data["software_deployments"][0]["environment"] = "staging"
    elif mutation == "foreign-binding":
        data["software_sbom_bindings"][0]["tenant_id"] = "another-bank"
    else:
        data["software_deployments"][0]["tenant_id"] = "another-bank"
    assert run(data)["impact"]["affected_system_count"] == 0


def test_multiple_deployments_and_sboms_are_deduped_without_dropping_evidence():
    data = snapshot()
    data["software_deployments"].append({**data["software_deployments"][0], "id": "replica"})
    data["software_sbom_bindings"].append({**data["software_sbom_bindings"][0], "id": "second-sbom"})
    result = run(data)
    assert result["impact"]["system_classification"]["direct_exposure"]["count"] == 1
    assert len(result["layers"]["software"]["deployments"]) == 2
    assert len(result["layers"]["software"]["sbom_bindings"]) == 2


def test_system_target_exposes_only_its_release_context():
    result = run(snapshot(), "pay", "system")
    assert result["layers"]["software"]["artifacts"][0]["digest"] == DIGEST
    assert run(snapshot(), "db", "system")["layers"]["software"]["artifacts"] == []


def test_artifact_uuid_does_not_steal_an_existing_system_auto_target():
    data = snapshot()
    data["software_artifacts"][0]["id"] = "pay"
    result = run(data, "pay", None)
    assert result["target"]["kind"] == "system"


def test_truncated_package_inputs_remain_unknown_even_when_no_target_matches():
    data = snapshot()
    data["software_supply_chain_coverage"] = {"truncated": True}
    result = run(data, "pkg:pypi/missing@1.0")
    assert result["verdict"] == "NOT_FOUND"
    assert any("truncated" in unknown for unknown in result["honest_unknowns"])


@pytest.mark.parametrize("version", ["${crypto.version}", "1.x", "[1.0,2.0)"])
@pytest.mark.parametrize("target_kind", ["package", "artifact"])
def test_quality_increment_legacy_unresolved_identity_does_not_create_exact_exposure(version, target_kind):
    from urllib.parse import quote
    purl = "pkg:maven/org.bank/crypto@" + quote(version, safe="")
    data = snapshot()
    data["software_sbom_bindings"][0]["components"] = [
        {"package_identity": purl, "purl": purl, "version": version}]
    data["software_sbom_bindings"][0]["unresolved_component_count"] = 0  # pre-upgrade projection
    if target_kind == "package":
        result = run(data, purl, "package")
        assert result["verdict"] == "NOT_FOUND"
        assert result["impact"]["affected_system_count"] == 0
    else:
        result = run(data, DIGEST, "artifact")
        # The explicit artifact/deployment relation remains available, but the
        # old projection cannot turn a build variable into an exact package.
        assert result["verdict"] == "AFFECTED"
        assert result["layers"]["software"]["packages"][0]["package_identity"] is None
        assert result["layers"]["software"]["sbom_bindings"][0]["unresolved_component_count"] == 1
