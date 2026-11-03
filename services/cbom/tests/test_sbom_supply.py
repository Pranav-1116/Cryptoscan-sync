"""The supply chain from the store, and the questions underneath it, as tests."""

from __future__ import annotations

import pytest
from cbom import digital_twin as dt
from cbom import nbom_graph as n
from cbom import sbom_dependency as sbom
from cbom import sbom_supply as supply
from cbom import techbom as tb

EVID_SRC = "EVID-95101"
EVID_CI = "EVID-95102"
EVID_SBOM = "EVID-95103"
EVID_IMG = "EVID-95104"
EVID_K8S = "EVID-95105"
EVID_RT = "EVID-95106"
EVID_HSM = "EVID-95107"
EVID_NET = "EVID-95108"

NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"

DIGEST_ARTIFACT = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"

SDK = "pkg:generic/payments-sdk@2.4.0"
HTTP = "pkg:generic/http-core@1.2.0"
OPENSSL = "pkg:generic/openssl"
OPENSSL_DEV = "pkg:generic/openssl-dev"
MAVEN = "pkg:generic/maven@3.9.6"
MOCKITO = "pkg:generic/mockito@5.4.0"
GHOST = "pkg:generic/ghost@0.0.9"
UNOWNED = "pkg:generic/legacy-agent@0.4.2"


# --------------------------------------------------------------------------- #
# The inventory
# --------------------------------------------------------------------------- #

def inventory(*, moved: bool = True) -> dict:
    software: list[dict] = [
        {"coordinate": SDK, "version": "2.4.0", "origin": "SBOM", "scope": "RUNTIME",
         "direct": True, "evidence_ref": EVID_SBOM},
        {"coordinate": HTTP, "version": "1.2.0", "origin": "SBOM", "scope": "RUNTIME",
         "evidence_ref": EVID_SBOM},
        {"coordinate": OPENSSL, "version": "3.0.13", "origin": "SBOM", "scope": "RUNTIME",
         "component_type": "library", "crypto_bearing": True, "product": "OpenSSL 3.x",
         "evidence_ref": EVID_SBOM,
         "version_sources": [
             {"source": "sbom", "value": "3.0.13", "class": "IMPORTED",
              "evidence_id": EVID_SBOM},
             {"source": "process-map", "value": "3.0.11", "class": "RUNTIME_OBSERVED",
              "evidence_id": EVID_RT}]},
        {"coordinate": MAVEN, "version": "3.9.6", "origin": "MANIFEST", "scope": "BUILD",
         "direct": True, "evidence_ref": EVID_CI},
        {"coordinate": MOCKITO, "version": "5.4.0", "origin": "MANIFEST", "scope": "TEST",
         "evidence_ref": EVID_CI},
        {"coordinate": GHOST, "version": "0.0.9", "origin": "SBOM", "scope": "RUNTIME",
         "evidence_ref": EVID_SBOM},
        {"coordinate": UNOWNED, "version": "0.4.2", "origin": "SCAN", "scope": "RUNTIME",
         "evidence_ref": EVID_IMG},
        # a row with no identity, and one claiming a probe class with nothing behind it
        {"version": "1.0.0", "origin": "SBOM", "scope": "RUNTIME"},
        {"coordinate": "pkg:generic/sneaky@1.0.0", "version": "1.0.0", "origin": "SBOM",
         "basis": "runtime-probe"},
    ]
    dependencies: list[dict] = [
        {"source": SDK, "target": HTTP, "type": "depends_on", "evidence_ref": EVID_SBOM},
        {"source": HTTP, "target": OPENSSL, "type": "depends_on", "evidence_ref": EVID_SBOM},
        {"source": OPENSSL, "target": "pkg:generic/zlib@1.3", "type": "depends_on"},
    ]
    if not moved:
        dependencies = [
            {"source": SDK, "target": OPENSSL, "type": "depends_on",
             "evidence_ref": EVID_SBOM},
            # a test-scope edge that the next projection no longer has
            {"source": MOCKITO, "target": HTTP, "type": "depends_on",
             "evidence_ref": EVID_CI}]
    if not moved:
        software = [row for row in software if row.get("coordinate") != OPENSSL_DEV]
    else:
        software.append({"coordinate": OPENSSL_DEV, "version": "3.0.13", "origin": "SCAN",
                         "scope": "BUILD", "evidence_ref": EVID_IMG})
    return {
        "environment": "PRODUCTION",
        "applications": [
            {"id": "APP-1", "name": "Payments API", "system": "Payments System",
             "evidence_ref": EVID_SRC},
            {"id": "APP-2", "name": "Reporting API", "system": "Payments System",
             "evidence_ref": EVID_IMG}],
        "software": software,
        "dependencies": dependencies,
        "supply": {
            "repositories": [{"name": "git.bank.internal/payments/payments-api",
                              "url": "https://git.bank.internal",
                              "applications": ["Payments API"], "evidence_ref": EVID_SRC}],
            "commits": [{"sha": "a81f92c",
                         "repository": "git.bank.internal/payments/payments-api",
                         "author": "payments-team", "committed_at": EARLIER,
                         "evidence_ref": EVID_SRC}],
            "builds": [{"name": "BUILD-18291", "commit": "a81f92c",
                        "repository": "git.bank.internal/payments/payments-api",
                        "pipeline": "jenkins-payments-ci", "evidence_ref": EVID_CI}],
            "artifacts": [
                {"name": "payments-api-4.2.1.jar", "digest": DIGEST_ARTIFACT,
                 "build": "BUILD-18291", "kind": "JAR", "evidence_ref": EVID_CI},
                {"name": "payments-api:latest", "build": "BUILD-18291",
                 "evidence_ref": EVID_IMG}],
            "layers": [{"name": "layer:ubuntu-22.04-base", "image": "payments-api:4.2.1",
                        "base": "ubuntu:22.04", "packages": [OPENSSL, HTTP, "pkg:gone@0"],
                        "evidence_ref": EVID_IMG}],
            "images": [
                {"name": "payments-api:4.2.1", "digest": DIGEST_IMAGE,
                 "artifact": "payments-api-4.2.1.jar", "tag": "4.2.1",
                 "layers": ["layer:ubuntu-22.04-base"], "installed": [OPENSSL],
                 "evidence_ref": EVID_IMG},
                {"name": "reporting-api:1.0.0", "digest": "sha256:1122aabbccdd3344eeff5566",
                 "installed": [OPENSSL_DEV] if moved else [], "evidence_ref": EVID_IMG}],
            "releases": [{"name": "payments-api 4.2.1", "application": "Payments API",
                          "version": "4.2.1", "artifact": "payments-api-4.2.1.jar",
                          "evidence_ref": EVID_CI}],
            "sboms": [{"name": "SBOM-18291", "artifact": "payments-api-4.2.1.jar",
                       "tool": "syft-1.18", "generated_at": EARLIER,
                       "components": [SDK, HTTP, OPENSSL, MAVEN, MOCKITO, GHOST,
                                      "pkg:never@9.9.9"], "evidence_ref": EVID_SBOM}],
            "deployments": [{"name": "payments-api-deploy", "image": "payments-api:4.2.1",
                             "namespace": "payments", "cluster": "prod-cluster",
                             "replica_set": "payments-api-7d9f4c", "evidence_ref": EVID_K8S,
                             "pods": [{"name": "payments-api-7d9f4c-x2m8p", "node": "node-03",
                                       "host": "srv-k8s-03",
                                       "containers": ["payments-api-ctr"]}]}],
            "processes": [{"name": "payments-api[1821]", "pid": 1821,
                           "application": "Payments API", "pod": "payments-api-7d9f4c-x2m8p",
                           "loads": [OPENSSL], "basis": "process-trace",
                           "evidence_ref": EVID_RT}]},
        "vendors": [{"name": "OpenSSL Project", "product": "OpenSSL 3.x",
                     "version": "3.0.13", "lifecycle": "ACTIVE", "evidence_ref": EVID_SBOM}],
        "crypto": [
            {"id": "CR-1", "algorithm": "RSA", "key_size": 2048, "family": "RSA",
             "library": OPENSSL, "operation": "SIGN", "process": "payments-api[1821]",
             "application": "Payments API", "hash": "SHA-256", "observed_at": NOW,
             "evidence_ref": EVID_RT},
            {"id": "CR-2", "algorithm": "AES", "key_size": 256, "mode": "GCM",
             "library": OPENSSL, "evidence_ref": EVID_SBOM},
            {"id": "CR-3", "algorithm": "ECDSA", "key_size": 256, "curve": "P-256",
             "library": OPENSSL, "evidence_ref": EVID_SBOM}],
        "hardware": [{"name": "HSM-001", "type": "HSM", "model": "nShield",
                      "algorithms": ["RSA-2048"], "evidence_ref": EVID_HSM}],
        "certificates": [{"name": "CERT-001", "subject": "CN=payments.bank.example",
                          "signature_algorithm": "ECDSA-256", "key_algorithm": "ECDSA-256",
                          "endpoint": "payments.bank.example:443",
                          "evidence_ref": EVID_NET}],
        "endpoints": [{"name": "payments.bank.example:443", "host": "203.0.113.10",
                       "port": 443, "suite": "TLS_AES_256_GCM_SHA384",
                       "algorithm": "AES-256", "application": "Payments API",
                       "evidence_ref": EVID_NET}],
    }


@pytest.fixture(scope="module")
def built() -> dict:
    current = supply.from_inventory(inventory())
    previous = supply.from_inventory(inventory(moved=False))
    return {"current": current, "bom": tb.build(current["estate"]),
            "previous": tb.build(previous["estate"])}


@pytest.fixture(scope="module")
def bom(built: dict) -> dict:
    return built["bom"]


# --------------------------------------------------------------------------- #
# The adapter
# --------------------------------------------------------------------------- #

def test_an_inventory_becomes_the_twelve_levels(built: dict):
    levels = sbom.levels(built["bom"])
    assert all(levels[name] for _, name in sbom.SUPPLY_LEVELS), levels


def test_the_store_builds_through_the_canonical_estate(built: dict):
    assert built["bom"]["source_of_truth"] == "CANONICAL_ESTATE"
    assert built["bom"]["projection"] is True
    assert built["bom"]["refusals"] == []


def test_a_row_with_no_identity_is_skipped_with_a_reason(built: dict):
    reasons = [row for row in built["current"]["skipped"]
               if "no coordinate" in row["reason"]]
    assert reasons and reasons[0]["kind"] == "COMPONENT"


def test_a_probe_class_needs_the_collectors_evidence(built: dict):
    codes = {row["code"] for row in built["current"]["skipped"]}
    assert "PROBE_BASIS_WITHOUT_EVIDENCE" in codes
    assert "pkg:generic/sneaky@1.0.0" not in {row["name"] for row in built["bom"]["assets"]}


def test_a_probe_basis_with_its_evidence_is_accepted(built: dict):
    process = next(row for row in built["bom"]["assets"]
                   if row["kind"] == "PROCESS")
    loads = [claim for claim in built["bom"]["claims"]
             if claim["relation"] == "LOADS" and claim["to"] == OPENSSL]
    assert process["name"] == "payments-api[1821]"
    assert loads and loads[0]["basis"] == "process-trace"


def test_an_edge_to_an_undeclared_node_is_refused(built: dict):
    subjects = " ".join(row["subject"] for row in built["current"]["skipped"])
    assert "zlib" in subjects
    assert "pkg:gone@0" in subjects
    assert "pkg:never@9.9.9" in subjects


def test_a_tag_only_artifact_is_refused_by_the_store_too(built: dict):
    codes = {row["code"] for row in built["current"]["skipped"]}
    assert "ARTIFACT_WITHOUT_DIGEST" in codes
    assert "payments-api:latest" not in {row["name"] for row in built["bom"]["assets"]}


def test_a_system_named_by_two_applications_is_one_asset(built: dict):
    systems = [row for row in built["bom"]["assets"] if row["kind"] == "BUSINESS_SYSTEM"]
    assert len(systems) == 1
    contains = [claim for claim in built["bom"]["claims"]
                if claim["relation"] == "CONTAINS"]
    assert len(contains) == 2


def test_a_process_is_run_by_a_pod_and_not_by_a_container(built: dict):
    relations = {claim["relation"] for claim in built["bom"]["claims"]
                 if claim["to"] == "payments-api[1821]"}
    assert "RUNS_PROCESS" in relations
    runner = next(claim for claim in built["bom"]["claims"]
                  if claim["to"] == "payments-api[1821]"
                  and claim["relation"] == "RUNS_PROCESS")
    assert runner["from"] == "payments-api-7d9f4c-x2m8p"


# --------------------------------------------------------------------------- #
# The chain, on the store-built projection
# --------------------------------------------------------------------------- #

def test_provenance_is_complete_from_stored_rows(bom: dict):
    found = sbom.provenance(bom, artifact="payments-api-4.2.1.jar")
    assert found["complete"] is True
    assert found["steps"]["commit"] == "a81f92c"
    assert found["steps"]["build"] == "BUILD-18291"
    assert found["steps"]["digest"] == DIGEST_ARTIFACT


def test_the_application_owns_its_component_through_the_release(bom: dict):
    owners = sbom.component_owners(bom, query=OPENSSL)
    assert owners["applications"] == ["Payments API"]
    assert any("RELEASED_AS" in step for step in owners["owners"][0]["path"])


def test_a_component_nobody_lists_has_no_owner(bom: dict):
    assert sbom.component_owners(bom, query=UNOWNED)["applications"] == []


def test_installed_is_not_deployed(bom: dict):
    states = sbom.deployment_state(bom, query=OPENSSL_DEV)
    assert states["states"]["INSTALLED"] is True
    assert states["states"]["DEPLOYED"] is False
    assert states["deployed"] is False


def test_a_component_installed_in_a_deployed_image_is_deployed(bom: dict):
    assert sbom.deployment_state(bom, query=OPENSSL)["states"]["DEPLOYED"] is True


def test_two_stored_versions_survive_the_mapping(bom: dict):
    versions = sbom.version_layers(bom, query=OPENSSL)
    assert versions["layers"]["DECLARED_VERSION"] == "3.0.13"
    assert versions["layers"]["RUNTIME_VERSION"] == "3.0.11"
    assert versions["code"] == "DEPENDENCY_VERSION_CONFLICT"


def test_direct_and_transitive_are_read_from_the_store(bom: dict):
    tree = sbom.dependency_tree(bom, query="Payments API")
    assert SDK in {row["component"] for row in tree["direct"]}
    assert HTTP in {row["component"] for row in tree["transitive"]}
    openssl = next(row for row in tree["transitive"] if row["component"] == OPENSSL)
    assert openssl["path"] == [SDK, HTTP, OPENSSL]


def test_the_crypto_rows_hand_capability_to_the_cbom(bom: dict):
    handoff = sbom.crypto_handoff(bom, query=OPENSSL)
    assert handoff["count"] == 3
    assert handoff["corroborated"] == ["pkg:generic/openssl:RSA-2048"]


def test_component_states_sees_the_operation_through_the_algorithm(bom: dict):
    states = sbom.component_states(bom, query=OPENSSL)
    assert {"SBOM_PRESENT", "INSTALLED", "LOADED", "RUNTIME_USED"} <= set(states["present"])


def test_an_installed_in_edge_is_read_from_the_component_side(built: dict):
    """A package that says where it is installed does not need the image to say it back."""
    estate = n.estate(
        tb.asset("PACKAGE", "pkg:generic/pinned@1.0", evidence_ids=[EVID_SBOM]),
        tb.asset("IMAGE", "app:1.0", digest="sha256:aa", evidence_ids=[EVID_IMG]),
        n.part(claims=[tb.claim("pkg:generic/pinned@1.0", "INSTALLED_IN", "app:1.0",
                                basis="sbom-import", evidence_ids=[EVID_IMG])]),
        estate_id="installed-in")
    doc = tb.build(estate)
    states = sbom.deployment_state(doc, query="pkg:generic/pinned@1.0")
    assert states["states"]["INSTALLED"] is True
    assert "installed in app:1.0" in states["evidence"]["INSTALLED"]


# --------------------------------------------------------------------------- #
# The questions underneath the chain
# --------------------------------------------------------------------------- #

def test_canonical_ids_are_issued_per_asset_and_stable(bom: dict):
    first = sbom.canonical_assets(bom)
    second = sbom.canonical_assets(bom)
    assert [row["id"] for row in first["canonical"]] == [row["id"] for row in second["canonical"]]
    assert first["counts"]["canonical"] <= first["counts"]["records"]


def test_one_artifact_reached_two_ways_is_one_canonical_asset(bom: dict):
    result = sbom.canonical_assets(bom)
    merged = [row for row in result["canonical"] if len(row["records"]) > 1]
    assert merged
    assert all(row["by"] == "evidence" for row in merged)
    names = {entry["name"] for row in merged for entry in row["records"]}
    assert "payments-api-4.2.1.jar" in names


def test_a_name_only_record_is_never_merged(bom: dict):
    result = sbom.canonical_assets(bom)
    weak = [row for row in result["canonical"] if row["by"] == "name"]
    assert weak and all(len(row["records"]) == 1 for row in weak)


def test_the_vendor_is_reached_through_the_product(bom: dict):
    chain = sbom.vendor_chain(bom, query=OPENSSL)
    assert chain["product"] == "OpenSSL 3.x"
    assert chain["vendor"] == "OpenSSL Project"
    assert chain["deployments"]
    assert sbom.vendor_chain(bom, query=MAVEN)["vendor"] is None


def test_the_blast_radius_of_a_crypto_upgrade_reaches_the_hardware(bom: dict):
    radius = sbom.remediation_blast_radius(bom, query=OPENSSL, target_version="3.0.14")
    assert radius["affected"]["applications"] == 1
    assert "RSA-2048" in radius["algorithms"]
    assert radius["hardware"] == ["HSM-001"]
    assert radius["certificates"] == ["CERT-001"]
    assert radius["endpoints"] == ["payments.bank.example:443"]
    assert any("re-validation" in item for item in radius["regression"])
    assert any("re-issue" in item for item in radius["regression"])


def test_a_superseded_edge_keeps_the_row_that_replaced_it(built: dict):
    lifecycle = sbom.supply_lifecycle(built["bom"], built["previous"], detected_at=NOW)
    superseded = [row for row in lifecycle["rows"] if row["state"] == "SUPERSEDED"]
    assert superseded
    assert superseded[0]["superseded_by"]
    assert superseded[0]["source"] == SDK
    assert superseded[0]["target"] == OPENSSL


def test_a_first_seen_edge_is_not_an_active_one(built: dict):
    lifecycle = sbom.supply_lifecycle(built["bom"], built["previous"])
    states = {row["state"] for row in lifecycle["rows"]}
    assert {"FIRST_SEEN", "ACTIVE"} <= states
    assert lifecycle["counts"]["FIRST_SEEN"] >= 1


def test_a_removed_edge_is_kept_rather_than_deleted(built: dict):
    lifecycle = sbom.supply_lifecycle(built["bom"], built["previous"])
    removed = [row for row in lifecycle["rows"] if row["state"] == "REMOVED"]
    assert removed and removed[0]["source"] == MOCKITO


def test_every_crypto_edge_carries_one_of_the_eight_types(bom: dict):
    profile = sbom.evidence_profile(bom)
    assert profile["rows"]
    assert all(row["evidence_type"] in sbom.EVIDENCE_TYPES for row in profile["rows"])
    assert set(profile["counts"]) <= set(sbom.EVIDENCE_TYPES)
    assert profile["proven"] >= 1 and profile["unproven"] >= 1


def test_the_projection_states_its_source(bom: dict):
    twin = sbom.twin_projection(bom)
    assert twin["second_store"] is False
    assert twin["canonical"] == "CANONICAL_ESTATE"
    assert twin["derived_from"] == bom["derived_from"]


def test_a_twin_is_checked_when_one_is_handed_over(bom: dict):
    twin = sbom.twin_projection(bom, {"nodes": [{"id": "pkg:generic/openssl"},
                                                 {"id": "not-an-asset"}]})
    assert twin["matched"] >= 1
    assert twin["twin_nodes"] == 2


def test_a_real_twin_document_is_accepted_as_the_comparison(bom: dict):
    twin_document = dt.build({"name": "bank-estate", "components": [], "operations": [],
                              "keys": [], "probes": [], "findings": [], "conflicts": [],
                              "coverage": {}})
    result = sbom.twin_projection(bom, twin_document)
    assert result["twin_nodes"] >= 1
    assert result["second_store"] is False


# --------------------------------------------------------------------------- #
# The bundle
# --------------------------------------------------------------------------- #

def test_a_nested_part_keeps_its_claims():
    """``part()`` used to flatten a nested part's assets and drop its claims."""
    inner = n.part(tb.asset("PACKAGE", "pkg:inner@1", evidence_ids=[EVID_SBOM]),
                   claims=[tb.claim("pkg:inner@1", "INSTALLED_IN", "app:1.0",
                                    basis="sbom-import", evidence_ids=[EVID_SBOM])])
    bundled = n.part(tb.asset("IMAGE", "app:1.0", digest="sha256:aa",
                              evidence_ids=[EVID_IMG]), inner)
    assert {row["name"] for row in bundled["assets"]} == {"app:1.0", "pkg:inner@1"}
    assert [claim["relation"] for claim in bundled["claims"]] == ["INSTALLED_IN"]
