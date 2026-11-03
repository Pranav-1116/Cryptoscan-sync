"""Live collection: transports, payloads, and the chain they walk into, as tests.

The module under test turns a recorded answer from each bank system — git host, CI,
registry, scanner, cluster, probe, SBOM, CMDB, agent — into rows, merges those rows into one
inventory without losing their disagreements, and hands the inventory to the supply-chain
adapter so that the chain can be walked. Every test below asserts something the guide claims:
a class ceiling, a refusal, a kept conflict, a level of the chain.
"""

from __future__ import annotations

import pytest
from cbom import sbom_collectors as sc
from cbom import sbom_dependency as sd
from cbom import techbom as tb

NOW = "2026-11-03T08:30:00Z"
RECENT = "2026-11-03T06:30:00Z"
STALE = "2026-10-24T06:30:00Z"

DIGEST_JAR = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"
DIGEST_OTHER = "sha256:99999999aaaabbbbccccddddeeeeffff"
LAYER = "sha256:aa11bb22cc33dd44ee55ff66aa77bb88"

REPO = "bank/payments-api"
SHA = "a81f92c"
OPENSSL = "pkg:generic/openssl"
SDK = "pkg:generic/payments-sdk"
HTTP = "pkg:generic/http-core"
APP = "Payments API"


# --------------------------------------------------------------------------- #
# Payloads — one recorded answer per transport
# --------------------------------------------------------------------------- #
def git_payload(**overrides):
    payload = {
        "transport": "git", "collected_at": RECENT,
        "repository": {"full_name": REPO, "url": "https://git.bank.internal/bank/payments-api",
                       "default_branch": "main", "applications": [APP]},
        "commits": [{"sha": SHA, "author": "payments-team", "committed_at": RECENT,
                     "message": "harden card data path"},
                    {"branch": "main", "author": "payments-team"}],
    }
    payload.update(overrides)
    return payload


def ci_payload(**overrides):
    payload = {
        "transport": "ci", "collected_at": RECENT,
        "build": {"name": "BUILD-18291", "commit": SHA, "repository": REPO,
                  "pipeline": "jenkins-payments-ci", "status": "SUCCESS"},
        "artifacts": [
            {"name": "payments-api-4.2.1.jar", "digest": DIGEST_JAR, "kind": "JAR"},
            {"name": "payments-api.jar"},
        ],
    }
    payload.update(overrides)
    return payload


def registry_payload(**overrides):
    payload = {
        "transport": "registry", "collected_at": RECENT,
        "image": {"repository": "payments-api", "tag": "4.2.1", "digest": DIGEST_IMAGE},
        "layers": [{"digest": LAYER, "size": 74_000_000, "media_type": "application/vnd.oci"}],
    }
    payload.update(overrides)
    return payload


def kubernetes_payload(**overrides):
    payload = {
        "transport": "kubernetes", "collected_at": RECENT, "cluster": "prod-cluster",
        "nodes": [{"name": "node-03", "host": "srv-k8s-03", "datacenter": "Mumbai-DC2"}],
        "deployments": [
            {"name": "payments-api-deploy", "namespace": "payments",
             "replica_set": "payments-api-7d9f4c", "image": "payments-api:4.2.1",
             "pods": [{"name": "payments-api-7d9f4c-x2m8p", "node": "node-03",
                       "containers": ["payments-api-ctr"]}]},
            {"name": "ghost-deploy", "namespace": "payments"},
        ],
    }
    payload.update(overrides)
    return payload


def probe_payload(**overrides):
    payload = {
        "transport": "process", "collected_at": NOW, "host": "srv-k8s-03",
        "processes": [
            {"name": "payments-api[1821]", "pid": 1821, "application": APP,
             "pod": "payments-api-7d9f4c-x2m8p", "provider": OPENSSL,
             "libraries": [{"name": "libcrypto.so.3", "package": OPENSSL, "version": "3.0.11",
                            "crypto": True, "path": "/usr/lib/libcrypto.so.3"},
                           {"name": "libssl.so.3", "package": OPENSSL, "version": "3.0.11",
                            "crypto": True}],
             "operations": [
                 {"operation": "SIGN", "algorithm": "RSA", "family": "RSA", "key_size": 2048,
                  "hash": "SHA-256", "purpose": "payment instruction signature",
                  "observed_at": NOW},
                 {"operation": "ENCRYPT", "algorithm": "AES", "family": "AES", "key_size": 256,
                  "mode": "GCM", "observed_at": NOW},
                 {"operation": "VERIFY", "observed_at": NOW}]},
        ],
    }
    payload.update(overrides)
    return payload


def scan_payload(**overrides):
    payload = {
        "transport": "scan", "collected_at": RECENT,
        "image": {"name": "payments-api:4.2.1", "tag": "4.2.1", "digest": DIGEST_IMAGE},
        "packages": [
            {"coordinate": OPENSSL, "name": "openssl", "version": "3.0.13", "crypto": True},
            {"coordinate": SDK, "name": "payments-sdk", "version": "2.4.0"},
            {"coordinate": HTTP, "name": "http-core", "version": "1.2.0"},
            {"name": "mystery"},
        ],
    }
    payload.update(overrides)
    return payload


def sbom_payload(**overrides):
    payload = {
        "transport": "sbom", "collected_at": RECENT, "document": "SBOM-18291",
        "artifact": "payments-api-4.2.1.jar", "tool": "syft-1.18",
        "components": [
            {"purl": f"{OPENSSL}@3.0.13", "name": "openssl", "version": "3.0.13",
             "component_type": "library", "crypto_bearing": True, "product": "OpenSSL 3.x"},
            {"purl": f"{SDK}@2.4.0", "name": "payments-sdk", "version": "2.4.0",
             "direct": True, "depends_on": [HTTP]},
            {"purl": f"{HTTP}@1.2.0", "name": "http-core", "version": "1.2.0",
             "depends_on": [OPENSSL]},
            {"name": "left-pad", "version": "^1.3.0"},
            {"name": "mystery"},
        ],
    }
    payload.update(overrides)
    return payload


def cmdb_payload(**overrides):
    payload = {
        "transport": "cmdb", "collected_at": RECENT, "source": "service-registry",
        "applications": [
            {"id": "APP-9281", "name": APP, "system": "Payments System",
             "owner": "payments-team", "criticality": "TIER-1"},
            {"name": "Unregistered Thing", "system": "Payments System"},
        ],
    }
    payload.update(overrides)
    return payload


def host_payload(**overrides):
    payload = {
        "transport": "host", "collected_at": RECENT, "host": "srv-lb-01",
        "os": "Ubuntu 22.04", "type": "PHYSICAL_SERVER",
        "packages": [{"name": "openssl", "version": "3.0.13", "crypto": True},
                     {"name": "openssh", "version": "8.7p1"}],
    }
    payload.update(overrides)
    return payload


ALL = [cmdb_payload(), git_payload(), ci_payload(), registry_payload(), kubernetes_payload(),
       probe_payload(), scan_payload(), sbom_payload(), host_payload()]


def collected():
    return sc.collect_all(ALL, as_of=NOW)


def assembled():
    return sc.assemble(*collected(), as_of=NOW, estate_id="live")


# --------------------------------------------------------------------------- #
# 1. The registry of transports, and the ceiling each may claim
# --------------------------------------------------------------------------- #
def test_every_transport_has_a_collector():
    registry = sc.collectors()
    assert set(registry) == set(sc.TRANSPORTS)
    assert all(callable(handler) for handler in registry.values())


def test_only_the_probe_may_claim_observed():
    assert sc.PROBE_TRANSPORTS == frozenset({"process"})
    for transport in sc.TRANSPORTS:
        result = sc.collectors()[transport]({}, collected_at=RECENT)
        if transport == "process":
            assert result["class"] == tb.OBSERVED, transport
        else:
            assert result["class"] != tb.OBSERVED, transport


def test_a_collector_cannot_be_built_for_a_transport_that_does_not_exist():
    with pytest.raises(sc.Refused) as refused:
        sc._Collector("spreadsheet")
    assert refused.value.code == "UNKNOWN_TRANSPORT"


# --------------------------------------------------------------------------- #
# 2. git — a commit is a sha, never a branch name
# --------------------------------------------------------------------------- #
def test_a_commit_is_identified_by_its_sha():
    result = sc.from_git(git_payload())
    assert [row["sha"] for row in result["rows"]["commits"]] == [SHA]
    assert result["rows"]["repositories"][0]["name"] == REPO


def test_a_branch_name_is_refused_as_an_identity():
    result = sc.from_git(git_payload())
    codes = {(row["code"], row["subject"]) for row in result["refusals"]}
    assert ("MUTABLE_IDENTITY", "main") in codes
    # the branch is recorded on the commit as an attribute, never as its identity
    assert [row["sha"] for row in result["rows"]["commits"]] == [SHA]


# --------------------------------------------------------------------------- #
# 3. ci — a build names its commit; an artifact needs a digest
# --------------------------------------------------------------------------- #
def test_a_build_names_the_commit_it_was_built_from():
    result = sc.from_ci(ci_payload())
    build = result["rows"]["builds"][0]
    assert (build["name"], build["commit"]) == ("BUILD-18291", SHA)


def test_an_artifact_without_a_digest_is_refused_by_name():
    result = sc.from_ci(ci_payload())
    assert [row["name"] for row in result["rows"]["artifacts"]] == ["payments-api-4.2.1.jar"]
    assert [(row["code"], row["subject"]) for row in result["refusals"]] == \
        [("ARTIFACT_WITHOUT_DIGEST", "payments-api.jar")]


# --------------------------------------------------------------------------- #
# 4. registry — the digest is the identity, the tag is recorded beside it
# --------------------------------------------------------------------------- #
def test_the_digest_is_the_image_identity_and_the_tag_is_beside_it():
    result = sc.from_registry(registry_payload())
    image = result["rows"]["images"][0]
    assert image["name"] == "payments-api:4.2.1"
    assert image["digest"] == DIGEST_IMAGE
    assert image["tag"] == "4.2.1"
    assert image["evidence_ref"] == f"oci:payments-api@{DIGEST_IMAGE}"


def test_a_moving_tag_is_not_an_identity():
    result = sc.from_registry({"image": {"repository": "payments-api", "tag": "latest"}})
    assert result["rows"] == {}
    assert [row["code"] for row in result["refusals"]] == ["IMAGE_WITHOUT_DIGEST"]


def test_the_layers_are_collected_with_the_image():
    result = sc.from_registry(registry_payload())
    assert [row["digest"] for row in result["rows"]["layers"]] == [LAYER]


# --------------------------------------------------------------------------- #
# 5. kubernetes — metadata, and it stops at the pod
# --------------------------------------------------------------------------- #
def test_a_deployment_without_an_image_is_refused():
    result = sc.from_kubernetes(kubernetes_payload())
    assert [(row["code"], row["subject"]) for row in result["refusals"]] == \
        [("DEPLOYMENT_WITHOUT_IMAGE", "ghost-deploy")]


def test_a_pod_names_its_node_and_the_host_behind_it():
    result = sc.from_kubernetes(kubernetes_payload())
    pod = result["rows"]["deployments"][0]["pods"][0]
    assert (pod["node"], pod["host"]) == ("node-03", "srv-k8s-03")
    # the host is carried by the pod, not emitted as a second host row
    assert "hosts" not in result["rows"]


def test_deployment_metadata_is_not_an_observation():
    result = sc.from_kubernetes(kubernetes_payload())
    assert result["class"] != tb.OBSERVED
    assert result["basis"] == "deployment-metadata"


# --------------------------------------------------------------------------- #
# 6. the probe — the one transport that saw the process
# --------------------------------------------------------------------------- #
def test_a_traced_operation_is_recorded_with_its_algorithm():
    result = sc.from_process_probe(probe_payload())
    operations = {(row["algorithm"], row["operation"]) for row in result["rows"]["crypto"]}
    assert operations == {("RSA", "SIGN"), ("AES", "ENCRYPT")}


def test_an_operation_with_no_algorithm_is_refused():
    result = sc.from_process_probe(probe_payload())
    assert [row["code"] for row in result["refusals"]] == ["OPERATION_WITHOUT_ALGORITHM"]


def test_the_probe_evidence_ref_names_the_host_and_pid():
    result = sc.from_process_probe(probe_payload())
    assert result["rows"]["crypto"][0]["evidence_ref"].startswith("probe:srv-k8s-03:1821:")


# --------------------------------------------------------------------------- #
# 7. the SBOM — components, dependencies, and a version that must be exact
# --------------------------------------------------------------------------- #
def test_a_component_is_keyed_without_its_version():
    result = sc.from_sbom(sbom_payload())
    coordinates = [row["coordinate"] for row in result["rows"]["software"]]
    assert OPENSSL in coordinates
    assert f"{OPENSSL}@3.0.13" not in coordinates


def test_a_range_is_not_a_version_and_is_refused():
    result = sc.from_sbom(sbom_payload())
    refused = {(row["code"], row["subject"]) for row in result["refusals"]}
    assert ("UNPINNED_VERSION", "left-pad") in refused


def test_a_component_with_no_version_at_all_is_refused():
    result = sc.from_sbom(sbom_payload())
    assert ("UNPINNED_VERSION", "mystery") in \
        {(row["code"], row["subject"]) for row in result["refusals"]}


def test_a_dependency_edge_names_both_ends():
    result = sc.from_sbom(sbom_payload())
    edges = {(row["source"], row["target"]) for row in result["rows"]["dependencies"]}
    assert (SDK, HTTP) in edges and (HTTP, OPENSSL) in edges


# --------------------------------------------------------------------------- #
# 8. the CMDB and the agent's inventory
# --------------------------------------------------------------------------- #
def test_the_cmdb_is_what_registers_an_application():
    result = sc.from_cmdb(cmdb_payload())
    assert [row["name"] for row in result["rows"]["applications"]] == \
        [APP, "Unregistered Thing"]
    assert result["class"] == tb.IMPORTED


def test_an_agent_inventory_is_a_filesystem_fact_on_a_named_host():
    result = sc.from_host_inventory(host_payload())
    assert result["basis"] == "agent-inventory"
    assert result["rows"]["hosts"][0]["name"] == "srv-lb-01"
    assert {row["coordinate"] for row in result["rows"]["software"]} == \
        {"pkg:generic/openssl", "pkg:generic/openssh"}


def test_no_collector_claims_a_class_stronger_than_its_transport():
    ceiling = {transport: sc._class_of(transport) for transport in sc.TRANSPORTS}
    for result in collected():
        transport = result["transport"]
        claimed = tb.CONFIDENCE[result["class"]]
        assert claimed <= tb.CONFIDENCE[ceiling[transport]], transport
        # an SBOM is a document: it may never be reported as something that was observed
        if transport == "sbom":
            assert result["class"] == tb.IMPORTED


def test_the_inventory_carries_each_rows_own_basis():
    built = sc.assemble(*collected(), as_of=NOW)
    bases = {row.get("basis") for row in built["supply"]["estate"]["claims"]}
    assert {"agent-inventory", "sbom-import", "process-trace"} <= bases


# --------------------------------------------------------------------------- #
# 9. merging — one component, several observations, no winner
# --------------------------------------------------------------------------- #
def test_two_versions_of_one_component_are_merged_not_duplicated():
    inventory = sc.collect(*collected(), as_of=NOW)["inventory"]
    rows = [row for row in inventory["software"] if row["coordinate"] == OPENSSL]
    assert len(rows) == 1
    sources = {(entry["source"], entry["value"]) for entry in rows[0]["version_sources"]}
    assert ("sbom", "3.0.13") in sources
    assert ("process-map", "3.0.11") in sources


def test_the_declared_version_is_the_one_carried_forward():
    inventory = sc.collect(*collected(), as_of=NOW)["inventory"]
    row = next(row for row in inventory["software"] if row["coordinate"] == OPENSSL)
    # the SBOM declares 3.0.13 and a probe saw 3.0.11 loaded; the row carries the declaration
    # and the probe's version stays in `version_sources`, which is where the conflict lives
    assert row["version"] == "3.0.13"


def test_a_disagreeing_digest_is_a_finding_not_an_overwrite():
    first = sc.from_registry(registry_payload())
    second = sc.from_registry(registry_payload(
        image={"repository": "payments-api", "tag": "4.2.1", "digest": DIGEST_OTHER}))
    merged = sc.collect(first, second, as_of=NOW)
    assert [row["code"] for row in merged["conflicts"]] == ["COLLECTOR_DISAGREEMENT"]
    conflict = merged["conflicts"][0]
    assert (conflict["kept"], conflict["reported"]) == (DIGEST_IMAGE, DIGEST_OTHER)
    # whichever arrived first is kept, and neither is dropped from the record
    assert len(merged["inventory"]["images"]) == 1


def test_two_agreeing_reads_of_one_asset_keep_both_facts():
    registry = sc.from_registry(registry_payload())
    scan = sc.from_image_scan(scan_payload())
    merged = sc.collect(registry, scan, as_of=NOW)
    assert merged["conflicts"] == []
    image = merged["inventory"]["images"][0]
    assert image["digest"] == DIGEST_IMAGE
    assert "layer:aa11bb22cc33" in image.get("layers", [])   # the registry's fact survived
    assert OPENSSL in image.get("installed", [])             # so did the scanner's


def test_an_unknown_transport_is_refused_by_name():
    results = sc.collect_all([{"transport": "spreadsheet", "collected_at": RECENT}], as_of=NOW)
    assert results[0]["rows"] == {}
    assert results[0]["refusals"][0]["code"] == "UNKNOWN_TRANSPORT"


# --------------------------------------------------------------------------- #
# 10. freshness
# --------------------------------------------------------------------------- #
def test_a_fresh_read_is_live():
    fresh = sc.freshness(sc.from_git(git_payload()), as_of=NOW)
    assert fresh["stale"] is False and fresh["age_hours"] == 2.0


def test_a_stale_read_is_imported_and_labelled():
    result = sc.from_git(git_payload(collected_at=STALE), collected_at=STALE)
    report = sc.freshness(result, as_of=NOW)
    assert report["stale"] is True
    merged = sc.collect(result, as_of=NOW)
    assert merged["counts"]["stale"] == 1
    assert merged["inventory"]["commits"], "a stale row is still a row"


def test_a_read_with_no_timestamp_cannot_be_called_live():
    report = sc.freshness({"transport": "git"}, as_of=NOW)
    assert report["stale"] is True and report["age_hours"] is None


# --------------------------------------------------------------------------- #
# 11. payloads → inventory → estate → chain
# --------------------------------------------------------------------------- #
def test_every_level_of_the_chain_is_populated():
    levels = assembled()["levels"]
    for name, count in levels.items():
        assert count > 0, name


def test_the_chain_reaches_from_a_business_system_to_an_algorithm():
    built = assembled()
    bom = built["bom"]
    owners = sd.component_owners(bom, query=OPENSSL)
    assert owners["applications"] == [APP]
    chain = sd.supply_chain(bom, query=APP)
    assert chain["down"]["component"] or chain["down"]["process"]


def test_the_component_is_installed_and_loaded_but_the_two_stay_apart():
    built = assembled()
    states = sd.component_states(built["bom"], query=OPENSSL)
    assert {"INSTALLED", "LOADED"} <= set(states["present"])


def test_the_transitive_path_is_printed():
    tree = sd.dependency_tree(assembled()["bom"], query=APP)
    transitive = [row for row in tree["transitive"]
                  if row["component"] == OPENSSL and len(row["path"]) == 3]
    assert transitive, tree["statement"]


def test_a_refused_row_never_becomes_an_asset():
    built = assembled()
    names = {row["name"] for row in built["bom"]["assets"]}
    for absent in ("payments-api.jar", "left-pad", "mystery", "ghost-deploy"):
        assert absent not in names
    refusal_subjects = {row["subject"] for row in built["collected"]["refusals"]}
    assert {"payments-api.jar", "left-pad", "mystery", "ghost-deploy"} <= refusal_subjects


def test_the_assembly_states_what_it_built():
    built = assembled()
    assert built["schema"] == sc.SCHEMA
    assert "asset(s)" in built["statement"] and "claim(s)" in built["statement"]
    assert built["bom"]["assets"] and built["bom"]["claims"]


def test_a_fingerprint_names_the_payload_that_was_read():
    assert sc.fingerprint(git_payload()) == sc.fingerprint(git_payload())
    assert sc.fingerprint(git_payload()) != sc.fingerprint(ci_payload())
