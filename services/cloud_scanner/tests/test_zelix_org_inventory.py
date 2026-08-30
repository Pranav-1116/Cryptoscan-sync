"""ZELNX §1 organization hierarchy + §2 asset inventory."""

from __future__ import annotations

from cloud_scanner.enterprise.asset_inventory import (
    AssetInventoryBuilder,
    normalize_workload,
)
from cloud_scanner.enterprise.org_hierarchy import OrgHierarchyBuilder, default_region_rows
from cloud_scanner.enterprise.providers import fake_provider

from zelix_fixtures import (
    AWS_ACCOUNTS,
    AWS_ROWS,
    AZURE_ACCOUNTS,
    AZURE_ROWS,
    GCP_ACCOUNTS,
    GCP_ROWS,
    all_providers,
    _aws_regions,
)


# ------------------------------------------------------------------ §1 org


def test_org_hierarchy_builds_provider_roots():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    assert len(hierarchy.roots) == 3
    assert {root.provider for root in hierarchy.roots} == {"aws", "azure", "gcp"}
    assert hierarchy.account_count == 5  # 2 aws + 1 azure + 2 gcp


def test_org_hierarchy_account_org_path():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    aws = hierarchy.accounts_for("aws")
    assert len(aws) == 2
    assert aws[0].org_path == ["aws-organization", "Payments"]
    assert aws[0].name == "prod-core"


def test_org_hierarchy_regions_attached():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    aws = hierarchy.accounts_for("aws")[0]
    assert [region.name for region in aws.regions] == ["us-east-1", "eu-west-1"]
    assert aws.regions[0].zones == ["us-east-1a", "us-east-1b"]


def test_org_hierarchy_business_unit_nodes():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    root = hierarchy.roots[0]
    bu_nodes = [child for child in root.children if child.kind == "business_unit"]
    assert [node.name for node in bu_nodes] == ["Payments"]


def test_org_hierarchy_tree_compact():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    tree = hierarchy.tree()
    assert "aws" in tree and "Payments" in tree["aws"]
    assert "111122223333" in tree["aws"]["Payments"]


def test_org_hierarchy_records_errors_on_missing_enumerator():
    hierarchy = OrgHierarchyBuilder([{"provider": "aws"}]).discover()
    assert hierarchy.errors
    assert hierarchy.errors[0]["kind"] == "no_enumerator"


def test_org_hierarchy_records_enumerator_exception():
    def boom():
        raise RuntimeError("org api down")

    hierarchy = OrgHierarchyBuilder(
        [{"provider": "aws", "enumerate_accounts": boom}]).discover()
    assert hierarchy.errors
    assert "org api down" in hierarchy.errors[0]["detail"]


def test_org_hierarchy_truncation():
    def many():
        return {"accounts": [{"account_id": f"a{i}"} for i in range(10)],
                "truncated": False, "errors": []}

    hierarchy = OrgHierarchyBuilder(
        [{"provider": "aws", "enumerate_accounts": many}], max_accounts=3).discover()
    assert len(hierarchy.accounts) == 3
    assert hierarchy.truncated is True


def test_org_hierarchy_propagates_enumerator_truncation_flag():
    hierarchy = OrgHierarchyBuilder([{
        "provider": "aws",
        "enumerate_accounts": lambda: {"accounts": [], "truncated": True, "errors": []},
    }]).discover()
    assert hierarchy.truncated is True


def test_default_region_rows_shape():
    rows = default_region_rows("aws", ["us-east-1"])
    assert rows[0]["name"] == "us-east-1"
    assert rows[0]["zones"] == ["us-east-1a", "us-east-1b", "us-east-1c"]


def test_org_hierarchy_status_and_metadata():
    entries = [p.to_provider_entry() for p in all_providers()]
    hierarchy = OrgHierarchyBuilder(entries).discover()
    aws = hierarchy.accounts_for("aws")[0]
    assert aws.status == "ACTIVE"
    assert aws.metadata["partition"] == "public"
    assert aws.metadata["email"] == "core@example.com"


# ------------------------------------------------------------------ §2 assets


def test_asset_inventory_normalizes_workload_fields():
    workload = normalize_workload({
        "workload_id": "i-0001", "account": "111122223333", "region": "us-east-1",
        "zone": "us-east-1a", "environment": "prod", "network": "vpc-core",
        "application": "payments-api", "owner": "payments-team", "runtime": "java17",
        "os": "amazon-linux-2", "container": "img:1",
        "crypto_usage": ["TLS1.3"], "certificate_usage": ["cert-1"],
        "key_dependencies": ["kms-key-1"],
    }, provider="aws")
    assert workload.workload_id == "i-0001"
    assert workload.cloud_provider == "aws"
    assert workload.account == "111122223333"
    assert workload.region == "us-east-1"
    assert workload.zone == "us-east-1a"
    assert workload.environment == "prod"
    assert workload.network == "vpc-core"
    assert workload.application == "payments-api"
    assert workload.owner == "payments-team"
    assert workload.runtime == "java17"
    assert workload.os == "amazon-linux-2"
    assert workload.container == "img:1"
    assert workload.crypto_usage == ["TLS1.3"]
    assert workload.certificate_usage == ["cert-1"]
    assert workload.key_dependencies == ["kms-key-1"]


def test_asset_inventory_discovers_all_providers():
    entries = [p.to_provider_entry() for p in all_providers()]
    inventory = AssetInventoryBuilder(entries).discover()
    assert inventory.count() == 6  # 3 aws + 1 azure + 2 gcp
    assert inventory.count("aws") == 3
    assert inventory.count("azure") == 1
    assert inventory.count("gcp") == 2


def test_asset_inventory_summary():
    entries = [p.to_provider_entry() for p in all_providers()]
    inventory = AssetInventoryBuilder(entries).discover()
    summary = inventory.summary()
    assert summary["workloads"] == 6
    assert summary["by_provider"] == {"aws": 3, "azure": 1, "gcp": 2}


def test_asset_inventory_errors_on_missing_enumerator():
    inventory = AssetInventoryBuilder([{"provider": "aws"}]).discover()
    assert inventory.errors
    assert inventory.errors[0]["kind"] == "no_enumerator"


def test_asset_inventory_truncates_at_cap():
    def many():
        return [{"workload_id": f"w{i}"} for i in range(10)]

    inventory = AssetInventoryBuilder(
        [{"provider": "aws", "enumerate_workloads": many}], max_workloads=3).discover()
    assert inventory.count() == 3
    assert inventory.truncated is True


def test_asset_inventory_records_exceptions():
    def boom():
        raise RuntimeError("compute api down")

    inventory = AssetInventoryBuilder(
        [{"provider": "aws", "enumerate_workloads": boom}]).discover()
    assert inventory.errors
    assert "compute api down" in inventory.errors[0]["detail"]


def test_workload_evidence_block_present():
    workload = normalize_workload({"workload_id": "w1"}, provider="aws")
    payload = workload.to_dict()
    assert "evidence" in payload
    assert payload["evidence"]["normalization_version"] == "zelix-1.0"
