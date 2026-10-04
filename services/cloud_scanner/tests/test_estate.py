from types import SimpleNamespace

from cloud_scanner.estate import (
    is_cloud_target,
    job_type_for_target,
    parse_cloud_target,
    plan_campaign,
    row_from_finding,
    scan_target_for_finding,
    should_run_cloud_job,
    system_name_for_finding,
)


def test_classifies_cloud_and_git_targets():
    assert is_cloud_target("cloud://aws/111122223333")
    assert is_cloud_target("aws://kms/alias/pay")
    assert is_cloud_target("azure://vaults/core")
    assert not is_cloud_target("https://github.com/bank/pay.git")
    assert not is_cloud_target("local://test-fixture/polyglot-app")
    assert job_type_for_target("cloud://gcp/proj") == "CLOUD"
    assert job_type_for_target("https://git/bank/pay.git") == "SYSTEM"


def test_parse_cloud_target_extracts_account():
    assert parse_cloud_target("cloud://aws/111122223333") == ("aws", "111122223333")
    assert parse_cloud_target("azure://sub-1") == ("azure", "sub-1")
    assert parse_cloud_target("cloud://gcp") == ("gcp", None)


def test_campaign_groups_million_kms_keys_to_one_job():
    systems = [
        SimpleNamespace(
            id=f"s{i}",
            name=f"aws:kms:key-{i}",
            scan_target=f"cloud://aws/kms/key-{i}",
            cloud_provider="AWS",
            cloud_account="111122223333",
            scan_branch="main",
        )
        for i in range(1000)
    ]
    systems.append(
        SimpleNamespace(
            id="git1",
            name="payments-api",
            scan_target="https://git/bank/pay.git",
            cloud_provider=None,
            cloud_account=None,
            scan_branch="main",
        )
    )
    planned = plan_campaign(systems, limit=25)
    cloud = [item for item in planned if item["job_type"] == "CLOUD"]
    git = [item for item in planned if item["job_type"] != "CLOUD"]
    assert len(cloud) == 1
    assert cloud[0]["members"] == 1000
    assert cloud[0]["target"] == "cloud://aws/111122223333"
    assert len(git) == 1
    assert not should_run_cloud_job({"job_type": "SYSTEM", "target_repo": "https://git/x.git"})
    assert should_run_cloud_job({"job_type": "COVERAGE", "target_repo": "cloud://aws/1"})


def test_finding_maps_to_system_row():
    finding = {
        "algorithm": "AES",
        "file_path": "aws://kms/alias/payments",
        "line_number": 1,
        "metadata": {"cloud_provider": "AWS", "resource": "alias/payments"},
    }
    assert system_name_for_finding(finding) == "aws:alias/payments"
    assert scan_target_for_finding(finding) == "cloud://kms/alias/payments"
    row = row_from_finding(finding, account="111122223333")
    assert row["cloud_provider"] == "AWS"
    assert row["cloud_account"] == "111122223333"
    assert row["algorithm"] == "AES"
