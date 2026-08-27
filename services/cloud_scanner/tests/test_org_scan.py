"""Org-level enumeration, fan-out pool and org target tests."""

from __future__ import annotations



from cloud_scanner.core.reliability import ScanTelemetry
from cloud_scanner.estate import is_cloud_target, is_org_target, org_provider, parse_cloud_target, should_run_cloud_job
from cloud_scanner.org.enumerators import enumerate_aws_org, enumerate_gcp_projects, enumerate_org
from cloud_scanner.org.pool import TokenBucketLimiter, rollup_org, scan_accounts_parallel, worst_status


# --------------------------------------------------------------------------- #
# fake org clients
# --------------------------------------------------------------------------- #


class FakeOrgClient:
    """boto3-style organizations client with two pages + a suspended account."""

    def __init__(self):
        self.calls = 0

    def list_accounts(self, **kwargs):
        self.calls += 1
        if kwargs.get("NextToken") == "t1":
            return {
                "Accounts": [
                    {"Id": "222233334444", "Name": "data-platform", "Email": "ops@data.example", "Status": "ACTIVE"},
                    {"Id": "999900001111", "Name": "closed", "Email": "x@x", "Status": "SUSPENDED"},
                ]
            }
        return {
            "Accounts": [{"Id": "111122223333", "Name": "prod", "Email": "ops@prod.example", "Status": "ACTIVE"}],
            "NextToken": "t1",
        }


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, name):
        return self._client


class FakeCrm:
    """googleapiclient-style cloudresourcemanager service."""

    def __init__(self, pages):
        self._pages = pages
        self.filters_seen = []

    def projects(self):
        return self

    def list(self, **kwargs):
        self.filters_seen.append(kwargs.get("filter"))
        token = kwargs.get("pageToken")
        page = self._pages[1] if token else self._pages[0]
        class _Req:
            def __init__(self, payload):
                self.payload = payload

            def execute(self):
                return self.payload

        return _Req(page)


# --------------------------------------------------------------------------- #
# enumerators
# --------------------------------------------------------------------------- #


def test_enumerate_aws_org_walks_pages_skips_suspended_builds_role_arns():
    discovery = enumerate_aws_org(session=FakeSession(FakeOrgClient()), role_name="CryptoScanCrossAccountRole")
    assert discovery["provider"] == "aws"
    assert [a["account_id"] for a in discovery["accounts"]] == ["111122223333", "222233334444"]
    assert discovery["accounts"][0]["role_arn"] == "arn:aws:iam::111122223333:role/CryptoScanCrossAccountRole"
    assert discovery["truncated"] is False
    assert discovery["errors"] == []


def test_enumerate_aws_org_records_cap_truncation():
    discovery = enumerate_aws_org(session=FakeSession(FakeOrgClient()), max_accounts=1)
    assert len(discovery["accounts"]) == 1
    assert discovery["truncated"] is True


def test_enumerate_aws_org_reports_errors_not_empty_success():
    class Boom:
        def client(self, name):
            raise PermissionError("not a delegated admin")

    telemetry = ScanTelemetry()
    discovery = enumerate_aws_org(session=Boom(), telemetry=telemetry)
    assert discovery["accounts"] == []
    assert discovery["errors"]
    assert telemetry.status() == "FAILED"


def test_enumerate_gcp_projects_folder_filter_and_pagination():
    pages = [
        {"projects": [{"projectId": "payments-prod", "name": "Payments", "lifecycleState": "ACTIVE"}], "nextPageToken": "p2"},
        {"projects": [{"projectId": "risk-dev", "name": "Risk", "lifecycleState": "ACTIVE"}]},
    ]
    client = FakeCrm(pages)
    discovery = enumerate_gcp_projects(client=client, folder="1234567890")
    assert [a["account_id"] for a in discovery["accounts"]] == ["payments-prod", "risk-dev"]
    assert "parent.id:1234567890" in client.filters_seen[0]
    assert "lifecycleState:ACTIVE" in client.filters_seen[0]


def test_enumerate_org_dispatch_and_unknown_provider():
    assert enumerate_org("AWS", session=FakeSession(FakeOrgClient()))["provider"] == "aws"
    assert enumerate_org("aws-org", session=FakeSession(FakeOrgClient()))["accounts"]
    assert enumerate_org("digitalocean")["errors"]


def test_enumerate_aws_org_missing_boto3_fail_open_reported(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_boto3(name, *a, **k):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_boto3)
    telemetry = ScanTelemetry()
    discovery = enumerate_aws_org(telemetry=telemetry)
    assert discovery["accounts"] == [] and discovery["errors"]


# --------------------------------------------------------------------------- #
# rate limiter + pool
# --------------------------------------------------------------------------- #


def test_token_bucket_blocks_and_refills():
    now = {"t": 0.0}
    sleeps = []

    def clock():
        return now["t"]

    def sleep(seconds):
        sleeps.append(seconds)
        now["t"] += seconds

    limiter = TokenBucketLimiter(rate_per_second=1.0, burst=2, clock=clock, sleep=sleep)
    assert limiter.acquire() == 0.0
    assert limiter.acquire() == 0.0  # burst consumed
    waited = limiter.acquire()  # must wait ~1s for one token
    assert waited > 0.5
    assert sleeps


def test_scan_accounts_parallel_pool_and_rollup(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_CLOUD_FANOUT_WORKERS", "4")
    monkeypatch.delenv("CRYPTOSCAN_CLOUD_ORG_RATE", raising=False)

    def scan_account(account):
        if account["account_id"] == "bad":
            raise PermissionError("assume-role denied")
        return {
            "resources": 2,
            "findings": [{"algorithm": "AES", "metadata": {"cloud_account": account["account_id"]}}],
            "live_scan": {"status": "OK", "resources_scanned": 2, "errors": []},
        }

    accounts = [{"account_id": "a1"}, {"account_id": "a2"}, {"account_id": "bad"}]
    out = scan_accounts_parallel(scan_account, accounts)
    rollup = out["rollup"]
    assert rollup["accounts_total"] == 3
    assert rollup["accounts_scanned"] == 2
    assert rollup["accounts_failed"] == 1
    assert rollup["resources_scanned"] == 4
    assert rollup["status"] == "PARTIAL"
    failed = next(r for r in out["results"] if not r["ok"])
    assert failed["error"].startswith("PermissionError")


def test_rollup_all_failed_is_failed():
    rows = [
        {"account": "a", "ok": False, "live_scan": {"errors": [{"provider": "AWS", "error": "x"}]}},
        {"account": "b", "ok": False, "live_scan": {}},
    ]
    rollup = rollup_org(rows)
    assert rollup["status"] == "FAILED"
    assert rollup["accounts_failed"] == 2


def test_worst_status_precedence():
    assert worst_status(["OK", "PARTIAL", "FAILED"]) == "FAILED"
    assert worst_status(["OK", "PARTIAL"]) == "PARTIAL"
    assert worst_status(["OK"]) == "OK"
    assert worst_status([]) == "SKIPPED"


# --------------------------------------------------------------------------- #
# org targets
# --------------------------------------------------------------------------- #


def test_org_targets_parse_and_route():
    assert is_org_target("cloud://aws-org/111122223333")
    assert is_org_target("azure-org://tenant-abc")
    assert not is_org_target("cloud://aws/111122223333")
    assert not is_org_target("https://git/repo.git")
    assert org_provider("cloud://gcp-org/1234567890") == "gcp-org"
    assert org_provider("cloud://aws/1") is None
    assert parse_cloud_target("cloud://aws-org/111122223333") == ("aws-org", "111122223333")
    # org targets are cloud targets everywhere (jobs, estate planning)
    assert is_cloud_target("cloud://azure-org/tenant")
    job = {"job_type": "CLOUD", "target_repo": "cloud://aws-org/111122223333"}
    assert should_run_cloud_job(job)
