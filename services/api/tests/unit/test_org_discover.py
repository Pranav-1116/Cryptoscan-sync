"""/cloud/orgs endpoints: discovery, registration, enqueue."""

from __future__ import annotations

from fastapi import HTTPException

from api.routers.cloud import CloudOrgDiscoverRequest, discover_org, scan_org_endpoint


class _Account:
    def __init__(self, provider, identifier):
        self.cloud_provider = provider
        self.account_identifier = identifier


class _Intel:
    def __init__(self, existing=()):
        self._existing = {(a.cloud_provider, a.account_identifier) for a in existing}
        self.created = []

    def find_cloud_account(self, provider, identifier):
        from cloud_scanner.estate import parse_cloud_target  # noqa: F401

        key = (str(provider).upper(), identifier)
        return _Account(*key) if key in self._existing else None

    def create_cloud_account(self, **kwargs):
        self.created.append(kwargs)
        return _Account(kwargs["cloud_provider"], kwargs["account_identifier"])


class _Db:
    def commit(self):
        pass


class _Jobs:
    def create(self, **kwargs):
        return type("Job", (), {"job_id": "j-" + str(kwargs.get("repo_url"))})()

    def to_response(self, job):
        return {"job_id": job.job_id}


def _fake_enqueue(jobs, background_tasks, **kwargs):
    return {"job_id": "queued-" + kwargs["repo_url"]}


def test_discover_org_registers_and_enqueues(monkeypatch):
    import api.routers.cloud as cloud_router

    monkeypatch.setattr(
        "cloud_scanner.org.enumerators.enumerate_org",
        lambda provider, **kw: {
            "provider": provider,
            "accounts": [
                {"account_id": "111122223333", "name": "prod", "status": "ACTIVE", "role_arn": "arn:aws:iam::111122223333:role/CryptoScanCrossAccountRole"},
                {"account_id": "222233334444", "name": "dev", "status": "ACTIVE", "role_arn": "arn:aws:iam::222233334444:role/CryptoScanCrossAccountRole"},
            ],
            "truncated": False,
            "errors": [],
        },
    )
    monkeypatch.setattr("api.routers.trigger.enqueue_scan_job", _fake_enqueue)

    intel = _Intel(existing=[_Account("AWS", "222233334444")])
    monkeypatch.setattr(cloud_router, "IntelligenceRepository", lambda db: intel)

    body = CloudOrgDiscoverRequest(provider="AWS", role_name="CryptoScanCrossAccountRole")
    result = discover_org(body, background_tasks=[], user="admin", db=_Db(), jobs=_Jobs())

    assert result["discovered"] == 2
    assert result["registered"] == 1  # 222233334444 already existed
    assert result["already_registered"] == 1
    assert result["jobs_enqueued"] == 2
    assert intel.created[0]["account_identifier"] == "111122223333"
    assert intel.created[0]["role_arn"].endswith("CryptoScanCrossAccountRole")
    assert result["accounts"][0]["account_id"] == "111122223333"


def test_discover_org_bad_provider_rejected():
    try:
        discover_org(
            CloudOrgDiscoverRequest(provider="digitalocean"),
            background_tasks=[],
            user="admin",
            db=_Db(),
            jobs=_Jobs(),
        )
        raise AssertionError("must reject unknown providers")
    except HTTPException as exc:
        assert exc.status_code == 400


def test_discover_org_enumeration_failure_is_502(monkeypatch):
    monkeypatch.setattr(
        "cloud_scanner.org.enumerators.enumerate_org",
        lambda provider, **kw: {"provider": provider, "accounts": [], "truncated": False, "errors": ["AccessDenied"]},
    )
    try:
        discover_org(
            CloudOrgDiscoverRequest(provider="aws"),
            background_tasks=[],
            user="admin",
            db=_Db(),
            jobs=_Jobs(),
        )
        raise AssertionError("must surface enumeration failure")
    except HTTPException as exc:
        assert exc.status_code == 502


def test_scan_org_endpoint_builds_org_target(monkeypatch):
    monkeypatch.setattr("api.routers.trigger.enqueue_scan_job", _fake_enqueue)
    body = CloudOrgDiscoverRequest(provider="gcp", gcp_folder="987654321")
    result = scan_org_endpoint(body, background_tasks=[], user="admin", jobs=_Jobs())
    assert result["target"] == "cloud://gcp-org/987654321"
    assert result["queued"]["job_id"].startswith("queued-")
