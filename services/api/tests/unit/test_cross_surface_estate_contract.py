"""Actual authenticated GraphQL/export/SSE metadata estate checks."""

from datetime import datetime, timezone
import pytest
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.models.evidence_record import EvidenceRecord
from test_software_supply_chain_api import banks as banks


@pytest.fixture
def estate(banks):
    clients, db, _ = banks
    rows = {}
    for who, owner in [("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)]:
        scan = Scan(
            tenant_id=owner, scan_start=datetime.now(timezone.utc), target_location="private-" + who, status="COMPLETED"
        )
        job = ScanJob(tenant_id=owner, target_repo="private-" + who, triggered_by=who, status="FAILED")
        db.add_all([scan, job])
        db.flush()
        db.add(
            EvidenceRecord(
                tenant_id=owner,
                scan_id=scan.id,
                content_hash="a" * 64,
                chain_hash="b" * 64,
                chain_position=1,
                algorithm="AES",
                file_path="private-" + who,
                line_number=1,
                finding_data={},
            )
        )
        rows[who] = (scan, job)
    db.commit()
    return clients, db, rows


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_graphql_id_and_list_are_same_estate(estate, who):
    clients, _, rows = estate
    for target, (_, job) in rows.items():
        result = clients[who].post(
            "/api/v1/graphql",
            json={"query": '{ binaryJob(id:"' + job.id + '") { jobId target } binaryJobs(limit:1) { target } }'},
        )
        assert result.status_code == 200, result.text
        data = result.json()["data"]
        assert (data["binaryJob"] is not None) == (target == who)
        assert data["binaryJobs"] == [{"target": "private-" + who}]


@pytest.mark.parametrize("suffix", ["export", "export.csv", "verification-script", "cbom", "verify"])
@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_scan_exports_never_read_foreign_or_platform_estate(estate, suffix, who):
    clients, _, rows = estate
    for target, (scan, _) in rows.items():
        if target == who:
            continue
        response = clients[who].get(f"/api/v1/scans/{scan.id}/{suffix}")
        assert response.status_code == 404, response.text
        assert "private-" not in response.text


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_estate_csv_filters_before_counting(estate, who):
    clients, _, _ = estate
    response = clients[who].get("/api/v1/export/findings.csv?limit=1")
    assert response.status_code == 200, response.text
    assert response.headers["X-Total-Matching"] == "1"
    assert "private-" + who in response.text


def test_multi_estate_aggregate_archive_is_fail_closed(estate):
    clients, _, _ = estate
    assert clients["platform_admin"].get("/api/v1/audit-export/pack").status_code == 409
    assert clients["reader_a"].get("/api/v1/audit-export/pack").status_code in (403, 409)


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_own_scan_export_and_foreign_evidence_cannot_poison_a_chain(estate, who):
    clients, db, rows = estate
    scan, _ = rows[who]
    other = "b" if scan.tenant_id != "b" else "a"
    db.add(
        EvidenceRecord(
            tenant_id=other,
            scan_id=scan.id,
            content_hash="c" * 64,
            chain_hash="d" * 64,
            chain_position=2,
            algorithm="AES",
            file_path="POISON-FOREIGN",
            line_number=2,
            finding_data={},
        )
    )
    db.commit()
    for suffix in ("export", "export.csv", "verification-script", "cbom", "verify"):
        response = clients[who].get(f"/api/v1/scans/{scan.id}/{suffix}")
        assert response.status_code == 200, response.text
        assert "POISON-FOREIGN" not in response.text
    payload = clients[who].get(f"/api/v1/scans/{scan.id}/export").json()
    assert len(payload["findings"]) == 1


@pytest.mark.parametrize("middleware", [False, True])
@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_graphql_get_batch_runtime_summary_and_selected_platform(estate, middleware, who):
    from api.main import create_app
    from api.middleware.tenant_scope import TenantScopeMiddleware
    from fastapi.testclient import TestClient
    from db.models.runtime_finding import RuntimeFinding

    clients, db, rows = estate
    for name, (_, job) in rows.items():
        job.progress = {"scan_options": {"batch_id": "shared-batch"}}
        db.add(
            RuntimeFinding(
                tenant_id=job.tenant_id,
                scanner_id="scanner",
                dedup_key=name,
                hostname="host-" + name,
                cipher_suite="suite-" + name,
                algorithm="algo-" + name,
                weak_tls=True,
                observation_count=10,
            )
        )
    db.commit()
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    with TestClient(app) as client:
        client.cookies.update(clients[who].cookies)
        query = '{ binaryBatch(batchId:"shared-batch") { jobs files { target } totals { findings } } runtimeFindings(limit:1) { items { hostname } returned summary } }'
        response = client.get("/api/v1/graphql", params={"query": query})
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["binaryBatch"]["jobs"] == 1
        assert data["binaryBatch"]["files"] == [{"target": "private-" + who}]
        assert data["runtimeFindings"]["items"] == [{"hostname": "host-" + who}]
        summary = data["runtimeFindings"]["summary"]
        assert summary["total_findings"] == 1 and summary["weak_findings"] == 1 and summary["hosts"] == 1
        assert summary["top_cipher_suites"] == [{"cipher_suite": "suite-" + who, "observations": 10}]
        if who == "platform_admin":
            selected = client.get("/api/v1/graphql", params={"query": query}, headers={"X-Tenant-ID": "a"}).json()[
                "data"
            ]
            assert selected["binaryBatch"]["files"] == [{"target": "private-bank_a"}]
            scan_a = rows["bank_a"][0]
            assert client.get(f"/api/v1/scans/{scan_a.id}/export", headers={"X-Tenant-ID": "a"}).status_code == 200


@pytest.mark.parametrize("suffix", ["exit-report", "engagement-archive", "pack", "access-review", "access-reviews"])
def test_every_mixed_source_audit_read_is_refused(estate, suffix):
    clients, _, _ = estate
    assert clients["platform_admin"].get("/api/v1/audit-export/" + suffix).status_code == 409
    assert (
        clients["platform_admin"].get("/api/v1/audit-export/" + suffix, headers={"X-Tenant-ID": "a"}).status_code == 403
    )
    assert clients["reader_a"].get("/api/v1/audit-export/" + suffix).status_code == 403


def test_multi_estate_access_review_cannot_be_attested(estate):
    clients, _, _ = estate
    response = clients["platform_admin"].post(
        "/api/v1/audit-export/access-reviews", json={"period": "2026-Q4", "report_hash": "a" * 64}
    )
    assert response.status_code == 409


def test_foreign_and_missing_scan_exports_are_indistinguishable(estate):
    clients, _, rows = estate
    for suffix in ("export", "export.csv", "verification-script", "cbom", "verify"):
        missing = clients["bank_a"].get(f"/api/v1/scans/missing/{suffix}")
        foreign = clients["bank_a"].get(f"/api/v1/scans/{rows['bank_b'][0].id}/{suffix}")
        assert missing.status_code == foreign.status_code == 404
        # Trace IDs identify individual requests, not whether a scan exists.
        # Compare every externally meaningful error field without demanding
        # that two independent requests share a request identifier.
        assert {k: v for k, v in missing.json().items() if k != "request_id"} == \
            {k: v for k, v in foreign.json().items() if k != "request_id"}


def test_deleting_tenant_catalog_does_not_declassify_orphaned_history(estate):
    from db.models.tenant import Tenant

    clients, db, _ = estate
    db.query(Tenant).delete()
    db.commit()
    for suffix in ("pack", "engagement-archive", "access-review", "access-reviews", "exit-report"):
        assert clients["platform_admin"].get("/api/v1/audit-export/" + suffix).status_code == 409
    assert clients["platform_admin"].get("/api/v1/security/posture/stream").status_code == 409
