#!/usr/bin/env python3
"""Opt-in real browser → existing console → API → migrated disposable PG.

Synthetic fixtures only. Requires the same external tooling/private principal
config as production_cbom_e2e.py. Never run against an existing deployment.
"""
from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from _bootstrap import bootstrap
bootstrap()

from cbom.cyclonedx16 import validate_cyclonedx16
from cbom.generator import CbomGenerator
from db.models import CryptoAsset, System, SystemAsset
from db.models.user import AuditLog
from db.repositories.user_repository import verify_audit_chain
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:3003")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    url = make_url(config["database_url"])
    assert url.get_backend_name() == "postgresql" and (url.database or "").startswith("cryptoscan_e2e_")
    assert not url.host or url.host in {"localhost", "127.0.0.1"} or url.host.startswith("/home/user/")
    assert urlsplit(args.base_url).hostname in {"localhost", "127.0.0.1"}
    name = "Synthetic historical review " + uuid.uuid4().hex[:10]
    engine = create_engine(url)
    with Session(engine) as db:
        assert db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0107"
        system = System(tenant_id="e2e-a", name=name, coverage_status="CURRENT",
                        last_scanned_at=datetime.now(timezone.utc), scan_target="/synthetic/historical-only")
        asset = CryptoAsset(tenant_id="e2e-a", algorithm="ML-KEM-768", purpose="kem", key_size=1184,
                            file_path="declared/historical.conf", line_number=1, confidence="HIGH",
                            scanner_ids=["cbom-ingest"], extra={"scan_id":"cbom-ingest:historical"})
        db.add_all([system, asset]); db.flush()
        sid, aid = system.id, asset.id
        db.add(SystemAsset(tenant_id="e2e-a", system_id=sid, asset_id=aid)); db.commit()
    document = CbomGenerator().from_records([{
        "id":"synthetic-declared-kem", "algorithm":"ML-KEM-768", "purpose":"kem", "key_size":1184,
        "file_path":"declared/historical.conf", "line_number":1, "owner":"synthetic-declared-owner",
    }], name=name, spec_version="1.6")
    report = {"schema":"cryptoscan.historical-cbom-browser/1", "scope":"DISPOSABLE_SYNTHETIC_ESTATES",
              "bank_approved":False, "whole_product_production_qualified":False, "checks":[]}
    checks = report["checks"]
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True,
            args=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--use-angle=swiftshader"])
        report["browser"] = browser.version
        contexts, errors = [], []
        def login(username):
            context = browser.new_context(base_url=args.base_url, accept_downloads=True)
            contexts.append(context)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)[:300]))
            page.goto("/login")
            page.locator("#login-user").fill(username)
            page.locator("#login-pass").fill(config["password"])
            with page.expect_response(lambda r: r.url.endswith("/api/v1/auth/login") and r.request.method == "POST") as login_response:
                page.get_by_role("button", name=re.compile("^sign in$", re.I)).click()
            assert login_response.value.status == 200, f"Login HTTP {login_response.value.status}; respect normal rate limits, do not disable them"
            page.wait_for_url("**/command-center")
            page.goto("/cbom")
            expect(page.get_by_role("heading", name="Cryptographic Bill of Materials", exact=True)).to_be_visible()
            return context, page
        context, page = login(config.get("username_a", "e2e_bank_a"))
        assert page.request.get(f"/api/v1/cbom/system/{sid}").status == 409
        coverage = page.request.get("/api/v1/cbom/coverage").json()
        assert coverage["legacy_coverage_unproven"] >= 1
        checks += ["REAL_BROWSER_LOGIN", "HISTORICAL_EXPORT_BLOCKED", "LEGACY_COVERAGE_FLAGGED"]
        page.get_by_role("button", name="Review historical imports", exact=True).click()
        page.get_by_role("button", name="Review " + name, exact=True).click()
        expect(page.get_by_text(re.compile("None — first reimport"))).to_be_visible()
        expect(page.get_by_role("button", name="Reconcile historical declarations", exact=True)).to_be_disabled()
        checks.append("BROWSER_REQUIRES_REIMPORT")
        page.get_by_label("Import system name", exact=True).fill(name)
        page.get_by_label("CBOM JSON file", exact=True).set_input_files({"name":"synthetic-original.json","mimeType":"application/json","buffer":json.dumps(document).encode()})
        with page.expect_response(lambda r: r.url.endswith("/api/v1/cbom/ingest") and r.request.method == "POST") as pending:
            page.get_by_role("button", name="Import metadata", exact=True).click()
        assert pending.value.status == 200
        imported = pending.value.json()
        assert imported["system"]["id"] == sid
        checks.append("BROWSER_NATIVE_FILE_REIMPORT")
        page.get_by_role("button", name="Review " + name, exact=True).click()
        expect(page.get_by_text(re.compile("Replacement document SHA-256: " + imported["document_sha256"]))).to_be_visible()
        snapshot = page.request.get(f"/api/v1/cbom/system/{sid}/legacy-imports").json()
        reader_context, reader_page = login(config.get("username_reader", "e2e_reader"))
        body = {"expected_snapshot_sha256":snapshot["snapshot_sha256"],
                "replacement_document_sha256":snapshot["replacement_document_sha256"],
                "reason":"Synthetic original declaration reviewed against replacement; no scanner proof asserted."}
        assert reader_page.request.post(f"/api/v1/cbom/system/{sid}/reconcile-legacy", data=body).status == 403
        _, foreign_page = login(config.get("username_b", "e2e_bank_b"))
        assert foreign_page.request.get(f"/api/v1/cbom/system/{sid}/legacy-imports").status == 404
        assert name not in foreign_page.request.get("/api/v1/cbom/legacy-imports").text()
        checks += ["READONLY_WRITE_403", "FOREIGN_REVIEW_404", "FOREIGN_LIST_ISOLATED"]
        page.get_by_label("Review rationale (no secrets)", exact=True).fill(body["reason"])
        page.get_by_role("region", name="Historical import review", exact=True).get_by_role("checkbox").check()
        with page.expect_response(lambda r: r.url.endswith("/reconcile-legacy") and r.request.method == "POST") as pending:
            page.get_by_role("button", name="Reconcile historical declarations", exact=True).click()
        assert pending.value.status == 200, pending.value.text()
        receipt = pending.value.json()
        expect(page.get_by_text(re.compile("Reconciliation committed. Audit receipt: " + receipt["audit_id"]))).to_be_visible()
        checks.append("BROWSER_RECONCILIATION_DURABLE_RECEIPT")
        if args.screenshot:
            page.get_by_role("region", name="Historical import review", exact=True).screenshot(path=str(args.screenshot))
        with page.expect_download() as pending:
            page.get_by_role("button", name="Export persisted metadata", exact=True).click()
        exported = json.loads(Path(pending.value.path()).read_bytes())
        assert validate_cyclonedx16(exported)["ok"]
        assert len(exported["components"]) == 1
        assert "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS" in json.dumps(exported)
        checks.append("BROWSER_AUTHENTICATED_NATIVE_EXPORT_AFTER_REVIEW")
        page.reload()
        assert page.request.get(f"/api/v1/cbom/system/{sid}/legacy-imports").json()["pending_assets"] == 0
        checks.append("BROWSER_RELOAD_RETAINS_RECONCILIATION")
        # Two real concurrent requests against one locked review: at most one
        # can commit. Re-create another isolated synthetic system for this case.
        with Session(engine) as db:
            race_system = System(tenant_id="e2e-a", name=name + " race", coverage_status="CURRENT")
            race_asset = CryptoAsset(tenant_id="e2e-a", algorithm="ML-KEM-768", purpose="kem", file_path="declared/historical.conf",
                                    line_number=1, confidence="HIGH", scanner_ids=["cbom-ingest"])
            db.add_all([race_system,race_asset]); db.flush()
            race_sid = race_system.id
            db.add(SystemAsset(tenant_id="e2e-a",system_id=race_sid,asset_id=race_asset.id)); db.commit()
        assert page.request.post("/api/v1/cbom/ingest", data={"bom":document,"system_name":name+" race"}).status == 200
        race = page.request.get(f"/api/v1/cbom/system/{race_sid}/legacy-imports").json()
        race_body = {**body,"expected_snapshot_sha256":race["snapshot_sha256"],"replacement_document_sha256":race["replacement_document_sha256"]}
        import httpx
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        barrier = Barrier(2)
        cookies = {c["name"]:c["value"] for c in context.cookies(args.base_url)}
        def request(_):
            with httpx.Client(base_url=args.base_url,cookies=cookies,timeout=40) as client:
                barrier.wait(timeout=10)
                return client.post(f"/api/v1/cbom/system/{race_sid}/reconcile-legacy", json=race_body).status_code
        with ThreadPoolExecutor(max_workers=2) as workers:
            statuses = list(workers.map(request,range(2)))
        assert sorted(statuses) == [200,409], statuses
        report["concurrent_statuses"] = statuses
        checks.append("CONCURRENT_RECONCILIATION_200_AND_STALE_409")
        with Session(engine) as db:
            old = db.get(CryptoAsset, aid)
            assert old.confidence == "HIGH" and old.extra["scan_id"] == "cbom-ingest:historical"
            assert old.extra["legacy_cbom_disposition"]["audit_id"] == receipt["audit_id"]
            assert db.execute(select(SystemAsset.id).where(SystemAsset.asset_id==aid)).first() is None
            audit = db.get(AuditLog, receipt["audit_id"])
            assert audit.action == "cbom.legacy_reconciled" and audit.actor == config.get("username_a","e2e_bank_a")
            raw = db.get(System, sid)
            assert raw.coverage_status == "CURRENT" and raw.last_scanned_at is not None
            verification = verify_audit_chain(db)
            assert verification["status"] == "OK", verification
            report["audit_chain"] = verification
        projected = page.request.get(f"/api/v1/systems/{sid}")
        assert projected.status == 200, projected.text()
        assert projected.json()["coverage_status"] == "NEVER_SCANNED"
        assert projected.json()["last_scanned_at"] is None
        checks += ["POSTGRES_ORIGINAL_FIELDS_RETAINED", "POSTGRES_AUDIT_LINKED", "POSTGRES_GLOBAL_CHAIN_VALID", "SYSTEM_API_PROJECTS_UNPROVEN_COVERAGE"]
        assert not errors, errors
        checks.append("NO_BROWSER_PAGE_ERRORS")
        report["system_id"],report["audit_id"] = sid,receipt["audit_id"]
        for context in contexts:
            context.close()
        browser.close()
    engine.dispose()
    report["status"]="PASS"
    args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"status":"PASS","checks":len(checks),"scope":report["scope"]}))


if __name__ == "__main__":
    main()
