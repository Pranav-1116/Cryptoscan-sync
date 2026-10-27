#!/usr/bin/env python3
"""Opt-in real Chromium → built console → API → migrated PostgreSQL check.

Disposable synthetic estates ONLY. No API mocks, dependency overrides, schema
bootstrap, production setting exemptions or production approval are supplied.
Servers and test-only users must already exist; see the companion evidence doc.
Requires optional playwright tooling and an operator-provided Chromium binary.
Credentials/storage state stay in external files and are never in the report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from _bootstrap import bootstrap

bootstrap()

from cbom.cyclonedx16 import validate_cyclonedx16
from cbom.generator import CbomGenerator
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def check_database(url, receipts):
    engine = create_engine(url)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0107"
            for key, receipt in receipts.items():
                system = db.execute(text("SELECT tenant_id, last_scan_id, last_scanned_at, coverage_status, extra FROM systems WHERE id=:id"),
                                    {"id": receipt["system"]["id"]}).mappings().one()
                assert system["tenant_id"] == {"a": "e2e-a", "b": "e2e-b"}[key]
                assert system["last_scan_id"] is None and system["last_scanned_at"] is None
                assert system["coverage_status"] != "CURRENT"
                assert system["extra"]["cbom_import"]["source"] == "ingest"
                audit_count = db.execute(text("SELECT count(*) FROM audit_log WHERE action='cbom.ingest' AND target_id=:id"),
                                         {"id":receipt["system"]["id"]}).scalar_one()
                assert audit_count >= 1
                assets = db.execute(text("SELECT a.* FROM crypto_assets a JOIN system_assets l ON l.asset_id=a.id WHERE l.system_id=:id"),
                                    {"id": receipt["system"]["id"]}).mappings().all()
                assert len(assets) == receipt["imported"] == 2
                assert all(asset["tenant_id"] == system["tenant_id"] and asset["confidence"] == "LOW" for asset in assets)
                assert all(asset["extra"]["cbom_import"]["document_sha256"] == receipt["document_sha256"] for asset in assets)
                kem = next(asset for asset in assets if asset["algorithm"] == "ML-KEM-768")
                assert kem["key_size"] == 1184
                assert kem["extra"]["cbom_import"]["parameter_set_identifier"] == "768"
                assert kem["extra"]["cbom_import"]["business_contexts"][0]["owner"] == "synthetic-declared-owner"
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="External private JSON: database_url, password, optional username_a/username_b/username_reader")
    parser.add_argument("--base-url", default="http://127.0.0.1:3003")
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--storage-state", required=True, type=Path, help="External private browser state, never commit")
    parser.add_argument("--readback-only", type=Path, help="Prior report; run after restarting API with the same database")
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    url = make_url(config["database_url"])
    assert url.get_backend_name() == "postgresql" and (url.database or "").startswith("cryptoscan_e2e_"), "Disposable PostgreSQL database required"
    assert urlsplit(args.base_url).hostname in {"localhost", "127.0.0.1"}, "This harness is restricted to the authorized local sandbox"
    from playwright.sync_api import sync_playwright, expect

    report = {"schema": "cryptoscan.cbom-durable-browser-check/1", "bank_approved": False,
              "deployment_qualified": False, "scope": "DISPOSABLE_SYNTHETIC_ESTATES", "checks": []}
    checks = report["checks"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True,
                                            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--use-angle=swiftshader"])
        report["browser"] = browser.version
        contexts = []
        errors = []

        def login(username):
            context = browser.new_context(base_url=args.base_url, accept_downloads=True)
            contexts.append(context)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)[:300]))
            page.goto("/login")
            page.locator("#login-user").fill(username)
            page.locator("#login-pass").fill(config["password"])
            page.get_by_role("button", name=re.compile(r"^sign in$", re.I)).click()
            page.wait_for_url("**/command-center")
            page.goto("/cbom")
            expect(page.get_by_role("heading", name="Cryptographic Bill of Materials", exact=True)).to_be_visible()
            return context, page

        def download(page, name):
            with page.expect_download() as pending:
                page.get_by_role("button", name=name, exact=True).click()
            artifact = pending.value
            document = json.loads(Path(artifact.path()).read_bytes())
            assert validate_cyclonedx16(document)["ok"]
            assert "synthetic-declared-owner" in json.dumps(document)
            assert "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS" in json.dumps(document)
            return document

        if args.readback_only:
            prior = json.loads(args.readback_only.read_text())
            context = browser.new_context(base_url=args.base_url, storage_state=str(args.storage_state), accept_downloads=True)
            contexts.append(context)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)[:300]))
            page.goto("/cbom")
            expect(page.get_by_role("heading", name="Cryptographic Bill of Materials", exact=True)).to_be_visible()
            document = download(page, "Export CycloneDX 1.6 JSON")
            assert page.request.get(f"/api/v1/cbom/system/{prior['receipts']['b']['system']['id']}").status == 404
            check_database(config["database_url"], prior["receipts"])
            report["receipts"] = prior["receipts"]
            checks += ["SESSION_COOKIE_RESTORED_AFTER_API_RESTART", "POST_RESTART_BROWSER_EXPORT_VALID", "POST_RESTART_FOREIGN_SYSTEM_404", "POST_RESTART_POSTGRES_READBACK"]
            report["export_sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
        else:
            name = "Synthetic CBOM e2e " + uuid.uuid4().hex[:12]
            bom = CbomGenerator().from_records([
                {"id":"reported-kem", "algorithm":"ML-KEM-768", "key_size":1184, "file_path":"declared/kem.conf", "line_number":1,
                 "owner":"synthetic-declared-owner", "data_classification":"confidential", "retention_years":12},
                {"id":"reported-aes", "algorithm":"AES", "mode":"GCM", "key_size":256, "file_path":"declared/aes.conf", "line_number":2},
            ], name=name, spec_version="1.6")

            def submit(page):
                page.get_by_label("Import system name", exact=True).fill(name)
                page.get_by_label("CBOM JSON file", exact=True).set_input_files({"name":"declarations.json", "mimeType":"application/json", "buffer":json.dumps(bom).encode()})
                with page.expect_response(lambda response: response.url.endswith("/api/v1/cbom/ingest") and response.request.method == "POST") as pending:
                    page.get_by_role("button", name="Import metadata", exact=True).click()
                response = pending.value
                assert response.status == 200, f"Import HTTP {response.status}"
                receipt = response.json()
                assert re.fullmatch("[0-9a-f]{64}", receipt["document_sha256"])
                expect(page.get_by_text(f"Saved metadata: 2 assets for {name}. Not a scan or approval.", exact=True)).to_be_visible()
                return receipt

            context_a, page_a = login(config.get("username_a", "e2e_bank_a"))
            first = submit(page_a)
            document = download(page_a, "Export persisted metadata")
            checks += ["REAL_BROWSER_PASSWORD_LOGIN", "BROWSER_NATIVE_FILE_UPLOAD", "COMMITTED_IMPORT_RECEIPT", "AUTHENTICATED_PERSISTED_NATIVE_EXPORT"]
            page_a.reload()
            expect(page_a.get_by_text("crypto:ML-KEM-768", exact=True)).to_be_visible()
            repeated = submit(page_a)
            assert repeated["system"]["id"] == first["system"]["id"]
            checks += ["BROWSER_RELOAD_READS_PERSISTED_IDENTITY", "REIMPORT_KEEPS_SYSTEM_ID"]
            # Real concurrent HTTP requests against the migrated database, not
            # an in-process transport. Existing-system imports serialize; a
            # first-create race may explicitly return 409, never success+loss.
            from concurrent.futures import ThreadPoolExecutor
            from threading import Barrier
            import httpx
            cookies = {cookie["name"]:cookie["value"] for cookie in context_a.cookies(args.base_url)}
            with httpx.Client(base_url=args.base_url, cookies=cookies, timeout=40) as http:
                for business_name in (name, name + " concurrent first-create"):
                    barrier = Barrier(4)
                    def concurrent_import(_):
                        barrier.wait(timeout=10)
                        return http.post("/api/v1/cbom/ingest", json={"bom":bom,"system_name":business_name})
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        responses = list(workers.map(concurrent_import, range(4)))
                    assert all(response.status_code in (200,409) for response in responses)
                    accepted = [response.json()["system"]["id"] for response in responses if response.status_code == 200]
                    assert accepted and len(set(accepted)) == 1
                    if business_name == name:
                        assert set(accepted) == {first["system"]["id"]}
                    report.setdefault("concurrency", []).append({"scenario":"existing" if business_name == name else "first_create",
                                                                "statuses":[response.status_code for response in responses],
                                                                "accepted_system_id":accepted[0]})
            checks += ["CONCURRENT_EXISTING_SYSTEM_IMPORTS_SERIALIZE", "CONCURRENT_FIRST_CREATE_HAS_ONE_SYSTEM_OR_EXPLICIT_409"]
            context_a.storage_state(path=str(args.storage_state))
            os.chmod(args.storage_state, 0o600)
            if args.screenshot:
                page_a.screenshot(path=str(args.screenshot), full_page=True)
            page_a.get_by_label("Import system name", exact=True).fill("unsubmitted private draft")
            page_a.evaluate("window.dispatchEvent(new Event('zelinx:tenant'))")
            expect(page_a.get_by_label("Import system name", exact=True)).to_have_value("")
            checks.append("BROWSER_PRIVATE_SCOPE_EVENT_CLEARS_DRAFT")
            _context_b, page_b = login(config.get("username_b", "e2e_bank_b"))
            second = submit(page_b)
            assert first["system"]["id"] != second["system"]["id"]
            assert page_b.request.get(f"/api/v1/cbom/system/{first['system']['id']}").status == 404
            assert page_a.request.get(f"/api/v1/cbom/system/{second['system']['id']}").status == 404
            checks += ["SAME_NAME_DIFFERENT_BANK_IDS", "FOREIGN_SYSTEM_READ_DENIED_BOTH_DIRECTIONS"]
            _reader_context, reader = login(config.get("username_reader", "e2e_reader"))
            reader.get_by_label("Import system name", exact=True).fill(name)
            reader.get_by_label("CBOM JSON file", exact=True).set_input_files({"name":"declarations.json", "mimeType":"application/json", "buffer":json.dumps(bom).encode()})
            with reader.expect_response(lambda response: response.url.endswith("/api/v1/cbom/ingest") and response.request.method == "POST") as pending:
                reader.get_by_role("button", name="Import metadata", exact=True).click()
            assert pending.value.status == 403
            expect(reader.get_by_text(re.compile("Import not confirmed.*HTTP 403"))).to_be_visible()
            assert reader.get_by_role("button", name="Export persisted metadata", exact=True).count() == 0
            checks.append("READONLY_REAL_SESSION_IMPORT_403")
            report["receipts"] = {"a": repeated, "b": second}
            check_database(config["database_url"], report["receipts"])
            checks += ["POSTGRES_NEW_CONNECTION_READBACK", "NO_FALSE_SCAN_TIMESTAMPS", "BANK_SCOPED_DECLARATIONS_AND_LINKS", "REIMPORT_NO_DUPLICATE_ASSETS"]
            report["export_sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
        report["page_errors"] = errors
        assert not errors, errors
        for context in contexts:
            context.close()
        browser.close()
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(checks)} real-browser/database checks; no production or bank approval claimed")


if __name__ == "__main__":
    main()
