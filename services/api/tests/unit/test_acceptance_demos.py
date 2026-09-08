"""End-to-end acceptance demos from the plan (W53-56 testing scenarios).

Scenario 1 — migration: 207 failing assets -> 207 auto-tasks; 50 done -> 24%.
Scenario 2 — compliance: a payment-environment scan reported against the full
requirement pool with exactly 3 violations.

Honest note on scenario 2: the plan quoted "89% (32 of 36)" against a
36-requirement PCI template that does not exist here. The shipped native pack
grew to 8 templates (PCI-DSS 4.0, DORA, NIST SP 800-131A, FIPS 140-3, SOC 2,
ISO 27001, NIST SP 800-53, UAE PDPL). This demo asserts the *actual* evaluation
math against the real, derived pool — N estate requirements, exactly 3
violations — rather than re-staging fictional numbers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.migration_project import MigrationTask
from db.models.scan import Scan


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "pm"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed_scan(session, scan_id, findings_specs):
    session.add(
        Scan(id=scan_id, scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location="https://github.com/org/payments.git",
             target_type="GIT_REPOSITORY", status="COMPLETED", statistics={})
    )
    for index, (algorithm, purpose, status, path, line, policy) in enumerate(findings_specs):
        session.add(
            EvidenceRecord(
                scan_id=scan_id, content_hash=f"{scan_id}{index:058d}"[:64],
                chain_hash=f"{index:064d}", chain_position=index, previous_hash=None,
                algorithm=algorithm, confidence="HIGH", purpose=purpose, mode=None,
                key_size=1024 if algorithm == "RSA" else None,
                file_path=path, line_number=line, finding_data={"scanner_id": "s"},
                compliance_status=status, policy_evaluation=policy,
            )
        )
    session.flush()


@pytest.mark.asyncio
async def test_migration_demo_207_assets_50_done_is_24_percent():
    app, session, engine = _make_app()
    # 207 failing RSA findings -> the "RSA to PQC" estate from the plan
    _seed_scan(
        session, "scan-demo",
        [("RSA", "SIGNING", "FAIL", f"src/node{i}/Crypto.java", i + 1, None) for i in range(207)],
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (
            await client.post("/api/v1/migrations/from-scan", json={"scan_id": "scan-demo"})
        ).json()
        assert created["tasks_created"] == 207  # one task per failing finding
        project_id = created["project"]["id"]

        tasks = (await client.get(f"/api/v1/migrations/{project_id}/tasks")).json()["tasks"]
        assert len(tasks) == 207
        assert all(task["algorithm_from"] == "RSA" for task in tasks)

        # complete 50 tasks with spread timestamps (velocity needs real history)
        task_ids = [task["id"] for task in tasks[:50]]
        base = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for offset, task_id in enumerate(task_ids):
            session.execute(
                update(MigrationTask)
                .where(MigrationTask.id == task_id)
                .values(status="DONE", completed_at=base + timedelta(days=offset))
            )
        session.flush()

        progress = (await client.get(f"/api/v1/migrations/{project_id}/progress")).json()
        assert progress["tasks_done"] == 50
        assert progress["task_progress_pct"] == 24.2  # 50/207, honest to the decimal
        assert int(progress["task_progress_pct"]) == 24  # the plan's headline number
        assert progress["tasks_actionable"] == 207


@pytest.mark.asyncio
async def test_compliance_demo_three_violations_across_full_pool():
    app, session, engine = _make_app()

    # requirement ids + a matching rule prefix per requirement, from the templates
    from reporting.report_templates import _TEMPLATES

    pool = []
    prefix_for = {}
    for spec in _TEMPLATES.values():
        for requirement in spec["requirements"]:
            if requirement["id"] not in prefix_for:
                prefix_for[requirement["id"]] = requirement["rule_prefixes"][0]
                pool.append(requirement["id"])
    # The requirement pool grows as compliance templates are added. Derive the
    # expected totals from the registry so this test stays correct without a
    # magic number: 29 unique IDs across 8 templates (25 estate + 4 PAY-xxx).
    assert len(pool) >= 19  # at least the original 15 estate + 4 payment pool

    # prefixes chosen to match exactly ONE requirement each. Many rule prefixes
    # are shared across requirements (e.g. BASELINE-005 is used by CC6.7, SC-8,
    # Art.9 and Art.20), so a fail must use a prefix owned by a single id or the
    # report would cascade a violation into every requirement that shares it.
    fail_rule = {"4.2.1": "PCIDSS-002", "ICT-32": "CNSA-002", "SA-15": "SBOM-001"}
    specs = []
    line = 1
    for rid in pool:
        prefix = fail_rule.get(rid) or prefix_for[rid]
        result = "FAIL" if rid in fail_rule else "PASS"
        specs.append(
            (
                "DES" if result == "FAIL" else "AES-256-GCM",
                "ENCRYPTION",
                result,
                f"src/pay/req_{rid.replace('.', '_')}.java",
                line,
                {"rules_evaluated": [
                    {"rule_id": f"{prefix}-9", "standard_reference": f"demo {rid}",
                     "evaluation_result": result}
                ]},
            )
        )
        line += 1
    _seed_scan(session, "scan-pci", specs)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        estate_pool = [rid for rid in pool if "-pay" not in rid]
        # payment (-pay) requirements need HSM evidence, excluded here
        assert len(estate_pool) >= 15
        report = (
            await client.get(
                "/api/v1/scans/scan-pci/report",
                params={"template": "custom", "requirements": ",".join(estate_pool)},
            )
        ).json()
        evaluation = report["template_evaluation"]
        summary = evaluation["summary"]
        assert summary["total"] == len(estate_pool)  # every estate requirement evaluated
        assert summary["fail"] == 3  # exactly three violations
        assert summary["not_evaluated"] == 0  # every requirement has policy evidence
        assert summary["pass"] == len(estate_pool) - 3
        # honest score computed from the real (derived) pool size
        assert evaluation["summary"]["compliant_pct"] == round(
            (len(estate_pool) - 3) / len(estate_pool) * 100, 1
        )
        assert len(report["report_hash"]) == 64  # tamper-evident (canonical SHA-256)
        assert report["attestation"]["statement"]  # signed attestation block
        failing_rows = [row for row in evaluation["requirements"] if row["status"] == "FAIL"]
        assert {row["id"] for row in failing_rows} == set(fail_rule)
        assert all(row["failure_locations"] for row in failing_rows)  # evidence attached
