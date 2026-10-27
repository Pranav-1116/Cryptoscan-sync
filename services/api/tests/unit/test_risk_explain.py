"""The risk explainability chain (§4.6, round 58).

Every high-risk verdict must answer: what asset is affected, where the
evidence lives, why the control fails, who owns the business impact,
which inputs are declared versus observed, and why a remediation/PQC
wave is recommended — from persisted state, with limitations listed.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register every table
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from api.risk_explain import FACTOR_BASES, cite_failing_controls
from db.connection.session import Base
from db.models.business_process import BusinessProcess
from db.models.crypto_asset import CryptoAsset
from db.models.evidence_record import EvidenceRecord
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_business_process import SystemBusinessProcess
from db.models.user import User

SECRET = "risk-explain-test-" + "x" * 16


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="op", roles="developer", password_hash="x"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "op"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


class _Row:
    """Evidence-row double for the pure citation tests."""

    def __init__(self, rule_results, row_id="ev-1"):
        self.id = row_id
        self.policy_evaluation = {"rules_evaluated": rule_results}


def test_failing_controls_cite_the_stored_verdicts_grouped_per_rule():
    rows = [
        _Row([
            {"rule_id": "BASE-001", "rule_name": "No DES", "evaluation_result": "FAIL",
             "severity": "HIGH", "message": "DES is deprecated",
             "remediation": "Move to AES"},
            {"rule_id": "BASE-002", "rule_name": "Sizes", "evaluation_result": "WARN",
             "severity": "LOW", "message": "small key", "remediation": None},
        ]),
        _Row([
            {"rule_id": "BASE-001", "rule_name": "No DES", "evaluation_result": "FAIL",
             "severity": "HIGH", "message": "DES is deprecated",
             "remediation": "Move to AES"},
        ], row_id="ev-2"),
        _Row([{"rule_id": "BASE-003", "evaluation_result": "PASS"}]),  # passes are not cited
    ]
    controls = cite_failing_controls(rows)
    assert [c["rule_id"] for c in controls] == ["BASE-001", "BASE-002"]
    des = controls[0]
    assert des["worst_outcome"] == "FAIL"
    assert des["evidence_ids"] == ["ev-1", "ev-2"]
    assert des["evidence_count"] == 2
    assert des["messages"] == ["DES is deprecated"], "duplicate messages collapse"
    assert des["remediation"] == "Move to AES"


def test_fail_outranks_warn_in_control_ordering():
    rows = [_Row([{"rule_id": "A-WARN", "evaluation_result": "WARN", "severity": "LOW",
                   "message": "w"}]),
            _Row([{"rule_id": "B-FAIL", "evaluation_result": "FAIL", "severity": "HIGH",
                   "message": "f"}])]
    controls = cite_failing_controls(rows)
    assert [c["rule_id"] for c in controls] == ["B-FAIL", "A-WARN"]


def test_every_factor_declares_its_epistemic_basis():
    """The 8 unified factors each carry DECLARED or OBSERVED — and the
    dependency count is never allowed to masquerade as blast radius."""
    assert set(FACTOR_BASES) == {
        "technical", "crypto", "pqc", "exposure", "business_criticality",
        "dependency_impact", "evidence_confidence", "threat",
    }
    for name, (basis, note) in FACTOR_BASES.items():
        assert basis in {"DECLARED", "OBSERVED"}, name
        assert len(note) > 20, f"{name} needs a real basis note"
    assert FACTOR_BASES["dependency_impact"][0] == "DECLARED"
    assert "NOT an observed blast radius" in FACTOR_BASES["dependency_impact"][1]
    assert FACTOR_BASES["exposure"][0] == "DECLARED"
    assert FACTOR_BASES["technical"][0] == "OBSERVED"


def _seed(session):
    session.add(System(
        id="sys-x", name="card-payments", environment="prod", criticality="TIER-1",
        cloud_provider="AWS", last_scan_id="scan-x", owner="payments-team",
        technical_owner="alice", security_owner="bob",
    ))
    session.add(System(id="sys-noscan", name="unscanned-system"))
    for i, (alg, status) in enumerate([("DES", "FAIL"), ("RSA-2048", "PASS")]):
        session.add(EvidenceRecord(
            scan_id="scan-x", content_hash=f"c{i}" * 32, chain_hash=f"h{i}" * 32,
            chain_position=i, algorithm=alg, confidence="HIGH", key_size=2048,
            file_path=f"src/F{i}.java", line_number=i + 1,
            compliance_status=status, finding_data={},
            policy_evaluation={"rules_evaluated": [
                {"rule_id": "BASE-001", "rule_name": "No DES",
                 "evaluation_result": "FAIL" if alg == "DES" else "PASS",
                 "severity": "HIGH", "message": f"{alg} fails the baseline",
                 "remediation": "Replace with AES-256-GCM"},
            ]},
        ))
    asset = CryptoAsset(algorithm="DES", purpose="ENCRYPTION", file_path="src/F0.java",
                        line_number=1, confidence="HIGH")
    session.add(asset)
    session.flush()
    session.add(SystemAsset(system_id="sys-x", asset_id=asset.id))
    process = BusinessProcess(name="Card Checkout", revenue_daily=1000.0)
    session.add(process)
    session.flush()
    session.add(SystemBusinessProcess(system_id="sys-x", process_id=process.id,
                                      role="PRIMARY"))
    session.commit()
    return asset


@pytest.mark.asyncio
async def test_explanation_answers_all_six_questions():
    app, session, engine = _make_app()
    asset = _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/risk/systems/sys-x/explain")
    assert r.status_code == 200, r.text
    body = r.json()

    # 1 WHAT asset is affected — spine-keyed (persisted key preferred,
    # derived from the canonical identity when the row predates it)
    from shared_models.asset_identity import crypto_asset_key_from_row
    expected_key = asset.asset_key or crypto_asset_key_from_row(asset.to_dict())
    assert body["affected_assets"][0]["asset_key"] == expected_key
    assert body["affected_assets"][0]["algorithm"] == "DES"
    # 2 WHERE the evidence lives — verify path + hash + location
    trail = body["evidence_trail"]
    assert trail["verify_path"] == "/api/v1/scans/scan-x/verify"
    assert trail["entries"][0]["location"] == "src/F0.java:1"
    assert trail["entries"][0]["content_hash"]
    # 3 WHY the control fails — the stored rule verdict
    control = body["failing_controls"][0]
    assert control["rule_id"] == "BASE-001"
    assert control["worst_outcome"] == "FAIL"
    assert "DES fails the baseline" in control["messages"]
    assert control["evidence_count"] == 1
    # 4 WHO owns the business impact
    assert body["accountability"]["owner"] == "payments-team"
    assert body["accountability"]["business_processes"][0]["name"] == "Card Checkout"
    # 5 DECLARED vs OBSERVED
    factors = {f["factor"]: f for f in body["factors"]}
    assert factors["exposure"]["basis"] == "DECLARED"
    assert factors["dependency_impact"]["basis"] == "DECLARED"
    assert factors["technical"]["basis"] == "OBSERVED"
    # 6 WHY the PQC wave — real planner output per site
    pqc = body["pqc_rationale"]
    assert pqc["vulnerable_sites"] >= 1
    assert pqc["sites"], "vulnerable assets produce wave assignments"
    for site in pqc["sites"]:
        assert site["wave"] in {"1", "2", "3"}
        assert site["wave_focus"]
        assert site["recommended_replacement"]
    # limitations are listed, never absorbed
    assert any("blast radius" in note for note in body["limitations"])
    assert body["model"] == "risk-explanation/v1"
    engine.dispose()


@pytest.mark.asyncio
async def test_unscanned_system_explains_honestly():
    """No scan → nothing fabricated: observed factors are 0 because
    nothing was observed, and the explanation says exactly that."""
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/risk/systems/sys-noscan/explain")
    assert r.status_code == 200
    body = r.json()
    assert body["evidence_trail"]["entries"] == []
    assert "No scan recorded" in body["evidence_trail"]["note"]
    assert any("No scan recorded" in note for note in body["limitations"])
    assert body["failing_controls"] == []
    assert body["affected_assets"] == []
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_system_is_404():
    app, _session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/risk/systems/nope/explain")
    assert r.status_code == 404
    engine.dispose()
