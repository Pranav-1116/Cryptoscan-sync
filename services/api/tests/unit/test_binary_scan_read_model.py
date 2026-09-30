"""The binary read-model routes use exact tenant predicates."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

import db.models  # noqa: F401 — register model metadata
from api.routers.devsecops import (
    BinaryScanCompareRequest,
    _binary_tenant_clause,
    binary_scan_compare,
    binary_scan_coverage,
    binary_scan_findings,
    binary_scan_observations,
)
from db.connection.session import Base
from db.models.binary_scan import BinaryScanObservation, BinaryScanRecord


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [],
                    "query_string": b""})


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


def test_binary_route_clause_never_mixes_tenant_and_platform_rows():
    engine, session = _session()
    try:
        session.add_all([
            BinaryScanRecord(tenant_id="tenant-a", artifact_id="a", target="/a", sha256="1"),
            BinaryScanRecord(tenant_id="tenant-b", artifact_id="b", target="/b", sha256="2"),
            BinaryScanRecord(tenant_id=None, artifact_id="platform", target="/platform", sha256="3"),
        ])
        session.commit()
        tenant_rows = session.query(BinaryScanRecord).filter(
            _binary_tenant_clause(BinaryScanRecord, "tenant-a")).all()
        platform_rows = session.query(BinaryScanRecord).filter(
            _binary_tenant_clause(BinaryScanRecord, None)).all()
        assert [row.artifact_id for row in tenant_rows] == ["a"]
        assert [row.artifact_id for row in platform_rows] == ["platform"]
    finally:
        session.close()
        engine.dispose()


def test_binary_read_model_routes_page_filter_and_compare_observations():
    engine, session = _session()
    try:
        before = BinaryScanRecord(artifact_id="before", target="/before", sha256="1",
                                  files_walked=2, binaries_scanned=1,
                                  summary={"findings_excerpt": [{"code": "BIN-X", "severity": "HIGH", "path": "lib/a.so"}]})
        after = BinaryScanRecord(artifact_id="after", target="/after", sha256="2",
                                 files_walked=3, binaries_scanned=2, coverage={"searched_bytes": 12})
        session.add_all([before, after])
        session.flush()
        session.add_all([
            BinaryScanObservation(scan_record_id=before.id, artifact_id="before", path="lib/a.so",
                                  format="elf", evidence_state="partial", parsed=False,
                                  findings=[{"code": "BIN-X", "severity": "HIGH", "detail": "partial"}],
                                  crypto={"algorithms": ["AES"]}),
            BinaryScanObservation(scan_record_id=after.id, artifact_id="after", path="lib/a.so",
                                  format="elf", evidence_state="observed", parsed=True,
                                  findings=[], crypto={"algorithms": ["AES", "SHA-256"]}),
            BinaryScanObservation(scan_record_id=after.id, artifact_id="after", path="lib/b.so",
                                  format="elf", evidence_state="observed", parsed=True,
                                  findings=[], crypto={}),
        ])
        session.commit()

        observations = binary_scan_observations(before.id, _request(), limit=10, offset=0,
                                                format_filter=None, evidence_state="partial", q=None,
                                                crypto_only=True, db=session, user="platform")
        assert observations["total"] == 1
        assert observations["observations"][0]["evidence_state"] == "partial"

        findings = binary_scan_findings(before.id, _request(), severity="HIGH", code=None, limit=10,
                                        offset=0, db=session, user="platform")
        assert findings["total"] == 1
        assert findings["findings"][0]["code"] == "BIN-X"

        coverage = binary_scan_coverage(after.id, _request(), db=session, user="platform")
        assert coverage["evidence_states"] == {"observed": 2}
        assert coverage["formats"] == {"elf": 2}

        diff = binary_scan_compare(BinaryScanCompareRequest(from_scan_id=before.id, to_scan_id=after.id),
                                   _request(), db=session, user="platform")
        assert diff["counts"] == {"added": 1, "removed": 0, "changed": 1}
        assert diff["changed"][0]["before"]["evidence_state"] == "partial"
    finally:
        session.close()
        engine.dispose()
