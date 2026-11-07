"""The dedicated security regression suite for the security-control plane.

Ten suites, exactly the ones the review named, each pinning the behaviour that was broken:

1.  cross-origin pagination and credential-leak tests
2.  HTTP downgrade and redirect tests
3.  snapshot canonical-hash tests
4.  child finding tampering tests
5.  evidence artifact digest verification
6.  cross-tenant evidence reference tests
7.  cross-snapshot and cross-asset evidence tests
8.  FileTail partial-line and truncation tests
9.  file rotation and cursor recovery tests
10. concurrent snapshot sequence tests

Suites 1–2 and 8–9 exercise the transport layer (``cbom.security_controls.transport``);
suites 3–7 and 10 exercise the API router over a real database. Nothing here is mocked
beyond the network socket and the injected HTTP client, which the transport declares as
its test seam.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cbom.security_controls.transport import ControlRefused, FileTail, HttpTransport


# --------------------------------------------------------------------------- #
# an injected HTTP client: the transport's declared seam for testing the read path
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, status_code: int = 200, body: Any = None,
                 headers: dict[str, str] | None = None, text: str | None = None) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = dict(headers or {})
        self._text = text

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("not json")
        return self._body

    @property
    def text(self) -> str:
        if self._text is not None:
            return self._text
        return json.dumps(self._body) if self._body is not None else ""


class FakeHTTP:
    """Records every request the transport actually sends; serves queued responses.

    Anything the transport refuses never reaches ``calls`` — which is the point of the
    credential-leak suites: the assertion is on the *absence* of a request.
    """

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses or [])

    def queue(self, response: Any) -> "FakeHTTP":
        self._responses.append(response)
        return self

    def __call__(self) -> Any:
        outer = self

        class _Client:
            def request(self, method: str, url: str, *, headers: Any, params: Any) -> Any:
                outer.calls.append({"method": method, "url": url,
                                    "headers": dict(headers), "params": dict(params or {})})
                if not outer._responses:
                    return FakeResponse(503, {"error": "no response queued"})
                item = outer._responses.pop(0)
                return item() if callable(item) else item

            def close(self) -> None:
                return None

        return _Client()


def transport(base: str = "https://device.example:8443/api", http: FakeHTTP | None = None,
              **options: Any) -> HttpTransport:
    from cbom.security_controls.transport import Credential

    http = http if http is not None else FakeHTTP()
    return HttpTransport(base_url=base, credential=Credential(value="device-secret",
                                                             source="test"),
                         _client_factory=http, _sleep=lambda _s: None, **options)


# --------------------------------------------------------------------------- #
# Suite 1 — cross-origin pagination and credential-leak tests
# --------------------------------------------------------------------------- #

class TestSuite01CrossOriginPaginationAndCredentialLeak:

    def test_a_cross_origin_pagination_link_is_refused_and_never_requested(self):
        http = FakeHTTP([FakeResponse(
            200, {"results": [{"id": 1}]},
            headers={"link": '<https://evil.example/steal?page=2>; rel="next"'})])
        client = transport(http=http)
        rows, result = client.get_all("policies")
        assert rows == [{"id": 1}]
        # the credential-bearing request to the foreign host never happened
        assert [c["url"] for c in http.calls] == ["https://device.example:8443/api/policies"]
        assert result.state == "REFUSED"
        assert "evil.example" in result.reason

    def test_the_authorization_header_only_ever_reaches_the_approved_origin(self):
        http = FakeHTTP([
            FakeResponse(200, {"results": [{"id": 1}]},
                         headers={"link": '<https://evil.example/steal?page=2>; rel="next"'}),
            FakeResponse(200, {"results": [{"id": 2}]}),
        ])
        client = transport(http=http)
        client.get_all("policies")
        for call in http.calls:
            assert call["url"].startswith("https://device.example:8443")
            assert call["headers"].get("Authorization") == "Bearer device-secret"
        # and nothing was addressed to the foreign host at all
        assert not any("evil.example" in c["url"] for c in http.calls)

    def test_a_same_origin_absolute_pagination_link_is_followed(self):
        http = FakeHTTP([
            FakeResponse(200, {"results": [{"id": 1}]},
                         headers={"link": '<https://device.example:8443/api/policies?page=2>; '
                                          'rel="next"'}),
            FakeResponse(200, {"results": [{"id": 2}]}),
        ])
        client = transport(http=http)
        rows, result = client.get_all("policies")
        assert rows == [{"id": 1}, {"id": 2}]
        assert result.state == "OK"
        assert len(http.calls) == 2
        assert http.calls[1]["url"] == "https://device.example:8443/api/policies?page=2"

    def test_a_relative_pagination_link_resolves_against_the_base_url(self):
        http = FakeHTTP([
            FakeResponse(200, {"results": [{"id": 1}]},
                         headers={"link": '<policies?page=2>; rel="next"'}),
            FakeResponse(200, {"results": [{"id": 2}]}),
        ])
        client = transport(http=http)
        rows, result = client.get_all("policies")
        assert rows == [{"id": 1}, {"id": 2}]
        assert result.state == "OK"
        assert http.calls[1]["url"] == "https://device.example:8443/api/policies?page=2"

    def test_a_cross_origin_absolute_request_path_is_refused(self):
        http = FakeHTTP()
        client = transport(http=http)
        result = client.get("https://other-device.example/api/policies")
        assert result.state == "REFUSED"
        assert http.calls == []

    def test_a_userinfo_url_is_refused_before_any_request(self):
        http = FakeHTTP()
        client = transport(http=http)
        result = client.get("https://user:pass@device.example:8443/api/policies")
        assert result.state == "REFUSED"
        assert "user:pass" not in result.reason
        assert "user:pass" not in result.url
        assert http.calls == []


# --------------------------------------------------------------------------- #
# Suite 2 — HTTP downgrade and redirect tests
# --------------------------------------------------------------------------- #

class TestSuite02HttpDowngradeAndRedirects:

    def test_an_https_base_never_follows_a_target_down_to_http(self):
        http = FakeHTTP()
        client = transport(base="https://device.example/api", http=http)
        result = client.get("http://device.example/api/policies")
        assert result.state == "REFUSED"
        assert http.calls == []
        assert "downgrade" in result.reason

    def test_a_port_change_is_cross_origin_even_on_the_same_host(self):
        http = FakeHTTP()
        client = transport(base="https://device.example:8443/api", http=http)
        result = client.get("https://device.example:9999/api/policies")
        assert result.state == "REFUSED"
        assert http.calls == []

    def test_a_redirect_is_refused_and_never_followed(self):
        http = FakeHTTP([FakeResponse(302, headers={"location": "https://evil.example/next"})])
        client = transport(http=http)
        result = client.get("policies")
        assert result.state == "REFUSED"
        assert "redirect" in result.reason
        # one request only: the 302 response itself, no follow-up to the Location
        assert len(http.calls) == 1

    def test_redirects_are_disabled_in_the_real_httpx_client_too(self):
        import inspect

        from cbom.security_controls import transport as module

        source = inspect.getsource(module.HttpTransport._send)
        assert "follow_redirects=False" in source, (
            "the real client must be constructed with redirects disabled, so a 3xx can "
            "never become a credential-bearing follow-up")


# --------------------------------------------------------------------------- #
# Suite 8 — FileTail partial-line and truncation tests
# --------------------------------------------------------------------------- #

class TestSuite08FileTailPartialLineAndTruncation:

    def test_a_partial_line_is_never_skipped(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n{"n": 3, "par')
        tail = FileTail(str(log), max_bytes=4096, max_lines=5000)
        rows, detail = tail.read_lines()
        assert [r["n"] for r in rows] == [1, 2]
        assert detail["pending_bytes"] == len(b'{"n": 3, "par')
        assert detail["pending_bytes"] > 0
        # the tail's completion arrives in the next write and is read exactly once
        with log.open("ab") as handle:
            handle.write(b'tial": true}\n')
        rows, detail = tail.read_lines()
        assert rows == [{"n": 3, "partial": True}]
        assert detail["pending_bytes"] == 0

    def test_a_final_unterminated_line_is_reported_as_pending_never_lost(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}')  # no trailing newline
        tail = FileTail(str(log))
        rows, detail = tail.read_lines()
        assert [r["n"] for r in rows] == [1]
        assert detail["pending_bytes"] == len(b'{"n": 2}')
        rows, _ = tail.read_lines()
        assert rows == []  # still pending, not duplicated, not dropped
        rows, detail = tail.read_lines(flush_tail=True)
        assert rows == [{"n": 2}]  # the caller who knows the file is done can flush it
        assert detail["pending_bytes"] == 0

    def test_the_durable_cursor_advances_only_through_consumed_records(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n{"n": 3}\n')
        tail = FileTail(str(log), max_lines=2)
        rows, detail = tail.read_lines()
        assert [r["n"] for r in rows] == [1, 2]
        # record 3 was read into memory but NOT consumed: the cursor stops at record 2
        assert detail["truncated"] is True
        assert detail["offset_after"] == len(b'{"n": 1}\n{"n": 2}\n')
        rows, detail = tail.read_lines()
        assert [r["n"] for r in rows] == [3]
        assert detail["truncated"] is False

    def test_a_short_read_never_moves_the_cursor_past_unread_content(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n{"n": 3}\n')
        tail = FileTail(str(log), max_bytes=10)  # first read cannot even hold two records
        rows, detail = tail.read_lines()
        total = list(rows)
        assert detail["offset_after"] <= 10 + 2  # never past what was actually consumed
        while True:
            rows, detail = tail.read_lines()
            total.extend(rows)
            if not rows and detail["pending_bytes"] == 0:
                break
        assert [r["n"] for r in total] == [1, 2, 3]

    def test_a_truncated_file_is_detected_and_reread_from_zero(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n{"n": 3}\n')
        tail = FileTail(str(log))
        rows, _ = tail.read_lines()
        assert len(rows) == 3
        # the file is truncated and rewritten smaller (a logrotate copy-truncate)
        log.write_bytes(b'{"n": 9}\n')
        rows, detail = tail.read_lines()
        assert rows == [{"n": 9}]
        assert detail["rotated"] is True


# --------------------------------------------------------------------------- #
# Suite 9 — file rotation and cursor recovery tests
# --------------------------------------------------------------------------- #

class TestSuite09FileRotationAndCursorRecovery:

    def test_rotation_replaces_the_file_under_the_path_and_starts_over(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n')
        tail = FileTail(str(log))
        rows, _ = tail.read_lines()
        assert [r["n"] for r in rows] == [1, 2]
        # rotate: the old file moves away and a new file takes the path
        log.rename(tmp_path / "eve.json.1")
        log.write_bytes(b'{"n": 100}\n')
        rows, detail = tail.read_lines()
        assert rows == [{"n": 100}]
        assert detail["rotated"] is True
        assert detail["offset_after"] == len(b'{"n": 100}\n')

    def test_a_new_tail_resumes_from_the_persisted_cursor(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n')
        first = FileTail(str(log))
        rows, detail = first.read_lines()
        assert len(rows) == 2
        saved = detail["cursor"]  # the operator persists this alongside the feed state
        assert saved["offset"] == first.durable_cursor()["offset"]
        # a restart: a brand-new tail resumes at the exact byte boundary
        resumed = FileTail(str(log), cursor=saved)
        with log.open("ab") as handle:
            handle.write(b'{"n": 3}\n')
        rows, detail = resumed.read_lines()
        assert rows == [{"n": 3}]
        assert detail["offset_before"] == saved["offset"]

    def test_a_cursor_from_before_a_rotation_is_detected_not_trusted(self, tmp_path):
        log = tmp_path / "eve.json"
        log.write_bytes(b'{"n": 1}\n{"n": 2}\n')
        first = FileTail(str(log))
        _, detail = first.read_lines()
        saved = detail["cursor"]
        log.unlink()
        log.write_bytes(b'{"n": 100}\n')  # a different inode under the same path
        resumed = FileTail(str(log), cursor=saved)
        rows, detail = resumed.read_lines()
        assert rows == [{"n": 100}]  # restarted at zero, not at the stale offset
        assert detail["rotated"] is True

    def test_a_line_written_in_two_chunks_becomes_one_record(self, tmp_path):
        log = tmp_path / "eve.json"
        with log.open("ab") as handle:
            handle.write(b'{"n": 1, "long": "aaaa')
        tail = FileTail(str(log))
        rows, _ = tail.read_lines()
        assert rows == []
        with log.open("ab") as handle:
            handle.write(b'bbbb", "end": true}\n')
        rows, _ = tail.read_lines()
        assert rows == [{"n": 1, "long": "aaaabbbb", "end": True}]


# --------------------------------------------------------------------------- #
# the API harness: the router on a real database, with a real evidence store
# --------------------------------------------------------------------------- #

@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    import db.models.security_control  # noqa: F401
    from db.models.user import AuditLog

    engine = create_engine(f"sqlite:///{tmp_path / 'controls.db'}")
    Base.metadata.create_all(engine, tables=[
        db.models.security_control.SecurityControlSnapshot.__table__,
        db.models.security_control.SecurityControlFinding.__table__,
        AuditLog.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def store(tmp_path, monkeypatch):
    from api.config.settings import get_settings

    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.setattr(get_settings(), "SECURITY_CONTROLS_EVIDENCE_ROOT", str(root),
                        raising=False)
    return root


@pytest.fixture()
def api(session):
    from api import dependencies
    from api.dependencies import TenantContext
    from api.routers import security_controls

    app = FastAPI()
    app.include_router(security_controls.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
        username="auditor", tenant_id=None, tenant_role="admin", is_platform_admin=True)
    return app


class CollectorClient:
    """Writes the content-addressed body first, then posts — exactly what a collector does."""

    def __init__(self, client, store, tenant: str = "_platform") -> None:
        self._client = client
        self._store = store
        self._tenant = tenant

    def _attach(self, payload: dict, *, records: list[dict] | None = None) -> dict:
        from datetime import datetime, timezone

        captured = payload.get("captured_at") or datetime.now(timezone.utc).isoformat()
        body_doc: dict = {"captured_at": captured, "collector": payload.get("collector"),
                          "evidence": []}
        if records is not None:
            body_doc["evidence"] = list(records)
        else:
            for finding in payload.get("findings", []):
                for evidence_id in finding.get("evidence_ids", []):
                    body_doc["evidence"].append({
                        "evidence_id": evidence_id, "scheme": "v1",
                        "control": finding.get("control"),
                        "vendor": finding.get("vendor") or "test-vendor",
                        "system": finding.get("subject"),
                        "kind": finding.get("kind", "STATE"),
                        "identity": finding.get("subject"),
                        "config_version": {}})
        raw = json.dumps(body_doc, sort_keys=True).encode("utf-8")
        location = f"{str(payload.get('digest', 'body')).replace(':', '_')}.json"
        target = self._store / self._tenant / location
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        payload = dict(payload)
        payload["captured_at"] = captured
        payload["body_location"] = location
        payload["body_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        payload["body_bytes"] = len(raw)
        return payload

    def post(self, url: str, json: dict | None = None, *, records: list[dict] | None = None,
             **kwargs):
        # an explicit records= means "this is the artifact body" — write it even when the
        # payload names a location, so a crafted location cannot skip the store
        if json is not None and (json.get("body_location") is None or records is not None):
            json = self._attach(json, records=records)
        return self._client.post(url, json=json, **kwargs)

    def get(self, url: str, **kwargs):
        return self._client.get(url, **kwargs)


@pytest.fixture()
def writer(api, store, monkeypatch):
    from api.routers import security_controls

    monkeypatch.setattr(security_controls, "_service_identity",
                        lambda request, signature=None: {"kind": "api_key",
                                                         "id": "key-collector-1",
                                                         "signature_bound": False})
    return CollectorClient(TestClient(api), store)


def snapshot_payload(digest: str = "sha256:aaaabbbbccccdddd", **overrides) -> dict:
    payload = {
        "digest": digest,
        "controls": ["FIREWALL"],
        "counts": {"assets": 1, "claims": 1},
        "read_state": "OK",
        "collector": "key-collector-1",
        "findings": [{
            "control": "FIREWALL", "state": "OBSERVED", "subject": "FW-EDGE-01",
            "facts": ["OBSERVED"], "evidence_ids": ["EVID-FIREWALL-00000000abcd"],
            "reason": "TLS inspection enabled on the edge policy",
        }],
    }
    payload.update(overrides)
    return payload


def verify(writer) -> dict:
    response = writer.get("/api/security-controls/verify")
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Suite 3 — snapshot canonical-hash tests
# --------------------------------------------------------------------------- #

class TestSuite03SnapshotCanonicalHash:

    @pytest.mark.parametrize("field,value", [
        ("read_state", "PARTIAL_READ"), ("counts", {"assets": 99}), ("refusals", 7),
        ("controls", ["REWRITTEN"]), ("collector", "someone-else"),
    ])
    def test_editing_a_manifest_field_invalidates_the_chain(self, writer, session, field, value):
        from db.models.security_control import SecurityControlSnapshot

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        row = session.query(SecurityControlSnapshot).one()
        setattr(row, field, value)
        session.commit()
        result = verify(writer)
        assert result["verified"] is False
        assert any(p["code"] == "ENTRY_HASH_MISMATCH" for p in result["problems"])

    def test_the_body_digest_is_bound_not_just_the_digest_field(self, writer, session):
        from db.models.security_control import SecurityControlSnapshot

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        row = session.query(SecurityControlSnapshot).one()
        row.body_digest = "sha256:0000000000000000"
        session.commit()
        result = verify(writer)
        assert result["verified"] is False
        assert any(p["code"] == "ENTRY_HASH_MISMATCH" for p in result["problems"])

    def test_the_capture_time_is_bound(self, writer, session):
        from datetime import timedelta

        from db.models.security_control import SecurityControlSnapshot

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        row = session.query(SecurityControlSnapshot).one()
        row.captured_at = row.captured_at + timedelta(hours=3)
        session.commit()
        assert any(p["code"] == "ENTRY_HASH_MISMATCH"
                   for p in verify(writer)["problems"])

    def test_a_v1_history_row_verifies_under_its_own_scheme_and_is_never_upgraded(
            self, writer, session):
        from api.routers.security_controls import _entry_hash_v1
        from db.models.security_control import SecurityControlSnapshot

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        row = session.query(SecurityControlSnapshot).one()
        row.entry_hash = _entry_hash_v1(row)  # exactly what the pre-fix code would have stored
        session.commit()
        result = verify(writer)
        assert result["verified"] is True  # history verifies under the scheme it recorded
        assert result["head"] == row.entry_hash
        assert not result["head"].startswith("v2:")

    def test_new_writes_carry_the_manifest_scheme(self, writer, session):
        from db.models.security_control import SecurityControlSnapshot

        first = writer.post("/api/security-controls/snapshots",
                            json=snapshot_payload()).json()
        assert first["entry_hash"].startswith("v2:")
        row = session.query(SecurityControlSnapshot).one()
        assert len(row.entry_hash) <= 80  # the column holds the scheme tag and the digest


# --------------------------------------------------------------------------- #
# Suite 4 — child finding tampering tests
# --------------------------------------------------------------------------- #

class TestSuite04ChildFindingTampering:

    def test_editing_a_finding_state_invalidates_the_chain(self, writer, session):
        from db.models.security_control import SecurityControlFinding

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        session.query(SecurityControlFinding).one().state = "CONFIGURED"
        session.commit()
        result = verify(writer)
        assert result["verified"] is False
        assert any(p["code"] == "ENTRY_HASH_MISMATCH" for p in result["problems"])

    def test_editing_a_finding_reason_invalidates_the_chain(self, writer, session):
        from db.models.security_control import SecurityControlFinding

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        session.query(SecurityControlFinding).one().reason = "nothing to see here"
        session.commit()
        assert any(p["code"] == "ENTRY_HASH_MISMATCH"
                   for p in verify(writer)["problems"])

    def test_silently_swapping_evidence_ids_invalidates_the_chain(self, writer, session):
        from db.models.security_control import SecurityControlFinding

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        session.query(SecurityControlFinding).one().evidence_ids = ["EVID-FIREWALL-FORGED"]
        session.commit()
        result = verify(writer)
        assert result["verified"] is False
        assert any(p["code"] in {"ENTRY_HASH_MISMATCH", "EVIDENCE_NOT_FOUND"}
                   for p in result["problems"])

    def test_deleting_a_child_finding_is_visible(self, writer, session):
        from db.models.security_control import SecurityControlFinding

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        session.delete(session.query(SecurityControlFinding).one())
        session.commit()
        assert any(p["code"] == "ENTRY_HASH_MISMATCH"
                   for p in verify(writer)["problems"])

    def test_an_extra_finding_smuggled_in_invalidates_the_chain(self, writer, session):
        from db.models.security_control import (SecurityControlFinding,
                                                SecurityControlSnapshot)

        assert writer.post("/api/security-controls/snapshots",
                           json=snapshot_payload()).status_code == 200
        row = session.query(SecurityControlSnapshot).one()
        session.add(SecurityControlFinding(
            tenant_id=row.tenant_id, snapshot_id=row.id, control="FIREWALL",
            state="CONFIGURED", subject="FW-EDGE-02", kind="STATE",
            facts=["CONFIGURED"], evidence_ids=["EVID-FIREWALL-FORGED"]))
        session.commit()
        assert any(p["code"] == "ENTRY_HASH_MISMATCH"
                   for p in verify(writer)["problems"])


# --------------------------------------------------------------------------- #
# Suite 5 — evidence artifact digest verification
# --------------------------------------------------------------------------- #

class TestSuite05EvidenceArtifactDigest:

    def test_a_modified_artifact_is_a_mismatch_not_a_gap(self, writer, store):
        payload = writer._attach(snapshot_payload())
        assert writer.post("/api/security-controls/snapshots", json=payload).status_code == 200
        target = store / "_platform" / payload["body_location"]
        target.write_bytes(target.read_bytes() + b" ")
        response = writer.get("/api/security-controls/verify").json()
        assert response["verified"] is False
        assert response["evidence"]["mismatched"]
        assert any(p["code"] == "EVIDENCE_DIGEST_MISMATCH" for p in response["problems"])

    def test_a_missing_artifact_is_unverifiable_never_valid(self, writer, store):
        payload = writer._attach(snapshot_payload())
        assert writer.post("/api/security-controls/snapshots",
                           json=payload).status_code == 200
        (store / "_platform" / payload["body_location"]).unlink()
        response = writer.get("/api/security-controls/verify").json()
        assert response["verified"] is False
        assert response["evidence"]["unverifiable"]
        codes = {item["code"] for item in response["evidence"]["unverifiable"]}
        assert codes == {"EVIDENCE_UNVERIFIABLE"}

    def test_a_write_naming_an_absent_artifact_is_refused(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "not-written-yet.json"
        payload["body_digest"] = "sha256:0000000000000000"
        payload["body_bytes"] = 12
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["error"] == "evidence_unverifiable"
        assert detail["code"] == "EVIDENCE_ARTIFACT_MISSING"
        assert detail["stored"] is False

    def test_a_write_with_the_wrong_digest_is_refused(self, writer, store):
        payload = writer._attach(snapshot_payload())
        payload["body_digest"] = "sha256:ffffffffffffffff"
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "EVIDENCE_DIGEST_MISMATCH"

    def test_the_artifact_digest_is_checked_at_write_too(self, writer, store):
        payload = writer._attach(snapshot_payload())
        target = store / "_platform" / payload["body_location"]
        target.write_bytes(b"{}")  # a different body under the recorded name
        payload["body_bytes"] = 2
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "EVIDENCE_DIGEST_MISMATCH"


# --------------------------------------------------------------------------- #
# Suite 6 — cross-tenant evidence reference tests
# --------------------------------------------------------------------------- #

class TestSuite06CrossTenantEvidenceReference:

    def test_a_traversal_location_never_leaves_the_tenant_directory(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "../other-tenant/body.json"
        payload["body_digest"] = "sha256:0000000000000000"
        payload["body_bytes"] = 2
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "EVIDENCE_LOCATION_UNSAFE"

    def test_an_absolute_location_is_refused(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "/etc/passwd"
        payload["body_digest"] = "sha256:0000000000000000"
        payload["body_bytes"] = 2
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "EVIDENCE_LOCATION_UNSAFE"

    def test_another_tenants_artifact_does_not_resolve(self, writer, store, api, monkeypatch):
        # tenant A writes a real artifact and stores a snapshot against it
        payload_a = writer._attach(snapshot_payload("sha256:tenant-aaaa00001111"))
        assert writer.post("/api/security-controls/snapshots",
                           json=payload_a).status_code == 200
        # tenant B presents the same relative location: its own directory has no such body
        from api.routers import security_controls

        monkeypatch.setattr(security_controls, "current_tenant", lambda: "tenant-b")
        payload_b = snapshot_payload("sha256:tenant-bbbb00002222")
        payload_b["body_location"] = payload_a["body_location"]
        payload_b["body_digest"] = payload_a["body_digest"]
        payload_b["body_bytes"] = payload_a["body_bytes"]
        response = writer.post("/api/security-controls/snapshots", json=payload_b)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "EVIDENCE_ARTIFACT_MISSING"

    def test_verify_never_reads_another_tenants_directory(self, writer, store, monkeypatch):
        from api.routers import security_controls

        payload = writer._attach(snapshot_payload())
        assert writer.post("/api/security-controls/snapshots",
                           json=payload).status_code == 200
        monkeypatch.setattr(security_controls, "current_tenant", lambda: "tenant-b")
        response = verify(writer)
        # under tenant B the platform estate's artifact is absent — unverifiable, not valid
        assert response["verified"] is False
        assert response["evidence"]["unverifiable"]


# --------------------------------------------------------------------------- #
# Suite 7 — cross-snapshot and cross-asset evidence tests
# --------------------------------------------------------------------------- #

class TestSuite07CrossSnapshotAndCrossAssetEvidence:

    def test_an_id_that_exists_only_in_another_snapshots_body_does_not_resolve(self, writer):
        # snapshot 1 legitimately contains EVID-OTHER-1
        first = snapshot_payload("sha256:first-snapshot-0001",
                                controls=["SIEM"],
                                findings=[{"control": "SIEM", "state": "CONFIGURED",
                                           "subject": "splunk-01", "facts": ["CONFIGURED"],
                                           "evidence_ids": ["EVID-OTHER-1"],
                                           "reason": "correlation rules deployed"}])
        assert writer.post("/api/security-controls/snapshots", json=first).status_code == 200
        # snapshot 2 cites that id, but its own body does not contain it
        second = snapshot_payload("sha256:second-snapshot-0002")
        second["body_location"] = "second-body.json"
        records = [{"evidence_id": "EVID-FIREWALL-00000000abcd", "scheme": "v1",
                    "control": "FIREWALL", "vendor": "test-vendor", "system": "FW-EDGE-01",
                    "kind": "STATE", "identity": "FW-EDGE-01", "config_version": {}}]
        response = writer.post("/api/security-controls/snapshots", json=second,
                               records=records)
        assert response.status_code == 200  # its own id resolves; now swap in the foreign one
        third = snapshot_payload("sha256:third-snapshot-00033")
        third["findings"][0]["evidence_ids"] = ["EVID-OTHER-1"]
        third["body_location"] = "third-body.json"
        response = writer.post("/api/security-controls/snapshots", json=third,
                               records=records)
        assert response.status_code == 422
        assert any(p["code"] == "EVIDENCE_NOT_FOUND"
                   for p in response.json()["detail"]["problems"])

    def test_evidence_for_another_asset_cannot_support_the_finding(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "forged-body.json"
        records = [{"evidence_id": "EVID-FIREWALL-00000000abcd", "scheme": "v1",
                    "control": "FIREWALL", "vendor": "test-vendor",
                    "system": "FW-CORE-99",  # minted for a different device
                    "kind": "STATE", "identity": "policy:outbound-any",
                    "config_version": {}}]
        response = writer.post("/api/security-controls/snapshots", json=payload,
                               records=records)
        assert response.status_code == 422
        assert any(p["code"] == "EVIDENCE_SUBJECT_MISMATCH"
                   for p in response.json()["detail"]["problems"])

    def test_evidence_for_another_control_does_not_back_a_finding(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "cross-control-body.json"
        records = [{"evidence_id": "EVID-FIREWALL-00000000abcd", "scheme": "v1",
                    "control": "WAF", "vendor": "test-vendor", "system": "FW-EDGE-01",
                    "kind": "STATE", "identity": "FW-EDGE-01", "config_version": {}}]
        response = writer.post("/api/security-controls/snapshots", json=payload,
                               records=records)
        assert response.status_code == 422
        assert any(p["code"] == "EVIDENCE_CONTROL_MISMATCH"
                   for p in response.json()["detail"]["problems"])

    def test_an_observed_state_needs_an_observation_not_an_arbitrary_id(self, writer):
        payload = snapshot_payload()
        payload["findings"][0]["facts"] = ["CONFIGURED"]  # state is still OBSERVED
        response = writer.post("/api/security-controls/snapshots", json=payload)
        assert response.status_code == 422
        assert any(p["code"] == "FACT_CLASS_DOES_NOT_SUPPORT_STATE"
                   for p in response.json()["detail"]["problems"])

    def test_a_vendor_mismatch_is_provenance_not_a_detail(self, writer):
        payload = snapshot_payload()
        payload["body_location"] = "vendor-body.json"
        payload["findings"][0]["vendor"] = "OtherCorp"
        records = [{"evidence_id": "EVID-FIREWALL-00000000abcd", "scheme": "v1",
                    "control": "FIREWALL", "vendor": "test-vendor", "system": "FW-EDGE-01",
                    "kind": "STATE", "identity": "FW-EDGE-01", "config_version": {}}]
        response = writer.post("/api/security-controls/snapshots", json=payload,
                               records=records)
        assert response.status_code == 422
        assert any(p["code"] == "EVIDENCE_PROVENANCE_MISMATCH"
                   for p in response.json()["detail"]["problems"])


# --------------------------------------------------------------------------- #
# Suite 10 — concurrent snapshot sequence tests
# --------------------------------------------------------------------------- #

class TestSuite10ConcurrentSnapshotSequence:

    def test_concurrent_writers_allocate_gapless_unique_sequences(self, tmp_path, store,
                                                                  monkeypatch):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        import db.models  # noqa: F401
        from db.models.base import Base
        import db.models.security_control  # noqa: F401
        from db.models.user import AuditLog
        from api import dependencies
        from api.dependencies import TenantContext
        from api.routers import security_controls

        engine = create_engine(f"sqlite:///{tmp_path / 'controls.db'}",
                               connect_args={"timeout": 30})
        Base.metadata.create_all(engine, tables=[
            db.models.security_control.SecurityControlSnapshot.__table__,
            db.models.security_control.SecurityControlFinding.__table__,
            AuditLog.__table__,
        ])
        factory = sessionmaker(bind=engine)

        def fresh_session():
            session = factory()
            try:
                yield session
            finally:
                session.close()

        app = FastAPI()
        app.include_router(security_controls.router, prefix="/api")
        app.dependency_overrides[dependencies.get_db_session] = fresh_session
        app.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
            username="auditor", tenant_id=None, tenant_role="admin", is_platform_admin=True)
        monkeypatch.setattr(security_controls, "_service_identity",
                            lambda request, signature=None: {
                                "kind": "api_key", "id": "key-collector-1",
                                "signature_bound": False})
        client = CollectorClient(TestClient(app), store)

        results: list[tuple[int, int]] = []
        errors: list[str] = []

        def post(index: int) -> None:
            try:
                payload = snapshot_payload(f"sha256:concurrent-{index:04d}")
                response = client.post("/api/security-controls/snapshots", json=payload)
                if response.status_code != 200:
                    errors.append(f"{index}: {response.status_code} {response.text[:200]}")
                else:
                    body = response.json()
                    results.append((index, body["sequence"]))
            except Exception as exc:  # noqa: BLE001 — surfaced through errors, never swallowed
                errors.append(f"{index}: {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=post, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert not errors, errors
        sequences = sorted(sequence for _, sequence in results)
        # every writer got a sequence, none was duplicated, and the chain has no gaps
        assert sequences == list(range(1, 9))
        engine.dispose()
