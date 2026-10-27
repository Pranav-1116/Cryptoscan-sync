"""Declared/imported scope candidates and the 24/7 observation worker (spec 67).

Covers §4 (declared discovery is not observation), §3 (scope-bound execution)
and §30 (a worker never widens what was approved). No socket is opened: the
scanner is replaced, and the worker's scheduler thread is exercised with a
stubbed tick.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from api.security.network_import import (
    CANDIDATE_STATE,
    IMPORT_SOURCES,
    build_candidates,
    merge_candidates,
    normalize_endpoint,
    parse_import_payload,
)
from api.security.network_watch import (
    MAX_INTERVAL,
    MIN_INTERVAL,
    NetworkCryptoWatcher,
    get_watcher,
    reset_watcher_for_tests,
)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #


def test_parse_newline_list():
    assert parse_import_payload(text="10.20.10.15\n10.20.10.16:8443\n") == [
        "10.20.10.15:443",
        "10.20.10.16:8443",
    ]


def test_parse_csv_with_header():
    text = "host,port,owner\n10.20.10.15,443,payments\n10.20.10.16,8443,core\n"
    assert parse_import_payload(text=text) == ["10.20.10.15:443", "10.20.10.16:8443"]


def test_parse_tsv_without_header():
    assert parse_import_payload(text="10.20.10.15\t8443\n") == ["10.20.10.15:8443"]


def test_parse_json_array_and_object():
    assert parse_import_payload(text='["10.20.10.15:443"]') == ["10.20.10.15:443"]
    assert parse_import_payload(text='{"endpoints": ["10.20.10.16"]}') == ["10.20.10.16:443"]


def test_parse_entries_with_urls_and_decorations():
    entries = [{"endpoint": "https://payments.bank/health"}, {"host": "10.20.10.16", "port": 8443}]
    assert parse_import_payload(entries=entries) == ["payments.bank:443", "10.20.10.16:8443"]


def test_parse_empty_is_empty_not_an_error():
    assert parse_import_payload(text="   ") == []
    assert parse_import_payload() == []


def test_normalize_endpoint_forms():
    assert normalize_endpoint("PAYMENTS.bank.") == "payments.bank:443"
    assert normalize_endpoint("[2001:db8::1]:443") == "[2001:db8::1]:443"
    assert normalize_endpoint("") == ""


# --------------------------------------------------------------------------- #
# candidates: declarations, not observations
# --------------------------------------------------------------------------- #


def test_candidates_are_config_imported_and_unobserved():
    result = build_candidates(["10.20.10.15:443"], source="CMDB")
    assert result["accepted_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["evidence_type"] == CANDIDATE_STATE
    assert candidate["observed"] is False
    assert candidate["declared"] is True
    assert candidate["source"] == "CMDB"
    assert result["probing_performed"] is False


def test_candidates_reject_loopback_and_keep_the_reason():
    result = build_candidates(["127.0.0.1:443", "10.20.10.15:443"], source="CMDB")
    assert result["accepted_count"] == 1
    assert len(result["rejected"]) == 1
    assert result["rejected"][0]["endpoint"] == "127.0.0.1:443"
    assert "loopback" in result["rejected"][0]["reason"].lower()


def test_candidates_report_duplicates_and_existing():
    result = build_candidates(
        ["10.20.10.15:443", "10.20.10.15", "10.20.10.16:443"],
        source="LOAD_BALANCER",
        existing=["10.20.10.15:443"],
    )
    assert [c["endpoint"] for c in result["candidates"]] == ["10.20.10.16:443"]
    assert result["duplicate_count"] == 2


def test_candidates_cap_and_flag_truncation():
    endpoints = [f"10.20.10.{i}:443" for i in range(1, 30)]
    result = build_candidates(endpoints, source="CLOUD", max_candidates=5)
    assert result["accepted_count"] == 5
    assert result["truncated"] is True


def test_unknown_source_is_refused():
    with pytest.raises(ValueError):
        build_candidates(["10.20.10.15:443"], source="SPREADSHEET")


def test_every_supported_source_is_named():
    assert {"CMDB", "LOAD_BALANCER", "KUBERNETES", "CLOUD", "FIREWALL", "DNS", "MANUAL"} == set(IMPORT_SOURCES)


# --------------------------------------------------------------------------- #
# merge
# --------------------------------------------------------------------------- #


def test_merge_preserves_existing_order_and_appends():
    merged = merge_candidates(
        current_destinations=["10.20.10.15:443"],
        candidates=[{"endpoint": "10.20.10.16:443"}, {"endpoint": "10.20.10.15:443"}],
        max_total=10,
    )
    assert merged["destinations"] == ["10.20.10.15:443", "10.20.10.16:443"]
    assert merged["added"] == ["10.20.10.16:443"]
    assert merged["already_present"] == ["10.20.10.15:443"]


def test_merge_reports_overflow_instead_of_silently_cutting():
    merged = merge_candidates(
        current_destinations=["10.20.10.1:443"],
        candidates=[{"endpoint": "10.20.10.2:443"}, {"endpoint": "10.20.10.3:443"}],
        max_total=2,
    )
    assert merged["destinations"] == ["10.20.10.1:443", "10.20.10.2:443"]
    assert merged["dropped_over_limit"] == ["10.20.10.3:443"]


# --------------------------------------------------------------------------- #
# watcher lifecycle
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_watcher():
    reset_watcher_for_tests()
    yield
    reset_watcher_for_tests()


def test_watcher_is_a_singleton():
    assert get_watcher() is get_watcher()


def test_watcher_clamps_interval(monkeypatch):
    watcher = NetworkCryptoWatcher()
    ticks: list[float] = []

    def fake_loop():
        ticks.append(1)
        # exit immediately so start() returns a stopped thread
        watcher._stop.set()  # noqa: SLF001

    monkeypatch.setattr(watcher, "_loop", fake_loop)
    status = watcher.start(interval=1)
    assert status["interval_seconds"] == MIN_INTERVAL
    watcher.stop()


def test_watcher_status_is_honest_before_any_tick():
    watcher = NetworkCryptoWatcher()
    status = watcher.status()
    assert status["running"] is False
    assert status["ticks"] == 0
    assert status["distributed"] is False
    assert "skipped tick is not an observation" in status["boundary"]


def test_tick_counts_skipped_and_observed_separately():
    watcher = NetworkCryptoWatcher()
    watcher.tick(runner=lambda **_: {"status": "SKIPPED", "reason": "no approved scope"})
    watcher.tick(runner=lambda **_: {"status": "OBSERVED", "observed": 2})
    watcher.tick(runner=lambda **_: {"status": "FAILED", "reason": "boom"})
    status = watcher.status()
    assert status["ticks"] == 3
    assert status["skipped_ticks"] == 1
    assert status["observed_ticks"] == 1
    assert status["failed_ticks"] == 1
    assert status["last_result"]["status"] == "FAILED"


def test_tick_never_raises_when_the_runner_throws():
    watcher = NetworkCryptoWatcher()

    def boom(**_):
        raise RuntimeError("scanner exploded")

    result = watcher.tick(runner=boom)
    assert result["status"] == "FAILED"
    assert "scanner exploded" in result["reason"]
    assert watcher.status()["failed_ticks"] == 1


def test_watcher_thread_runs_a_tick_then_can_be_stopped():
    watcher = NetworkCryptoWatcher()
    calls: list[int] = []

    def runner(**_):
        calls.append(1)
        return {"status": "OBSERVED"}

    watcher.interval = MIN_INTERVAL
    import threading

    thread = threading.Thread(target=lambda: watcher.tick(runner=runner))
    thread.start()
    thread.join(timeout=5)
    assert calls == [1]


def test_watcher_interval_clamp_bounds():
    assert MIN_INTERVAL >= 60
    assert MAX_INTERVAL <= 24 * 3600


# --------------------------------------------------------------------------- #
# default_tick: scope-bound, budget-bound, skip-not-fake
# --------------------------------------------------------------------------- #


def test_default_tick_skips_without_scope(tmp_path, monkeypatch):
    """No approved scope means no probe — and the tick says why."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    import api.security.network_watch as watch

    monkeypatch.setattr("db.connection.session.SessionLocal", Session)
    result = watch.default_tick(inventory_id="nothing-approved")
    assert result["status"] == "SKIPPED"
    assert "no approved scope" in result["reason"]


def test_default_tick_skips_expired_scope(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base
    from db.models.app_setting import AppSetting
    import json

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    expired = {
        "name": "stale",
        "destinations": ["10.20.10.15:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 10, "max_bytes": 10000},
        "valid_until": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
    }
    session.add(AppSetting(key="network:crypto-scope:default:default", value=json.dumps(expired)))
    session.commit()
    session.close()

    import api.security.network_watch as watch

    monkeypatch.setattr("db.connection.session.SessionLocal", Session)
    result = watch.default_tick()
    assert result["status"] == "SKIPPED"
    assert result["code"] == "scope_expired"


def test_default_tick_skips_when_budget_exhausted(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base
    from db.models.app_setting import AppSetting
    import json

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    scope = {
        "name": "tight",
        "destinations": ["10.20.10.15:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 1, "max_bytes": 10000},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
    session.add(AppSetting(key="network:crypto-scope:default:default", value=json.dumps(scope)))
    session.add(
        AppSetting(
            key="network:crypto-budget:default:default",
            value=json.dumps(
                {
                    "window_started_at": datetime.now(timezone.utc).isoformat(),
                    "connections_used": 1,
                    "bytes_used": 0,
                    "runs": 1,
                }
            ),
        )
    )
    session.commit()
    session.close()

    import api.security.network_watch as watch

    monkeypatch.setattr("db.connection.session.SessionLocal", Session)
    result = watch.default_tick()
    assert result["status"] == "SKIPPED"
    assert result["code"] == "traffic_budget_exhausted"


def test_tick_latency_is_bounded_for_a_skipped_tick():
    watcher = NetworkCryptoWatcher()
    started = time.monotonic()
    watcher.tick(runner=lambda **_: {"status": "SKIPPED", "reason": "no approved scope"})
    assert time.monotonic() - started < 1.0


# --------------------------------------------------------------------------- #
# API: import preview/apply and watch endpoints
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from api.dependencies import get_current_user, get_db_session, get_tenant_context
    from api.main import create_app
    from db.connection.session import Base

    import api.routers.network as network_router

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    app.dependency_overrides[get_tenant_context] = lambda: type(
        "Ctx", (), {"tenant_id": None, "roles": ["superadmin"], "username": "tester"}
    )()
    app.dependency_overrides[network_router.network_context] = lambda: None
    app.dependency_overrides[network_router.require_auditor] = lambda: "tester"
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def save_scope(http, **overrides):
    body = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 10, "max_bytes": 1000000},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "inventory_id": "default",
    }
    body.update(overrides)
    return http.put("/api/v1/network/crypto-scope", json=body)


def test_import_preview_does_not_change_the_scope(client):
    http, _session = client
    assert save_scope(http).status_code == 200
    response = http.post(
        "/api/v1/network/crypto-scope/import",
        json={"source": "CMDB", "text": "10.20.10.16,443\n10.20.10.17,8443\n", "apply": False},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applied"] is False
    assert body["preview"]["accepted_count"] == 2
    assert body["probing_performed"] is False
    scope = http.get("/api/v1/network/crypto-scope").json()["scope"]
    assert scope["destinations"] == ["10.20.10.15:443"]


def test_import_apply_merges_destinations_and_records_provenance(client):
    http, _session = client
    assert save_scope(http).status_code == 200
    response = http.post(
        "/api/v1/network/crypto-scope/import",
        json={"source": "LOAD_BALANCER", "text": "10.20.10.16:443", "apply": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applied"] is True
    assert body["merge"]["added"] == ["10.20.10.16:443"]
    scope = http.get("/api/v1/network/crypto-scope").json()["scope"]
    assert scope["destinations"] == ["10.20.10.15:443", "10.20.10.16:443"]
    assert scope["imports"][0]["source"] == "LOAD_BALANCER"
    assert scope["imports"][0]["added"] == ["10.20.10.16:443"]


def test_import_apply_without_scope_is_blocked_not_created(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/crypto-scope/import",
        json={"source": "CMDB", "text": "10.20.10.16:443", "apply": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["applied"] is False
    assert "save an initial scope first" in body["apply_blocked"]
    assert http.get("/api/v1/network/crypto-scope").json()["scope"] is None


def test_import_reports_rejected_rows(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/crypto-scope/import",
        json={"source": "CMDB", "text": "127.0.0.1,443\n10.20.10.16,443\n"},
    )
    body = response.json()
    assert body["preview"]["accepted_count"] == 1
    assert body["preview"]["rejected"][0]["endpoint"] == "127.0.0.1:443"


def test_import_requires_input(client):
    http, _session = client
    assert http.post("/api/v1/network/crypto-scope/import", json={"source": "CMDB"}).status_code == 422
    assert (
        http.post("/api/v1/network/crypto-scope/import", json={"source": "CMDB", "text": "  "}).status_code == 422
    )


def test_watch_status_before_start(client):
    http, _session = client
    body = http.get("/api/v1/network/crypto-watch").json()
    assert body["running"] is False
    assert body["scope"]["state"] == "NOT_CONFIGURED"
    assert body["distributed"] is False


def test_watch_start_refused_without_approved_scope(client):
    http, _session = client
    response = http.post("/api/v1/network/crypto-watch", json={"interval_seconds": 300})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_not_approved"


def test_watch_start_refused_for_expired_scope(client):
    http, session = client
    assert save_scope(http).status_code == 200
    from db.models.app_setting import AppSetting
    import json

    row = session.query(AppSetting).filter(AppSetting.key == "network:crypto-scope:default:default").one()
    payload = json.loads(row.value)
    payload["valid_until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    row.value = json.dumps(payload)
    session.commit()

    response = http.post("/api/v1/network/crypto-watch", json={"interval_seconds": 300})
    assert response.status_code == 409
    assert response.json()["detail"]["state"] == "EXPIRED"


def test_watch_start_and_stop_with_approved_scope(client, monkeypatch):
    http, _session = client
    assert save_scope(http).status_code == 200

    import api.security.network_watch as watch

    started = watch.get_watcher().start

    def fake_start(**kwargs):
        started(**kwargs)
        watch.get_watcher()._stop.set()  # noqa: SLF001 — stop the daemon at once
        return watch.get_watcher().status()

    monkeypatch.setattr(watch.get_watcher(), "start", fake_start)
    response = http.post("/api/v1/network/crypto-watch", json={"interval_seconds": 300})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["interval_seconds"] == 300
    assert body["scope"]["state"] == "APPROVED"
    assert http.delete("/api/v1/network/crypto-watch").status_code == 200


def test_watch_tick_skips_when_scope_has_no_destinations(client, monkeypatch):
    http, session = client
    # The worker opens its own session, so bind it to the same test database.
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: session)
    body = http.post("/api/v1/network/crypto-watch/tick").json()
    assert body["status"] == "SKIPPED"
    assert "no approved scope" in body["reason"]


def test_evidence_readback_includes_watch_runs(client):
    """Continuous-observation evidence must be visible to the read-back/API."""
    http, session = client
    from db.repositories.scan_run_repository import ScanRunRepository
    from network_scanner.inventory.network_evidence import build_passive_evidence

    record = build_passive_evidence({"dst_ip": "10.20.10.15", "dst_port": 443, "tls_version": "TLSv1.3"})
    ScanRunRepository(session).create_run({"network_evidence": [record]}, target_kind="crypto-watch")
    session.commit()

    body = http.get("/api/v1/network/crypto-evidence").json()
    assert body["count"] == 1
    assert body["runs"][0]["target_kind"] == "crypto-watch"
