"""Real SQLite scheduler ownership/fairness tests, never external HTTP."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from control_plane import delivery
from control_plane.notification_dispatch import drain_notifications
from db.connection.session import Base
from db.models.control_plane import Tenant
from db.models.enterprise import Integration
from db.models.monitor import MonitorEvent
from db.models.notification_delivery import NotificationDelivery
from db.tenancy import TenantScopeViolation, current_tenant, install_tenant_guard, tenant_scope
from worker import notifications as module
from worker.notifications import NotificationLoop, NotificationSettings

A = "00000000-0000-0000-0000-000000000001"
B = "00000000-0000-0000-0000-000000000002"
C = "00000000-0000-0000-0000-000000000003"
NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[4]


def settings(**kwargs):
    defaults = dict(NOTIFICATION_DISPATCH_ENABLED=True, NOTIFICATION_DISPATCH_PLATFORM=True,
                    NOTIFICATION_DISPATCH_REGION="us", ENVIRONMENT="test", DATABASE_URL="sqlite:///test.db")
    defaults.update(kwargs)
    return NotificationSettings(_env_file=None, **defaults)


@pytest.fixture
def database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/schedule.db")
    Base.metadata.create_all(engine)
    install_tenant_guard()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        session.add_all([Tenant(id=A, name="A", data_residency_region="us"),
                         Tenant(id=B, name="B", data_residency_region="us")])
        session.commit()
    yield factory
    engine.dispose()


def result(**kwargs):
    return {"ok": True, "delivered": 0, "failed": 0, "skipped": 0, "lease_lost": 0,
            "enqueued": 0, "destination_attempts": 0, "receipts": {}, **kwargs}


def test_disabled_scheduler_does_not_open_database():
    def forbidden():
        pytest.fail("disabled scheduler opened a database")

    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_ENABLED=False), session_factory=forbidden)
    assert loop.run_once() == {"enabled": False, "ok": False, "scopes_attempted": 0}
    assert loop.run_forever() == 2


@pytest.mark.parametrize("kwargs", [
    {"NOTIFICATION_DISPATCH_PLATFORM": False},
    {"NOTIFICATION_DISPATCH_TENANTS": [A], "NOTIFICATION_DISPATCH_REGION": " "},
    {"NOTIFICATION_DISPATCH_TENANTS": [A, A]},
    {"NOTIFICATION_DISPATCH_TENANTS": ["all"]},
    {"NOTIFICATION_DISPATCH_INTERVAL_SECONDS": 0},
    {"NOTIFICATION_DISPATCH_INTERVAL_SECONDS": float("nan")},
    {"NOTIFICATION_DISPATCH_BUDGET_SECONDS": float("inf")},
    {"NOTIFICATION_DISPATCH_SCOPE_BUDGET_SECONDS": 21},
    {"NOTIFICATION_DISPATCH_LIMIT": 201},
    {"NOTIFICATION_DISPATCH_LIMIT": 0},
    {"NOTIFICATION_DISPATCH_MAX_SCOPES": 0},
])
def test_unsafe_scheduler_configuration_is_rejected(kwargs):
    with pytest.raises(ValidationError):
        settings(**kwargs)


@pytest.mark.parametrize("url", ["sqlite:///test.db", "sqlite:///:memory:", "mysql://test/db", "not-a-url"])
def test_production_scheduler_fails_closed_without_postgres(url):
    with pytest.raises(RuntimeError):
        settings(ENVIRONMENT="production", DATABASE_URL=url).validate_runtime()


def test_scheduler_does_not_require_scan_credentials_and_redacts_database_url():
    config = settings(ENVIRONMENT="production", DATABASE_URL="postgresql://user:never-log-me@localhost/db")
    config.validate_runtime()
    assert "never-log-me" not in repr(config)
    assert "never-log-me" not in str(config)
    assert "never-log-me" not in str(config.redacted())


@pytest.mark.parametrize("url", ["sqlite://", "sqlite:///:memory:", "sqlite:///file:mem?mode=memory&uri=true"])
def test_scheduler_requires_durable_development_database(url):
    with pytest.raises(RuntimeError, match="durable"):
        settings(DATABASE_URL=url).validate_runtime()


def test_round_robin_is_bounded_and_restores_scope_with_fresh_sessions(database):
    visited, sessions = [], []

    def drain(session, **kwargs):
        visited.append(current_tenant())
        sessions.append(session)
        assert kwargs["limit"] == 7 and 0 < kwargs["budget_s"] <= 5
        assert not kwargs["should_stop"]()
        return result()

    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_TENANTS=[A, B], NOTIFICATION_DISPATCH_MAX_SCOPES=1,
                                     NOTIFICATION_DISPATCH_LIMIT=7), session_factory=database, drain=drain)
    for _ in range(4):
        assert loop.run_once()["scopes_completed"] == 1
        assert current_tenant() is None
    assert visited == [None, A, B, None]
    assert len({id(session) for session in sessions}) == 4


def test_hot_or_failed_scope_does_not_starve_later_scopes(database, caplog):
    now = [0.0]
    visited = []

    def drain(session, **kwargs):
        owner = current_tenant()
        visited.append(owner)
        now[0] += 21
        if owner is None:
            raise RuntimeError("credential https://private.example/never-log-this")
        return result()

    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_TENANTS=[A, B]),
                            session_factory=database, drain=drain, monotonic=lambda: now[0])
    assert loop.run_once()["scopes_failed"] == 1
    assert loop.run_once()["scopes_completed"] == 1
    assert loop.run_once()["scopes_completed"] == 1
    assert visited == [None, A, B]
    assert "never-log-this" not in caplog.text
    assert current_tenant() is None


@pytest.mark.parametrize("regions,region,active,exists", [
    (["eu"], "us", True, True),
    ([], "us", True, True),
    ("us", "us", True, True),
    ([1], "us", True, True),
    (None, "eu", True, True),
    (None, "us", False, True),
    (None, "us", True, False),
])
def test_inactive_unknown_or_region_denied_tenants_never_drain(database, regions, region, active, exists):
    with database() as session:
        tenant = session.get(Tenant, A)
        tenant.processing_regions, tenant.is_active = regions, active
        session.commit()
    calls = []
    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_PLATFORM=False,
                                     NOTIFICATION_DISPATCH_TENANTS=[A if exists else C],
                                     NOTIFICATION_DISPATCH_REGION=region), session_factory=database,
                            drain=lambda *a, **kw: calls.append(1))
    outcome = loop.run_once()
    assert not outcome["ok"] and outcome["scopes_blocked"] == 1 and not calls
    assert current_tenant() is None


def test_declared_processing_region_allows_active_tenant_and_rechecks_each_tick(database):
    with database() as session:
        session.get(Tenant, A).processing_regions = ["EU"]
        session.commit()
    calls = []

    def drain(session, **kwargs):
        calls.append(current_tenant())
        return result()

    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_PLATFORM=False, NOTIFICATION_DISPATCH_TENANTS=[A],
                                     NOTIFICATION_DISPATCH_REGION=" EU "), session_factory=database, drain=drain)
    assert loop.run_once()["ok"]
    with database() as session:
        session.get(Tenant, A).is_active = False
        session.commit()
    assert loop.run_once()["scopes_blocked"] == 1
    assert calls == [A]


def test_scheduler_refuses_tenant_context_instead_of_silently_elevating(database):
    loop = NotificationLoop(settings(), session_factory=database)
    with tenant_scope(A), pytest.raises(TenantScopeViolation, match="platform"):
        loop.run_once()
    assert current_tenant() is None


def test_scope_failures_close_sessions_and_do_not_block_next_scope(database):
    sessions = []

    def factory():
        session = database()
        sessions.append(session)
        return session

    def drain(session, **kwargs):
        session.scalar(select(Tenant.id).limit(1))
        if current_tenant() is None:
            raise RuntimeError("broken scope")
        return result(ok=False, lease_lost=1)

    outcome = NotificationLoop(settings(NOTIFICATION_DISPATCH_TENANTS=[A]),
                               session_factory=factory, drain=drain).run_once()
    assert not outcome["ok"] and outcome["scopes_failed"] == 1 and outcome["scopes_unconfirmed"] == 1
    assert all(not session.in_transaction() and not session.identity_map for session in sessions)


def test_stop_between_scopes_prevents_next_scope_and_interrupts_sleep(database):
    stop = threading.Event()
    calls = []

    def drain(session, **kwargs):
        calls.append(current_tenant())
        stop.set()
        return result()

    loop = NotificationLoop(settings(NOTIFICATION_DISPATCH_TENANTS=[A]), session_factory=database,
                            drain=drain, stop_event=stop)
    assert loop.run_forever() == 0
    assert calls == [None]
    assert loop.run_once()["scopes_attempted"] == 0


def seed_notification(factory, owner):
    with factory() as session:
        session.add(MonitorEvent(tenant_id=owner, event_type="remediation.task_verified", target_name="task",
                                 detail="verified", created_at=NOW))
        session.add(Integration(tenant_id=owner, name="SOC", kind="siem", provider="webhook",
                                enabled=True, endpoint="https://soc.example/receive", config={}))
        session.commit()


def test_real_receipt_drain_is_tenant_exact_and_shared_by_scheduler_replicas(database, monkeypatch):
    for owner in (None, A, B):
        seed_notification(database, owner)
    posts = []
    monkeypatch.setattr(delivery, "validate_webhook_url", lambda url: url)
    monkeypatch.setattr(delivery, "_http_post", lambda *a, **kw: (posts.append(kw) or (202, "accepted")))
    config = settings(NOTIFICATION_DISPATCH_PLATFORM=False, NOTIFICATION_DISPATCH_TENANTS=[A])
    assert NotificationLoop(config, session_factory=database).run_once()["delivered"] == 1
    assert NotificationLoop(config, session_factory=database).run_once()["destination_attempts"] == 0
    with database() as session:
        receipts = session.scalars(select(NotificationDelivery)).all()
        assert len(receipts) == 1 and receipts[0].tenant_id == A and receipts[0].status == "delivered"
    assert len(posts) == 1 and len(posts[0]["headers"]["Idempotency-Key"]) == 64


def test_scheduler_retries_due_failure_without_manual_api_or_early_resend(database, monkeypatch):
    seed_notification(database, None)
    now = [NOW]
    posts = []
    monkeypatch.setattr(delivery, "validate_webhook_url", lambda url: url)

    def send(*args, **kwargs):
        posts.append(kwargs)
        return (503, "unavailable") if len(posts) == 1 else (200, "accepted")

    monkeypatch.setattr(delivery, "_http_post", send)
    loop = NotificationLoop(settings(), session_factory=database,
                            drain=lambda session, **kwargs: drain_notifications(session, clock=lambda: now[0], **kwargs))
    first = loop.run_once()
    assert first["failed"] == 1 and not first["ok"] and first["observed_pending_receipts"] == 1
    assert loop.run_once()["destination_attempts"] == 0
    now[0] += timedelta(seconds=61)
    assert loop.run_once()["delivered"] == 1
    assert posts[0]["headers"]["Idempotency-Key"] == posts[1]["headers"]["Idempotency-Key"]


def test_cli_disabled_and_invalid_configuration_do_not_initialize_database(monkeypatch):
    monkeypatch.setattr(module, "_initialize", lambda *_: pytest.fail("opened database"))
    monkeypatch.setenv("NOTIFICATION_DISPATCH_ENABLED", "false")
    assert module.main(["--once"]) == 2
    monkeypatch.setenv("NOTIFICATION_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("NOTIFICATION_DISPATCH_PLATFORM", "false")
    monkeypatch.setenv("NOTIFICATION_DISPATCH_TENANTS", "[]")
    assert module.main(["--once"]) == 2


def test_cli_one_shot_rejects_multi_estate_starvation_before_database_init(monkeypatch):
    monkeypatch.setattr(module, "NotificationSettings", lambda: settings(NOTIFICATION_DISPATCH_TENANTS=[A]))
    monkeypatch.setattr(module, "_initialize", lambda *_: pytest.fail("opened database"))
    assert module.main(["--once"]) == 2


@pytest.mark.parametrize("ok,code", [(True, 0), (False, 1)])
def test_cli_one_shot_exit_status_disposal_and_signal_restoration(monkeypatch, capsys, ok, code):
    import signal

    disposed = []
    handlers = {signal.SIGINT: object(), signal.SIGTERM: object()}
    originals = dict(handlers)

    def set_signal(sig, handler):
        previous, handlers[sig] = handlers[sig], handler
        return previous

    monkeypatch.setattr(signal, "signal", set_signal)
    monkeypatch.setattr(module, "NotificationSettings", lambda: settings())
    monkeypatch.setattr(module, "_initialize", lambda _: SimpleNamespace(dispose=lambda: disposed.append(True)))
    monkeypatch.setattr(module, "NotificationLoop", lambda *a, **kw: SimpleNamespace(
        request_stop=lambda *a: None, run_once=lambda: {"ok": ok, "enabled": True}))
    assert module.main(["--once"]) == code
    assert json.loads(capsys.readouterr().out)["ok"] == ok
    assert disposed == [True] and handlers == originals


def test_initialization_propagates_production_mode_and_disposes_on_migration_failure(monkeypatch):
    import db.connection.engine as engines
    import db.connection.session as sessions

    disposed = []
    engine = SimpleNamespace(dispose=lambda: disposed.append(True))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setattr(engines, "create_db_engine", lambda *a, **kw: engine)

    def fail(actual):
        assert actual is engine and os.environ["ENVIRONMENT"] == "production"
        raise RuntimeError("database migrations behind")

    monkeypatch.setattr(sessions, "init_db", fail)
    with pytest.raises(RuntimeError, match="migrations"):
        module._initialize(settings(ENVIRONMENT="production", DATABASE_URL="postgresql://localhost/test"))
    assert disposed == [True]


def test_repository_script_bootstraps_without_ambient_pythonpath():
    env = {**os.environ, "PYTHONPATH": "", "NOTIFICATION_DISPATCH_ENABLED": "false"}
    completed = subprocess.run([sys.executable, str(ROOT / "scripts/run_notifications.py"), "--help"],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0 and "--once" in completed.stdout
    completed = subprocess.run([sys.executable, str(ROOT / "scripts/run_notifications.py"), "--once"],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 2 and "notification_scheduler_disabled" in completed.stderr


def test_compose_scheduler_is_separate_opt_in_and_production_migration_gated():
    import yaml

    base = yaml.load((ROOT / "docker-compose.yml").read_text(), Loader=yaml.BaseLoader)["services"]["notifications"]
    prod = yaml.load((ROOT / "docker-compose.prod.yml").read_text(), Loader=yaml.BaseLoader)["services"]["notifications"]
    assert base["profiles"] == ["notifications"]
    assert base["command"] == ["python", "scripts/run_notifications.py"]
    assert base["environment"]["NOTIFICATION_DISPATCH_ENABLED"] == "${NOTIFICATION_DISPATCH_ENABLED:-false}"
    assert base["environment"]["NOTIFICATION_DISPATCH_PLATFORM"] == "${NOTIFICATION_DISPATCH_PLATFORM:-false}"
    assert "redis" not in base["depends_on"] and "neo4j" not in base["depends_on"]
    assert prod["environment"]["ENVIRONMENT"] == "production"
    assert prod["depends_on"]["migrate"]["condition"] == "service_completed_successfully"


def test_enabled_repository_cli_runs_one_bounded_empty_tick_on_disposable_sqlite(tmp_path):
    env = {**os.environ, "PYTHONPATH": "", "ENVIRONMENT": "test",
           "DATABASE_URL": f"sqlite:///{tmp_path}/empty.db",
           "NOTIFICATION_DISPATCH_ENABLED": "true", "NOTIFICATION_DISPATCH_PLATFORM": "true",
           "NOTIFICATION_DISPATCH_TENANTS": "[]"}
    completed = subprocess.run([sys.executable, str(ROOT / "scripts/run_notifications.py"), "--once"],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=45)
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)
    assert outcome["scopes_completed"] == 1 and outcome["destination_attempts"] == 0
    assert outcome["observed_pending_receipts"] == 0


def test_scheduler_cli_quiets_full_url_client_logs(monkeypatch):
    import logging

    for name in ("httpx", "httpcore"):
        monkeypatch.setattr(logging.getLogger(name), "level", logging.INFO)
    monkeypatch.setenv("NOTIFICATION_DISPATCH_ENABLED", "false")
    assert module.main(["--once"]) == 2
    assert all(logging.getLogger(name).level == logging.WARNING for name in ("httpx", "httpcore"))
