"""Alert routing: CEF formatting, signed webhook, honest skip, loop safety."""

from __future__ import annotations


from worker.monitor.alerting import AlertRouter, format_cef


class _Settings:
    def __init__(self, **kwargs):
        self.ALERT_CEF_HOST = ""
        self.ALERT_CEF_PORT = 514
        self.ALERT_WEBHOOK_URL = ""
        self.ALERT_WEBHOOK_SECRET = ""
        self.SMTP_HOST = ""
        self.ALERT_EMAIL_FROM = "alerts@test"
        self.ALERT_EMAIL_TO = "soc@test"
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_cef_line_shape():
    line = format_cef(target="bank-gateway", issue="WEAK_TLS_VERSION:h:443")
    assert line.startswith("CEF:0|CryptoScan|LiveMonitor|1.0|MONITOR_ALERT|")
    assert "target=bank-gateway" in line
    assert "issue=WEAK_TLS_VERSION:h:443" in line


def test_no_sinks_is_honest_noop():
    router = AlertRouter(settings=_Settings())
    assert router.dispatch(target="t", issue="i") == {}


def test_webhook_sink_signs_and_posts():
    posted = []

    def fake_post(url, body, headers):
        posted.append((url, body, headers))

    settings = _Settings(ALERT_WEBHOOK_URL="https://soc.example/hook", ALERT_WEBHOOK_SECRET="s3cret")
    router = AlertRouter(settings=settings, post=fake_post)
    outcome = router.dispatch(target="hsm-1", issue="PAY-001", payload={"severity": 5})
    assert outcome == {"webhook": "sent"}
    url, body, headers = posted[0]
    assert url == "https://soc.example/hook"
    assert body["target"] == "hsm-1"
    assert headers["X-CryptoScan-Signature"].startswith("sha256=")
    assert len(headers["X-CryptoScan-Signature"]) == 71  # prefix + 64 hex


def test_cef_and_email_sinks():
    cef_lines = []
    emails = []
    settings = _Settings(ALERT_CEF_HOST="siem.bank", ALERT_CEF_PORT=514, SMTP_HOST="smtp.bank")
    router = AlertRouter(settings=settings,
                         send_cef=cef_lines.append, send_email=lambda s, b: emails.append((s, b)))
    outcome = router.dispatch(target="edge", issue="UNREACHABLE:h:443")
    assert outcome == {"cef": "sent", "email": "sent"}
    assert cef_lines[0].startswith("CEF:0|CryptoScan|")
    assert "[CryptoScan ALERT] edge" in emails[0][0]


def test_failing_sink_never_raises():
    def boom(url, body, headers):
        raise RuntimeError("siem down")

    settings = _Settings(ALERT_WEBHOOK_URL="https://x")
    router = AlertRouter(settings=settings, post=boom)
    outcome = router.dispatch(target="t", issue="i")  # must not raise
    assert outcome["webhook"].startswith("failed:")


def test_engine_alert_hook_dispatches_once_per_new_issue():
    """Engine integration: the on_alert callback fires for new issues only."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import db.models  # noqa: F401
    from db.connection.session import Base
    from db.models.monitor import MonitorTarget
    from worker.monitor.engine import MonitorEngine

    engine_db = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                              poolclass=StaticPool)
    Base.metadata.create_all(engine_db)
    session = sessionmaker(bind=engine_db, expire_on_commit=False)()

    t0 = datetime(2026, 8, 30, tzinfo=timezone.utc)
    session.add(MonitorTarget(name="edge", target_type="NETWORK",
                              config={"endpoints": ["dead:1"]}, interval_seconds=900,
                              next_scan_at=t0 - timedelta(seconds=1)))
    session.commit()

    fired = []

    def runner(config, session_arg):
        return {"observation_complete": False, "summary": {"issues": ["UNREACHABLE:dead:1"]}, "degraded": True,
                "issues": ["UNREACHABLE:dead:1"]}

    monitor = MonitorEngine(session, runners={"NETWORK": runner}, clock=lambda: t0,
                            on_alert=lambda target, issue, payload: fired.append((target, issue)))
    first = monitor.tick()
    session.commit()
    assert fired == [("edge", "OBSERVATION_INCOMPLETE"), ("edge", "UNREACHABLE:dead:1")]
    assert first["results"][0]["new_issues"] == ["OBSERVATION_INCOMPLETE", "UNREACHABLE:dead:1"]

    fired.clear()
    target = session.query(MonitorTarget).one()
    target.next_scan_at = t0 + timedelta(seconds=1)  # due again, same issue
    session.commit()
    monitor2 = MonitorEngine(session, runners={"NETWORK": runner}, clock=lambda: t0 + timedelta(seconds=2),
                             on_alert=lambda target, issue, payload: fired.append((target, issue)))
    monitor2.tick()
    session.commit()
    assert fired == []  # steady state: no re-alert, no re-dispatch
