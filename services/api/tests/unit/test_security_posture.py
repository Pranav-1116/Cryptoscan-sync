"""Security-posture aggregator: build_security_posture over a real in-memory DB.

Seeds a small but representative store (one healthy agent, one signed+active
plugin, one critical open anomaly flag, one valid certificate, one active
credential, no audit trail) and asserts the aggregator counts them honestly.
Also asserts that a zero-data store reads low (never a fabricated green).

Runs against an in-memory SQLite with the full ORM metadata so the query paths
(list_agents / list_credentials / PluginPackage / AnomalyFlag / Certificate /
AuditLog) are exercised exactly as in production.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from db.models.base import Base
from db.models.control_plane import Agent, CredentialRef
from db.models.p2 import AnomalyFlag, PluginPackage
from db.models.certificate import Certificate


def _engine():
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _seed(session: Session) -> None:
    now = datetime.now(timezone.utc)
    # one healthy agent
    session.add(Agent(name="edge-1", region="us-east", healthy=True, status="connected"))
    # one signed + active plugin (signature present, not quarantined)
    session.add(PluginPackage(
        plugin_id="p1", version="1.0.0", plugin_type="scanner", name="nmap",
        content_sha256="abcd", signature="c2ln", state="ACTIVE", trusted=True,
    ))
    # one critical open anomaly flag
    session.add(AnomalyFlag(rule="z-score", severity="CRITICAL", status="OPEN"))
    # one valid certificate (expires in a year -> not expired, not expiring)
    session.add(Certificate(
        fingerprint_sha256="f1", subject="CN=example", not_after=now + timedelta(days=365),
        days_until_expiry=365, expiry_status="VALID", revocation_status="NOT_REVOKED",
        renewal_status="NONE", is_self_signed=False,
    ))
    # one active credential
    session.add(CredentialRef(name="vault-a", secret_ref="vault://a", status="active", health_ok=True))
    session.commit()


def test_build_security_posture_counts_real_signals():
    from control_plane.security_posture import build_security_posture

    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        _seed(session)
        posture = build_security_posture(session)

    assert posture["agents_total"] == 1
    assert posture["agents_healthy"] == 1
    assert posture["plugins_total"] == 1
    assert posture["plugins_verified"] == 1
    assert posture["threats_open"] == 1
    assert posture["threats_critical"] == 1
    assert posture["cert_total"] == 1
    assert posture["cert_valid_pct"] == 100
    assert posture["failed_logins"] == 0
    assert posture["credentials_total"] == 1
    assert posture["credentials_active"] == 1
    # no audit trail was written -> the integrity signal is not green
    assert posture["audit_ok"] is False
    assert posture["components"]["audit"]["value"] == 0.0
    # a populated (but audit-less) store must still read above zero honestly
    assert posture["score"] > 0


def test_build_security_posture_unprovisioned_reads_low():
    from control_plane.security_posture import build_security_posture

    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        posture = build_security_posture(session)

    # empty store: 0 agents/plugins/certs/credentials, no audit trail, no flags
    assert posture["agents_total"] == 0
    assert posture["plugins_total"] == 0
    assert posture["cert_total"] == 0
    assert posture["credentials_total"] == 0
    assert posture["threats_open"] == 0
    assert posture["audit_ok"] is False
    # honest-low: an unprovisioned store is never near-green (it can only earn
    # the small "no failed logins" + "no open threats" credit, i.e. ~0.30).
    assert posture["score"] <= 35
