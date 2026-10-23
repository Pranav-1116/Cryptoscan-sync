"""Current operating assessment must not promote future/historical assertions.

Synthetic authenticated users only; no real roster, support or alert delivery.
"""
from datetime import timedelta
import pytest
from api.assurance import launch
from db.models.base import utcnow
from test_assurance_workflows import assured as assured, banks as banks, blob, done
from test_launch_readiness import fill_operating_duties, P


def test_clock_rollback_does_not_reuse_future_reviewed_operating_success(assured, monkeypatch):
    clients, db, _ = assured
    a = clients["bank_a"]
    fill_operating_duties(clients, db, blob(a))
    assert done(a.get(P + "/operations"), 200)["all_owner_reviewed_records_current"] is True
    monkeypatch.setattr(launch, "utcnow", lambda: utcnow() - timedelta(hours=1))
    result = done(a.get(P + "/operations"), 200)
    assert result["all_owner_reviewed_records_current"] is False
    assert all("EXERCISE_FAILED_UNREVIEWED_OR_STALE" in row["issues"] for row in result["duties"])
    assert result["sla_authorized"] is False


def test_historical_review_survives_current_exercise_expiry(assured, monkeypatch):
    clients, db, _ = assured
    a = clients["bank_a"]
    fill_operating_duties(clients, db, blob(a))
    before = done(a.get(P + "/operations"), 200)
    monkeypatch.setattr(launch, "utcnow", lambda: utcnow() + timedelta(hours=2))
    after = done(a.get(P + "/operations"), 200)
    assert not after["all_owner_reviewed_records_current"]
    for old, current in zip(before["duties"], after["duties"]):
        assert current["exercise"] == old["exercise"]
        assert current["exercise"]["payload"]["state"] == "REVIEWED_EXERCISE_ASSERTION"
        assert "EXERCISE_FAILED_UNREVIEWED_OR_STALE" in current["issues"]
