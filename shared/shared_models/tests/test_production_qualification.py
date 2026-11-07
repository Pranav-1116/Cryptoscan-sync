"""Phase-6 production-qualification register tests.

Seven of the eight activities happen outside this repository: the platform
cannot be their performer and synthetic evidence never qualifies them. The
eighth (large-estate synthetic testing) files synthetic results that stay
labelled synthetic and never read as production qualification."""

from __future__ import annotations

import pytest

from shared_models.production_qualification import (
    ACTIVITIES, BANK_PILOT_ACCEPTANCE, BACKUP_RESTORE_DRILL,
    HA_DISASTER_RECOVERY_TESTING, LARGE_ESTATE_SYNTHETIC_TESTING,
    LINUX_WINDOWS_ENV_QUALIFICATION, NOT_FILED, NOT_QUALIFIED,
    PRODUCTION_QUALIFICATION_SCHEMA, QUALIFIED, SYNTHETIC_ONLY,
    file_result, qualification_status,
)

AS_OF = "2026-11-07"


def _file(activity=LINUX_WINDOWS_ENV_QUALIFICATION, **over):
    base = dict(activity=activity, evidence_ids=["ev-1"],
                performed_by="Bank qualification team", performed_at=AS_OF,
                result="PASS")
    base.update(over)
    return file_result(**base)


def test_a_qualification_without_evidence_or_performer_is_a_claim():
    with pytest.raises(ValueError):
        _file(evidence_ids=[])
    with pytest.raises(ValueError):
        _file(performed_by="")
    with pytest.raises(ValueError):
        _file(result="MAYBE")
    with pytest.raises(ValueError):
        _file(activity="SOMETHING_ELSE")


def test_the_platform_cannot_perform_real_environment_qualification():
    with pytest.raises(ValueError) as exc:
        _file(performed_by="cryptoscan")
    assert "cannot be the performer" in str(exc.value)
    # ... but it can run the synthetic large-estate tests it hosts
    row = _file(activity=LARGE_ESTATE_SYNTHETIC_TESTING,
                performed_by="cryptoscan scale validation", synthetic=True)
    assert row["state"] == SYNTHETIC_ONLY


def test_synthetic_evidence_never_qualifies_a_real_environment_activity():
    with pytest.raises(ValueError) as exc:
        _file(synthetic=True)
    assert "stay labelled synthetic" in str(exc.value)


def test_synthetic_results_stay_labelled_and_never_ready_the_estate():
    row = _file(activity=LARGE_ESTATE_SYNTHETIC_TESTING, synthetic=True)
    assert row["state"] == SYNTHETIC_ONLY
    status = qualification_status([row])
    assert status["synthetic_results"] == [LARGE_ESTATE_SYNTHETIC_TESTING]
    assert status["production_ready"] is False
    assert status["is_clean_result"] is False
    assert "stay labelled synthetic" in status["note"]


def test_a_missing_filing_reads_not_filed_never_passed():
    status = qualification_status([])
    assert all(a["state"] == NOT_FILED for a in status["activities"])
    assert "never passed" in status["note"]
    assert status["production_ready"] is False
    assert set(status["blockers"]) == set(ACTIVITIES) - {
        LARGE_ESTATE_SYNTHETIC_TESTING}


def test_a_failed_qualification_reads_not_qualified():
    row = _file(activity=BANK_PILOT_ACCEPTANCE, result="FAIL")
    assert row["state"] == NOT_QUALIFIED
    status = qualification_status([row])
    entry = next(a for a in status["activities"]
                 if a["activity"] == BANK_PILOT_ACCEPTANCE)
    assert entry["state"] == NOT_QUALIFIED
    assert BANK_PILOT_ACCEPTANCE in status["blockers"]


def test_production_ready_needs_every_real_activity_qualified():
    rows = [_file(activity=activity, evidence_ids=[f"ev-{activity}"])
            for activity in ACTIVITIES
            if activity != LARGE_ESTATE_SYNTHETIC_TESTING]
    rows.append(_file(activity=LARGE_ESTATE_SYNTHETIC_TESTING,
                      synthetic=True, performed_by="cryptoscan scale validation"))
    status = qualification_status(rows)
    assert status["production_ready"] is True
    assert status["is_clean_result"] is True
    assert status["blockers"] == []
    # the synthetic filing is still labelled synthetic
    assert status["synthetic_results"] == [LARGE_ESTATE_SYNTHETIC_TESTING]

    # dropping any real activity (say the HA/DR test) blocks readiness again
    partial = [r for r in rows
               if r["activity"] != HA_DISASTER_RECOVERY_TESTING]
    status = qualification_status(partial)
    assert status["production_ready"] is False
    assert status["blockers"] == [HA_DISASTER_RECOVERY_TESTING]
    assert status["schema"] == PRODUCTION_QUALIFICATION_SCHEMA
