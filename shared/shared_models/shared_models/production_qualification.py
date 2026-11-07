"""Phase-6 production-qualification register (gap analysis §Phase 6).

"Qualify real Linux and Windows environments. Qualify supported HSM and
network devices. Complete cloud and database integration testing. Run
synthetic large-estate tests. Perform real backup and restore drills. Test HA
and disaster recovery. Validate upgrade, rollback and migration procedures.
Complete bank-side pilot acceptance."

These are the activities that stand between the platform and production
readiness. Seven of the eight happen in real environments — outside this
repository — so the platform does not perform them and does not mark them
done; it keeps the register, exactly like :mod:`shared_models.external_validation`
and the external acceptance gates: ``performed_by`` and ``evidence_ids`` are
mandatory at construction and nothing auto-files.

The eighth — large-estate **synthetic** testing — may be produced by the
platform itself, but its rows stay labelled synthetic and never read as
production qualification:

    "The synthetic accuracy figures ... should remain labelled as synthetic
    results until real-estate qualification supports stronger claims."

A qualification activity with no filed row is ``NOT_FILED`` — "no evidence
the platform holds", never "passed" and never "not applicable".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

PRODUCTION_QUALIFICATION_SCHEMA = "cryptoscan.production-qualification/1"

LINUX_WINDOWS_ENV_QUALIFICATION = "LINUX_WINDOWS_ENV_QUALIFICATION"
HSM_NETWORK_DEVICE_QUALIFICATION = "HSM_NETWORK_DEVICE_QUALIFICATION"
CLOUD_DATABASE_INTEGRATION_TESTING = "CLOUD_DATABASE_INTEGRATION_TESTING"
LARGE_ESTATE_SYNTHETIC_TESTING = "LARGE_ESTATE_SYNTHETIC_TESTING"
BACKUP_RESTORE_DRILL = "BACKUP_RESTORE_DRILL"
HA_DISASTER_RECOVERY_TESTING = "HA_DISASTER_RECOVERY_TESTING"
UPGRADE_ROLLBACK_MIGRATION_VALIDATION = "UPGRADE_ROLLBACK_MIGRATION_VALIDATION"
BANK_PILOT_ACCEPTANCE = "BANK_PILOT_ACCEPTANCE"

ACTIVITIES: tuple[str, ...] = (
    LINUX_WINDOWS_ENV_QUALIFICATION,
    HSM_NETWORK_DEVICE_QUALIFICATION,
    CLOUD_DATABASE_INTEGRATION_TESTING,
    LARGE_ESTATE_SYNTHETIC_TESTING,
    BACKUP_RESTORE_DRILL,
    HA_DISASTER_RECOVERY_TESTING,
    UPGRADE_ROLLBACK_MIGRATION_VALIDATION,
    BANK_PILOT_ACCEPTANCE,
)

#: the one activity whose evidence is synthetic by design
SYNTHETIC_ALLOWED: frozenset[str] = frozenset({LARGE_ESTATE_SYNTHETIC_TESTING})

_QUALIFIERS = frozenset(ACTIVITIES) - SYNTHETIC_ALLOWED

QUALIFIED = "QUALIFIED"
NOT_QUALIFIED = "NOT_QUALIFIED"
SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
NOT_FILED = "NOT_FILED"

PASS, FAIL = "PASS", "FAIL"

_PLATFORM_NAMES = {"cryptoscan", "crypto scan", "the platform", "platform"}


def file_result(*, activity: str, evidence_ids: Sequence[str],
                performed_by: str, performed_at: str, result: str,
                synthetic: bool = False,
                note: str | None = None) -> dict[str, Any]:
    """File evidence of one qualification activity.

    A qualification without evidence is a claim, and this register does not
    carry claims. Real-environment activities refuse synthetic evidence and
    refuse the platform as their performer; the synthetic activity files
    synthetic results but they never read QUALIFIED.
    """
    name = str(activity or "").upper()
    if name not in ACTIVITIES:
        raise ValueError(f"unknown production-qualification activity "
                         f"{activity!r}; expected one of {', '.join(ACTIVITIES)}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "qualification evidence is mandatory: a pass without evidence "
            "is a claim, and this register does not carry claims")
    who = str(performed_by or "").strip()
    if not who:
        raise ValueError("performed_by is mandatory: qualification evidence "
                         "names who produced it")
    if name in _QUALIFIERS and who.lower() in _PLATFORM_NAMES:
        raise ValueError(
            f"{name} is a real-environment qualification: it happens outside "
            "this repository, and the platform cannot be the performer")
    if name in _QUALIFIERS and synthetic:
        raise ValueError(
            "synthetic evidence never qualifies a real-environment activity: "
            "a synthetic drill is not a real-environment qualification, and "
            "synthetic results stay labelled synthetic until real-estate "
            "qualification supports stronger claims")
    outcome = str(result or "").upper()
    if outcome not in {PASS, FAIL}:
        raise ValueError(f"unknown result {result!r}; expected {PASS} or {FAIL}")
    if synthetic:
        state = SYNTHETIC_ONLY
    else:
        state = QUALIFIED if outcome == PASS else NOT_QUALIFIED
    return {
        "schema": PRODUCTION_QUALIFICATION_SCHEMA,
        "activity": name,
        "evidence_ids": ids,
        "performed_by": who,
        "performed_at": str(performed_at),
        "result": outcome,
        "synthetic": bool(synthetic),
        "state": state,
        "note": str(note) if note else None,
    }


def qualification_status(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll the register up per activity — latest filing per activity wins.

    ``production_ready`` is true only when every real-environment activity
    holds a QUALIFIED filing. A synthetic result never sets it, and no
    filing reads NOT_FILED — never "passed" and never "not applicable".
    """
    latest: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        name = str(row.get("activity") or "").upper()
        if name not in ACTIVITIES:
            raise ValueError(f"unknown production-qualification activity "
                             f"{row.get('activity')!r}")
        current = latest.get(name)
        if current is None or str(row.get("performed_at") or "") >= str(
                current.get("performed_at") or ""):
            latest[name] = dict(row)

    activities = []
    for name in ACTIVITIES:
        row = latest.get(name)
        if row is None:
            activities.append({"activity": name, "state": NOT_FILED,
                               "evidence_ids": [], "performed_by": None,
                               "note": "no evidence the platform holds"})
        else:
            activities.append({
                "activity": name,
                "state": str(row.get("state") or ""),
                "evidence_ids": list(row.get("evidence_ids") or []),
                "performed_by": row.get("performed_by"),
                "performed_at": row.get("performed_at"),
                "note": row.get("note"),
            })

    blockers = [a["activity"] for a in activities
                if a["activity"] in _QUALIFIERS and a["state"] != QUALIFIED]
    synthetic_rows = [a["activity"] for a in activities
                      if a["state"] == SYNTHETIC_ONLY]
    production_ready = not blockers
    return {
        "schema": PRODUCTION_QUALIFICATION_SCHEMA,
        "activities": activities,
        "production_ready": production_ready,
        "blockers": blockers,
        "synthetic_results": synthetic_rows,
        "is_clean_result": production_ready,
        "note": ("synthetic results stay labelled synthetic until real-estate "
                 "qualification supports stronger claims; a missing filing "
                 "is NOT_FILED, never passed"),
    }
