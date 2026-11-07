"""Deployment and operations controls (roadmap item 10).

A deployment is not ready because a checkbox exists — it is ready when each ops
control carries a fresh, evidence-backed attestation. This model holds the
controls the roadmap names (on-prem and air-gapped modes, HA, backup, tested
restore, DR, tenant isolation, bank IAM, mTLS, key rotation, signed releases,
own SBOM, migration validation, monitoring, data custody) and refuses the two
classic lies:

* **"we have backups" is not "restore is tested"** — ``BACKUP`` and
  ``RESTORE_TESTED`` are separate controls and the first never covers the
  second. An attestation without evidence is refused at construction, and a
  stale drill is ``STALE`` — still in the history, no longer holding readiness;
* **"the bank keeps control" is not a slogan** — ``DATA_CUSTODY`` must locate
  the database, the evidence store and the crypto metadata and name the bank as
  controller of each. A missing class is unknown location, which is not control.

Air-gapped is "if offered": a mode nobody offered is reported as not offered and
is never claimed ready. Unattested controls are ``NOT_ATTESTED`` — which is
never drawn as OK.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from shared_models.evidence_freshness import freshness_of

CONTROLS_SCHEMA = "cryptoscan.deployment-controls/1"

#: control id → (the question it answers, days an attestation stays current)
CONTROLS: dict[str, tuple[str, int]] = {
    "HA": ("is the service highly available with tested failover?", 180),
    "BACKUP": ("are backups taken on schedule?", 30),
    "RESTORE_TESTED": ("has a restore been tested against those backups?", 90),
    "DR": ("is there a disaster-recovery plan, exercised as a drill?", 180),
    "TENANT_ISOLATION": ("is tenant isolation enforced and tested?", 180),
    "BANK_IAM": ("does authentication run through the bank's IAM?", 365),
    "MTLS": ("is service transport mutually authenticated?", 180),
    "KEY_ROTATION": ("are platform keys rotated on schedule?", 180),
    "SIGNED_RELEASES": ("are releases signed and verified on install?", 180),
    "OWN_SBOM": ("does the platform ship its own SBOM for each release?", 180),
    "MIGRATION_VALIDATION": ("are schema migrations validated on upgrade?", 180),
    "MONITORING": ("is the platform monitored with actionable alerting?", 180),
    "DATA_CUSTODY": ("do database, evidence and crypto metadata stay under bank "
                     "control?", 365),
}

#: deployment modes; AIR_GAPPED is offered only where a product ships it
MODES: tuple[str, ...] = ("ON_PREM", "AIR_GAPPED")

#: controls every mode must attest; air-gapped runs the same core set
CORE_CONTROLS: tuple[str, ...] = tuple(CONTROLS)

#: the three custody classes the roadmap names
CUSTODY_CLASSES: tuple[str, ...] = ("database", "evidence", "crypto_metadata")

#: attestation states
ATTESTED = "ATTESTED"
STALE = "STALE"
FAILED = "FAILED"
NOT_ATTESTED = "NOT_ATTESTED"
CONTROL_STATES: tuple[str, ...] = (ATTESTED, STALE, FAILED, NOT_ATTESTED)


def attest(*, control: str, evidence_ids: Sequence[str], observed_at: str,
           actor: str, status: str = "OK",
           note: str | None = None) -> dict[str, Any]:
    """One attestation of one control. Evidence and a clock are mandatory.

    A failed drill files ``status="FAILED"`` — a failure is a coverage fact and
    stays visible; this model never silently drops the drill that did not pass.
    """
    name = str(control or "").upper()
    if name not in CONTROLS:
        raise ValueError(f"unknown deployment control {control!r}; expected one "
                         f"of {', '.join(CONTROLS)}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "an attestation without evidence is a claim: this model files only "
            "evidence-backed attestations")
    if not str(observed_at or "").strip():
        raise ValueError("an attestation without observed_at cannot age, so it "
                         "cannot hold or lose readiness honestly")
    state = str(status or "OK").upper()
    if state not in {"OK", "FAILED"}:
        raise ValueError(f"unknown attestation status {status!r}; expected OK or "
                         f"FAILED")
    return {
        "schema": CONTROLS_SCHEMA,
        "control": name,
        "status": state,
        "evidence_ids": ids,
        "observed_at": str(observed_at),
        "actor": str(actor or "(unnamed)"),
        "note": str(note) if note else None,
    }


def control_state(control: str, attestations: Iterable[Mapping[str, Any]],
                  *, now: Any = None) -> dict[str, Any]:
    """The state of one control from its attestations — never OK by default.

    The newest attestation decides, its age against the control's validity window
    decides ``ATTESTED`` vs ``STALE``, and a FAILED drill stays FAILED until a
    newer passing attestation replaces it in the history (the old one remains).
    """
    name = str(control or "").upper()
    question, validity_days = CONTROLS.get(name, ("unknown control", 30))
    rows = sorted((dict(a) for a in attestations
                   if str(a.get("control")) == name),
                  key=lambda r: str(r.get("observed_at") or ""))
    if not rows:
        return {"control": name, "question": question, "state": NOT_ATTESTED,
                "reason": ("no attestation exists: this control is unattested, "
                           "which is never drawn as OK"),
                "latest": None}
    latest = rows[-1]
    fresh = freshness_of(latest.get("observed_at"),
                         evidence_type="AUDIT_OBSERVED", now=now)
    age_ok = fresh["age_days"] is not None and fresh["age_days"] <= validity_days
    if latest.get("status") == "FAILED":
        state = FAILED
        reason = ("the most recent drill failed: a failure is recorded as a "
                  "failure until a newer passing attestation exists")
    elif age_ok:
        state = ATTESTED
        reason = (f"attested with evidence inside its {validity_days}-day "
                  f"validity window")
    else:
        state = STALE
        reason = (f"the newest attestation is past its {validity_days}-day "
                  f"validity window: it remains in the history and cannot hold "
                  f"readiness")
    return {"control": name, "question": question, "state": state,
            "reason": reason, "latest": latest,
            "attestations": rows}


def deployment_readiness(*, attestations: Iterable[Mapping[str, Any]],
                         mode: str = "ON_PREM",
                         offered_modes: Sequence[str] = ("ON_PREM",),
                         custody: Mapping[str, Any] | None = None,
                         now: Any = None) -> dict[str, Any]:
    """Deployment readiness for one mode. Unattested is never ready.

    Air-gapped is "if offered": a mode outside ``offered_modes`` returns
    ``MODE_NOT_OFFERED`` and nothing is claimed about it. The readiness verdict
    is ``DEPLOYMENT_READY`` only when every core control is ATTESTED and custody
    is clean; otherwise every gap is listed and the verdict says incomplete.
    """
    mode_name = str(mode or "").upper()
    offered = {str(m).upper() for m in offered_modes}
    if mode_name not in MODES:
        raise ValueError(f"unknown deployment mode {mode!r}; expected one of "
                         f"{', '.join(MODES)}")

    if mode_name not in offered:
        return {
            "schema": CONTROLS_SCHEMA, "mode": mode_name,
            "verdict": "MODE_NOT_OFFERED",
            "reason": (f"{mode_name} is not an offered deployment mode here: "
                       f"air-gapped support is claimed only where a product "
                       f"actually ships it, and never assumed"),
            "controls": {}, "gaps": [],
            "custody": None,
        }

    states = {name: control_state(name, attestations, now=now)
              for name in CORE_CONTROLS}
    gaps: list[dict[str, Any]] = []
    for name, entry in states.items():
        if entry["state"] == ATTESTED:
            continue
        gaps.append({
            "control": name, "state": entry["state"],
            "detail": entry["reason"], "is_clean_result": False})

    backup_state = states["BACKUP"]["state"]
    restore_state = states["RESTORE_TESTED"]["state"]
    if backup_state == ATTESTED and restore_state != ATTESTED:
        gaps.append({
            "control": "RESTORE_TESTED", "state": restore_state,
            "detail": ("backups are attested but the restore is not tested: a "
                       "backup is not a tested restore, and an untested restore "
                       "is not a rollback plan"),
            "is_clean_result": False})

    custody_rows: dict[str, Any] = {}
    if custody is None:
        gaps.append({
            "control": "DATA_CUSTODY", "state": "NOT_ATTESTED",
            "detail": ("no custody map was supplied: the location of the bank's "
                       "database, evidence and crypto metadata is unknown, and "
                       "unknown location is not bank control"),
            "is_clean_result": False})
    else:
        for cls in CUSTODY_CLASSES:
            entry = custody.get(cls)
            controller = (entry or {}).get("controller") if isinstance(entry, Mapping) else None
            location = (entry or {}).get("location") if isinstance(entry, Mapping) else None
            custody_rows[cls] = {"controller": controller, "location": location}
            if not entry or not location:
                gaps.append({
                    "control": "DATA_CUSTODY", "state": "NOT_ATTESTED",
                    "detail": (f"{cls}: location unknown — unknown location is "
                               f"not bank control: the bank keeps control of "
                               f"{cls} only when its location is known and named"),
                    "is_clean_result": False})
            elif str(controller).upper() != "BANK":
                gaps.append({
                    "control": "DATA_CUSTODY", "state": "FAILED",
                    "detail": (f"{cls} at {location} is controlled by "
                               f"{controller!r}, not the bank: 'the bank keeps "
                               f"control' is a requirement, not a caption"),
                    "is_clean_result": False})

    if gaps:
        verdict = "ATTESTATION_INCOMPLETE"
        reason = ("every gap above is unattested, stale, failed or misplaced: "
                  "a missing attestation is never a clean deployment result")
    else:
        verdict = "DEPLOYMENT_READY"
        reason = (f"every core control is attested with current evidence and "
                  f"custody is clean for {mode_name}")

    return {
        "schema": CONTROLS_SCHEMA, "mode": mode_name,
        "verdict": verdict, "reason": reason,
        "controls": states,
        "gaps": gaps,
        "custody": custody_rows or None,
        "offered_modes": sorted(offered),
        "note": ("a backup is not a tested restore, a stale drill is not "
                 "readiness, an unattested control is not OK, and custody is "
                 "located and named or it is not control"),
    }


def control_catalog() -> dict[str, Any]:
    """The control catalogue and mode rules — for audits and the UI."""
    return {
        "schema": CONTROLS_SCHEMA,
        "controls": [{"id": name, "question": question,
                      "attestation_validity_days": days}
                     for name, (question, days) in CONTROLS.items()],
        "modes": list(MODES),
        "core_controls": list(CORE_CONTROLS),
        "custody_classes": list(CUSTODY_CLASSES),
        "note": ("every control answers a question with evidence; nothing is "
                 "ready because a checkbox exists"),
    }
