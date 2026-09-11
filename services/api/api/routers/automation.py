"""Automation engine API (deterministic, no AI/ML).

Exposes the event-driven orchestration that ties discovery, scanning, CBOM,
risk, PQC, alerts, tickets and approvals together:

* GET  /automation/capabilities        event kinds, actions, scanners, playbooks
* GET  /automation/rules               list configured WHEN/IF/THEN rules
* POST /automation/rules               create / replace a rule (validated)
* DELETE /automation/rules/{rule_id}   remove a rule
* POST /automation/process-event       process an event -> plan (persist + fan out)
* GET  /automation/runs                recent automation runs
* POST /automation/select-scanners     preview auto-selected scanners for assets
* POST /automation/schedule            adaptive scan schedule for assets

Processing an event produces a plan (scanners to run, matched rules, playbook,
auto vs approval-gated actions). Auto actions are announced on the event bus
(alert/ticket/rescan/CBOM fans out downstream); EXECUTE-tier actions are never
auto-run and instead raise a governance approval request (human gate).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/automation", tags=["automation"])

_ADMINS = ("admin", "superadmin", "ciso", "security_analyst")


def _publish(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="automation")
    except Exception:  # noqa: BLE001
        logger.debug("automation event publish skipped", exc_info=True)


# ------------------------------------------------------------------ catalog
@router.get("/capabilities")
def capabilities(user: str = Depends(get_current_user)):
    from automation.engine import known_playbooks
    from automation.rules_engine import ACTIONS, EVENT_KINDS
    from automation.scanner_selection import Scanner

    return {
        "event_kinds": sorted(EVENT_KINDS),
        "actions": sorted(ACTIONS),
        "scanners": sorted(s.value for s in Scanner),
        "playbooks": known_playbooks(),
        "safety_model": {
            "tiers": ["OBSERVE", "ANALYZE", "RECOMMEND", "APPROVE", "EXECUTE", "VERIFY"],
            "note": "read/derive/notify actions run automatically; production-change "
                    "actions require human approval and are never auto-executed",
        },
    }


# ------------------------------------------------------------------ rules
class ConditionBody(BaseModel):
    field: str
    operator: str
    value: object = None


class RuleBody(BaseModel):
    rule_id: str = Field(..., min_length=2, max_length=80)
    name: str = Field(default="", max_length=200)
    when: str
    if_conditions: list[ConditionBody] = Field(default_factory=list, alias="if")
    then: list[str] = Field(default_factory=list)
    severity: str = "MEDIUM"
    enabled: bool = True

    model_config = {"populate_by_name": True}


def _load_rules(db: Session):
    from automation.rules_engine import AutomationRule
    from db.models.automation import AutomationRuleRow as Row

    rows = db.execute(select(Row).where(Row.enabled.is_(True))).scalars().all()
    out = []
    for r in rows:
        try:
            out.append(AutomationRule.from_dict({
                "id": r.rule_id, "name": r.name, "when": r.when,
                "if": r.conditions or [], "then": r.actions or [],
                "severity": r.severity, "enabled": r.enabled,
            }))
        except Exception:  # noqa: BLE001
            logger.warning("automation_rule_skipped", extra={"rule_id": r.rule_id})
    return out


@router.get("/rules")
def list_rules(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from db.models.automation import AutomationRuleRow as Row

    rows = db.execute(select(Row).order_by(Row.rule_id)).scalars().all()
    return {"rules": [r.to_dict() for r in rows], "total_count": len(rows)}


@router.post("/rules", status_code=201)
def upsert_rule(body: RuleBody,
                user: str = Depends(require_roles(*_ADMINS)),
                db: Session = Depends(get_db_session)):
    from automation.rules_engine import AutomationRule, RulesError
    from db.models.automation import AutomationRuleRow as Row

    payload = {
        "id": body.rule_id, "name": body.name, "when": body.when,
        "if": [c.model_dump() for c in body.if_conditions],
        "then": body.then, "severity": body.severity, "enabled": body.enabled,
    }
    try:
        AutomationRule.from_dict(payload)  # fail-closed validation
    except RulesError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = db.execute(select(Row).where(Row.rule_id == body.rule_id)).scalars().first()
    if row is None:
        row = Row(rule_id=body.rule_id, created_by=user)
        db.add(row)
    row.name = body.name or body.rule_id
    row.when = body.when
    row.conditions = payload["if"]
    row.actions = body.then
    row.severity = body.severity.upper()
    row.enabled = body.enabled
    db.commit()
    db.refresh(row)
    _publish("automation.rule_saved", {"rule_id": body.rule_id, "by": user})
    return row.to_dict()


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str,
                user: str = Depends(require_roles(*_ADMINS)),
                db: Session = Depends(get_db_session)):
    from db.models.automation import AutomationRuleRow as Row

    row = db.execute(select(Row).where(Row.rule_id == rule_id)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="rule not found")
    db.delete(row)
    db.commit()
    return {"rule_id": rule_id, "deleted": True}


# ------------------------------------------------------------------ process
class EventBody(BaseModel):
    event_kind: str = Field(..., min_length=2, max_length=60)
    data: dict = Field(default_factory=dict)
    asset: dict | None = None


def run_automation(db: Session, *, event_kind: str, data: dict | None = None,
                   asset: dict | None = None, triggered_by: str = "system",
                   persist: bool = True) -> dict:
    """Build an automation plan for an event and (optionally) persist + fan it out.

    Shared by the HTTP endpoint and the live event-bus bridge. Auto actions are
    announced on the bus; EXECUTE/APPROVE actions open a governance approval gate
    and are never auto-run.
    """
    from automation.engine import build_plan
    from db.models.automation import AutomationRun

    data = data or {}
    event = dict(data)
    event.setdefault("asset_id", data.get("asset_id"))
    rules = _load_rules(db)
    plan = build_plan(event_kind, event, rules, select_scanners_for=asset)
    pd = plan.as_dict()

    run = AutomationRun(
        event_kind=event_kind,
        asset_id=pd.get("asset_id"),
        scanners=pd["scanners"],
        auto_actions=pd["auto_actions"],
        gated_actions=pd["requires_approval"],
        matched_rules=pd["matched_rules"],
        playbook=(pd["playbook"] or {}).get("id") if pd["playbook"] else None,
        needs_human=pd["needs_human"],
        recommended_tier=pd["recommended_tier"],
        triggered_by=triggered_by,
    )
    governance_ref = None
    if persist:
        db.add(run)

        action_names = [a["action"] for a in pd["auto_actions"]]
        if "create_alert" in action_names or "notify_crypto_team" in action_names:
            _publish("alert.raised", {
                "event_kind": event_kind, "asset_id": pd.get("asset_id"),
                "severity": pd["recommended_tier"], "matched_rules": pd["matched_rules"]})
        if "targeted_rescan" in action_names:
            _publish("scan.targeted", {
                "asset_id": pd.get("asset_id"), "scanners": pd["scanners"],
                "reason": f"event {event_kind}"})
        if "update_cbom" in action_names:
            _publish("cbom.update_requested", {"asset_id": pd.get("asset_id")})
        if "create_ticket" in action_names:
            _publish("ticket.requested", {
                "asset_id": pd.get("asset_id"), "event_kind": event_kind,
                "severity": pd["recommended_tier"]})
        if "add_pqc_queue" in action_names or "add_to_pqc_queue" in action_names:
            _publish("pqc.queue_add", {"asset_id": pd.get("asset_id")})

        if pd["requires_approval"]:
            try:
                from governance.rules import ChangeRequest, evaluate
                from db.models.p2 import GovernanceApproval

                req = ChangeRequest(request_type="automation_action",
                                    requested_by=triggered_by,
                                    payload={"event_kind": event_kind,
                                             "asset_id": pd.get("asset_id"),
                                             "gated_actions": [a["action"] for a in pd["requires_approval"]],
                                             "playbook": run.playbook})
                result = evaluate(req)
                grow = GovernanceApproval(
                    request_type="automation_action",
                    request_ref=str(pd.get("asset_id") or ""),
                    requested_by=triggered_by,
                    status="PENDING" if result.decision.name == "REQUIRES_APPROVAL" else "AUTO_APPROVED",
                    decision=None if result.decision.name == "REQUIRES_APPROVAL" else result.decision.value,
                    rationale=result.rationale,
                    policy_rules=result.rules,
                    risk_level=result.risk_level.value,
                    payload={**req.payload, "required_approvers": result.required_approvers},
                )
                db.add(grow)
                db.flush()
                governance_ref = str(grow.id)
            except Exception:  # noqa: BLE001
                logger.debug("governance gate creation skipped", exc_info=True)
        run.governance_ref = governance_ref
        db.flush()

    out = run.to_dict() if persist else {"event_kind": event_kind}
    out["plan"] = pd
    out["governance_ref"] = governance_ref
    return out


@router.post("/process-event", status_code=201)
def process_event(body: EventBody,
                  user: str = Depends(require_roles(*(_ADMINS + ("scanner", "worker")))),
                  db: Session = Depends(get_db_session)):
    out = run_automation(db, event_kind=body.event_kind, data=body.data,
                         asset=body.asset, triggered_by=user, persist=True)
    db.commit()
    return out


@router.get("/runs")
def list_runs(limit: int = 50,
              user: str = Depends(get_current_user),
              db: Session = Depends(get_db_session)):
    from db.models.automation import AutomationRun

    rows = db.execute(
        select(AutomationRun).order_by(AutomationRun.created_at.desc()).limit(min(limit, 200))
    ).scalars().all()
    return {"runs": [r.to_dict() for r in rows], "total_count": len(rows)}


# ------------------------------------------------------------------ selection/schedule
class AssetsBody(BaseModel):
    assets: list[dict] = Field(default_factory=list, max_length=100_000)


@router.post("/select-scanners")
def select_scanners_preview(body: AssetsBody, user: str = Depends(get_current_user)):
    from automation.scanner_selection import select_for_many

    results = select_for_many(body.assets)
    return {"selections": [r.as_dict() for r in results], "total_count": len(results)}


@router.post("/schedule")
def schedule_preview(body: AssetsBody, user: str = Depends(get_current_user)):
    from automation.scheduling import due_assets

    due = due_assets(body.assets)
    return {"due": [s.as_dict() for s in due], "due_count": len(due),
            "total_assets": len(body.assets)}


# ------------------------------------------------------------------ connectors
# ITSM/SIEM delivery of automation runs. Payload mappers are pure (automation
# .connectors); the sender is injectable and never raises into the engine.
# Status responses carry configuration NAMES only — values never leave the API.

_CONNECTOR_SETTINGS = (
    "SERVICENOW_INSTANCE_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD",
    "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN",
)


class ConnectorBody(BaseModel):
    connector: str = Field(..., pattern="^(servicenow|splunk)$")
    run_id: str = Field(..., min_length=1)


@router.get("/connectors")
def list_connectors(user: str = Depends(require_roles(*_ADMINS))):
    from api.config.settings import get_settings
    from automation.connectors import CONNECTORS, connector_status

    settings = get_settings()
    config = {key: str(getattr(settings, key, "") or "") for key in _CONNECTOR_SETTINGS}
    return {"connectors": connector_status(config), "catalog": CONNECTORS}


def _connector_run(db: Session, run_id: str) -> dict:
    from db.models.automation import AutomationRun

    row = db.execute(select(AutomationRun).where(AutomationRun.id == run_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"automation run '{run_id}' not found")
    return row.to_dict()


@router.post("/connectors/preview")
def connector_preview(body: ConnectorBody,
                      user: str = Depends(require_roles(*_ADMINS)),
                      db: Session = Depends(get_db_session)):
    """Build the exact payload that WOULD be delivered — nothing is sent."""
    from automation.connectors import servicenow_incident_payload, splunk_hec_payload

    run = _connector_run(db, body.run_id)
    payload = (servicenow_incident_payload(run) if body.connector == "servicenow"
               else splunk_hec_payload(run))
    return {"connector": body.connector, "run_id": body.run_id,
            "payload": payload, "delivered": False,
            "note": "preview only — nothing was sent"}


@router.post("/connectors/dispatch")
def connector_dispatch(body: ConnectorBody,
                       user: str = Depends(require_roles(*_ADMINS)),
                       db: Session = Depends(get_db_session)):
    """Deliver an automation run to the configured connector, honestly."""
    from api.config.settings import get_settings
    from automation.connectors import send, servicenow_incident_payload, splunk_hec_payload

    run = _connector_run(db, body.run_id)
    payload = (servicenow_incident_payload(run) if body.connector == "servicenow"
               else splunk_hec_payload(run))
    settings = get_settings()
    config = {key: str(getattr(settings, key, "") or "") for key in _CONNECTOR_SETTINGS}
    result = send(body.connector, payload, config=config)
    return {"connector": body.connector, "run_id": body.run_id, **result}
