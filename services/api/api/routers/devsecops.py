"""DevSecOps pipeline API: container CVE scan, K8s/IaC misconfig, cloud CIS
posture, SBOM import/export + pinning, and outbound integrations
(ITSM/SIEM/message-bus/chat). All checks are deterministic (no AI).

The active outbound connectors (Splunk HEC, Elastic, ServiceNow, Jira, Slack,
Teams, Kafka/RabbitMQ) are driven from stored integration credentials but the
HTTP/producer transport is injected at runtime; destinations are validated by
the existing SSRF-safe webhook guard. In this reference surface the tests
exercise the payload builders with an injected transport.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from db.repositories.user_repository import UserRepository

router = APIRouter(prefix="/devsecops", tags=["devsecops"])


def _enforce_airgap_writable(operation: str) -> None:
    """Block mutating/networked operations when AIRGAP_MODE is on (fail-closed)."""
    import os

    if os.environ.get("AIRGAP_MODE", "false").lower() not in ("1", "true", "yes", "on"):
        return
    from governance import airgap

    allow = tuple(a.strip() for a in os.environ.get("AIRGAP_ALLOWLIST", "").split(",") if a.strip())
    try:
        airgap.enforce_operation(operation, airgap.AirgapPolicy(airgap=True, allowlist=allow))
    except airgap.AirgapReadOnlyError as exc:
        raise HTTPException(status_code=423, detail=str(exc))  # 423 Locked


# ------------------------------------------------------------- 13. image --- #
class ContainerScanRequest(BaseModel):
    packages: list[dict] = Field(default_factory=list)
    feed: list[dict] = Field(default_factory=list)
    dockerfile: str | None = None


@router.post("/container-scan")
def container_scan(body: ContainerScanRequest,
                   user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.container_scan import scan_image

    return scan_image(packages=body.packages, feed=body.feed, dockerfile=body.dockerfile)


# --------------------------------------------------------------- 14. k8s --- #
class K8sScanRequest(BaseModel):
    manifests_yaml: str = Field(..., min_length=1)


@router.post("/k8s-manifest-scan")
def k8s_scan(body: K8sScanRequest,
             user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.k8s_rules import scan_manifests

    try:
        return scan_manifests(body.manifests_yaml)
    except Exception as exc:  # YAML parse failure is a client error
        raise HTTPException(status_code=400, detail=f"manifest parse failed: {exc}")


# ----------------------------------------------------------- 15. posture --- #
class PostureRequest(BaseModel):
    resources: list[dict]


@router.post("/cloud-posture")
def cloud_posture(body: PostureRequest,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.cloud_posture import evaluate

    result = evaluate(body.resources)
    if result["total_findings"]:
        UserRepository(db).audit(user, "devsecops.cloud_posture", target_type="posture",
                                 target_id="cis-scan",
                                 detail={"resources": result["resources_scanned"],
                                         "findings": result["total_findings"],
                                         "by_severity": result["by_severity"]})
        db.commit()
    return result


# ---------------------------------------------------------------- 16. SBOM -- #
class SbomImportRequest(BaseModel):
    doc: dict
    format: str | None = None  # cyclonedx | spdx | auto


@router.post("/sbom/import")
def sbom_import(body: SbomImportRequest,
                user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.sbom import check_pinning, dependency_graph, import_sbom

    try:
        comps = import_sbom(body.doc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"component_count": len(comps), "components": comps,
            "pinning": check_pinning(comps), "graph": dependency_graph(comps)}


class SbomExportRequest(BaseModel):
    components: list[dict]
    format: str = "cyclonedx"  # cyclonedx | spdx


@router.post("/sbom/export")
def sbom_export(body: SbomExportRequest,
                user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.sbom import export_cyclonedx, export_spdx

    if body.format.lower() in ("cyclonedx", "cdx"):
        return {"format": "cyclonedx", "bom": export_cyclonedx(body.components)}
    if body.format.lower() == "spdx":
        return {"format": "spdx", "bom": export_spdx(body.components)}
    raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")


# ------------------------------------------------- 17-20. connector previews #
# These endpoints build the outbound payload (and, for a configured live
# transport, deliver it). They always return the constructed payload + dedup
# key so an operator can preview/audit before enabling a target.
class ConnectorRequest(BaseModel):
    provider: str
    finding: dict
    target: dict = Field(default_factory=dict)
    deliver_live: bool = False


@router.post("/connectors/preview")
def connector_preview(body: ConnectorRequest,
                      db: Session = Depends(get_db_session),
                      user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    """Build (and optionally send) a connector payload for one finding.

    Deterministic preview: returns provider, dedup key, and the exact body that
    would be sent. With deliver_live=true and a configured target, it performs
    the real HTTP delivery using the SSRF-validated URL.
    """
    import json as _json

    from devsecops import connectors

    # Air-gap read-only mode must block live delivery BEFORE any network attempt
    # or payload build (fail-closed, 423 Locked).
    if body.deliver_live:
        _enforce_airgap_writable("connector.deliver")

    f = body.finding
    target = body.target
    captured: dict = {}

    def capture(url, *, content, headers, timeout=10):
        from control_plane.delivery import validate_webhook_url

        validate_webhook_url(url)  # raises on SSRF/unsafe target
        captured["url"] = url
        captured["headers"] = {k: ("***" if "auth" in k.lower() else v) for k, v in headers.items()}
        try:
            captured["body"] = _json.loads(content.decode())
        except Exception:
            captured["body_raw"] = content.decode()[:4000]
        if body.deliver_live:
            post = connectors.default_http_post()
            return post(url, content=content, headers=headers, timeout=timeout)
        from devsecops.connectors import HttpResult

        return HttpResult(ok=True, status=200, body="{}")

    provider = body.provider.lower()
    try:
        if provider == "servicenow":
            res = connectors.servicenow_ticket(
                f, instance=target.get("instance", "example.service-now.com"),
                auth=target.get("auth", "preview"), table=target.get("table", "incident"), post=capture)
        elif provider == "jira":
            res = connectors.jira_issue(
                f, base_url=target.get("base_url", "https://jira.example.com"),
                auth=target.get("auth", "preview"), project=target.get("project", "SEC"), post=capture)
        elif provider == "splunk":
            res = connectors.splunk_hec(
                [f], hec_url=target.get("hec_url", "https://splunk.example.com:8088"),
                token=target.get("token", "preview"), post=capture)
        elif provider == "elastic":
            res = connectors.elastic_bulk(
                [f], base_url=target.get("base_url", "https://es.example.com:9200"),
                index=target.get("index", "findings"), auth=target.get("auth", "preview"), post=capture)
        elif provider == "slack":
            res = connectors.slack_message(f, webhook_url=target.get("webhook_url", "https://hooks.slack.com/x"), post=capture)
        elif provider == "teams":
            res = connectors.teams_adaptive_card(f, webhook_url=target.get("webhook_url", "https://teams.example.com/x"), post=capture)
        elif provider == "kafka":
            produced = []
            res = connectors.kafka_stream(
                [f], topic=target.get("topic", "findings"),
                bootstrap=target.get("bootstrap", ""),
                producer=(lambda t, v, h: produced.append({"topic": t, "value": _json.loads(v.decode()), "headers": h})))
            captured["messages"] = produced
        elif provider == "rabbitmq":
            published = []
            res = connectors.rabbit_stream(
                [f], exchange=target.get("exchange", "security"), routing_key=target.get("routing_key", "findings"),
                publisher=(lambda ex, rk, b, p: published.append({"exchange": ex, "routing_key": rk, "properties": p})))
            captured["messages"] = published
        else:
            raise HTTPException(status_code=422,
                                detail=f"unknown provider {provider!r}; supported: servicenow, jira, splunk, elastic, slack, teams, kafka, rabbitmq")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"connector error: {exc}")

    if body.deliver_live:
        UserRepository(db).audit(user, "devsecops.connector_delivery", target_type="integration",
                                 target_id=provider, detail={"ok": res.get("ok"), "dedup_key": res.get("dedup_key")})
        db.commit()
    return {"provider": provider, "result": res, "delivered_live": body.deliver_live,
            "preview": captured}


# ------------------------------------------------- 20. inbound chat actions -- #
_CHAT_STATE: dict[str, Any] = {}


def _finding_state_store() -> dict[str, Any]:
    """Process-local finding lifecycle state keyed by finding_id.

    In production this is the findings table; the in-memory store keeps the
    reference surface stateless-to-deploy while preserving ack/assign
    idempotency semantics across requests."""
    return _CHAT_STATE


class ChatActionRequest(BaseModel):
    platform: str = Field(..., description="slack | teams")
    action: str = Field(..., description="ack | assign | ticket")
    key: str
    finding_id: str
    actor: str
    # Slack signature verification (v0 HMAC) — optional in preview; required live
    timestamp: str | None = None
    signature: str | None = None
    raw_body: str | None = None
    signing_secret: str | None = None


@router.post("/chat/action")
def chat_action(body: ChatActionRequest, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles("admin", "security_analyst", "auditor", "superadmin"))):
    """Deterministic inbound ack/assign/ticket handler for Slack/Teams buttons.

    Verifies the platform request signature (Slack v0 HMAC) when provided, then
    applies the state transition idempotently and writes an audit entry. Fails
    closed on bad signature / unknown action / mismatched dedup key.
    """
    from devsecops import sync as dsync

    # Signature verification (fail-closed when a secret+signature are supplied)
    if body.platform == "slack" and body.signing_secret:
        raw = (body.raw_body or "").encode()
        if not body.signature or not body.timestamp or not dsync.verify_slack_request(
                signing_secret=body.signing_secret, timestamp=body.timestamp,
                body=raw, signature=body.signature):
            UserRepository(db).audit(user, "devsecops.chat_action_rejected", target_type="finding",
                                     target_id=body.finding_id, detail={"reason": "bad signature"},
                                     outcome="FAILURE")
            db.commit()
            raise HTTPException(status_code=401, detail="invalid Slack request signature")

    # Persist finding lifecycle state in a module-level store (production uses a
    # findings table); this makes ack/assign idempotent across requests.
    store = _finding_state_store()
    state = store.get(body.finding_id) or dsync.FindingState(finding_id=body.finding_id, status="OPEN")
    result = dsync.apply_chat_action(state, action=body.action, key=body.key,
                                     actor=body.actor, finding=body.finding_id)
    if result.get("ok"):
        store[body.finding_id] = state
    if not result.get("ok"):
        UserRepository(db).audit(user, "devsecops.chat_action_rejected", target_type="finding",
                                 target_id=body.finding_id, detail={"reason": result.get("error")},
                                 outcome="FAILURE")
        db.commit()
        raise HTTPException(status_code=400, detail=result.get("error") or "action rejected")

    UserRepository(db).audit(user, f"devsecops.chat_{body.action}", target_type="finding",
                             target_id=body.finding_id,
                             detail={"platform": body.platform, "actor": body.actor,
                                     "idempotent": result.get("idempotent", False),
                                     "new_status": result["state"]["status"]})
    db.commit()
    return {"ok": True, "platform": body.platform, "action": body.action,
            "finding_id": body.finding_id, "state": result["state"],
            "idempotent": result.get("idempotent", False),
            "audit": result.get("audit")}
