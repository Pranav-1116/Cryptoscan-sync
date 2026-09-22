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

import json
import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
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


# ------------------------------------------- 16b. SBOM scanner (E2E) ---- #
_SBOM_OPERATORS = ("admin", "auditor", "security_analyst", "superadmin")
_SBOM_STORE = None
_ARTIFACT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _sbom_storage():
    """Persistent on-disk SBOM artifact store (survives restarts)."""
    import tempfile

    from governance.backup_jobs import DiskBackupStorage

    global _SBOM_STORE
    if _SBOM_STORE is None:
        root = os.environ.get("SBOM_STORAGE_DIR", "/var/lib/cryptoscan/sboms")
        try:
            _SBOM_STORE = DiskBackupStorage(root)
        except Exception:
            _SBOM_STORE = DiskBackupStorage(os.path.join(tempfile.gettempdir(), "cryptoscan-sboms"))
    return _SBOM_STORE


class SbomScanRequest(BaseModel):
    kind: str = Field(..., description="source | container")
    target: str = Field(..., min_length=1, max_length=512,
                        description="source tree path, filesystem root, docker-save .tar, or registry image")
    format: str = Field("cyclonedx", description="cyclonedx | spdx")
    as_image: bool = Field(False, description="treat the target as a registry image even if a path exists")
    include_vendored: bool = Field(False, description="source kind: also parse manifests under vendor/")


@router.post("/sbom/scan", status_code=status.HTTP_201_CREATED)
def sbom_scan(body: SbomScanRequest, db: Session = Depends(get_db_session),
              user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """End-to-end SBOM generation: scan a source tree or container target and
    produce a deterministic CycloneDX 1.5 / SPDX 2.3 bill of materials with
    crypto-relevance enrichment, pinning summary, and a signed-by-hash
    persistent artifact (download via GET /sbom/{artifact_id}/download)."""
    from datetime import datetime, timezone

    import hashlib
    import uuid

    from devsecops import sbom_scan as sb
    from devsecops.sbom import check_pinning
    from api.security.target_validation import TargetValidationError, validate_source_target

    kind = body.kind.lower()
    if kind not in ("source", "container"):
        raise HTTPException(status_code=422, detail="kind must be source or container")
    if body.format.lower() not in ("cyclonedx", "cdx", "spdx"):
        raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    fmt = "spdx" if body.format.lower() == "spdx" else "cyclonedx"

    if kind == "source":
        try:
            resolved = validate_source_target(body.target, label="target")
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if resolved.startswith(("http://", "https://", "git@")):
            raise HTTPException(400, "remote git URLs are not supported by the SBOM scanner — point it at a local source tree")
        try:
            result = sb.scan_source(resolved, include_vendored=body.include_vendored)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        raw = str(body.target).strip()
        raw_path = Path(raw).expanduser()
        looks_path = body.as_image is False and (
            raw_path.exists() or raw.startswith(("/", "~", ".")))
        if looks_path:
            try:
                raw = validate_source_target(raw, label="target")
            except TargetValidationError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        elif not (sb.is_image_ref(raw) and (":" in raw or "/" in raw)):
            raise HTTPException(400, detail=("target must be a local path, docker-save .tar, "
                                             "or a registry image reference (e.g. nginx:1.27)"))
        if not looks_path:
            # a registry pull is a networked operation — fail closed in airgap
            _enforce_airgap_writable("scan.sbom.container")
        try:
            result = sb.scan_container(raw, as_image=body.as_image)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"container target not found: {exc}")
        except Exception as exc:  # noqa: BLE001 — docker/pull unavailability: report honestly
            raise HTTPException(status_code=503, detail=f"container scan unavailable: {exc}")

    try:
        bom = sb.render_sbom(result, fmt=fmt)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    packages = result.get("packages") or []
    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = str(uuid.uuid4())
    ext = "cdx.json" if fmt == "cyclonedx" else "spdx.json"
    key = f"{artifact_id}.{ext}"

    components = [{"name": p.get("name"),
                   "version": p.get("raw_spec") or p.get("version"),
                   "ecosystem": p.get("manager")} for p in packages]
    pinning = check_pinning(components)
    component_count = len(packages) + len(result.get("binaries") or [])
    manifest = {
        "artifact_id": artifact_id,
        "kind": kind,
        "target": str(result.get("target") or body.target),
        "format": fmt,
        "sha256": sha256,
        "component_count": component_count,
        "binary_count": len(result.get("binaries") or []),
        "crypto_components": len(result.get("libraries") or []),
        "manifest_count": result.get("manifest_count", 0),
        "pinned": pinning["pinned"],
        "unpinned": pinning["unpinned"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": user,
        "storage_key": key,
    }
    store = _sbom_storage()
    store.put(key, payload)
    store.put_manifest(key, manifest)
    UserRepository(db).audit(user, "devsecops.sbom_scan", target_type="sbom_artifact",
                             target_id=artifact_id,
                             detail={"kind": kind, "target": manifest["target"], "format": fmt,
                                     "components": component_count, "sha256": sha256[:16]})
    db.commit()
    return {"artifact_id": artifact_id, "manifest": manifest,
            "download_url": f"/api/v1/devsecops/sbom/{artifact_id}/download", "bom": bom}


@router.get("/sbom/artifacts")
def sbom_artifacts(user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """List generated SBOM artifacts (newest first, capped at 50)."""
    items = _sbom_storage().list_manifests()
    items.sort(key=lambda m: str(m.get("created_at") or ""), reverse=True)
    return {"artifacts": items[:50], "total": len(items)}


@router.get("/sbom/{artifact_id}/download")
def sbom_download(artifact_id: str, user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """Download a persisted SBOM artifact (JSON) with its provenance header."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob = store.get(man["storage_key"])
    except Exception:  # noqa: BLE001 — manifest without a readable blob
        raise HTTPException(status_code=404, detail="artifact not found")
    ext = "cdx.json" if man.get("format") == "cyclonedx" else "spdx.json"
    return Response(
        content=blob, media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cryptoscan-sbom-{artifact_id[:8]}.{ext}"',
            "X-SBOM-SHA256": str(man.get("sha256") or ""),
        })


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

    # Persist finding lifecycle state in the settings-backed store so ack/assign
    # survives restarts and is shared with bidirectional ITSM sync.
    from db.repositories.settings_repository import SettingsRepository
    from devsecops.finding_state import FindingStateStore

    store = FindingStateStore(SettingsRepository(db))
    state = store.get_or_create(body.finding_id)
    result = dsync.apply_chat_action(state, action=body.action, key=body.key,
                                     actor=body.actor, finding=body.finding_id)
    if result.get("ok"):
        store.save(state, by=user)
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


# ------------------------------------------- 17. bidirectional ticket sync -- #
class TicketPullRequest(BaseModel):
    provider: str = Field(..., description="servicenow | jira")
    # Injected remote state (deterministic reconciliation). Ignored when
    # live=true, which performs real HTTPS GET against a configured instance.
    remote_rows: list[dict] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    live: bool = False
    instance: str | None = None     # ServiceNow host (e.g. acme.service-now.com)
    base_url: str | None = None     # Jira base URL
    auth: str | None = None         # Basic auth token (base64 user:pass)
    jql: str | None = None


@router.post("/tickets/sync-pull")
def ticket_sync_pull(body: TicketPullRequest, db: Session = Depends(get_db_session),
                     user: str = Depends(require_roles("admin", "security_analyst", "auditor", "superadmin"))):
    """Reconcile remote ITSM ticket state (status/assignee/comments) back onto
    local findings by de-dup key. Persists reconciled state and audits changes.

    Two modes:
    - live=false (default): remote_rows supplied in the request (deterministic).
    - live=true: performs a REAL HTTPS GET against the ServiceNow/Jira instance
      using provided/vault credentials; the destination is SSRF-validated and a
      reachable-but-failed poll is reported honestly (never faked)."""
    from devsecops import sync as dsync
    from devsecops.finding_state import FindingStateStore
    from db.repositories.settings_repository import SettingsRepository

    state_store = FindingStateStore(SettingsRepository(db))
    states = {fid: state_store.get_or_create(fid) for fid in body.finding_ids}

    synced = set()
    for st in states.values():
        synced.update(st.synced_comment_ids)

    transport_errors: list[dict] = []
    if body.live:
        # REAL HTTP transport against a live ITSM (SSRF-validated).
        from devsecops import runtime_adapters as rt
        from control_plane.delivery import validate_webhook_url
        auth = body.auth or os.environ.get("ITSM_BASIC_AUTH", "")
        if not auth:
            raise HTTPException(400, "live sync requires ITSM credentials (auth or ITSM_BASIC_AUTH)")
        base = body.instance or body.base_url
        if not base:
            raise HTTPException(400, "live sync requires instance (ServiceNow) or base_url (Jira)")
        host = base if base.startswith("http") else f"https://{base}"
        try:
            validate_webhook_url(f"{host}/api/now/table/incident") if body.provider == "servicenow" \
                else validate_webhook_url(f"{host}/rest/api/3/search/jql")
        except Exception as exc:  # noqa: BLE001 - SSRF rejection
            raise HTTPException(421, f"destination rejected (SSRF/unsafe): {exc}")
        raw_get = rt.urllib_get()

        def live_get(url, headers=None):
            h = {"Accept": "application/json", "Authorization": f"Basic {auth}", **(headers or {})}
            return raw_get(url, headers=h)
        ts = dsync.TicketSync(get=live_get, synced_comments=synced)
        if body.provider == "servicenow":
            outcomes = ts.pull_servicenow(states, instance=host, auth=auth)
        elif body.provider == "jira":
            outcomes = ts.pull_jira(states, base_url=host, auth=auth, jql=body.jql or "labels = cryptoscan")
        else:
            raise HTTPException(422, "provider must be servicenow or jira")
        # surface any poll failure honestly
        for o in outcomes:
            if not o.get("ok"):
                transport_errors.append({"provider": o.get("provider"), "error": o.get("error")})
    else:
        # Deterministic injected mode.
        remote_json = {"result": body.remote_rows} if body.provider == "servicenow" \
            else {"issues": body.remote_rows}
        import json as _json

        def fake_get(url, headers=None):
            from devsecops.connectors import HttpResult
            return HttpResult(ok=True, status=200, body=_json.dumps(remote_json))

        ts = dsync.TicketSync(get=fake_get, synced_comments=synced)
        if body.provider == "servicenow":
            outcomes = ts.pull_servicenow(states, instance="injected", auth="injected")
        elif body.provider == "jira":
            outcomes = ts.pull_jira(states, base_url="https://injected", auth="x")
        else:
            raise HTTPException(422, "provider must be servicenow or jira")

    # persist reconciled states (including synced comment ids for idempotency)
    for fid, st in states.items():
        st.synced_comment_ids = sorted(ts._synced_comments)
        state_store.save(st, by=user)

    reconciled = [o for o in outcomes if o.get("action") == "RECONCILED"]
    for o in reconciled:
        UserRepository(db).audit(user, f"devsecops.ticket_sync_{body.provider}",
                                 target_type="finding", target_id=o.get("finding_id", ""),
                                 detail={"ticket_id": o.get("ticket_id"), "changes": o.get("changes")})
    db.commit()
    return {"provider": body.provider, "mode": "live" if body.live else "injected",
            "reconciled": len(reconciled),
            "no_match": sum(1 for o in outcomes if o.get("action") == "NO_MATCH"),
            "transport_errors": transport_errors,
            "ok": not transport_errors,
            "outcomes": outcomes,
            "states": {fid: st.to_dict() for fid, st in states.items()}}
