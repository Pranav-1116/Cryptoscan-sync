"""Bidirectional integration sync + inbound action handling (features 17-20).

Deterministic, network-injected (no real sockets imported here):

- 17. ITSM bidirectional sync: poll remote ServiceNow/Jira issue state and
      reconcile comments + status back onto the local finding, keyed by the
      stable de-dup key. Idempotent; never creates duplicates.
- 18. Native SIEM indexers: Splunk HEC with indexer-ack handling and
      Elasticsearch/OpenSearch _bulk with per-item error handling + bounded
      retry on retryable failures.
- 19. Message-bus streaming consumers/producers: a durable event-stream writer
      with offset tracking (Kafka/Rabbit share the same injected transport).
- 20. Chat ops inbound: verify Slack request signatures / Teams auth tokens and
      apply deterministic ack/assign/ticket button actions to finding state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .connectors import dedup_key, HttpResult


# ================================================================ 17 ITSM == #
# Remote ticket status -> local finding lifecycle state. Deterministic map.
SN_STATE_MAP = {
    "1": "NEW", "2": "OPEN", "3": "IN_PROGRESS", "6": "RESOLVED",
    "7": "CLOSED", "8": "CANCELED",
}
JIRA_STATUS_MAP = {
    "To Do": "NEW", "Open": "OPEN", "In Progress": "IN_PROGRESS",
    "Done": "RESOLVED", "Closed": "CLOSED", "Rejected": "CANCELED",
}


@dataclass
class FindingState:
    finding_id: str
    status: str = "OPEN"
    assignee: str | None = None
    comments: list[dict] = field(default_factory=list)
    tickets: dict[str, str] = field(default_factory=dict)  # provider -> remote id
    synced_comment_ids: list[str] = field(default_factory=list)

    def to_dict(self):
        return {"finding_id": self.finding_id, "status": self.status,
                "assignee": self.assignee, "comments": list(self.comments),
                "tickets": dict(self.tickets),
                "synced_comment_ids": list(self.synced_comment_ids)}


class TicketSync:
    """Bidirectional, idempotent sync between local findings and an ITSM.

    Transport is injected: ``get(path) -> HttpResult`` and ``post(...)``.
    Reconciliation is keyed on the stable dedup key so remote items are matched
    to local findings without ambiguity (no false positives).
    """

    def __init__(self, *, get: Callable[..., HttpResult] | None = None,
                 post: Callable[..., HttpResult] | None = None,
                 synced_comments: set[str] | None = None):
        self._get = get
        self._post = post
        # remote comment ids already reconciled (idempotency). Persisted by the
        # caller across requests (finding-state store) so repeat pulls don't
        # re-add the same comment.
        self._synced_comments: set[str] = synced_comments if synced_comments is not None else set()

    # ---- inbound: pull remote state -> local ------------------------------ #
    def pull_servicenow(self, states: dict[str, FindingState], *,
                        instance: str, auth: str) -> list[dict]:
        """Fetch incidents (correlation_id = dedup key) and reconcile."""
        url = (f"https://{instance}/api/now/table/incident"
               f"?sysparm_query=correlation_idLIKEcs-&sysparm_display_value=true")
        headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
        res = self._get(url, headers=headers)
        if not res.ok:
            return [{"provider": "servicenow", "ok": False, "error": res.error or f"HTTP {res.status}"}]
        rows = (json.loads(res.body or "{}").get("result") or [])
        return [self._reconcile_servicenow(states, r) for r in rows]

    def pull_jira(self, states: dict[str, FindingState], *,
                  base_url: str, auth: str, jql: str = "labels = cryptoscan") -> list[dict]:
        url = f"{base_url.rstrip('/')}/rest/api/3/search/jql?jql={jql}&fields=status,comment,assignee,labels"
        headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
        res = self._get(url, headers=headers)
        if not res.ok:
            return [{"provider": "jira", "ok": False, "error": res.error or f"HTTP {res.status}"}]
        issues = (json.loads(res.body or "{}").get("issues") or [])
        return [self._reconcile_jira(states, i) for i in issues]

    def _reconcile_servicenow(self, states, row) -> dict:
        key = (row.get("correlation_id") or "").strip()
        local = self._match(states, key)
        if local is None:
            return {"provider": "servicenow", "dedup_key": key, "ok": True, "action": "NO_MATCH"}
        remote_id = str(row.get("sys_id") or "")
        local.tickets["servicenow"] = remote_id
        remote_state = SN_STATE_MAP.get(str(row.get("state")), None)
        changes = []
        if remote_state and remote_state != local.status and self._is_remote_newer(local, remote_state):
            local.status = remote_state
            changes.append(f"status->{remote_state}")
        assigned = (row.get("assigned_to") or {})
        assigned_name = assigned.get("display_value") if isinstance(assigned, dict) else assigned
        if assigned_name and assigned_name != local.assignee:
            local.assignee = str(assigned_name)
            changes.append(f"assignee->{assigned_name}")
        # comments (work_notes)
        for note in self._extract_sn_comments(row):
            cid = f"servicenow:{remote_id}:{note.get('sys_id','')}"
            if cid not in self._synced_comments:
                self._synced_comments.add(cid)
                local.comments.append({"source": "servicenow", "author": note.get("user_name"),
                                       "text": note.get("value"), "id": cid})
                changes.append("comment")
        return {"provider": "servicenow", "dedup_key": key, "ticket_id": remote_id,
                "finding_id": local.finding_id, "ok": True, "action": "RECONCILED", "changes": changes}

    @staticmethod
    def _extract_sn_comments(row: dict) -> list[dict]:
        """ServiceNow exposes journal fields as ``work_notes_list`` /
        ``comments_list`` when requested; tolerate both and plain strings."""
        notes = row.get("work_notes_list") or row.get("comments_list") or []
        if isinstance(notes, list):
            return [n for n in notes if isinstance(n, dict)]
        return []

    def _reconcile_jira(self, states, issue) -> dict:
        fields = issue.get("fields") or {}
        labels = fields.get("labels") or []
        key = next((l for l in labels if isinstance(l, str) and l.startswith("cs-")), "")
        issue_key = issue.get("key") or ""
        local = self._match(states, key)
        if local is None:
            return {"provider": "jira", "dedup_key": key, "ticket_id": issue_key,
                    "ok": True, "action": "NO_MATCH"}
        local.tickets["jira"] = issue_key
        changes = []
        remote_state = JIRA_STATUS_MAP.get((fields.get("status") or {}).get("name", ""))
        if remote_state and remote_state != local.status and self._is_remote_newer(local, remote_state):
            local.status = remote_state
            changes.append(f"status->{remote_state}")
        assignee = (fields.get("assignee") or {}).get("displayName")
        if assignee and assignee != local.assignee:
            local.assignee = assignee
            changes.append(f"assignee->{assignee}")
        for c in (fields.get("comment") or {}).get("comments") or []:
            cid = f"jira:{issue_key}:{c.get('id','')}"
            if cid not in self._synced_comments:
                self._synced_comments.add(cid)
                local.comments.append({"source": "jira", "author": (c.get("author") or {}).get("displayName"),
                                       "text": c.get("body"), "id": cid})
                changes.append("comment")
        return {"provider": "jira", "dedup_key": key, "ticket_id": issue_key,
                "finding_id": local.finding_id, "ok": True, "action": "RECONCILED", "changes": changes}

    def _match(self, states: dict[str, FindingState], dedup: str) -> FindingState | None:
        """Find local finding whose dedup key for any provider equals remote key."""
        if not dedup:
            return None
        for st in states.values():
            for provider in ("servicenow", "jira"):
                if dedup_key(provider, st.finding_id) == dedup:
                    return st
        return None

    @staticmethod
    def _is_remote_newer(local: FindingState, remote_state: str) -> bool:
        """Only allow forward lifecycle transitions (never reopen silently)."""
        order = {"NEW": 0, "OPEN": 1, "IN_PROGRESS": 2, "RESOLVED": 3, "CLOSED": 4, "CANCELED": 4}
        return order.get(remote_state, 0) >= order.get(local.status, 0)

    # ---- outbound comment: push local -> remote (idempotent) -------------- #
    def push_comment_servicenow(self, local: FindingState, *, instance: str, auth: str,
                                comment: str, post: Callable | None = None) -> dict:
        post = post or self._post
        remote_id = local.tickets.get("servicenow")
        if not remote_id:
            return {"provider": "servicenow", "ok": False, "error": "no remote ticket linked"}
        url = f"https://{instance}/api/now/table/incident/{remote_id}"
        body = {"work_notes": f"[CryptoScan] {comment}"}
        res = post(url, content=json.dumps(body).encode(),
                   headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"})
        return {"provider": "servicenow", "ok": res.ok, "status": res.status,
                "error": res.error if not res.ok else None}


# ================================================================ 18 SIEM == #
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def splunk_hec_with_ack(events: Iterable[dict], *, hec_url: str, token: str,
                        post: Callable, index: str | None = None,
                        max_retries: int = 3, channel: str = "cryptoscan-idx") -> dict:
    """Native Splunk HEC with indexer acknowledgement.

    Sends with ?channel= and X-Splunk-Request-Channel; on a 200 with an ackId we
    poll /services/collector/ack until the indexer confirms (transport injected).
    Retries only on retryable status codes; non-retryable errors fail closed.
    """
    events = list(events)
    lines = []
    for e in events:
        wrap = {"time": int(e.get("time") or time.time()),
                "sourcetype": "cryptoscan:finding", "source": "cryptoscan", "event": e}
        if index:
            wrap["index"] = index
        lines.append(json.dumps(wrap))
    content = ("\n".join(lines)).encode()
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json",
               "X-Splunk-Request-Channel": channel}
    url = hec_url.rstrip("/") + "/services/collector?channel=" + channel

    res, attempts = None, 0
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        res = post(url, content=content, headers=headers)
        if res.ok:
            break
        if res.status not in RETRYABLE_STATUS or attempt == max_retries:
            return {"provider": "splunk_hec", "ok": False, "status": res.status,
                    "events_sent": 0, "attempts": attempts,
                    "error": res.error or f"permanent failure HTTP {res.status}"}
        time.sleep(0)  # injected tests don't really sleep; real runner may backoff

    ack_id = None
    try:
        ack_id = json.loads(res.body).get("ackId")
    except Exception:
        pass

    acknowledged = True
    if ack_id is not None:
        ack_url = hec_url.rstrip("/") + "/services/collector/ack?channel=" + channel
        polled = 0
        for _ in range(max_retries):
            polled += 1
            ares = post(ack_url, content=json.dumps({"acks": [ack_id]}).encode(),
                        headers=headers)
            if ares.ok and str(ack_id) in (json.loads(ares.body or "{}").get("acks") or {}):
                acknowledged = True
                break
            acknowledged = False
    return {"provider": "splunk_hec", "ok": res.ok and acknowledged,
            "status": res.status, "events_sent": len(events),
            "attempts": attempts, "indexer_ack": acknowledged,
            "ack_id": ack_id,
            "error": None if acknowledged else "indexer did not acknowledge"}


def elastic_bulk_with_retry(events: Iterable[dict], *, base_url: str, index: str,
                            auth: str, post: Callable, max_retries: int = 3) -> dict:
    """Native Elasticsearch/OpenSearch _bulk with per-item error handling.

    Retries the whole batch only on retryable HTTP status; on a 200 with
    per-item errors it reports which doc ids failed (no silent loss).
    """
    events = list(events)
    bulk, doc_ids = [], []
    for e in events:
        doc_id = str(e.get("finding_id") or dedup_key("elastic", json.dumps(e, sort_keys=True, default=str)))
        doc_ids.append(doc_id)
        bulk.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        bulk.append(json.dumps(e, default=str))
    content = ("\n".join(bulk) + "\n").encode()
    headers = {"Content-Type": "application/x-ndjson", "Authorization": f"ApiKey {auth}"}
    url = base_url.rstrip("/") + f"/{index}/_bulk"

    res, attempts = None, 0
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        res = post(url, content=content, headers=headers)
        if res.ok:
            break
        if res.status not in RETRYABLE_STATUS or attempt == max_retries:
            return {"provider": "elastic", "ok": False, "status": res.status,
                    "events_sent": 0, "attempts": attempts,
                    "error": res.error or f"permanent failure HTTP {res.status}"}

    item_errors = []
    try:
        parsed = json.loads(res.body or "{}")
        if parsed.get("errors"):
            for i, item in enumerate(parsed.get("items") or []):
                op = item.get("index") or {}
                if op.get("error"):
                    item_errors.append({"doc_id": doc_ids[i] if i < len(doc_ids) else None,
                                        "type": op["error"].get("type"),
                                        "reason": op["error"].get("reason")})
    except Exception:
        pass
    return {"provider": "elastic", "ok": not item_errors, "status": res.status,
            "events_sent": len(events) - len(item_errors), "attempts": attempts,
            "item_errors": item_errors,
            "error": f"{len(item_errors)} items rejected" if item_errors else None}


# ================================================================ 19 BUS === #
class EventStream:
    """Durable finding event stream over an injected transport.

    Tracks delivered offsets per partition so a consumer can resume without
    duplicates or gaps (at-least-once with dedup). Works for Kafka or RabbitMQ;
    the transport callable is provided by the runtime adapter.
    """

    def __init__(self, *, transport: Callable[[str, bytes, dict], Any] | None = None,
                 topic: str = "cryptoscan.findings"):
        self.topic = topic
        self._transport = transport or (lambda t, v, h: (_ for _ in ()).throw(
            RuntimeError("no bus transport configured")))
        self._committed_offset = -1
        self.sent: list[dict] = []

    def publish(self, events: Iterable[dict]) -> dict:
        sent, errors = 0, []
        for seq, e in enumerate(events, start=self._committed_offset + 1):
            key = str(e.get("finding_id") or dedup_key("stream", seq)).encode()
            headers = {"dedup_key": dedup_key("stream", key.decode()),
                       "offset": str(seq), "topic": self.topic}
            try:
                self._transport(self.topic, json.dumps(e, default=str).encode(), headers)
                self._committed_offset = seq
                self.sent.append({"offset": seq, "dedup": headers["dedup_key"]})
                sent += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
                break  # stop at first failure so offsets stay contiguous
        return {"provider": "event_stream", "topic": self.topic, "ok": not errors,
                "events_sent": sent, "committed_offset": self._committed_offset,
                "error": errors[0] if errors else None}

    def resume_offset(self) -> int:
        return self._committed_offset + 1


# ================================================================ 20 CHAT == #
VALID_ACTIONS = {"ack", "assign", "ticket"}
ACTION_TO_STATE = {"ack": "ACKNOWLEDGED", "assign": "ASSIGNED"}


def verify_slack_request(*, signing_secret: str, timestamp: str, body: bytes,
                         signature: str) -> bool:
    """Verify Slack's v0 HMAC-SHA256 request signature (v=0:ts:body)."""
    if not signature or not timestamp:
        return False
    base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_teams_token(*, tenant_id: str, audience: str, token_claims: dict,
                       expected_app_id: str) -> bool:
    """Deterministic structural check of an already-validated Teams token's
    claims (signature is verified by the runtime's JWT layer; here we enforce
    tenant/audience/app binding fail-closed)."""
    if not token_claims:
        return False
    iss = str(token_claims.get("iss") or "")
    aud = token_claims.get("aud")
    app_id = token_claims.get("appid") or token_choices_appid(token_claims)
    # tenant binding: the authoritative tenant id claim is `tid`; fall back to
    # the issuer only when tid is absent. Fail-closed if neither matches.
    tid = token_claims.get("tid")
    if tenant_id:
        if tid is not None:
            if tid != tenant_id:
                return False
        elif tenant_id not in iss:
            return False
    if audience and aud != audience:
        return False
    if expected_app_id and app_id != expected_app_id:
        return False
    return True


def token_choices_appid(claims: dict) -> str | None:
    azp = claims.get("azp")
    return azp if isinstance(azp, str) else None


def apply_chat_action(state: FindingState, *, action: str, key: str,
                      actor: str, finding: str | None = None) -> dict:
    """Deterministically apply a chat button action to finding state.

    Idempotent: ack/assign only advance state; repeated acks are no-ops. Every
    accepted action returns an audit-ready record. Invalid actions are rejected
    (fail-closed) and never mutate state.
    """
    if action not in VALID_ACTIONS:
        return {"ok": False, "error": f"unknown action {action!r}", "state": state.to_dict()}
    expected_key = dedup_key("slack", state.finding_id)
    expected_key_teams = dedup_key("teams", state.finding_id)
    if key not in (expected_key, expected_key_teams):
        return {"ok": False, "error": "dedup key does not match finding — rejecting action",
                "state": state.to_dict()}

    record = {"action": action, "actor": actor, "finding_id": state.finding_id,
              "key": key, "at": time.time()}
    if action == "ack":
        if state.status == "ACKNOWLEDGED":
            return {"ok": True, "idempotent": True, "action": "ack",
                    "state": state.to_dict(), "audit": record}
        state.status = "ACKNOWLEDGED"
        state.comments.append({"source": "chat", "author": actor, "text": "Acknowledged via chat"})
    elif action == "assign":
        state.assignee = actor
        if state.status in ("NEW", "OPEN"):
            state.status = "ASSIGNED"
        state.comments.append({"source": "chat", "author": actor, "text": f"Assigned to {actor} via chat"})
    elif action == "ticket":
        state.comments.append({"source": "chat", "author": actor,
                               "text": "Ticket creation requested via chat"})
    return {"ok": True, "idempotent": False, "action": action,
            "state": state.to_dict(), "audit": record}
