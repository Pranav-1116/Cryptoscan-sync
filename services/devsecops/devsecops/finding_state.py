"""Persistent finding lifecycle state for bidirectional sync + chat ops.

Replaces the in-process dict used for ack/assign so that state survives restarts
and is shared by the ITSM inbound sync and the chat-action handler. Stored in
the platform settings table as a JSON map (finding_id -> state) — no AI, fully
deterministic. `TicketSync` and `apply_chat_action` both read/write through this
store so tickets and chat buttons reconcile the same record.
"""

from __future__ import annotations

from typing import Any

from .sync import FindingState

SETTING_KEY = "devsecops.finding_states"


class FindingStateStore:
    def __init__(self, settings_repo):
        self.repo = settings_repo

    def _load(self) -> dict[str, dict[str, Any]]:
        return self.repo.get(SETTING_KEY, default={}) or {}

    def _save(self, data: dict[str, dict[str, Any]], *, by: str = "finding-state"):
        self.repo.set(SETTING_KEY, data, updated_by=by)

    def get(self, finding_id: str) -> FindingState | None:
        row = self._load().get(finding_id)
        if not row:
            return None
        return FindingState(
            finding_id=row["finding_id"], status=row.get("status", "OPEN"),
            assignee=row.get("assignee"), comments=list(row.get("comments", [])),
            tickets=dict(row.get("tickets", {})),
            synced_comment_ids=list(row.get("synced_comment_ids", [])))

    def get_or_create(self, finding_id: str) -> FindingState:
        return self.get(finding_id) or FindingState(finding_id=finding_id, status="OPEN")

    def save(self, state: FindingState, *, by: str = "finding-state") -> None:
        data = self._load()
        data[state.finding_id] = state.to_dict()
        self._save(data, by=by)

    def all(self) -> dict[str, FindingState]:
        out = {}
        for fid, row in self._load().items():
            out[fid] = FindingState(
                finding_id=row["finding_id"], status=row.get("status", "OPEN"),
                assignee=row.get("assignee"), comments=list(row.get("comments", [])),
                tickets=dict(row.get("tickets", {})),
                synced_comment_ids=list(row.get("synced_comment_ids", [])))
        return out
