"""Dependency-edge history in Cassandra: the append-only timeline of one edge.

PostgreSQL is the authoritative record of every relationship. This store is a
rebuildable projection — it holds edge lifecycle *events* (observations and
state transitions over time), never authoritative asset or relationship rows.
Its shape matches the workload Cassandra is for: massive append volume, ordered
per-edge timelines, cheap retention.

Partitioning: PRIMARY KEY ((tenant_id, edge_id), occurred_at, event_id).
Tenant isolation is enforced by the query layer and authorization — it is
never assumed from the partition key. Every statement binds ``tenant_id``
explicitly alongside ``edge_id``; a query without a tenant binding is
rejected, and the test double rejects it too.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from shared_models.dependency_semantics import normalize_relation, system_id
from shared_models.relationship_lifecycle import utc

logger = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FAR = datetime(9999, 1, 1, tzinfo=timezone.utc)

EVENT_TYPES = frozenset({"OBSERVED", "STATE_CHANGE", "SUPERSEDED", "RECONCILED", "REMOVED"})

_COLUMNS = (
    "tenant_id", "edge_id", "occurred_at", "event_id",
    "subject_id", "object_id", "relation",
    "event_type", "lifecycle_state", "lifecycle_revision",
    "lifecycle_reason", "lifecycle_source", "lifecycle_evidence_ref",
    "detail",
)

SCHEMA_QUERIES = (
    "-- cryptoscan.query=history_schema_keyspace\n"
    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = "
    "{{'class': 'SimpleStrategy', 'replication_factor': 1}}",
    "-- cryptoscan.query=history_schema_table\n"
    "CREATE TABLE IF NOT EXISTS {keyspace}.dependency_edge_events (\n"
    "    tenant_id text,\n"
    "    edge_id text,\n"
    "    occurred_at timestamp,\n"
    "    event_id text,\n"
    "    subject_id text,\n"
    "    object_id text,\n"
    "    relation text,\n"
    "    event_type text,\n"
    "    lifecycle_state text,\n"
    "    lifecycle_revision text,\n"
    "    lifecycle_reason text,\n"
    "    lifecycle_source text,\n"
    "    lifecycle_evidence_ref text,\n"
    "    detail text,\n"
    "    PRIMARY KEY ((tenant_id, edge_id), occurred_at, event_id)\n"
    ") WITH CLUSTERING ORDER BY (occurred_at DESC, event_id ASC)",
)

INSERT_EVENT = (
    "-- cryptoscan.query=edge_event_insert\n"
    "INSERT INTO {keyspace}.dependency_edge_events ({columns}) "
    "VALUES ({values})"
)

EDGE_HISTORY = (
    "-- cryptoscan.query=edge_history\n"
    "SELECT * FROM {keyspace}.dependency_edge_events "
    "WHERE tenant_id = %(tenant_id)s AND edge_id = %(edge_id)s "
    "AND occurred_at >= %(since)s AND occurred_at <= %(until)s "
    "LIMIT %(limit)s"
)

EDGE_HISTORY_AS_OF = (
    "-- cryptoscan.query=edge_history_as_of\n"
    "SELECT * FROM {keyspace}.dependency_edge_events "
    "WHERE tenant_id = %(tenant_id)s AND edge_id = %(edge_id)s "
    "AND occurred_at <= %(at)s "
    "LIMIT 1"
)

PURGE_EDGE = (
    "-- cryptoscan.query=edge_history_purge\n"
    "DELETE FROM {keyspace}.dependency_edge_events "
    "WHERE tenant_id = %(tenant_id)s AND edge_id = %(edge_id)s"
)

PING = (
    "-- cryptoscan.query=history_ping\n"
    "SELECT now() FROM system.local"
)


def _ident(value: str, label: str) -> str:
    text = (value or "").strip()
    if not text or not all(c.isalnum() or c == "_" for c in text) or not text[0].isalpha():
        raise ValueError(f"unsafe {label} identifier")
    return text


def edge_key(subject: str, relation: str, object_: str) -> str:
    """Canonical edge partition id, aligned with the graph stores' edge identity."""
    return "::".join((system_id(subject), normalize_relation(relation), system_id(object_)))


def event_id_for(event: dict[str, Any]) -> str:
    """Deterministic idempotency key: re-appending the same event is a no-op."""
    edge = str(event.get("edge_key") or event.get("edge_id") or "")
    basis = "|".join(
        [edge] + [
            str(event.get(key) or "")
            for key in ("occurred_at", "event_type", "lifecycle_revision", "detail")
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _row_to_dict(row: Any) -> dict[str, Any]:
    if hasattr(row, "_asdict"):
        return dict(row._asdict())
    if isinstance(row, dict):
        return dict(row)
    return {column: getattr(row, column) for column in _COLUMNS}


class CassandraEdgeHistory:
    """Append-only dependency-edge timeline. Every method is tenant-bound."""

    backend = "cassandra"

    def __init__(self, session: Any, keyspace: str = "cryptoscan_graph") -> None:
        self.session = session
        self.keyspace = _ident(keyspace, "keyspace")

    def _execute(self, statement: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        rows = self.session.execute(statement, params)
        return [_row_to_dict(row) for row in rows]

    def apply_schema(self) -> dict[str, Any]:
        applied = []
        for statement in SCHEMA_QUERIES:
            self.session.execute(statement.format(keyspace=self.keyspace), None)
            applied.append(statement.splitlines()[0])
        return {"applied": applied}

    def ping(self) -> bool:
        try:
            self.session.execute(PING, None)
            return True
        except Exception:
            return False

    def append_event(self, tenant_id: str, event: dict[str, Any]) -> dict[str, Any]:
        tenant = _ident(tenant_id, "tenant")
        subject = system_id(event.get("subject") or event.get("from"))
        object_ = system_id(event.get("object") or event.get("to"))
        relation = normalize_relation(event.get("relation") or event.get("label"))
        if not subject or not object_:
            raise ValueError("edge event requires subject and object")
        occurred_at = event.get("occurred_at")
        if occurred_at is None:
            raise ValueError("edge event requires occurred_at")
        occurred_at = utc(occurred_at)
        event_type = str(event.get("event_type") or "OBSERVED").upper()
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown edge event_type: {event_type}")
        row = {
            "tenant_id": tenant,
            "edge_key": edge_key(subject, relation, object_),
            "occurred_at": occurred_at,
            "subject_id": subject,
            "object_id": object_,
            "relation": relation,
            "event_type": event_type,
            "lifecycle_state": event.get("lifecycle_state"),
            "lifecycle_revision": event.get("lifecycle_revision"),
            "lifecycle_reason": event.get("lifecycle_reason"),
            "lifecycle_source": event.get("lifecycle_source"),
            "lifecycle_evidence_ref": event.get("lifecycle_evidence_ref"),
            "detail": event.get("detail"),
        }
        row["event_id"] = str(event.get("event_id") or event_id_for(row))
        params = {column: row.get(column) if column != "edge_id" else row["edge_key"]
                  for column in _COLUMNS}
        statement = INSERT_EVENT.format(
            keyspace=self.keyspace,
            columns=", ".join(_COLUMNS),
            values=", ".join(f"%({column})s" for column in _COLUMNS),
        )
        self._execute(statement, params)
        return {column: params[column] for column in _COLUMNS}

    def history(
        self,
        tenant_id: str,
        subject: str,
        object_: str,
        relation: str,
        *,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        tenant = _ident(tenant_id, "tenant")
        params = {
            "tenant_id": tenant,
            "edge_id": edge_key(subject, relation, object_),
            "since": utc(since) if since is not None else _EPOCH,
            "until": utc(until) if until is not None else _FAR,
            "limit": max(1, min(int(limit), 1000)),
        }
        rows = self._execute(EDGE_HISTORY.format(keyspace=self.keyspace), params)
        return sorted(rows, key=lambda row: row["occurred_at"], reverse=True)[: params["limit"]]

    def as_of(
        self,
        tenant_id: str,
        subject: str,
        object_: str,
        relation: str,
        at: datetime | str,
    ) -> dict[str, Any] | None:
        tenant = _ident(tenant_id, "tenant")
        params = {
            "tenant_id": tenant,
            "edge_id": edge_key(subject, relation, object_),
            "at": utc(at),
        }
        rows = self._execute(EDGE_HISTORY_AS_OF.format(keyspace=self.keyspace), params)
        return rows[0] if rows else None

    def purge_edge(self, tenant_id: str, subject: str, object_: str, relation: str) -> None:
        """Drop one edge's timeline — used by rebuild-from-PostgreSQL."""
        tenant = _ident(tenant_id, "tenant")
        params = {
            "tenant_id": tenant,
            "edge_id": edge_key(subject, relation, object_),
        }
        self._execute(PURGE_EDGE.format(keyspace=self.keyspace), params)
