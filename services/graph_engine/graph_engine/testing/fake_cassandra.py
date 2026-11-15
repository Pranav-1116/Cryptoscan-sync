"""In-memory Cassandra test double dispatching tagged CQL to Python handlers.

It does not parse or execute CQL and cannot qualify a real Cassandra
deployment. The adapter sends the same statement text and parameters to this
double in tests.

The double enforces the store's tenant-isolation contract from the other
side: every data statement must bind ``tenant_id`` and reference it in its
WHERE clause. A statement that tries to read or write without a tenant
binding raises — isolation is enforced by the query layer, never assumed
from the partition key.
"""

from __future__ import annotations

import re
from typing import Any

from graph_engine.history.edge_history import _COLUMNS


def query_tag(cql: str) -> str:
    match = re.search(r"cryptoscan\.query=([a-z0-9_]+)", cql)
    return match.group(1) if match else ""


class TenantIsolationError(RuntimeError):
    """A data statement reached the store without a tenant binding."""


class FakeCassandraRow(dict):
    def _asdict(self) -> dict[str, Any]:
        return dict(self)

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError as exc:  # pragma: no cover - attribute-style access
            raise AttributeError(key) from exc


class FakeCassandraSession:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.statements: list[tuple[str, dict[str, Any] | None]] = []
        self.schema_applied: list[str] = []

    def _require_tenant(self, cql: str, params: Any) -> str:
        tenant = (params or {}).get("tenant_id")
        if not tenant or "%(tenant_id)s" not in cql:
            raise TenantIsolationError(
                "dependency-edge history statement lacks a tenant binding"
            )
        if "WHERE" in cql.upper() and "TENANT_ID =" not in cql.split("WHERE", 1)[-1].upper():
            raise TenantIsolationError(
                "dependency-edge history statement lacks a tenant binding"
            )
        return str(tenant)

    def execute(self, cql: str, params: dict[str, Any] | None = None) -> list[FakeCassandraRow]:
        tag = query_tag(cql)
        self.statements.append((tag, params))
        if tag in ("history_schema_keyspace", "history_schema_table"):
            self.schema_applied.append(tag)
            return []
        # The tenant-isolation contract outranks dispatch: any data statement
        # without a tenant binding is rejected before it is understood.
        tenant = self._require_tenant(cql, params)
        if tag == "edge_event_insert":
            row = {column: (params or {}).get(column) for column in _COLUMNS}
            row["tenant_id"] = tenant
            key = (row["tenant_id"], row["edge_id"], row["occurred_at"], row["event_id"])
            self.rows = [
                existing for existing in self.rows
                if (existing["tenant_id"], existing["edge_id"], existing["occurred_at"],
                    existing["event_id"]) != key
            ]
            self.rows.append(row)
            return []
        if tag in ("edge_history", "edge_history_as_of", "edge_history_purge"):
            tenant = self._require_tenant(cql, params)
            edge_id = (params or {}).get("edge_id")
            matching = [
                row for row in self.rows
                if row["tenant_id"] == tenant and row["edge_id"] == edge_id
            ]
            if tag == "edge_history_purge":
                self.rows = [row for row in self.rows if row not in matching]
                return []
            if tag == "edge_history_as_of":
                at = (params or {}).get("at")
                eligible = [row for row in matching if row["occurred_at"] <= at]
                eligible.sort(key=lambda row: (row["occurred_at"], row["event_id"]), reverse=True)
                return [FakeCassandraRow(eligible[0])] if eligible else []
            since = (params or {}).get("since")
            until = (params or {}).get("until")
            limit = int((params or {}).get("limit") or 100)
            eligible = [row for row in matching if since <= row["occurred_at"] <= until]
            eligible.sort(key=lambda row: (row["occurred_at"], row["event_id"]), reverse=True)
            return [FakeCassandraRow(row) for row in eligible[:limit]]
        raise AssertionError(f"unhandled cassandra statement: {tag or cql[:60]}")
