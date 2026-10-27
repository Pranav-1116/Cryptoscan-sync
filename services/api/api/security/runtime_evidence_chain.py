"""Tamper-evident hash chain for runtime crypto events (spec 92 §11, §16).

Runtime observations are the strongest evidence the platform holds ("this
process really ran this operation"), which is exactly why they need the same
tamper evidence as network evidence. The generic implementation lives in
:mod:`api.security.evidence_chain`; runtime uses its own namespace and its own
id field (``event_id``), so a runtime event can never be read as network
evidence or vice versa.
"""

from __future__ import annotations

from typing import Any, Iterable

from api.security.evidence_chain import (
    GENESIS,
    MAX_ENTRIES,
    RUNTIME_CHAIN,
    attach_integrity as _attach_integrity,
    append as _append,
    canonical_record,
    empty_chain as _empty_chain,
    ensure_ids,
    read_chain as _read_chain,
    record_hash,
    verify as _verify,
)

CHAIN_SCHEMA = RUNTIME_CHAIN.chain_schema
VERIFY_SCHEMA = RUNTIME_CHAIN.verify_schema


def chain_key(tenant_id: str | None) -> str:
    return RUNTIME_CHAIN.key(tenant_id)


def ensure_event_ids(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return ensure_ids(events, RUNTIME_CHAIN)


def empty_chain() -> dict[str, Any]:
    return _empty_chain(RUNTIME_CHAIN)


def read_chain(db, *, tenant_id: str | None) -> dict[str, Any]:
    return _read_chain(db, spec=RUNTIME_CHAIN, tenant_id=tenant_id)


def append(
    db,
    events: Iterable[dict[str, Any]],
    *,
    run_id: str | None = None,
    tenant_id: str | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    """Append runtime events to the tenant runtime chain."""
    return _append(db, events, spec=RUNTIME_CHAIN, run_id=run_id, tenant_id=tenant_id, user=user)


def attach_integrity(events: Iterable[dict[str, Any]], chain: dict[str, Any]) -> list[dict[str, Any]]:
    return _attach_integrity(events, chain, spec=RUNTIME_CHAIN)


def verify(
    chain: dict[str, Any],
    *,
    events: Iterable[dict[str, Any]] = (),
    events_by_run: dict[str, Iterable[dict[str, Any]]] | None = None,
    expected_head: str | None = None,
) -> dict[str, Any]:
    return _verify(
        chain,
        spec=RUNTIME_CHAIN,
        records=events,
        records_by_run=events_by_run,
        expected_head=expected_head,
    )


__all__ = [
    "CHAIN_SCHEMA",
    "GENESIS",
    "MAX_ENTRIES",
    "VERIFY_SCHEMA",
    "append",
    "attach_integrity",
    "canonical_record",
    "chain_key",
    "empty_chain",
    "ensure_event_ids",
    "read_chain",
    "record_hash",
    "verify",
]
