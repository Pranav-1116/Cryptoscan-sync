"""Tamper-evident hash chain for network evidence (spec 67 §24, §29).

The implementation lives in :mod:`api.security.evidence_chain` so runtime events
and network evidence get the same treatment without sharing a chain head. This
module keeps the network-facing names (and signatures) that the routers and
tests already use.
"""

from __future__ import annotations

from typing import Any, Iterable

from api.security.evidence_chain import (
    GENESIS,
    MAX_ENTRIES,
    NETWORK_CHAIN,
    canonical_record,
    empty_chain as _empty_chain,
    ensure_ids,
    read_chain as _read_chain,
    record_hash,
    verify as _verify,
    attach_integrity as _attach_integrity,
    append as _append,
)

CHAIN_SCHEMA = NETWORK_CHAIN.chain_schema
VERIFY_SCHEMA = NETWORK_CHAIN.verify_schema


def chain_key(tenant_id: str | None) -> str:
    return NETWORK_CHAIN.key(tenant_id)


def ensure_evidence_ids(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return ensure_ids(records, NETWORK_CHAIN)


def empty_chain() -> dict[str, Any]:
    return _empty_chain(NETWORK_CHAIN)


def read_chain(db, *, tenant_id: str | None) -> dict[str, Any]:
    return _read_chain(db, spec=NETWORK_CHAIN, tenant_id=tenant_id)


def append(
    db,
    records: Iterable[dict[str, Any]],
    *,
    run_id: str | None = None,
    tenant_id: str | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    """Append network evidence to the tenant chain; returns the head receipt."""
    return _append(db, records, spec=NETWORK_CHAIN, run_id=run_id, tenant_id=tenant_id, user=user)


def attach_integrity(records: Iterable[dict[str, Any]], chain: dict[str, Any]) -> list[dict[str, Any]]:
    return _attach_integrity(records, chain, spec=NETWORK_CHAIN)


def verify(
    chain: dict[str, Any],
    *,
    records: Iterable[dict[str, Any]] = (),
    records_by_run: dict[str, Iterable[dict[str, Any]]] | None = None,
    expected_head: str | None = None,
) -> dict[str, Any]:
    return _verify(
        chain,
        spec=NETWORK_CHAIN,
        records=records,
        records_by_run=records_by_run,
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
    "ensure_evidence_ids",
    "read_chain",
    "record_hash",
    "verify",
]
