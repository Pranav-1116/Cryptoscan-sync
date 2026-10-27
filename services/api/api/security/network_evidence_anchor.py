"""Exportable anchor receipts for the network evidence hash chain (spec 67 §28, §31).

The chain in :mod:`api.security.network_evidence_chain` is
``local-database-only``: it proves that no record was rewritten *inside* this
database. If an attacker can rewrite the database, they can rewrite the chain
with it. An anchor receipt closes exactly that hole, and nothing more:

* at a point in time the operator signs the current chain head with a key the
  database does not hold (``HMAC-SHA256`` over the canonical receipt);
* the receipt is **exported** — to a WORM bucket, a change ticket, a CMDB, a
  signed mail — so a later rewrite of the database no longer matches it;
* verification compares the anchored head against the live chain and reports
  ``HEAD_INTACT`` / ``ADVANCED`` / ``HISTORY_REWRITTEN``.

Honesty about the limit: an anchor is only external once it has left this
system. Until then the receipt says ``external: false`` and the report says
``anchoring: "signed-receipt-exportable"`` — never "anchored externally". If no
key is configured, anchoring refuses instead of inventing one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

SCHEMA = "cryptoscan.network-evidence-anchor/1"
VERIFY_SCHEMA = "cryptoscan.network-evidence-anchor-verification/1"
KEY_ENV = "CRYPTOSCAN_ANCHOR_KEY"
MAX_ANCHORS = 200
SETTING_PREFIX = "network:evidence-anchors:"

_allowed_status = ("HEAD_INTACT", "ADVANCED", "HISTORY_REWRITTEN", "SIGNATURE_INVALID", "UNKNOWN")


class AnchorError(RuntimeError):
    """Raised when anchoring cannot be performed honestly."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(reason)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def settings_key(tenant_id: str | None) -> str:
    return f"{SETTING_PREFIX}{tenant_id or 'global'}"


def anchor_key() -> tuple[bytes | None, str]:
    """Return the signing key and where it came from (never the key itself)."""
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        return None, "NOT_CONFIGURED"
    try:
        from api.security.vault import is_reference, resolve_secret

        if is_reference(raw):
            return resolve_secret(raw).encode("utf-8"), "REFERENCE"
    except Exception:  # noqa: BLE001 - an unresolvable reference is not a key
        return None, "UNRESOLVABLE_REFERENCE"
    return raw.encode("utf-8"), "ENVIRONMENT"


def key_status() -> dict[str, Any]:
    key, source = anchor_key()
    return {
        "configured": key is not None,
        "source": source,
        "variable": KEY_ENV,
        "scheme": "HMAC-SHA256",
        "note": (
            "the signing key must live outside the database — otherwise the anchor "
            "proves nothing an attacker with database access cannot forge"
        ),
    }


def _canonical(payload: dict[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_receipt(receipt: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(receipt), hashlib.sha256).hexdigest()


def _chain_summary(chain: dict[str, Any]) -> dict[str, Any]:
    entries = list(chain.get("entries") or [])
    return {
        "namespace": "network",
        "seq": int(chain.get("seq") or 0),
        "head": chain.get("head"),
        "entries": len(entries),
        "last_entry": entries[-1] if entries else None,
        "truncated": bool(chain.get("truncated_before_seq")),
        "complete_from_seq": int(chain.get("truncated_before_seq") or 0),
    }


def _read(db, tenant_id: str | None) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == settings_key(tenant_id))).scalars().first()
    if row is None or not row.value:
        return []
    try:
        payload = json.loads(row.value)
    except (TypeError, ValueError):
        return []
    anchors = payload.get("anchors") if isinstance(payload, dict) else None
    return list(anchors or [])


def _write(db, tenant_id: str | None, anchors: list[dict[str, Any]], user: str | None) -> None:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    key = settings_key(tenant_id)
    value = json.dumps({"schema": SCHEMA, "anchors": anchors[-MAX_ANCHORS:]}, default=str)
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        db.add(AppSetting(key=key, value=value, updated_by=user))
    else:
        row.value = value
        row.updated_by = user
    db.commit()


def create_anchor(
    db,
    *,
    tenant_id: str | None,
    user: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Sign the current network chain head into an exportable receipt."""
    from api.security.network_evidence_chain import read_chain

    key, source = anchor_key()
    if key is None:
        raise AnchorError(
            "anchor_key_not_configured",
            f"{KEY_ENV} is not configured ({source}) — an unsigned anchor would be a claim, not evidence",
        )
    chain = read_chain(db, tenant_id=tenant_id)
    if not chain.get("entries"):
        raise AnchorError(
            "evidence_chain_empty",
            "there is no chained network evidence to anchor yet",
        )
    summary = _chain_summary(chain)
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "anchor_id": f"anchor-{uuid.uuid4().hex[:16]}",
        "tenant": tenant_id or "global",
        "created_at": _now(),
        "created_by": user,
        "note": (note or "")[:400] or None,
        "chain": summary,
        "signature_scheme": "HMAC-SHA256",
        "key_source": source,
        "external": False,
        "export_hint": (
            "store this receipt outside CryptoScan (WORM bucket, change ticket, CMDB). "
            "Until it is exported it is not an external anchor"
        ),
        "boundary": "an anchor attests the chain head at one moment — it does not prove the records are correct",
    }
    receipt["signature"] = sign_receipt(receipt, key)
    anchors = _read(db, tenant_id)
    anchors.append(receipt)
    _write(db, tenant_id, anchors, user)
    return receipt


def list_anchors(db, *, tenant_id: str | None) -> dict[str, Any]:
    anchors = _read(db, tenant_id)
    return {
        "schema": SCHEMA,
        "count": len(anchors),
        "anchors": anchors,
        "key": key_status(),
        "max_anchors": MAX_ANCHORS,
        "note": "a receipt is external only once it has left this database",
    }


def verify_receipt(receipt: dict[str, Any], chain: dict[str, Any], *, key: bytes | None) -> dict[str, Any]:
    """Compare one receipt against the live chain."""
    if key is None:
        return {
            "schema": VERIFY_SCHEMA,
            "anchor_id": receipt.get("anchor_id"),
            "status": "UNKNOWN",
            "signature_valid": None,
            "reason": f"{KEY_ENV} is not configured — the signature cannot be checked",
            "rewritten": None,
        }
    signature_valid = hmac.compare_digest(str(receipt.get("signature") or ""), sign_receipt(receipt, key))
    anchored = receipt.get("chain") or {}
    anchored_seq = int(anchored.get("seq") or 0)
    anchored_head = anchored.get("head")
    current_seq = int(chain.get("seq") or 0)
    current_head = chain.get("head")
    entries = {int(entry.get("seq") or 0): entry for entry in chain.get("entries") or []}
    entry = entries.get(anchored_seq)
    entry_hash = (entry or {}).get("record_hash")

    if not signature_valid:
        status, rewritten, reason = (
            "SIGNATURE_INVALID",
            True,
            "the receipt signature does not match this key — the receipt was altered or signed with another key",
        )
    elif anchored_seq == 0 or not anchored_head:
        status, rewritten, reason = "UNKNOWN", None, "the receipt carries no anchored head"
    elif current_seq < anchored_seq:
        status, rewritten, reason = (
            "HISTORY_REWRITTEN",
            True,
            "the live chain is shorter than the anchored one — entries were deleted after the anchor",
        )
    elif entry is None:
        status, rewritten, reason = (
            "HISTORY_REWRITTEN" if current_seq >= anchored_seq else "UNKNOWN",
            True,
            f"the anchored sequence {anchored_seq} is no longer present in the chain",
        )
    elif current_seq == anchored_seq and current_head == anchored_head:
        status, rewritten, reason = "HEAD_INTACT", False, "the live chain still ends at the anchored head"
    elif current_head == anchored_head or entry_hash == anchored_head:
        status, rewritten, reason = (
            "ADVANCED",
            False,
            f"the chain advanced from seq {anchored_seq} to {current_seq}; the anchored prefix is unchanged",
        )
    else:
        status, rewritten, reason = (
            "HISTORY_REWRITTEN",
            True,
            "the entry at the anchored sequence no longer hashes to the anchored head",
        )

    return {
        "schema": VERIFY_SCHEMA,
        "anchor_id": receipt.get("anchor_id"),
        "status": status,
        "signature_valid": signature_valid,
        "rewritten": rewritten,
        "anchored_seq": anchored_seq,
        "anchored_head": anchored_head,
        "current_seq": current_seq,
        "current_head": current_head,
        "reason": reason,
        "external": bool(receipt.get("external")),
        "limitations": [
            "an anchor proves the chain head at one moment; a record can still be wrong, only not silently rewritten",
            "receipts stored only in this database are self-attested — export them to make them external",
        ],
    }


def verify_anchor(db, receipt: dict[str, Any], *, tenant_id: str | None) -> dict[str, Any]:
    from api.security.network_evidence_chain import read_chain

    key, _source = anchor_key()
    chain = read_chain(db, tenant_id=tenant_id)
    report = verify_receipt(receipt, chain, key=key)
    if receipt.get("schema") != SCHEMA:
        report["status"] = "UNKNOWN"
        report["reason"] = f"receipt schema is {receipt.get('schema')!r}, expected {SCHEMA!r}"
    return report


def status(db, *, tenant_id: str | None) -> dict[str, Any]:
    anchors = _read(db, tenant_id)
    return {
        "schema": SCHEMA,
        "anchoring": "signed-receipt-exportable",
        "distributed": False,
        "external": any(bool(anchor.get("external")) for anchor in anchors),
        "anchors": len(anchors),
        "last_anchor": anchors[-1] if anchors else None,
        "key": key_status(),
        "limitations": [
            "the anchor key must be held outside the database",
            "an unexported receipt is a local claim, not an external anchor",
        ],
    }


__all__ = [
    "KEY_ENV",
    "MAX_ANCHORS",
    "SCHEMA",
    "SETTING_PREFIX",
    "VERIFY_SCHEMA",
    "AnchorError",
    "anchor_key",
    "create_anchor",
    "key_status",
    "list_anchors",
    "settings_key",
    "sign_receipt",
    "status",
    "verify_anchor",
    "verify_receipt",
]
