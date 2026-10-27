"""Exportable anchor receipts for projected BOM sets (spec 93 §12, §18).

The projection is content-addressed: every BOM carries the same ``projection_id``
because all six are views of one evidence graph. That id proves the BOMs agree
with *each other*; it does not prove the document an auditor is holding is the
document CryptoScan produced. An anchor receipt closes that gap and nothing more:

* at a point in time the operator signs ``{projection_id, per-BOM digests}`` with
  a key the database does not hold (``HMAC-SHA256``, ``CRYPTOSCAN_ANCHOR_KEY`` —
  the same out-of-database key policy as the network evidence chain);
* the receipt is exported by the operator (WORM bucket, change ticket, CMDB,
  signed mail), so a later rewrite of the database no longer matches it;
* verification recomputes the digests from the BOMs in hand and reports
  ``PROJECTION_INTACT`` / ``PROJECTION_CHANGED`` / ``SIGNATURE_INVALID`` /
  ``KEY_UNKNOWN``.

Honest limits: a receipt attests *which* BOM set existed at a moment, not that
the facts inside it are correct (the evidence chain and coverage matrix carry
that). Until it leaves this system the receipt says ``external: false`` — never
"externally anchored". With no key configured, anchoring refuses rather than
inventing a signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from api.security.network_evidence_anchor import KEY_ENV, AnchorError, anchor_key, key_status

SCHEMA = "cryptoscan.estate-bom-anchor/1"
VERIFY_SCHEMA = "cryptoscan.estate-bom-anchor-verification/1"
SETTING_PREFIX = "estate:bom-anchors:"
MAX_ANCHORS = 200
MAX_BOMS = 8


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def settings_key(tenant_id: str | None) -> str:
    return f"{SETTING_PREFIX}{tenant_id or 'global'}"


def _canonical(payload: Mapping[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_receipt(receipt: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(receipt), hashlib.sha256).hexdigest()


#: Fields that describe *when* something happened, not what it says. Hashing them
#: would make the same snapshot digest differently on every read, which would make
#: the anchor useless and the drift report noisy.
VOLATILE_FIELDS = ("generated_at", "observed_at")


def _stable(value: Any) -> Any:
    """Recursively drop volatile timestamps so a digest covers content only."""
    if isinstance(value, Mapping):
        return {key: _stable(item) for key, item in value.items() if key not in VOLATILE_FIELDS}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    return value


def stable_view(value: Any) -> Any:
    """Public alias of :func:`_stable` — the canonical, timestamp-free view."""
    return _stable(value)


def bom_digest(bom: Mapping[str, Any]) -> str:
    """Content digest of one projected BOM: canonical JSON minus timestamps."""
    body = json.dumps(_stable(bom), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def projection_digest(boms: Mapping[str, Mapping[str, Any]]) -> str:
    """Digest over the *set* of BOMs: a changed, added or removed BOM changes it."""
    material = "|".join(f"{kind.upper()}:{bom_digest(bom)}" for kind, bom in sorted(boms.items()))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read(db: Any, tenant_id: str | None) -> list[dict[str, Any]]:
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


def _write(db: Any, tenant_id: str | None, anchors: list[dict[str, Any]], user: str | None) -> None:
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
    db: Any,
    *,
    boms: Mapping[str, Mapping[str, Any]],
    projection_id: str,
    tenant_id: str | None,
    run_id: Any = None,
    user: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Sign one projected BOM set into an exportable receipt."""
    if not boms:
        raise AnchorError(
            "no_projection_to_anchor",
            "there is no projected BOM set to anchor — run an estate discovery first",
        )
    if len(boms) > MAX_BOMS:
        raise AnchorError("too_many_boms", f"a BOM set is at most {MAX_BOMS} documents")
    key, source = anchor_key()
    if key is None:
        raise AnchorError(
            "anchor_key_not_configured",
            f"{KEY_ENV} is not configured ({source}) — an unsigned anchor would be a claim, not evidence",
        )
    digests = {kind.upper(): bom_digest(bom) for kind, bom in boms.items()}
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "anchor_id": f"estate-anchor-{uuid.uuid4().hex[:16]}",
        "tenant": tenant_id or "global",
        "run_id": run_id,
        "projection_id": projection_id,
        "created_at": _now(),
        "created_by": user,
        "note": (note or "")[:400] or None,
        "bom_count": len(digests),
        "bom_digests": digests,
        "bom_set_digest": projection_digest(boms),
        "signature_scheme": "HMAC-SHA256",
        "key_source": source,
        "external": False,
        "export_hint": (
            "store this receipt outside CryptoScan (WORM bucket, change ticket, CMDB). "
            "Until it is exported it is not an external anchor"
        ),
        "boundary": (
            "an anchor attests which BOM set existed at one moment; it does not attest that the facts "
            "inside the BOMs are correct or complete — the coverage matrix and evidence chain carry that"
        ),
    }
    receipt["signature"] = sign_receipt(receipt, key)
    anchors = _read(db, tenant_id)
    anchors.append(receipt)
    _write(db, tenant_id, anchors, user)
    return receipt


def list_anchors(db: Any, *, tenant_id: str | None) -> dict[str, Any]:
    anchors = _read(db, tenant_id)
    return {
        "schema": SCHEMA,
        "count": len(anchors),
        "anchors": anchors,
        "key": key_status(),
        "max_anchors": MAX_ANCHORS,
        "note": "a receipt is external only once it has left this database",
    }


def verify_anchor(receipt: Mapping[str, Any], boms: Mapping[str, Mapping[str, Any]], *, key: bytes | None) -> dict[str, Any]:
    """Recompute the digests of the BOMs in hand and compare them with the receipt."""
    if key is None:
        return {
            "schema": VERIFY_SCHEMA,
            "anchor_id": receipt.get("anchor_id"),
            "status": "KEY_UNKNOWN",
            "signature_valid": None,
            "changed_boms": [],
            "reason": f"{KEY_ENV} is not configured — the signature cannot be checked",
        }
    signature_valid = hmac.compare_digest(str(receipt.get("signature") or ""), sign_receipt(receipt, key))
    anchored = dict(receipt.get("bom_digests") or {})
    current = {kind.upper(): bom_digest(bom) for kind, bom in boms.items()}
    changed = sorted(kind for kind, digest in anchored.items() if current.get(kind) != digest)
    added = sorted(set(current) - set(anchored))
    removed = sorted(set(anchored) - set(current))

    if not signature_valid:
        status = "SIGNATURE_INVALID"
        reason = "the receipt signature does not match this key — the receipt was altered or signed with another key"
    elif changed or added or removed:
        status = "PROJECTION_CHANGED"
        reason = (
            "the BOM set in hand no longer matches the anchored one: "
            f"changed={changed or 'none'} added={added or 'none'} removed={removed or 'none'}"
        )
    else:
        status = "PROJECTION_INTACT"
        reason = "every BOM in hand hashes to the digest in the receipt"

    return {
        "schema": VERIFY_SCHEMA,
        "anchor_id": receipt.get("anchor_id"),
        "projection_id": receipt.get("projection_id"),
        "status": status,
        "signature_valid": signature_valid,
        "changed_boms": changed,
        "added_boms": added,
        "removed_boms": removed,
        "reason": reason,
        "note": (
            "PROJECTION_CHANGED is not automatically tampering: a new discovery produces new BOMs. It means the "
            "anchored set is no longer current, and both the receipt and the new discovery must be kept"
        ),
    }
