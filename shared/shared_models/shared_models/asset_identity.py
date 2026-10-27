"""The crypto asset identity spine (§4.2, round 57).

The platform has three write-side shapes for the same crypto observation —
evidence rows, ``crypto_assets`` rows and fact rows — and the BOM renders
components from either of the first two. Each shape carries the same five
identity fields, but until now identity lived only as *in-memory tuples*
in each path (the asset repository's merge tuple, the fact kernel's
``fact_key``), so nothing durable joined an observation across shapes,
scans or exports.

This module is the ONE canonical, durable string form:

    "fact:v1:" + sha256(algorithm | purpose | file_path | key_size | mode)

The five fields are exactly the fact kernel's declared identity
(``db/fact_projection.py`` — "what + why + where + parameters"; line
number deliberately excluded: the same algorithm/purpose/parameters in
the same file is one fact observed at several lines). Cloud-collected
assets participate naturally: their stable resource ref
(``aws-kms://…``) is their ``file_path``.

Contract:

* **Verbatim field values** — upstream normalization (the normalization
  engine) has already run by the time rows exist; the spine does not
  re-normalize, it commits. ``None`` normalizes to ``""`` (SQLite NULL
  distinctness must not fork identity, same rule as the fact kernel).
* **Versioned** (``fact:v1``) — if the identity space is ever refined
  (e.g. a context-hash locator), the new derivation ships as ``v2`` and
  the old keys stay interpretable.
* **Not a physical-device claim.** Two observations sharing a key are the
  same *crypto fact*; whether they are the same physical key/HSM/system
  is a separate, undeclared judgment (§4.4: algorithms alone cannot join
  observations to a device).
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

#: bumped ONLY with a deliberate identity-space redesign; v1 = fact kernel
IDENTITY_VERSION = "fact:v1"
_FIELD_SEPARATOR = "\x1f"  # unit separator — cannot occur in field values


def _field(value: Any) -> str:
    """None → "" (never let SQL NULL distinctness fork identity)."""
    return "" if value is None else str(value)


def crypto_asset_key(
    algorithm: Any,
    purpose: Any,
    file_path: Any,
    key_size: Any,
    mode: Any,
) -> str:
    """The canonical durable identity for one crypto asset/fact."""
    material = _FIELD_SEPARATOR.join(
        (_field(algorithm), _field(purpose), _field(file_path),
         _field(key_size), _field(mode)))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{IDENTITY_VERSION}:{digest}"


def crypto_asset_key_from_row(row: Mapping[str, Any]) -> str:
    """Derive the spine key from any observation shape (evidence row,
    crypto_assets row, fact row, scanner dict).

    Returns "" (no identity claim) when the row has no algorithm or no
    locator (file_path / resource ref): identity is what + why + WHERE +
    parameters — a key without a "where" would join unrelated rows, which
    is worse than no key.
    """
    algorithm = _field(row.get("algorithm"))
    file_path = _field(row.get("file_path"))
    if not algorithm or not file_path:
        return ""
    return crypto_asset_key(
        algorithm,
        row.get("purpose"),
        file_path,
        row.get("key_size"),
        row.get("mode"),
    )
