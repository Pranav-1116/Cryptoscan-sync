"""Evidence reprocessing contract (gap analysis §5, key database rule).

"Preserve original evidence separately from normalized facts. If a parser
changes or a normalization policy improves, CryptoScan should be able to
reprocess retained evidence without losing the original observation."

Reprocessing produces a NEW normalization of the SAME original observation.
The contract enforces the separation absolutely:

- the original observation and its content hash travel through reprocessing
  byte-identical — :func:`original_intact` is the acceptance check;
- every normalization is versioned and dated, and a superseded normalization
  is kept in history, never overwritten into the void;
- a record with no retained original observation is refused: it cannot be
  reprocessed, only re-guessed;
- a "reprocess" that edits the original is refused — that is falsification,
  not normalization.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

REPROCESS_SCHEMA = "cryptoscan.evidence-reprocessing/1"


def _freeze(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def original_fingerprint(record: Mapping[str, Any]) -> str:
    """The identity of the retained original observation."""
    finding_data = record.get("finding_data")
    if finding_data is None:
        raise ValueError(
            "a record with no retained original observation cannot be "
            "reprocessed: re-guessing is not reprocessing")
    return "sha256:" + hashlib.sha256(
        _freeze(finding_data).encode("utf-8")).hexdigest()


def reprocessable(record: Mapping[str, Any]) -> dict[str, Any]:
    """Verify a record is fit for reprocessing and say why if not."""
    fingerprint = original_fingerprint(record)
    content_hash = str(record.get("content_hash") or "").strip()
    if not content_hash:
        raise ValueError(
            "a record without a content hash cannot prove its original "
            "survived reprocessing")
    return {
        "schema": REPROCESS_SCHEMA,
        "reprocessable": True,
        "original_fingerprint": fingerprint,
        "content_hash": content_hash,
    }


def reprocess(record: Mapping[str, Any], *, normalizer_version: str,
              normalized_crypto: Mapping[str, Any],
              at: str | None = None) -> dict[str, Any]:
    """Normalize the retained original again, never touching it.

    Returns a new record view: the original observation and content hash are
    carried through unchanged; the new normalization is stamped with its
    normalizer version and time; the previous normalization moves into
    ``superseded_normalizations`` — improving the parser never erases what
    the old one concluded.
    """
    check = reprocessable(record)
    version = str(normalizer_version or "").strip()
    if not version:
        raise ValueError(
            "normalizer_version is mandatory: an unversioned normalization "
            "cannot be reproduced or blamed")
    if not isinstance(normalized_crypto, Mapping):
        raise ValueError("normalized_crypto must be a mapping of normalized facts")
    stamp = at or datetime.now(timezone.utc).isoformat()

    out = dict(record)
    # the original is carried through byte-identical — enforced, not promised
    out["finding_data"] = record["finding_data"]
    out["content_hash"] = record["content_hash"]

    previous = record.get("normalized_crypto")
    history = list(record.get("superseded_normalizations") or [])
    if previous is not None:
        history.append({
            "normalized_crypto": previous,
            "normalization": dict(record.get("normalization") or {}),
        })
    out["normalized_crypto"] = dict(normalized_crypto)
    out["normalization"] = {
        "normalizer_version": version,
        "reprocessed_at": stamp,
        "original_fingerprint": check["original_fingerprint"],
    }
    out["superseded_normalizations"] = history
    if not original_intact(record, out):
        raise ValueError(
            "reprocessing altered the original observation: refused")
    return out


def original_intact(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any] | bool:
    """The acceptance check: the original survived byte-identical."""
    same_hash = (str(before.get("content_hash") or "") ==
                 str(after.get("content_hash") or "") and
                 bool(before.get("content_hash")))
    try:
        same_observation = _freeze(before.get("finding_data")) == _freeze(
            after.get("finding_data")) and before.get("finding_data") is not None
    except Exception:
        same_observation = False
    ok = bool(same_hash and same_observation)
    return {
        "original_intact": ok,
        "content_hash_match": same_hash,
        "observation_match": same_observation,
    }


def normalize_with(record: Mapping[str, Any], *, normalizer_version: str,
                   normalizer: Callable[[Mapping[str, Any]], Mapping[str, Any]],
                   at: str | None = None) -> dict[str, Any]:
    """Reprocess by running a normalizer function over the ORIGINAL only.

    The normalizer receives a frozen COPY of the original observation: even a
    buggy or hostile normalizer structurally cannot edit the retained record.
    """
    if not callable(normalizer):
        raise ValueError("normalizer must be callable")
    raw_copy = json.loads(_freeze(record["finding_data"]))
    facts = normalizer(raw_copy)
    return reprocess(record, normalizer_version=normalizer_version,
                     normalized_crypto=facts, at=at)
