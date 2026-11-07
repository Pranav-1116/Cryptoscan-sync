"""Collector standard contract (gap analysis §D).

Every collector publishes one contract — who it is, what it may touch, what it
found, and how its result is signed — and one report per run. The review's
rule is absolute:

    "A collector that returns zero assets must explain whether it found
    nothing, lacked permissions, failed, or did not support the target."

So a zero-asset result without one of those four reasons is refused at
construction: zero is a measurement only when it comes with its explanation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

CONTRACT_SCHEMA = "cryptoscan.collector-contract/1"

FOUND_NOTHING = "FOUND_NOTHING"
NO_PERMISSION = "NO_PERMISSION"
FAILED = "FAILED"
UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"
ZERO_REASONS: tuple[str, ...] = (FOUND_NOTHING, NO_PERMISSION, FAILED,
                                 UNSUPPORTED_TARGET)

SUCCESS, PARTIAL, REFUSED, RUN_FAILED = ("SUCCESS", "PARTIAL", "REFUSED",
                                         "FAILED")
RUN_STATES: tuple[str, ...] = (SUCCESS, PARTIAL, REFUSED, RUN_FAILED)

PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED = ("PUBLIC", "INTERNAL",
                                              "CONFIDENTIAL", "RESTRICTED")
SENSITIVITY_LEVELS: tuple[str, ...] = (PUBLIC, INTERNAL, CONFIDENTIAL,
                                       RESTRICTED)


def collector_contract(*, collector_id: str, version: str,
                       supported_asset_types: Sequence[str],
                       required_permissions: Sequence[str],
                       data_sensitivity: str,
                       signature: Mapping[str, Any]) -> dict[str, Any]:
    """The publishable descriptor. Identity, version and integrity are mandatory.

    A contract without a signature is unsigned code claiming a scope: the
    "signature or integrity metadata" field is how a reader checks what
    produced the data.
    """
    if not str(collector_id or "").strip():
        raise ValueError("collector_id is mandatory: an unnamed collector is "
                         "unaccountable")
    if not str(version or "").strip():
        raise ValueError("version is mandatory: a collector without a version "
                         "cannot be qualified or revoked")
    types = [str(t) for t in supported_asset_types if str(t).strip()]
    if not types:
        raise ValueError("supported_asset_types is mandatory: a collector "
                         "that names no asset type has an unbounded claim")
    permissions = [str(p) for p in required_permissions if str(p).strip()]
    if not permissions:
        raise ValueError(
            "required_permissions is mandatory and may not be empty: a "
            "collector with no listed permission is one nobody can review "
             "before granting access")
    sensitivity = str(data_sensitivity or "").upper()
    if sensitivity not in SENSITIVITY_LEVELS:
        raise ValueError(f"unknown data_sensitivity {data_sensitivity!r}; "
                         f"expected one of {', '.join(SENSITIVITY_LEVELS)}")
    sig = dict(signature or {})
    if not sig.get("algorithm") or not sig.get("value"):
        raise ValueError(
            "signature.algorithm and signature.value are mandatory: "
            "integrity metadata is what makes the contract checkable")
    return {
        "schema": CONTRACT_SCHEMA,
        "collector_id": str(collector_id), "version": str(version),
        "supported_asset_types": types, "required_permissions": permissions,
        "data_sensitivity": sensitivity, "signature": sig,
    }


def collection_report(*, contract: Mapping[str, Any], started_at: str,
                      ended_at: str, target_scope: str, state: str,
                      assets_found: Sequence[Mapping[str, Any]],
                      evidence_ids: Sequence[str],
                      coverage_metrics: Mapping[str, Any],
                      zero_reason: str | None = None,
                      note: str | None = None) -> dict[str, Any]:
    """One run's report against a contract. Zero assets must explain themselves.

    * ``started_at``/``ended_at`` and ``target_scope`` are mandatory: a run
      with no clock or no scope is un-auditable;
    * a SUCCESS with no evidence is refused — success without evidence is a
      claim;
    * ``assets_found`` empty requires ``zero_reason`` from the four the review
      names. ``FAILED`` as a zero reason is honest; an unexplained zero is not.
    """
    if not str(started_at or "").strip() or not str(ended_at or "").strip():
        raise ValueError("started_at and ended_at are mandatory: a run "
                         "without a clock cannot be placed or aged")
    if str(ended_at) < str(started_at):
        raise ValueError("ended_at precedes started_at: the clock is wrong")
    if not str(target_scope or "").strip():
        raise ValueError("target_scope is mandatory: a run with no scope "
                         "reports nothing about anywhere")
    name = str(state or "").upper()
    if name not in RUN_STATES:
        raise ValueError(f"unknown run state {state!r}; expected one of "
                         f"{', '.join(RUN_STATES)}")
    assets = [dict(a) for a in assets_found]
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if name == SUCCESS and not ids:
        raise ValueError("a SUCCESS with no evidence is a claim: file the run "
                         "evidence or report a lesser state")
    if not assets:
        reason = str(zero_reason or "").upper()
        if reason not in ZERO_REASONS:
            raise ValueError(
                "a collector that returns zero assets must explain itself: "
                "FOUND_NOTHING, NO_PERMISSION, FAILED or UNSUPPORTED_TARGET — "
                "an unexplained zero is not a measurement")
    else:
        reason = None
    report = {
        "schema": CONTRACT_SCHEMA,
        "collector_id": contract.get("collector_id"),
        "version": contract.get("version"),
        "started_at": str(started_at), "ended_at": str(ended_at),
        "target_scope": str(target_scope),
        "state": name,
        "assets_found": assets,
        "asset_count": len(assets),
        "evidence_ids": ids,
        "coverage_metrics": dict(coverage_metrics or {}),
        "data_sensitivity": contract.get("data_sensitivity"),
        "zero_reason": reason,
        "note": str(note) if note else None,
    }
    material = json.dumps(report, sort_keys=True, default=str).encode()
    report["report_digest"] = "sha256:" + hashlib.sha256(material).hexdigest()
    return report
