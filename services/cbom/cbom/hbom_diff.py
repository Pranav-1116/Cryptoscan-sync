"""Compare two pinned estate HBOM snapshots (§4.4, round 72).

Estate-HBOM pinning (round 71) answers "what exactly was the hardware
estate then?". This module answers the operator's next question:
**what changed between two pins?** — added devices (new hardware in the
estate), removed devices (hardware gone), and field-level drift on the
devices that stayed (firmware version, TPM/HSM posture, capabilities,
risk, serial/revision/fingerprint identity).

It reuses the SAME diff engine as the CBOM leg (``snapshot_diff.py``,
round 56) — one set of join/flatten/exclude semantics, not a second
dialect — with two HBOM-specific decisions:

* **Identity is the component's ``bom-ref``** — for the estate HBOM that
  is ``hw:{asset_id}``, the 24/7 engine's stable device key. Unlike the
  CBOM (where bom-ref is a per-scan evidence id), the HBOM bom-ref IS
  stable across pins, so no spine keying is needed.
* **Two keying modes, both honest**:
  ``key_by="asset_id"`` (default) joins by device and compares
  ASSET-stable fields only — the observation ledger (last/first seen,
  last verified, last crypto check, the recorded evidence IDs) and the
  derived ``as_of`` anchor are excluded BY NAME, because a re-observed
  but unchanged device is not estate drift. ``key_by="bom_ref"``
  compares everything exactly, so observation churn is visible when an
  operator wants it. Neither mode invents semantics: excluded paths are
  listed in the result.

The diff is computed from the two content-addressed payloads on every
call and never stored — its trustworthiness is the pins'. Top-level
derived aggregates (``hsm_fleet``/``tpm_fleet``/``device_types``) are
not compared separately: they are functions of the component set, so
their drift is already reported component-by-component.
"""

from __future__ import annotations

from typing import Any

from cbom.hbom import HBOM_FORMAT
from cbom.snapshot_diff import _diff_component, diff_components

#: fields excluded from drift comparison in asset_id mode: they record
#: WHEN the device was observed (or the ledger of observations), not
#: WHAT the device is. A heartbeat that moves ``last_seen`` or appends
#: an evidence id is observation churn, not estate drift.
HBOM_OBSERVATION_EXCLUDED_PATHS = (
    "evidence.last_seen",
    "evidence.first_seen",
    "evidence.last_verified",
    "evidence.last_crypto_check",
    "evidence.evidence_ids",
)

#: metadata members excluded in asset_id mode for the same reason:
#: ``as_of`` is derived from the latest observation timestamp and moves
#: with every re-observation of an otherwise unchanged estate.
HBOM_METADATA_EXCLUDED_PATHS = ("as_of",)


def _require_hbom(document: dict[str, Any], *, role: str) -> None:
    if not isinstance(document, dict) or document.get("bomFormat") != HBOM_FORMAT:
        raise ValueError(
            f"{role} document is not a {HBOM_FORMAT} estate HBOM "
            f"(bomFormat={document.get('bomFormat') if isinstance(document, dict) else type(document).__name__!r})"
        )


def diff_hbom_documents(
    baseline_payload: dict[str, Any],
    target_payload: dict[str, Any],
    *,
    key_by: str = "asset_id",
) -> dict[str, Any]:
    """Full estate-HBOM vs estate-HBOM diff: device set drift, field
    drift on surviving devices, metadata drift — deterministic, derived.

    Args:
        baseline_payload: the OLDER pinned estate document.
        target_payload: the NEWER pinned estate document.
        key_by: "asset_id" (default) — device-keyed, observation churn
            excluded; "bom_ref" — exact comparison of everything the
            documents carry.

    Returns:
        The diff result (see module docstring); ``identical`` is True
        only when nothing compared differs under the chosen mode.
    """
    if key_by not in {"asset_id", "bom_ref"}:
        raise ValueError(f"unknown key_by {key_by!r}")
    _require_hbom(baseline_payload, role="baseline")
    _require_hbom(target_payload, role="target")

    excludes = HBOM_OBSERVATION_EXCLUDED_PATHS if key_by == "asset_id" else ()
    component_diff = diff_components(
        baseline_payload.get("components") or [],
        target_payload.get("components") or [],
        key_by="bom_ref",  # the HBOM bom-ref (hw:{asset_id}) is stable
        excludes=excludes,
    )

    baseline_meta = baseline_payload.get("metadata") or {}
    target_meta = target_payload.get("metadata") or {}
    meta_excludes = HBOM_METADATA_EXCLUDED_PATHS if key_by == "asset_id" else ()
    metadata_changes = _diff_component(baseline_meta, target_meta, meta_excludes)

    identical = (
        not component_diff["added"]
        and not component_diff["removed"]
        and not component_diff["changed"]
        and not metadata_changes
    )
    return {
        "key_by": key_by,
        "identical": identical,
        "excluded_paths": list(excludes) + list(meta_excludes),
        "components": component_diff,
        "metadata_changes": metadata_changes,
        "summary": {
            "baseline_components": len(baseline_payload.get("components") or []),
            "target_components": len(target_payload.get("components") or []),
            "added": len(component_diff["added"]),
            "removed": len(component_diff["removed"]),
            "changed": len(component_diff["changed"]),
            "unchanged": component_diff["unchanged"],
        },
    }
