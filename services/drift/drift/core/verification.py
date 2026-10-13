"""Condition-level verification of administratively resolved drift events.

``RESOLVED`` is an administrative statement by an operator; it is not
evidence that the drifted condition is gone (product vision §4.7). This
module computes what a LATER authorized scan's evidence says about the
condition, deterministically and without guessing:

- ``CONDITION_PRESENT`` — the later scan's evidence still matches the
  condition signature: the administrative closure closed nothing.
- ``VERIFIED`` — the later scan OBSERVED the same file and the condition
  signature is absent from everything it observed there.
- ``UNCOVERED`` — the later scan produced no evidence for the affected
  file. A vanished path alone cannot prove remediation, so no verdict is
  claimed.
- ``NOT_CHECKABLE`` — the event carries no current-finding signature
  (e.g. a REMOVED event); nothing is inferred from its absence.

The evaluator is pure: events and evidence arrive as mappings, verdicts
leave as data. Persistence and audit live with the callers.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

VERIFIED = "VERIFIED"
CONDITION_PRESENT = "CONDITION_PRESENT"
UNCOVERED = "UNCOVERED"
NOT_CHECKABLE = "NOT_CHECKABLE"


def condition_signature(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """The checkable condition of a drift event, or None when absent.

    The signature is the drifted-to state: algorithm + file path, with
    key size when the event recorded one. No signature means the event
    type has no current-finding condition to verify — never a guess.
    """
    details = event.get("drift_details") or {}
    if not isinstance(details, Mapping):
        return None
    finding = details.get("current_finding") or {}
    if not isinstance(finding, Mapping):
        return None
    algorithm = finding.get("algorithm")
    file_path = finding.get("file_path")
    if not algorithm or not file_path:
        return None
    return {
        "algorithm": str(algorithm),
        "file_path": str(file_path),
        "key_size": finding.get("key_size"),
    }


def _row_matches(signature: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    if str(row.get("algorithm") or "") != signature["algorithm"]:
        return False
    if str(row.get("file_path") or "") != signature["file_path"]:
        return False
    key_size = signature.get("key_size")
    if key_size not in (None, 0) and row.get("key_size") != key_size:
        return False
    return True


def evaluate_condition_verification(
    events: Iterable[Mapping[str, Any]],
    evidence_rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Verdict per event, from the later scan's evidence rows only."""
    rows = [row for row in evidence_rows if isinstance(row, Mapping)]
    files_observed: dict[str, int] = {}
    for row in rows:
        path = str(row.get("file_path") or "")
        if path:
            files_observed[path] = files_observed.get(path, 0) + 1

    verdicts: list[dict[str, Any]] = []
    for event in events:
        drift_id = event.get("drift_id") or event.get("id")
        signature = condition_signature(event)
        if signature is None:
            verdicts.append({
                "drift_id": drift_id,
                "verification_status": NOT_CHECKABLE,
                "reason": "event carries no current-finding signature",
            })
            continue
        observed = files_observed.get(signature["file_path"], 0)
        if observed == 0:
            verdicts.append({
                "drift_id": drift_id,
                "verification_status": UNCOVERED,
                "reason": (
                    "rescan produced no evidence for the affected file — "
                    "a vanished path is not proof of remediation"
                ),
            })
            continue
        present = any(_row_matches(signature, row) for row in rows)
        verdicts.append({
            "drift_id": drift_id,
            "verification_status": CONDITION_PRESENT if present else VERIFIED,
            "reason": (
                "condition signature still present in the rescan's evidence"
                if present else
                f"file observed ({observed} evidence record"
                f"{'s' if observed != 1 else ''}) and condition signature absent"
            ),
        })
    return verdicts
