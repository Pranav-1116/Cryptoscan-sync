"""Compare two pinned CBOM snapshots (§4.4, round 56).

Snapshot pinning (round 45) answers "what exactly was the CBOM then?".
This module answers the operator's next question: **what changed between
two pins?** — added components (new crypto in the estate), removed
components (retired findings), and field-level drift on the components
that stayed (key size, mode, compliance verdict, confidence).

Design contract:

* **Identity is the component's ``bom-ref``** (the evidence id — stable
  across pins of the same finding), falling back to ``name@type``. Two
  components with no bom-ref and the same name are the same asset; we
  never invent identity beyond what the document carries.
* **Path-level diff, no semantics invented**: every field of a surviving
  component is compared via its dotted path; a change is reported with
  its exact before/after values. ``properties`` lists are keyed by
  property *name* (order is not semantic); every other list is compared
  by index.
* **Deterministic**: components, paths and results are sorted, so the
  same pair of snapshots always produces the byte-identical diff.
* The diff is **computed, never stored** — it derives from the two
  content-addressed payloads, so it is as trustworthy as the pins and
  costs nothing to keep current.
"""

from __future__ import annotations

from typing import Any


def component_ref(component: dict[str, Any]) -> str:
    """Stable identity of one component within/between snapshots."""
    ref = component.get("bom-ref")
    if ref:
        return str(ref)
    return f"{component.get('name') or 'UNKNOWN'}@{component.get('type') or 'unknown'}"


#: fields excluded from drift comparison in asset_key mode: they name the
#: OBSERVATION (per-scan evidence id/position/hashes), not the asset.
#: Two scans of the same crypto fact produce new evidence rows by design —
#: that churn is not estate drift.
SPINE_EXCLUDED_PATHS = (
    "bom-ref",                      # per-scan evidence id
    "evidence.identity",            # observation method/confidence chain
    "evidence.occurrences",         # positional
    "evidence.file",
    "evidence.line",
    "evidence.content_hash",
    "evidence.chain_hash",
    "properties.cryptoscan:asset_key",  # the key itself
)


def stable_component_key(component: dict[str, Any]) -> str:
    """Identity-spine key (round 57) — stable ACROSS scans, unlike
    bom-ref (a per-scan evidence id). Falls back to bom-ref form for
    components built before the spine, namespaced so the two keyspaces
    never collide."""
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "cryptoscan:asset_key":
            return f"spine:{prop.get('value')}"
    return f"ref:{component_ref(component)}"


def _path_excluded(path: str, excludes: tuple[str, ...]) -> bool:
    return any(path == ex or path.startswith(ex + ".") or path.startswith(ex + "[")
               for ex in excludes)


def _flatten(value: Any, prefix: str = "") -> dict[str, str | None]:
    """Flatten a component to dotted-path → scalar, so field drift is
    reportable per path. Lists flatten by index — except ``properties``,
    whose order is not semantic and which is keyed by property name."""
    out: dict[str, str | None] = {}
    if isinstance(value, dict):
        for key in sorted(value):
            out.update(_flatten(value[key], f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, list):
        if prefix == "properties" or prefix.endswith(".properties"):
            for item in value:
                if isinstance(item, dict) and item.get("name") is not None:
                    out[f"{prefix}.{item['name']}"] = item.get("value")
                else:  # malformed property: fall back to positional
                    out[f"{prefix}[{len(out)}]"] = str(item)
        else:
            for index, item in enumerate(value):
                out.update(_flatten(item, f"{prefix}[{index}]"))
    else:
        out[prefix] = value
    return out


def _diff_component(before: dict[str, Any], after: dict[str, Any],
                    excludes: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    flat_before = _flatten(before)
    flat_after = _flatten(after)
    changes = []
    for path in sorted(set(flat_before) | set(flat_after)):
        if excludes and _path_excluded(path, excludes):
            continue
        old, new = flat_before.get(path), flat_after.get(path)
        if old != new:
            changes.append({"path": path, "before": old, "after": new})
    return changes


def diff_components(before: list[dict[str, Any]], after: list[dict[str, Any]],
                    *, key_by: str = "bom_ref",
                    excludes: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Set + field diff of two component lists.

    key_by="bom_ref" (default): exact same-scan semantics — the per-scan
    evidence id IS the identity, so evidence-level mutation is visible.

    key_by="asset_key": the identity-spine key (round 57) — stable across
    scans. Repeated scans produce new evidence rows (new bom-refs) for
    unchanged crypto BY DESIGN; under bom-ref keying that churn reads as
    100% turnover. Spine keying joins the same crypto fact across scans
    and compares only asset-stable fields (observation-position and
    hash fields are excluded, named in SPINE_EXCLUDED_PATHS).

    excludes: additional caller-supplied paths to exclude from field
    drift (same path grammar as SPINE_EXCLUDED_PATHS). The HBOM estate
    diff (round 72) uses this to separate observation churn from estate
    drift; the default () changes nothing for existing callers.
    """
    if key_by not in {"bom_ref", "asset_key"}:
        raise ValueError(f"unknown key_by {key_by!r}")
    all_excludes = (SPINE_EXCLUDED_PATHS if key_by == "asset_key" else ()) + tuple(excludes or ())
    key_of = (stable_component_key if key_by == "asset_key" else component_ref)
    before_map = {key_of(c): c for c in before or []}
    after_map = {key_of(c): c for c in after or []}
    added_keys = sorted(set(after_map) - set(before_map))
    removed_keys = sorted(set(before_map) - set(after_map))
    changed = []
    unchanged = 0
    for key in sorted(set(before_map) & set(after_map)):
        changes = _diff_component(before_map[key], after_map[key], all_excludes)
        if changes:
            changed.append({"key": key,
                            "bom-ref": before_map[key].get("bom-ref"),
                            "changes": changes})
        else:
            unchanged += 1
    return {
        "key_by": key_by,
        "added": [
            {"key": key, "bom-ref": after_map[key].get("bom-ref"),
             "name": after_map[key].get("name"),
             "type": after_map[key].get("type")}
            for key in added_keys
        ],
        "removed": [
            {"key": key, "bom-ref": before_map[key].get("bom-ref"),
             "name": before_map[key].get("name"),
             "type": before_map[key].get("type")}
            for key in removed_keys
        ],
        "changed": changed,
        "unchanged": unchanged,
    }


def diff_snapshots(baseline_payload: dict[str, Any], target_payload: dict[str, Any],
                   *, key_by: str = "bom_ref") -> dict[str, Any]:
    """Full snapshot-vs-snapshot diff: component set drift, field drift on
    survivors, and metadata drift — all deterministic, all derived."""
    baseline_components = baseline_payload.get("components") or []
    target_components = target_payload.get("components") or []
    component_diff = diff_components(baseline_components, target_components, key_by=key_by)
    baseline_meta = baseline_payload.get("metadata") or {}
    target_meta = target_payload.get("metadata") or {}
    metadata_changes = _diff_component(baseline_meta, target_meta)
    identical = (
        not component_diff["added"]
        and not component_diff["removed"]
        and not component_diff["changed"]
        and not metadata_changes
    )
    return {
        "identical": identical,
        "components": component_diff,
        "metadata_changes": metadata_changes,
        "summary": {
            "baseline_components": len(baseline_components),
            "target_components": len(target_components),
            "added": len(component_diff["added"]),
            "removed": len(component_diff["removed"]),
            "changed": len(component_diff["changed"]),
            "unchanged": component_diff["unchanged"],
        },
    }
