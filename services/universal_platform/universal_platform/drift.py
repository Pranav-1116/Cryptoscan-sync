"""§20 Platform drift detection — approved baseline vs live state across
all nine drift categories (network, cloud, vendor, hardware, firmware,
crypto, certificate, protocol, PQC).

Baseline and live are both plain structured inventories; drift is a
deterministic diff (added / removed / changed fields). No AI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

#: the nine drift categories (§20)
DRIFT_CATEGORIES = [
    "network", "cloud", "vendor", "hardware", "firmware", "crypto",
    "certificate", "protocol", "pqc",
]


class DriftEngine:
    """Compare approved baseline vs live state per category."""

    def __init__(self, baseline: Optional[dict[str, Any]] = None) -> None:
        # A caller may pass a bare version string or a list by accident;
        # only a mapping is a usable baseline.
        self.baseline: dict[str, Any] = (
            baseline if isinstance(baseline, dict) else {}
        )

    def set_baseline(self, baseline: dict[str, Any]) -> None:
        self.baseline = baseline if isinstance(baseline, dict) else {}

    def _diff(self, category: str, live: Any) -> list[dict[str, Any]]:
        base = self.baseline.get(category, {})
        if isinstance(base, list) or isinstance(live, list):
            base_set = {str(x) for x in (base or [])}
            live_set = {str(x) for x in (live or [])}
            out = []
            for item in sorted(live_set - base_set):
                out.append({"change": "added", "item": item})
            for item in sorted(base_set - live_set):
                out.append({"change": "removed", "item": item})
            return out
        base_map = {str(k): v for k, v in (base or {}).items()}
        live_map = {str(k): v for k, v in (live or {}).items()}
        out = []
        for key in sorted(live_map):
            if key not in base_map:
                out.append({"change": "added", "item": key,
                            "value": live_map[key]})
            elif live_map[key] != base_map[key]:
                out.append({"change": "changed", "item": key,
                            "from": base_map[key], "to": live_map[key]})
        for key in sorted(base_map):
            if key not in live_map:
                out.append({"change": "removed", "item": key,
                            "value": base_map[key]})
        return out

    def evaluate(self, live: dict[str, Any]) -> dict[str, Any]:
        """Diff every category present in baseline or live state."""
        if not isinstance(live, dict):
            live = {}
        categories = sorted(set(DRIFT_CATEGORIES) |
                            set(self.baseline) | set(live))
        results: dict[str, Any] = {}
        total_changes = 0
        for category in categories:
            changes = self._diff(category, live.get(category, {}))
            total_changes += len(changes)
            results[category] = {
                "drift": bool(changes),
                "changes": changes,
                "change_count": len(changes),
            }
        return {
            "drift_detected": total_changes > 0,
            "total_changes": total_changes,
            "categories": results,
            "compared_at": datetime.now(timezone.utc).isoformat(),
        }


def evaluate_drift(baseline: dict[str, Any],
                   live: dict[str, Any]) -> dict[str, Any]:
    """Module-level entry point."""
    return DriftEngine(baseline).evaluate(live)
