"""IPS: block events, rule actions and policy — read, never applied.

An IPS reports what it stopped. The collector keeps the block events and the rule identity
behind them, so the estate can say which systems a blocked flow was aimed at and which
cryptographic material those systems depend on. It does not block, unblock, tune a signature
or sit inline — the capability surface carries no write and no ``BLOCK`` operation.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, OBSERVED
from ..ids.base import IdsCollector

CONTROL = "IPS"

COLLECTS: tuple[str, ...] = (
    "block_events", "signature_and_policy_ids", "rule_actions", "event_timestamps",
    "flow_metadata",
)
MUST_NOT: tuple[str, ...] = (
    "block_or_unblock_traffic", "tune_or_disable_a_signature", "sit_inline",
    "read_packet_payload",
)


class IpsCollector(IdsCollector):
    """An IPS is an IDS that also reports an action, so the collector extends that one."""

    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def blocks(self) -> list[dict[str, Any]]:
        """Only the events where the device says it acted — 'alert' is not a block."""
        return [row for row in self.collect_security_events()
                if (row.get("action") or "") in {"BLOCK", "DROP", "DENY", "RESET"}
                or row["kind"] in {"BLOCK", "DROP"}]

    def policy(self) -> list[dict[str, Any]]:
        rows = self._section_rows("policy")
        return [{"policy": self._field(raw, "policy") or self._field(raw, "name"),
                 "mode": str(self._field(raw, "mode") or "PREVENT").upper(),
                 "signatures": list(self._field(raw, "signatures") or []),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("POLICY", index, raw)}
                for index, raw in enumerate(rows, start=1)]

    def enforcement_summary(self) -> dict[str, Any]:
        blocks = self.blocks()
        return {
            "control": CONTROL,
            "vendor": self.spec.vendor,
            "events": len(self.collect_security_events()),
            "blocks": len(blocks),
            "facts": {OBSERVED: len(blocks), CONFIGURED: len(self.policy())},
            "blocked_evidence": [row["evidence_id"] for row in blocks],
            "note": "a count of blocks is not a count of threats; the estate correlates "
                    "each block to the systems and crypto it was aimed at",
        }


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> IpsCollector:
    from .vendors import spec_for

    return IpsCollector(spec_for(vendor), feed)
