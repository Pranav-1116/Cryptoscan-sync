"""Wiring drift into the live pipeline (phase H7/H6 integration).

:mod:`~universal_vendor.hardware.drift` can classify a change and
:mod:`~universal_vendor.hardware.change_correlation` can say what moved beside
it — but until this module existed neither reached the live pipeline, so the
findings were computable and never emitted. A bank's SOC does not call a
function; it reads events.

What this does:

* **drift → canonical events.** Each :class:`~universal_vendor.hardware.drift.HardwareChange`
  becomes a :class:`~universal_vendor.hardware.live.events.HardwareEvent` in the
  taxonomy the live state engine already speaks, so a firmware bump lands in the
  timeline and the HBOM versioning exactly like any other hardware event.
* **events → correlation records.** Every ingested change is also recorded as a
  :class:`~universal_vendor.hardware.change_correlation.ChangeRecord`, so the
  correlation window fills itself from the pipeline rather than from a caller
  remembering to call it.
* **findings → the ingest result.** When a change is unaccompanied or
  suspicious, the result says so in the same response that carried the event.

The mapping is deliberately lossy in one place: the canonical taxonomy has no
``PQC_CAPABILITY_ADDED``, so post-quantum rows ride ``CRYPTO_CAPABILITY_CHANGED``
with ``payload["pqc"]`` set. Inventing an event type the state engine does not
know would be worse — it would be accepted by the bus and silently ignored by
the state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from universal_vendor.hardware.change_correlation import (
    ChangeRecord,
    correlate_changes,
    migration_readiness,
    record_from_change,
)
from universal_vendor.hardware.live.events import HardwareEvent, HardwareEventType

SCHEMA = "cryptoscan.hardware-change-feed/1"

#: Drift event type -> canonical live event type. Anything not listed is
#: reported as ``HARDWARE_CHANGED`` rather than dropped: an event the pipeline
#: cannot classify is still a fact, and silence would be a lie.
EVENT_TYPE_MAP: dict[str, str] = {
    "FIRMWARE_CHANGED": HardwareEventType.FIRMWARE_CHANGED.value,
    "TPM_FIRMWARE_CHANGED": HardwareEventType.TPM_FIRMWARE_CHANGED.value,
    "CRYPTO_CAPABILITY_CHANGED": HardwareEventType.CRYPTO_CAPABILITY_CHANGED.value,
    "PQC_CAPABILITY_ADDED": HardwareEventType.CRYPTO_CAPABILITY_CHANGED.value,
    "PQC_CAPABILITY_REMOVED": HardwareEventType.CRYPTO_CAPABILITY_CHANGED.value,
    "HSM_CAPABILITY_CHANGED": HardwareEventType.HSM_CAPABILITY_CHANGED.value,
    "HARDWARE_CHANGED": HardwareEventType.HARDWARE_CHANGED.value,
}

#: Drift rows that are about crypto capability, for the payload flag.
_CRYPTO_ROWS = frozenset({"CRYPTO_CAPABILITY_CHANGED", "PQC_CAPABILITY_ADDED",
                          "PQC_CAPABILITY_REMOVED", "HSM_CAPABILITY_CHANGED"})


def _append_once(records: list[ChangeRecord], record: ChangeRecord) -> None:
    """The same change seen twice is one change.

    A diff produces records, and the controller records the events it then
    ingests — the same fact crossing the seam twice. Counting it twice would
    inflate every correlation count, and a count that lies is worse than no
    count.
    """
    key = (record.domain, record.subject, record.event_type, record.at,
           tuple(sorted(record.detail.items(), key=lambda item: item[0])),
           record.evidence)
    for existing in records:
        if (existing.domain, existing.subject, existing.event_type, existing.at,
                tuple(sorted(existing.detail.items(), key=lambda item: item[0])),
                existing.evidence) == key:
            return
    records.append(record)


@dataclass
class ChangeFeedResult:
    """What one drift diff produced, in both vocabularies."""

    asset_id: str
    changes: list[dict[str, Any]] = field(default_factory=list)
    events: list[HardwareEvent] = field(default_factory=list)
    records: list[ChangeRecord] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "asset_id": self.asset_id,
            "changes": list(self.changes),
            "events": [event.event_type.value for event in self.events],
            "unmapped_event_types": list(self.unmapped),
        }


def to_hardware_event(change: Mapping[str, Any], *, source: str = "local_os") -> HardwareEvent:
    """One drift row as a canonical live event."""
    change = dict(change)
    event_type = str(change.get("event_type") or "HARDWARE_CHANGED")
    canonical = EVENT_TYPE_MAP.get(event_type, HardwareEventType.HARDWARE_CHANGED.value)
    device_type = change.get("device_type")
    detail = dict(change.get("detail") or {})
    payload: dict[str, Any] = {
        "drift_event_type": event_type,
        "change_class": change.get("change_class"),
        "severity": change.get("severity"),
        "evidence": list(change.get("evidence") or []),
        "detail": detail,
    }
    if event_type in _CRYPTO_ROWS:
        payload["pqc"] = bool(change.get("pqc_affected"))
        payload["pqc_algorithms"] = list(detail.get("algorithms") or [])
    component = None
    version = None
    if event_type in {"FIRMWARE_CHANGED", "TPM_FIRMWARE_CHANGED"}:
        components = detail.get("components") or {}
        if components:
            component = sorted(components)[0]
            version = str((components[component] or {}).get("after") or "") or None
    return HardwareEvent(
        event_type=HardwareEventType(canonical),
        asset_id=str(change.get("asset_id") or ""),
        source=source,
        observed_at=str(change.get("detected_at") or ""),
        device_type=str(device_type) if device_type else None,
        component=component,
        version=version,
        payload=payload,
    )


class HardwareChangeFeed:
    """Accumulates changes and answers the correlation questions about them."""

    def __init__(self) -> None:
        self._hardware: list[ChangeRecord] = []
        self._others: list[ChangeRecord] = []
        self._aliases: dict[str, str] = {}

    # -- in from the pipeline -------------------------------------------- #

    def record_hardware(self, change: Mapping[str, Any] | Any) -> ChangeRecord:
        record = record_from_change(change)
        _append_once(self._hardware, record)
        return record

    def record_change(self, domain: str, subject: str, event_type: str, at: str,
                      **detail: Any) -> ChangeRecord:
        record = ChangeRecord(domain=domain, subject=subject, event_type=event_type,
                              at=at, detail=detail)
        _append_once(self._others, record)
        return record

    def alias(self, spelled: str, as_estate_spells_it: str) -> None:
        self._aliases[spelled] = as_estate_spells_it

    # -- out to the pipeline ---------------------------------------------- #

    def from_diff(self, before: Mapping[str, Any], after: Mapping[str, Any],
                  *, source: str = "local_os") -> ChangeFeedResult:
        """Diff two observations, emitting an event per change.

        The diff module owns the comparison; this only translates. A change the
        mapping does not recognise still becomes ``HARDWARE_CHANGED`` and is
        listed in ``unmapped`` so the gap is visible rather than silent.
        """
        from universal_vendor.hardware.drift import diff  # noqa: PLC0415

        asset_id = str(after.get("asset_id") or "")
        result = ChangeFeedResult(asset_id=asset_id)
        for change in diff(before, after):
            payload = change.to_dict()
            payload["device_type"] = after.get("device_type")
            result.changes.append(payload)
            result.records.append(self.record_hardware(payload))
            if change.event_type not in EVENT_TYPE_MAP:
                result.unmapped.append(change.event_type)
            result.events.append(to_hardware_event(payload, source=source))
        return result

    # -- questions --------------------------------------------------------- #

    def correlation(self, *, window_minutes: int = 120) -> dict[str, Any]:
        return correlate_changes(self._hardware, self._others,
                                 window_minutes=window_minutes,
                                 asset_aliases=self._aliases)

    def pqc_readiness(self, *, window_minutes: int = 1440) -> dict[str, Any]:
        return migration_readiness(self._hardware, self._others,
                                   window_minutes=window_minutes,
                                   asset_aliases=self._aliases)

    def findings_for(self, asset_id: str, *, window_minutes: int = 120) -> dict[str, Any]:
        """The correlation rows about one asset, for the response that carried it."""
        report = self.correlation(window_minutes=window_minutes)
        rows = [row for row in report["results"]
                if row["change"]["subject"] == asset_id]
        return {
            "schema": SCHEMA,
            "asset_id": asset_id,
            "window_minutes": window_minutes,
            "rows": rows,
            "verdicts": [row["verdict"] for row in rows],
            "needs_attention": [row for row in rows
                                if row["verdict"] in {"SUSPICIOUS", "UNACCOMPANIED"}],
        }

    # -- for the artifact's own honesty ------------------------------------ #

    def counts(self) -> dict[str, int]:
        return {"hardware_changes": len(self._hardware),
                "other_changes": len(self._others),
                "aliases": len(self._aliases)}


def ingest_changes(controller: Any, feed: HardwareChangeFeed, before: Mapping[str, Any],
                   after: Mapping[str, Any], *, source: str = "local_os") -> dict[str, Any]:
    """Diff, emit every change through ``controller.ingest``, then correlate.

    Kept as a function rather than a method on the controller so the wiring can
    be tested without a live controller, and so the controller does not gain a
    dependency on the drift module it does not otherwise need.
    """
    result = feed.from_diff(before, after, source=source)
    ingested = [controller.ingest(event) for event in result.events]
    return {
        "feed": result.to_dict(),
        "ingested": ingested,
        "findings": feed.findings_for(result.asset_id),
    }


def events_for_records(records: Iterable[ChangeRecord]) -> list[HardwareEvent]:
    """Correlation records that describe hardware, as events (for replay)."""
    return [to_hardware_event({**record.to_dict(), "asset_id": record.subject,
                               "detected_at": record.at})
            for record in records if record.domain == "HARDWARE"]
