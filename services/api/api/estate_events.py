"""Estate run events — the realtime half of a 24/7 estate (spec 93 §18).

A scan that only answers when someone clicks "run" is a report generator. A
product that runs continuously has to *say what it is doing while it does it*,
and it has to do so without turning a working scan into a failed one.

Contract:

* **events never break a run.** Publication is best-effort and counted; a bus,
  journal or Redis failure is recorded (`publish_failures`) and the scan
  continues. The opposite rule — fail the scan because a notification could not
  be delivered — turns a monitoring product into an outage amplifier.
* **events carry the evidence verdict, not a mood.** Every published payload
  names coverage, verdict and the planes that answered, so a consumer cannot
  render "scan finished" as "everything is fine".
* **one vocabulary.** ``estate.run.started``, ``estate.plane.finished``,
  ``estate.phase.finished``, ``estate.run.finished``, ``estate.run.failed``,
  ``estate.change.detected``. Consumers key off these strings; adding a type is a
  documented change, not an accident.
* **tenant ownership is explicit.** The daemon runs platform-wide; the API runs
  inside a tenant scope. ``tenant_id`` is passed by the caller that already
  authorized it, never inferred from an event payload.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

logger = logging.getLogger(__name__)

SCHEMA = "cryptoscan.estate-events/1"
SOURCE = "estate"

#: the complete realtime vocabulary of the estate engine
EVENT_TYPES = (
    "estate.run.started",
    "estate.plane.finished",
    "estate.phase.finished",
    "estate.run.finished",
    "estate.run.failed",
    "estate.change.detected",
)

Publisher = Callable[[str, dict[str, Any]], Any]


class EventSink:
    """Collects publication outcomes so a caller can report them honestly.

    ``publish_failures`` above zero means the run happened but the realtime feed
    did not see all of it — a state the API reports rather than hides.
    """

    def __init__(self, publisher: Publisher | None = None, *, tenant_id: str | None = None,
                 estate: str | None = None) -> None:
        self._publisher = publisher
        self.tenant_id = tenant_id
        self.estate = estate
        self.published = 0
        self.publish_failures = 0
        self.last_error: str | None = None
        self.types: list[str] = []

    def __call__(self, event_type: str, payload: Mapping[str, Any]) -> None:
        if self._publisher is None:
            return
        if event_type not in EVENT_TYPES:
            # an unknown type is a programming error, not a runtime condition:
            # publishing it would break every consumer's switch statement
            raise ValueError(f"unknown estate event type: {event_type}")
        body = {
            "schema": SCHEMA,
            "estate": self.estate,
            **(dict(payload) or {}),
        }
        try:
            self._publisher(event_type, body)
            self.published += 1
            self.types.append(event_type)
        except Exception as exc:  # noqa: BLE001 — the scan must survive the feed
            self.publish_failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("estate_event_publish_failed", extra={"type": event_type,
                                                                 "error": self.last_error})

    def summary(self) -> dict[str, Any]:
        return {
            "published": self.published,
            "publish_failures": self.publish_failures,
            "last_error": self.last_error,
            "types": sorted(set(self.types)),
        }


def bus_publisher(*, source: str = SOURCE, tenant_id: str | None = None) -> Publisher:
    """Publish onto the platform event bus (the SSE stream's authority)."""

    def publish(event_type: str, payload: dict[str, Any]) -> None:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source=source, tenant_id=tenant_id)

    return publish


def sink(publisher: Publisher | None = None, *, tenant_id: str | None = None,
         estate: str | None = None) -> EventSink:
    """A sink that publishes to the platform bus unless a publisher is injected."""
    return EventSink(publisher if publisher is not None else bus_publisher(tenant_id=tenant_id),
                     tenant_id=tenant_id, estate=estate)


def run_finished_payload(report: Mapping[str, Any], *, duration_seconds: float | None = None,
                         trigger: str = "manual") -> dict[str, Any]:
    """The run's own verdict, in the shape a live consumer needs."""
    coverage = (report.get("coverage") or {}).get("summary") or {}
    return {
        "run_id": report.get("run_id"),
        "projection_id": report.get("projection_id"),
        "verdict": report.get("verdict"),
        "verdict_detail": report.get("verdict_detail"),
        "coverage_state": coverage.get("coverage_state"),
        "attempted": coverage.get("attempted"),
        "collected": coverage.get("collected"),
        "failed_planes": list(report.get("failed_planes") or []),
        "partial_planes": list(report.get("partial_planes") or []),
        "not_attempted_planes": list(report.get("not_attempted_planes") or []),
        "summary": report.get("summary"),
        "bom_counts": report.get("bom_counts"),
        "duration_seconds": duration_seconds,
        "trigger": trigger,
    }
