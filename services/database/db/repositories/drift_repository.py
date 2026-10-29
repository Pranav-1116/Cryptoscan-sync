"""Drift event repository."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.drift_event import DriftEvent
from db.repositories.base_repository import BaseRepository
from db.tenancy import current_tenant


class DriftRepository(BaseRepository[DriftEvent]):
    def __init__(self, session: Session):
        super().__init__(DriftEvent, session)

    def record_scan_change(
        self, *, baseline_id: str, scan_id: str, change, tenant_id: str | None
    ) -> bool:
        """Persist a scan comparison once; retries must not reopen dispositions.

        The primary key is stable for this baseline, scan and concrete change.
        This is also a uniqueness backstop for two workers racing to process
        the same scan (one transaction will fail, rather than duplicate rows).
        """
        def finding(fp):
            if fp is None:
                return None
            return {
                "evidence_id": fp.evidence_id,
                "algorithm": fp.algorithm, "key_size": fp.key_size,
                "mode": fp.mode, "purpose": fp.purpose,
                "file_path": fp.file_path, "line_number": fp.line_number,
            }

        details = {
            "change_type": change.change_type,
            "reason": change.reason,
            "algorithm": change.affected_algorithm,
            "baseline_finding": finding(change.baseline_fingerprint),
            "current_finding": finding(change.current_fingerprint),
        }
        return self.record_event_once(
            baseline_id=baseline_id, scan_id=scan_id, tenant_id=tenant_id,
            drift_type=change.change_type, severity=change.severity, details=details,
        )

    def record_event_once(
        self, *, baseline_id: str, scan_id: str, tenant_id: str | None,
        drift_type: str, severity: str, details: dict,
    ) -> bool:
        identity = json.dumps(
            [tenant_id, baseline_id, scan_id, drift_type, details],
            sort_keys=True, separators=(",", ":"),
        )
        event_id = str(uuid5(NAMESPACE_URL, f"cryptoscan/drift/{identity}"))
        if self.get_by_id(event_id) is not None:
            return False
        self.session.add(DriftEvent(
            id=event_id, tenant_id=tenant_id, baseline_id=baseline_id,
            current_scan_id=scan_id, detected_at=datetime.now(timezone.utc),
            drift_type=drift_type, severity=severity,
            drift_details=details, resolution_status="OPEN",
        ))
        self.session.flush()
        return True

    def list_events(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        scan_id: str | None = None,
        drift_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[DriftEvent], int]:
        stmt = select(DriftEvent)
        count_stmt = select(func.count()).select_from(DriftEvent)
        if severity:
            stmt = stmt.where(DriftEvent.severity == severity)
            count_stmt = count_stmt.where(DriftEvent.severity == severity)
        if drift_type:
            stmt = stmt.where(DriftEvent.drift_type == drift_type)
            count_stmt = count_stmt.where(DriftEvent.drift_type == drift_type)
        if status:
            stmt = stmt.where(DriftEvent.resolution_status == status)
            count_stmt = count_stmt.where(DriftEvent.resolution_status == status)
        if scan_id:
            stmt = stmt.where(DriftEvent.current_scan_id == scan_id)
            count_stmt = count_stmt.where(DriftEvent.current_scan_id == scan_id)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(desc(DriftEvent.detected_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def open_counts_by_severity(self) -> dict[str, int]:
        stmt = (
            select(DriftEvent.severity, func.count())
            .where(DriftEvent.resolution_status == "OPEN")
            .group_by(DriftEvent.severity)
        )
        # The zero-filled shape must cover every severity this table actually
        # stores, or a LOW-only estate returns no LOW key while a LOW+MEDIUM
        # estate does — the same reader sees two different shapes. All five
        # levels are present so callers can rely on the keys, not just the
        # levels that happen to be non-zero.
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for severity, count in self.session.execute(stmt):
            counts[str(severity)] = int(count)
        return counts

    def verify_resolved_against_scan(
        self, *, scan, evidence_rows: list[dict], scan_end: datetime | None = None,
    ) -> list[dict]:
        """§4.7 (round 40): condition-level verification of RESOLVED events.

        Evaluates every administratively resolved drift event on the same
        target (same tenant, resolution predating ``scan_end``) against the
        later scan's evidence, using the pure evaluator in
        ``drift.core.verification``. Only evidence-backed verdicts are
        stamped: VERIFIED and CONDITION_PRESENT. UNCOVERED and NOT_CHECKABLE
        are returned for the caller to report but leave the stored state
        untouched — no verdict is recorded when the rescan did not observe
        the affected file.
        """
        from drift.core.verification import (
            CONDITION_PRESENT,
            VERIFIED,
            evaluate_condition_verification,
        )

        end = scan_end or scan.scan_end or datetime.now(timezone.utc)
        stmt = (
            select(DriftEvent)
            .where(
                DriftEvent.resolution_status == "RESOLVED",
                DriftEvent.resolved_at.isnot(None),
                DriftEvent.resolved_at < end,
            )
            .order_by(DriftEvent.detected_at)
            .limit(500)
        )
        rows = list(self.session.execute(stmt).scalars().all())
        # same-target filter in Python: the event's scan shares the target
        # location with the verifying scan (tenant guard already applied).
        def _target(scan_id: str) -> str | None:
            if not scan_id:
                return None
            from db.models.scan import Scan as ScanRow

            other = self.session.execute(
                select(ScanRow).where(ScanRow.id == scan_id)
            ).scalar_one_or_none()
            return getattr(other, "target_location", None) if other else None

        wanted = scan.target_location
        # Tenant-exact match (NULL-safe, explicit — the worker pipeline may
        # run outside ORM tenant scope, so do not rely on the global guard):
        # another tenant's identical target string must never be verified
        # by this scan.
        scan_tenant = getattr(scan, "tenant_id", None)
        candidates = [
            r for r in rows
            if _target(r.current_scan_id) == wanted
            and (r.tenant_id or None) == (scan_tenant or None)
        ]

        events = [
            {"drift_id": r.id, "drift_details": r.drift_details or {}}
            for r in candidates
        ]
        verdicts = evaluate_condition_verification(events, evidence_rows)
        by_id = {r.id: r for r in candidates}
        stamped = 0
        for verdict in verdicts:
            row = by_id.get(verdict.get("drift_id"))
            if row is None:
                continue
            status = verdict.get("verification_status")
            if status in (VERIFIED, CONDITION_PRESENT):
                row.verification_status = status
                row.verified_by_scan_id = scan.id
                row.verified_at = datetime.now(timezone.utc)
                stamped += 1
        if stamped:
            self.session.flush()
        return verdicts

    def acknowledge(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        """Acknowledge ≠ resolve (report 31 §5): stamp the acknowledgment,
        leave the resolution untouched. Notes, when given, append to the
        resolution notes (the workflow's existing notes field)."""
        row = self.get_by_id(drift_id)
        if row is None or (current_tenant() is not None and row.tenant_id != current_tenant()):
            return None
        row.acknowledged_at = datetime.now(timezone.utc)
        row.acknowledged_by = user
        if row.resolution_status == "OPEN":
            row.resolution_status = "ACKNOWLEDGED"
        if notes:
            existing = row.resolution_notes or ""
            row.resolution_notes = f"{existing}\n{notes}" if existing else notes
        self.session.flush()
        return row

    def resolve(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        return self._close(drift_id, user, notes, "RESOLVED")

    def mark_false_positive(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        return self._close(drift_id, user, notes, "FALSE_POSITIVE")

    def list_since(self, since: datetime, *, page_size: int = 200) -> list[DriftEvent]:
        stmt = (
            select(DriftEvent)
            .where(DriftEvent.detected_at >= since)
            .order_by(desc(DriftEvent.detected_at))
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all())

    #: SLA targets (report 31 §5.2) — acknowledgement and resolution
    #: windows per severity. Breach = still open past the window, or the
    #: ack/resolve action happened past it.
    SLA_TARGETS = {
        "CRITICAL": {"acknowledge_hours": 1.0, "resolve_hours": 24.0},
        "HIGH": {"acknowledge_hours": 4.0, "resolve_hours": 24.0 * 7},
        "MEDIUM": {"acknowledge_hours": 24.0, "resolve_hours": 24.0 * 30},
        "INFO": {"acknowledge_hours": None, "resolve_hours": None},
    }

    def sla_summary(self, *, now: datetime | None = None, max_events: int = 50_000) -> dict:
        """Drift MTTA/MTTR and SLA compliance (report 31 §5/§6, round 23).

        Deterministic arithmetic over drift_events timestamps — nothing
        estimated, nothing imputed: events acknowledged before the
        ``acknowledged_at`` column existed are counted as
        ``acknowledge_time_unknown`` and excluded from MTTA rather than
        guessed from resolve or audit timestamps. Reads are bounded
        (``max_events``) with an explicit truncation flag, like every other
        estate-wide view.
        """
        now = now or datetime.now(timezone.utc)

        def _hours(start: datetime, end: datetime) -> float:
            # SQLite returns naive datetimes; the storage convention is UTC
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            return (end - start).total_seconds() / 3600.0

        def _percentile(values: list[float], fraction: float) -> float | None:
            if not values:
                return None
            ordered = sorted(values)
            index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
            return round(ordered[index], 2)

        def _mean(values: list[float]) -> float | None:
            return round(sum(values) / len(values), 2) if values else None

        rows: list[DriftEvent] = []
        page = 1
        truncated = False
        while True:
            batch, _total = self.list_events(page=page, page_size=500)
            if not batch:
                break
            rows.extend(batch)
            if len(rows) >= max_events:
                truncated = len(rows) < _total
                rows = rows[:max_events]
                break
            if len(rows) >= _total:
                break
            page += 1

        per_severity: dict[str, dict] = {}
        ack_times: list[float] = []
        resolve_times: list[float] = []
        unknown_ack = 0

        for row in rows:
            sev = str(row.severity or "INFO").upper()
            bucket = per_severity.setdefault(
                sev,
                {
                    "open": 0,
                    "acknowledged": 0,
                    "resolved": 0,
                    "false_positive": 0,
                    "other": 0,
                    "acknowledge_breaches": 0,
                    "resolve_breaches": 0,
                    "oldest_open_hours": None,
                    "mtta_hours": [],
                    "mttr_hours": [],
                },
            )
            status = str(row.resolution_status or "OPEN").upper()
            detected = row.detected_at
            if status == "OPEN":
                bucket["open"] += 1
                if detected is not None:
                    age = _hours(detected, now)
                    bucket["oldest_open_hours"] = (
                        age if bucket["oldest_open_hours"] is None
                        else max(bucket["oldest_open_hours"], age)
                    )
                    targets = self.SLA_TARGETS.get(sev, {})
                    if targets.get("acknowledge_hours") is not None and row.acknowledged_at is None:
                        if age > targets["acknowledge_hours"]:
                            bucket["acknowledge_breaches"] += 1
                    if targets.get("resolve_hours") is not None and age > targets["resolve_hours"]:
                        bucket["resolve_breaches"] += 1
            elif status == "ACKNOWLEDGED":
                bucket["acknowledged"] += 1
            elif status == "RESOLVED":
                bucket["resolved"] += 1
            elif status == "FALSE_POSITIVE":
                bucket["false_positive"] += 1
            else:
                bucket["other"] += 1

            # stamps are read regardless of the status label — an event can
            # carry an acknowledgment (or a resolution) the status field has
            # not caught up with, and the metric should follow the facts

            if row.acknowledged_at is not None and detected is not None:
                ack_h = _hours(detected, row.acknowledged_at)
                bucket["mtta_hours"].append(ack_h)
                ack_times.append(ack_h)
                targets = self.SLA_TARGETS.get(sev, {})
                if targets.get("acknowledge_hours") is not None and ack_h > targets["acknowledge_hours"]:
                    bucket["acknowledge_breaches"] += 1
            elif status in {"ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"} and row.acknowledged_at is None and detected is not None:
                # acknowledged before the column existed — unknown, not zero
                unknown_ack += 1

            if row.resolved_at is not None and detected is not None:
                res_h = _hours(detected, row.resolved_at)
                if status == "RESOLVED":
                    bucket["mttr_hours"].append(res_h)
                    resolve_times.append(res_h)
                    targets = self.SLA_TARGETS.get(sev, {})
                    if targets.get("resolve_hours") is not None and res_h > targets["resolve_hours"]:
                        bucket["resolve_breaches"] += 1

        severity_out = {}
        for sev, bucket in sorted(per_severity.items()):
            targets = self.SLA_TARGETS.get(sev, {})
            severity_out[sev] = {
                "open": bucket["open"],
                "acknowledged": bucket["acknowledged"],
                "resolved": bucket["resolved"],
                "false_positive": bucket["false_positive"],
                "other": bucket["other"],
                "oldest_open_hours": round(bucket["oldest_open_hours"], 2) if bucket["oldest_open_hours"] is not None else None,
                "mtta_hours": _mean(bucket["mtta_hours"]),
                "mtta_p95_hours": _percentile(bucket["mtta_hours"], 0.95),
                "mttr_hours": _mean(bucket["mttr_hours"]),
                "mttr_p95_hours": _percentile(bucket["mttr_hours"], 0.95),
                "sla_targets": targets,
                "sla": {
                    "acknowledge_breaches": bucket["acknowledge_breaches"],
                    "resolve_breaches": bucket["resolve_breaches"],
                },
            }

        return {
            "events_considered": len(rows),
            "truncated": truncated,
            "generated_at": now.isoformat(),
            "mtta_hours": _mean(ack_times),
            "mtta_p95_hours": _percentile(ack_times, 0.95),
            "mttr_hours": _mean(resolve_times),
            "mttr_p95_hours": _percentile(resolve_times, 0.95),
            "acknowledge_time_unknown": unknown_ack,
            "per_severity": severity_out,
            "targets_note": (
                "acknowledge/resolve windows per severity (report 31 §5.2); "
                "a breach is an open event past the window or an action that "
                "took longer than the window"
            ),
        }

    def _close(
        self, drift_id: str, user: str, notes: str | None, status: str
    ) -> DriftEvent | None:
        row = self.get_by_id(drift_id)
        if row is None or (current_tenant() is not None and row.tenant_id != current_tenant()):
            return None
        row.resolution_status = status
        row.resolved_by = user
        row.resolved_at = datetime.now(timezone.utc)
        row.resolution_notes = notes
        self.session.flush()
        return row
