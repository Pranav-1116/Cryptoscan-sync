"""Telecom realtime evaluation (pure) — posture diffs → event stream.

The realtime loop re-probes (or ingests results for) registered NFs and
compares fingerprints against the previous state. This module turns the
diff into a deduplicated, severity-ranked event list — the unit that makes
the scanner *realtime* rather than periodic-and-silent:

* first observation of a target produces no per-target noise (the rollup
  is the baseline); only findings already critical get a TELECOM_FINDING
  event so an onboarding estate immediately surfaces what matters;
* REACHABILITY_LOST on a previously-reachable target, RECOVERED on return;
* FINDINGS_CHANGED when the verdict-code set or serving certificate
  changes; CERT_EXPIRING when a certificate crosses the 30-day threshold;
* identical (kind, target, fingerprint) events within the cooldown window
  are suppressed — a flapping endpoint does not flood the stream.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

DEFAULT_COOLDOWN_S = 300

_SEV_RANK = {"ok": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cert_state(verdict: Mapping[str, Any]) -> tuple[str, int | None]:
    """(expiry_status, days_left) from the verdict's certificate metadata."""
    not_after = verdict.get("cert_not_after")
    if not not_after:
        return "", None
    try:
        expiry = datetime.fromisoformat(str(not_after))
        days = (expiry - datetime.now(timezone.utc)).days
        if days < 0:
            return "EXPIRED", days
        if days <= 7:
            return "EXPIRING_CRITICAL", days
        if days <= 30:
            return "EXPIRING_SOON", days
        return "VALID", days
    except (TypeError, ValueError):
        return "", None


def evaluate_changes(
    previous: Mapping[str, Mapping[str, Any]] | None,
    current: Iterable[Mapping[str, Any]],
    *,
    now: datetime | None = None,
    cooldown_s: int = DEFAULT_COOLDOWN_S,
) -> list[dict[str, Any]]:
    """Events for one scan pass. ``previous`` maps nf_id → prior verdict
    (None/empty = first observation). Deterministic apart from timestamps.
    """
    moment = now or datetime.now(timezone.utc)
    at = moment.isoformat()
    first_pass = not previous
    events: list[dict[str, Any]] = []
    recent: dict[tuple[str, str, str], float] = {}

    for verdict in current:
        nf_id = str(verdict.get("nf_id") or "")
        if not nf_id:
            continue
        before = (previous or {}).get(nf_id)
        base = {
            "target": nf_id,
            "nf_type": verdict.get("nf_type"),
            "carrier_code": verdict.get("carrier_code"),
            "plane": verdict.get("plane"),
        }

        def emit(kind: str, severity: str, message: str, **extra: Any) -> None:
            key = (kind, nf_id, str(verdict.get("fingerprint")))
            if key in recent and moment.timestamp() - recent[key] < cooldown_s:
                return
            recent[key] = moment.timestamp()
            events.append({"kind": kind, "severity": severity, "message": message,
                           "at": at, **base, **extra})

        if before is None:
            if first_pass and verdict.get("severity") == "critical":
                emit("TELECOM_FINDING", "critical",
                     f"First observation already critical: {verdict.get('status')} — "
                     + "; ".join(f.get("message") or "" for f in (verdict.get("findings") or [])[:2]))
            elif not first_pass:
                emit("TELECOM_TARGET_ADDED", "info",
                     f"Target observed for the first time: {verdict.get('status')}")
            continue

        prev_status = before.get("status")
        this_status = verdict.get("status")

        if prev_status not in ("UNREACHABLE",) and this_status == "UNREACHABLE":
            emit("TELECOM_REACHABILITY_LOST", "critical",
                 f"{nf_id} became unreachable ({verdict.get('endpoint')})")
        elif prev_status == "UNREACHABLE" and this_status not in ("UNREACHABLE", "NOT_PROBED"):
            emit("TELECOM_RECOVERED", "info", f"{nf_id} is reachable again ({this_status})")

        prev_codes = set(str(before.get("fingerprint")).split("|")[1].split(",")) - {""}
        this_codes = set(str(verdict.get("fingerprint")).split("|")[1].split(",")) - {""}
        gained = this_codes - prev_codes
        lost = prev_codes - this_codes
        if (gained or lost) and this_status != "UNREACHABLE":
            worst = max(
                [str(f.get("severity", "info")) for f in verdict.get("findings") or []] or ["info"],
                key=lambda s: _SEV_RANK.get(s, 0),
            )
            parts = []
            if gained:
                parts.append(f"gained {', '.join(sorted(gained))}")
            if lost:
                parts.append(f"resolved {', '.join(sorted(lost))}")
            emit("TELECOM_FINDINGS_CHANGED",
                 worst if worst in ("critical", "high", "medium") else "info",
                 f"Verdicts changed for {nf_id}: " + "; ".join(parts),
                 gained=sorted(gained), resolved=sorted(lost))

        state, days = _cert_state(verdict)
        prev_state, _ = _cert_state(before)
        if state in ("EXPIRING_CRITICAL", "EXPIRING_SOON", "EXPIRED") and state != prev_state:
            sev = {"EXPIRED": "critical", "EXPIRING_CRITICAL": "high", "EXPIRING_SOON": "medium"}[state]
            emit("TELECOM_CERT_EXPIRING", sev,
                 f"Certificate on {nf_id} {state.lower().replace('_', ' ')} ({days} days)")

    return events


def summarize_events(events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[str(event.get("kind"))] = counts.get(str(event.get("kind")), 0) + 1
    return counts
