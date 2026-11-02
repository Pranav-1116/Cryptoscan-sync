"""Network crypto correlation: several changes, one pattern, still not an attack.

Review item 19 asks for the sentence the platform is allowed to say:

    TLS downgrade + certificate mutation + new endpoint + new process is a
    `CORRELATED_PATTERN` at `SUSPICIOUS_ACTIVITY`, never "attack detected";
    compromise, attribution and intent stay unproven.

The reason a network inventory can say anything at all is the graph around the change:
one downgrade is a fact, a downgrade *and* a replaced certificate *and* a listener that
was not there yesterday *and* a process that started — inside one window — describe one
event rather than four.

The vocabulary is the shared one in ``shared_models.attack_patterns``: levels 0–4,
``SUSPICIOUS_ACTIVITY`` at level 2, ``SECURITY_INCIDENT`` reserved for a human. This
module maps a network snapshot comparison into that vocabulary and adds the network
rule, which the shared engine does not have because it reads *evidence classes*, not
negotiated protocol.

Where it deliberately stops:

* **level 2 is the ceiling.** The shared engine reserves level 4 for combinations it
  can corroborate across independent planes; a window of network changes is one plane,
  so a pattern named ``CORRELATED_PATTERN`` here is classified ``SUSPICIOUS_ACTIVITY``
  and never ``SECURITY_INCIDENT``;
* **a combination needs a weakening.** A new listener and a new process on their own
  are normal operations; the correlated pattern requires at least one downgrade or one
  certificate replacement, so an unrelated deploy does not raise one;
* **a collection gap is not activity.** ``COLLECTION_STATUS_CHANGED`` is carried as a
  blind spot on the result, not as a signal, because an endpoint that stopped answering
  changes what the window means;
* **nothing is attributed.** No actor, no motive, no "attack". ``not_proven`` says so on
  every pattern.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from shared_models import attack_patterns as ap

SCHEMA = "cryptoscan.nbom-patterns/1"

#: The network signals this module derives from a snapshot comparison.
SIGNALS: tuple[str, ...] = (
    "TLS_DOWNGRADE",
    "CIPHER_DOWNGRADE",
    "CERTIFICATE_MUTATION",
    "TRUST_PATH_CHANGE",
    "NEW_ENDPOINT",
    "ENDPOINT_LOST",
    "NEW_PROCESS",
    "ALPN_CHANGE",
    "SNI_CHANGE",
    "PORT_CHANGE",
)

#: Signals that weaken something. A pattern that combines activity without one of these
#: is reported as ordinary change.
WEAKENING: tuple[str, ...] = ("TLS_DOWNGRADE", "CIPHER_DOWNGRADE",
                              "CERTIFICATE_MUTATION", "TRUST_PATH_CHANGE")

#: The four the review names, in its order.
REVIEW_SIGNALS: tuple[str, ...] = ("TLS_DOWNGRADE", "CERTIFICATE_MUTATION",
                                   "NEW_ENDPOINT", "NEW_PROCESS")

PATTERNS: tuple[str, ...] = ("NETWORK_CRYPTO_REGRESSION", "TRUST_PATH_SHIFT",
                             "NEW_EXPOSURE", "DISAPPEARANCE", "CORRELATED_PATTERN")

#: The level this module may reach, and the shared ladder it borrows the name from.
MAX_LEVEL = 2

NOT_PROVEN = [
    "that anything was attacked: a downgrade, a replacement certificate, a new "
    "listener and a new process are facts about configuration and timing, and the "
    "combination raises review priority rather than establishing a cause",
    "that the endpoint is compromised, or that its cryptography was intercepted",
    "who did it, or whether it was done at all: no actor, no motive and no external "
    "intelligence take part in this correlation",
    "that the window is complete: changes outside it, or inside a plane nobody "
    "collected, are invisible here",
]

DEFAULT_WINDOW_SECONDS = 3600

#: which change kinds from ``cbom.nbom_history`` become which signal
_KIND_MAP: dict[str, str] = {
    "TLS_VERSION_CHANGED": "TLS_DOWNGRADE",
    "CIPHER_SUITE_CHANGED": "CIPHER_DOWNGRADE",
    "CERTIFICATE_CHANGED": "CERTIFICATE_MUTATION",
    "TRUST_PATH_CHANGED": "TRUST_PATH_CHANGE",
    "ENDPOINT_ADDED": "NEW_ENDPOINT",
    "ENDPOINT_REMOVED": "ENDPOINT_LOST",
    "ALPN_CHANGED": "ALPN_CHANGE",
    "SNI_CHANGED": "SNI_CHANGE",
    "PORT_CHANGED": "PORT_CHANGE",
}


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(timezone.utc).isoformat() if moment else None


def _moment(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def signals(comparison: Mapping[str, Any], *,
            processes: Iterable[Mapping[str, Any]] | None = None,
            from_iso: str | None = None,
            to_iso: str | None = None) -> dict[str, Any]:
    """A snapshot comparison (and any new processes) -> signals with a window.

    A downgrade is only a ``TLS_DOWNGRADE`` when the comparison says the change went
    *down*. An upgrade is not a signal at all: it is a change, and putting it in the
    same bucket as a downgrade is how a rotation becomes an incident.
    """
    derived: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for change in comparison.get("changes") or []:
        kind = str(change.get("kind") or "")
        name = _KIND_MAP.get(kind)
        if name is None:
            skipped.append({"kind": kind, "reason": "not a network crypto signal"})
            continue
        if change.get("direction") == "UPGRADE":
            skipped.append({"kind": kind, "reason": (
                "an upgrade weakens nothing, so it is a change and not a signal")})
            continue
        if change.get("direction") == "DOWNGRADE" and name in {
                "TLS_DOWNGRADE", "CIPHER_DOWNGRADE"}:
            pass
        elif name in {"TLS_DOWNGRADE", "CIPHER_DOWNGRADE"} and change.get(
                "direction") != "DOWNGRADE":
            skipped.append({"kind": kind, "reason":
                            "this comparison did not classify the change as a downgrade"})
            continue
        derived.append({
            "signal": name,
            "change_kind": kind,
            "endpoint": change.get("endpoint"),
            "subject": change.get("endpoint"),
            "before": change.get("before"),
            "after": change.get("after"),
            "severity": change.get("severity"),
            "at": change.get("observed_at") or to_iso or comparison.get(
                "after", {}).get("taken_at"),
            "evidence_ids": sorted({*(change.get("evidence_before") or []),
                                    *(change.get("evidence_after") or [])}),
            "source": "NETWORK",
        })
    for row in processes or ():
        if not isinstance(row, Mapping):
            continue
        subject = str(row.get("host") or row.get("endpoint") or row.get("process") or "")
        derived.append({
            "signal": "NEW_PROCESS",
            "change_kind": "ASSET_ADDED",
            "endpoint": subject,
            "subject": subject,
            "before": None,
            "after": (f"{row.get('process')} (pid {row.get('pid')})"
                      if row.get("process") else None),
            "severity": "INFO",
            "at": row.get("observed_at") or row.get("started_at") or to_iso,
            "evidence_ids": sorted({str(value) for value in
                                    (row.get("evidence_id"), row.get("evidence_ids") or [])
                                    if value and not isinstance(value, list)}),
            "source": "RUNTIME",
        })
    dated = [signal for signal in derived if _moment(signal.get("at"))]
    anchor = max((_moment(signal["at"]) for signal in dated), default=None)
    if anchor is None:
        window_start = None
        in_window = []
    else:
        window_start = anchor.timestamp() - max(1, DEFAULT_WINDOW_SECONDS)
        in_window = [signal for signal in dated
                     if window_start <= _moment(signal["at"]).timestamp()
                     <= anchor.timestamp()]
    blind = sorted({change["endpoint"] for change in comparison.get("changes") or []
                    if change.get("kind") == "COLLECTION_STATUS_CHANGED"})
    return {
        "schema": SCHEMA,
        "signals": in_window,
        "out_of_window": len(dated) - len(in_window),
        "undated": len(derived) - len(dated),
        "skipped": skipped,
        "blind_spots": blind,
        "window": {"from": from_iso or _iso(
            datetime.fromtimestamp(window_start, tz=timezone.utc) if window_start else None),
            "to": _iso(anchor),
            "seconds": DEFAULT_WINDOW_SECONDS},
        "counts": {name: sum(1 for signal in in_window if signal["signal"] == name)
                   for name in SIGNALS if any(signal["signal"] == name
                                              for signal in in_window)},
        "statement": (
            f"{len(in_window)} network crypto signal(s) in one {DEFAULT_WINDOW_SECONDS}s "
            f"window ending {_iso(anchor) or 'now'}"
            + (f"; {len(blind)} endpoint(s) went blind, which changes what the window "
               "means" if blind else "")
            + (f"; {len(dated) - len(in_window)} signal(s) fell outside the window"
               if len(dated) - len(in_window) else "")),
    }


def _pattern(name: str, level: int, signals: list[Mapping[str, Any]], *,
             why: str, next_action: str,
             extra_not_proven: Iterable[str] = (),
             extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The shared pattern shape, with the shared ladder's name for the level."""
    seed = hashlib.sha256("|".join([
        name, *sorted({str(s.get("subject") or "") for s in signals}),
        *sorted({str(s["signal"]) for s in signals}),
    ]).encode()).hexdigest()[:16]
    moments = [m for m in (_moment(s.get("at")) for s in signals) if m]
    return {
        "pattern_id": f"NPAT-{seed}",
        "name": name,
        "level": level,
        "level_name": ap.LEVELS[level]["name"],
        "level_meaning": ap.LEVELS[level]["meaning"],
        "classification": ap.LEVELS[level]["name"],
        "why": why,
        "subjects": sorted({str(s.get("subject") or "") for s in signals
                            if s.get("subject")}),
        "signals": [{"signal": s["signal"], "change_kind": s["change_kind"],
                     "subject": s.get("subject"), "before": s.get("before"),
                     "after": s.get("after"), "at": s.get("at"),
                     "evidence_ids": s.get("evidence_ids") or [],
                     "source": s.get("source")} for s in signals],
        "first_seen": _iso(min(moments)) if moments else None,
        "last_seen": _iso(max(moments)) if moments else None,
        "not_proven": [*NOT_PROVEN, *extra_not_proven],
        "next_action": next_action,
        **(dict(extra or {})),
    }


def correlate(window: Mapping[str, Any]) -> dict[str, Any]:
    """Signals in one window -> patterns, each capped at ``SUSPICIOUS_ACTIVITY``."""
    if not isinstance(window, Mapping) or window.get("schema") != SCHEMA:
        raise ValueError(f"the signal window is not a {SCHEMA} document")
    found: dict[str, list[Mapping[str, Any]]] = {}
    for signal in window.get("signals") or []:
        found.setdefault(str(signal["signal"]), []).append(signal)

    patterns: list[dict[str, Any]] = []
    weakening = [signal for signal in window.get("signals") or []
                 if signal["signal"] in WEAKENING]
    if weakening:
        patterns.append(_pattern(
            "NETWORK_CRYPTO_REGRESSION", 2, weakening,
            why=("negotiated cryptography weakened on an endpoint: a lower protocol, a "
                 "weaker suite, a replaced certificate or a moved trust anchor"),
            next_action=("compare against the change record for the terminating device "
                         "and confirm the weaker setting was intended"),
            extra_not_proven=["the endpoint may be serving the same policy as before; "
                              "what moved is what the handshake showed"]))

    per_subject: dict[str, list[Mapping[str, Any]]] = {}
    for signal in window.get("signals") or []:
        per_subject.setdefault(str(signal.get("subject") or ""), []).append(signal)
    for subject in sorted(per_subject):
        group = per_subject[subject]
        names = {signal["signal"] for signal in group}
        if {"TLS_DOWNGRADE", "CERTIFICATE_MUTATION"} <= names or {
                "CIPHER_DOWNGRADE", "CERTIFICATE_MUTATION"} <= names:
            patterns.append(_pattern(
                "TRUST_PATH_SHIFT", 2, group,
                why=("the protocol or suite weakened and the certificate was replaced on "
                     "the same endpoint inside one window — the two facts that together "
                     "describe a trust path"),
                next_action=("confirm with the PKI owner that the certificate was "
                             "renewed, and with the platform owner that the weaker "
                             "protocol is a deliberate fallback"),
                extra_not_proven=["a renewal and an interception look the same from "
                                  "outside; only the PKI and the device logs separate them"]))

    new_exposure = [signal for signal in window.get("signals") or []
                    if signal["signal"] == "NEW_ENDPOINT"]
    if new_exposure:
        patterns.append(_pattern(
            "NEW_EXPOSURE", 1, new_exposure,
            why=("a listener appeared that no earlier snapshot contained; a new "
                 "listener needs an owner before it needs a verdict"),
            next_action="assign the listener to an owner and confirm it was provisioned",
            extra_not_proven=["a listener can be a collector seeing an endpoint it "
                              "missed before, rather than a new service"]))

    lost = [signal for signal in window.get("signals") or []
            if signal["signal"] == "ENDPOINT_LOST"]
    if lost:
        patterns.append(_pattern(
            "DISAPPEARANCE", 1, lost,
            why=("a listener that an earlier snapshot contained is gone. A "
                 "decommission and a moved service look the same from outside"),
            next_action=("confirm with the owner whether the listener was retired or "
                         "moved, and re-probe before closing anything"),
            extra_not_proven=["an endpoint that stopped answering has not stopped "
                              "existing, and its cryptography is unknown rather than "
                              "absent"]))

    categories = {signal["signal"] for signal in window.get("signals") or []
                  if signal["signal"] in REVIEW_SIGNALS}
    if len(categories) >= 2 and categories & set(WEAKENING):
        participants = [signal for signal in window.get("signals") or []
                        if signal["signal"] in REVIEW_SIGNALS]
        patterns.append(_pattern(
            "CORRELATED_PATTERN", MAX_LEVEL, participants,
            why=("several independent network signals coincide in one window: "
                 + ", ".join(sorted(categories))
                 + ". A downgrade alone is a fact, and a new process alone is a fact; "
                   "together they describe one event rather than four"),
            next_action=("open one investigation covering the listed subjects and "
                         "evidence ids, and confirm or dismiss each signal separately — "
                         "do not treat the combination as a single finding"),
            extra_not_proven=["coincidence in one window is also what a maintenance "
                              "window, a failover and a certificate renewal look like"],
            extra={"coinciding_signals": sorted(categories)}))

    counts: dict[str, int] = {}
    for pattern in patterns:
        counts[pattern["classification"]] = counts.get(
            pattern["classification"], 0) + 1
    worst = max((pattern["level"] for pattern in patterns), default=0)
    return {
        "schema": SCHEMA,
        "patterns": patterns,
        "counts": dict(sorted(counts.items())),
        "levels": {ap.LEVELS[level]["name"]: sum(1 for pattern in patterns
                                                if pattern["level"] == level)
                   for level in sorted({pattern["level"] for pattern in patterns})},
        "worst": ap.LEVELS[worst]["name"] if patterns else None,
        "blind_spots": window.get("blind_spots") or [],
        "statement": (
            f"{len(patterns)} pattern(s) in one window"
            + (f"; the strongest is {ap.LEVELS[worst]['name']}"
               f" ({', '.join(sorted({p['name'] for p in patterns if p['level'] == worst}))})"
               if patterns else "; nothing coincides")
            + (f"; {len(window.get('blind_spots') or [])} endpoint(s) were blind, so the "
               "window is not complete" if window.get("blind_spots") else "")
            + ". This is a reason to investigate, not a finding of compromise"),
        "not_proven": list(NOT_PROVEN),
        "never": ["attack detected", "compromise confirmed", "attacker identified",
                  "SECURITY_INCIDENT"],
    }


def summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: how many patterns, how strong, and what could not be seen."""
    patterns = result.get("patterns") or []
    return {
        "schema": SCHEMA,
        "patterns": len(patterns),
        "by_name": {name: sum(1 for pattern in patterns if pattern["name"] == name)
                    for name in PATTERNS
                    if any(pattern["name"] == name for pattern in patterns)},
        "worst": result.get("worst"),
        "blind_spots": result.get("blind_spots") or [],
        "statement": result.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
