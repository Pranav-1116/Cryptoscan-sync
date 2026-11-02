"""Correlating hardware drift with everything else that moved (phase H7).

:mod:`~universal_vendor.hardware.drift` answers *what changed on this appliance*.
The question a change board actually asks is the one it cannot answer: **what
else moved at the same moment, and does the story hold together?**

Three shapes matter, and each is a different finding:

* **Correlated** — an HSM gained ML-DSA at 09:14, the payment service switched
  its TLS profile at 09:16, the certificate was reissued at 09:20. One change
  window, three records, and the estate can say so. Without this, the three
  land in three dashboards and nobody sees the migration.
* **Unaccompanied** — the HSM's firmware moved and nothing else did. Either
  nobody has started the migration this firmware enables, or the application
  team was not told. Both are worth asking about, and neither is a defect.
* **Suspicious** — the certificate moved and the HSM did *not*, on a service
  whose keys live in that HSM. That is either a key that moved somewhere it
  should not have, or a correlation that was never true; the estate should ask.

The rule the module will not break: **correlation is not causation, and proximity
in time is not a relationship.** Every result says how many records were
compared, what window was used, and that a co-occurrence proves the change board
should look, not that one change caused another. Nothing here mints a
:class:`~universal_vendor.hardware.relationships.HardwareEdge`: an edge needs
evidence naming both ends, and "it happened at the same time" is not that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.hardware-change-correlation/1"

#: The domains a change record can come from. Kept as an explicit set: a record
#: tagged with something else is a caller bug, and silently dropping it would
#: make the correlation look cleaner than it is.
DOMAINS = ("HARDWARE", "CERTIFICATE", "APPLICATION", "POLICY")

#: Domains that *should* move together for a migration, by hardware event.
#: A PQC capability arriving on an HSM is only useful if the application and its
#: certificates move with it; a firmware bump on a switch needs no companions.
COMPANION_DOMAINS: dict[str, tuple[str, ...]] = {
    "PQC_CAPABILITY_ADDED": ("APPLICATION", "CERTIFICATE"),
    "PQC_CAPABILITY_REMOVED": ("APPLICATION", "CERTIFICATE"),
    "CRYPTO_CAPABILITY_CHANGED": ("APPLICATION",),
    "HSM_CAPABILITY_CHANGED": ("APPLICATION",),
    "FIRMWARE_CHANGED": (),
    "TPM_FIRMWARE_CHANGED": (),
    "HARDWARE_CHANGED": ("APPLICATION",),
}

#: A change that means "this service's crypto posture moved". Used for the
#: suspicious case: a certificate moving without the hardware that holds its key.
_CRYPTO_POLICY_EVENTS = frozenset({"CERTIFICATE_REISSUED", "CERTIFICATE_REPLACED",
                                   "TLS_PROFILE_CHANGED", "ALGORITHM_POLICY_CHANGED"})


class ChangeRecordRejected(ValueError):
    """A change record was malformed enough to make the correlation misleading."""


@dataclass(frozen=True)
class ChangeRecord:
    """One thing that moved, anywhere in the estate.

    ``domain`` names where it was observed, ``subject`` names what moved (an
    asset id, an application, a certificate), and ``at`` is when the platform
    observed it — not when the operator believes it happened.
    """

    domain: str
    subject: str
    event_type: str
    at: str
    detail: dict[str, Any] = field(default_factory=dict)
    evidence: str | None = None

    def __post_init__(self) -> None:
        if self.domain not in DOMAINS:
            raise ChangeRecordRejected(
                f"domain {self.domain!r} is not one of {list(DOMAINS)}")
        if not self.subject.strip():
            raise ChangeRecordRejected("a change record needs a subject")
        if parse_moment(self.at) is None:
            raise ChangeRecordRejected(
                f"{self.at!r} is not an ISO-8601 instant; a change without a time cannot "
                "be correlated and must not be guessed at")

    @property
    def moment(self) -> datetime:
        parsed = parse_moment(self.at)
        assert parsed is not None  # guarded in __post_init__
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "subject": self.subject,
                "event_type": self.event_type, "at": self.at,
                "detail": dict(self.detail), "evidence": self.evidence}


def parse_moment(text: str | None) -> datetime | None:
    if not text:
        return None
    candidate = str(text).strip().replace("Z", "+00:00")
    for pattern in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(candidate, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def record_from_change(change: Any, *, domain: str = "HARDWARE") -> ChangeRecord:
    """Turn a :class:`~universal_vendor.hardware.drift.HardwareChange` into a record.

    The drift module's own output is the natural input, so a caller does not have
    to re-shape it — and cannot accidentally drop the evidence ids on the way.
    """
    payload = change.to_dict() if hasattr(change, "to_dict") else dict(change)
    return ChangeRecord(
        domain=domain,
        subject=str(payload.get("asset_id") or ""),
        event_type=str(payload.get("event_type") or "UNKNOWN"),
        at=str(payload.get("detected_at") or ""),
        detail=dict(payload.get("detail") or {}),
        evidence=",".join(payload.get("evidence") or []) or None,
    )


@dataclass
class CorrelatedChange:
    """One hardware change and what else moved around it."""

    change: ChangeRecord
    companions: list[ChangeRecord] = field(default_factory=list)
    missing_domains: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """One word the change board can filter on.

        ``PARTIAL`` exists because "some companions, not the expected ones" is a
        different situation from "nothing at all": a TLS profile moved but no
        certificate was reissued, which is a migration half-done rather than a
        migration nobody started.
        """
        if self.suspicious:
            return "SUSPICIOUS"
        if self.companions and not self.missing_domains:
            return "CORRELATED"
        if self.companions:
            return "PARTIAL"
        if self.missing_domains:
            return "UNACCOMPANIED"
        return "ISOLATED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "change": self.change.to_dict(),
            "verdict": self.verdict,
            "companions": [record.to_dict() for record in self.companions],
            "companion_domains": sorted({record.domain for record in self.companions}),
            "missing_domains": list(self.missing_domains),
            "suspicious": list(self.suspicious),
        }


def correlate_changes(hardware_changes: Iterable[Any], other_changes: Iterable[Any] = (),
                      *, window_minutes: int = 120,
                      asset_aliases: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Pair each hardware change with the certificate/app/policy changes near it.

    ``asset_aliases`` maps a subject as one system spells it to the subject the
    hardware estate uses (``lb-01`` vs ``lb-01.bank.example``). Without it, a
    correlation quietly misses the pair it should have found — and a missed pair
    looks identical to "nothing else moved".
    """
    if window_minutes <= 0:
        raise ValueError("a correlation window must be positive")

    hardware = [record if isinstance(record, ChangeRecord) else record_from_change(record)
                for record in hardware_changes]
    others: list[ChangeRecord] = []
    for record in other_changes:
        if isinstance(record, ChangeRecord):
            others.append(record)
        elif isinstance(record, Mapping):
            others.append(ChangeRecord(**record))
        else:
            others.append(record_from_change(record, domain="CERTIFICATE")
                          if hasattr(record, "to_dict") else
                          ChangeRecord(**dict(record)))

    aliases = {key: value for key, value in (asset_aliases or {}).items()}
    window = timedelta(minutes=window_minutes)
    results: list[CorrelatedChange] = []

    for change in hardware:
        subject = aliases.get(change.subject, change.subject)
        # A companion is near in time and about the same thing: the same asset,
        # or an application/certificate the caller declared belongs to it.
        related = [
            record for record in others
            if abs(record.moment - change.moment) <= window
            and (record.subject == subject or aliases.get(record.subject, record.subject)
                 == subject)
        ]
        related.sort(key=lambda record: (record.moment, record.domain, record.subject))
        companion_domains = {record.domain for record in related}
        expected = COMPANION_DOMAINS.get(change.event_type, ())
        missing = [domain for domain in expected if domain not in companion_domains]

        suspicious: list[str] = []
        if change.event_type in {"FIRMWARE_CHANGED", "HARDWARE_CHANGED",
                                 "HSM_CAPABILITY_CHANGED"}:
            # A certificate moved on this subject while the hardware that holds
            # its key did not. Either the key moved, or the linkage was never real.
            moved_crypto = [record for record in related
                            if record.event_type in _CRYPTO_POLICY_EVENTS]
            if moved_crypto:
                suspicious.append(
                    f"{len(moved_crypto)} cryptographic change(s) on {subject} in the same "
                    f"window without a capability change on the appliance: check where the "
                    "key now lives")
        results.append(CorrelatedChange(change=change, companions=related,
                                        missing_domains=missing, suspicious=suspicious))

    by_verdict: dict[str, int] = {}
    for result in results:
        by_verdict[result.verdict] = by_verdict.get(result.verdict, 0) + 1
    return {
        "schema": SCHEMA,
        "window_minutes": window_minutes,
        "hardware_changes": len(hardware),
        "other_changes": len(others),
        "results": [result.to_dict() for result in results],
        "by_verdict": by_verdict,
        "unaccompanied": [result.to_dict() for result in results
                          if result.verdict == "UNACCOMPANIED"],
        "partial": [result.to_dict() for result in results
                    if result.verdict == "PARTIAL"],
        "suspicious": [result.to_dict() for result in results
                       if result.verdict == "SUSPICIOUS"],
        "limits": [
            "proximity in time is not causation: a companion is a record the change "
            "board should read beside this one, not proof that either caused the other",
            "a missed companion may be an alias this correlation was not told about, so "
            "UNACCOMPANIED means 'nothing found under this subject', not 'nothing happened'",
        ],
    }


def migration_readiness(hardware_changes: Iterable[Any], other_changes: Iterable[Any] = (),
                        *, window_minutes: int = 1440,
                        asset_aliases: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Did the PQC capability land, and did anything start using it?

    The question a PQC programme asks after a firmware upgrade: the appliance can
    do ML-DSA, so has any application or certificate moved to it? "No" is not a
    failure — it is the migration that has not started, stated as such.
    """
    report = correlate_changes(hardware_changes, other_changes,
                               window_minutes=window_minutes, asset_aliases=asset_aliases)
    pqc_gains = [result for result in report["results"]
                 if result["change"]["event_type"] == "PQC_CAPABILITY_ADDED"]
    adopted = [result for result in pqc_gains
               if {"APPLICATION", "CERTIFICATE"} & set(result["companion_domains"])]
    return {
        "schema": SCHEMA,
        "capabilities_gained": len(pqc_gains),
        "with_companion_movement": len(adopted),
        "adoption_observed": bool(adopted),
        "statement": ("a post-quantum capability arrived and something else moved with it"
                      if adopted else
                      "a post-quantum capability arrived and nothing has started using it: "
                      "this is an available migration, not a completed one"
                      if pqc_gains else
                      "no post-quantum capability arrived in this window"),
        "devices": [result["change"]["subject"] for result in pqc_gains],
        "window_minutes": window_minutes,
    }
