"""Tier-2 runtime cryptographic observation (approved — §3 of
docs/os-kernel-intelligence/01_PRODUCT_SPEC.md).

The runtime engine produces METADATA EVENTS ONLY. It never collects:
plaintext, private keys, encryption keys, passwords, tokens, decrypted
application data, TLS session secrets, HSM key material, or full
cryptographic input/output buffers. The bounded event filter refuses
any field outside the allowlist and counts every refusal.

Event schema (the spec's §3 list):
  event_id · host_id · boot_id · process_id · process_start_time ·
  executable_digest · operation_category · algorithm_identifier ·
  provider_identifier · kernel_or_userspace · interface · timestamp ·
  evidence_source · collection_profile

Pipeline (the spec's recommended implementation):
  approved tracepoints / eBPF programs
    -> bounded event filter (process identity, event category,
       allowlisted fields)
    -> local event normalizer (schema validation, deduplication,
       timestamping)
    -> evidence records with provenance.

runtime_usage_confirmed is raised ONLY by runtime evidence and never
overwrites the static registration row (§2.2): the confirmation record
names the events that confirm it and the process identity observed.

Event-loss accounting feeds OS-CRYPTO-017 ('Runtime collector losing
events — observability gap'): lost events are counted from the
collector's own accounting (LOST lines), never guessed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MAX_EVENTS = 50000
MAX_LINE = 4096
MAX_REFUSALS = 1000

#: The allowlist — an event carries these fields and NOTHING else.
EVENT_FIELDS = (
    "event_id", "host_id", "boot_id", "process_id",
    "process_start_time", "executable_digest", "operation_category",
    "algorithm_identifier", "provider_identifier",
    "kernel_or_userspace", "interface", "timestamp",
    "evidence_source", "collection_profile",
)

#: Never collected (§3) — a field NAME containing any of these markers
#: is REFUSED, whatever its value. Metadata events only.
PROHIBITED_FIELD_MARKERS = (
    "plaintext", "private_key", "password", "token", "secret",
    "payload", "buffer", "key_material", "session_key",
    "recovery", "decrypted", "input", "output", "seed", "pin",
)

#: The spec's operation categories. An unknown category is recorded as
#: 'unclassified' — never guessed.
OPERATION_CATEGORIES = (
    "crypto_api_allocation",
    "algorithm_selection",
    "key_generation_request",
    "encrypt_decrypt_operation",
    "hash_operation",
    "signature_generate_verify",
    "kernel_tls_state_transition",
    "ipsec_policy_change",
    "crypto_module_load_unload",
    "tpm_hsm_provider_activity",
)

#: Categories that OBSERVE an algorithm implementation in runtime use.
USAGE_CATEGORIES = (
    "crypto_api_allocation",
    "algorithm_selection",
    "key_generation_request",
    "encrypt_decrypt_operation",
    "hash_operation",
    "signature_generate_verify",
)


@dataclass
class RuntimeEvent:
    event_id: str = ""
    host_id: str = ""
    boot_id: str = ""
    process_id: str = ""
    process_start_time: str = ""
    executable_digest: str = ""
    operation_category: str = "unclassified"
    algorithm_identifier: str = ""
    provider_identifier: str = ""
    kernel_or_userspace: str = ""
    interface: str = ""
    timestamp: str = ""
    evidence_source: str = ""
    collection_profile: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {name: getattr(self, name) for name in EVENT_FIELDS}

    def content_hash(self) -> str:
        payload = "|".join(self.as_dict()[k] for k in
                           sorted(EVENT_FIELDS) if k != "event_id")
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class RuntimeSession:
    """One bounded runtime-collection session."""
    session_id: str
    host_id: str
    boot_id: str = ""
    collection_profile: str = "tier2-approved-tracepoints"
    evidence_source: str = ""
    started_at: str = ""
    ended_at: str = ""
    attached_points: List[str] = field(default_factory=list)
    events: List[RuntimeEvent] = field(default_factory=list)
    #: the collector's own loss accounting — recorded, never guessed
    events_lost: int = 0
    #: refused/skipped inputs with reasons (bounded) — refusals are
    #: COUNTED, never drawn as truths
    refusals: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "host_id": self.host_id,
            "boot_id": self.boot_id,
            "collection_profile": self.collection_profile,
            "evidence_source": self.evidence_source,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "attached_points": list(self.attached_points),
            "events_accepted": len(self.events),
            "events_lost": self.events_lost,
            "refusals": list(self.refusals[:MAX_REFUSALS]),
            "notes": list(self.notes),
            "note": ("Tier-2 runtime METADATA events only — plaintext, "
                     "keys, passwords, tokens, secrets and crypto "
                     "input/output buffers are never collected (§3); "
                     "a raised runtime_usage_confirmed comes from these "
                     "events and never overwrites the static "
                     "registration row (§2.2)"),
        }

    def usage_confirmations(self) -> List[Dict[str, Any]]:
        """Runtime usage confirmations derived from accepted events.

        A confirmation is scoped to the OBSERVED PROCESS IDENTITY and
        names the confirming events. It confirms that an algorithm
        implementation was observed in runtime use — it is never a
        claim about any specific application beyond the observed
        process, and never a co-location inference (§2.2)."""
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for ev in self.events:
            if ev.operation_category not in USAGE_CATEGORIES:
                continue
            key = (ev.algorithm_identifier, ev.provider_identifier
                   or ev.interface or "unknown")
            if not key[0]:
                continue
            entry = groups.setdefault(key, {
                "algorithm": key[0],
                "implementation": key[1],
                "runtime_usage_confirmed": True,
                "evidence_class": "observed",
                "observed_processes": set(),
                "confirmed_by_events": [],
            })
            if ev.process_id or ev.executable_digest:
                digest_part = (" digest=" + ev.executable_digest
                               if ev.executable_digest else "")
                identity = f"pid={ev.process_id or '?'}{digest_part}"
                entry["observed_processes"].add(identity)
            if len(entry["confirmed_by_events"]) < 20:
                entry["confirmed_by_events"].append(ev.event_id)
        confirmations = []
        for entry in groups.values():
            entry["observed_processes"] = sorted(
                entry["observed_processes"])
            entry["evidence_source"] = self.evidence_source
            entry["note"] = (
                "raised ONLY by observed runtime events (§2.2) — the "
                "static registration row is never overwritten; the "
                "confirmation is scoped to the observed process "
                "identity and is never inferred from co-location")
            confirmations.append(entry)
        return confirmations

    def loss_report(self) -> Dict[str, Any]:
        """Event-loss accounting for OS-CRYPTO-017."""
        accepted = len(self.events)
        total = accepted + self.events_lost
        return {
            "session_id": self.session_id,
            "events_accepted": accepted,
            "events_lost": self.events_lost,
            "events_total_accounted": total,
            "loss_ratio": (self.events_lost / total) if total else None,
            "note": ("lost-event counts come from the collector's own "
                     "accounting — recorded, never guessed; a session "
                     "without loss accounting is UNKNOWN, never "
                     "'lossless'"),
        }


def _refuse(refusals: List[Dict[str, str]], where: str,
            reason: str) -> None:
    if len(refusals) < MAX_REFUSALS:
        refusals.append({"where": where[:120], "reason": reason[:200]})


def _filter_fields(raw: Dict[str, Any], refusals: List[Dict[str, str]],
                   where: str) -> Dict[str, str]:
    """Bounded event filter: allowlisted fields only. A prohibited
    marker in a field NAME refuses the whole field with a reason —
    metadata events only."""
    clean: Dict[str, str] = {}
    for key, value in raw.items():
        low = str(key).lower()
        if any(marker in low for marker in PROHIBITED_FIELD_MARKERS):
            _refuse(refusals, where,
                    f"field {key!r} refused — the runtime engine "
                    "collects metadata events only and NEVER collects "
                    "secrets, keys, payloads or buffers (§3)")
            continue
        if key not in EVENT_FIELDS:
            _refuse(refusals, where,
                    f"field {key!r} is outside the allowlist — "
                    "refused, never stored")
            continue
        clean[key] = "" if value is None else str(value)[:MAX_LINE]
    return clean


def ingest_events(session_id: str, host_id: str,
                  raw_events: List[Dict[str, Any]], *,
                  boot_id: str = "",
                  collection_profile: str = "tier2-approved-tracepoints",
                  evidence_source: str = "",
                  events_lost: int = 0,
                  attached_points: Optional[List[str]] = None,
                  started_at: str = "", ended_at: str = ""
                  ) -> RuntimeSession:
    """Normalize raw captured events into a RuntimeSession.

    Malformed events are refused with reasons and counted — never
    fabricated. Duplicate events (identical content) are collapsed
    with a note — deduplication, never silent loss."""
    session = RuntimeSession(
        session_id=session_id, host_id=host_id, boot_id=boot_id,
        collection_profile=collection_profile,
        evidence_source=evidence_source,
        started_at=started_at, ended_at=ended_at,
        events_lost=max(0, int(events_lost)),
        attached_points=list(attached_points or []))
    seen: set = set()
    for i, raw in enumerate(raw_events):
        where = f"events[{i}]"
        if not isinstance(raw, dict):
            _refuse(session.refusals, where,
                    "event is not a mapping — skipped, never guessed")
            continue
        clean = _filter_fields(raw, session.refusals, where)
        category = clean.get("operation_category", "")
        if category and category not in OPERATION_CATEGORIES:
            clean["operation_category"] = "unclassified"
            _refuse(session.refusals, where,
                    f"operation_category {category!r} is not a "
                    "documented category — recorded as 'unclassified', "
                    "never guessed")
        elif not category:
            clean["operation_category"] = "unclassified"
        ev = RuntimeEvent(**{k: clean.get(k, "") for k in
                             EVENT_FIELDS})
        if not ev.timestamp and not ev.event_id:
            _refuse(session.refusals, where,
                    "event carries neither timestamp nor event_id — "
                    "skipped; an unplaceable event is not evidence")
            continue
        if not ev.event_id:
            ev.event_id = f"rt-{session_id}-{i}"
        digest = ev.content_hash()
        if digest in seen:
            session.notes.append(
                f"duplicate event {ev.event_id} collapsed "
                "(deduplication — never silent loss)")
            continue
        seen.add(digest)
        if len(session.events) >= MAX_EVENTS:
            session.events_lost += 1
            continue
        ev.host_id = ev.host_id or host_id
        ev.boot_id = ev.boot_id or boot_id
        ev.collection_profile = (ev.collection_profile
                                 or collection_profile)
        ev.evidence_source = ev.evidence_source or evidence_source
        session.events.append(ev)
    session.notes.append(
        "runtime_usage_confirmed is raised ONLY by these metadata "
        "events and never overwrites the static registration row "
        "(§2.2)")
    return session


_TRACE_LINE = re.compile(
    r"^EVT\|(?P<ts>[^|]*)\|(?P<pid>[^|]*)\|(?P<start>[^|]*)\|"
    r"(?P<digest>[^|]*)\|(?P<category>[^|]*)\|(?P<algo>[^|]*)\|"
    r"(?P<provider>[^|]*)\|(?P<ku>[^|]*)\|(?P<iface>[^|]*)\|"
    r"(?P<comm>[^|]*)$")
_LOST_LINE = re.compile(r"^LOST\|(?P<n>\d+)")
_HEADER_LINE = re.compile(r"^META\|(?P<key>[^=]+)=(?P<value>.*)$")


def parse_trace_text(text: str, session_id: str, host_id: str,
                     *, evidence_source: str = "runtime collector",
                     collection_profile: str =
                     "tier2-approved-tracepoints"
                     ) -> RuntimeSession:
    """Parse the capture format emitted by tools/runtime_capture/.

    Format: META|key=value header lines, EVT|... pipe records (the
    canonical fields), LOST|N loss-accounting lines. Unparseable lines
    are refused with reasons — never fabricated. The 'comm' field is
    process NAME metadata (never command lines, which may embed
    secrets)."""
    meta: Dict[str, str] = {}
    raw_events: List[Dict[str, Any]] = []
    lost = 0
    refusals: List[Dict[str, str]] = []
    for idx, line in enumerate(text.splitlines()[:MAX_EVENTS * 2]):
        line = line.strip()[:MAX_LINE]
        if not line:
            continue
        m = _HEADER_LINE.match(line)
        if m:
            meta[m.group("key").strip()] = m.group("value").strip()
            continue
        m = _LOST_LINE.match(line)
        if m:
            lost += int(m.group("n"))
            continue
        m = _TRACE_LINE.match(line)
        if m:
            fields = m.groupdict()
            raw_events.append({
                "timestamp": fields["ts"],
                "process_id": fields["pid"],
                "process_start_time": fields["start"],
                "executable_digest": fields["digest"],
                "operation_category": fields["category"],
                "algorithm_identifier": fields["algo"],
                "provider_identifier": fields["provider"],
                "kernel_or_userspace": fields["ku"],
                "interface": fields["iface"],
            })
            continue
        if line.startswith("#"):
            continue
        _refuse(refusals, f"line {idx + 1}",
                "unparseable trace line — skipped, never fabricated")
    session = ingest_events(
        session_id, host_id, raw_events,
        boot_id=meta.get("boot_id", ""),
        collection_profile=meta.get("collection_profile",
                                    collection_profile),
        evidence_source=meta.get("evidence_source", evidence_source),
        events_lost=lost,
        attached_points=[p for p in
                         meta.get("attached_points", "").split(",")
                         if p.strip()],
        started_at=meta.get("started_at", ""),
        ended_at=meta.get("ended_at", ""))
    session.refusals = refusals + session.refusals
    return session
