"""Observations become facts here, and nowhere else.

The review's hardest complaint was not that the platform misread a device. It was that the
platform's own pipeline turned *"OpenSSL 3.0.13 is installed"* into *"the application uses
AES-256-GCM"*. That single step made the BOM look rich, made a customer's false-positive rate
100%, and is the reason an accuracy target of 95% looked unreachable: the shortcut reached it by
guessing.

So the boundary is a module with the rules written down as code:

```
observation → evidence check → normalise → identity → FACT → correlation → BOM
```

Three separations, each enforced by a refusal rather than a convention
----------------------------------------------------------------------
**Capability is not usage.** A library's algorithm list is a :data:`CAPABILITY` fact. It is a real
fact — about what the library *can* do — and it is not a usage fact. Only a runtime observation, a
negotiated handshake or a configuration that states a usage can produce :data:`RUNTIME_USAGE`,
:data:`NETWORK_NEGOTIATED` or :data:`CONFIGURED_USAGE`. A document cannot, and :class:`Observation`
raises when someone tries (see :data:`_LEGAL`).

**A class is carried, never inferred upward.** ``VENDOR_DECLARED`` stays ``VENDOR_DECLARED``
however many documents repeat it; corroboration is not promotion. ``INFERRED`` is recorded as a
lead, shown as a lead, and excluded from every decision (:data:`DECIDING_CLASSES`): a value that
rests only on an inference comes out :data:`UNKNOWN_STATE` with an ``INFERRED_ONLY`` refusal.

**Absence is four facts.** :data:`NOT_FOUND_WITHIN_SCOPE` (the only state that is evidence of
absence, and only inside the scope it names), :data:`NOT_OBSERVABLE` (no collector reaches it),
:data:`COLLECTION_FAILED` (the look failed) and :data:`UNKNOWN_STATE` (nobody looked). "HSM
collection failed" never becomes "HSM crypto = none".

And disagreement is preserved: the weights in :data:`STRENGTH` order the classes for display and
never pick the winner. Two values on the same plane produce :data:`CONFLICT` with every side, its
class, its source and its evidence id — the same REAL-versus-EXPLAINED rule the estate conflict
module applies one layer up, applied here at the moment a fact is minted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.facts/1"

# --------------------------------------------------------------------------- #
# observation classes
# --------------------------------------------------------------------------- #

RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
NETWORK_OBSERVED = "NETWORK_OBSERVED"
#: The component was seen in an inventory or a sweep: it demonstrably exists, which is not the
#: same as anyone having read inside it.
OBSERVED = "OBSERVED"
STATIC_OBSERVED = "STATIC_OBSERVED"
CONFIGURED = "CONFIGURED"
IMPORTED = "IMPORTED"
VENDOR_DECLARED = "VENDOR_DECLARED"
INFERRED = "INFERRED"
UNKNOWN_CLASS = "UNKNOWN"

OBSERVATION_CLASSES = frozenset({
    RUNTIME_OBSERVED, NETWORK_OBSERVED, OBSERVED, STATIC_OBSERVED, CONFIGURED, IMPORTED,
    VENDOR_DECLARED, INFERRED, UNKNOWN_CLASS,
})

#: How much a class is worth when something has to be *displayed* as the best evidence. It is not
#: a tie-breaker: :func:`aggregate` never uses it to resolve a disagreement, only to name the
#: strength of a fact that has already been agreed.
STRENGTH: Mapping[str, float] = {
    RUNTIME_OBSERVED: 1.00,
    NETWORK_OBSERVED: 0.98,
    STATIC_OBSERVED: 0.95,
    OBSERVED: 0.85,
    CONFIGURED: 0.85,
    IMPORTED: 0.70,
    VENDOR_DECLARED: 0.60,
    INFERRED: 0.30,
    UNKNOWN_CLASS: 0.00,
}

#: Classes that may decide a fact. An inference and an unknown are recorded, displayed, and given
#: no vote — which is the whole difference between "we think" and "we know".
DECIDING_CLASSES = frozenset(OBSERVATION_CLASSES - {INFERRED, UNKNOWN_CLASS})

# --------------------------------------------------------------------------- #
# what a fact is about
# --------------------------------------------------------------------------- #

CAPABILITY = "CAPABILITY"
CONFIGURED_USAGE = "CONFIGURED_USAGE"
STATIC_REFERENCE = "STATIC_REFERENCE"
INVENTORY = "INVENTORY"
RUNTIME_USAGE = "RUNTIME_USAGE"
NETWORK_NEGOTIATED = "NETWORK_NEGOTIATED"

KINDS = frozenset({CAPABILITY, CONFIGURED_USAGE, STATIC_REFERENCE, INVENTORY, RUNTIME_USAGE,
                   NETWORK_NEGOTIATED})

KIND_MEANING: Mapping[str, str] = {
    CAPABILITY: "the component can do this; nothing says it does",
    CONFIGURED_USAGE: "a configuration states this is in use",
    STATIC_REFERENCE: "code, a manifest or a binary refers to this",
    INVENTORY: "an SBOM, an image or a CMDB record says this exists",
    RUNTIME_USAGE: "a running process was observed using this",
    NETWORK_NEGOTIATED: "the wire negotiated this in a handshake",
}

#: Kinds that make a statement about *use*, as opposed to one about capability. A capability beside
#: a usage is not a contradiction — it is a component that can do more than the application asked
#: of it, which is a finding in its own right and never a conflict.
USAGE_KINDS = frozenset({CONFIGURED_USAGE, STATIC_REFERENCE, INVENTORY, RUNTIME_USAGE,
                         NETWORK_NEGOTIATED})

#: Which observation classes may back which kind. Exhaustive and checked in ``__post_init__``:
#: adding a class or a kind without deciding this is not possible, and a document claiming a
#: runtime usage is refused where it is created rather than where it is read.
_LEGAL: Mapping[str, frozenset[str]] = {
    # An inferred capability is allowed to exist as a lead — a scanner may guess that a modern
    # library "can do" X — but it reaches no usage kind, and aggregate() gives it no vote, so it
    # cannot become an answer by being recorded.
    CAPABILITY: frozenset({CONFIGURED, STATIC_OBSERVED, OBSERVED, RUNTIME_OBSERVED, IMPORTED,
                           VENDOR_DECLARED, INFERRED}),
    CONFIGURED_USAGE: frozenset({CONFIGURED, STATIC_OBSERVED, OBSERVED, VENDOR_DECLARED,
                                 INFERRED}),
    STATIC_REFERENCE: frozenset({STATIC_OBSERVED, OBSERVED, IMPORTED, CONFIGURED, INFERRED}),
    INVENTORY: frozenset({IMPORTED, STATIC_OBSERVED, OBSERVED, CONFIGURED}),
    RUNTIME_USAGE: frozenset({RUNTIME_OBSERVED}),
    NETWORK_NEGOTIATED: frozenset({NETWORK_OBSERVED}),
}

# --------------------------------------------------------------------------- #
# fact states
# --------------------------------------------------------------------------- #

FOUND = "FOUND"
CONFLICT = "CONFLICT"
UNKNOWN_STATE = "UNKNOWN"
NOT_FOUND_WITHIN_SCOPE = "NOT_FOUND_WITHIN_SCOPE"
NOT_OBSERVABLE = "NOT_OBSERVABLE"
COLLECTION_FAILED = "COLLECTION_FAILED"

STATES = frozenset({FOUND, CONFLICT, UNKNOWN_STATE, NOT_FOUND_WITHIN_SCOPE, NOT_OBSERVABLE,
                    COLLECTION_FAILED})

#: The only states that are evidence of absence. ``NOT_OBSERVABLE`` is a statement about the
#: collector, not about the estate; ``UNKNOWN`` is a statement about nobody having asked.
ABSENCE_EVIDENCE = frozenset({NOT_FOUND_WITHIN_SCOPE})

# --------------------------------------------------------------------------- #
# conflict kinds
# --------------------------------------------------------------------------- #

RUNTIME_STATIC_CONFLICT = "RUNTIME_STATIC_CONFLICT"
DEPENDENCY_VERSION_CONFLICT = "DEPENDENCY_VERSION_CONFLICT"
VALUE_CONFLICT = "VALUE_CONFLICT"

#: Properties that are about *what is installed* rather than *what is done*, so a disagreement
#: between an inventory and a running system is a version conflict and not a crypto conflict.
_VERSION_PROPERTIES = frozenset({"dependency_version", "version", "package_version"})

_REFUSAL_MESSAGES = {
    "INFERRED_ONLY": ("the only observation is an inference; it is recorded as a lead and is not "
                      "used for a decision"),
    "COLLECTION_FAILED": "the collection did not complete, so nothing can be concluded",
    "NO_EVIDENCE": "no observation carries an evidence id",
}


# --------------------------------------------------------------------------- #
# the observation
# --------------------------------------------------------------------------- #

def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(prefix: str, payload: Any, length: int) -> str:
    return f"{prefix}-v1-{hashlib.sha256(_canonical(payload)).hexdigest()[:length]}"


def observation_digest(observation: "Observation") -> str:
    """A stable id for the *observation*, so repeating a collection does not create a new fact."""
    return _digest("EVID", observation.as_dict(), 24)


def fact_digest(fact: "Fact") -> str:
    return _digest("FACT", fact.as_dict(), 24)


@dataclass(frozen=True, slots=True)
class Observation:
    """One thing one collector saw, with the class of seeing it and the evidence that proves it."""

    subject: str
    property: str
    value: Any
    klass: str
    kind: str
    source: str
    evidence_id: str
    scope: str = ""
    observed_at: str | None = None

    def __post_init__(self) -> None:
        if not str(self.subject).strip():
            raise ValueError("an observation needs a subject")
        if not str(self.property).strip():
            raise ValueError("an observation needs a property")
        if self.klass not in OBSERVATION_CLASSES:
            raise ValueError(
                f"unknown observation class {self.klass!r}; one of "
                f"{sorted(OBSERVATION_CLASSES)}")
        if self.kind not in KINDS:
            raise ValueError(f"unknown fact kind {self.kind!r}; one of {sorted(KINDS)}")
        if not str(self.evidence_id).strip():
            raise ValueError(
                "an observation without an evidence id is a rumour: every observation must name "
                "the record that proves it")
        legal = _LEGAL[self.kind]
        if self.klass not in legal:
            raise ValueError(
                f"{self.klass} cannot support {self.kind}: legal backing for {self.kind} is "
                f"{sorted(legal)}")

    @property
    def strength(self) -> float:
        return STRENGTH.get(self.klass, 0.0)

    @property
    def decided(self) -> bool:
        return self.klass in DECIDING_CLASSES

    def normalised_value(self) -> Any:
        if isinstance(self.value, str):
            return self.value.strip()
        return self.value

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject, "property": self.property,
            "value": self.normalised_value(), "class": self.klass, "kind": self.kind,
            "source": self.source, "evidence_id": self.evidence_id, "scope": self.scope,
            "observed_at": self.observed_at,
        }


# --------------------------------------------------------------------------- #
# the fact
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class Fact:
    """What the platform is prepared to say, why, and on whose evidence."""

    subject: str
    property: str
    state: str
    kind: str | None
    value: Any = None
    classes: frozenset[str] = field(default_factory=frozenset)
    evidence_ids: tuple[str, ...] = ()
    scope: str = ""
    conflict: str | None = None
    sides: tuple[dict[str, Any], ...] = ()
    detail: str = ""

    @property
    def decided(self) -> bool:
        """A found value resting only on non-deciding classes is not a decision."""
        return self.state == FOUND and bool(self.classes & DECIDING_CLASSES)

    @property
    def used_for_decision(self) -> bool:
        return self.decided

    def strength(self) -> float:
        return max((STRENGTH.get(klass, 0.0) for klass in self.classes), default=0.0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject, "property": self.property, "state": self.state,
            "kind": self.kind, "value": self.value, "classes": sorted(self.classes),
            "evidence_ids": list(self.evidence_ids), "scope": self.scope,
            "conflict": self.conflict, "sides": [dict(side) for side in self.sides],
            "detail": self.detail, "schema": SCHEMA,
        }


@dataclass(frozen=True, slots=True)
class Derivation:
    facts: tuple[Fact, ...]
    refusals: tuple[dict[str, str], ...] = ()

    def get(self, subject: str, property_name: str) -> Fact | None:
        for fact in self.facts:
            if fact.subject == subject and fact.property == property_name:
                return fact
        return None

    def for_subject(self, subject: str) -> tuple[Fact, ...]:
        return tuple(fact for fact in self.facts if fact.subject == subject)

    def as_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "facts": [fact.as_dict() for fact in self.facts],
                "refusals": [dict(refusal) for refusal in self.refusals]}


def _refusal(code: str, subject: str, property_name: str, detail: str) -> dict[str, str]:
    return {"code": code, "subject": subject, "property": property_name,
            "detail": detail or _REFUSAL_MESSAGES.get(code, "")}


def _sides(observations: Sequence[Observation]) -> tuple[dict[str, Any], ...]:
    """Every observation, grouped by value, with the class and evidence that carried it."""
    grouped: dict[str, list[Observation]] = {}
    for observation in observations:
        grouped.setdefault(str(observation.normalised_value()), []).append(observation)
    sides = []
    for value, items in sorted(grouped.items()):
        best = max(items, key=lambda item: item.strength)
        sides.append({
            "value": value,
            "classes": sorted({item.klass for item in items}),
            "class": best.klass,
            "sources": sorted({item.source for item in items}),
            "evidence_id": best.evidence_id,
            "evidence_ids": sorted({item.evidence_id for item in items}),
            "scope": best.scope,
        })
    return tuple(sides)


def _conflict_kind(property_name: str, observations: Sequence[Observation]) -> str:
    classes = {item.klass for item in observations}
    if property_name in _VERSION_PROPERTIES and (
            IMPORTED in classes or VENDOR_DECLARED in classes) and (
            RUNTIME_OBSERVED in classes or NETWORK_OBSERVED in classes):
        return DEPENDENCY_VERSION_CONFLICT
    if classes & {IMPORTED, STATIC_OBSERVED} and classes & {RUNTIME_OBSERVED, NETWORK_OBSERVED}:
        return RUNTIME_STATIC_CONFLICT
    return VALUE_CONFLICT


def aggregate(observations: Sequence[Observation]) -> tuple[Fact, dict[str, str] | None]:
    """One property of one subject, from every observation of it.

    Usage-plane observations decide the fact; capabilities are kept beside it. Nothing here
    consults :data:`STRENGTH` to settle a disagreement — that is the rule the whole module exists
    to enforce.
    """
    if not observations:
        raise ValueError("aggregate() needs at least one observation")
    subject = observations[0].subject
    property_name = observations[0].property

    deciding = [item for item in observations if item.decided]
    evidence = tuple(sorted({item.evidence_id for item in deciding}))
    classes = frozenset(item.klass for item in deciding)
    scope = next((item.scope for item in deciding if item.scope), "")

    if not deciding:
        # recorded, shown, and given no vote
        details = ("no observation may decide this; the only evidence is "
                   + ", ".join(sorted({item.klass for item in observations})))
        return (Fact(subject=subject, property=property_name, state=UNKNOWN_STATE, kind=None,
                     value=None, classes=frozenset({INFERRED}), evidence_ids=tuple(
                         sorted({item.evidence_id for item in observations})),
                     scope="", detail=details),
                _refusal("INFERRED_ONLY", subject, property_name, details))

    usage = [item for item in deciding if item.kind in USAGE_KINDS]
    capability = [item for item in deciding if item.kind == CAPABILITY]

    if usage:
        values = {str(item.normalised_value()) for item in usage}
        if len(values) == 1:
            best = max(usage, key=lambda item: item.strength)
            detail = f"{len(usage)} observation(s) agree; strongest class {best.klass}"
            if len(classes) > 1:
                detail = f"corroborated across {len(classes)} classes; strongest {best.klass}"
            if capability:
                extra = sorted({str(item.normalised_value()) for item in capability
                                if str(item.normalised_value()) not in values})
                if extra:
                    detail += (f"; the component also has the capability {', '.join(extra)}, "
                               "which is a capability and not a usage")
            return (Fact(subject=subject, property=property_name, state=FOUND, kind=best.kind,
                         value=best.normalised_value(), classes=classes, evidence_ids=evidence,
                         scope=scope, detail=detail), None)
        conflict = _conflict_kind(property_name, usage)
        sides = _sides(usage)
        detail = (f"{len(values)} values on the usage plane; the {conflict.lower().replace('_', ' ')} "
                  "is preserved with every side and no value is asserted")
        return (Fact(subject=subject, property=property_name, state=CONFLICT, kind=None, value=None,
                     classes=classes, evidence_ids=tuple(sorted({item.evidence_id
                                                                 for item in usage})),
                     scope=scope, conflict=conflict, sides=sides, detail=detail), None)

    # capability only
    values = sorted({str(item.normalised_value()) for item in capability})
    if len(values) == 1:
        best = max(capability, key=lambda item: item.strength)
        return (Fact(subject=subject, property=property_name, state=FOUND, kind=CAPABILITY,
                     value=best.normalised_value(), classes=classes, evidence_ids=evidence,
                     scope=scope,
                     detail="a capability: the component can do this, nothing says it does"),
                None)
    sides = _sides(capability)
    return (Fact(subject=subject, property=property_name, state=FOUND, kind=CAPABILITY, value=None,
                 classes=classes, evidence_ids=evidence, scope=scope, sides=sides,
                 detail=f"the component supports {len(values)} values ({', '.join(values)}); "
                        "capability is plural, so this is a set and not a conflict"), None)


# --------------------------------------------------------------------------- #
# absence
# --------------------------------------------------------------------------- #

def presence(observations: Sequence[Observation], *, subject: str, property_name: str,
             scope: str = "", searched: bool | None = True,
             failure: str | None = None) -> Fact:
    """What "we found nothing" means here.

    ``searched`` says a collector actually looked inside ``scope``; ``failure`` says the look
    raised. Neither is a synonym for "the estate does not have this", and only the first is
    evidence of absence at all. ``searched=None`` means nobody recorded whether anyone looked —
    which is not the same as "nobody could", and not the same as "we looked".
    """
    if observations:
        fact, _refusal_entry = aggregate(observations)
        return fact
    if failure:
        return Fact(subject=subject, property=property_name, state=COLLECTION_FAILED, kind=None,
                    scope=scope,
                    detail=f"collection failed ({failure}); nothing can be concluded about "
                           f"{property_name}")
    if searched is None:
        return Fact(subject=subject, property=property_name, state=UNKNOWN_STATE, kind=None,
                    scope=scope,
                    detail="nothing was recorded about this question: no collector reported "
                           "looking and no scope was declared, so this is a gap and not an "
                           "absence")
    if not searched:
        return Fact(subject=subject, property=property_name, state=NOT_OBSERVABLE, kind=None,
                    scope=scope,
                    detail="no collector reaches this scope, so a missing value says nothing "
                           "about the estate")
    return Fact(subject=subject, property=property_name, state=NOT_FOUND_WITHIN_SCOPE, kind=None,
                scope=scope,
                detail=f"searched {scope or 'the whole scope'} and found nothing; this is absence "
                       "within that scope and not absence in the estate")


# --------------------------------------------------------------------------- #
# derivation
# --------------------------------------------------------------------------- #

def _requested(properties: Mapping[str, Iterable[str]] | Iterable[str] | None,
               observations: Sequence[Observation]) -> dict[str, set[str]]:
    requested: dict[str, set[str]] = {}
    if properties is None:
        return requested
    if isinstance(properties, Mapping):
        for subject, names in properties.items():
            if isinstance(names, str):
                names = [names]
            requested.setdefault(str(subject), set()).update(str(name) for name in names)
    else:
        for observation in observations:
            requested.setdefault(observation.subject, set()).update(
                str(name) for name in properties)
    return requested


def derive(observations: Iterable[Observation],
           properties: Mapping[str, Iterable[str]] | Iterable[str] | None = None,
           scopes: Mapping[str, Mapping[str, Any]] | None = None) -> Derivation:
    """Every fact these observations support, plus every question they cannot answer."""
    items = list(observations)
    grouped: dict[tuple[str, str], list[Observation]] = {}
    for observation in items:
        grouped.setdefault((observation.subject, observation.property), []).append(observation)

    facts: list[Fact] = []
    refusals: list[dict[str, str]] = []
    for (subject, property_name), group in sorted(grouped.items()):
        scope_info = dict((scopes or {}).get(subject) or {})
        fact, refusal = aggregate(group)
        if refusal:
            refusals.append(refusal)
        if (not fact.decided and fact.state != CONFLICT
                and scope_info.get("failure")):
            fact = presence([], subject=subject, property_name=property_name,
                            scope=str(scope_info.get("scope") or ""), searched=False,
                            failure=str(scope_info["failure"]))
            refusals.append(_refusal("COLLECTION_FAILED", subject, property_name, fact.detail))
        facts.append(fact)

    for subject, names in _requested(properties, items).items():
        scope_info = dict((scopes or {}).get(subject) or {})
        for property_name in sorted(names):
            if (subject, property_name) in grouped:
                continue
            fact = presence([], subject=subject, property_name=property_name,
                            scope=str(scope_info.get("scope") or ""),
                            searched=scope_info.get("searched"),
                            failure=scope_info.get("failure"))
            if fact.state == COLLECTION_FAILED:
                refusals.append(_refusal("COLLECTION_FAILED", subject, property_name, fact.detail))
            facts.append(fact)

    return Derivation(facts=tuple(facts), refusals=tuple(refusals))


# --------------------------------------------------------------------------- #
# placement
# --------------------------------------------------------------------------- #

def cap_placement(fact: Fact) -> dict[str, Any]:
    """Where this fact may appear in a BOM, and with what value.

    A conflict carries no value: a BOM that printed one side of a disagreement would have decided
    it, quietly, in the artefact the bank files.
    """
    placement = {
        FOUND: fact.kind,
        CONFLICT: CONFLICT,
        NOT_FOUND_WITHIN_SCOPE: "ABSENCE",
        NOT_OBSERVABLE: "NOT_OBSERVABLE",
        COLLECTION_FAILED: "COLLECTION_FAILED",
        UNKNOWN_STATE: "UNKNOWN",
    }.get(fact.state, "UNKNOWN")
    return {
        "subject": fact.subject,
        "property": fact.property,
        "placement": placement,
        "value": fact.value if fact.state == FOUND and fact.value is not None else None,
        "evidence_ids": list(fact.evidence_ids),
        "class": max(fact.classes, key=lambda klass: STRENGTH.get(klass, 0.0))
        if fact.classes else None,
        "refusal": fact.detail if fact.state != FOUND else "",
    }


def placements(derivation: Derivation) -> list[dict[str, Any]]:
    return [cap_placement(fact) for fact in derivation.facts]


def refused(fact: Fact) -> bool:
    """True when this fact must never be printed as a value in a BOM."""
    return fact.state != FOUND or fact.value is None


__all__ = [
    "ABSENCE_EVIDENCE", "CAPABILITY", "COLLECTION_FAILED", "CONFIGURED", "CONFIGURED_USAGE",
    "CONFLICT", "DECIDING_CLASSES", "DEPENDENCY_VERSION_CONFLICT", "Derivation", "FOUND", "Fact",
    "INFERRED", "IMPORTED", "INVENTORY", "KINDS", "KIND_MEANING", "NETWORK_NEGOTIATED",
    "NETWORK_OBSERVED", "NOT_FOUND_WITHIN_SCOPE", "NOT_OBSERVABLE", "OBSERVATION_CLASSES",
    "Observation", "RUNTIME_OBSERVED", "RUNTIME_STATIC_CONFLICT", "RUNTIME_USAGE", "SCHEMA",
    "STATES", "STATIC_OBSERVED", "STATIC_REFERENCE", "STRENGTH", "UNKNOWN_CLASS", "UNKNOWN_STATE",
    "USAGE_KINDS", "VALUE_CONFLICT", "VENDOR_DECLARED", "aggregate", "cap_placement", "derive",
    "fact_digest", "observation_digest", "placements", "presence", "refused",
]
