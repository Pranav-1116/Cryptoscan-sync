"""The canonical State Machine Register — one vocabulary for every state in the
product, observed from code and never invented.

This module is the Python projection of ``state_machines.json`` (the canonical
register, kept beside this file). The TypeScript mirror lives at
``frontend/src/lib/stateMachines.json`` and must stay byte-identical — a test
fails when the two drift.

Why this exists: the product carried dozens of implicit state machines — status
columns written as magic strings, vocabularies duplicated across services, and
honesty rules living only in reviewers' heads. UX, DX and agents all read the
same register now:

- UX  — every console state renders with one tone per semantic class
        (frontend/src/lib/stateMachines.ts ``stateTone``).
- DX  — code imports a machine instead of re-declaring strings;
        ``can_transition`` answers "may this move happen?".
- AX  — agents read the JSON (or run ``python -m shared_models.state_machines``)
        to learn every state a field may hold before touching the product.

Rules the register enforces on itself (and tests enforce on the register):

1. Every state is observed from code — model default, declared tuple, enum,
   model comment or write site. Nothing is invented.
2. ``vocabulary: "partial"`` means the observed vocabulary is a subset;
   ``"unobserved"`` means the field exists but its vocabulary is not yet known.
   Both are honest; guessing is not.
3. unknown is never zero. A failed read is a failure. Absence is never a clean
   result. Capability is never usage. A refusal is counted, never drawn as a
   truth.

CLI:
    python -m shared_models.state_machines list [--domain D]
    python -m shared_models.state_machines show MACHINE_ID
    python -m shared_models.state_machines vocab FIELD
    python -m shared_models.state_machines validate
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

_REGISTER_PATH = Path(__file__).resolve().parent / "state_machines.json"

SCHEMA_VERSION = 1

#: semantic class -> the viz tone word the console renders it with
STATE_CLASSES: dict[str, dict[str, str]] = {}
#: machine id -> machine dict (raw register payload)
MACHINES: dict[str, dict[str, Any]] = {}
#: model field path (e.g. "scan.Scan.status") -> machine id
FIELD_INDEX: dict[str, str] = {}


@dataclass(frozen=True)
class MachineState:
    id: str
    class_: str
    meaning: str


@dataclass(frozen=True)
class Transition:
    from_: str
    to: str
    trigger: str
    observed_in: tuple[str, ...] = ()


@dataclass(frozen=True)
class Machine:
    id: str
    label: str
    domain: str
    kind: str
    description: str
    vocabulary: str
    vocabulary_source: str
    states: tuple[MachineState, ...]
    transitions: tuple[Transition, ...]
    invariants: tuple[str, ...]
    fields: tuple[str, ...]
    sources: tuple[str, ...]
    raw: dict[str, Any] = dc_field(repr=False, compare=False, default_factory=dict)

    @property
    def state_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self.states)

    @property
    def terminal_states(self) -> tuple[str, ...]:
        """States with no outgoing observed transition."""
        out = {t.from_ for t in self.transitions}
        return tuple(s.id for s in self.states if s.id not in out)


def _load() -> dict[str, Any]:
    data = json.loads(_REGISTER_PATH.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"state machine register schema {data.get('schema_version')!r} "
            f"!= supported {SCHEMA_VERSION}"
        )
    return data


def _index() -> None:
    data = _load()
    STATE_CLASSES.clear()
    STATE_CLASSES.update(data["state_classes"])
    MACHINES.clear()
    FIELD_INDEX.clear()
    for m in data["machines"]:
        MACHINES[m["id"]] = m
        for f in m["fields"]:
            if f in FIELD_INDEX:
                raise ValueError(f"field {f} registered on both {FIELD_INDEX[f]} and {m['id']}")
            FIELD_INDEX[f] = m["id"]


_index()


def machine(machine_id: str) -> Machine:
    """Typed view of one machine. Raises KeyError for an unknown id."""
    m = MACHINES[machine_id]
    return Machine(
        id=m["id"],
        label=m["label"],
        domain=m["domain"],
        kind=m["kind"],
        description=m.get("description", ""),
        vocabulary=m["vocabulary"],
        vocabulary_source=m.get("vocabulary_source", ""),
        states=tuple(MachineState(s["id"], s["class"], s.get("meaning", "")) for s in m["states"]),
        transitions=tuple(
            Transition(t["from"], t["to"], t.get("trigger", ""), tuple(t.get("observed_in", ())))
            for t in m["transitions"]
        ),
        invariants=tuple(m.get("invariants", ())),
        fields=tuple(m.get("fields", ())),
        sources=tuple(m.get("sources", ())),
        raw=m,
    )


def states_of(machine_id: str) -> tuple[str, ...]:
    return machine(machine_id).state_ids


def state_class(machine_id: str, state_id: str) -> str | None:
    """Semantic class of a state, or None when the state is not declared."""
    for s in machine(machine_id).states:
        if s.id == state_id:
            return s.class_
    return None


def state_tone(machine_id: str, state_id: str) -> str:
    """The console tone word for one state ('slate' when undeclared — an
    undeclared state must not render as a pass)."""
    cls = state_class(machine_id, state_id)
    return STATE_CLASSES[cls]["tone"] if cls else "slate"


def can_transition(machine_id: str, from_state: str, to_state: str) -> bool:
    """True only for transitions observed in code. Self-loops are not implicit:
    a state with no observed edges stays put by exhaustion, not by an edge."""
    if machine_id not in MACHINES:
        raise KeyError(f"unknown state machine {machine_id!r}")
    return any(
        t.from_ == from_state and t.to == to_state for t in machine(machine_id).transitions
    )


def machines_for_field(field_path: str) -> Machine | None:
    """The machine that owns a model field ('scan.Scan.status'), or None."""
    mid = FIELD_INDEX.get(field_path)
    return machine(mid) if mid else None


def by_domain() -> dict[str, list[Machine]]:
    out: dict[str, list[Machine]] = {}
    for mid in MACHINES:
        m = machine(mid)
        out.setdefault(m.domain, []).append(m)
    return out


def validate() -> list[str]:
    """Self-check: returns a list of problems (empty = valid)."""
    problems: list[str] = []
    for mid, m in MACHINES.items():
        declared = {s["id"] for s in m["states"]}
        if not m["states"] and m["vocabulary"] != "unobserved":
            problems.append(f"{mid}: no states but vocabulary={m['vocabulary']!r}")
        if m["states"] and m["vocabulary"] == "unobserved":
            problems.append(f"{mid}: unobserved vocabulary must carry no states")
        for s in m["states"]:
            if s["class"] not in STATE_CLASSES:
                problems.append(f"{mid}:{s['id']} unknown class {s['class']!r}")
        for t in m["transitions"]:
            if t["from"] not in declared or t["to"] not in declared:
                problems.append(f"{mid}: transition {t['from']}->{t['to']} references undeclared state")
        if m["vocabulary"] not in ("observed", "partial", "unobserved"):
            problems.append(f"{mid}: bad vocabulary {m['vocabulary']!r}")
    return problems


def _main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m shared_models.state_machines")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("list", help="list machines")
    pl.add_argument("--domain", default=None)
    ps = sub.add_parser("show", help="show one machine")
    ps.add_argument("machine_id")
    pv = sub.add_parser("vocab", help="states of one model field")
    pv.add_argument("field")
    sub.add_parser("validate", help="self-check the register")
    args = p.parse_args(argv)

    if args.cmd == "list":
        for mid, m in MACHINES.items():
            if args.domain and m["domain"] != args.domain:
                continue
            n = len(m["states"])
            print(f"{mid:42} {m['domain']:12} {m['vocabulary']:10} {n:3} states  {m['label']}")
    elif args.cmd == "show":
        m = machine(args.machine_id)
        print(f"{m.id} — {m.label} [{m.domain}/{m.kind}, vocabulary={m.vocabulary}]")
        if m.description:
            print(f"  {m.description}")
        for s in m.states:
            print(f"  {s.id:26} class={s.class_:12} {s.meaning}")
        for t in m.transitions:
            print(f"  {t.from_} -> {t.to}: {t.trigger}")
        for inv in m.invariants:
            print(f"  invariant: {inv}")
    elif args.cmd == "vocab":
        m = machines_for_field(args.field)
        if not m:
            print(f"no machine owns field {args.field!r}")
            return 1
        print(f"{args.field} -> {m.id} ({m.vocabulary}): {', '.join(m.state_ids) or '(vocabulary not yet observed)'}")
    elif args.cmd == "validate":
        problems = validate()
        for pr in problems:
            print(pr)
        print("OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
