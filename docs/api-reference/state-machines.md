# State machine register — developer and agent reference

**Status:** supported surface. **Source of truth:**
[`shared/shared_models/shared_models/state_machines.json`](../../shared/shared_models/shared_models/state_machines.json)
(the canonical register) — this page explains the interfaces; the JSON is the
data. Console surface: [`/state-machines`](../state-machines/README.md).

The register is the product's one state vocabulary: **97 machines, 294 states,
91 `db.models` status fields**, every state observed from code (model default,
declared tuple, enum, model comment or write site) and never invented. It is
consumed three ways — the console draws its tones, Python and TypeScript code
resolve machines and transitions, and agents read the JSON or run the CLI.

## Files

| File | Role |
|---|---|
| `shared/shared_models/shared_models/state_machines.json` | canonical register (schema version 1) |
| `shared/shared_models/shared_models/state_machines.py` | Python projection + CLI |
| `frontend/src/lib/stateMachines.json` | console mirror — **must stay byte-identical** to the canonical file (pinned by test) |
| `frontend/src/lib/stateMachines.ts` | TypeScript projection |
| `frontend/src/pages/StateMachines.tsx` | console explorer page (`/state-machines`) |
| `docs/state-machines/README.md` | full inventory tables and the rules |
| `shared/shared_models/tests/test_state_machines.py` | drift guards (see below) |

## Register shape (schema_version 1)

```json
{
  "schema_version": 1,
  "register": "cryptoscan-state-machines",
  "principles": ["…honesty rules…"],
  "state_classes": {
    "progress":  { "tone": "accent", "meaning": "In flight…" },
    "done":      { "tone": "green",  "meaning": "…" },
    "unknown":   { "tone": "slate",  "meaning": "NEVER zero, never clean…" }
  },
  "machines": [
    {
      "id": "scan.status", "label": "Scan lifecycle",
      "domain": "collection", "kind": "lifecycle",
      "fields": ["scan.Scan.status"],
      "vocabulary": "observed",
      "vocabulary_source": "tuple SCAN_STATUSES + CheckConstraint + Scan methods",
      "states":    [{ "id": "QUEUED", "class": "progress", "meaning": "…" }],
      "transitions": [{ "from": "QUEUED", "to": "RUNNING", "trigger": "…", "observed_in": ["…"] }],
      "invariants": ["…"],
      "sources": ["services/database/db/models/scan.py"]
    }
  ]
}
```

- `vocabulary` is one of `observed` (complete), `partial` (observed subset), or
  `unobserved` (the field exists; its vocabulary is not yet known — such
  machines carry **no states**, on purpose).
- `state_classes` are the 11 semantic classes; each carries one console tone, so
  the same state looks the same on every page. An undeclared state always
  resolves to slate — never a pass.
- `transitions` list only moves **observed in code**; a state with no observed
  edges stays put by exhaustion, not by an implicit self-loop.

## Python API

```python
from shared_models.state_machines import (
    MACHINES, STATE_CLASSES, machine, machines_for_field,
    states_of, state_class, state_tone, can_transition, by_domain, validate,
)

machine("scan.status").state_ids      # ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')
can_transition("scan.status", "QUEUED", "RUNNING")            # True — observed in Scan.start
can_transition("binary.usage_status", "capability_only", "runtime_confirmed")  # False — capability never promotes to usage
state_tone("scan.status", "FAILED")   # 'red' — the failure class tone
state_tone("scan.status", "NOPE")     # 'slate' — an undeclared state never renders as a pass
machines_for_field("scan.Scan.status")  # the machine that owns a model field
validate()                            # [] when clean
```

Module import needs `shared/shared_models` on `PYTHONPATH`.

## CLI (agents)

```
python -m shared_models.state_machines list [--domain collection]
python -m shared_models.state_machines show binary.usage_status
python -m shared_models.state_machines vocab scan.Scan.status
python -m shared_models.state_machines validate
```

## TypeScript API (console)

```ts
import { machine, statesOf, stateClass, stateTone, canTransition,
         machineForField, machinesByDomain } from "../lib/stateMachines";

stateTone("ui.performance_tile", "unknown")  // "slate" — unknown tiles never render 0
```

## Drift guards

`shared/shared_models/tests/test_state_machines.py` fails when:

- a status-bearing column in `services/database/db/models` is not registered
  (columns are discovered by AST — adding a column forces a register update);
- a registered field no longer exists, or a column's declared default is not
  one of its machine's states;
- a declared tuple (`SCAN_STATUSES`, `FINDING_STATES`, `TICKET_STATES`, …) or
  enum (`UsageStatus`, `EvidenceClass`) drifts from the register's states;
- the two JSON copies differ by one byte;
- capability gains any edge into usage, or an `unobserved` machine grows
  invented states.

## Honesty rules the register carries

unknown is never zero · a failed read is a failure and never prints zeros ·
absence is never a clean result · capability is never usage · a refusal is
counted, never drawn as a truth · NOT_CONFIGURED ≠ UNKNOWN. These ride on each
machine as `invariants[]` and are rendered on `/state-machines`.

This page is documentation of the current repository, not a product promise or
an external assurance claim.
