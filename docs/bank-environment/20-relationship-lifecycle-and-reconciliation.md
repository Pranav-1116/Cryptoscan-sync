# 20. Relationship expiry, retained tombstones and safe reconciliation

[Guide index](README.md) · [Release identity](19-package-artifact-deployment-identity.md) ·
[Engineering plan](../dev/dependency-intelligence-roadmap.md)

## 1. What step 4 implements

An immutable package identity is different from a time-dependent assertion that
its release is deployed. Likewise, a historically declared system dependency is
not necessarily eligible for today's modeled traversal. This implementation
adds lifecycle metadata to **SystemDependency, ReleaseSbomBinding and
SoftwareDeployment**, not to content-addressed SoftwareArtifact identities.

Migration **0099**, following 0098, adds:

- persisted ACTIVE, STALE, DELETED and SUPERSEDED states; effective EXPIRED is
  calculated at the evaluation clock from `valid_until`;
- source ownership, a revision, validity deadline, last confirmation, reason,
  evidence reference and reconciliation receipt ID;
- exact-estate, source/kind-partitioned monotonic collection receipts;
- an application-append-only transition journal containing before/after
  lifecycle metadata, retained relationship identity, actor and evidence;
- graph snapshot policy and evaluation-clock fields.

A recently confirmed **declaration is still a declaration**. Neither a valid
expiry deadline nor a successful collector run establishes runtime use, actual
application failure, remediation, or a complete inventory. There is no new
availability simulator or automatically trusted collector integration.

## 2. Eligibility and uncertainty

`cryptoscan.system-dependency-policy/2` retains step 2's consumer → provider
relation meanings and 12-hop bound, but additionally requires current eligibility.
The lifecycle contract is `cryptoscan.relationship-lifecycle/1`.

| State/effective condition | Active traversal | Separate potential reachability | Evidence retained |
|---|---|---|---|
| ACTIVE, no deadline or before deadline | Yes, if relation propagates | Already active, not double-counted | Yes |
| STALE | No | Yes, through nonterminal links | Yes |
| Deadline reached, including exact equality | No: EXPIRED | Yes | Yes |
| Unknown state or malformed deadline | No: UNKNOWN | Yes, conservatively | Yes |
| DELETED | No | No propagation through this tombstone | Yes |
| SUPERSEDED | No | No propagation through this historical assertion | Yes |

Expiry is evaluated **as of the answer's clock**, not by rewriting the stored
record. A background sweeper is not required. A persisted STALE row whose
deadline has elapsed is effectively EXPIRED; its stored stale reason remains.
Terminal states take precedence over expiry. Unknown/corrupt states fail closed.

Legacy rows migrate to ACTIVE / `manual` / revision 0 with **no invented
confirmation time or deadline**. They remain eligible for modeled compatibility,
but are explicitly reported as unbounded, not verified fresh. There is no default
TTL, automatic aging of every old import, or implicit collector adoption. Choose
source-specific deadlines and ownership under an approved bank policy.

The unified cascade keeps existing **active** direct / consumer / context
buckets and adds:

- `relationship_lifecycle`: counts, evaluation clock, unbounded-active count,
  excluded evidence (first 200, with an explicit truncation flag);
- `impact.lifecycle_uncertainty`: possible additional systems and directional
  reachability through nonterminal uncertain links, separate from active scope;
- retained software bindings/deployments with effective state, uncertain systems
  and terminal historical systems.

Example: mobile → payments → ledger; only payments has the selected release.
An active binding/deployment yields direct 1, consumer 1, context 1. Marking the
payments deployment STALE yields **active scope 0**, but the potential additional
systems remain mobile, payments and ledger. It does **not** yield an all-clear.
A deleted package-to-release binding does not seed current or potential package
exposure through that assertion; the package, binding and deployment evidence
remain reviewable. Independent active assertions can still establish exposure.
Potential reachability is bounded by the requested propagation depth; it is not
an exhaustive bank-wide outage prediction.

## 3. Lifecycle API and authorization

The lifecycle prefix is `/api/v1/relationship-lifecycle`. `kind` is one of
`system_dependency`, `sbom_binding`, `deployment`; use returned record IDs.
Sources are stable, case-sensitive URL-segment identifiers (letters/digits and
`_ . : -`, up to 120 characters), for example `bank-a.payments.prod`.
`manual` is reserved and cannot be reconciled as a collector stream.

| Operation | Endpoint |
|---|---|
| Inspect current row and effective state | GET /api/v1/relationship-lifecycle/{kind}/{id} |
| Inspect retained transition events | GET /api/v1/relationship-lifecycle/{kind}/{id}/events |
| Explicit audited state change | POST /api/v1/relationship-lifecycle/{kind}/{id}/state |
| Explicit source ownership transfer | POST /api/v1/relationship-lifecycle/{kind}/{id}/claim |
| Record/execute one collection | POST /api/v1/relationship-lifecycle/{kind}/sources/{source_id}/collections |
| Inspect collection receipts and last sequence | GET /api/v1/relationship-lifecycle/{kind}/sources/{source_id}/collections |

Reads require an authenticated selected-estate user. Mutations require admin,
superadmin or security_analyst under the existing role catalog. Exact tenant AND
scope are checked, including platform requests. System dependencies also require
both endpoints to belong to that exact estate. This is not a claim that all
older graph APIs have been qualified for bank isolation; step 10 remains open.

State requests forbid extra fields, require an expected revision, reason and
nonblank evidence reference. API timestamps require explicit timezone offsets and are normalized to UTC before
persistence, including SQLite stores that do not retain offsets.
For example, after reading a deployment's current revision, an approved operator
can submit the following body to its `/state` endpoint:

```json
{
  "expected_revision": 3,
  "state": "SUPERSEDED",
  "reason": "Approved rollout replaced this declared deployment revision",
  "evidence_ref": "change/BANK-456"
}
```

This changes only lifecycle metadata: the immutable artifact ID, system,
environment, deployment revision key and original evidence are not replaced.
Creating a new rollout revision remains a separate step-3 registration.
Reactivation is an explicit audited ACTIVE change with the current revision.
For an expired row, renew `valid_until` or **explicitly** set it to null; silently
retaining an already elapsed deadline does not reactivate it (409).

### Source ownership is an explicit decision

A collector cannot adopt records by mentioning their IDs. First inspect and
approve the source transfer, then POST a claim such as:

```json
{
  "expected_revision": 0,
  "expected_source": "manual",
  "source_id": "bank-a.payments.prod",
  "reason": "Approved ownership of these deployment assertions by the production reconciler",
  "evidence_ref": "control/DEPLOYMENT-SOURCE-17"
}
```

Claiming changes ownership/revision and records an event; it does **not** make the
record newly confirmed, clear expiry, or reactivate a tombstone. A different
source transfer also requires matching previous ownership and revision.

### Graph-edge deletion is now a tombstone operation

GET /api/v1/graph/edges now includes the row ID, revision and lifecycle metadata.
POST /api/v1/graph/edges requires a writer role and accepts an optional aware
`valid_until`. DELETE /api/v1/graph/edges/{parent_id}/{child_id} now requires query
parameters `expected_revision`, `reason`, `evidence_ref`. It retains the SQL row
and transition event, returning `deleted: true, retained: true`. It no longer
means physical deletion. Repeating an obsolete revision returns 409.

The console's dependency-edge manager requires an approved reason/reference,
sends the row revision, displays retained state and calls the action **retire**.
Older clients must migrate; silently supplying a guessed revision is unsafe.
Re-registering the same pair cannot resurrect its tombstone. Existing worker
`add_dependency` retries return the existing record without reactivating it.

## 4. Complete, partial and failed collections

Each stream is isolated by **estate + kind + source**. Use a unique collection key
and monotonically increasing positive sequence. A collection only confirms IDs
already owned by that source; it does not create relationships or assert measured
runtime deployment. Confirmation requires each row's current revision.

Illustrative request-building Python below uses a row returned by `/claim`.
Select deadlines, clocks, keys and sequence from the approved source control;
these values are examples, not a production freshness policy.

```python
from datetime import datetime, timedelta, timezone

def build_collection(claimed_row, sequence, collection_key, evidence_ref):
    observed_at = datetime.now(timezone.utc)
    return {
        "collection_key": collection_key,
        "sequence": sequence,
        "outcome": "COMPLETE",
        "observed_at": observed_at.isoformat(),
        "reported_count": 1,
        "truncated": False,
        "observed": [{
            "id": claimed_row["id"],
            "expected_revision": claimed_row["lifecycle_revision"],
            "valid_until": (observed_at + timedelta(hours=1)).isoformat(),
        }],
        "evidence_ref": evidence_ref,
    }
```

| Outcome | Confirm listed owned records | Infer anything from missing records |
|---|---|---|
| COMPLETE | Yes, except terminal tombstones | Owned ACTIVE rows missing from the complete enumeration become STALE, never deleted |
| PARTIAL | Yes, except terminal tombstones | **No** |
| FAILED | No; observed list must be empty | **No** |

COMPLETE requires explicit `truncated: false` and an exact reported count.
Truncation defaults to true. Duplicate IDs, reported-count inconsistencies and
FAILED batches containing observations are rejected. No silent bounded prefix
is treated as a complete inventory. A complete source is capped at 5,000 owned
rows; larger sources must be explicitly partitioned before reconciliation.
Observed lists are also capped at 5,000. Collection-key hashes normalize object
keys, timestamp instants and observed-ID ordering; changing the payload under an existing key is 409.

An identical retry returns the original immutable receipt without new events or
revision increments. Reordered observed IDs are equivalent. A new key with an
old/equal sequence is rejected. A higher sequence cannot overwrite a later
confirmation with an older observation clock. Clocks over five minutes into the
future are rejected; this is a sanity bound, not source attestation.

All source sequence changes, relationship compare-and-swap updates, events and
the receipt commit in one SQL transaction. A later record conflict rolls back the
whole batch, including earlier confirmations. Concurrent source initialization
or unique-key races return 409 for inspection/retry. Terminal records are named
in the receipt and are never automatically reactivated. Confirmations may renew
a deadline; removing one requires the explicit operator state API.

A FAILED receipt records the attempted source sequence and evidence; it is not a
successful observation. An invalid/rejected HTTP request rolls back and does not
silently create a FAILED receipt on the caller's behalf. Receipt/event inspection
is bounded and reports total/truncation; events survive independently of the row
identity. These journals are application-append-only, **not** cryptographic
signatures or tamper-proof storage against privileged SQL administrators.

## 5. Backends, history and replay

Memory and native query contracts filter lifecycle eligibility in both
directions, shortest paths, dependency cycles and the system prefix of vendor
paths. SQL → twin, graph payload, memory export/import, native writes and native
exports preserve lifecycle fields and relationship record identity. The native
predicate binds an epoch evaluation clock; malformed validity cannot become an
unbounded active relationship.

Before serving a populated native graph, the facade refreshes known SQL-backed
relationship eligibility and its system nodes. A failed eligibility refresh
fails the request rather than serving an older active answer. Revision guards
prevent an older projection from overwriting a newer tombstone. This refresh is
not full inventory reconciliation or a large-estate performance qualification.

Unstamped legacy CALLS projections with a parallel managed relationship are
retained but quarantined as uncertain (`projection_state: STALE`), so a duplicate
old transport row cannot resurrect a newly retired SQL relationship. Other
unmanaged legacy relationships retain explicitly unbounded compatibility until
reviewed; they are not silently claimed as a collector's observed evidence.

Graph sync never absence-prunes System nodes, which would detach-delete the
relationship history. Other node-kind maintenance pruning requires an explicit
COMPLETE/nontruncated collection attestation. Unknown, partial, failed and
truncated inputs skip destructive pruning. The API's bounded multi-source graph
payload does **not** make that attestation. A mid-sync error occurs before prune;
previous writes may remain, but no collection gap authorizes destructive cleanup.

Graph snapshots fingerprint lifecycle and effective eligibility, not just edge
presence, and record policy/clock. Comparisons expose lifecycle changes even
when no structural edge disappears; unknown/different policy versions are not
count-comparable. Stored old snapshots and cascade answers are not rewritten.

For POST /api/v1/technology-bom/cascade with a captured `version` query parameter:

- default evaluation uses the snapshot's **capture clock**, under the named
  current policy; it is a new evaluation, not a claim to reproduce an older
  algorithm byte-for-byte;
- optional aware `as_of` in the request body explicitly reevaluates the captured
  evidence at another clock and labels that choice in `replayed_over`;
- `as_of` without a captured version is rejected; an absent capture clock needs
  an explicit clock rather than a silent guess;
- saved historical runs remain unchanged and retain their original results.

Snapshots are not an operational time series between captures. An old ACTIVE
assertion before expiry is evidence of what was declared then, not proof that it
was actually running. The UI prominently warns when old answers lack lifecycle
metadata and keeps potential uncertain systems separate from active counts.

## 6. Rollout and qualification boundaries

Back up/export evidence and test the migration on the bank's approved database:

```bash
python -m alembic -c services/database/migrations/alembic.ini upgrade head
```

Do not deploy this code against an unmigrated schema. Downgrading 0099 removes
lifecycle fields, receipts, events and graph policy/clock metadata. The original
relationship rows remain, but lifecycle evidence is lost: an approved export and
rollback plan are required, not a claim of safe automatic downgrade.

Local checks exercise real SQLite migration upgrades/downgrades, real HTTP + SQL
lifecycles, source isolation, transaction rollback, complete/partial/failed
batches, clock/replay behavior, legacy/tombstone handling, native query-text
contracts, FakeDriver parity, and actual two-bank/platform authentication and
negative cases. The frontend tests/typecheck/build also cover warnings and
revision/evidence-gated retirement. Exact recorded counts are in the engineering
plan's step-4 delivery section.

**Live PostgreSQL concurrent transaction qualification and real Neo4j execution
remain unverified.** FakeDriver does not parse or execute Cypher. There is no
large-estate/load benchmark, collector scheduler, automatic TTL policy, external
source signature verification, replacement-target validation for SUPERSEDED,
or complete operational dependency-mode model.
[Step 5](21-traversal-provenance-evidence-and-freshness.md) subsequently implements
bounded provenance/freshness witnesses, with explicit missing references and
legacy seed gaps rather than a universal all-paths claim. Steps 6–10 remain
pending; this stage does not certify the whole
platform's bank authorization, historical isolation or production readiness.

Implementation references:

- [Lifecycle policy](../../shared/shared_models/shared_models/relationship_lifecycle.py)
- [Lifecycle API](../../services/api/api/routers/relationship_lifecycle.py)
- [Migration 0099](../../services/database/migrations/versions/0099_relationship_lifecycle.py)
- [API/SQL regressions](../../services/api/tests/unit/test_relationship_lifecycle_api.py)
- [Backend lifecycle regressions](../../services/graph_engine/tests/test_relationship_lifecycle.py)
