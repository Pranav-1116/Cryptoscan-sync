# 26. Bank-negative tests and backend qualification

[Bank guide index](README.md) · [Implementation roadmap](../dev/dependency-intelligence-roadmap.md) ·
[Coverage qualifications](25-coverage-truncation-and-missing-link-qualifications.md)

## Step 10 delivery and its boundary

Step 10 implements bank-specific denial, isolation, immutable-history/replay
and backend semantic tests. These are executable tests and production fixes,
not a documentation-only acceptance promise. The ten implementation stages are
now delivered locally; **whole-bank deployment certification is not implied**.

The new local suites are:

- `services/api/tests/unit/test_bank_dependency_security.py`: actual persisted
  sessions, two banks, a platform operator, database-backed roles, real tenant
  resolution/middleware and SQL queries. Authentication is not overridden.
- `services/graph_engine/tests/test_bank_dependency_qualification.py`: current
  and non-current edges across operational modes, domain-context negatives,
  memory/native-selected-query-double/unified parity, and a no-Bolt tenant gate.
  Six separately marked live Neo4j cases are provided but not run by the local
  non-live gate.

A test double does not parse Cypher, exercise the Neo4j server, or certify a
multi-tenant native deployment. SQLite API tests do not qualify PostgreSQL,
concurrent writers, database privileges, capacity, or customer approval.

## Security gaps found and fixed

### Derived history is not shared platform inventory

The ordinary ORM inventory policy can expose tenant-local plus unattributed
platform inventory. A platform-owned **derived answer**, however, may contain
privileged aggregate data gathered across multiple banks. Sharing that JSON
with every bank is not equivalent to sharing a curated inventory row.

Negative tests created a platform answer containing Bank A data, then requested
it from Bank B through history, replay, or version selection. They also created
platform and bank captures with colliding version numbers. This exposed the
need for explicit exact-estate predicates on:

- Cascade run list/get/diff repository reads.
- Captured twin list/get and cascade replay lookup.
- Graph timeline/compare and graph-snapshot dependency/discovery fallback.
- Watch listing, deletion and run-due selection.

These reads now require `row.tenant_id == current_tenant()`, including the
platform namespace (`NULL`). A bank cannot inherit a platform aggregate merely
because the ORM allows shared platform inventory. Missing/foreign history or
versions return 404. A platform administrator must select a bank explicitly
with its authorized tenant context to inspect that bank's derived history.

This tightens derived-artifact visibility, not ordinary inventory sharing.
Stored JSON is not rewritten, replayed from today's graph, or moved between
owners. No new migration is needed.

### Watch mutations require a writer

Creating/deleting a watch and running due watches change scheduled review state,
baselines and possibly change notifications. They now use the same writer-role
family as dependency annotations: `security_analyst` and `superadmin` (including
the legacy `admin` alias). Authentication and role checks happen before mutation.

Provisioned `readonly`, `auditor`, `supervisor`, `developer`, unknown/custom-empty
and empty-role principals cannot perform these operations. Negative tests assert
403 and unchanged dependency/watch/run/lifecycle-event state. The existing
legacy single-admin authentication policy is not expanded by this step.

Authenticated readers can still inspect their own estate's history, list
watches and run read-only modeled analyses. Such analyses append their own
immutable audit answers; they do not mutate production dependencies. A read-only
user cannot change operational modes, lifecycle state or source ownership.

### Missing baseline is not authority to rebaseline

A watch whose previous run is missing or belongs to another estate now reports
attention required and retains its baseline pointer. It emits no comparison or
removal claim and does not silently establish a new baseline. This extends the
coverage-aware baseline guards introduced in Step 9.

## Negative-test matrix

| Bank scenario | Expected behavior |
|---|---|
| Anonymous or invalid session asks for history or schedules work | 401; no domain mutation |
| Bank member supplies another bank's tenant header | 404; no fallback to global history |
| Suspended bank or ambiguous multi-membership context | 423 / 400; request refused before reading aggregate history |
| Foreign or platform-owned run ID / comparison baseline | 404; no result disclosure or change claim |
| Platform capture version supplied to bank replay | 404; no appended replay run |
| Identical snapshot version exists in platform, Bank A and Bank B | Resolve only within the selected estate |
| Platform graph snapshot is the latest version | Bank timeline/compare/fallback must not import it |
| Bank run-due encounters platform or foreign watches | Do not select, execute, delete or advance them |
| Read-only/provisioned nonwriter manages watches | 403; no watch/run changes |
| Read-only/foreign/platform principal edits Bank A's relationship | 403 / 404; no revision, deadline or lifecycle audit change |
| Foreign failover ID, stale revision, terminal edge or source-owned annotation | 404 / 409; no implicit ownership claim, refresh or revival |
| Caller supplies `tenant_id`, `created_by` or an existing run ID in an unsupported body field | Never honor those claims; server stamps owner/actor and appends a fresh run |
| Reader replays a capture after live mode/limit changes | Captured mode, read metadata and clock remain independent of the live estate |
| Foreign exact target ID | Unresolved selection, no private candidates/names; empty compatibility counts are not safety |

The tests compare domain/audit table state before and after denied writes.
Authentication/security telemetry may legitimately record a refusal; the test
contract does not prohibit such telemetry.

## Backend semantics: parity is narrower than byte equality

The bank fixture includes a mobile channel, payments, ledger, a declared
alternative and an unrelated island. A ledger/payments cycle tests that reverse
reachability can make ledger a consumer rather than supporting-only context.
Different process IDs may have the same display name without being merged.

For UNKNOWN, HARD, OPTIONAL, FAILOVER and ASYNC_BUFFERED declarations, tests
exercise ACTIVE, STALE, UNKNOWN, DELETED, SUPERSEDED, inclusive expiry and
malformed deadline conditions. A mode cannot revive an ineligible edge, make
context relations propagate, turn a pointer into a failover path, or remove a
consumer from modeled exposure. Malformed assertions become unknown, not hard
or safe. No mode implies measured provider disruption.

Shared outputs compared locally include direct/consumer/context memberships,
compact process counts and operational-mode counts. Source evidence is not
rewritten as observation. Inputs and historical results remain unchanged.
Coverage is deliberately different where capabilities differ: native extension
is `NOT_EVALUATED`/null, not a fabricated zero. Such uncertainty is not a parity
failure or discovery certificate.

### Tenant-scoped native access remains deliberately disabled

The public graph facade serves tenant-scoped requests from the ORM-filtered
in-memory graph. It must not probe, read, sync or populate the global Bolt store,
regardless of Bolt health. A driver that fails on any session access pins this
boundary for operational, process, witness and coverage operations too.

This is the supported isolation boundary, **not** a claim that direct
`Neo4jGraphStore` use provides tenant authorization. Do not bypass the facade
and expose a global native store to bank-scoped requests. The standalone/native
qualification below is single-estate semantic testing only.

## Running the local gate

From the repository root, using an environment with the repository requirements:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/api/tests/unit/test_bank_dependency_security.py \
  services/graph_engine/tests/test_bank_dependency_qualification.py
```

The default `not live` selection excludes the six live Neo4j cases. A local pass
must never be recorded as six successful Neo4j executions.

Related regression suites include cascade/twin/graph/software/lifecycle and
operational API tests, graph tenant-isolation tests, database migrations and
cross-tenant adversarial/tenant-resolution/route-auth inventory tests.

Functional cascade fixtures that intentionally override authentication now
supply request credentials when exercising writer routes; that does not weaken
the real-session negative suite. Older provenance and production-worker test
fixtures were aligned with the existing preserved `manual` source and mandatory
immutable scanner-image configuration. No production security validation was
relaxed. Hardware assertions compare exact membership without depending on
randomly generated row-ID ordering.

## Opt-in live Neo4j gate: disposable database only

The live cases require an **exclusive empty disposable database**, not a bank
production database. Supply configuration through the operator's approved
secret mechanism; never put passwords in chat or repository files:

- `CRYPTOSCAN_TEST_NEO4J_DISPOSABLE=1`
- `CRYPTOSCAN_TEST_NEO4J_URI`
- `CRYPTOSCAN_TEST_NEO4J_USER`
- `CRYPTOSCAN_TEST_NEO4J_PASSWORD`
- `CRYPTOSCAN_TEST_NEO4J_DATABASE`

Then explicitly select the live tests:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q -m live \
  services/graph_engine/tests/test_bank_dependency_qualification.py
```

Missing opt-in/configuration fails before connection; a nonempty database fails
before sync or pruning. Fixture entities use random-prefixed exact identities;
cleanup only targets that prefix and never issues a database-wide delete. The
operator must prevent concurrent users of the disposable database.

The live cases compare actual native membership, process counts and mode counts
against memory under optional/buffered/active/stale/terminal/expired conditions.
They do not certify native cross-tenant reads, production performance, actual
failover, queue drain behavior, PostgreSQL transaction isolation or bank controls.

## Acceptance evidence and remaining work

Retain test command, commit, Python/dependency versions, selected/deselected
counts, backend version, disposable database identity and full logs in the bank's
approved evidence location. Do not publish passwords or real customer inventory
in a test report.

Before a deployment claim, the bank still needs live PostgreSQL and Neo4j results,
role/API-key/identity-provider policy review, concurrent-write and operational
load checks, approved migrations, safe backup/restore and bank-owner acceptance.
The local implementation and negative tests are delivered; those external
qualification obligations remain open.


### Local execution record — 2026-10-18

Python 3.11.2; the final scoped regression command covered shared models, CBOM,
graph engine, database, business context, relevant cascade/twin/graph/software/
lifecycle/operational API suites and five tenant/security modules:
**1,845 passed, 1 skipped, 13 deselected** (180.97 seconds). Existing warning
classes remain nonfatal. The new Step 10 modules contribute **103 non-live
cases**; their six live cases are excluded, not passed. No frontend files or
CI workflows changed. Changed Python F/E9 lint and whitespace checks passed.

These results are scoped local regression evidence, not a claim that every
repository test, frontend check, PostgreSQL gate or live Neo4j case ran.
