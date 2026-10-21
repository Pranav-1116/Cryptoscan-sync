# 4.2 — Finding → owner → approved change → rescan → retained proof

Engineering increment, 2026-10-21. The central distinction is explicit:

- **REPORTED_COMPLETE** is an authenticated person's declaration that an action
  happened. It retains the change/ticket reference, actual reported completion
  time and evidence reference. It is not independently verified resolution.
- **VERIFIED** is a machine result about the **explicit approved predicate**,
  derived from durable completed collector observations made after the reported
  change. It does not certify the ticket, whole application or whole bank.
- Missing observations, invalid scope, unfinished/old/future scans, expired or
  changed authority and unavailable source receipts are **INCONCLUSIVE**, not a
  pass. A different actually observed identity is **FAILED**. The source
  comparator also retains PARTIAL/REGRESSION outcomes.

## API and durable lifecycle

All routes are beneath `/api/v1/assurance`, exact-estate, residency-admitted,
bounded metadata routes. A current typed **human session** and durable role are
required for mutations; API keys cannot propose/approve/report/verify. Management
requires `assurance.manage`; independent approval and verification require
`assurance.review`. Review roles include authorized CISO/auditor/business-owner
roles; tenant membership/scope and durable identity are still enforced.

| Route | Meaning |
|---|---|
| `POST /remediation-tasks` | Create assigned task from an exact-owner source finding; body `evidence_id`, `owner_ref`, optional `notes` |
| `POST /remediation-changes` | Propose frozen predicate/owner/change/baseline, starts revision 1 |
| `POST /remediation-changes/{id}/approve` | Different authorized human approves current revision and rationale; becomes APPROVED |
| `POST /remediation-changes/{id}/report-complete` | Record actual action time/reference after approval; becomes REPORTED_COMPLETE |
| `POST /remediation-changes/{id}/revoke` | Append authenticated revocation/reason; retained historical proof does not remain a current grant |
| `POST /remediation-changes/{id}/verify` | Independently compare a newer completed observation; append a condition-proof revision |
| `GET /records/remediation_change/{id}` | Read retained proposal/approval/completion revision history |
| `GET /records/condition_proof/{id}` | Read retained proof revisions, before/after observations, verdict and scope |

Approval/completion use `expected_revision`. Verification binds both the change's
`expected_revision` and `expected_proof_revision` (0 for the first proof). Proof
identity is deterministic per change; subsequent verifications append immutable
revisions. A stale/concurrent proof revision conflicts rather than silently
replacing proof. Read history before retrying an interrupted request.

The approved payload binds the current estate policy ID/revision/contract hash
and stop state. Expiry or a changed policy makes the grant stale. Propose/review
a **new** change rather than editing an approved predicate. Baseline source/
network observations are frozen at proposal; the proof retains copies before
and after, the exact approved change revision/hash and predicate version
`condition/1`. Existing assurance hash/CAS append-only rules apply. Storage
administrator grants, backup and retention controls are still external duties.

## Source-site predicate

A source proposal contains `kind: SOURCE_SITE`, `task_id`, `owner_ref`,
`change_ref`, `verification_criteria`, `expires_at` and `expected_algorithm`.
The task owner must already match the proposed owner. The baseline must have:

- exact-owner task/finding/scan, with the finding snapshot matching retained
  evidence and the same target;
- exactly one completed MANUAL job bound to the scan and target;
- coherent completed job/scan intervals, not future-dated;
- a completed parser receipt for the **original file**, including its SHA256.

Approval accepts a PROPOSED source task; reporting requires an assigned ACCEPTED
task and records completion without inventing a verification. A later rescan
must be a different completed job of the same target, started after the action,
with the original-file receipt and **changed source checksum**. The approved
replacement must be independently observed **once** at the exact original
file/line/purpose with an explicit `PASS` policy outcome. The comparator checks
remaining violations and new non-compliance against the frozen baseline.

This predicate is deliberately narrow: file/line movement, deleted files, no
crypto evidence, missing receipts, unchanged source or unknown policy results
cannot automatically verify. A moved/deleted-site proof needs a separately
reviewed predicate/adapter, not a looser absence heuristic. At most 5,000 findings
per observation are compared; larger scans fail closed and need partitioning,
not silent truncation. Human criteria text is retained context; it is **not an
arbitrary executable policy engine**. Expected algorithm + site/purpose + PASS +
source-change are the current machine predicate, not every sentence in a ticket.

## Certificate example: endpoint plus replacement identity

A TLS proposal uses:

```json
{
  "kind": "TLS_CERTIFICATE",
  "owner_ref": "certificate-operations",
  "change_ref": "approved-change-reference",
  "verification_criteria": "Observe the intended replacement certificate at the exact endpoint",
  "expires_at": "2026-11-01T00:00:00Z",
  "before_run_id": "<actual-owned-network-run-id>",
  "endpoint": "payments.example:443",
  "expected_fingerprint_sha256": "<actual-64-lowercase-hex-replacement-SHA256>"
}
```

The placeholders above are **not valid observations/digests**. Obtain both run
IDs and fingerprints from the actual approved collector history. Verification:

1. Resolves the exact owned `NetworkScanRun` and its collection-linked durable
   completed `NETWORK_SCAN` job; only live `hosts` TLS collection is eligible.
2. Requires exactly one successful probe of the **exact endpoint including
   port**, and the observed leaf certificate SHA256—not a deduplicated inventory
   renewal flag, ticket status or supplier assertion.
3. Requires an independent later job beginning after reported action completion.
4. Preserves the baseline's SNI/certificate-hostname and STARTTLS identity.
   Changing virtual host/protocol is not a like-for-like proof.
5. Compares the observed SHA256 to the approved replacement SHA256, which must
   differ from the baseline fingerprint, and retains both observations.

A certificate `renewal_status=COMPLETED`, a closed ticket, the original run,
another endpoint or another SNI cannot satisfy this predicate. **Only endpoint
replacement identity** is verified; chain trust, expiry policy, revocation,
every load-balancer node and every client path are not silently included.
Controlled production still refuses new live TLS acquisition: this metadata
workflow does not expand the collector allowlist.

## Existing remediation behavior and compatibility

The older comparator's missing-file → VERIFIED bug is fixed. Unknown compliance
is no longer interpreted as PASS, and an unidentified/moved original line cannot
be inferred resolved. Explicit rescan IDs now require completed, coherent,
newer-than-action evidence just like automatic selection. Unaccepted PROPOSED
tasks cannot be marked complete through the old route.

The legacy `/remediation` lifecycle remains available outside the controlled
surface, but a favorable comparison without an approved condition is now a
candidate improvement / INCONCLUSIVE. It cannot independently promote a new
fix to VERIFIED. Existing historical labels are not rewritten on upgrade; read
the original proof and scope and use the approved workflow for new acceptance.
The Operator decisions page links to both task history and retained predicates.

## Negative acceptance evidence

Automated synthetic SQL/auth tests cover report≠proof, old runs, wrong replacement,
foreign estate, endpoint mismatch, failed job, changed SNI, missing probes,
expired/policy-changed approval, self-approval, denied reader, exact site and
changed source content. They demonstrate engineering invariants, **not customer
fix acceptance or an externally witnessed certificate rotation**.

### Freshness and superseded task conditions

Each proposal also binds `freshness_seconds` (default 3,600, permitted 60–604,800).
A proof cannot renew freshness simply by re-running verification: age is measured
from **collector completion**, not when someone pressed Verify. An old observation
requires a new collection. The inbox separately derives current predicate validity
and expiry; a historically VERIFIED task can therefore need attention again.

Approving another source change appends an immutable active assignment for that
task. A superseded change cannot verify or downgrade the newer assigned task.
The old predicate/proofs remain auditable. Current task/proof state is batched
from exact-estate assignments/changes/proofs rather than trusting the legacy task
label or a ticket's completion state.

An authorized reviewer may explicitly revoke a proposed/approved/reported change
with its expected revision, evidence reference and reason. The old proof remains
a historical observation; the inbox immediately marks its current authority as
stale/unavailable and the revoked change cannot be verified or completed again.
