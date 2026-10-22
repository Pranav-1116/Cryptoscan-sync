# Evidence assurance upgrade and published quality-source handoff

## Current quality-source handoff (2fd8fc8f)

**Published source:** `2fd8fc8fba255333f605202ebb68d04c4029c610`, current PR branch,
2026-10-22. The three quality increments are pushed, not merely proposed. See the
[publication ledger](../product-improvement/IMPLEMENTATION-STATUS.md#published-engineering-snapshot)
for actual local checks and the remaining review/site boundary.

This source change adds **no migration**; its release contract remains head
**0105**. The 0103 foundation sequence later in this document is historical and
must not be mistaken for the complete current upgrade target. Use the
[current operator upgrade/recovery procedure](operator-install-upgrade-recover.md)
and [on-premises guide](../BANK-ON-PREMISES-DEPLOYMENT.md) for the exact reviewed
0105 package, coordinated images, backups and guarded event-history downgrade.
Do not use a Git commit SHA as an image digest or skip external package signing.

### Changed behavior to include in the bank's staging/change checklist

| Current behavior | Operator response | Do not do |
|---|---|---|
| Source coverage/read-dependent operator summary returns 409 when eligible backing parser/file/hash/job/scan proof is invalid or missing | Inspect retained history, current target/estate and actual SQL proof; obtain a new authorized eligible observation where needed | Keep old green counts, patch receipts, reset job states or infer a successful empty collection |
| Known variable/wildcard/interval package versions remain unresolved; legacy PACKAGE_CRYPTO review can refuse with 409 and current trace has no eligible path | Obtain an actual resolved build/SBOM and separately reviewed exact package mapping | Guess from package names, edit old SBOM rows or rewrite historical approvals/counts |
| Role storage unavailable returns 503; disabled/deleted or missing production identities refuse privileged role lookup with 403 | Restore authorized dependency access or correct current durable account/session/membership under the bank's identity process | Fall back to stale token roles, create implicit production admins or bypass scope |
| Dependency health remains down/degraded; readiness remains 503 on failure; safe category replaces raw exception details | Use status/down/error category and approved restricted diagnostics; liveness alone does not establish readiness | Request connection passwords, raw SQL or unredacted exception/traceback dumps in public logs or support tickets |
| Old offline supplier qualifications no longer match the package-validation engine fingerprint | Actually re-exercise the approved exact offline profile and retain its result/review | Patch qualification hashes, call NOT_QUALIFIED a pass or infer live vendor support |
| New frontend entrypoint/CSP no longer requests/allows known remote Google Fonts bootstrap assets | Build the reviewed new image, verify its digest/approved CSP and actual browser network/fallback-font behavior | Assume an old installed image changed or claim whole-application zero egress from source inspection |

Original documents, raw stored projections, snapshots and reviewed history remain
unchanged. Current derived views re-evaluate eligibility; historical stored counts
are not a substitute for current proof. Partial primary-source observation still
does not establish complete source, deployment, invocation or whole-bank coverage.

Before rollout, stage the coordinated signed package and check both allowed and
refused cases. Preserve the existing exact-condition remediation predicate and
current authority. Source publication performs no bank installation or automatic
update. Independent review, actual PostgreSQL/browser/fault/restore/operator
exercises and customer acceptance remain open; the disposable-PostgreSQL local
fixture skip is not a passed site exercise.

## Original foundation support boundary


This increment implements durable partial progress, registered denominators,
reviewed six-BOM assertions, immutable customer-review workflows, contextual
assessments, verified Redis consumer routing, and a **bounded offline export**
qualification/quarantine workflow. It does **not** manufacture customer samples,
owner sign-off, live vendor qualification, infrastructure acceptance or a new
production-readiness PASS.

The controlled deployment still executes only `local-source/v1`. The new
`/api/v1/assurance/*` surface is evidence metadata, bounded quarantine storage,
review and bounded JSON contract validation—not permission to launch a live
vendor connector, SSH collector, remote fetch, archive/XML parser, shell command,
background job or privileged import. The existing controlled-surface refusal of
unqualified acquisition APIs remains. Development SSH uses the new receipts;
that does not make SSH a qualified production execution profile.

## Original foundation upgrade order (0103)

The sequence below describes the original receipt/assurance-table introduction.
It is retained for provenance and compatibility review, **not** permission to stop
an installation of `2fd8fc8f` at 0103. Its later release requirements include 0104
and 0105 under the current operator procedure; this documentation does not run
migrations or authorize destructive downgrade.

1. Back up and rehearse restore of the exact regional SQL estate. Quiesce API
   writes and drain synchronous collectors before migration. An old collector
   cannot safely continue across a receipt schema change.
2. Run the normal deployment Alembic command to upgrade through **0103**.
   Migration 0102 and its fresh-sign-in requirement still apply. 0103 adds
   `assurance_revisions`, `assurance_blobs`, `collection_phase_receipts`; it does
   not invent progress for old jobs, tenant ownership, trust grants or approvals.
3. Rebuild/redeploy the API, worker and approved digest-pinned parser image
   together. The parser now emits bounded source-file byte receipts. Older scans
   remain historical observations but **cannot establish byte-bound negatives,
   held-out accuracy or executed regression results**; recollect those samples.
4. Provision the selected estate's existing execution/evidence-region policy.
   All new endpoints check declared SQL residency, including reads and writes
   during a stop. Physical routing, TLS, encrypted SQL/storage/backups, retention,
   capacity, replica locations and ingress residency still require provider
   controls and external qualification. This API does not certify those controls.
5. Restrict UPDATE/DELETE privileges on revision/blob history at the database
   service-role boundary. The application has no edit/delete API and rejects ORM
   edits/deletes; DB administrators and bulk SQL remain outside that guard.
   Hash links detect ordinary changes, not an administrator rewriting an entire
   unanchored chain. Retain externally anchored exports/backups and an audited
   retention process. Downgrade drops the three new tables: export/review before
   rollback; never treat downgrade as a retention solution.
6. Apply Redis configuration below, roll pools/processes for credential or trust
   rotation, then run the approved topology's fault exercises and separate review.
7. Register expected targets and an honest register-completeness assertion before
   interpreting coverage. Collect fresh samples, nominate the **durable user ID**
   of an active, entitled domain reviewer, and keep review separate from proposal.

## Authority and data handling

Writes require a current typed human session, the immutable original session-user
ID from 0102, current durable account roles and an authorized selected estate.
API keys cannot approve, upload or mutate these workflows. The server chooses
owner, actor, subject IDs on creation, revision hashes and review timestamps.

| Permission | Roles | Use |
|---|---|---|
| `assurance.manage` | superadmin, CISO, security analyst | Registers, observations, sample proposals, quarantine intake, manifest declarations, repeat/regression receipts |
| `assurance.review` | superadmin, CISO, auditor, business owner | Relationship/supplier review, contextual assessment; sample review additionally requires its nominated domain-owner user ID |
| `assurance.trust` | superadmin, CISO | Signer trust, Redis objectives |
| `assurance.raw` | superadmin, CISO | Download raw quarantine/fixture bytes, with a current human session |

An administrator without `X-Tenant-ID` sees **only platform/NULL records**, not
all banks. A selected tenant is membership/administrative-authority validated.
References to other tenants or the platform estate are not adopted by name.
There is no implicit sharing of NULL evidence.

All new requests have a **2 MiB wire cap**, including chunked requests. JSON
rejects duplicate keys, nonfinite constants and nesting deeper than 24 before
Pydantic contract validation. Raw blobs are limited to **1 MiB**. Raw uploads are
opaque and untrusted; only a separately reviewed, correctly signed, exact-build
supplier envelope can enter the bounded offline JSON lane. No XML/archive/code
execution is offered. Raw downloads use attachment/octet-stream, `nosniff`,
`no-store`, and a privileged human role. Apply regional encryption, storage quotas,
network rate limits and retention externally. Supply approved, redacted accuracy
fixtures; do not upload real private keys or credentials as test cases.

## Redis configuration

All eight roles use `shared_models.redis_connection`:
`realtime`, `current_run`, `queue`, `rate_limit`, `health`, `platform_state`,
`sso_state`, `telecom`. API and worker inherit `REDIS_URL`, `REDIS_CA_CERTS`,
`REDIS_SENTINELS`, `REDIS_SENTINEL_MASTER`, `REDIS_SENTINEL_USERNAME`,
`REDIS_SENTINEL_PASSWORD`. Production requires verified `rediss`, hostname
checking and a named non-default ACL user. Sentinel also requires three distinct
TLS discovery endpoints, a service name and dedicated discovery credentials.
**Production URL query overrides are now refused**, including apparently safe
or duplicate TLS options: move trust/routing into explicit settings.

A role can be separated using `CRYPTOSCAN_REDIS_<ROLE>_URL` and the corresponding
`_CA_CERTS`, `_SENTINELS`, `_SENTINEL_MASTER`, `_SENTINEL_USERNAME`,
`_SENTINEL_PASSWORD`. For example, `<ROLE>` is `QUEUE` or `RATE_LIMIT`.
A dedicated URL resets inherited Sentinel discovery/master credentials; configure
that dedicated topology explicitly, rather than accidentally rediscovering the
base deployment. Base production Redis remains required by startup policy.
Never put connection secrets in review records, CLI arguments, screenshots or Git.

Platform/SAML cached clients notice configuration/credential/discovery and CA-file
metadata changes; other long-lived pools require a controlled process roll. A
successful new connection is not proof that an old credential/root was revoked.
Production queue, limiter and shared-state paths retain fail-closed behavior;
there is no new production memory fallback. Health PING proves reachability only.

## Practical workflow map

Every POST/PUT response includes a server-generated `subject_id`. Use that exact
ID on subsequent requests. Revisions start at 1; edits/reviews carry the current
`expected_revision`. Stale/conflicting writes return 409 rather than overwrite.

| Section | Start here | Review / consumption |
|---|---|---|
| 3.1 | Existing admitted development SSH scan | `GET /assurance/collections/{job_id}`; durable job progress and successful SSH result also carry independent conclusions |
| 3.2 | `POST /assurance/redis-objectives` | Measurements → separate `/redis-measurements/{id}/review` → `/redis-objectives/{id}/qualification` |
| 3.3 | `POST /assurance/registers` | `PUT /registers/{id}/observations/{target_id}`, `GET /registers/{id}/coverage` |
| 3.4 | Existing artifact/SBOM/deployment registration; `POST /assurance/relationships` | Separate `/relationships/{id}/approve`; `GET /applications/{system_id}/trace` |
| 3.5 | Raw approved fixture blobs; `POST /assurance/samples` | Domain-owner approval → workbook → immutable first-pass review → seeds → new repeat scan → held-out review |
| 3.6 | `POST /assurance/findings/{evidence_id}/assessments` | New revision changes contextual recommendation, never original evidence |
| 3.7 | Signer trust → signed supplier quarantine → separate approval → exact adapter manifest | Execute seven qualification cases; consume only via qualified `/adapters/{id}/supplier-evidence/{evidence_id}/observations` |

Paths in this table after `/assurance` are relative to `/api/v1/assurance`.
`GET /assurance/records?kind=...&limit=100&offset=0` lists bounded history;
`GET /assurance/records/{kind}/{subject_id}?after_revision=0` reads revisions.
These are historical assertions, not a substitute for a current qualification
check. `GET /assurance/evidence-blobs/{blob_id}/content` is raw, privileged access.
The generated [REST reference](../api-reference/rest-api.md) describes all schemas.

## Seven detailed implementation/acceptance notes

- [3.1 Partial-progress receipts](../bank-environment/46-partial-progress-evidence.md)
- [3.2 Infrastructure qualification](../bank-environment/47-redis-consumer-and-recovery-evidence.md)
- [3.3 Expected-estate ledger](../bank-environment/48-expected-estate-coverage-ledger.md)
- [3.4 Six-BOM evidence relationships](../bank-environment/49-six-bom-evidence-paths.md)
- [3.5 Customer-reviewed accuracy](../bank-environment/50-customer-reviewed-accuracy-workflow.md)
- [3.6 Purpose/applicability](../bank-environment/51-purpose-and-applicability-assessments.md)
- [3.7 Qualified adapters/quarantine](../bank-environment/52-qualified-adapters-and-supplier-quarantine.md)

## Remaining acceptance, not hidden workarounds

Actual bank target-register completeness, representative source classes, reviewed
TP/FP/misses, externally approved regression fixture retention, held-out repeat,
firmware/runtime/deployment identities, supplier due diligence, named vendor live
profiles, PostgreSQL concurrency/restore, encrypted/quota-controlled regional
storage and deployed Redis rotation/partitions/lag/disk/memory/kill/power-loss/
backup/restore/failback/load objectives require supplied environments and separate
reviewers. Local tests, this metadata workflow and the portable observer do not
close those external gates. Older broad graph/policy/accuracy/adapter consumers
are not silently upgraded or newly authorized by this increment.
