# 3. Strengthen existing security, privacy and isolation

[Pack index](README.md) · [Previous: correctness](02-correctness-and-six-bom-quality.md) ·
[Next: reliability](04-reliability-performance-and-recovery.md)

## 3.1 Goal and scope

Make existing controls consistently effective under realistic negative conditions.
This is not a recommendation for more security products, new identity features,
a new multi-tenant topology or live collectors. A named test below is a required
check to retain/extend, not an allegation of an exploitable defect in this baseline.

The controlled profile is deliberately local-source/v1, with an isolated parser,
regional external PostgreSQL and verified-TLS Redis. Unsupported routes must stay
refused. A role badge, sidebar guard or supplier signature cannot bypass the
server's current estate/authority contract.

## 3.2 Threat-focused review of the existing journey

| Boundary | Existing control to exercise | Evidence the reviewer needs |
|---|---|---|
| Browser → API | Current durable session/API-key scope, role/membership and selected estate | Anonymous, denied, expired/revoked and foreign-estate requests cannot expose protected data or mutate it. |
| API → queued job | Persisted original authority, current policy/approval and queue descriptor agreement | A forged owner, old credential or modified queue payload cannot obtain execution. |
| Worker → source/parser | Admitted root, bounded staging, isolation, resource and egress restrictions | Symlink/path/archive/resource adversarial cases refuse safely; intended isolation is verified at the actual site. |
| SQL → reads/history/export | Exact-estate filtering, append-only/CAS and permitted raw evidence access | Object-ID guessing, list/detail mismatch and platform/NULL confusion fail closed. |
| Supplier payload → review | Exact customer/build, trusted public key, bounded quarantine and separate approval | Valid origin does not skip quarantine; wrong-build/revoked/stale/malformed evidence cannot be consumed as trusted truth. |
| Stream/cache → browser | Owner filtering, fresh authority, bounded replay and estate-change invalidation | Revocation while idle, foreign/spoofed frames and late responses cannot leak old/new estate data. |
| Release → site | Verified package/digests, secret/CA provisioning and human change approval | Tampered package, unresolved placeholders and untrusted signing keys fail before installation. |

## 3.3 Build one identity/authority negative matrix

Use actual test fixtures/durable identities for platform scope, estate A and
estate B. No production identity is created by this document.

For every selected critical list, detail, history, mutation and export, exercise:

1. Anonymous access and an authenticated but insufficient role.
2. Estate A accessing A, then guessing a retained B object ID.
3. Platform-unselected access versus explicitly selected authorized estate A.
4. Expired/revoked session, API key or membership, including during a stream.
5. A machine credential attempting an operation requiring a human reviewer.
6. The proposer attempting the independent approval/review step.
7. A stale revision and concurrent updates; verify no partial write survives.
8. Region/evidence-destination mismatch and unavailable authority storage.
9. Missing/forged owner fields and same-name user/system identities across estates.
10. An interrupted request followed by history reconciliation rather than blind retry.

Use the documented endpoint error contract, not a newly invented universal HTTP
code. A foreign detail usually refuses/not-found according to its existing
contract; the body must not leak another estate's metadata. Server refusal is
required even if the browser hides the action.

Relevant existing tests include `test_cross_surface_estate_contract.py`,
`test_estate_history_contract.py`, `test_events_stream.py`,
`test_sse_estate_contract.py`, `test_assurance_controlled_boundary.py` and
`test_launch_readiness.py` under `services/api/tests/unit/`.

## 3.4 Hostile-input and isolation quality

Review the current parser/staging boundary against malicious **approved test
fixtures**, not customer infrastructure without written permission:

- path traversal, absolute paths, symlinks, changed source between validation/read;
- large counts/deep nesting, decompression expansion and parser CPU/memory/disk use;
- malformed/truncated binary or source inputs and optional-tool absence;
- attempted network access, execution of embedded commands and secret discovery;
- process kill, cleanup failure, leftover mounts/files and reused workspace content;
- output size limits and sanitization before durable retention.

First establish what is already bounded/tested, then improve a specific gap.
Retain partial progress and a refusal reason. Never “fix” a hostile-input test by
running the parser inline, enabling egress or giving it a privileged host mount.

A dedicated worker runtime with Docker-daemon access is not a shared hostile
multi-tenant sandbox: daemon access is root-equivalent. Site isolation and escape
assessment remain separate externally witnessed acceptance. Do not market the
reference profile as a general secure shared-tenant service.

## 3.5 Data minimization and secret-handling review

Trace each sensitive field through input, memory, exception, log, SQL, evidence,
UI, export, backup and deletion/hold. For each path ask:

- Is it needed for the existing decision? Can metadata/digest replace raw content?
- Was sanitization applied before hashing/retention under the evidence contract?
- Could a connection URL, query string, exception, stack trace or subprocess
  argument expose a password/token/key or customer source?
- Is raw evidence more restricted than ordinary result metadata?
- Are original-file paths and supplier metadata appropriate for this audience?
- Do caches, artifacts, test snapshots and backups inherit the approved policy?
- Can an old credential be revoked without exposing its value in a rotation proof?

Use synthetic canary secrets in isolated tests and assert they are absent from
outputs. Never put real credentials or private signing keys into fixtures,
screenshots, commits, public issue descriptions or this documentation.

Log a bounded diagnostic/error category with the appropriate job/attempt
reference. Do not solve secret leakage by swallowing every error: unavailable
storage or failed cleanup must remain visible without dumping sensitive content.

## 3.6 Transport and dependency checks

Verified TLS is an end-to-end configuration requirement, not just HTTPS at nginx:

- PostgreSQL hostname verification, approved CA and separated runtime/migration grants;
- Redis verified TLS, named ACL roles and correct command readiness;
- failure on wrong CA/hostname, expired certificate or insufficient command grants;
- intended role-specific Sentinel/URL isolation where that configuration is used;
- certificate/credential rotation, including evidence that old access is refused.

Review all current consumer roles using the
[Redis consumer/recovery contract](../bank-environment/47-redis-consumer-and-recovery-evidence.md),
not an older note limited to realtime clients. Successful PING or startup is not
state durability or RPO evidence.

Keep dependencies and base images supported through reviewed updates. Triage
actual affected components/configuration rather than declare every advisory
exploitable or run force-fix blindly. Exact version constraints do not establish
hash-verified reproducibility or independent security qualification.

## 3.7 Independent assessment of what is already shipped

Use the existing [independent-security contract](../bank-environment/56-independent-security-assurance.md).
An assessor should examine the agreed current scope, including the existing
five areas and 13 mandatory negative case IDs. Do not replace those exact case
requirements with a new informal checklist.

The real process is: approve scope/rules of engagement → independent authorized
execution → retain original report and authenticated signed binding → accountable
finding disposition/change → later exact-condition retest → separate review.
Missing tests stay NOT_TESTED/INCONCLUSIVE. A valid signature establishes origin
and integrity, not competence, independence or factual correctness by itself.

## 3.8 Exit criteria and stop conditions

**Stop promotion** on reproduced cross-estate disclosure, secret leakage,
unapproved execution, evidence corruption, false verification or a required
security test/assessment failure. Record scope and preserve evidence under the
incident process; do not conduct destructive experimentation on a live bank.

Exit requires critical negative regressions on the exact candidate, appropriately
independent security results for its real scope, addressed/reviewed findings and
post-fix retests. A responsible exception must follow the actual gate/policy;
it cannot rename mandatory FAIL/SKIP as PASS or waive bank authority.


## 3.9 Implemented authority/dependency-failure correction

The [third quality increment](../readiness-evidence/quality-authority-privacy-2026-10-22.md)
reproduced a role-store failure entering legacy empty-role/admin compatibility,
missing production identity/scope handling and selected public health/log paths
exposing synthetic exception canaries. Existing role dependencies now refuse
unavailable storage with 503, rather than infer privilege from unreadable rows or
stale token claims. Disabled/deleted current rows cannot provide those roles;
affirmatively missing non-production legacy identities retain compatibility.

Public dependency/readiness failure details and selected role/tenant/database
failure logs retain status and safe categories without raw driver/connection/SQL
payloads. Liveness and readiness-drain semantics remain distinct. Forty new cases
include isolated post-auth role gates and four actual artifact-route checks with
real durable synthetic sessions and targeted role-stage faults. Original adverse
results and exact broader checks are retained, not represented as a live outage,
independent assessment, full secret scrub or complete race matrix.

See [implementation status](IMPLEMENTATION-STATUS.md). Remaining independent
security and site/operating evidence is still required; no CI failure is waived,
production permission added or customer acceptance granted by the source push.
