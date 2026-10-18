# 32 — Problems to expect, their consequences and how to prove safe behavior

[Guide index](README.md) · [Collection](29-system-by-system-collection-playbooks.md) ·
[Priorities](33-international-bank-engineering-and-rollout.md)

**Purpose:** a threat/failure register for bank acceptance. A scenario below is
not a claim that the repository currently contains that vulnerability or that a
bank incident occurred. Current known limitations are separately source-linked
in guides 08, 26 and 33. Test in isolated, authorized environments first.

## 1. Authorization, ownership and disclosure failures

| ID | Problem and likely consequence | Required control / negative qualification |
|---|---|---|
| F01 | Bank reader guesses another bank's run/version/export ID | Refuse disclosure; test own, foreign, platform and colliding versions across every read/export channel |
| F02 | Same tenant spans regions with different disclosure rules | Enforce approved additional boundary or isolated deployments; test prohibited same-tenant cross-region access |
| F03 | Worker loses tenant/region context after retry or thread reuse | Fresh per-job scope; interleave jobs from two banks and prove no context/cache/result crossover |
| F04 | Legacy platform inventory contains sensitive bank observations | Audit ownership/sharing; migration review; test that new bank evidence never enters unintended shared inventory |
| F05 | Supplier-owned target is assumed authorized because bank uses it | Require target/method-specific bank and supplier approval; refusal must be a visible blocked outcome |
| F06 | Revoked identity or expired approval remains valid in queued jobs | Revalidate execution authority; revoke between enqueue and execution and verify no collection |

Step 10 supplies local real-session tests for important derived-history/watch
boundaries. It does not certify every storage, region, worker and export path
listed here. Preserve those tests and extend them rather than widening roles.

## 2. Unsafe collection and hostile input

| ID | Problem and likely consequence | Required control / negative qualification |
|---|---|---|
| F07 | Alternate API/scheduler path bypasses window, stop or persistence | Route-equivalence tests and restricted ingress; same refusal/receipt invariants for every alias |
| F08 | DNS changes or redirects move an admitted target to prohibited infrastructure | Review resolution/use binding and each redirect/profile; block forbidden actual destinations with independent egress rules |
| F09 | Excessive TLS enumeration exhausts a fragile service or HSM sessions | Canary, per-device/provider quotas, bounded timeouts; test stop and maximum connection counts |
| F10 | Malformed BOM/archive causes traversal, decompression bomb or parser denial of service | Quarantine, safe extraction, resource limits; malicious fixtures must not escape staging or invoke network/executables |
| F11 | Source/build hooks execute with bank secrets | Never build untrusted projects for basic inventory; prove isolated parsing sees no worker secrets/DB/socket and cannot egress |
| F12 | Supposedly passive OT path transmits packets | Capture traffic at the boundary; zero target packets is a measurable release gate, not a naming convention |
| F13 | Raw exports or source contain keys, PANs, personal data or credentials | Approved metadata allowlists, restricted raw handling and secret-safe logs; test canaries are absent from projections and exports |

A harmless-looking read can create audit events, load and sessions. Qualification
must monitor the actual system effects, not merely HTTP method names. Do not
prove active failure by disrupting a real payment service.

## 3. Evidence and inventory failures

| ID | Problem and likely consequence | Required control / negative qualification |
|---|---|---|
| F14 | Valid supplier document belongs to another release/customer | Check exact binding and authority; quarantine wrong-customer/wrong-build packages |
| F15 | Digest or signature is treated as proof of complete truth | Independent checks for integrity, signer trust, scope, freshness and omissions; unknown signer stays untrusted |
| F16 | Cloud pagination/permission failure returns zero resources | Explicit partial/error receipt; old source-owned relationships must not be removed |
| F17 | Old export arrives late and appears current | Preserve observation vs ingestion time; out-of-order import must not refresh old facts |
| F18 | Reused names/IPs merge unrelated products, branches or tenants | Namespace-aware exact identity; collision fixtures must remain distinct |
| F19 | Cap, sample or unsupported parser makes unseen objects appear absent | Sentinel/continuation/completeness metadata; test exact/over/zero budgets and unknown source totals |
| F20 | Vendor brochure becomes installed hardware/PQC attestation | Preserve declared vs observed and firmware/partition bindings; unknown readiness remains explicitly qualified |
| F21 | API returns results but evidence commit fails | Report persistence failure separately; simulate DB outage and verify no durable-success claim or unsafe rebaseline |
| F22 | Duplicate delivery or lost acknowledgment duplicates state | Idempotency and immutable receipts; replay and crash between commit/ack in a controlled test |

False positives need owners and dispute handling. False negatives need known
coverage boundaries and reference fixtures. Neither a large count nor a clean
report proves detector quality across proprietary implementations.

## 4. Interpretation, availability and governance failures

| ID | Problem and likely consequence | Required control / negative qualification |
|---|---|---|
| F23 | Edge TLS is used to certify every backend's crypto | Vantage/termination mapping; explicit missing backend evidence |
| F24 | Partial data reduces findings and looks like remediation | Compatible-scope comparison; withhold removals and retain comparable baseline |
| F25 | Optional/failover/buffered annotation is represented as continuity proof | Keep modeled exposure; actual failover/load testing is a separate bank-owned program |
| F26 | Process revenue is reported as predicted incident loss | Label economic context; no unsupported financial-loss estimate |
| F27 | One regional outage causes unlimited retries or global credential fallback | Bounded retry budget, backpressure, local evidence handling and no unauthorized fail-open region |
| F28 | Stale advisory mirror is presented as no vulnerabilities | Record feed age/coverage and mark applicability unknown where not evaluated |
| F29 | Backup restores bytes but loses ownership, trust keys or evidence linkage | Isolated restore rehearsal including authorization, chains, decryption and historical references |
| F30 | Report becomes “compliant” without control-owner review | Record rule/profile versions, evidence and exceptions; compliance owner determines applicability and acceptance |

## 5. Qualification ladder

### Level A — static and unit checks

Schema validation, parser known-answer/negative fixtures, exact identity,
role/tenant rules, history invariants, limit behavior and no-Bolt tenant tests.
Useful and repeatable; not proof of real device behavior or runtime isolation.

### Level B — component integration in a disposable environment

Real PostgreSQL transactions/migrations, actual Neo4j single-estate semantics,
queue/object-store round trips and approved parser runtime. Include rejected
writes, partial commits, connection loss, duplicate deliveries and cleanup.

Use [guide 26's opt-in live gate](26-bank-negative-tests-and-backend-qualification.md)
only with its exclusive empty disposable Neo4j database prerequisites. Direct
native-store testing does not authorize tenant-scoped Bolt access in production.

### Level C — adapter qualification with vendor and bank samples

Specific product/version/format/encoding; representative valid, malformed,
partial and changed outputs; permission failures and rate limits. Agree expected
results with the owner. Avoid calling one successful sample a whole-vendor
certification. Proprietary support gaps need explicit unresolved cases.

### Level D — operational canary

One approved low-risk target, observed service metrics, bounded collection,
correct destination/identity, durable evidence and tested local stop. The owner
can halt expansion. No unapproved transaction, failover or key operation.

### Level E — regional and program acceptance

Controlled scale, safe fault injection, recovery, regional export controls,
change-management handoff and reconciliation against expected estate. Any
production fault exercise needs its own authorization; use nonproduction where
impact cannot be safely bounded.

## 6. What to retain for every qualification result

Record build/commit, configuration, scope revision, test environment, product
and backend versions, operator, timestamps, expected/actual outcomes, logs with
approved redaction, observations, limitations and reviewer sign-off. Preserve
failed attempts and waivers. Label not-run, skipped and deselected tests honestly.

A waiver needs an accountable risk owner, impact, compensating control, expiry
and retest trigger. It must not transform an unknown into a passing result.

## 7. Stop and incident playbook

If service health degrades, scope changes, an unauthorized destination appears
or unexpected sensitive data is collected:

1. Stop affected work and prevent new admission within the approved boundary.
2. Revoke/quarantine the collector identity if compromise or scope escape is suspected.
3. Preserve minimal approved audit/receipt evidence; do not spread sensitive payloads.
4. Notify the bank's operations, SOC, data owner and supplier contacts as appropriate.
5. Assess service impact and data exposure under the bank's incident procedures.
6. Correct the method/configuration; retest in isolation before restarting.
7. Resume only with explicit owner approval and a recorded scope revision.

The scanner is a participant in the bank's incident process, not an authority
to bypass change controls or silently erase evidence of its own failure.
