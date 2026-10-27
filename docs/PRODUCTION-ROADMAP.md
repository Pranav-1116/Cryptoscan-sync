# Production roadmap — end to end, from today's state to bank sign-off

**Current as of:** 2026-10-04 UTC
**State snapshot commit:** `fa92881` (branch `arena/01a106c8-cryproscan`, draft PR #23)
**Decision owner:** [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) → `docs/readiness-evidence/bank-readiness.{json,md}`
**Companion docs:** [`NEXT-STEPS.md`](NEXT-STEPS.md) (detector accuracy loop) · [`ops/production-checklist.md`](ops/production-checklist.md) · [`production-qualification-runbook.md`](production-qualification-runbook.md)

This is the end-to-end plan for everything that remains between the current
state and an unattended production approval. It is ordered by dependency, not
by effort: every phase lists what it closes, who owns it, the exact commands,
and its acceptance criterion. Nothing here can be honestly skipped — the gate
is fail-closed by design.

---

## 0. Internal-work update (2026-10-05)

Everything in this section is work that needed no credential, provider or
customer — the "internal" remainder. It does **not** move any phase below, and
no gate category flips: those still turn on external evidence. What it changes
is that a set of defects which would each have surfaced *in* production are
fixed, three drills are green, and the one product question this document
previously recorded as open has been decided.

Most of these were found by **running** the product rather than reading it: a
paused database rather than a mock that raises, a restart rather than a review
of the restart path, a scan of a real directory rather than a fixture. Each
one was silent — a passing check, a probe that proved less than it appeared
to, or a number that was simply too large.

**Probe behaviour under a database outage — three defects, all fixed.**
Found by running `scripts/reliability_drill.py` against a paused PostgreSQL
container rather than a mock that raises:

| Endpoint | Before | After |
|---|---|---|
| `/healthz` (liveness) | hung 20 s+ | **200 in 2 ms** |
| `/health` | hung 20 s+ | **200 in 1 ms** |
| `/readyz` (readiness) | hung 25 s+ | **503 in 4.0 s** |

1. `tail_monitor_events` is an `async` coroutine that called a synchronous
   SQLAlchemy query directly, so an unreachable database blocked the event
   loop and froze *every* endpoint. Now `run_in_threadpool`. This is the same
   defect class `PRODUCTION-READINESS.md` records for the auth middleware's
   session-revocation check, in a different place.
2. `/healthz` called `check_db_health()` inline, making the **liveness** probe
   depend on PostgreSQL. `readyz`'s own docstring already stated the intended
   contract — *"Liveness (/healthz) stays 200 through a DB outage"* — so the
   implementation contradicted its documented spec. A hung liveness probe
   means Kubernetes kills a pod whose only problem is that the database is
   briefly away: a restart storm exactly when the database is already
   struggling.
3. `/readyz` may check the database, but exceeded any probe budget. An
   unreachable host is not a refused one — it accepts the TCP connection and
   never answers, so pool pre-ping and checkout each wait out their own
   timeout and stack. Now bounded at `READINESS_PROBE_TIMEOUT_SECONDS = 4.0`
   and answering 503, which says "drain me, I am alive" rather than looking
   like a wedged process.

The existing outage test passed throughout, because it mocks an engine that
*raises* immediately. Two tests now model the blocking case instead.

**Drill evidence (local sandbox, not target topology):**

| Drill | Result | Artifact |
|---|---|---|
| Realtime data plane | **PASS 23/23** | `readiness-evidence/realtime-dataplane.json` |
| Reliability | **PASS 21/21** | `readiness-evidence/reliability.json` |
| Backup / restore | **PASS 12/12** | `readiness-evidence/backup-restore-drill-2026-10-05.md` |

The backup drill had been reported as blocked: it needs the SQLite staging
estate and the local stack runs PostgreSQL, so it backed up an empty SQLite
file and found zero event-bus logs. Four checks failed for that reason
alone. Standing a SQLite staging API up on a separate port — the
configuration the drill is written for — was the answer rather than
recording the mismatch as a defect. The green run also exercises the
hardened restore assertion below against a genuine restore.

**A phantom-process bug in the local stack.** `pgrep -f worker.main` matches
any shell whose command line contains that string — including the commands
used to check on it. `run_local_stack.sh` therefore reported "worker already
running" and never started a real one, leaving jobs queued in Redis with
nothing consuming them, while the drill's restart check passed against the
phantom. Both now track the worker by PID file.

**Monitor liveness — the open product question, now resolved.** `engine.tick()`
re-materialized every known gateway event on each quiet tick to record
liveness. Components stayed idempotent, but the CBOM version and `_event_log`
grew once per event per tick: measured at version 53 and 52 log entries after
one real event and 50 quiet ticks — roughly 43k rows a day on a two-second
loop against an estate that never changed, and a version that counted ticks
rather than content.

Two comments inside `tick()` disagreed about whether this should happen, and
that settled it: the step-2 block already promised *"no repeated CBOM version
bumps"*, so the contract was written and the code contradicted it. Liveness is
now a separate `LiveCbom.observe_liveness()` heartbeat — O(1) per tick, bounded
in memory, carried through `export_state`/`restore_state`. The version and log
move only when content changes, and `cbom.liveness()` answers *"when was this
last confirmed"*. Measured after: version 2 and 1 log row for the same
sequence, with `observations: 12`.

The diagnostic consequence matters more than the row count. A dead collector
and a quiet estate both used to produce a steadily rising version, so neither
was distinguishable from the other. Change and confirmation are now separate
facts.

**Evidence integrity — duplicate findings no longer reach the chain.** The AST
and regex detection paths can both report the same crypto use on the same
line, and each emitted its own evidence record. `content_hash` excludes
`evidence_id`, `finding_id`, `created_at` and `scan_timestamp`, so the two hash
identically: the duplicate is provably the same observed fact stored twice.
The inflated number reaches finding totals, compliance percentages and CBOM
component counts, which are the figures a bank reads.

Measured on two real scans in the same estate, before and after the fix:

| Scan | Records | Duplicate `(scan_id, content_hash)` groups |
|---|---|---|
| `6c5f7684` (before) | 7,315 | **1** |
| `e1a4621e` (after) | 4,012 | **0** |

Collapsed in `EvidencePipeline.process_findings`, immediately before
`chain_position` is assigned. The placement is the point: `evidence_records` is
a contiguous append-only hash chain, so the obvious alternative — a unique
index on `(scan_id, content_hash)` — is wrong twice over. It aborts a load
mid-chain, and a duplicate already stored cannot be deleted afterwards without
breaking the `previous_hash` links around it. Duplicates are counted and logged
rather than dropped silently, so a detector that starts double-reporting stays
visible.

**DR and restore probes now prove the database serves.** Removing the database
check from `/healthz` was correct, but it silently weakened two drills that had
been relying on liveness to touch the database incidentally:

| Drill | Was | Now |
|---|---|---|
| `backup_drill.py` | polled `/healthz` → "uvicorn started" | waits on `/readyz` **and** requires `database: ok` |
| `postgres_drill.py` | any URL returning `< 400` | refuses liveness URLs outright; requires `database: ok` |

A liveness URL is now rejected with the reason rather than quietly accepted:
taking one would produce DR evidence stronger than the check behind it. The
restore drill also keeps the recovered instance's output instead of sending it
to `DEVNULL` — a drill that cannot say *why* a boot failed is useless at the
one moment it matters.

**The local stack no longer destroys its own estate.** The postgres and redis
containers ran with no volume, so the data lived only in the container
filesystem — and `down` does a `docker rm -f`. Stopping the stack to reload the
frontend deleted every scan, unrecoverably; 3,163 evidence records were lost
that way during this work. Both containers now use named volumes, and the
destructive path is split out and named for what it does: `down` keeps the data
and says which volumes hold it, `purge` deletes it and asks first. Verified by
dumping the estate, migrating, restoring, and taking it through `down` → `up`
three times with the chain intact.

**A scan of a directory containing its own workspace.** Scanning the project
checkout died at pipeline stage `init` with `maximum recursion depth exceeded`,
before a file was read. `shutil.copytree` walks the source while writing into
the destination, so when the destination sits under the source it descends into
the tree it is still producing. Two distinct causes, both handled: the
destination inside the source, and a tree that is simply pathological — this
repository carried `_tmp/snbchk/ws/repo/ws/repo/...` some 250 levels deep,
5,167 files of recursively duplicated fixture committed by an earlier harness
run hitting exactly this bug, since removed. The copy is now iterative, prunes
the workspace root, caps depth at 64, copies directory symlinks as links, and
logs what it skipped — a silently truncated scan would under-report an estate.

**Frontend.** The two advisories that actually ship to the browser are closed:
`react-router-dom` v7 took the production count from 2 to 0. Budgeted at one to
two days as a semver-major migration, it needed no code changes, because the
console only uses the declarative core and v7's breaking changes are in the
data-router APIs it has never used. The remaining npm advisories are
devDependencies that never reach the browser. The dev server was also binding
`0.0.0.0` with `allowedHosts: true`, publishing a development server and its
authenticated `/api` proxy on every attached network with DNS-rebinding
protection off; it now binds loopback with host checking on.

Separately, the console was bypassing its own design system — 90 emoji used as
icons, 185 hardcoded colours, 10 CSS custom properties that did not exist, and
a brand mark measuring 1.14:1 in dark mode. Those are now 0, and type colours
no longer borrow status colours: CBOM read amber ("warning") and HBOM orange
("high risk") purely to tell BOM layers apart.

**Job progress was written but never visible.** The status transition was not
missing. `BaseRepository.update` only flushes, and the pipeline commits its own
session once, after the final stage — so every progress update sat in an
uncommitted transaction that no other connection could read. The API, reading
on a separate connection, saw `QUEUED` for the whole scan and then `COMPLETED`,
because that was the moment the work became *visible* rather than the moment it
happened. A nine-minute scan was indistinguishable from a wedged one, and
`started_at` only appeared once it no longer mattered.

Committing inline on the pipeline session would have been the wrong fix: that
session carries the half-built scan and evidence rows, and the evidence load is
deliberately atomic. Status, progress and `error_message` now travel on their
own short-lived session and commit immediately — they are operational telemetry
about the job, not part of the scan's data transaction. `scan_id` is the one
exception; it is a foreign key to `scans.id`, so it stays on the pipeline's
transaction and lands with the scan row.

One backend caveat is handled explicitly. SQLite permits a single writer, so
while the pipeline holds its transaction the telemetry connection is locked
out; it falls back to the pipeline session, which defers the update exactly as
before rather than dropping it. On PostgreSQL the fast path wins and progress
is live. Measured on a real scan after the change:

```
RUNNING | started_at=2026-10-05T15:44:09 | stage=load 29
...
COMPLETED | stage=alert 100
```

The swallow that hid this is also gone: the handler logged at `debug`, so a
failing status update was invisible in normal operation.

**Findings recorded, not fixed.** One thing worth a decision rather than a
quiet change:

* `config/exception-allowlist.json` keys reviewed exception handlers by
  `file:line`. Adding an import above a reviewed handler shifts its line and
  silently un-reviews it — which is how the engineering gate failed during this
  work, on a handler nobody had touched. Keying on handler content or enclosing
  function would survive formatting churn while still catching real changes.

The job-status item previously listed here is resolved and moved above. Worth
noting why it was mis-described: recorded as "status skips the `RUNNING`
transition", it was really "every transition is written and none are visible".
The observable symptom was identical, and the wrong description would have sent
someone hunting for a missing assignment that was never missing.

---

## 1. Where we are now (2026-10-04)

The unified gate (`scripts/bank_readiness.py`) currently records:

| Category | Status | Evidence |
|---|---|---|
| postgresql_dr | **PASS** | `readiness-evidence/postgres-dr-drill-2026-10-04.json` — 35/35 checks, promotion RTO 0.103 s, RPO 0 s, clean restore verified |
| load_soak | **PASS** | `readiness-evidence/load-test-2026-10-04.json` (7 559 req, 0 errors) + `readiness-evidence/soak-2026-10-04/` (3/3 cycles, chain verified, flat RSS) |
| integrations | **PASS** | `readiness-evidence/burn-in-2026-10-04.json` — signed GitHub webhook round-trip, TLS 1.3, SMTP |
| compliance | **PASS** | `readiness-evidence/compliance-burn-2026-10-04.md` — 11/11 over live HTTP |
| documentation | **PASS** | 309 Markdown files, consistency-checked |
| operational_policy | **PASS** | structural findings = 0 |
| engineering | **FAIL** | re-audited 2026-10-14 at `3dc4830`+working tree: tenant-isolation audit now **PASS** (114 scoped tables, 0 violations — the last in-repo fixable finding, a PK-lookup bypass on `GET /compliance/evidence/packs/{id}`, was fixed in round 67 with an adversarial cross-tenant test); remaining failures are purely external: branch-protection API 403 (re-verified 2026-10-14), immutable image digests (registry unreachable from the qualification sandbox), no customer corpora |
| hsm / readiness_closure / external_attestations | **SKIP** | provider/customer-controlled evidence; a source session cannot produce these |

Honest assessment that follows from this state:

- **Single bank, own instance, supervised pilot: ~90 %.** Everything
  executable from the codebase is done and evidenced. The remaining ~10 %
  is credentials, calendar time, and external parties.
- **Strict gate (unattended production): 6/10 categories PASS (~60 %).** The
  remaining four are exactly the external-evidence categories.
- **Shared multi-tenant SaaS: ~78 %.** Tenant isolation is hardened
  (114 tenant-scoped tables with a zero-violation audit at round 67,
  graph-engine gate, adversarial suite), but a
  multi-day multi-tenant soak, an external security assessment and per-tenant
  capacity evidence are still required before that number can honestly move.

---

## 2. The path at a glance

| Phase | What it closes | Owner | Effort | Prerequisite |
|---|---|---|---|---|
| 0. Credential unblocks | engineering (branch protection + CI publish) | repo admin | hours | a workflow-scoped GitHub token / admin session |
| 1. Immutable release pipeline | engineering (image digests) | platform-release | hours–1 day | Phase 0 |
| 2. Target-environment qualification | load_soak at production scale; observability | SRE/operations | 3–7 days calendar | Phase 1 (pinned images to deploy) |
| 3. HSM qualification | hsm | cryptography-security + provider | days–weeks | provider contract |
| 4. Independent security assessment | P0-1; feeds closure | external assessor | weeks | Phase 2 (stable environment to test) |
| 5. First bank pilot | P0-2, customer corpora, external attestations | product-security + bank | weeks–months | bank engagement |
| 6. Closure manifest + strict gate | readiness_closure; overall PASS | evidence owner (deployment lead) | days | Phases 1–5 outputs |
| 7. Production operations | stays qualified over time | operations | ongoing | go-live |

Phases 3, 4 and 5 can run in parallel with each other once Phase 2 is up.
Phase 6 is the convergence point; Phase 7 is forever.

---

## 3. Phase 0 — Credential unblocks (hours)

**Closes:** engineering sub-checks that are blocked purely by credentials, and
unblocks the release pipeline.

The qualification session of 2026-10-04 proved the code and evidence; these
two items failed only on token scope and must be done by someone with rights:

> **Re-verified 2026-10-14 — both items are still blocked by the same
> credential.** The session token is a GitHub App installation token
> (`X-OAuth-Scopes` empty) that reports `admin: true` on this repository but
> still cannot exercise either right: the workflow-file push probe (moving
> `secret-scan.yml` into `.github/workflows/` and pushing) was rejected with
> *"refusing to allow a GitHub App to create or update workflow … without
> `workflows` permission"*, and the branch-protection PUT below returned
> `403 Resource not accessible by integration`. The probe commit was rolled
> back; the staged files remain intact in `.github/workflows-pending/`.
> Do not retry either with this credential.

1. **Publish the release CI workflow.** `.github/workflows/docker-build.yml`
   is **0 bytes on `main`**, along with `db-migration.yml` and
   `scanner-tests.yml`: commit `5a32105e` emptied all three because the
   automation token lacks the `workflow` scope and any non-empty file under
   that directory makes the push fail with HTTP 403. Only `ci.yml` still has
   content.

   This entry previously described a complete workflow with multi-arch
   build, SBOM, provenance and digest recording as "existing locally". That
   was not accurate: the last version with any content (`39e0a3e2`, 470
   bytes) ran `docker build -t cryptoscan-api:ci` and stopped — no registry
   login, no push, no digest — so it could not have fed the digest pinning
   in §4 even if it had been pushed.

   A workflow that does produce those digests now lives in
   `.github/workflows-pending/`, together with the other two restored files
   and install instructions. Moving them into `.github/workflows/` and
   pushing requires a `workflow`-scoped credential.
2. **Enable branch protection on `main`.** The API call was attempted and
   refused (403, Administration scope). Run from an admin session:

   ```bash
   gh api -X PUT repos/ZKChainForge/CryproScan/branches/main/protection --input - <<'EOF'
   {
     "required_status_checks": {"strict": true, "contexts": ["ci"]},
     "required_pull_request_reviews": {"required_approving_review_count": 1},
     "enforce_admins": false,
     "restrictions": null
   }
   EOF
   ```

**Acceptance:** `GITHUB_REPOSITORY=ZKChainForge/CryproScan python scripts/engineering_gate.py`
reports `branch protection API verification: PASS`.

---

## 4. Phase 1 — Immutable release pipeline (hours–1 day)

**Closes:** the `production image immutable digests` engineering check.

The three mutable template references (`cryptoscan-api:v1.0.0`,
`cryptoscan-worker:v1.0.0`, `neo4j:5.26-community`) must become
digest-pinned manifests:

1. Let the CI workflow from Phase 0 build and push images; copy the printed
   digests (or read them from the release artifacts).
2. Render the release:

   ```bash
   python scripts/pin_release_images.py \
     --api-digest sha256:… --worker-digest sha256:… --neo4j-digest sha256:… \
     --registry ghcr.io/zkchainforge --source k8s --out releases/v1.0.1
   ```

3. Re-run the engineering gate with the rendered release:

   ```bash
   GITHUB_REPOSITORY=ZKChainForge/CryproScan \
   python scripts/engineering_gate.py --release-manifests releases/v1.0.1
   ```

**Acceptance:** engineering gate reports
`production image immutable digests: PASS`. The only remaining engineering
SKIPs are then the COBOL/PLI/RPG customer samples, which Phase 5 supplies.

---

## 5. Phase 2 — Target-environment qualification (3–7 days calendar)

**Closes:** load_soak *at production scale* (the 2026-10-04 evidence is a
short-run qualification, not a capacity claim) and operational readiness.

1. **Deploy** the digest-pinned release from Phase 1 to the bank-side or
   company-side staging topology (PostgreSQL primary + streaming standby,
   Redis, worker, monitor daemon, Neo4j if the graph estate is in scope).
2. **Multi-day soak** — the same harness that produced the 3-cycle evidence,
   run for real duration against a real target repository set:

   ```bash
   python scripts/soak.py --api https://staging.example.internal \
     --username <ops-admin> --password <from-vault> \
     --target <authorized-repo-url> --hours 72 --interval 300 \
     --staging-dir /srv/cryptoscan-staging --out releases/soak-<date>/
   ```

3. **Load test at target scale** (users sized to the bank's concurrency):

   ```bash
   python scripts/load_test.py --url https://staging.example.internal \
     --users <N> --duration 900 --username <ops-admin> --identity api-keys \
     --max-error-rate 0.01 --out releases/load-<date>.json
   ```

4. **Re-run the DR drill in that environment** (quarterly cadence is required
   anyway — see the 90-day freshness window on P0-4 in the closure policy):

   ```bash
   python scripts/postgres_drill.py \
     --primary-dsn  postgresql://… --standby-dsn postgresql://… \
     --promote-command "…" --execute-promotion --acknowledge-destructive \
     --require-promotion --api-url https://staging…/api/v1/readyz \
     --worker-health-command "python scripts/drill_worker_recovery.py --run-seconds 6" \
     --restore-command "bash -c 'pg_dump … | psql …'" \
     --clean-restore-dsn postgresql://… \
     --out releases/dr-drill-<date>.json
   ```

   `/readyz`, not `/healthz`: since `fe0fddf` the drill refuses liveness URLs
   outright — liveness stays 200 through a database outage by design, so it
   cannot prove failover. The probe also requires the response body to name
   the database as `ok`.

5. **Alert-escalation exercise** (`docs/ops/on-call-and-comms.md`) and a
   **backup drill** (`docs/backup-drill.md` / `scripts/backup_drill.py`).

**Acceptance:** soak summary `cycles_failed == 0` over ≥ 72 h with flat RSS;
load test error rate ≤ 1 % at target concurrency; DR drill verdict PASS in
the target environment; escalation exercise logged.

---

## 6. Phase 3 — HSM qualification (days–weeks, provider-parallel)

**Closes:** the `hsm` gate category and P0-3 in the closure policy.

1. Select the provider: `aws` (CloudHSM custom key store), `azure` (Managed
   HSM), `gcp` (Cloud KMS/EKM), `pkcs11` (network HSM), or `luna`
   (Thales). SoftHSM is a local dev gate only and is explicitly **not**
   evidence.
2. Provision a qualification key in the provider (never exportable).
3. Run the qualification with real operator wrappers:

   ```bash
   python scripts/hsm_qualification.py --provider aws \
     --key-id <provider-key-ref> \
     --rotation-command  "<operator script>" \
     --revocation-command "<operator script>" \
     --audit-log-command "<operator script>" \
     --out releases/hsm-qualification-<date>.json --strict
   ```

**Acceptance:** `--strict` exit 0; the report carries non-exportability,
sign/verify, rotation, revocation and audit-trail evidence from the provider
itself. Feed the artifact to `bank_readiness.py --hsm`.

---

## 7. Phase 4 — Independent security assessment (weeks)

**Closes:** P0-1 (pen test) in the closure policy; strengthens every
customer conversation.

1. Contract an external assessor against the Phase-2 environment (scope: API,
   worker, multi-tenant isolation, evidence chain, auth flows).
2. Remediate findings through the normal PR flow (branch protection from
   Phase 0 enforces review).
3. Re-test closures; retain the final report in the controlled evidence
   store (not in this repository).

**Acceptance:** final report with no open critical/high findings; remediation
commits referenced from the evidence store.

---

## 8. Phase 5 — First bank pilot (weeks–months)

**Closes:** P0-2 (customer pilot + field accuracy), the COBOL/PLI/RPG
customer-sample engineering checks, P1-4 (integration in the bank
environment), and produces the external attestations.

1. Run the triage workbook loop on the bank's own repositories — this is the
   accuracy loop defined in [`NEXT-STEPS.md §1`](NEXT-STEPS.md):

   ```bash
   python scripts/bank_triage.py workbook --repo <bank-repo> --out review.xlsx
   # bank's crypto owner marks TP / FP / MISS, then:
   python scripts/bank_triage.py score review.xlsx
   ```

2. Supply customer corpora to the engineering gate:

   ```bash
   python scripts/engineering_gate.py --release-manifests releases/v1.0.1 \
     --cobol-sample <bank-icsf-sample> --pli-sample <bank-pli-sample> \
     --rpg-sample <bank-rpg-sample>
   ```

3. Turn every confirmed MISS into a corpus file + rule; keep
   `scripts/accuracy_benchmark.py` at 100 % and record the round in
   `docs/accuracy/EXTERNAL-VALIDATION.md`.
4. Run the integration qualification inside the bank's environment (network
   paths, IdP, webhook endpoints, log shipping).

**Acceptance:** first-pass precision ≥ 0.95 and recall ≥ 0.95 on the bank's
own code; engineering gate fully PASS; signed customer attestations retained
in the controlled evidence store.

---

## 9. Phase 6 — Closure manifest and strict gate PASS (days)

**Closes:** `readiness_closure` and `external_attestations`; flips the overall
verdict.

The full register is `config/readiness-closure-policy.json` — 14 gaps
(P0-1…P0-9, P1-1…P1-5). Each gap needs every one of its `required_kinds`
supplied as an artifact with **all** of these fields:

`evidence_id, kind, status=PASS, evidence_tier (≥ gap minimum), artifact_source="external_controlled", artifact_path (OUTSIDE this repository), artifact_sha256, captured_at, release_commit (the release being approved), environment, scope, limitations (non-empty list), owner, issuer, reviewed_by, reviewed_at, operator, independent_review=true`

The gate enforces fail-closed mechanics — separation of duties
(`operator ≠ reviewed_by`), independent review, freshness windows
(e.g. DR drill ≤ 90 days, signed release bundle ≤ 30 days), and digests that
must match files in the controlled store. Two artifacts are already
reusable: the 2026-10-04 DR drill (P0-4 `topology_dr_drill`, pending the
`continuity_plan_approval` side) and the load/soak evidence (P1-2
`target_topology_load_soak`) — copy them into the controlled store with a
proper evidence owner, issuer and reviewer.

1. Evidence owner assembles `closure-manifest.json` in the controlled store.
2. Validate:

   ```bash
   python scripts/readiness_closure_gate.py \
     --manifest /secure/evidence/closure-manifest.json \
     --expected-commit <release-sha> --strict
   ```

3. Final gate run with every artifact:

   ```bash
   GITHUB_REPOSITORY=ZKChainForge/CryproScan \
   python scripts/bank_readiness.py --strict \
     --engineering docs/readiness-evidence/engineering-gate.json \
     --postgresql-dr <drill>.json \
     --hsm <hsm-qualification>.json \
     --integrations <burn-in>.json \
     --compliance <compliance-burn>.md \
     --load-soak <soak-summary>.json \
     --external-attestations /secure/customer-attestations.json \
     --readiness-closure /secure/evidence/closure-manifest.json
   ```

**Acceptance:** `Bank readiness verdict: PASS` — the recommendation line
flips to *unattended production candidate, subject to signed approval and
retained external evidence*.

---

## 10. Phase 7 — Stay qualified (ongoing)

Production is not a finish line; the closure policy's freshness windows are
the operating cadence:

| Cadence | Activity | Window source |
|---|---|---|
| Monthly | re-render digest-pinned release; deployment admission record | P0-5 (30 days) |
| Quarterly | full DR drill; access review | P0-4 / P0-7 (90 days) |
| Every release | engineering gate + compliance burn + load smoke | P0-5 |
| Semi-annual | observability tabletop; load/soak refresh | P1-2 / P1-3 (180 days) |
| Annual | pen test refresh; policy re-approval; HSM re-qualification | P0-1 / P0-3 / P0-6 (365 days) |

Also ongoing: `docs/ops/on-call-and-comms.md` rotations, patch/vulnerability
program records (P0-6), and audit exports on request
(`docs/compliance-burn.md`).

Add to the per-release set the two drills added on 2026-10-05, both of which
need a live stack rather than a test double:

```bash
bash scripts/run_local_stack.sh up          # or point --api at staging
python scripts/realtime_dataplane_drill.py --out <evidence>/realtime-dataplane.json
python scripts/reliability_drill.py         --out <evidence>/reliability.json
```

The reliability drill is destructive by design — it SIGKILLs the worker and
pauses the database container — so run it against staging, never production,
and expect it to restart the worker through `run_local_stack.sh`.

A note on how to read their output: both drills measure the product only when
nothing else is loading the machine. Run concurrently with the full test
suite, the data-plane drill reported three failures — an API timeout and an
apparent loss of durable evidence — that were entirely contention. Neither
reproduced on a quiet host. A drill that can fail for the wrong reason is
worse than no drill, so run them alone and treat a failure as real only after
re-running on an idle machine.

---

## 11. Honest boundary

Repeating the boundary the gate itself enforces:

- A digest proves integrity of a file, not who ran it or that its claims are
  true.
- SoftHSM, synthetic estates, corpus scores and this session's qualification
  runs are **not** customer certification.
- No repository document may convert source inspection into an external
  attestation. The ~40 % that remains between here and strict sign-off is,
  by construction, work that only providers, assessors and a bank customer
  can do.

The fastest honest path to production is therefore: **Phase 0 today** (any
repo admin, under an hour), **Phase 1 this week**, **Phase 2 next**, and the
external tracks (3/4/5) started in parallel — because every day they are not
started is a day added to the critical path that no engineering can shorten.
