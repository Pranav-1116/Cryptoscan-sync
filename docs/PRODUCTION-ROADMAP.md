# Production roadmap — end to end, from today's state to bank sign-off

**Current as of:** 2026-10-04 UTC
**State snapshot commit:** `fa92881` (branch `arena/01a106c8-cryproscan`, draft PR #23)
**Decision owner:** [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) → `docs/readiness-evidence/bank-readiness.{json,md}`
**Companion docs:** [`NEXT-STEPS.md`](NEXT-STEPS.md) (detector accuracy loop) · [`ops/production-checklist.md`](ops/production-checklist.md) · [`operations/production-qualification-runbook.md`](operations/production-qualification-runbook.md)

This is the end-to-end plan for everything that remains between the current
state and an unattended production approval. It is ordered by dependency, not
by effort: every phase lists what it closes, who owns it, the exact commands,
and its acceptance criterion. Nothing here can be honestly skipped — the gate
is fail-closed by design.

---

## 0. Internal-work update (2026-10-05)

Everything in this section is work that needed no credential, provider or
customer — the "internal" remainder. It does **not** move any phase below:
the gate categories still turn on external evidence. What it changes is that
three defects which would have surfaced *in* production are now fixed, and
two drills that could not previously pass are green.

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

**A phantom-process bug in the local stack.** `pgrep -f worker.main` matches
any shell whose command line contains that string — including the commands
used to check on it. `run_local_stack.sh` therefore reported "worker already
running" and never started a real one, leaving jobs queued in Redis with
nothing consuming them, while the drill's restart check passed against the
phantom. Both now track the worker by PID file.

**One unresolved product question, pinned in CI rather than silently fixed.**
`engine.tick()` re-materializes every known gateway event when none are
pending, to record liveness. Components stay idempotent, but the CBOM version
and `_event_log` grow once per tick: measured at version 53 and 52 log entries
after one real event and 50 quiet ticks. On a two-second loop that is ~43k
duplicate entries a day and a version that counts ticks rather than changes.
Two comments inside `tick()` disagree about whether this should happen. A test
now records the shipped behaviour so the contradiction is visible; whether
liveness belongs in the version, a heartbeat, or a bounded log is a product
decision, not a cleanup.

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
| engineering | **FAIL** | immutable image digests unresolved (registry unreachable from the qualification sandbox), branch-protection API 403 for the automation credential, no customer corpora |
| hsm / readiness_closure / external_attestations | **SKIP** | provider/customer-controlled evidence; a source session cannot produce these |

Honest assessment that follows from this state:

- **Single bank, own instance, supervised pilot: ~90 %.** Everything
  executable from the codebase is done and evidenced. The remaining ~10 %
  is credentials, calendar time, and external parties.
- **Strict gate (unattended production): 6/10 categories PASS (~60 %).** The
  remaining four are exactly the external-evidence categories.
- **Shared multi-tenant SaaS: ~78 %.** Tenant isolation is hardened
  (94 tenant-scoped tables, graph-engine gate, adversarial suite), but a
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

1. **Publish the release CI workflow.** A complete `.github/workflows/docker-build.yml`
   (multi-arch build, SBOM, provenance, digest recording, tag on green runs)
   exists locally but could not be pushed — the automation token lacks the
   `workflow` scope (HTTP 403). Push it from a credential that has it.
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
