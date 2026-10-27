# External and regulated readiness

> **Production implementation substantially complete, operational
> qualification in progress.**

That sentence is `update.md` section 6's own wording, and it is the correct
status until the artifacts below exist. This page says, per item, what the
repository can show and what it cannot — so nobody has to infer the
difference from a green test suite.

Section 6 opens with the reason: *"You cannot claim external qualification
merely because the code and tests pass."* Everything here is deliberately
unflattering, because a procurement reviewer who finds one overstated row
discounts the rest of the pack.

## How to read the evidence column

The tiers are the ones enforced by
[`config/control-register.yaml`](../../config/control-register.yaml) and
[`scripts/control_register.py`](../../scripts/control_register.py):
**repository control** (code exists), **operational record** (it was run and
dated), **customer attestation** (the customer signed), **external
certification** (an independent body certified). The gate refuses a claim
that outranks its evidence, and the top two cannot be self-issued.

## The fifteen items

| # | Item | Best evidence today | Tier | What is missing |
|---|---|---|---|---|
| 1 | Deployment architecture | `k8s/`, `docker-compose.prod.yml`, `scripts/run_local_stack.sh` | repository control | No deployed reference environment; topology is described, not operated |
| 2 | Access control | RBAC + ABAC middleware, 728/728 routes auth-covered (engineering gate) | repository control | No access review record, no joiner/mover/leaver evidence |
| 3 | Tenant isolation | ORM guard, fail-closed middleware, 30-test battery, `cryptoscan_tenant_isolation_violation_total` | repository control | **Three leaks were found in this control by inspection.** Needs independent testing — see note below |
| 4 | Secret handling | Evidence redaction tests; key *metadata* only; `db_backup.sh` refuses plaintext when encryption is required | repository control | No secrets-manager integration record, no rotation evidence |
| 5 | Backup and restore | Backup/restore drill 12/12, PostgreSQL DR 35/35 (RPO 0.0 s, RTO 0.15 s) | operational record | One host, local sandbox. No off-host copy, retention, destruction or encrypted round trip |
| 6 | Vulnerability management | Dependabot, pinned lockfile, one dated dependency audit | repository control | A single audit is not a programme; no triage-to-closure record, no patch SLA |
| 7 | Logging and audit retention | Tamper-evident audit hash chain, verified on a restored copy | repository control | No retention period defined, no WORM destination, no shipping record |
| 8 | Scanner accuracy | Corpus benchmark; 16-family fixture qualification, 0 violations | repository control | Self-scored against own corpus. No customer-sample validation (COBOL/PL-I/RPG remain SKIP) |
| 9 | False-positive handling | Triage endpoints, confidence and `confidence_reason` on every finding | repository control | No measured FP rate on customer code, no reviewed sample |
| 10 | HSM / payment controls | TR-31 parsing (metadata only), PKCS#11 against SoftHSM2 in CI | repository control | SoftHSM is **not** a customer HSM. No CloudHSM / Luna / Utimaco qualification |
| 11 | Cloud least-privilege | Read-only scanners, no-ambient-credentials test fixture | repository control | No live run against a customer tenant, no denied-permission evidence |
| 12 | Network authorization | SSRF guard refuses loopback/link-local/metadata; scan targets confined to `CRYPTOSCAN_SOURCE_ROOTS` | repository control | No signed authorization-to-scan for any real target |
| 13 | Incident response | — | **none** | No plan, no notification window, no exercise. See `config/operational-policy.yaml` for the draft |
| 14 | Customer responsibility boundaries | `shared_models/platform_scope.py`, served at `/platform/scope`, test-enforced | repository control | Not countersigned by any customer |
| 15 | Security review / penetration test | Scope document, own cross-tenant battery | **none** | No independent test has been performed |

## Two items that cannot be closed from inside

**Item 3 and item 15 are the same problem.** Three cross-tenant leaks have
now been found in this codebase — in the repository filters, in the
middleware that enters the scope, and in the worker that never entered one.
Each failed open and failed silently, so absence of errors was never
evidence the control worked. I wrote both the current isolation and the
tests that check it, which is the weakest form of assurance available.

An independent penetration test is therefore not a box to tick after the
engineering is done. On this control it is the only assurance that means
anything, and the evidence so far argues for it rather than against it.

## What changed the honest answer, and what did not

Running the product found defects that reading it did not: a DR drill whose
RPO check could never pass, a scan trigger with no path containment that
walked `/etc`, an SSE endpoint that ignored `Last-Event-ID`, an SBOM that
reported 21/21 components pinned when 18 had unresolved versions. Those are
now fixed and covered.

None of that moves items 1–15 above `repository control` on its own.
Qualification is an *operational* property: it needs the real topology, real
credentials, real customer samples and an independent reviewer. The code
being right is a precondition, not the evidence.
