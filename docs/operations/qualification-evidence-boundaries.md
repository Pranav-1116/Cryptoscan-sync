# Capacity and recovery: what this implementation actually establishes

## Capacity harness correction

The old load harness could return exit 0 when every request received HTTP 429:
errors were zero and latency appeared as zero. A regression test reproduced that
actual `main()` behavior before the fix. It now fails without successful 2xx
operations, on excessive throttling/errors, failed workers or unconfirmed
revocation of known temporary keys. Useful throughput and p50/p90/p95/p99/max
latency use successful requests only; missing latency is null, not zero.

The parent production-evidence runner rejects old/missing verdicts, no-success
reports and unconfirmed cleanup. It passes passwords via environment rather than
process arguments. This does not make environment variables a secret vault.
Cancellation stops workers before cleanup; revocation attempts continue across
known keys after network failure. A lost key-creation response remains ambiguous:
reconcile key inventory before retrying, including keys whose creation response
was never received. Expiry is a fallback, not confirmed revocation.

A local **2-VU, 3-second** run completed 12 HTTP operations, all 200, with both
minted keys independently confirmed revoked in PostgreSQL. That exercises the
harness/cleanup, **not bank workload capacity, a scanner benchmark, a soak test,
HA, or an agreed latency SLO**. Its percentiles are descriptive of 12 samples;
there is no defensible production p99 extrapolation.

The agreed engineering targets remain open: no correctness regression, no
p95/p99 slowdown and at least 20% improvement for a selected bottleneck, measured
before/after on the same workload and limits. No such paired improvement is
claimed here. Regression execution time under competing compilation/test jobs
is not an application-performance benchmark. No cache/architecture rewrite was
used to manufacture improvement.

## Actual authorized local recovery execution

`controlled_recovery_drill.py` uses the existing backup/restore commands against
an explicitly owned local `cryptoscan_e2e_*` database. It encrypts a logical
backup, refuses a wrong key and modified ciphertext before writes, demonstrates
real psql transactional DDL rollback after a deliberate SQL error, then restores
to a newly created empty database. All reflected table row counts/content digests,
schema 0107 and the audit chain are checked; the original source is unchanged.
The target database and temporary backups/keys are removed.

This is a **quiesced same-host logical restore**, not host destruction, replica
promotion, PITR, deployed API/worker recovery, service RTO/RPO or external key
custody. The measured restore-command duration is not an agreed service RTO.

The existing Redis drill delivered actual SIGKILL after SAVE plus additional
acknowledged writes, then restarted the same private Redis 8.2.4 from RDB:
**105 acknowledged synthetic IDs, 70 recovered, 35 lost** across seven stateful
roles; health/PING has no event-loss denominator. Missing queue/stream IDs were
replayed from the external fsynced witness; other role-specific scratch state was
invalidated/held unknown. This is not all eight production consumers, exactly-once
collector effects, power-loss durability, TLS/ACL/Sentinel/replication, or a bank
zero-loss result. Memory-overcommit warnings remain a stated limitation.

## The original45 and six separate BOMs remain separate

| Output | What this increment changes | What it does not establish |
|---|---|---|
| CBOM | Controlled historical-source decisions, retained evidence, explicit partialness | Complete discovery, correct runtime use, verified PQC migration or bank acceptance |
| NBOM | No new collection/qualification | Segmented, opaque and all protocol/platform coverage |
| TechBOM | Existing relationship data unchanged | Independently observed full dependency completeness |
| HBOM | Existing hardware inventory unchanged | Measured HSM/firmware/platform qualification or app-to-hardware truth |
| VBOM (vendor BOM) | Existing supplier/due-diligence data unchanged | Verified supplier internals, partnerships or signed attestations |
| SBOM | Existing software BOM/digest/deployment workflows unchanged | Complete binary/runtime/component or bank-wide supply-chain coverage |

The [original45 requirement-by-requirement register](bank-original45-engineering-gaps.md)
remains authoritative for outstanding engineering and external acceptance.
These changes strengthen existing workflows; they do not satisfy all45.
Sanctioned platform/protocol tests, independent ground truth, actual migration/
PKI/PQC/HSM performance, deployed residency/security/DR/HA/capacity, legal/policy
review, integrations, commercial references and bank sign-off remain distinct.
No penetration-test report, bank reference, staffed 24/7 response or SLA is
created by these local tests. Scheduling/team availability and urgent incidents
still require real operating arrangements.
