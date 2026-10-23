# Executed isolated recovery — 2026-10-23

## What actually ran, and what did not

The user authorized disposable local PostgreSQL/Redis, synthetic data/artifacts
and test keys. **No existing deployment was touched.** These are executed drills,
not a replacement recovery-plan document. They demonstrate bounded mechanisms,
not bank RPO/RTO, production cutover, whole-site completeness or independent
acceptance. PostgreSQL and Redis exercises ran separately; they are **not a
single transactionally aligned production/site cohort**.

[Raw PostgreSQL cohort result](quality-six-bom-perf-recovery-2026-10-23/cohort-recovery.json),
[raw Redis fault result](quality-six-bom-perf-recovery-2026-10-23/redis-recovery.json),
[native19-test log](quality-six-bom-perf-recovery-2026-10-23/native.log),
[input hashes/results](quality-six-bom-perf-recovery-results-2026-10-23.json).

## PostgreSQL + referenced fixture artifacts + historical keys

Native PostgreSQL**16.2**, UTF8 test databases, migration0106, private Unix socket,
TCP disabled, disposable local trust. Authenticated product routes use real SQL
and server-side sessions through in-process TestClient; this is not a second
production API/worker deployment or a network/SSO/browser qualification.

Executed sequence in `test_isolated_cohort_recovery.py`:

1. Seed the selected synthetic estate: actual stored original SBOM, release/
   deployment, reviewed package/crypto assertion, retained signed supplier blob,
   real sessions, positive execution approval and a claimed RUNNING attempt.
   No collector is launched. The source scan observations are synthetic fixture
   rows, not a newly verified source-finding chain.
2. Quiesce the single-writer fixture. Retain **all145 public SQL tables** with
   per-table logical row hashes, and **all three created fixture files** (approved
   source plus encrypted original SBOM and its manifest). Supplier/evidence blobs
   stored inside SQL are included in the dump. This is complete for this selected
   fixture's SQL/file cohort, **not every production external store or bank estate**.
3. Run the real encrypted `backup_evidence.py`/native `pg_dump`; retain an isolated
   file copy and hashes. Backup and artifact master keys are synthetic, kept out
   of retained reports. Historical artifact key material is required explicitly.
4. After the backup, acknowledge a marker write, withdraw a finding, revoke a
   session and append signer revocation. Capture complete changed SQL rows in a
   privileged operator-side **drill-only** journal. Four rows changed: two assurance
   revisions, one finding and one session. The helper refuses unknown deletions/
   missing identities instead of inferring a successful reconciliation.
5. Fence the old database with actual PostgreSQL `ALLOW_CONNECTIONS false`, then
   terminate existing sessions. An already-open writer fails and a new connection
   fails. Only generated disposable `cs_quality_<uuid>` databases can be fenced.
   This privileged drill action is **not an automatic production failover feature**.
6. Restore into a fresh generated database using the real `restore_evidence.py`/
   native `psql`. Every initial table/file hash matches. Demonstrate the marker is
   absent without the post-backup journal; **do not expose that stale candidate**.
7. Replay all changed SQL rows, preserving full immutable envelopes. Require all
   table hashes to match the source's post-backup quiesced point before switching
   the client session layer. Fence the deliberately expired attempt to UNKNOWN
   using actual current time; retain capacity. Duplicate queue claim and the old
   completion fence are refused. This does not prove stopping an external process.
8. Current trace has no withdrawn path; revoked signer blocks current supplier
   bytes; revoked session cannot read; historical reviewed assertion remains.
9. Accept a new **estate-register API write and evidence-blob API write** after
   cutover. The controlled local-source profile correctly refuses unqualified
   software-supply-chain adapter writes; the drill does **not** disable that rule.
   Separately exercise a synthetic unbound second-generation encrypted object:
   explicit historical/current secrets decrypt their own generation; the wrong
   generation fails. This is not a newly admitted SBOM or automatic keyring.
10. Take a fresh encrypted candidate backup and complete file copy, fence that
    database, restore to a fresh failback target, and compare **all** SQL/file hashes.
    New register/blob and post-backup marker survive; UNKNOWN and signer revocation
    remain. Failback is never implemented by restoring the older snapshot over
    newly accepted writes.

**Measured:** fence-to-verified-candidate **1.224s**; staged failback
**1.055s**. One explicitly acknowledged post-backup marker is
missing without replay and zero are missing after replay. Complete selected SQL
hashes match at the replay and failback checkpoints. These durations exclude
provisioning, migrations, external stores, actual collector shutdown, traffic
routing and human approval: **not an RTO/RPO promise**.

## Actual Redis SIGKILL/RDB loss and role-specific scratch reconciliation

Native Redis**8.2.4**, private Unix socket, standalone RDB, no TLS. For each of
seven event/state roles, write10 synthetic IDs, perform `SAVE`, then acknowledge
five more IDs. Health has no durability events. Fsync an external witness,
**SIGKILL the actual Redis process**, then separately restart the same private
server from its RDB. The finish phase verifies the original IDs, not PING alone.

**105 acknowledged IDs;70 recovered from RDB;35 lost** (five per non-health role).
Fault-to-verified finish including operator restart delay: **8.478s**.
Do not hide this deliberate checkpoint-gap loss with later witness replay.

| Role | Actually executed scratch reconciliation | Boundary |
|---|---|---|
| `realtime` | Replay the five missing IDs from fsynced witness to the Redis stream; all15 IDs present. | Not actual downstream event consumers or external side effects. |
| `queue` | Replay missing hints, add one duplicate, drain a16-item backlog to zero;15 unique IDs and one duplicate detected. |17 timed LPOP operations including terminal empty read; not exactly-once collector execution. SQL duplicate/old-fence denial is a separate native test. |
| `current_run` | Replace restored scratch state with `UNKNOWN_RECOVERY`, pending authoritative reconstruction. | No replayed green completion; actual production consumer not exercised here. |
| `rate_limit` | Saturate scratch counters with a60-second recovery hold instead of resetting to empty allowance. | Consumer error/fail-closed behavior and real admission limits still require integrated qualification. |
| `health` | PING after restart; zero events/loss metric not applicable. | Liveness is not durability. |
| `platform_state` | Replace scratch state with UNKNOWN pending authoritative reconstruction. | No assertion that stale control state is current. |
| `sso_state` | Invalidate every restored scratch cache entry. | Require fresh SQL/auth authority; actual post-backup SQL session revocation separately tested. Not external SSO qualification. |
| `telecom` | Replace restored scratch state with UNKNOWN pending reconstruction. | Not an actual telecom controller/process restart. |

Queue scratch drain measured **1.408ms total**, **0.108ms maximum command**, not a
worker capacity or sustained recovery-load result. Role scratch keys were
removed at finish. All roles used real Redis structures, **not all eight real
application consumers**. No HA, replica promotion, Sentinel, power-loss, TLS/ACL,
load/endurance or single-observer-crash guarantee is inferred. Redis emitted a
memory-overcommit warning; system settings were not silently changed. TLS build
failed for missing OpenSSL development headers; the plain build is not TLS
qualification. Historical builds/versions are not relabeled as current results.

## Proven restore defects fixed, with failing tests first

1. **Native psql could exit0 after SQL errors.** The retained negative test creates
   a table and then executes invalid SQL; the old CLI falsely returned success.
   Restore now uses `--no-psqlrc --set=ON_ERROR_STOP=1 --single-transaction`.
   The real native negative exits nonzero and leaves no partly restored guard table.
2. **Decryption could overwrite an adjacent existing plaintext filename and leave
   plaintext after malformed-manifest errors.** The negative test reproduced this.
   Decryption now occurs inside a private `TemporaryDirectory`, cleaned on every
   exit/exception. Existing adjacent files survive. This does not claim every
   SQLite staging/error path or parser temporary-storage path is newly qualified.

[Original cleanup failure](quality-six-bom-perf-recovery-2026-10-23/restore-negative-cleanup.log),
[original native SQL failure](quality-six-bom-perf-recovery-2026-10-23/restore-negative-sql.log).
Current backup tests, including wrong key/tamper, pass within248; native SQL-error
and cohort/failback tests pass within19. The first broad native run rejected
Unicode JSON in inherited SQL_ASCII databases; fixtures now explicitly use UTF8.
A subsequent run lacked the required native-client-directory environment variable;
it was supplied before the retained complete19-pass run. These were execution
failures/corrections, not hidden production defects or green CI claims.

## Reproduction and outstanding acceptance

Use the [native test environment/command](quality-trace-performance-2026-10-23.md#reproduction-and-safety).
The Redis fault helper is deliberately hard-bound to the separately provisioned
`/home/user/quality-redis.sock`, no TCP, native executable
`/home/user/redis-8.2.4/src/redis-server`, lab `quality-redis-drill.rdb` in
`/home/user`. It refuses other servers; it is **not a deployment fault tool**.
Provision/inspect that disposable lab first. `prepare` genuinely SIGKILLs it;
restart the same lab from its retained RDB **between** the two commands:

```bash
export CRYPTOSCAN_DISPOSABLE_REDIS_OPT_IN=local-synthetic-fault
python scripts/drill_disposable_redis.py prepare \
  --directory /home/user/quality-redis-fault-evidence
# Separately restart ONLY the authorized private lab from its RDB, then:
python scripts/drill_disposable_redis.py finish \
  --directory /home/user/quality-redis-fault-evidence
```

The final cleanup stops both disposable services. A future run needs a fresh
witness directory; never overwrite the acknowledgement witness or substitute
production URLs. Backups/test keys stay outside Git; retained JSON contains
nonsecret hashes and synthetic result counts, not keys or SQL/session dumps.

**Item6 is partially delivered:** real SQL/artifact restore and new-write-
preserving failback, real connection/attempt fences and measured Redis loss are
now executed. A joint production-shaped consistent cohort, integrated consumer
reconciliation, external-process fences, real cutover/failback traffic and
**different-person independent review are still pending**. The reviewer must
check scope/hashes, observed loss, old-writer denial, post-backup revocations,
UNKNOWN reservations and accepted new-write preservation. A same-agent report
cannot supply that review. No production RPO/RTO is offered before that work.
