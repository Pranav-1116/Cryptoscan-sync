# 45 — Redis TLS/ACL/Sentinel controls and executable qualification

[Guide index](README.md) · [Queue authority and SSH receipts](44-queued-authority-and-durable-ssh.md) · [Replay semantics](42-estate-streams-graphql-and-exports.md)

**Local engineering evidence, 2026-10-21. No production bank service was tested.**
The implementation adds verified transport, explicit discovery credentials,
command-level readiness, subscriber recovery and conservative primary-bound
replay epochs. A disposable one-host TLS/Sentinel lab exercises those controls.
It is not a certificate of production HA, lossless replication, restored-history
completeness, cross-zone availability or security approval of a Redis version.

## 1. Configuration contract

The realtime/current-run client factory is `api/events/redis_backend.py`.
Production startup validates settings and refuses an unusable required journal.

```dotenv
# Illustrative names only. Provision secrets through the approved secret store.
REDIS_URL=rediss://replay:URL_ENCODED_SECRET@redis.internal:6379/0
REDIS_CA_CERTS=/run/secrets/redis-ca.pem
REDIS_SENTINELS=[["sentinel-a.internal",26379],["sentinel-b.internal",26379],["sentinel-c.internal",26379]]
REDIS_SENTINEL_MASTER=estate-events
REDIS_SENTINEL_USERNAME=discovery
REDIS_SENTINEL_PASSWORD=SEPARATE_DISCOVERY_SECRET
```

Do not copy placeholder credentials into a running service. The server name
returned by Sentinel must match a SAN in its data-server certificate; verifying
a Sentinel certificate does not verify the subsequently discovered primary.

Production requirements:

- `rediss://` with a named, non-default ACL user and a password. Anonymous,
  plaintext and Unix-socket realtime production configurations are refused.
- Required certificate verification and hostname verification. URL query flags
  cannot disable either. `REDIS_CA_CERTS` selects an approved CA bundle; when
  omitted, normal system CA verification still applies.
- Optional Sentinel routing uses TLS for **both** discovery and data connections.
  At least three distinct discovery host/port pairs and separate discovery
  credentials must be configured. Distinct addresses do not prove distinct
  machines, availability zones, independent power or a correctly operated quorum.
- Sentinel URL query overrides are rejected; use the explicit supported fields.
- A configured Sentinel master without endpoints is refused.
- Redis Cluster is unsupported: the journal transaction spans keys without a
  cross-slot design. A Cluster URL is not an alternative HA implementation.

Standalone verified TLS remains supported with empty Sentinel fields. It does
not become HA merely by passing these settings checks.

### Important deployment boundary

This increment makes **realtime federation/replay and shared current-run state**
use the factory. It does not migrate worker queues, rate limiting, every cache or
other Redis consumer to Sentinel. Some consumers still construct direct clients
from `REDIS_URL`. A shared URL also needs their separately reviewed commands and
key prefixes; the disposable replay-only ACL below is not a complete API/worker
production ACL. Review service-specific environment overrides and credentials.
Do not announce platform-wide Redis HA based on this factory alone.

## 2. Readiness must execute the journal contract

A server that answers PING or permits reads can still deny XADD or MULTI.
Production startup now exercises the actual append/replay commands using unique
scratch keys under `zelinx:events:qualification:<random-id>`. It:

1. Allocates a disposable sequence through redis-py's increment command.
2. Runs a WATCH/MULTI transaction with stream writes, metadata and publication.
3. Reads and validates the resulting owner-partitioned retained snapshot.
4. Deletes only those scratch keys in `finally`.

The scratch channel is also under the qualification namespace. Bank journals
are not used as test data and no FLUSH command is needed. A failed probe makes
the required federation unready; startup does not silently fall back to local
history and report durable success. Runtime append failures also propagate
rather than inserting an unjournaled local success event.

Review ACLs against the installed redis-py and Redis versions. In this lab,
redis-py's `incr()` sends **INCRBY**. An ACL that only grants INCR passed neither
actual readiness nor publication; the real-server tests caught that mistake.

The replay/current-run command set includes PING, GET, SET, INCRBY, TYPE, EXISTS,
HGETALL, HSET, XRANGE, XREVRANGE, XADD, MULTI, EXEC, DISCARD, WATCH, UNWATCH,
PUBLISH/SUBSCRIBE and subscription cleanup, DEL for scratch cleanup, and applicable
expiry operations. Primary-bound snapshots additionally use **INFO replication
and INFO server**. Channel ACL patterns are separate from key patterns. Do not
solve a missing permission by granting `+@all` to the application.

The lab's broad operator account is **lab-only** and supports orchestration,
ACL-negative checks, WAIT and destructive actions. Discovery uses a separate
restricted observer. Production replication/Sentinel automation needs its own
approved service-account design, not reuse of that operator credential.

## 3. Promotion cannot silently continue a frozen snapshot

Redis replication is asynchronous. A newly promoted primary can have fewer
acknowledged records than its predecessor. If its sequence later catches up,
checking sequence numbers alone can confuse replacement events with the old
frozen snapshot.

For factory-created production clients and Sentinel clients, public estate
replay epochs now combine the stored estate epoch with the **actual Redis
process run ID**. The role and process identity are read on the same watched
connection in the transaction that validates the snapshot, not from a separate
pooled discovery query.

- The source must report `role=master`. A demoted source is refused and its pool
  disconnected, allowing a subsequent attempt to rediscover/reconnect.
- A different process/primary produces a different public epoch. An old cursor
  receives an explicit epoch-changed refusal and requires resynchronization.
- Internal stored frame epochs are checked before conversion to public epochs;
  a corrupt raw frame cannot be hidden by rewriting its public metadata.
- The public epoch is a digest. Raw process IDs and foreign/global sequence IDs
  are not returned as estate history.
- This conservative reset happens even when every event happened to replicate.
  Availability is not traded for an unsupported assertion of old-snapshot
  continuity. API-process restart on the same Redis process does not itself
  change the primary binding.

After a reset the client must explicitly discard its old continuation and
obtain a fresh retained snapshot. A complete **new** retained snapshot is not
proof that previously acknowledged writes survived the promotion. Durable
business records/receipts and approved reconciliation procedures remain
necessary. Restore, manual data mutation, split-brain prevention and operator
control of old primaries still require deployment-specific qualification.

Clients constructed outside this factory retain their explicit backend contract;
this feature does not retroactively make arbitrary raw Redis clients HA-aware.

## 4. Subscriber recovery is not durable delivery

The Pub/Sub listener now reconnects with bounded exponential backoff from 0.1 to
5 seconds and an interruptible stop event. Reconnection rechecks required journal
commands before declaring readiness. Quiet channels use bounded message polling,
not an idle blocking socket timeout treated as an outage. Unready periods remain
visible in federation health.

Notifications missed during a disconnect are not reconstructed from Pub/Sub.
The per-estate journal and existing polling/replay path remain authoritative.
The reconnect test exercises a broken subscription, command revalidation, an
idle poll, subsequent remote delivery and resource cleanup. This is not a claim
of exactly-once notifications, bounded recovery under every partition, or a
production availability SLO.

## 5. Prepare the disposable six-node lab

**Never point this destructive harness at bank Redis.** It changes ACLs, requests
failover and shuts down a primary. Both opt-in environment guards are required.
Use an isolated disposable host/container network, firewall the ports, and keep
all generated state outside the repository. Fixtures bind to `0.0.0.0` for this
sandbox; they are not production listener policy.

Prerequisites: Python/test dependencies, `openssl`, and an independently obtained
TLS-enabled `redis-server`. The observed lab used **Redis 8.10.2** built with
`BUILD_TLS=yes`, not a vendored binary or a recommendation to deploy that version
without the bank's current patch/support review.

```bash
# Run from the repository root; choose a NEW empty private directory.
LAB="$HOME/.cache/estate-replay-lab"
python scripts/prepare_replay_redis_lab.py --state-dir "$LAB"
```

The generator does not launch processes. It refuses a nonempty directory and
creates private files with restrictive permissions: a short-lived self-signed
CA, server key/certificate, random account credentials, six configs and
`lab.json`. Never commit, attach or print these credentials. The test certificate
has IP SAN `127.0.0.1` only, intentionally making `localhost` fail verification.
The private CA and server certificate expire after two days.

Start each command below in its **own supervised terminal/process**, substituting
your approved lab binary path. Do not run them sequentially in one blocking shell:

```bash
REDIS_SERVER=/absolute/path/to/tls-enabled/redis-server
# Terminal/process 1
"$REDIS_SERVER" "$LAB/redis-15379.conf"
# Terminal/process 2
"$REDIS_SERVER" "$LAB/redis-15380.conf"
# Terminal/process 3
"$REDIS_SERVER" "$LAB/redis-15381.conf"
# Terminal/process 4
"$REDIS_SERVER" "$LAB/sentinel-16379.conf" --sentinel
# Terminal/process 5
"$REDIS_SERVER" "$LAB/sentinel-16380.conf" --sentinel
# Terminal/process 6
"$REDIS_SERVER" "$LAB/sentinel-16381.conf" --sentinel
```

Export `LAB`/`REDIS_SERVER` appropriately in each terminal. Wait for replication
and discovery to stabilize before running the suite. The generated topology has:

- Three data processes; three TLS Sentinel processes; default user disabled.
- Scoped replay key/channel ACLs, restricted observer, read-only negative fixture
  and private lab operator credentials.
- AOF with `appendfsync always`, minimum one healthy replica for writes, maximum
  replica lag five seconds, Sentinel quorum two, one-second down detection and
  five-second failover timeout. These short lab timings are not production tuning.

The replay user is a trusted backend service identity, not an end-user/tenant
credential. It can access the shared service's bank partitions; per-estate HTTP/
SSE/WS isolation remains the API's fresh-authority boundary.

## 6. Execute qualification and interpret the evidence

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
ESTATE_REPLAY_REDIS_LAB="$LAB/lab.json" \
ESTATE_REPLAY_ALLOW_DESTRUCTIVE_LAB=1 \
python -m pytest -q \
  services/api/tests/unit/test_replay_redis_security.py \
  services/api/tests/integration/test_replay_redis_tls_sentinel.py \
  --timeout=60
```

Without both guards the eight real-server cases skip, not pass. The unit cases
still run. Every integration test uses a unique namespace and deletes only its
own keys. The destructive cases deliberately leave a primary stopped. Restore
that node and let all replicas/discovery converge, or provision a fresh isolated
lab, before repeating; Sentinel rewrites topology configuration during failover.
Do not run simultaneous destructive suites against one lab.

| Experiment | What is checked |
|---|---|
| Verified TLS and ACL | Actual journal commands pass; unrelated keys/channels, CONFIG and FLUSHALL are denied (FLUSHALL checked through privileged ACL DRYRUN, never executed) |
| Wrong password, wrong CA, hostname mismatch | Connection refused rather than disabling verification |
| PING/read-only ACL | Cannot become required write-journal ready; no local accepted event |
| Runtime XADD revocation | Publication refused; no locally invented success; later permitted writes preserve estate sequence |
| Planned Sentinel promotion | Converged discovery and real old-primary demotion; old cursor refuses; fresh estate-only pages reconcile all fixture events |
| Primary SHUTDOWN NOSAVE | Actual primary stops; elected healthy primary supports explicit reset and fresh retained replay, then new writes |

For the two promotion experiments, an operator writes a marker **after** fixture
events and executes `WAIT 2` on that same connection. This measured barrier
establishes the experiment's replicated input. It does **not** add WAIT to normal
application commits or prove lossless asynchronous replication. Promotion waits
for all three discovery endpoints to agree, old-primary demotion/unavailability,
and `min_slaves_good_slaves >= 1`, not merely a TCP-connected replica.

### Observed execution ledger

- The fresh real TLS/Sentinel plus unit run completed **28 passed, 3 warnings,
  26.83 seconds**: 20 unit cases and 8 real-server cases. It includes the
  primary-bound cursor reset, both promotion actions, quiet-channel polling and
  production direct-client binding. The earlier pre-interruption run also passed;
  this result is a separate fresh-lab execution, not a resumed process.
- An earlier 26-pass run predates the cursor-binding addition. An intermediate
  cursor test run failed because one Sentinel announcement was treated as full
  discovery convergence. The harness was corrected to wait for actual converged
  discovery and demotion, not to permit old-epoch continuation.
- After workspace restoration, the focused queue/SSH/security/production and
  adapted legacy suites completed **151 passed, 4 warnings, 25.06 seconds**.
  This includes quiet-channel polling and production direct-client epoch binding.
- The restored broad affected worker/API regression completed **1315 passed,
  4 skipped, 10 warnings, 420.80 seconds**. It covers all worker unit tests plus
  queue/SSH/admission, network, replay, stream, cross-surface/history, monitor and
  trigger contracts. Four optional tests skipped; this is not an entire-repository
  or real PostgreSQL run.
- The final publication-focused run completed **205 passed, 4 warnings, 27.32
  seconds** after the final typed-monitor/reserved-name controls. It reran the
  affected queue/SSH/security/production/routing/monitor producer contracts and
  existing durable-event, federation and estate-replay suites. The broader run
  preceded this final small increment; it was not rerun in full afterward.
- The earlier interrupted broad regression has no completed result. The final
  disposable lab processes were stopped after qualification; private generated
  certificates, credentials and compiled runtime remain outside the repository.

Counts overlap and must not be added together as independent coverage. The broad
run also reported existing blocked-network/evidence-model/async-mark warnings;
these and Pydantic/Starlette deprecations are not test failures.
No production topology, production secrets or bank target was involved.

## 7. Production release checklist — still external work

Before approving a real deployment, retain signed evidence for:

1. Approved Redis/redis-py versions, patch review, topology, independent failure
   domains, quorum behavior and no accidental Cluster cross-slot configuration.
2. Certificate SANs for every discovered endpoint, CA distribution/rotation,
   expiry alerts, revocation procedures and separately reviewed service accounts.
3. Key/channel ACL denies, command readiness, credential rotation/revocation,
   metrics, paging and controlled degraded/readiness behavior.
4. Persistence policy, no-eviction/capacity plan, per-estate retention sizing,
   restored receipt reconciliation and explicit epoch-reset procedures.
5. Failure under representative load: kill -9, power loss, packet loss,
   partitions, split brain, lag, disk full, memory pressure, contention, ambiguous
   writes, failback and recoveries. The graceful lab shutdown does not cover these.
6. Backup/restore and RPO/RTO verification across actual zones/regions. AOF always
   and minimum replicas are server policies, not proof of quorum commits.
7. All other Redis consumers, including queues and rate limiting. The replay
   factory is not an estate-wide redis-client migration.
8. Browser resynchronization, disconnect/reconnect, access revocation and exact
   bank A/bank B/platform denial tests against the deployed HTTP/WS/SSE estate.

Redis only redelivers stored facts. It cannot invent missing SBOM, NBOM, CBOM,
TechBOM, HBOM or VBOM evidence, refresh observation timestamps, certify a vendor,
or prove all bank assets were scanned. A01/A02 and broader bank certification
remain partial despite this implemented increment.
