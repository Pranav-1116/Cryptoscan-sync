# 3.2 — Redis consumers and deployment recovery evidence

## One verified transport contract, explicit consumer scope

Realtime, current-run, worker queue, shared rate limiting, dependency probes,
platform state, SAML replay state and telecom snapshots use the shared verified
TLS/Sentinel factory. They can share a deployment or have explicit role-specific
URLs, ACLs, trust and discovery. A dedicated role URL never accidentally inherits
the original deployment's Sentinel nodes/master. See the
[configuration/rotation upgrade](../runbooks/evidence-assurance-upgrade.md).

Transport verification is not durability. The bounded `probe_role_commands`
exercises list lease/move/ack, counter/expiry, stream/publish, one-time GETDEL and
shared-state GET/SET commands on isolated scratch keys. The full realtime journal
probe additionally exercises its existing transactional command set. Neither
PING nor successful local promotion proves recovery of acknowledged prior events.

## Objective → measurement → separate human review

1. A CISO/administrator creates `/assurance/redis-objectives`: approved deployment
   ID, nonsecret topology/configuration SHA-256, explicit consumer roles, maximum
   recovery time and acknowledged-event loss, minimum recovery throughput and
   duration, evidence reference and maximum measurement age (default 30 days).
2. An operator uploads an immutable bounded measurement JSON blob. The submission
   must exactly match its retained `measurement` object, including timestamps and
   acknowledgement IDs; a string `PASS` or a new snapshot is not accepted.
3. `/redis-objectives/{id}/measurements` computes actual reported elapsed time,
   prior-ACK survival/lost IDs, duration and throughput against those objectives.
   Events acknowledged **before** the fault are mandatory for state-bearing
   roles. Health PING has no durable-event RPO and must not invent such events.
4. A different entitled human reviews `/redis-measurements/{id}/review`.
5. The qualification report requires current, reviewed measurements for every
   requested **role × scenario**. Missing roles are listed as unqualified.
   A later failure or unreviewed run supersedes an older passing scenario;
   ambiguous equally timed runs do not select an older PASS. Changed
   objectives/topology invalidate prior campaign evidence. Expiry is checked at
   report time. This remains operator measurement plus human review, not a claim
   that the API independently witnessed an external fault.

Scenarios: certificate rotation, credential rotation, partition/split brain,
replica lag, disk full, memory pressure, process kill, power loss, backup/restore,
failback, representative recovery load.

## Portable scratch observer

`scripts/redis_recovery_evidence.py` writes a local, fsynced ACK ledger, reads
**those same IDs** after an approved operator-controlled event, and measures
bounded scratch recovery load. It never kills/promotes/partitions a server,
changes ACLs, or touches bank queues. Connection secrets stay in the deployment
secret environment; never paste them into chat or put them in CLI arguments.

```bash
# Run only in a separately approved qualification scope with the role's verified
# Redis settings supplied by your secret/configuration manager. These shell
# variables name REAL approved values, not fabricated approval placeholders.
: "${APPROVED_DEPLOYMENT_ID:?approved deployment ID required}"
: "${APPROVED_TOPOLOGY_SHA256:?approved nonsecret topology digest required}"
: "${QUALIFICATION_DIRECTORY:?new protected local evidence directory required}"
python scripts/redis_recovery_evidence.py prepare \
  --directory "$QUALIFICATION_DIRECTORY" --role queue \
  --deployment-id "$APPROVED_DEPLOYMENT_ID" \
  --topology-sha256 "$APPROVED_TOPOLOGY_SHA256" --events 100

# Perform ONLY the separately authorized, witnessed fault. Then use its actual
# start time and retained operator-log reference, not a guessed promotion time.
: "${WITNESSED_FAULT_START_UTC:?actual timestamp required}"
: "${FAULT_WITNESS_REFERENCE:?retained witness logs required}"
: "${EVIDENCE_REFERENCE:?retained exercise reference required}"
python scripts/redis_recovery_evidence.py finish \
  --directory "$QUALIFICATION_DIRECTORY" --scenario process_kill \
  --fault-at "$WITNESSED_FAULT_START_UTC" \
  --fault-witness "$FAULT_WITNESS_REFERENCE" \
  --evidence-ref "$EVIDENCE_REFERENCE" \
  --load-seconds 30 --operations-per-second 100
```

Upload `measurement.json` as a raw evidence blob, then submit its `measurement`
with the returned `evidence_blob_id`. Review is separate. Retain independent
provider logs and clock evidence. Scratch data has seven-day TTL; command probes
clean their keys. Bound events to 1,000 and load to 100,000 operations/300 seconds.
A failed observer keeps partial local evidence and never self-issues acceptance.
An ACK between the server response and observer fsync can be missing if the
**observer** is killed; an independently durable witness is needed to qualify
that window. Do not claim this script solves observer power-loss accounting.

## What a real exercise must prove

| Fault | Additional retained evidence, not supplied by local unit tests |
|---|---|
| CA/certificate rotation | New chain accepted, wrong host/old disallowed chain rejected, long-lived pools rolled, application commands still work |
| Credential rotation | New ACL credentials work, revoked old credentials fail, discovery and data credentials separately rotated |
| Partition/split brain | Partition boundaries/witness times, rejected stale-primary writes, promotion/fencing behavior, exact prior-ACK reconciliation |
| Replica lag | Measured lag at the fault, observed acknowledged loss, no snapshot substitution |
| Disk/memory pressure | Redis/provider error/eviction/persistence logs, fail-closed application behavior, no hidden memory fallback |
| Kill/power loss | Actual independently witnessed process/host event, durable ACK ledger and persistence recovery, not just restart commands |
| Backup/restore/failback | Backup identity/region/hash, restored old IDs, intended failback authority, application recovery under representative load |
| Recovery load | Approved request mix/concurrency/data size, recovery latency/throughput and continued ACK reconciliation |

A local Redis 8.10.2 private Unix-socket run exercised all eight command probes
and the full journal probe with zero scratch keys left by those probes. An
observer **no-fault smoke test** recovered 3/3 old IDs and wrote 20 load operations.
These are engineering checks only: no deployed certificate/credential rotation,
partition, power-loss, persistence, backup or bank recovery objective was proved.
