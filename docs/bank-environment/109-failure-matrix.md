# Nine failure modes — each row proven by an executed drill

`cryptoscan.failure-matrix/1` · generated 2026-10-31T17:13:47.258500+00:00 · **9 proven / 0 broken / 0 unproven of 9**

Every row below ran the code that is supposed to survive the failure, with the failure actually injected. `PROVEN` means the drill ran and every check passed; it is never inferred from reading the code. `UNPROVEN` means the drill could not run here or does not exist — it is not a pass.

| Mode | What breaks | Observed behaviour | Verdict |
|---|---|---|---|
| `api` | the API stops answering (database accepts, never replies) | 503 in 4.00s with 'no answer within 4.0s'; liveness stayed up | **PROVEN** |
| `database` | PostgreSQL is lost and a backup must be restored | valid restore; 4 altered artifacts refused (ciphertext-corrupt, manifest-tampered, wrong-encryption-key, wrong-signing-secret) | **PROVEN** |
| `worker` | a worker is killed holding a job | orphan requeued and redelivered with attempts=1; stale RUNNING row FAILED, fresh one left | **PROVEN** |
| `collector` | a collector errors or has no credentials | raise → FAILED + 'inventory is UNKNOWN, no absence of crypto may be inferred'; no credentials → NOT_ATTEMPTED; healthy → COMPLETE | **PROVEN** |
| `agent` | the agent's submission to the API fails | transport raises → {ok: false, error: 'api unreachable'}, no exception escapes; next submit ok: true | **PROVEN** |
| `network` | an endpoint is unreachable or black-holed | black-holed endpoint → UNKNOWN/NO_RESPONSE in 1.61s; closed port → UNKNOWN in 0.00s | **PROVEN** |
| `storage` | the backup volume is corrupt or unwritable | roundtrip from disk OK; corrupt artifact refused; unwritable path raised and the schedule did not advance | **PROVEN** |
| `certificate_expiry` | a certificate in the estate expires | expiry computed from not_after: -1d EXPIRED, ≤7d CRITICAL, ≤30d SOON, else VALID, no not_after → UNKNOWN; expired certificate lands in the NBOM as critical | **PROVEN** |
| `queue` | Redis drops out or a job is SIGKILLed mid-run | enqueue during a Redis outage raised in 0.00s; SIGKILL drill PASS (orphan requeued, redelivered with attempts=1) | **PROVEN** |

## What this does not prove

- `api`: the stalled probe thread is only released when the driver's own timeout expires; the endpoint stops waiting for it, so a probe-heavy interval can still leave orphaned threads
- `database`: the backend is an in-process fake, so this proves the integrity gate, not that a real pg_restore refuses a corrupt dump (see scripts/pitr_drill.py and postgres_drill.py)
- `worker`: Redis here is fakeredis and the lease loss is simulated by deleting the key; the actual SIGKILL is scripts/queue_kill9_drill.py (see the queue row)
- `collector`: the collector is injected, so this proves the runner's status mapping, not any one vendor API's error behaviour
- `agent`: the transport is injected and the agent has no local spool, so findings produced during the outage are dropped rather than replayed — that is the observed behaviour, not a retry
- `network`: no packet loss or asymmetric routing is simulated; the bounded timeouts are the production ones scaled down
- `storage`: the volume is a local temp directory, not the mounted production volume or an S3-compatible sink
- `certificate_expiry`: expiry is evaluated at observation time from the certificate's own not_after; no clock skew or timezone-shifted issuer is simulated, and nothing here renews or rotates
- `queue`: the SIGKILL drill runs against fakeredis; the real-Redis invocation (REDIS_URL=redis://… python scripts/queue_kill9_drill.py) is a bank-host step and was not executed here

And, across all nine rows: these drills run in-process against injected faults, real local files and real sockets. They are not a chaos run against a bank's live estate, and a `PROVEN` row says the code path behaves as specified under that specific fault — not that the deployment is configured correctly, monitored, or that anyone will notice.
