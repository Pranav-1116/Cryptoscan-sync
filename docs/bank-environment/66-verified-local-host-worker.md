# 66. Verified-source local host worker — development candidate

This implements the next executable slice after [65](65-signed-collector-isolation-and-native-gates.md). It does **not** declare production admission, independent acceptance, physical-host attestation, positive TPM/DMI/systemd qualification or native Windows success.

## What runs now

| Control | Actual implementation | Boundary |
|---|---|---|
| Source release | External Ed25519 signature over exact bounded source-lock bytes; approval pins their SHA-256 | Separate from the envelope signer; no private keys in these tools |
| Installed stage | Read-only/no-follow regular-file traversal, per-file digests, measured interpreter **file**, verified private source copy | Trusted supervisor/verifier, Python dependencies/loader/OS and same-UID tampering remain outside attestation |
| Worker authority | Existing tenant-scoped `AssuranceRevision` target/job chain, immutable target row as mutex | No new queue, fleet service, migration or production execution profile |
| Human authority | Typed user/session incarnation, current user/credential, roles, estate membership and active tenant | No literal username/service-account bypass; expired/revoked enqueue credentials stop collection |
| Admission | Target revision/hash, approval, manifest, system environment, time window, policy stop/exclusions | Reopened DB sessions before spawn, during collection and before durable result publication |
| Runtime | Real Landlock/seccomp, fixed child command, read-only file/proc/sysfs leaves, bounded output/resources | No systemd bus/subprocess or native Windows sandbox; no unsandboxed fallback |
| Cancellation | Expected-revision cancel; checkpoint exception kills/reaps the child; parent-death SIGKILL armed before stage imports | DB calls still depend on configured DB availability/timeouts; not a proved whole-worker hard deadline |
| Result | Public metadata snapshot in existing scoped `AssuranceBlob`, digest and blob reference committed atomically with audited job revision | Not an intake/Scan, not a new observation approval; raw recovery retains existing `assurance.raw` authorization |
| Intake | Approved external signer + original host-evidence endpoint; exact committed worker snapshot required | A valid signer cannot substitute a different worker snapshot; provenance stays IMPORTED |

The local binding supplies tenant, target, system, host **labels**, release public key and approved release digest. Labels are not proof that the machine has that physical identity, nor that an offline file originated on that host. The source-lock signer can be different from the approved snapshot-envelope signer. Neither establishes a protected key store, attested clock, measured boot or TPM quote.

## 1. Release bytes and operator trust

Use an ordinary Linux x86_64 account and the approved development environment. Do not disable controlled-production enforcement to make this candidate run in a customer deployment. The existing production boundary still refuses this adapter.

```bash
python scripts/collector_source_lock.py \
  --root "$PWD" --output /approved/collector-source-lock.json
sha256sum /approved/collector-source-lock.json
```

The helper exclusive-creates a 0600 public lock. It includes reviewed stage scripts, inventory parser sources and shared model/data files, with at most 256 files and 8 MiB source bytes. Interpreter-file measurement is separately bounded to 32 MiB. Locks are strict, duplicate-key JSON is rejected, and paths cannot escape the two source roots or the two fixed stage scripts. Source symlinks/hard links/special files are not shortcuts.

Send the **exact bytes**, without reformatting, to the separately administered release signer. Store its detached Ed25519 signature as base64 text in `/approved/collector-source-lock.signature`. This implementation never reads or creates a persistent release private key. Approve the lock hash and independently provision its public verification key on the node.

At execution the verifier checks the approval-pinned lock hash and external signature, reads each selected source with checked descriptors, verifies its digest, and writes a new private staging tree. The child imports from that copy, not from the mutable checkout. Staging is removed on normal success/refusal. An abrupt supervisor SIGKILL can leave its temporary directory: inspect and remove only owned `cryptoscan-verified-stage-*` / `cryptoscan-isolated-*` leftovers after proving no related process is active. No automatic broad `/tmp` deletion is supplied.

**Do not overread this control:** the verifier/supervisor and imported dependencies are trusted. The interpreter measurement is of a file, not a sealed measured-execution chain; launch races, loader/dependency replacement, same-UID interference and a hostile kernel are not solved. The worker controller/CLI itself is not fully measured by the stage lock. `host_attested` and `dependencies_attested` remain false. Restricted OS accounts, release distribution, custody, independent acceptance and stronger executable/host measurements are still required before production.

## 2. Bind and authorize explicitly

A local administrator provisions `LocalWorkerBinding` using [its schema](../../shared/shared_models/shared_models/schemas/local-worker-binding-v1.schema.json). Keep the binding, install root, output directory and DB configuration under operator control, not queue/API caller control. The public binding contains:

- `binding_id`, `tenant_id` (explicitly nullable for a platform estate);
- `system_id`, exact `target_id` UUID and approved `host_id`;
- `source_lock_sha256`, `release_public_key` (raw Ed25519 public key, base64).

Register the ordinary Phase 1 target with explicit paths/resources. In its admin authorization request add:

```json
{
  "worker": {
    "binding_id": "payments-local-node",
    "source_lock_sha256": "<actual SHA-256 of externally signed source-lock bytes>"
  },
  "collector_identity": {
    "key_id": "approved-envelope-signer",
    "public_key": "<approved raw Ed25519 envelope verification key in base64>",
    "release_sha256": "<same actual source-lock SHA-256>"
  }
}
```

This is an **excerpt with placeholders**, not a complete valid request; retain `expected_revision`, `evidence_ref` and `reason` from [Phase 1](62-universal-collection-foundation.md). Authorization refuses a worker pin without a matching collector-identity release digest. It does not accept private signing keys, arbitrary commands, node paths or per-job verification keys.

## 3. Durable job sequence and local run

Create the existing target-bound job. `POST /api/v1/collection/jobs/{id}/enqueue` takes the normal revision/decision body, for example:

```json
{
  "expected_revision": 1,
  "evidence_ref": "change/local-host-candidate-17",
  "reason": "Approved scoped local metadata collection for development qualification"
}
```

The current typed human session must have `assurance.manage`. Reader, cross-tenant, stale-revision, unbound and duplicate enqueue requests fail. HTTP handlers do not execute the collector. The local worker receives a **job identifier only** and separately trusted operator configuration:

```bash
python scripts/run_local_host_worker.py \
  --acknowledge-local-development \
  --binding /approved/payments-worker-binding.json \
  --source-lock /approved/collector-source-lock.json \
  --release-signature /approved/collector-source-lock.signature \
  --root /approved/CryproScan \
  --job-id "$APPROVED_JOB_ID" \
  --output /approved/public-snapshot.json
```

States are `READY → QUEUED → RUNNING → AWAITING_EVIDENCE →` the original `COMPLETED/PARTIAL/FAILED` evidence outcomes. Execution refusal after claim records `REFUSED`; cancellation records `CANCELLED`. A wrong binding/release is refused before consuming a claim. Claims have a random secret in process memory; only its hash is recorded. Two concurrent claims cannot both become RUNNING. No stale-claim timeout or takeover exists: after a crash, cancel the stale job and obtain fresh explicit authorization rather than replaying acquisition automatically.

`POST /jobs/{id}/cancel` also takes an expected-revision decision. Cancellation is allowed for this worker's QUEUED/RUNNING/AWAITING_EVIDENCE states. It does not erase already imported evidence or retract an existing external signature. A stale concurrent cancel may return 409; reread before any explicit retry.

The snapshot is durably stored before the CLI exclusive-creates its 0600 output. If file creation fails or the process exits after result commit, do **not** rerun collection. Read the job's `worker_snapshot_blob_id` and recover the exact public JSON using the existing admin/CISO raw endpoint:

`GET /api/v1/assurance/evidence-blobs/{blob_id}/content`

Existing typed `assurance.raw`, exact-estate and no-store protections still apply; analysts do not gain raw-blob download rights. Retention/backup policy must include this artifact. Missing, oversized, tampered or unauditable results are not silently accepted.

## 4. External signer and six views, not six collections

Use the current approval export as trusted public input. Prepare the original signature statement:

```bash
python scripts/collector_identity.py prepare \
  --approval /approved/current-approval.json \
  --snapshot /approved/public-snapshot.json \
  --output /approved/statement-to-sign.json
```

The external approved collector signer signs the canonical statement using the existing protocol; use the existing `verify` command before normal host-evidence intake. Then complete the job using its current revision. An approved key signing another snapshot does **not** satisfy the worker-result commitment. Existing signature/nonce/release/approval/window checks remain in force.

`GET /jobs/{id}/evidence` and `/projections` preserve NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM references to one original intake. Unsupported surfaces remain empty/UNKNOWN; observations are not forced into every BOM. Runtime invocation, PQC use, policy clearance, whole-host coverage and manufactured relationships remain unproven. CycloneDX claims still use the existing separately schema-validated export.

## 5. Native interface isolation and the next real gate

Explicit process/maps/cpu0 and current-netns TCP/TCP6 are supported by the Linux stage. Process identity race checks, byte budgets/digests and receipt semantics remain in the existing reader. Read-only exact proc/sysfs leaves are checked as kernel filesystem objects.

Proc net table opens can receive different inodes, so a Landlock rule on one open is insufficient for a later lookup. The child instead retains **only the explicitly approved TCP/TCP6 read-only verified descriptors** before enforcement and consumes those capabilities. It never grants `/proc`, a PID directory, or a net subtree. Unapproved environment, command line, UDP, maps and ordinary sensitive files remain unreadable in the negative witness. Opening or probing sockets is still denied by seccomp; observing an already owned listening socket is not an active network scan.

DMI/TPM leaf paths can enter the same stage, but a missing or denied native interface produces a gap, not positive qualification. Systemd execution and Windows still refuse the isolated profile. To require actual isolation in a reviewed expected-truth fixture:

```bash
python scripts/qualify_host_profile.py \
  --target /approved/native-target.json \
  --expectations /approved/independently-reviewed-truth.json \
  --output /approved/native-isolated-result.json --isolated
```

The fixture plan must be independently authored before measurement. Exit 0 is only `PASS_SCOPED_FIXTURE`; exit 2 indicates actual receipt gaps/truth mismatch, and exit 64 indicates invalid/refused execution/scope/output. No fallback, no absent-device pass and no independent-review claim from an operator reference.

**Next required external work:** approved ordinary-user native systemd/DMI/TPM hosts and native Windows execution; protected signer custody and a separately designed verified boot/executable/host/clock chain; independent full worker/control-plane/runtime/cleanup qualification and bank acceptance. This increment supplies runnable controls and negative tests, not that external evidence. [Execution report](../readiness-evidence/host-worker-2026-10-24.md).
