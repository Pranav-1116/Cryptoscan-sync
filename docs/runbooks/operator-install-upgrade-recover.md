# Operator package: install, coordinated upgrade and recovery

Original engineering increment: **2026-10-21**, migration **0104**; current build
head **0106**. This is an executable
package-integrity/preflight boundary and a reference site profile, **not a signed
release, bank capacity result, supported vendor certification, or witnessed site
recovery acceptance**. No real registry digests, signing authority or site
credentials were supplied. The tool deliberately cannot invent them.

## 1. Topology and support boundary

| Profile | Engineering support | Before site acceptance |
|---|---|---|
| `kubernetes-external-services/local-source-v1` | API + dedicated dispatcher/worker + frontend; regional external PostgreSQL and verified-TLS Redis; networkless digest-pinned parser launched by the dedicated runtime; exact-estate assurance metadata | Real immutable images, dedicated runtime, storage/CA/secret provisioning, isolation and restore drills, PostgreSQL contention, signed release and customer approval |
| SQLite / inline parser / stock development Compose | Developer tests only; not this production profile | Cannot be promoted by setting an override |
| Shared untrusted tenants on a Docker-daemon worker node | Not supported as a hostile multi-tenant isolation boundary | Use separately reviewed infrastructure isolation; daemon access is root-equivalent |
| Live TLS/SSH/cloud/vendor acquisition in controlled production | Refused; retained/imported qualified receipts can be reviewed as metadata | Separately approved collector adapters, not this package |
| Neo4j, HA/failover, cross-region active/active | Not qualified by this profile; graph remains disabled | Separate topology and witnessed acceptance |

Reference deployment input: [`deploy/operator-profile/site.example.yaml`](../../deploy/operator-profile/site.example.yaml).
It intentionally contains invalid `REPLACE_*` values. **Never apply it directly.**
The package validator refuses mutable images and unresolved placeholders. Keep
site manifests outside the checkout and provide every required value explicitly.

## 2. Provision prerequisites without embedding secrets

1. Choose the namespace, HTTPS console host/ingress class, registry, legal estate,
   execution region, evidence region and SQL destination. Bind them to the site's
   approved estate policy. Destination strings alone do not prove residency.
2. Provision regional PostgreSQL with hostname-verified TLS (`sslmode=verify-full`,
   mounted `PGSSLROOTCERT`), backups and tested restore. Use a least-privilege
   runtime account and a separately controlled migration account. This increment
   does not validate a particular PostgreSQL major or a customer's HA topology.
3. Provision Redis with verified TLS (`rediss://`), trusted CA, role ACLs and the
   existing eight-role configuration. See [Redis qualification](../bank-environment/47-redis-consumer-and-recovery-evidence.md).
   Do not use a new healthy snapshot as proof that old acknowledgements survived.
4. In the namespace, provision `cryptoscan-runtime` via the organization's secret
   manager: `DATABASE_URL`, Redis credentials/configuration, authentication and
   session secrets, and the deployment's production validation settings. In
   particular supply distinct approved values for `SECRET_KEY`, `STREAM_SECRET`,
   `METRICS_TOKEN`, `REGISTRY_WEBHOOK_SECRET`, `CBOM_SIGNING_SECRET` and
   `AUDITOR_API_KEY` (each at least 32 characters), `GITHUB_WEBHOOK_SECRET` (at
   least 24), `ADMIN_USERNAME` and a valid `ADMIN_PASSWORD_HASH`. Generate the
   bootstrap hash with `python scripts/hash_admin_password.py` in a protected
   interactive environment (no password argument, logs or shell history); place
   only the resulting hash into the secret manager. An empty users table is
   initialized with this bootstrap human superadmin at API startup; an existing
   user table is not overwritten. Sign in, create the independently authorized
   reviewer/operator accounts through the allowed auth administration API, and
   protect/rotate the bootstrap authority according to site policy. **No Secret YAML, passwords, bearer tokens or signing
   keys belong in the package.** Review secret `envFrom` keys: they must not
   override `ENVIRONMENT`, region/destination, controls, parser or staging settings.
5. Provision `cryptoscan-ca` with `postgres-ca.pem`, `redis-ca.pem` and
   `organization-ca.pem`. Mount it read-only at `/site-ca`; review expiry,
   hostname validation, rotation overlap and rollback. Provision ingress TLS
   separately. The validator checks declared references/mounts, not certificate
   validity or whether a secret has actually been provisioned.
6. Provision the `approved-source` PVC read-only to API/worker at
   `/approved-source`. Grant each estate only its approved path; don't use a
   shared PVC as proof of tenant isolation. Restrict execution-control policies
   to the actual estate's source root and permissions.
7. Provision a **dedicated worker node**, Docker daemon and private staging
   directory `/tmp/cryptoscan-workspaces` writable only by the reviewed dispatcher
   identity. The directory must exist at the **same absolute path** inside the
   worker and on the daemon host. Set `WORKSPACE_BASE_PATH` and `WORKSPACE_BASE`
   to this path. Never use a PVC path that only exists inside the worker as a
   daemon bind source. Set the actual socket GID; never `chmod 666` the socket.
8. The stock worker image does not contain a Docker CLI. Build the dedicated
   dispatcher with [`.docker/worker-runtime/Dockerfile`](../../.docker/worker-runtime/Dockerfile),
   supplying **reviewed digest-pinned** `WORKER_IMAGE` and `DOCKER_CLI_IMAGE` build
   arguments. Publish and record the resulting worker digest. This CLI/daemon
   access belongs only to the trusted dispatcher, **never the parser**. Review
   [source isolation](../dev/scanner-isolation.md) and run the real hostile-input,
   daemon-loss and orphan/fence drills before accepting the runtime.
9. Publish API, worker, parser and frontend images from the same reviewed source
   release. Rebuild the parser to include the approved parser revision. The
   frontend's same-origin `/api` proxy expects the API Service named `api:8010`.
   No browser code should call localhost or an internal backend hostname.
10. Set the explicit `CRYPTOSCAN_DEPLOYMENT_PROFILE` in **both** API and worker
    container `env` to `kubernetes-external-services/local-source-v1`, together
    with `ENVIRONMENT=production` and execution controls. The validator requires
    these pins after secret envFrom. This profile rejects configured graph and
    does not require dummy Neo4j credentials; keep `NEO4J_URI` empty. Startup
    skips graph schema acquisition and readiness labels the intentionally
    disabled realtime adapter SKIPPED while retaining real SQL/Redis checks.
    Other/unknown profile names do not silently gain this exception.
11. Set `CORS_ORIGINS` to the exact HTTPS console origin and `TRUSTED_HOSTS` to
    a JSON host allowlist. The template's API health probes explicitly use that
    console Host header; do not leave probes sending a pod-IP Host that the
    allowlist rejects. No wildcard host/CORS override is part of this profile.

## 3. Build, sign externally and verify the complete package

Copy the reference YAML to `$SITE_MANIFESTS`, replace **every** site value and
add the site's approved resources (network policy, PVC definitions if managed
here, imagePullSecrets, resource limits and ingress annotations). Keep actual
Secret resources outside the package. All init/sidecar/frontend images must also
be digest-pinned. Do not mix this with the legacy unreviewed manifests.

```bash
python scripts/operator_release.py build \
  --source "$SITE_MANIFESTS" --out "$RELEASE_PACKAGE" \
  --release "$RELEASE_ID" --registry "$RELEASE_REGISTRY" \
  --api-digest "$API_DIGEST" --worker-digest "$WORKER_DIGEST" \
  --neo4j-digest "$RESERVED_NEO4J_DIGEST" --parser-image "$PARSER_IMAGE"
```

Digests must be the real registry SHA256 values. The legacy attestation schema
requires a Neo4j digest even when graph is disabled: the reserved entry is **not
permission to deploy or enable graph**. The package also inventories the parser,
frontend and every sidecar image. Output must be a **new, disjoint directory**;
existing releases are never overwritten. No signing occurs in this tool.

The external release authority signs the exact bytes of
`release-image-lock.json` using the existing Ed25519 attestation format. Its
`files_sha256` field binds **all** manifests, runbooks, compatibility metadata and
bundled verifier scripts. The detached attestation contains:

- `schema: cryptoscan.release-attestation/1`, `algorithm: Ed25519`;
- `signed_file: release-image-lock.json`, the exact `lock_sha256`;
- the approved authority's `key_id` and strict-base64 64-byte signature.

Keep the detached attestation and trusted public key **outside** the package
inventory. Distribute the public-key fingerprint via an independent approved
channel. A key included beside a package is not automatically a trust anchor.
Run the verifier from the trusted checkout/verification installation, not from
an unverified package. Only after initial verification may its bundled copy be
trusted for subsequent operations.

```bash
python scripts/operator_release.py verify \
  --package "$RELEASE_PACKAGE" --public-key "$TRUSTED_RELEASE_PUBLIC_KEY" \
  --attestation "$DETACHED_RELEASE_ATTESTATION"
```

Any changed/missing/extra file, symlink, changed digest, unpinned image, embedded
Secret, absent CA declaration or invalid signature fails. A PASS establishes
package integrity, **not deployed readiness**. Reports/attestations written into
the package count as extra files and deliberately invalidate its inventory.

## 4. Air-gap procedure

Use the same signed package without editing it after transfer. Prepare the
verification host's approved Python 3.11+ environment with `cryptography==50.0.1`
and `PyYAML==6.0.3` plus their approved transitive dependencies from a separately
signed/hash-verified offline wheelhouse. The package does not download or bundle
unreviewed dependencies. Export the exact multi-platform OCI artifacts using an
approved digest-preserving tool such as `skopeo copy --all --preserve-digests`.
Keep a separately signed OCI/archive transfer inventory; **a SHA256 of a tar file
is not the image's OCI manifest digest**.

On the receiving side verify the transfer inventory, import into the private
registry preserving manifest digests, configure trusted registry CA/DNS, then run
the offline verifier above. The registry names in the signed manifests must
resolve to the approved mirror. If names or bytes change, rebuild and re-sign a
new package—never patch a signed manifest. Preload the exact parser digest into
the worker daemon as well as API/worker/frontend images into the orchestration
runtime. `docker load` success alone does not prove a `repo@sha256` reference is
available; inspect/pull the exact immutable reference from the approved mirror.

## 5. Preflight, install and smoke checks

1. Run offline verification first. With an authorized kubeconfig, add
   `--cluster-preflight` to perform strict **server-side dry-run admission**. It
   does not create resources or silently deploy. Inspect RBAC, namespace policy,
   requested resources, network-policy and volume admission failures locally.
2. Confirm referenced Secrets/PVCs/registry trust exist, mount permissions work,
   every worker's Docker CLI reaches the approved daemon, the parser digest is
   preloaded and host/worker staging paths resolve identically. These runtime
   checks are not established by server dry-run. Run the existing API `/readyz`
   and source-isolation/Redis fault exercises in a disposable estate.
3. Quiesce all producers and old workers. Take a consistent encrypted regional
   SQL backup and evidence/blob backup with a manifest; restore it in a disposable
   isolated instance and verify owner bindings and evidence chains. A successful
   backup command alone is insufficient. See `scripts/backup_evidence.py`,
   `scripts/restore_evidence.py` and `scripts/verify_evidence_chain.py`.
4. Using the **new API image** with the migration account, run
   `python -m alembic -c services/database/migrations/alembic.ini upgrade head`.
   Expected head for this build is **0106**: 0103 supplies assurance storage,
   0104 page indexes, 0105 long monitor event types, and 0106 adds native PostgreSQL
   UNKNOWN/DEFERRED/CANCELLED identities. Existing jobs, grants, approvals and
   evidence are not relabeled or reset. Run with separate migration authority;
   review the [native qualification](../readiness-evidence/quality-postgres-workflow-2026-10-23.md).
5. Apply only the verified `manifests/` with `kubectl apply -R -f`. Roll API and
   workers as one coordinated maintenance change; do not expose new producers
   to legacy workers. Confirm rollout image digests, schema head and health.
6. Sign in again with a current human session; provision/review provider budget,
   estate policy and an independently approved local-source execution grant.
   Use [controlled execution](controlled-execution-upgrade.md), not an implicit
   admin bypass. Confirm the approved destination matches the running nodes.
7. In a disposable approved estate, exercise one queued source scan, its durable
   completion, evidence receipt and owner-scoped history. Open
   `/operator-decisions`, create an assigned finding task, propose/independently
   approve a condition, report completion, and verify a **later** completed
   rescan. Confirm stale approvals, foreign estate IDs and missing receipts do
   not verify. Existing ordinary dashboard/collector routes remain restricted.
8. Retain release hash, trusted-key fingerprint, schema revision, readiness,
   smoke receipts and witnessed acceptance decisions outside the signed package.
   Only the site's designated authority may accept the deployment.

## 6. Upgrade, legacy queues, replay and recovery

- **No mixed-version window:** quiesce HTTP/automation producers, inventory old
  queued/running/UNKNOWN jobs, stop/drain legacy workers, back up, migrate, then
  replace workers/producers together. Read old jobs as history. Missing typed
  provenance/approval cannot be reconstructed from a username; resubmit approved
  work as a **new job**. Never reset reservations by editing SQL rows.
- **Replay compatibility:** old cursors, retention gaps and stream resets are not
  a complete activity history. The operator view clears/reconciles via full SQL
  reads every 30 seconds while visible and on replay/auth/estate changes. It
  does not replay an action based on a cursor or turn an event ACK into proof.
- **Unknown external outcome:** stop new admissions, inspect durable attempts,
  outbox, runtime and retained evidence. Fence/reconcile through the existing
  human control endpoints. A timeout is not proof a parser stopped. Do not free
  capacity or retry until its actual outcome is reconciled.
- **Rollback-forward:** after any new writes, keep schema 0106 and deploy a tested
  compatible application fix forward. Reverting image bytes alone does not undo
  evidence, approvals or external effects. Do not drop assurance history.
- **Pre-write rollback:** only with witnessed proof no new work/writes occurred,
  restore the complete consistent DB/evidence set and its compatible old images
  in an isolated environment first; verify chains, owner scope and grants before
  cutover. Reconcile queued effects separately. Record actual RPO/RTO—this
  repository provides no promised values.
- **0106 PostgreSQL downgrade** refuses while UNKNOWN jobs remain. Never relabel
  them or release held capacity just to downgrade. Additive enum labels remain
  on an allowed downgrade; this is not permission to resume incompatible old
  binaries. Prefer reviewed compatible fix-forward.
- **0105 downgrade** refuses to narrow `monitor_events.event_type` while any
  recorded value exceeds 30 characters. **0104 downgrade** removes only the
  two page indexes. Neither is data recovery or a reversal of 0103 assurance
  history. Do not run an older downgrade as an emergency shortcut.

## 7. Package acceptance checklist

A new operator should retain evidence for offline integrity, cluster admission,
secret/CA mounts, actual runtime/image availability, coordinated version/schema,
legacy-job refusal, owner-scoped smoke scans, independently verified conditions,
restore/unknown-outcome recovery and measured site limits. Any missing check
remains **NOT_RUN / BLOCKED**, not an inferred PASS. This increment supplies the
package/tooling/runbook; no actual customer installation/upgrade/recovery has been
performed in the engineering sandbox.


## Launch evidence handoff (5.1–5.3, Preview)

The [launch assurance runbook](launch-assurance-handoff.md) covers independent
assessment procurement/intake and signed retests, accountable operational duties
and one bounded payments pilot. Those launch workflows added no migration;
this build additionally requires 0105 for long monitor events and 0106 for native
PostgreSQL uncertain-job identities. Rebuild
API/shared models/frontend and the worker together. Actual external assessment, owners,
site exercises and customer acceptance remain external blockers. These workflows
do not authorize an SLA, certify the product or re-enable refused live collectors.
