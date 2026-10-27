# Deploying CryptoScan inside a bank: detailed on-premises guide

**Prepared:** 2026-10-22 UTC
**Source baseline:** `bfc42df0` on `arena/bb4b80dd-cryproscan`; application behavior
reviewed at `698beb38`, followed by documentation-only changes.
**Audience:** bank infrastructure, network, database, security, operations and
application teams, plus the CryptoScan implementation team.
**Status:** deployment explanation and operator procedure—not a completed bank
installation, certified architecture, signed release or production approval.

## Reading path

Read in order for a first installation, or jump to:

- [What the bank installs and the support boundary](#1-the-direct-answer-what-the-bank-installs)
- [Architecture and responsibilities](#3-reference-on-premises-architecture)
- [Sizing and network design](#7-infrastructure-and-sizing-do-not-confuse-examples-with-capacity)
- [Secrets, configuration and access](#9-dns-certificates-secrets-and-configuration)
- [Build, sign and transfer the release](#12-prepare-the-full-release-in-a-trusted-build-environment)
- [Bank-side preflight and installation](#15-bank-side-preflight-before-creating-application-workloads)
- [Backup, upgrades and recovery](#19-backup-retention-and-disaster-recovery)
- [24/7 operation, bank monitoring and weekly support](#211-247-operation-with-bank-monitoring-and-weekly-support)
- [Actual bank acceptance](#23-bank-acceptance-installation-is-not-go-live)

## 1. The direct answer: what the bank installs

**The bank runs CryptoScan in its own approved data centre. Its users open an
internal HTTPS address. Source material, observations, database, queues and
operating evidence stay in bank-controlled systems under bank access, network,
retention and backup policies.** Vendor support does not automatically receive
access to the bank's data or infrastructure.

For the currently reviewed controlled profile, the bank provisions:

1. An approved Kubernetes environment, which can run on bank-owned virtual or
   physical machines.
2. CryptoScan frontend and API workloads, plus a coordinated trusted worker.
3. A dedicated, reviewed worker node/runtime that launches a networkless parser.
4. Regional PostgreSQL and verified-TLS Redis, operated as approved bank services.
5. A private image registry, internal DNS/HTTPS certificates, secrets/CA custody,
   approved source storage, monitoring and isolated backup/recovery facilities.
6. Named people who authorize scope, operate the service, review evidence and
   accept the exact deployment.

**“External PostgreSQL/Redis” means outside the CryptoScan application workloads,
not outside the bank or on the public internet.** They can be bank-managed services
in the same approved data-centre region. Physical placement, replicas and backups
must actually satisfy the bank's residency policy.

Installing one server does **not** give CryptoScan permission or connectivity to
scan the whole bank. For this profile, approved local source is supplied through
a controlled bank transfer/storage process. No unqualified live collector is enabled.

## 2. Read the support boundary before designing the installation

The reviewed reference profile is:

`kubernetes-external-services/local-source-v1`

| Deployment/capability | Current boundary |
|---|---|
| One customer-controlled instance with API, worker, frontend and isolated source parser | Reference engineering profile; must still pass actual site qualification. |
| Bank-owned VMs | May host the approved Kubernetes/worker infrastructure. A VM alone is not the complete profile. |
| PostgreSQL + verified-TLS Redis outside application pods | Required bank-provisioned dependencies, with reviewed credentials, certificates and recovery. |
| Stock single-machine Docker Compose / SQLite / inline parser | Development examples, not a shortcut to this bank production profile. |
| Multiple unrelated banks on one Docker-daemon worker node | Not a supported hostile shared-tenant isolation boundary. |
| Live TLS/SSH/network/cloud/runtime/vendor acquisition | Refused in the controlled production profile; needs separately approved qualification, not an installation flag. |
| Existing assurance/operator/launch metadata | Available only under the admitted route/permission contracts; Preview workflows do not provide real assessor or customer evidence. |
| Full development dashboard, graph, arbitrary exports, monitoring and integrations | Their existence in the repository/schema does not enable them in this restricted profile. |
| Neo4j | Keep disabled; do not provision dummy graph credentials to satisfy old deployment examples. |
| HA, autoscaling, cross-region active/active or automatic failover | Not established by the reference manifests; require separately reviewed topology and witnessed acceptance. |

The reference API and worker deployments use one replica. Do not increase replica
counts or claim zero-downtime upgrades without testing the intended authority,
queue, state and database behavior. Kubernetes restart capability is not HA evidence.

Authorities: [operator installation/recovery](runbooks/operator-install-upgrade-recover.md),
[controlled execution](runbooks/controlled-execution-upgrade.md) and
[current implementation status](CURRENT-IMPLEMENTATION-STATUS.md). Older broad
Compose/air-gap examples must not override this profile.

## 3. Reference on-premises architecture

```text
BANK-CONTROLLED DATA CENTRE / APPROVED REGION

  Authorized bank workstation
          │ internal DNS + HTTPS 443
          ▼
  Bank ingress / approved TLS termination
          │ private service traffic
          ▼
  Frontend Service :3003
  - serves the existing browser application
  - same-origin /api/ proxy
          │ private API Service named "api", port 8010
          ▼
  API :8010 ───────────────► Bank PostgreSQL over verified TLS
     │                       - identities, controls, jobs and evidence/history
     │
     └────────────────────► Bank Redis over verified TLS + named ACL roles
                                 ▲
                                 │ approved role connections
  Dedicated trusted worker ──────┘
     │ also uses approved PostgreSQL/source/configuration
     │ local reviewed Docker CLI + daemon socket
     ▼
  Isolated parser container
  - exact preloaded image digest
  - no network, no daemon socket, no database credentials
  - read-only source bind, read-only root, bounded resources
     │ bounded result to trusted worker
     └──► durable owning job / evidence / approved read models

  Separate bank-controlled supporting systems:
  private registry | secret/PKI management | approved-source storage
  restricted operating logs | encrypted backups | isolated restore environment
```

This is a logical drawing, not a ready-to-apply firewall policy. The parser is
launched through the reviewed dedicated daemon runtime; it is not automatically
an ordinary Kubernetes pod governed by the worker pod's limits or NetworkPolicy.
Host/runtime-level restrictions need their own verification.

## 4. Responsibilities: who supplies what

| Bank/team | Responsibility before go-live |
|---|---|
| Bank sponsor and application owner | Approve purpose, exact application/release, expected targets, exclusions and acceptance authority. |
| Infrastructure/Kubernetes team | Approved nodes, namespace, scheduling, admission, registry trust, storage, ingress and restricted management access. |
| Network/PKI team | DNS, HTTPS, dependency TLS, allowlisted flows, time synchronization, certificate issuance/rotation and egress evidence. |
| Database/Redis owners | Least privilege, persistence/configuration, capacity, backups, restore and actual recovery measurements. |
| Security/identity team | Account/role/membership review, privileged access, secrets, independent assessment and incident handling. |
| CryptoScan release/implementation team | Exact compatible images, package/runbooks, declared limitations, verifier and migration/change support. |
| Operating primary/backup humans | Run procedures, triage failed/UNKNOWN jobs, rotate credentials, recover service and maintain evidence. |
| Independent reviewer/customer approver | Review actual results; accept only the exact site/release/scope their authority covers. |

Vendor remote access, if permitted, must be explicitly approved, time-bounded,
least-privilege and logged through bank-controlled channels. On-premises deployment
does not justify permanent vendor superadmin access or unrestricted data export.

## 5. What data enters, and where it travels

A normal supported source workflow is:

1. The application owner identifies a release and approved source snapshot.
2. The bank transfers it through its approved internal process to an isolated
   approved-source area. This is not a new browser upload feature or permission
   to clone arbitrary external repositories from production.
3. A register independently records what should be assessed, including missing
   or unattempted targets. Scanner output cannot shrink that denominator.
4. An authorized user submits work under the current estate, policy and approved
   local-source grant. The API records durable work; acknowledgement is not completion.
5. The worker rechecks current authority and stages a bounded source input.
6. The trusted dispatcher launches the exact isolated parser image. The parser
   sees its approved input, not bank credentials, Docker control or the wider network.
7. Bounded results become owning job/evidence records under the existing contract.
   Partial, refused, failed or UNKNOWN states remain visible.
8. Existing admitted operator/assurance views expose permitted metadata and proofs
   to current authorized users. Do not infer that every ordinary dashboard/export
   route is enabled.
9. The bank retains original observations, review decisions and later condition
   proofs under its approved retention/residency policy.

### How the six BOMs fit this deployment

| BOM | Evidence the bank must supply/retain | Not automatically established |
|---|---|---|
| **SBOM** | Exact release artifact digest, separately hashed SBOM document and versioned packages | Independent build/deployment/runtime truth |
| **CBOM** | Observed source crypto facts, original-file location/hash, purpose and parser receipts | All cryptography used by every bank system |
| **NBOM** | Legitimately obtained exact endpoint/protocol receipts and reviewed associations | New live network scanning enabled by this installation |
| **TechBOM** | Existing system/deployment/artifact identities and explicit reviewed relationships | Runtime dependencies inferred from matching names |
| **HBOM** | Exact hardware/firmware/mode metadata with disclosed observation/declaration source | Hardware-backed operation, attestation or certification from a product label |
| **VBOM** | Exact supplier/product/build evidence, valid origin signature, quarantine and separate review | Independent vendor truth or assurance from signature alone |

See [six-BOM evidence paths](bank-environment/49-six-bom-evidence-paths.md).
Some source intake and supplier evidence may contain sensitive bytes. “Metadata
only” is not a blanket assurance that no customer content is retained. Inventory
actual fields, raw evidence, logs, temporary files and backups; minimize access
and retention according to their real classification.

## 6. Before installation: a bank deployment worksheet

Obtain actual reviewed values for the following; do not invent IDs, image digests,
public keys or authority records to make a template validate.

| Item | Required bank decision/value |
|---|---|
| Purpose | One bounded application/source workflow and explicit exclusions |
| Estate | Actual authorized legal/operating estate and accountable owners |
| Site | Approved data centre/region, execution region, evidence region and destination |
| Kubernetes | Approved cluster/context, namespace, admission policy and dedicated worker node |
| Console | Internal DNS name, exact HTTPS origin, ingress class and certificate owner |
| Images | Private registry/repository names and actual API/worker/frontend/parser digests |
| PostgreSQL | Approved endpoint/port, database, CA, runtime/migration roles and restore policy |
| Redis | Approved TLS endpoint/port, consumer-role ACL/configuration, CA and recovery objectives |
| Source | Approved transfer, per-estate root/permissions, PVC and read-only mounts |
| Staging | Identical reviewed worker/daemon-host path and dispatcher UID/socket GID |
| Secrets | Custody, provisioning, expiry/rotation and break-glass procedure |
| Evidence | Authorized raw/metadata access, encryption, quotas, legal hold and retention |
| Acceptance | Actual operators, independent reviewer, measured objectives and decision authority |

Start with a disposable pre-production estate on representative infrastructure.
Do not perform first-use migration/fault experiments on a live bank database.

## 7. Infrastructure and sizing: do not confuse examples with capacity

The bank should use approved Linux/container/Kubernetes infrastructure compatible
with the required daemon/CLI behavior and file permissions. The actual runtime,
OS, kernel, Kubernetes/CNI, database, TLS and storage combinations need retained
site evidence; this guide does not certify arbitrary versions.

The reference input currently contains these **example** pod values:

| Component | Requests in reference | Limits in reference | Interpretation |
|---|---|---|---|
| API | 250m CPU, 256Mi memory | 1 CPU, 1Gi memory | Starting configuration, not a bank throughput recommendation. |
| Trusted worker | 500m CPU, 512Mi memory | 2 CPU, 2Gi memory | Does not account for every host-daemon child workload automatically. |
| Frontend | No complete resource envelope specified in the reference | Site must review/set appropriate bounds | Absence is not unlimited qualified capacity. |
| Launched parser | Existing launcher constrains each run to 1 CPU, 1g memory/swap ceiling and 64 PIDs | Networkless/read-only with bounded temporary space | Launcher settings, not proof of actual site enforcement or total node capacity. |

Do not sell “8 GB is enough for a bank” from an older development guide. Size
against actual source counts/bytes, parsing cost, permitted concurrency, retained
history, PostgreSQL I/O, Redis persistence, browser tasks and recovery objectives.

Budget node resources for Kubernetes/OS, dispatcher, concurrent parser containers,
staging expansion and safety margin. Budget storage separately for approved
source, temporary staging, SQL/evidence growth, Redis persistence, logs and
backup retention. Measure representative normal, maximum-admitted and refused
inputs before agreeing an operating envelope. No customer capacity/SLA number is
established here. See [measured workloads and limits](bank-environment/55-measured-workloads-and-capacity-limits.md).

## 8. Network zones and firewall rules

Use bank-managed network policy and firewalls with default-deny where supported,
then allow only reviewed paths. Kubernetes NetworkPolicy enforcement depends on
the CNI and does not by itself constrain host-daemon parser networking.

| Source → destination | Flow | Requirement |
|---|---|---|
| Approved workstations → ingress | HTTPS 443 | Internal DNS, valid hostname certificate and approved user access. |
| Ingress → frontend | Reference Service/container port 3003 | Private service path; not a public node port. |
| Frontend → API Service `api` | Reference port 8010 | Private same-origin proxy backend; restrict direct untrusted access. |
| API/worker → PostgreSQL | Bank-assigned database TLS port, commonly 5432 | Verify hostname/CA; allow only appropriate runtime/migration identities. |
| API/worker → Redis | Bank-assigned TLS port | Use `rediss://`, approved CA and correct named ACL roles; no assumption that every deployment uses 6380. |
| Nodes/approved runtime → private registry | Approved registry HTTPS endpoint | CA/DNS/authentication; immutable image access under bank policy. |
| Workloads/nodes → bank DNS/time/approved management | Site-specific | Only required destinations; time accuracy matters to expiry/proof validity. |
| Worker → dedicated Docker daemon | Reviewed local Unix socket | No unauthenticated TCP daemon; no socket inside parser. |
| Parser → network | None | Verify launcher/runtime isolation; no fallback enabling internet or internal bank targets. |
| Operations → backups/logs/management plane | Bank-approved restricted channels | Separate roles, retention and independent audit/custody. |

Do not open bank-wide subnets, internet egress, cloud metadata, SMTP, webhooks,
IdP or vendor tunnels merely because a development page references them. If an
approved integration is needed, verify actual profile availability and bank
qualification first; otherwise it remains refused/out of scope.

The API image accepts forwarded proxy headers broadly in its current launch
command. Restrict direct API access to the reviewed trusted proxy path and
verify Host/origin/proxy-header handling. Test HTTPS login/cookie behavior across
the actual ingress/frontend chain; do not assume every TLS-offload layout is safe.

## 9. DNS, certificates, secrets and configuration

Provision nonsecret configuration separately from secret values. The reference
uses `cryptoscan-profile` for configuration, `cryptoscan-runtime` for runtime
secrets, `cryptoscan-ca` for mounted CA files and a separate ingress TLS secret.
An existing Kubernetes Secret object is not proof of encryption, least privilege
or rotation: the bank must secure its secret store, cluster access and backups.

### Required explicit application pins

Both API and worker must explicitly set:

| Setting | Required meaning |
|---|---|
| `CRYPTOSCAN_DEPLOYMENT_PROFILE` | `kubernetes-external-services/local-source-v1` |
| `ENVIRONMENT` | `production` |
| `CRYPTOSCAN_EXECUTION_CONTROLS` | `true` |
| `CRYPTOSCAN_EXECUTION_REGION` / `CRYPTOSCAN_EVIDENCE_REGION` | Actual reviewed node/evidence regions |
| `CRYPTOSCAN_EVIDENCE_DESTINATION` | Actual permitted evidence destination, consistent with estate policy |
| `CRYPTOSCAN_STATIC_SCAN_MODE` | `container` |
| `CRYPTOSCAN_SOURCE_ROOTS` | Approved source roots, matching mount and estate policy |
| `CORS_ORIGINS` | Exact HTTPS console origin; no wildcard |
| `TRUSTED_HOSTS` | Reviewed JSON host allowlist; probes must use an accepted Host |
| `NEO4J_URI` | Empty/disabled in this profile |

For the worker, also explicitly bind `CRYPTOSCAN_SCANNER_IMAGE` to the real
parser `image@sha256:...` reference, and set both `WORKSPACE_BASE_PATH` and
`WORKSPACE_BASE` to `/tmp/cryptoscan-workspaces` for this reference profile.

Secret `envFrom` content must not introduce conflicting controls, source roots,
regions, runtime images or staging paths. Explicit protected settings take
precedence according to the manifest contract; inspect all effective values.

### Secret and trust custody

Use real approved values for `DATABASE_URL`, Redis credentials/configuration,
`SECRET_KEY`, `STREAM_SECRET`, `METRICS_TOKEN`, `REGISTRY_WEBHOOK_SECRET`,
`CBOM_SIGNING_SECRET`, `AUDITOR_API_KEY`, `GITHUB_WEBHOOK_SECRET`,
`ADMIN_USERNAME` and valid `ADMIN_PASSWORD_HASH`, as required by current
production validation. The operator runbook specifies minimum lengths; use the
bank's stronger entropy/custody policy, not merely the minimum number of characters.

Generate the bootstrap password hash interactively with the existing protected
hash helper. Do not put passwords, full connection URLs, tokens, private keys or
Secret YAML into shell arguments, this document, public tickets or release packages.

Mount approved `postgres-ca.pem`, `redis-ca.pem` and `organization-ca.pem`
read-only at `/site-ca`. PostgreSQL uses verified hostname TLS such as
`sslmode=verify-full` with `PGSSLROOTCERT`; Redis uses verified TLS with
`REDIS_CA_CERTS`. Edge HTTPS does not configure database/queue TLS. Retain tests
for wrong CA/hostname, insufficient ACL, expiry and rotation without disabling checks.

See [Redis consumers and recovery](bank-environment/47-redis-consumer-and-recovery-evidence.md)
for the existing consumer roles and role-specific configuration. PING alone does
not prove command permissions or survival of acknowledged state.

## 10. Identity and access inside the bank

An empty users table is bootstrapped at API startup from the approved admin
username/hash. An existing user table is not overwritten. After controlled
bootstrap, create separately authorized operator/reviewer accounts, review
estate membership and protect/rotate bootstrap authority under bank policy.

Do not use development `admin` / `cryptoscan` credentials in the bank. Do not
seed fake owners, accepted pilots or completed security reports.

A platform administrator selecting no bank estate addresses platform-owned
history, not every bank's records. Backend current role/membership and exact-estate
checks remain authoritative; hiding a browser button is not access control.
Human approval/reconciliation actions cannot be delegated to a machine key where
the existing contract requires a durable human and different reviewer.

If the bank mandates SSO/MFA/identity lifecycle integration, validate the exact
required flow against the admitted profile before go-live. The existence of
OIDC/SAML/LDAP code in the broad repository is not proof of its availability or
qualification here. A mandatory unsupported identity requirement is a blocker,
not justification to disable it or claim support.

## 11. Approved source storage and the dedicated parser runtime

### Source area

Provision the `approved-source` PVC and mount it read-only at `/approved-source`
to API/worker as documented. The bank supplies only the approved release snapshot.
Use per-estate path permissions and execution policy; a shared PVC does not
prove tenant isolation. Classify source and scrub unnecessary secrets before
approved transfer while preserving the evidence/provenance contract.

### Trusted dispatcher staging

The private staging directory `/tmp/cryptoscan-workspaces` must exist at the
**same absolute path inside the worker and on the Docker daemon host**. Protect
ownership/permissions for the dispatcher identity and verify actual mount identity.
A path that exists only inside a pod cannot be used as a host-daemon bind source.
The launcher performs a marker-based identity check; do not bypass it.

Set the actual daemon socket group GID through reviewed deployment configuration.
Never `chmod 666` the socket, expose unauthenticated Docker TCP or mount the
socket into the untrusted parser. Daemon control is effectively root-equivalent;
the dedicated node must not be shared with hostile tenants.

### Dispatcher and parser images are different

The stock worker image does not include the required Docker CLI. Build the
trusted dispatcher using [the worker-runtime recipe](../.docker/worker-runtime/Dockerfile)
with real reviewed digest-pinned `WORKER_IMAGE` and `DOCKER_CLI_IMAGE` inputs.
Record the resulting registry worker digest. Do not build the parser from a
privileged dispatcher image or give it the dispatcher's credentials.

The parser must be the exact approved preloaded digest. Current launch controls
include no network, no daemon socket, no worker environment/database sessions,
read-only root/input, non-root execution, dropped capabilities, no-new-privileges,
PID/CPU/memory/time bounds and bounded temporary/output space. Actual Docker/kernel
support, cleanup, daemon loss/orphans and escape resistance still need site tests.
There is no approved inline fallback when the isolated runtime is unavailable.

## 12. Prepare the full release in a trusted build environment

The connected/trusted build zone should not receive bank production source/data
merely to build CryptoScan. Build and review the application images from the
intended exact source/dependency inputs, then authorize publication to the bank's
approved registry/mirror.

Current CI builds six standard images without publishing them. It does not
supply trusted production digests/signatures, and the dedicated dispatcher build
has separate reviewed base-image inputs. The manual unsigned release preflight
is also not the complete bank-site package.

Use [the site input template](../deploy/operator-profile/site.example.yaml) only
as a starting point. It contains intentionally invalid `REPLACE_*` values.
**Do not apply it.** Create actual site manifests outside the checkout, add the
bank-approved network/storage/admission/image-pull/resource configuration and pin
all main/init/sidecar/frontend images by actual digest. Provision Secret resources
separately; they are not allowed package inputs.

### Build the immutable operator package

The commands below run from an approved trusted checkout and dependency environment.
Every shell variable must name actual reviewed values; these are not executable
sample credentials or a command to run against an unspecified cluster.

```bash
: "${SITE_MANIFESTS:?actual reviewed site manifest directory required}"
: "${RELEASE_PACKAGE:?new disjoint release output directory required}"
: "${RELEASE_ID:?approved release label required}"
: "${RELEASE_REGISTRY:?approved registry/repository prefix required}"
: "${API_DIGEST:?actual API registry SHA256 required}"
: "${WORKER_DIGEST:?actual dedicated dispatcher registry SHA256 required}"
: "${RESERVED_NEO4J_DIGEST:?reviewed legacy-schema digest entry required}"
: "${PARSER_IMAGE:?actual approved parser image at digest required}"
python scripts/operator_release.py build \
  --source "$SITE_MANIFESTS" --out "$RELEASE_PACKAGE" \
  --release "$RELEASE_ID" --registry "$RELEASE_REGISTRY" \
  --api-digest "$API_DIGEST" --worker-digest "$WORKER_DIGEST" \
  --neo4j-digest "$RESERVED_NEO4J_DIGEST" --parser-image "$PARSER_IMAGE"
```

The legacy lock schema requires a real reviewed Neo4j digest entry even with
graph disabled. That entry is **not authorization to deploy/enable Neo4j**.
The frontend image is present in the reviewed site manifests and full inventory;
it is not supplied through a nonexistent `--frontend-digest` argument.

The output directory must be new and disjoint from input. The tool inventories
the complete package, manifests, documentation and compatibility information.
It does **not** sign or deploy. Bank manifests must meet its bounded input rules;
do not hide secrets or unsupported resources in an opaque Kubernetes List.

## 13. Sign externally, verify independently, then transfer

The approved external release authority signs the exact `release-image-lock.json`
bytes with the existing Ed25519 attestation contract. Retain the detached
attestation and trusted public key outside the package inventory. Private signing
keys remain under the authority's approved custody, not inside bank application
pods, public repositories, untrusted PR jobs or a vendor chat.

Distribute the public-key fingerprint through an independent approved channel.
A public key supplied next to an untrusted package is not automatically trusted.

```bash
: "${TRUSTED_RELEASE_PUBLIC_KEY:?independently trusted public key path required}"
: "${DETACHED_RELEASE_ATTESTATION:?actual external attestation path required}"
python scripts/operator_release.py verify \
  --package "$RELEASE_PACKAGE" --public-key "$TRUSTED_RELEASE_PUBLIC_KEY" \
  --attestation "$DETACHED_RELEASE_ATTESTATION"
```

Use the verifier from a trusted verification installation initially, not an
unverified package's own executable. Changed/missing/extra files, symlinks,
embedded Secrets, unresolved inputs and signature/inventory mismatch fail.
A verifier PASS proves package integrity under its contract—not trusted data,
installed health, bank security qualification or customer acceptance.

Do not write logs/reports/new attestations into a signed package: extra files
invalidate its inventory. Store all deployment evidence in a separate protected
location. Any manifest or registry-name change needs a new package and signature.

## 14. Restricted internet and fully air-gapped banks

Prepare approved build artifacts/dependencies in a controlled connected zone,
then transfer through the bank's malware-scanned, reviewed transfer process.
Runtime operation must use only bank-approved destinations.

Transfer the exact OCI artifacts, signed package, separately trusted verification
materials and approved offline dependency/runtime installation artifacts. Use a
digest-preserving OCI transfer process; a checksum of an image tar archive is
**not** the OCI manifest digest. A multi-platform image requires the intended
platform manifest/artifacts, not whichever architecture happened to be cached.

On receipt:

1. Verify transfer inventory, custody, signatures and the independent trust anchor.
2. Import into the approved private registry preserving manifest digests and
   providing trusted registry DNS/CA/authentication.
3. Ensure names in the signed manifests resolve to the intended mirror. If names
   or bytes change, rebuild/re-sign; do not edit signed YAML in place.
4. Make exact API/worker/frontend references available to the orchestration runtime.
5. Separately preload/verify the exact parser `repo@sha256:...` in the dedicated
   Docker daemon. A Kubernetes/containerd cache or successful `docker load` alone
   does not prove that daemon can resolve the required immutable reference.
6. Prepare the trusted Python verifier environment offline with approved exact
   dependencies. The operator runbook currently specifies Python 3.11+,
   `cryptography==50.0.1`, `PyYAML==6.0.3` and approved transitive dependencies.
7. Re-run verification on the bank side, then perform site preflight/qualification.

### Frontend font hardening and offline verification

The original reviewed baseline at `69faec96` requested Google Fonts and external
preconnects. The first [quality implementation increment](product-improvement/IMPLEMENTATION-STATUS.md)
removes those entrypoint references and the runtime CSP's external font/stylesheet
allowances, using existing local/system fallback stacks. Static bootstrap/CSP
regressions and a local production build check the corrected source/bundle.

An older deployed frontend still has the original behavior until the reviewed
new image is rebuilt, verified, externally signed and installed. Verify real bank
browser network traces, font fallback/RTL/zoom/layout and the exact deployment's
CSP/firewall. Removing known remote font references is not proof that every runtime
path has no egress or that site isolation is accepted. The older legacy-dashboard
zero-CDN claim is not a substitute for checking the current actual frontend.
Blocking internet destinations alone does not prove no attempted requests.

## 15. Bank-side preflight: before creating application workloads

Check these foundations through the bank's infrastructure process:

- Correct approved kubeconfig/context and least-privilege change identity.
- Namespace, ingress controller, admission/RBAC and storage/PVC readiness.
- Provisioned runtime/CA/ingress secrets, correct read/mount access and no secrets
  overriding protected profile/settings.
- DNS, trusted certificates and actual TLS connections to approved database/Redis.
- Registry authentication/trust and exact image availability in **both** runtimes.
- Dedicated worker scheduling, socket permissions and identical staging paths.
- Network/firewall policy, no unintended public exposure and parser isolation.
- Backup/restore evidence and actual migration/change authorization.
- Independent operators/reviewers and a disposable smoke-test estate/input.

The verifier's optional cluster preflight uses current `kubectl` context, not a
custom `--context` argument. Guard that context explicitly:

```bash
: "${BANK_KUBECONFIG:?approved protected kubeconfig file path required}"
: "${BANK_KUBE_CONTEXT:?approved context name required}"
export KUBECONFIG="$BANK_KUBECONFIG"
ACTIVE_CONTEXT="$(kubectl config current-context)"
if [ "$ACTIVE_CONTEXT" != "$BANK_KUBE_CONTEXT" ]; then
  printf 'Wrong Kubernetes context; stop before preflight or deployment\n' >&2
  exit 1
fi
python scripts/operator_release.py verify \
  --package "$RELEASE_PACKAGE" --public-key "$TRUSTED_RELEASE_PUBLIC_KEY" \
  --attestation "$DETACHED_RELEASE_ATTESTATION" --cluster-preflight
```

This performs strict server-side dry-run admission without applying resources.
It contacts the actual API/admission path; obtain bank authorization. It does
not prove secrets exist, volumes mount, TLS works, parser images are present,
backups restore or jobs survive faults. Investigate admission failures rather
than turning off validation. Prepare the approved namespace/foundations as
required; dry-run cannot create its prerequisites for later objects.

## 16. Maintenance window, schema and coordinated installation

Have a reviewed change plan, stop conditions, communications and recovery owner.
Use the verified immutable candidate throughout:

1. Stop new HTTP/automation/scheduled admissions; inventory queued, running,
   deferred and UNKNOWN work. Stop/drain old workers under the existing procedure.
2. Take a consistent encrypted backup of SQL, evidence/blob data and relevant
   configuration/retention metadata. Rehearse restore in isolation and verify
   owner links and evidence, not just backup exit status.
3. Using the **new API image** in the approved one-shot migration environment,
   supply the separate migration identity through secret management. Do not
   paste its connection string into CLI arguments or leave runtime pods using
   migration-owner privileges.
4. Apply the reviewed full migration chain and confirm the intended head:

```bash
# Inside the approved new API image/migration environment, not an arbitrary laptop.
python -m alembic -c services/database/migrations/alembic.ini upgrade head
python -m alembic -c services/database/migrations/alembic.ini current
```

For this build, expected head is **0106**. Migration0103 adds assurance storage,
0104 page indexes, 0105 long monitor event types, and 0106 native PostgreSQL
UNKNOWN/DEFERRED/CANCELLED identities. No old job/approval/evidence is rewritten.
PostgreSQL0106 downgrade refuses while UNKNOWN remains; additive labels remain
even on permitted downgrade. Never relabel uncertainty/release reservations to
force rollback. See the [native qualification record](readiness-evidence/quality-postgres-workflow-2026-10-23.md).
Review the actual release contract rather than assuming `head` is fixed forever.

5. With actual change approval, apply **only** the verified package manifests:

```bash
: "${BANK_NAMESPACE:?approved namespace required}"
# Mutating command: run only in the authorized maintenance change after verification.
kubectl --context "$BANK_KUBE_CONTEXT" apply -R -f "$RELEASE_PACKAGE/manifests"
kubectl --context "$BANK_KUBE_CONTEXT" -n "$BANK_NAMESPACE" \
  rollout status deployment/cryptoscan-api --timeout=300s
kubectl --context "$BANK_KUBE_CONTEXT" -n "$BANK_NAMESPACE" \
  rollout status deployment/cryptoscan-worker --timeout=300s
kubectl --context "$BANK_KUBE_CONTEXT" -n "$BANK_NAMESPACE" \
  rollout status deployment/cryptoscan-frontend --timeout=300s
```

Manifest namespaces/names must match the approved reference contract and target;
`-n` on a status command does not rewrite explicit namespaces in signed YAML.
Reconfirm context if this is a new shell or another administrator changed it.
The 300-second command timeout is illustrative operating feedback, not an SLA
or proof that an unfinished rollout is safe to abandon.

6. Coordinate producers/workers without a legacy mixed-version execution window.
   Kubernetes applies/rollout success alone do not implement this maintenance policy.
7. Confirm actual image identities, mounted references, schema head and allowed
   endpoint health. Do not resume admissions solely because all pods are Running.

## 17. Health, readiness and browser verification

These checks answer different questions:

| Check | What it establishes | What it does not establish |
|---|---|---|
| API `/healthz` | Process liveness | Database/queue readiness or successful scanning |
| API `/readyz` | Current readiness contract, including dependency/schema conditions | Site capacity, isolation, old-ACK survival or customer acceptance |
| Worker/runtime examination and admitted source smoke | Actual dispatch, parser access, durable job/receipt path | Every workload or failure scenario |
| HTTPS browser login/task checks | Actual ingress/proxy/auth/current UI path | Whole-platform support from seeing a login page |
| Independent site drills | Observed behavior for the measured scenario/environment | Unmeasured topology, longer endurance or other versions |

The reference API probes send the exact allowed console Host header. A pod-IP
Host can be refused by the configured allowlist; do not “fix” it with wildcard
hosts. Inspect failure categories locally without dumping secrets to public logs.

The frontend proxies `/api/` to `api:8010`. Browser code should call same-origin
relative APIs, never localhost, pod IP or private service DNS. The frontend's
bare `/readyz` is **not** configured as the API root readiness proxy in the
reviewed nginx file; it can fall into SPA routing. Use the API Service probe or
an admitted `/api/v1/readyz` path through the intended proxy as appropriate.
Do not mistake an HTML 200/login page for JSON readiness. The older `/ready`
contract is also not equivalent to `/readyz` drain semantics.

Verify TLS termination/forwarded headers, secure session cookies, permitted
Host/origin, private API reachability and browser network behavior. Keep graph
and unqualified realtime adapters disabled; a deliberate SKIPPED adapter does
not excuse failure of required SQL/Redis checks.

## 18. First approved source scan and operator verification

With current real human accounts:

1. Sign in again after incompatible session/authority upgrades. Legacy username
   references are not sufficient original credential provenance.
2. In the appropriate platform context, provision/review the provider budget.
3. In the selected bank estate, configure the actual policy, source root,
   region/destination, limits and stop controls.
4. Have a different entitled human approve the intended executing principal under
   the existing grant contract. Admin membership is not an execution bypass.
5. Queue one bounded source scan of the approved disposable target; record its
   durable job/attempt, parser receipts, original-file hashes and completion.
6. Inspect exact-estate history and independent registered coverage. An empty
   finding list is not whole-estate safety; missing/partial observations stay visible.
7. Use `/operator-decisions` under its admitted contract: inspect a finding,
   assign an owner, propose the narrow condition and obtain independent approval.
8. Report the actual separately authorized action; collect a **later** completed
   eligible scan and inspect the computed proof. Old/empty/partial/missing-receipt
   scans must not verify a fix by absence.
9. Exercise anonymous/denied/foreign-estate, stale-policy and revoked-membership
   cases. No bank data may appear in another estate or platform-unselected history.
10. Keep smoke evidence and witnessed decisions outside the signed package.

Detailed semantics: [controlled execution API](api-reference/controlled-execution.md),
[operator decisions](bank-environment/53-operator-decision-workflow.md),
[condition verification](bank-environment/54-independent-remediation-verification.md).
Do not enable a refused full dashboard, collector or export route just to make
a development walkthrough appear complete.

## 19. Backup, retention and disaster recovery

The bank's backup plan must include all data required to reconstruct a consistent
accepted state—not just SQL rows:

- PostgreSQL data/schema, identity/ownership and immutable revisions/history;
- admitted evidence/blob/object locations and their custody/hash relationships;
- approved nonsecret configuration, release inventory and trusted verification material;
- secret/CA recovery dependencies through separate approved secure custody;
- Redis persistence/state and independently retained pre-fault ACK evidence where relevant;
- retention/legal-hold rules for primary, derived, temporary, log and backup copies.

Encrypt and restrict backups; ensure their region/storage/replicas actually satisfy
bank policy. A config string naming a region does not prove placement. Separate
backup operator and reviewer roles as required.

Restore into an isolated environment with outbound effects/admissions disabled.
Verify evidence hashes/chains, owner scope, account access, revision links and
compatible images/configuration before cutover. Reconcile queue effects separately;
a restored job is not permission to repeat an external operation.

Record measured RPO/RTO, lost IDs and limitations for the exact scenario. Do not
reuse the short historical development DR results as a promise for this bank.

## 20. Upgrades, failed rollout and UNKNOWN outcomes

**Published quality-source update:** `2fd8fc8f` contains the three bounded
engineering corrections, not a new deployment profile or bank-installed image.
There is no new migration in that commit; the reviewed head stays 0105. Include
the [quality-source handoff](runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f)
in staging: invalid current source proof may now return 409; unresolved package
versions cannot fill exact crypto paths; unreadable role storage refuses with 503
and invalid production identity authority with 403. Old offline supplier engine
qualifications need actual re-exercise. Keep history and evidence immutable.

Health failure diagnostics intentionally expose safe categories instead of raw
connection/SQL exceptions. Use approved restricted diagnostics, not public dumps.
The font change reaches browsers only after the reviewed new frontend is built,
verified and installed; actual browser/no-egress acceptance is still required.


- Review exact image/dependency/schema compatibility and package signatures for
  every release. Back up and coordinate producers/workers; no unreviewed mixed versions.
- Legacy unpinned jobs remain history. Newly approved work is submitted as a new
  job; do not invent old authority from a username or reset RUNNING/UNKNOWN rows.
- Timeout, worker death or loss of acknowledgement does not prove the parser or
  external effect stopped. Stop new admissions, inspect durable attempts/outbox,
  runtime and retained receipts, then use approved human reconciliation.
- At-least-once delivery is not exactly-once external execution. Do not free
  reservations or replay ambiguous work simply because the queue looks empty.
- Prefer a tested compatible forward fix after new writes. Reverting image bytes
  does not undo stored approvals/evidence or external effects.
- **0105 downgrade refuses** while any event type exceeds 30 characters. Never
  truncate audit history to force it. Earlier schema downgrade/removal of assurance
  tables is not recovery and may destroy required history.
- Pre-write restore/rollback is permitted only under the approved witnessed plan
  with a consistent DB/evidence set and compatible old images, first tested in isolation.

Reference: [operator recovery procedure](runbooks/operator-install-upgrade-recover.md)
and [quality/recovery plan](product-improvement/04-reliability-performance-and-recovery.md).

## 21. Daily operation and support

Name active primary/backup operators and a different reviewer for the existing
nine duties: vulnerability response, incident response, backup/restore, certificate
rotation, credential rotation, support escalation, release approval, data retention
and customer offboarding. They need real procedures, acknowledgements and fresh
exercises—not pre-populated successful records.

Monitor actual API/readiness, worker activity, queue age, failed/UNKNOWN work,
parser refusal/resource usage, SQL/Redis capacity, staging/evidence quotas,
certificate/secret expiry and backup/restore health through bank-approved tools.
Do not log tokens, raw private source, signing keys or database URLs for convenience.
API liveness must not be presented as worker or collector availability.

Support evidence shared outside the bank must be separately approved and sanitized.
Break-glass access, notifications, service hours and escalation commitments belong
to actual bank/service/legal decisions. The implemented operational assertion
workflow keeps **`sla_authorized=false`**; it does not grant a 24/7 SLA.

### 21.1 24/7 operation with bank monitoring and weekly support

After authorized installation and acceptance, the intended service schedule is
**24 hours a day, seven days a week** inside the bank. It is not something our
team starts only during a weekly visit. The bank SOC/security team monitors
approved service/security signals; named bank platform/database operators and
backups handle their infrastructure and incident duties.

Our team conducts an **agreed weekly review** of errors, failed/UNKNOWN work,
health/capacity, evidence freshness, backup status, security advisories and
available supported updates. We investigate product defects, prepare tested
fixes and assist with bank-approved changes. The bank keeps authority over
production access, maintenance windows and acceptance. Review does not mean
automatic weekly upgrades or unattended remote access.

**Urgent incidents follow the immediate bank escalation path, not the next weekly
meeting.** Vendor out-of-hours availability, response objectives and actual
contacts must be separately agreed and staffed; weekly support is not itself a
24/7 vendor support commitment. Continuous service operation neither guarantees
100% uptime nor enables continuous unqualified collection or refused monitor loops.

Read the [detailed 24/7 operations and weekly support model](BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md)
for responsibilities, monitoring, daily handover, the weekly agenda, incident
priorities, error-to-fix workflow, controlled updates and editable review records.
No operational SLA or demonstrated site availability is granted by this text.

## 22. Practical troubleshooting without weakening controls

| Symptom | Check first | Unsafe shortcut to avoid |
|---|---|---|
| Pod Running but login/task fails | Host/origin, proxy path/headers, secure cookies, actual API response and admitted route | Wildcard hosts/CORS or turning off production controls |
| Readiness remains failed | Actual TLS/CA, schema head, required role commands and mounted secrets | Replacing readiness with liveness or disabling certificate verification |
| Parser cannot start | Dedicated CLI/daemon, socket GID, exact preloaded digest, identical staging path | Inline parsing, world-writable socket, privileged/networked parser |
| ImagePullBackOff/offline parser image failure | Correct registry name/CA/auth, architecture and exact runtime digest availability | Mutable `latest`, public pulls or editing a signed package |
| DB migration fails | Correct new image/migrator identity, actual current head and retained database error | Applying tests to live data or deleting migration/history rows |
| Queued work refuses | Current policy, independent grant, original credential incarnation and estate/region/destination | Inventing legacy approval or impersonating another owner |
| A normal development route returns 409 | Controlled allowlist and declared supported workflow | Turning off execution controls to enable unqualified features |
| Job timeout/UNKNOWN | Actual attempt/runtime/outbox state and approved human reconciliation | SQL status reset or blind retry/freeing reservations |
| Browser requests internet fonts | Confirm reviewed corrected frontend digest, no old entry HTML/cache, actual assets/CSP and browser trace | Claiming fully offline behavior because the page still renders |
| New proof does not verify | Later completed observation, exact original site/purpose, changed bytes, receipts and current revision | Ticket-as-proof, empty-scan-as-safe or loosening predicate |
| Restore starts unexpected work | Isolation/admissions, schedules, credentials and retained queue effect history | Connecting a drill restore directly to live collectors/services |

These are investigation paths, not a diagnosis that each defect exists. Retain
actual secret-free errors and accountable follow-up; do not silently waive failed checks.

## 23. Bank acceptance: installation is not go-live

Before calling this deployment accepted, retain actual independently reviewed evidence:

| Gate | Minimum outcome |
|---|---|
| Authority and scope | Bank permission, actual independent target register, current roles/estate/grants and explicit exclusions. |
| Release integrity | Correct immutable complete package/images, separately trusted signature and compatible schema. |
| Site security | Approved TLS/secrets/RBAC/network/storage/runtime; hostile-input/isolation and denied/cross-estate tests. |
| Functional result | Durable source job/evidence/coverage, correct six-BOM provenance and eligible later condition proof. |
| Operations | Witnessed install/upgrade/recovery, nine-duty exercises and realistic escalation. |
| Capacity/browser | Measured permitted workload/resource/retention and real user/browser endurance objectives, not extrapolated localhost benchmarks. |
| Independent assurance | Actual scoped assessor report, accountable findings and later exact retests, not only a signed template. |
| Customer decision | Separate technical/customer review of the bounded current evidence fingerprint and limitations. |
| Unified readiness | All mandatory current evidence supplied and reviewed according to the actual gate; no missing required proof renamed PASS. |

The current retained readiness record is historical and not an approval for this
site. The user reports one remaining CI failure; its lane/run is unspecified
here and this session cannot independently inspect Actions results. Resolve and
retain required exact-candidate checks separately. CI success alone would still
not qualify the bank installation.

Use [production readiness](../PRODUCTION-READINESS.md),
[independent assurance](bank-environment/56-independent-security-assurance.md),
[operating ownership](bank-environment/57-operational-ownership-and-demonstrated-service.md)
and [bounded payments acceptance](bank-environment/58-focused-payments-customer-pilot.md).

## 24. A simple deployment record the bank can actually review

The following is an unexecuted worksheet, not an API payload or evidence:

```text
State: NOT_INSTALLED / NOT_TESTED
Bank-approved purpose and excluded capabilities:
Actual estate / application / release identities:
Source commit / image digests / package hash:
Independent release trust anchor and attestation reference:
Data centre / execution region / evidence region / destination:
Approved cluster/context/namespace and dedicated worker runtime:
Database/Redis versions, topology and nonsecret configuration identity:
Source transfer / paths / storage / retention / backup references:
Change approval, permitted impact and maintenance window:
Actual operator and different witness/reviewer:
Migration before/after and coordinated rollout result:
TLS/network/identity/isolation/negative-test evidence references:
Actual source job/receipt/condition-proof references:
Capacity/browser/restore/rotation measurements and limitations:
Independent security report/findings/retests:
Required readiness evidence and actual decision:
Remaining blockers / accountable owners:
Separate technical/customer acceptance and scope:
Bank continuous-monitoring owner / primary and backup / urgent escalation:
Our weekly review slot/timezone / support hours / backup contact:
Actual vendor out-of-hours agreement or explicit coverage gap:
Support ownership / review expiry / requalification triggers:
```

Keep missing values NOT_SUPPLIED/NOT_TESTED; obtain actual record IDs rather than
make them up. Sensitive evidence and all secret material remain in bank-approved
stores, not in this repository or a public release artifact.

## 25. What is complete after reading this guide

The guide explains **how to prepare, deliver, install, operate and qualify the
existing controlled product inside a bank**. It does not create infrastructure,
itself apply frontend hardening, enable features, sign a release, run migrations/CI or
perform any bank installation/fault/security exercise. Those remain authorized
work with actual evidence and owners.

For a broader quality-only improvement program, use
[the product-improvement pack](product-improvement/README.md). For execution details,
always keep the exact candidate's [operator runbook](runbooks/operator-install-upgrade-recover.md)
and compatibility metadata with the approved site change.
