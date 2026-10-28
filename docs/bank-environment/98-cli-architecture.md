# 98 — The CLI architecture: operate, investigate, integrate

**Status of this document.** It is the full architecture and command reference for the
operator CLI, written after the CLI was built (commit `9031574f`), not before. That ordering
matters for how it should be read: every claim below is marked **Implemented**, **Refused by
design** or **Roadmap**, and the marks describe this repository at that commit — not the
intent of the design.

Companion documents: [97 — operator CLI](97-operator-cli.md) is the short version (endpoint
table, refusals, auth matrix, verification). This document is the long one: why the boundary
is where it is, what each of the eight components consists of, where the proposed architecture
and the delivered code diverge, and what a bank should not believe yet.

---

## 1. The architecture

The product a bank installs is entirely inside its own data centre. ZELNX does not need
access to the bank's infrastructure, and the CLI does not need access to anything except the
bank's own control plane.

```text
                 BANK DATA CENTER / ON-PREM
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Admin Terminal                                             │
│       │                                                     │
│       ▼                                                     │
│  ┌───────────────┐                                          │
│  │ CryptoScan CLI│   ← this repository: api/cli_remote.py    │
│  └───────┬───────┘                                          │
│          │ HTTPS/mTLS                                       │
│          ▼                                                  │
│  ┌───────────────────────┐                                  │
│  │ CryptoScan Control    │  ← api/main.py + api/routers/*    │
│  │ Plane / API           │                                  │
│  └──────────┬────────────┘                                  │
│             │                                               │
│       ┌─────▼─────┐                                         │
│       │ Job Manager│       ← api/routers/jobs.py, collection │
│       └─────┬──────┘                                         │
│             │                                               │
│     ┌───────┼───────────────┐                               │
│     ▼       ▼               ▼                               │
│  Static   Runtime        Network                            │
│  Scanner  Collector      Scanner     ← estate_planes.py      │
│     │       │               │            estate_discovery.py │
│     └───────┼───────────────┘                               │
│             ▼                                               │
│       Evidence Engine        ← evidence/, estate_observations │
│             │                                               │
│             ▼                                               │
│     Canonical Estate Graph   ← shared_models/estate_graph.py │
│             │                                               │
│      ┌──────┼──────────────┐                                │
│      ▼      ▼              ▼                                │
│    CBOM   Digital Twin   Intelligence                       │
│                                                             │
│  PostgreSQL + Evidence Store + Graph/Index                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Two arrows are worth naming explicitly, because they are the whole design:

- **the vertical arrow from the terminal stops at the control plane.** There is no arrow from
  the CLI to a server, a switch, an HSM or a Kubernetes API. The CLI cannot collect, because
  it has no collector code and no credential to reach one;
- **the arrow into the evidence engine carries evidence, not conclusions.** Collectors emit
  observations; the graph, the twin and the six BOMs are projections of those observations.
  A scanner that emitted a CBOM directly would make the projection unauditable.

---

## 2. Why a CLI, and what it is not

A web console is the right instrument for **investigation**: the Digital Twin, crypto and
dependency graphs, blast radius, drift, PQC migration views, executive dashboards, evidence
exploration. None of that improves by being typed into a terminal.

The terminal is the right instrument for **operation**:

| The CLI is good at | The console is good at |
|---|---|
| installation, configuration, credential handling | dashboards and trend views |
| target registration and authorisation | Digital Twin and blast radius |
| submitting and watching jobs | CBOM/SBOM/HBOM/NBOM/VBOM/TechBOM exploration |
| evidence export and report generation | dependency and network graphs |
| troubleshooting (`doctor`, `status`) | investigations across many objects |
| automation, CI/CD, change-window scripts | executive and compliance reporting |
| working inside restricted or air-gapped networks | anything requiring a picture |

The division the product ships with:

```text
CLI = OPERATE        console = INVESTIGATE        API = INTEGRATE
```

**Implemented.** All three already exist against the same control plane: `cryptoscan` (this
document), `frontend/` (the console), and the FastAPI surface in `services/api`.

---

## 3. The CLI is not the scanner

The anti-pattern this architecture exists to avoid:

```text
CLI
 ├── Linux scanner
 ├── Windows scanner
 ├── Kubernetes scanner
 ├── Network scanner
 ├── HSM scanner
 ├── Cloud scanner
 ├── SBOM parser
 ├── CBOM parser
 └── Database
```

and the shape that is actually shipped:

```text
CLI  →  API  →  Job Manager  →  Collector Scheduler
                                     ├── Static Collector
                                     ├── Runtime Collector
                                     ├── Network Collector
                                     ├── Kubernetes Collector
                                     ├── Cloud Collector
                                     ├── HSM Collector
                                     ├── Database Collector
                                     ├── Certificate Collector
                                     └── SBOM/CBOM Importer
                                            ↓
                                        Evidence
                                            ↓
                                      Correlation
                                            ↓
                                     Digital Twin
                                            ↓
                             CBOM · SBOM · HBOM · NBOM · VBOM · TechBOM
```

**Implemented, with one documented exception.** The remote CLI collects nothing: it has no
collector import, no host access and no credential for one. The exception is the older
in-process commands (`collect`, `tick`, `serve`) which open the local database and, for
`collect`, negotiate TLS from the CLI's own process. That path predates this architecture, is
documented in [97 §9](97-operator-cli.md), and is the next thing to convert into a submission.
It is not hidden, and no remote command shares that code.

---

## 4. The eight components

### Component 1 — the CLI

**Implemented.** Entry point `cryptoscan = "api.cli:main"` (`services/api/pyproject.toml`),
with the client in `services/api/api/cli_remote.py` and the in-process operator in
`services/api/api/cli.py`.

```bash
cryptoscan version
cryptoscan status
cryptoscan doctor
cryptoscan login  [--mfa-code N]
cryptoscan logout

cryptoscan target list
cryptoscan target register --target-key … --system-id … --owner … --environment … \
                           --collection-method … --address … --not-before … \
                           --allowed-operation READ_PACKAGES
cryptoscan target show <id>
cryptoscan target authorize <id> [--reason …]
cryptoscan target revoke    <id> [--reason …]

cryptoscan scan [--system ID | --target ID --target-revision N | --dry-run | --manifest f]
cryptoscan scan --static | --runtime | --network

cryptoscan jobs list [--limit N]
cryptoscan jobs show <job-id>
cryptoscan jobs logs <job-id>
cryptoscan jobs cancel <job-id>
cryptoscan jobs retry <job-id>
cryptoscan jobs watch <job-id> [--timeout S] [--interval S] [--coverage]

cryptoscan evidence list [--target …] [--evidence-type …] [--limit N]
cryptoscan evidence show <evidence-id>
cryptoscan evidence verify <evidence-id>

cryptoscan bom sbom | cbom | hbom | nbom | vbom | techbom

cryptoscan report generate --scan <id> --format json|html|pdf [-o file]

cryptoscan twin status
cryptoscan twin snapshot [--include-payload]
cryptoscan twin diff [--from snapshot-a --to snapshot-b]

cryptoscan pqc status
cryptoscan pqc blockers
cryptoscan pqc impact --algorithm RSA|--protocol TLS|--asset <id> [--depth N]

cryptoscan ci gate --scan <id> [--profile banking] [--record] [--fail-on warn] [--sarif f]

cryptoscan bundle export --out DIR [--encrypt --passphrase-stdin]
cryptoscan bundle verify DIR
cryptoscan bundle import bundle.cse --into DIR

cryptoscan collect --submit --server URL [--system ID | --target ID --target-revision N] [--wait]

cryptoscan scope show

cryptoscan explain asset <id> [--fact-type …]
cryptoscan explain system <id>
cryptoscan explain node <id>

cryptoscan verify-installation --manifest release.json [--root DIR]
```

Global switches on every remote command: `--server`, `--json`, `--quiet`, `--token`,
`--api-key`, `--ca`, `--client-cert`, `--client-key`, `--insecure`.

Every one of these prints `source: <METHOD> <path> (HTTP <status>)` so an operator can check
it against the API. That is the mechanism by which a CLI number becomes auditable rather than
asserted.

### Component 2 — the control plane

The control plane is the FastAPI application in `services/api/api/` (1,192 routes at the time
of writing; `scripts/audit_build_status.py` measures them). The proposal's path list maps onto
what exists:

| Proposed | Actual in this build |
|---|---|
| `/api/v1/auth` | `/api/v1/auth/{login,login/mfa,logout,me,oidc,saml,mfa/*,roles}` |
| `/api/v1/targets` | `/api/v1/collection/targets` (+ `/{id}/authorize`, `/revoke`), `/api/v1/monitor/targets`, `/api/v1/network/targets` |
| `/api/v1/scans` | `/api/v1/scans/*`, `/api/v1/estate/evidence/scan`, `/api/v1/systems/{id}/scan` |
| `/api/v1/jobs` | `/api/v1/jobs`, `/api/v1/collection/jobs` (+ `/{id}/cancel`) |
| `/api/v1/evidence` | `/api/v1/estate/evidence/evidence/records`, `/api/v1/ops/evidence/chain-status` |
| `/api/v1/assets`, `/relationships` | `/api/v1/estate/evidence/catalog/{assets,relationships}` |
| `/api/v1/bom` | `/api/v1/estate/evidence/boms` (`?bom=SBOM\|CBOM\|HBOM\|NBOM\|VBOM\|TECHBOM`) |
| `/api/v1/twin` | `/api/v1/estate/evidence/twin/*` (20 routes) |
| `/api/v1/drift` | `/api/v1/estate/evidence/drift`, `/api/v1/network/scan/drift` |
| `/api/v1/pqc` | `/api/v1/estate/evidence/pqc`, `/api/v1/agility/pqc` |
| `/api/v1/reports` | `/api/v1/scans/{id}/report{,.html,.pdf}`, `/api/v1/report-snapshots` |
| `/api/v1/audit` | `/api/v1/auth/audit`, `/api/v1/auth/audit/verify` |

**Honest limitation.** The CLI uses the paths that exist; it does not invent `/api/v1/targets`
because a document proposed it. Where the proposal implies a capability that has no route
(§5 below, and scope diff), the command refuses rather than approximating.

### Component 3 — collectors

The collector contract the proposal describes (`discover`, `collect`, `validate`, `health`)
exists in the estate pipeline: `api/estate_planes.py` defines the planes,
`api/estate_discovery.py` runs them and stamps provenance, and each plane's evidence lands in
`estate_observations`. Collectors produce **evidence**, not BOMs — the projections are built
from the graph (`shared_models/estate_graph.py` → `BOM_KINDS`).

**Partially implemented, and not by the CLI.** The planes that exist today are the estate
collection planes plus the network/TLS collection adapters and the Kubernetes path
(`api/estate_kubernetes.py`). The proposal's full collector list — Windows, cloud metadata,
HSM, KMS, PKI, vendor agents — is **roadmap**, in the order Phase 5 of §12 describes. Nothing
in this repository claims a collector exists because a document listed it; the qualification
boundary for collection remains whatever `CURRENT-IMPLEMENTATION-STATUS.md` and the collector
verdicts say.

### Component 4 — the evidence fabric

**Implemented**, and it is the part of the product that most deserves the name "fabric".
Every observation carries an evidence id, target/asset identity, collector and collector
version, `observed_at`, evidence type, the fact itself, provenance (`source`, `method`) and a
hash; the schema lives in `shared_models/estate_graph.py` (`make_evidence`,
`POLICY_VERSION`, `annotate_raw_reference`) with storage in `api/estate_observations.py` and
migrations `0116`/`0117`.

```json
{
  "evidence_id": "EVID-9182",
  "target_id": "TARGET-001",
  "collector": "linux-runtime",
  "collector_version": "estate-collectors/1",
  "observed_at": "2026-10-28T06:20:00Z",
  "evidence_type": "RUNTIME_OBSERVED",
  "asset_id": "APP-PAYMENTS-01",
  "fact": { "algorithm": "AES-256-GCM", "purpose": "encryption" },
  "provenance": { "source": "runtime", "method": "crypto-api-observation", "raw_reference": "run:<id>" },
  "hash": "…"
}
```

```text
Evidence → Normalization → Identity Resolution → Correlation → Digital Twin → BOM projections
```

The CLI exposes read access to this (`evidence list`, `bom <kind>`, `explain …, twin …`), not
write access. A CLI that could write evidence would be a second, unaudited collection path.

### Component 5 — authentication

**Implemented** in the CLI, **partially** at the identity-provider level.

| Mechanism | Where | Status |
|---|---|---|
| Username/password + session | `POST /auth/login` → token; CLI stores it `0600` | Implemented |
| MFA | `POST /auth/login/mfa`; CLI refuses to store a challenge and asks for `--mfa-code` | Implemented |
| OIDC / SAML / SSO | `/auth/oidc/*`, `/auth/saml/*`, `/auth/sso/status` | Implemented server-side; the CLI does not run the browser flow yet (roadmap) |
| API key (machine) | `x-api-key`, validated in middleware before routing | Implemented; supported by the CLI, not the default |
| mTLS | `--client-cert/--client-key/--ca`; `SSLContext.load_cert_chain` | Implemented |
| Short-lived service identity / rotation | — | Roadmap |

The rule the proposal states — *do not make a permanent API key the primary mechanism* — is
respected: `login` obtains a session that expires, `logout` revokes it and clears the file, and
`doctor` reports the credential file's permissions (`PRIVATE` / `TOO_OPEN`) instead of assuming
them.

### Component 6 — least privilege

**Declared and partially enforced; this section is a claim a bank must verify per collector.**
What the platform says it does:

| Surface | Allowed | Never |
|---|---|---|
| Linux | `/etc`, package database, limited `/proc` metadata, systemd unit metadata, certificate locations, TLS configuration, binary metadata — read-only | root shell, arbitrary command execution, memory dumping, private keys, customer data, plaintext |
| Kubernetes | `get`, `list`, `watch` on an approved resource list (`api/estate_kubernetes.py`) | `create`, `delete`, `exec`, `patch`, `update` |
| Cloud | read-only IAM roles; discovery only | key retrieval, policy mutation |
| HSM | vendor, model, firmware, supported algorithms, key **metadata**, certificate associations | private keys, key material, plaintext |
| CLI | HTTP to the control plane | any of the above — it has no collector code |

The CLI's contribution to least privilege is architectural: because collection is not in the
CLI, an operator's terminal needs no estate credential at all. What it cannot do is prove a
collector's behaviour — that is a per-collector qualification, and this document does not
substitute for one.

### Component 7 — offline / air-gapped operation

**Implemented for the transfer artefact; roadmap for provenance.** The product is on-prem
first — nothing in the CLI or the API requires outbound internet — and an evidence bundle can
now be carried across a gap:

```bash
$ cryptoscan bundle export --out ./bundle --encrypt        # reads CRYPTOSCAN_BUNDLE_PASSPHRASE
bundle      ./bundle (9 files)
  unavailable boms/SBOM.json: HTTP 404: no stored run
encrypted   ./bundle.cse

$ cryptoscan bundle verify ./bundle
files       9 (0 missing, 0 modified)
signature   UNSIGNED
verdict     INTACT

$ cryptoscan bundle import ./bundle.cse --into ./restored
decrypted into ./restored
… then verified against the manifest it carried
```

What it carries, each file with the endpoint that answered it (`bundle.json → sources`):
the evidence records, the twin snapshot, the PQC exposure and each BOM projection. A
projection the platform cannot serve is written into `bundle.json → unavailable` and the
export exits `2` — a bundle that quietly omitted a BOM would read as a complete estate.

What it does not do, stated in every bundle's own `limits`: it carries stored evidence and
projections, **not** the collectors or their raw output; the manifest hashes prove the files
match the manifest, **not** who produced them (bundles are unsigned); encryption is
AES-256-GCM under a scrypt-derived key from one shared passphrase — confidentiality only, no
forward secrecy; and importing a bundle into another installation does not make its evidence
yours, because records keep the estate they were observed under.

Still roadmap: a signed bundle (an Ed25519 release/operator key over the manifest), incremental
bundles, a bundle that carries raw collector output, and offline licence/upgrade verification.

### Component 8 — signed packages

**Partially implemented — and the missing half is stated, not implied.**

```bash
$ python scripts/release_manifest.py --root /opt/cryptoscan -o release.json
wrote release.json (412 files)

$ cryptoscan verify-installation --manifest release.json --root /opt/cryptoscan
manifest   release.json
root       /opt/cryptoscan
files      412 (0 missing, 0 mismatched)
signature  MANIFEST_UNSIGNED
verdict    MATCH
```

The manifest carries `version`, `sha256` per file, `generated_at`, `signature: null` and its
own `limits`. A **signature, SBOM and build provenance attached to the release** are roadmap:
they are release-key operations outside this repository, and until they exist
`verify-installation` reports `MANIFEST_UNSIGNED` rather than printing a tick it cannot back.

---

## 5. Command reference: implemented, refused, roadmap

| Command (as proposed) | State | Behaviour in this build |
|---|---|---|
| `version`, `status`, `doctor`, `login`, `logout` | **Implemented** | §6 for `doctor`; `status` reads `/healthz`, `/readiness/summary`, `/auth/me` |
| `target list/show/register/authorize/revoke` | **Implemented** | `register` refuses without the authorisation fields |
| `scan` | **Implemented** (no `--system` → estate discovery) | |
| `scan --system` | **Implemented** | `POST /systems/{id}/scan` |
| `scan --target` | **Implemented** | `POST /collection/jobs`; requires `--target-revision` |
| `scan --static/--runtime/--network` | **Implemented** | mapped to `planes` in the request; sent, not assumed |
| `scan --dry-run` | **Implemented** | `GET /estate/evidence/plan`; no write |
| `scan --manifest` | **Implemented (subset)** | `scope.name` + `collectors`; everything else is printed as NOT sent |
| `jobs`, `jobs show`, `jobs cancel` | **Implemented** | `cancel` = `POST /collection/jobs/{id}/cancel` |
| `jobs watch` | **Implemented** | terminal states only; timeout exits 2; `--coverage` prints the platform's per-surface coverage |
| `jobs retry` | **Implemented** | `POST /jobs/{id}/retry`; prints the 409 reasons the server can refuse with |
| `evidence list` | **Implemented** | `GET /estate/evidence/evidence/records` |
| `evidence show <id>` | **Implemented** | `GET …/records/{id}` — added in this batch |
| `evidence verify <id>` | **Implemented** | `GET …/records/{id}/verify` — recomputes the content address (below) |
| `bom {sbom,cbom,hbom,nbom,vbom,techbom}` | **Implemented** | `GET /estate/evidence/boms?bom=<KIND>` |
| `report generate [--format]` | **Implemented** | streams to a file; prints sha256 of what it wrote |
| `twin status/snapshot/diff` | **Implemented** (remote) | never opens a local database |
| `pqc status` | **Implemented** | per-layer exposure only |
| `pqc blockers` | **Implemented, conditional** | exits 2 if the payload has no `blockers` field |
| `pqc impact` | **Implemented (as blast radius)** | `POST /estate/evidence/twin/impact`; refuses without a selector; exits 2 when the walk is truncated |
| `scope show` | **Implemented** | `GET /platform/scope` |
| `scope diff` | **Refused by design** | no scope-to-scope diff route |
| `explain finding <id>` | **Refused by design** | explain is per asset / system / node |
| `explain asset/system/node` | **Implemented** | every answer names its endpoint |
| `verify-installation` | **Implemented** (hashes only) | `MANIFEST_UNSIGNED` until releases are signed |
| `ci gate --scan <id>` | **Implemented** | `GET /scans/{id}/gate`, or `POST /ci/gate` with `--record`; exit 0 PASS / 2 WARN (`--fail-on warn`) / 1 FAIL; `--sarif` writes the report |
| `ci scan` (source tree) | **Roadmap** | the gate evaluates a completed scan; there is no source-tree mode, and the CLI refuses rather than pretending `ci gate` is one |
| `bundle export/verify/import` | **Implemented** | encrypted air-gap transfer; see §4 Component 7 |

Exit codes: `0` ok · `1` error or 4xx · `2` incomplete (5xx, coverage incomplete, watch
timeout, manifest mismatch, missing `blockers`) · `3` refused (capability absent, or
authorisation not expressible).

---

## 6. `doctor` in detail

```text
$ cryptoscan doctor
✓ credential file            OK            PRIVATE
! tls identity               NOT_CONFIGURED no client certificate — session token or API key will be used
✓ authenticated identity     OK            ops.bank
✓ control plane dependencies OK
✓ schema                     OK
✓ worker fleet               OK
! connectors                 WARN          HTTP 403: not authorised for connector health
✓ control plane              OK
✓ graph store                OK
· clock                      NOT_OBSERVED  the server does not report its clock; compare with NTP on the host

Result: READY WITH WARNINGS
note: READY means these probes answered. It does not mean a scan has run or that coverage is
complete — use `cryptoscan status --json` and the estate coverage report.
```

Four states, and the fourth is the point:

| State | Meaning |
|---|---|
| `OK` | the probe answered with a success verdict |
| `WARN` | degraded, or authorised-not-available (403/404/501 on a dependency) |
| `NOT_OBSERVED` | a 200 with no status field — a silent probe is **not** a pass |
| `FAIL` | an error, or an unreachable server |

`READY` never means "the estate is covered". The verdict says what it measured, and the line
beneath it says what it did not.

---

## 7. `dry-run`

```bash
$ cryptoscan scan --system payments --dry-run
DRY RUN — nothing was collected and nothing was written
estate       default
planes       7
  STATIC  [READY]
  RUNTIME [READY]
  NETWORK [READY]
  HSM     [NOT_CONFIGURED]  ← would run
the plan states what the platform is configured to collect; it is not a prediction of what a
run will observe.
```

**Implemented** as the platform's own plan (`GET /estate/evidence/plan`), printed verbatim.
What the proposal's mock-up shows that this does **not** do:

- it does not estimate target counts or collector counts that the endpoint does not return;
- it does not print a permissions table derived from `allowed_operations` per target. That
  information lives on the target (`cryptoscan target show <id>`), and a second copy computed
  by the CLI could disagree with the authorisation the server will enforce.

Both are roadmap items, and both need server-side support to be honest — a client-side
estimate would be a guess wearing a table.

---

## 8. Manifests

```yaml
scope:
  name: payments-production
collectors:
  static: true
  runtime: true
  network: true
policy:
  profile: banking
```

```bash
$ cryptoscan scan --manifest payments.yaml
scan: manifest key 'policy' has no field in the estate scan request and was NOT sent — the run
will not honour it
submitted — the CLI does not wait for collection unless asked
job           job-1
```

**Implemented subset:** `scope.name` → `scope`, `collectors` → `planes`. **Dropped loudly:**
anything else, including `targets`, `policy`, `cidrs`. This is deliberate: silently ignoring
`policy.profile` would let an operator believe a banking policy was applied to a run that
never saw it, which is precisely the failure this product exists to avoid. JSON needs nothing;
YAML needs PyYAML, and the command says so when it is absent.

---

## 9. Jobs, not synchronous scanning

**Implemented.** `scan` submits and returns; it does not block unless `--wait` is passed
(and `--wait` prints a warning that it is waiting).

```bash
$ cryptoscan scan --system payments
submitted — the CLI does not wait for collection unless asked
job           scan-77
status        QUEUED

watch it with: cryptoscan jobs watch scan-77
collectors run inside the bank; this command only submitted the work

$ cryptoscan jobs watch scan-77
[14:02:11] QUEUED
[14:02:19] RUNNING
[14:07:44] COMPLETED
```

**Progress is coverage, not a percentage.** The proposal's "Static Collection 83%" screen is
the right idea; a fabricated bar is not. `jobs watch --coverage` prints the platform's own
per-surface report (`GET /collection/jobs/{id}/coverage`) when the job settles:

```text
coverage
  PACKAGES               COLLECTED        412
  TLS                    NOT_AUTHORIZED
  basis: EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY
```

The `basis` line is printed verbatim because it is the honest scope of the number: the coverage
is the exact authorised manifest inputs, **not** an estate inventory. `NOT_AUTHORIZED` stays
`NOT_AUTHORIZED` — it is not rendered as 0%, which a reader would take as "nothing there".

---

## 10. Scope

```bash
$ cryptoscan scope show
organisation  Synthetic Bank
environment   Production
targets       124
status        AUTHORIZED
```

**Implemented** for `show`. **Refused** for `diff`:

```bash
$ cryptoscan scope diff --from yesterday.json --to today.json
scope diff: REFUSED — no scope-diff endpoint exists
  authorised scope is compared implicitly by the twin snapshot compare and by the collection
  coverage endpoints; there is no scope-to-scope diff route
  closest existing endpoint: GET /api/v1/estate/evidence/twin/compare
  closest existing endpoint: GET /api/v1/collection/jobs/{id}/coverage
```

The proposal's output (`+ payment-db-04`, `- legacy-api-02`, `~ hsm-prod-03`, `! network-zone-04`)
is the right shape for a **scope revision diff**, and it needs a server capability: revisions
of the authorised scope with an explicit comparison. Roadmap; a CLI-side file diff would
compare the operator's notes, not the authorisation the platform enforces.

---

## 11. CLI and console are complementary

```text
CLI = OPERATE   ·   console = INVESTIGATE   ·   API = INTEGRATE
```

| Task | Instrument | Where |
|---|---|---|
| login, MFA, session handling | CLI | `cryptoscan login` |
| register/authorise targets | CLI | `cryptoscan target …` |
| run and watch collection | CLI | `cryptoscan scan/jobs` |
| evidence and BOM export | CLI | `cryptoscan evidence/bom/report` |
| troubleshooting | CLI | `cryptoscan doctor/status` |
| automation, change windows, CI | CLI | scripts around the same commands |
| Digital Twin, graphs, drift, PQC views | console | `frontend/src/pages/*`, `components/DigitalTwinPanel.tsx` |
| live estate changes | console | SSE `/events/stream`, `/realtime/stream` (doc 96) |
| integration by another system | API | `services/api/api/routers/*` |

The console and the CLI read the same control plane, so a number cannot differ between them
except by time of reading — and the CLI prints the time implicitly by naming its endpoint.

---

## 12. Build order, mapped to what exists

The proposal's phases, against this repository:

| Phase | Content | State |
|---|---|---|
| 1 | CLI foundation: auth, config, TLS/mTLS, API client, `doctor`, `status` | **Done** (`cli_remote.py`, commit `9031574f`) |
| 2 | Target registry, scope, authorisation, revision, expiry, audit | **Partial** — registry/authorise/revoke and `not_before` exist; scope **revision diff** still has no route |
| 3 | Job engine: submit, queue, scheduler, worker, state, cancel, retry | **Partial** — submit/watch/cancel/**retry** and per-surface coverage are wired; queue inspection stays with the API |
| 4 | Evidence engine: schema, provenance, hashing, validation, storage, coverage | **Done** (spec 93/94 work; migrations `0116`/`0117`) |
| 5 | Collectors: Linux, Windows, network/TLS, certificates, containers, Kubernetes, SBOM, CBOM → HSM, KMS, database, cloud, PKI, runtime, vendor | **Partial** — Linux/network/TLS/Kubernetes/SBOM paths exist; the rest is roadmap |
| 6 | Correlation: identity resolution, relationships, crypto/dependency graph, conflicts | **Done** (`estate_graph.py`, `estate_conflicts.py`, `estate_catalog.py`) |
| 7 | Digital Twin: canonical estate, snapshots, history, drift, blast radius | **Done** (spec 94; `/twin/*`, `cryptoscan twin`) |
| 8 | BOMs: six projections | **Done** (`BOM_KINDS`, `/boms`) |
| 9 | Intelligence: risk, PQC readiness/blockers/impact, policy, compliance | **Partial** — exposure, `blockers` and `impact` wired, and the CI policy verdict is now a real command (`ci gate`); risk/compliance still console-side |
| 10 | Bank hardening: HA, backup/restore, air-gap, mTLS, SSO, RBAC, audit, monitoring, k8s, upgrade/rollback | **Partial, deployment-level** — `deploy/`, `k8s/`, `docker-compose*.yml`, runbooks; air-gap **bundles** now exist (§4 Component 7); **signed** releases and bundles remain roadmap |

Phase 10 is the one to be careful about. Most of it is true of a *deployment*, not of a
repository, and this document does not claim a bank has run it.

---

## 13. Digital Twin from the terminal

```bash
$ cryptoscan twin status          # GET /estate/evidence/twin
$ cryptoscan twin snapshot        # GET /estate/evidence/twin/snapshot
$ cryptoscan twin diff --from snapshot-100 --to snapshot-101
```

**Implemented** for the remote twin. The proposal's drift example (TLS 1.3 → TLS 1.2,
AES-256-GCM → AES-128-GCM, evidence ids, severity) is the shape `/twin/compare` returns; the
CLI prints the comparison's own counts and offers `--json` for the full document rather than
re-rendering it into a narrative it cannot verify.

The heavier twin operations remain **in-process** commands (`twin graph-load`,
`twin graph-verify`, `twin graph-traversal`, `twin simulate`, `twin why`, `twin changes`, …)
because they are operator actions against the same database, documented in
[94 — Digital Twin](94-cryptoscan-digital-twin.md).

---

## 14. Database and projection architecture

```text
PostgreSQL
   ├── identity / RBAC / sessions
   ├── evidence records + observations      ← source of truth
   ├── estate snapshots, policy_version, collector versions
   └── audit chain
              ↓  projection
        canonical estate graph  →  six BOMs  →  console / CLI reads
              ↓  optional load
          graph store (Neo4j) + search indexes   ← acceleration, never authority
```

The rule the proposal states — *evidence/canonical records are the source of truth; the graph
store is a projection* — is already enforced: `cryptoscan twin graph-verify` compares the store
against the projection id-by-id and can report `TRAVERSAL_MISMATCH` or `NOT_CONNECTED`; a load
without `--apply` only plans. Nothing in the product reads a conclusion back *from* the graph
store.

---

## 15. Security requirements and their status

| Requirement | Status |
|---|---|
| SSO / OIDC / SAML | endpoints implemented; CLI browser flow roadmap |
| MFA | implemented, honoured by the CLI |
| RBAC | implemented (8-role catalogue, `require_auditor`-style dependencies everywhere) |
| Service identities / mTLS | mTLS implemented in the client; service identity issuance roadmap |
| Target-level authorisation, expiry, revision | implemented (`not_before`, `expected_target_revision`) |
| Collector-level permissions | declared per collector; **verify per collector before a bank relies on it** |
| TLS everywhere, encryption at rest, key rotation | deployment-level; the CLI can refuse to proceed without TLS (`--insecure` is opt-in and visible) |
| Evidence hashing, immutable audit trail | implemented (hash chain, `/auth/audit/verify`, `/ops/evidence/chain-status`) |
| Backup/restore, HA | deployment-level, runbooks in `docs/runbooks/` |
| Runtime hardening (non-root, read-only FS, dropped caps, no Docker socket) | deployment-level (`k8s/`, `deploy/`); not asserted by this document |
| Audit of every operation: who/what/target/when/result/evidence/policy/version | implemented for control-plane actions; the CLI's own commands are not separately audited beyond the API calls they make |

---

## 16. `explain`

**Implemented** for the three objects that have routes:

```bash
$ cryptoscan explain asset payments-api --fact-type CRYPTO_ALGORITHM
subject     payments-api
evidence    ['EVID-9182']
reason      TLS 1.2 observed on the external listener
policy      BANK-TLS-003
confidence  HIGH

source: GET /api/v1/estate/evidence/why/payments-api?fact_type=CRYPTO_ALGORITHM (HTTP 200)

$ cryptoscan explain finding FIND-9182
explain finding: REFUSED — findings cannot be explained by id in this build
  the explain routes are per asset, per system and per graph node; a finding id has no route —
  using one of them would explain a different object
  closest existing endpoint: GET /api/v1/estate/evidence/why/{identifier}?fact_type=...
  closest existing endpoint: GET /api/v1/risk/systems/{system_id}/explain
  closest existing endpoint: GET /api/v1/graph/explain?node_id=...
```

The proposal's `explain finding` output (asset, observed value, cipher, evidence, source,
timestamp, collector+version, confidence, policy, reason, related objects, PQC relevance) is the
right target. Two of its fields are already available (evidence, policy, confidence, reason);
**collector + collector version** and **PQC relevance per finding** need a route that joins a
finding to its evidence record and its PQC classification — roadmap, and the reason this
command refuses today rather than assembling a partial answer that looks complete.

---

## 17. Repository structure: proposal vs. actual

The proposal suggests a `cli/` + `backend/` + `collectors/` re-organisation. This repository
keeps its current layout, and the reasoning is worth recording:

```text
actual                                  ← proposed equivalent
services/api/api/cli.py                 ← cli/main.py (in-process operator)
services/api/api/cli_remote.py          ← cli/{client,commands,config,output}
services/api/api/routers/*              ← backend/api
services/api/api/{estate_*,events}      ← backend/{jobs,evidence,correlation,digital_twin,bom,drift}
services/api/api/estate_planes.py       ← collectors/ (plane definitions)
shared/shared_models/shared_models/     ← shared_models/
services/database/db/                   ← database/
frontend/                               ← frontend
deploy/, k8s/, docker-compose*.yml      ← deployment/
docs/bank-environment/                  ← docs/bank
```

The entry point is `cryptoscan = "api.cli:main"`. Moving the tree would touch imports and CI
for a naming preference, and renames are the kind of change that produces a diff nobody can
review against behaviour. The boundary that matters — **client code cannot reach collector
code** — is enforced by module structure (`cli_remote.py` imports no estate/discovery module),
not by directory names. If the tree is reorganised later, this table is the mapping.

---

## 18. Deployment model

```text
                 ZELNX CryptoScan — ON-PREMISE
┌──────────────────────────────────────────┐
│ CryptoScan Platform                      │
│  API + Web UI + Job Manager              │
│  Evidence Engine · Correlation Engine    │
│  Digital Twin · Policy · BOM Engine      │
│  PostgreSQL · Evidence Storage · Graph   │
└───────────────────┬──────────────────────┘
                    │ secure internal API
        ┌───────────┼────────────┐
        ▼           ▼            ▼
     CLI/Admin   Collectors    Agents
                    │
       ┌────────────┼───────────────┐
       ▼            ▼               ▼
     Servers     Network          Cloud
       ▼            ▼               ▼
     Apps         LBs/HSM        K8s/KMS
```

**Everything is inside the bank.** The CLI is installed on an admin host or jump server; it
needs one outbound connection (HTTP to the control plane) and no estate credential. In this
repository that deployment is expressed by `docker-compose*.yml`, `k8s/`, `deploy/` and the
runbooks under `docs/runbooks/`.

---

## 19. What this document does not claim

1. No bank has run this CLI. It is tested against a fake control plane
   (`test_cli_control_plane.py`, 61 tests) and against the real API surface by endpoint
   existence and route-level tests, not by an end-to-end bank installation.
2. `doctor` proves probes answered. It does not prove the estate is covered, and it does not
   prove a collector is authorised.
3. `scan` submits work. It does not prove the control plane will execute it with the
   permissions the operator believes; the target's authorisation and the collector's scope are
   the authority.
4. `bom`, `evidence`, `pqc` and `twin` read stored evidence. An empty section means nothing was
   observed — which is not the same as nothing being present.
5. `verify-installation` verifies files against a manifest. It does not verify the manifest, and
   until releases are signed it says `MANIFEST_UNSIGNED`.
6. The collector list in §4 is the platform's, not the CLI's, and its qualification status is
   whatever the collector verdicts and `CURRENT-IMPLEMENTATION-STATUS.md` say — never this
   document.
7. **Signed** bundles and **signed** releases, `scope diff`, `ci scan` over a source tree,
   per-collector progress percentages and console risk/compliance verdicts are **roadmap**,
   listed as such in §5 and §12. The air-gap *bundle* and the CI *gate* exist, with the limits
   printed above: the bundle is unsigned and encrypts under one shared passphrase; the gate
   reports a decision the platform already made.
8. `evidence verify` recomputes a content address. A record whose id was assigned by the
   catalogue writer rather than derived from its content is reported as `ID_NOT_CONTENT_ADDRESSED`
   (exit 2), **not** as intact — and an intact hash says the record was not altered at rest, not
   that the observation it describes was true.

---

## 20. The architecture principle

> **CryptoScan is an on-premise cryptographic intelligence platform. The CLI is the bank's
> operational control interface, not the scanning engine. Collectors execute within the bank's
> security boundary, produce cryptographically verifiable evidence, and feed a canonical
> evidence-backed Digital Twin from which CBOM, SBOM, HBOM, NBOM, VBOM, and TechBOM are
> projected.**

The CLI implements this by having no collection code and one output contract:
`source: <endpoint>` on every command, `0/1/2/3` exit codes that distinguish success,
failure, incompleteness and refusal, and refusals that name the closest route instead of
approximating an answer.

---

## 21. Verification

| File | Tests | What is pinned |
|---|---|---|
| `services/api/tests/unit/test_cli_control_plane.py` | 41 | unconfigured client refuses before a connection; `--dry-run` issues only a GET; `scan --target` without a revision never reaches the server; the four refusals exit 3 with the closest route; 401 → 1 with the login hint; 5xx → 2 and "do not treat it as an empty result"; `doctor` reports `NOT_OBSERVED` for a silent probe; `twin status` never opens a local database; the session token is never echoed and is stored `0600`; both credentials are sent when configured |
| `services/api/tests/unit/test_release_manifest.py` | 4 | generator refuses an empty manifest; `verify-installation` accepts generator output; a tampered file is a mismatch |
| `test_estate_twin_cli.py`, `test_estate_kubernetes_cli.py`, `test_network_collect_cli.py` | 55 | the pre-existing in-process commands still behave after the merge |

Run them with the repository's PYTHONPATH (which includes `scripts/` for the manifest test):

```bash
export PYTHONPATH="services/api:services/api/tests/unit:services/runtime:services/network_scanner:\
services/network_scanner/tests:shared/shared_models:shared/shared_config:shared/shared_logging:\
services/cbom:services/database:services/control_plane:scripts:$(ls -d services/*/ | tr '\n' ':')"
.venv/bin/python -m pytest services/api/tests/unit/test_cli_control_plane.py \
    services/api/tests/unit/test_release_manifest.py -q
```
