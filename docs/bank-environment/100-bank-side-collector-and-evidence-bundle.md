# 100 — The bank-side collector and the evidence bundle it hands over

**Status:** the architecture is stored here in full; **one slice of it is built** at
`arena/bb4b80dd-cryproscan` — the bundle format, its verifier, and the ingestion *gate*
(§16–§18). Everything else below is marked **NOT BUILT** in its own section, including
the parts that sound finished. Nothing in this document is marked *built* because it was
described.

**What this document decides.** The bank's collectors run inside the bank. The platform
runs the projections. Between them travels **evidence**, never six pre-built inventories:

> The bank's CLI collects evidence and packages it into a signed bundle. CryptoScan
> verifies that bundle, then builds the six BOM projections from one canonical evidence
> graph. Six BOMs must never be six independent sources of truth.

The engine that does the second half already exists and is specified separately in
[`93-estate-evidence-graph-and-six-bom-projections.md`](93-estate-evidence-graph-and-six-bom-projections.md)
(`POST /estate/evidence/discover` → graph → SBOM/CBOM/HBOM/NBOM/VBOM/TechBOM). This
document is only about the seam in front of it.

---

## 1. Complete architecture

```text
                         BANK ENVIRONMENT
┌───────────────────────────────────────────────────────────────────────┐
│  Bank Admin / Security Engineer                                       │
│              │ commands                                               │
│              ▼                                                        │
│  ┌───────────────────────────────┐                                    │
│  │ CryptoScan CLI (bank-side)    │  auth / scope / target / scan      │
│  │ cryptoscan                    │  collect / package / transfer      │
│  └───────────────┬───────────────┘                                    │
│                  ▼                                                    │
│        ┌─────────────────────┐                                        │
│        │ Local agent/adapter │                                        │
│        └──────────┬──────────┘                                        │
│        ┌──────────┼─────────────────────────────┐                     │
│        ▼          ▼            ▼                ▼                     │
│     Linux      Windows      Network          K8s/Cloud                │
│        └──────────┴────────────┴────────────────┘                     │
│                           ▼                                           │
│                   Raw Observations                                    │
│                           ▼                                           │
│                    Evidence Bundle                                    │
│              (hash + signature + manifest)                            │
│                           ▼                                           │
│                  ┌───────────────────┐                                │
│                  │ Transfer Gateway  │                                │
│                  └─────────┬─────────┘                                │
│============================│==========================================│
│                            ▼                                          │
│              CRYPTOSCAN ON-PREM PLATFORM                              │
│       ┌──────────────────────────────────────────────┐                │
│       │ Ingestion / receiver                         │                │
│       └──────────────────────┬───────────────────────┘                │
│                     verify signature/hash                             │
│                              ▼                                        │
│                     Evidence Store                                    │
│                              ▼                                        │
│                     Normalization → Identity Resolution               │
│                              ▼                                        │
│                     Canonical Estate Graph / Twin                     │
│                ┌─────────────┼──────────────┐                         │
│                ▼             ▼              ▼                         │
│             SBOM          CBOM            HBOM                        │
│                └─────────────┼──────────────┘                         │
│                ┌─────────────┼──────────────┐                         │
│                ▼             ▼              ▼                         │
│              NBOM          VBOM           TechBOM                     │
│                              ▼                                        │
│                    Crypto Intelligence (drift / PQC / risk)           │
│                              ▼                                        │
│                     CryptoScan Web UI                                 │
└───────────────────────────────────────────────────────────────────────┘
```

Three interfaces, three jobs:

```text
CLI  →  collection / operation      (runs in the bank)
API  →  orchestration / integration (runs on the platform)
UI   →  visualization / investigation
```

| Stage | State at this commit | Where |
|---|---|---|
| CLI exists, sessions, refusal semantics | **built** | `services/api/api/cli_remote.py` (spec 97/98) |
| Collectors produce raw observations, not BOMs | **built** | `shared_models/host_collection.py`, `estate_discovery.py` |
| **Bundle format + manifest + verifier** | **built in this change** | `shared/shared_models/shared_models/evidence_bundle.py` |
| **Ingestion gate (verify a bundle over HTTP)** | **built in this change** | `services/api/api/routers/ingestion.py` |
| Bundle → normalisation → graph → six BOMs | **NOT BUILT** (the graph/projections exist; the bundle is not yet a source for them) | — |
| Chunked / resumable transfer | **NOT BUILT** | — |
| mTLS machine identity, `cryptoscan register` | **NOT BUILT** (the platform has an mTLS module for other callers) | `api/security/mtls.py` |
| CLI `bundle` command group | **NOT BUILT** | — |

---

## 2. Terminology: one CLI, not two talking to each other

The bank does **not** build its own CLI and point it at ours. The bank installs *our* CLI
inside their environment:

```text
Bank operator  →  cryptoscan (installed in the bank)
                        │  evidence bundle
                        ▼
              CryptoScan ingestion API      (on the platform)
```

There is no "CLI-to-CLI" protocol: the CLI is the client, the platform is the server.

---

## 3. Two deployment modes

**Mode A — connected on-prem.** The CLI talks to the platform directly over TLS/mTLS and
sends the bundle. *Today:* the CLI's transport is TLS with an operator-selected server,
and the ingestion gate accepts a bundle over an authenticated request. mTLS client
identity for collectors is **NOT BUILT**.

**Mode B — air-gapped / restricted.** The CLI writes a bundle to disk, an operator carries
it across the gap, and the receiver verifies it there. *Today:* `write_bundle` /
`read_bundle` / `all_paths` in the bundle module support exactly this shape
(`observations/`, `imports/`, `certificates/`, `relationships/`, `errors/`, plus
`scope.json`, `targets.json`, `coverage.json`, `hashes.json`). The CLI command that
produces it, and `cryptoscan bundle verify`, are **NOT BUILT** — see §25.

---

## 4. CLI authentication

Do not make `CLI → permanent API key` the primary enterprise model.

```text
Bank user → enterprise SSO → MFA → short-lived CLI session
CLI       → mTLS (machine identity) → platform
```

*Short-lived sessions* are **built** (the CLI stores a session token with an expiry and
`cryptoscan login` re-issues it; API keys exist but are not the human path).
*SSO to the platform* is **built on the server side** (`/sso`, `/scim` routers) and **NOT
WIRED INTO THE CLI**. *Machine identity via mTLS for collectors* is **NOT BUILT**.

---

## 5. Registration

`cryptoscan register` → approval → machine identity → stored certificate. **NOT BUILT.**
The CLI has `login`, `status`, `doctor`; it has no registration flow, and no certificate
is issued to an installation.

---

## 6. Scan request flow

```text
CLI → authenticate → validate authorisation → scope manager → job manager → collectors
```

**Built, with a different transport than this architecture assumes.** Jobs are real
(`POST /scans/trigger`, `GET /scans/{id}`, the queue, the worker, `cryptoscan jobs
watch`), and a scan never blocks: it is a job with its own status record. What is **NOT
BUILT** is the collector *scheduler running inside the bank*: today the collectors the
platform can run are the ones that run on the platform's side of the gap.

The rule that matters and is implemented: **a run's outcome is read from its own status
record, never inferred from the 202 that accepted it.**

---

## 7. Collectors must not generate six BOMs

This is the rule the tree already follows (spec 93), and this document keeps it:

```text
static │ runtime │ network │ pki │ hardware │ vendor │ k8s │ cloud
        └───────────┴───────┴─────┴──────────┴───────┘
                              ▼
                          EVIDENCE
                              ▼
                   CANONICAL ESTATE GRAPH
                              ▼
                  six BOM *projections*
```

A collector that emitted a BOM would be inventing an inventory. Collectors emit
observations with provenance; `build_graph` projects.

---

## 8. How the six BOMs are collected

Some facts are **collected**, some **imported**, some **derived**, some **correlated**.
The product therefore does not say "we scan six BOMs". It says:

> CryptoScan collects estate evidence and produces six evidence-backed BOM projections.

In the bundle, that distinction is structural: locally collected observations live under
`observations/`, imported third-party documents under `imports/`, and both carry their own
`sha256` in the manifest. `VENDOR_DECLARED` never becomes `OBSERVED` because it arrived in
the same file.

---

## 9–15. The six projections

| BOM | Question | Projection exists (spec 93) | Bundle member it can come from |
|---|---|---|---|
| **SBOM** | what software exists? | ✅ | `observations/linux|windows/*.json`, `imports/sbom/*` |
| **CBOM** | what cryptography is used, where? | ✅ | `observations/runtime|network/*.json`, `certificates/*` |
| **HBOM** | what hardware / HSM / TPM exists? | ✅ | `observations/hardware/*.json` |
| **NBOM** | what network assets and relationships? | ✅ | `observations/network/*.json`, `relationships/*` |
| **VBOM** | who supplies the technology? | ✅ | `imports/vendor/*`, `relationships/*` |
| **TechBOM** | how does the whole estate connect? | ✅ | all of the above |

The projections are the estate engine's; what is **NOT BUILT** is the adapter that turns a
verified bundle into the discovery payload that engine consumes (§18, §26).

HBOM stays metadata-only: no key material is collected, and the bundle format has no
member kind for secrets.

---

## 16. The bundle format — **built**

Schema `cryptoscan.bundle/1`. A bundle is:

```text
cryptoscan-bundle/
├── manifest.json          # signed, lists every member with its sha256 and size
├── scope.json             # optional: the scope revision the collector ran under
├── targets.json           # optional: what it expected to reach
├── coverage.json          # optional: the collector's own counters
├── hashes.json            # optional: per-directory detail
├── observations/{linux,windows,network,runtime,kubernetes,cloud,...}/*.json
├── imports/{sbom,cbom,vendor}/*
├── certificates/*
├── relationships/*
└── errors/*
```

`MEMBER_KINDS` and `BUNDLE_FILES` are the whole allow-list. A member path that is
absolute, contains `..` or `\`, or sits outside those prefixes is **refused when the
manifest is built** (`MEMBER_PATH_REFUSED` at verification time), so a bundle cannot be
used to write outside its own directory.

The manifest carries the signature block in the same shape the release manifest and the
air-gap bundle already use (`cryptoscan.signature/1`, Ed25519, from
`shared_models/release_signature.py`). A separate `signature.sig` file is **not** part of
this build; the signature is a member of `manifest.json` and covers every other member of
it, so the two documents cannot be separated in transit.

---

## 17. Manifest — **built**

```json
{
  "schema": "cryptoscan.bundle/1",
  "bundle_id": "BND-2026-00182",
  "organization_id": "BANK-001",
  "environment": "production",
  "scan_id": "SCAN-2026-00182",
  "collector_version": "1.0.0",
  "scope_revision": "REV-192",
  "created_at": "2026-10-29T08:30:00Z",
  "member_count": 2,
  "total_bytes": 96,
  "members": [
    {"path": "observations/linux/host-01.json", "kind": "observations", "sha256": "…", "bytes": 44}
  ],
  "coverage": { "counts": {...}, "state": "PARTIAL", "observed_fraction": 0.953, "reasons": [...] },
  "signature": {"schema": "cryptoscan.signature/1", "alg": "Ed25519", "…": "…"},
  "limits": ["…"]
}
```

`manifest_digest()` hashes the canonical bytes the signature covers, so a receipt can name
one manifest without re-deriving it.

---

## 18. Transfer protocol — the verify route is **built**, the ingest is not

Accepted today:

```text
GET  /api/v1/ingestion/bundles/schema    the format, member kinds, reason codes, limits, trust config
POST /api/v1/ingestion/bundles/verify    {manifest, members: {path: base64}}  → verdict
```

The verify route is deliberately a **gate, not an ingest**:

* `accepted` is `true` **only** when the manifest signature verifies against a key the
  *deployment* configured (`CRYPTOSCAN_BUNDLE_TRUST_KEYS`). A request cannot nominate the
  key it is verified against — otherwise a caller could authorise their own bundle.
* Without a configured key the answer is `SIGNATURE_UNCHECKED` plus
  `NO_TRUSTED_COLLECTOR_KEY` in `deployment_findings`. It is not an acceptance.
* An unsigned bundle is `UNSIGNED`; a tampered, missing, resized or unlisted member is
  `REJECTED` with that member's path named.
* A body over `CRYPTOSCAN_BUNDLE_MAX_BYTES` (default 64 MiB) is refused `413`
  `BUNDLE_TOO_LARGE`; a non-base64 member is `422` `MEMBER_NOT_BASE64` — a verdict, not a
  500.
* Every response says `"projection": {"state": "NOT_ATTEMPTED", "reason": …}` because this
  build does not yet normalise a bundle or project from it.

Not built: `POST /ingestion/sessions`, `/bundles`, `/{id}/chunks`, `/{id}/complete`,
`GET /{id}/status`; resumable transfer; the evidence store write; the projection run.

---

## 19. Large bank scanning — **NOT BUILT**

Parallel collectors, multiple bundles per estate, an ingestion queue and workers are a
design, not code. The format does not prevent it (`bundle_id` + `scan_id` are per-bundle),
but the receiver today verifies one bundle in one request. A large estate currently needs
a bounded slice; saying "chunked" without building it would be the exact kind of claim this
repository refuses.

---

## 20. Do not transfer duplicate data

One fact, several projections:

```text
Evidence E-001 (OpenSSL 3.0.13 on host-01, OBSERVED, 2026-10-29T07:43Z)
        ├── SBOM component
        ├── CBOM relationship (the provider of the application's crypto)
        └── TechBOM edge (application → host)
```

This is a property of the estate engine (spec 93), not of the bundle: the bundle carries
the observation **once**, and the projections are built from it. A collector that copies
one finding into three files undermines it, which is why the manifest records every member
and the receiver refuses members the manifest does not cover.

---

## 21. Worked example: one payment application

Collected in the bank, shipped as members:

```text
observations/linux/payments-api.json     OpenSSL 3.0.13, AES-GCM API reference
observations/runtime/payments-api.json   AES-256-GCM observed in a crypto call
observations/network/10.20.10.15:443.json TLS 1.3, TLS_AES_256_GCM_SHA384, X25519
certificates/ext-lb-01.json              ECDSA P-256, ECDSA-SHA256
observations/hardware/hsm-01.json        HSM-01, RSA-3072 key metadata (no key material)
observations/cloud/payments-image.json   image payments:v42
```

Projected on the platform from one graph: SBOM (OpenSSL), CBOM (AES-256-GCM, RSA-3072,
ECDSA P-256), NBOM (the TLS relationship), HBOM (HSM-01), VBOM (the HSM vendor),
TechBOM (the chain from system to vendor). One identity per real thing; one evidence
record cited by every projection that uses it.

---

## 22. The UI must expose the connections

Clicking a crypto asset should answer "why do you say this?" with the evidence record, its
type and its timestamp. That surface exists at the estate-graph level (spec 93: evidence
records carry `evidence_type`, `source`, `observed_at`, and the UI cites them). It does
**not** yet have a bundle-aware view showing which transfer a record arrived in — **NOT
BUILT**.

---

## 23. Conflict handling

Do not overwrite one source with another. The tree already keeps them apart:
`api/estate_conflicts.py` records conflicts as data (`IMPORTED` vs `OBSERVED`, versions,
confidence) instead of choosing a winner. In bundle terms, a version disagreement between
`imports/sbom/*` and `observations/runtime/*` is *visible*, because the two arrive as
different members with different digests and different evidence types.

---

## 24. Coverage travels with the bundle + **built**

`summarise_coverage()` returns counts, not a percentage:

```text
expected 150 · accounted 150 · unaccounted 0 · state PARTIAL
reasons: ["COVERAGE_FAILED_TARGETS"]   (2 failed, 1 unauthorized, 4 partial)
observed_fraction 0.953  — of the collector's own registered scope, not of the bank
```

* `unaccounted = expected − (collected + partial + failed + unauthorized + unavailable)`.
  Seven hosts nobody classified come back as `unaccounted: 7` with
  `COVERAGE_UNACCOUNTED_TARGETS`, not as "95% done".
* `expected: 0` or a missing counter is `UNKNOWN` with `observed_fraction: null` — never
  `1.0`.
* A bad outcome keeps the state `PARTIAL` even when every target is accounted for.

What is **NOT BUILT**: the per-plane coverage table in the CLI (`cryptoscan scan coverage`)
and the bundle-derived coverage screen.

---

## 25. CLI command architecture

The tree's CLI (spec 98) already has `auth`, `server`, `scope`, `target`, `scan`, `jobs`,
`evidence`, `bom`, `twin`, `pqc`, `report`, `doctor`, `collector`, `assurance`.

Missing for this architecture, and **NOT BUILT**:

```text
cryptoscan bundle create  --scope payments --output evidence.bundle
cryptoscan bundle verify  evidence.bundle          # local, air-gapped
cryptoscan bundle upload  evidence.bundle          # POST /ingestion/bundles/verify
```

`bundle verify` is a *local* command and therefore has no `source: METHOD /path (HTTP n)`
line to print — that is a real exception to the CLI's own contract and has to be decided
deliberately (the honest option is `source: LOCAL <path> (no network)`), not smuggled in.

---

## 26. End-to-end flow, with the seam marked

```text
bank user → CLI → short session → scope → job → collectors → observations
                                                              │
                                             ┌────────────────▼───────────────┐
                                             │ BUNDLE: manifest + hashes + sig│  BUILT (format)
                                             └────────────────┬───────────────┘
                                                              ▼
                                          POST /ingestion/bundles/verify   BUILT (gate)
                                                              ▼
                                              evidence store / normalise    NOT BUILT
                                                              ▼
                                             identity resolution + graph    built (spec 93)
                                                              ▼
                                                 six BOM projections        built (spec 93)
                                                              ▼
                                              crypto intelligence + UI      built
```

The seam is exactly one call wide today, and it verifies rather than ingests.

---

## 27. The core rule

> **The six BOMs are never independent sources of truth.**

```text
evidence → canonical estate graph → relationships + facts → six projections
```

Identity, relationships, timestamps and evidence are shared; only the projected view
differs. This rule is enforced by the engine (spec 93) and, from this change, by the
transfer format: one observation is one member, one digest, one signature.

---

## 28. What the bank transfers

Evidence, with its own hashes and provenance — not six databases:

```text
bank → bundle (evidence + scope + coverage + signature) → platform
platform → verify → normalise → graph → six projections → twin → intelligence → UI
```

---

## 29. What is built, and what proves it

**Built in this change**

| Item | File | Test |
|---|---|---|
| Bundle schema, member allow-list, safe paths, digests | `shared/shared_models/shared_models/evidence_bundle.py` | `services/api/tests/unit/test_evidence_bundle.py` (15) |
| Build/manifest/digest | same | same |
| Verify: `VERIFIED` / `UNSIGNED` / `SIGNATURE_UNCHECKED` / `REJECTED` with per-member reasons | same | same |
| Coverage accounting with `unaccounted` and no bare percentage | same | same |
| Air-gapped read/write of a bundle directory | same | same |
| `GET /api/v1/ingestion/bundles/schema` | `services/api/api/routers/ingestion.py` | `services/api/tests/unit/test_ingestion_bundle_verify.py` (6) |
| `POST /api/v1/ingestion/bundles/verify` (gate + deployment findings) | same | same |

**Verified**

```bash
PYTHONPATH="$(find $PWD/services $PWD/shared -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')" \
  .venv/bin/python -m pytest services/api/tests/unit/test_evidence_bundle.py \
                                services/api/tests/unit/test_ingestion_bundle_verify.py -q
# 21 passed
```

**Not built** — stated once, here, so no later reading of this document can mistake it:

1. the adapter that turns a verified bundle into the estate discovery payload;
2. the evidence-store write and the projection run triggered by an accepted bundle;
3. chunked/resumable transfer and ingestion sessions;
4. collector registration, machine identity, mTLS client certificates;
5. the CLI `bundle` command group (create / verify / upload);
6. a bundle-aware UI view (which transfer did this asset arrive in);
7. per-plane coverage in the CLI and on screen;
8. signing-key rotation, revocation and trusted timestamps for bundles.

**Next slice**, in dependency order: (1) → (2) → (5) → (3). Until (1) and (2) exist, an
accepted bundle is a verified transfer that has not yet become an estate.
