# 97 — The operator CLI: a control-plane client, not a scanner

Status: partial. Installed `scan`, `collect --submit`, `schedule`, `tick`, `coverage`
and `boms` commands now use the **bank-owned on-prem control plane** rather than the
administrator's local database. Collectors and job workers run inside that bank
boundary. Ten twin commands are migrated: from an operator terminal `graph-load`,
`graph-verify`, `placement`, `asset`, `search`, `why`, `graph-traversal`,
`simulate`, `simulations` and `changes` call the control plane's twin routes
(`POST /twin/graph/load`, `/twin/graph/verify`, `/twin/impact`, `/twin/simulate`
and the GET twin reads) — the control plane owns the graph-store connection and
the CLI still never touches one; the in-process bank-server CLI keeps its local
handlers. `serve` remains the bank-server daemon entry point; the remaining older
twin commands (catalog, algorithms, conflicts, lifecycle, intel, trust-paths,
history, evidence, detect, ack) still use direct database access and require
migration before the entire operator CLI is API-only.

The long-form architecture and command reference — the eight components, what is implemented
versus refused versus roadmap, and why — is
[98 — the CLI architecture](98-cli-architecture.md). This document is the short version.

## 1. The boundary this draws

```
admin terminal  →  cryptoscan  →  HTTPS / mTLS  →  CryptoScan control plane (in-bank)
                                                        │
                                                  job manager
                                                        │
                                    static · runtime · network · certificate · HSM collectors
                                                        │
                                                  evidence store
                                                        │
                                            canonical estate graph → CBOM/SBOM/HBOM/NBOM/VBOM/TechBOM
```

The installed operator CLI enumerates no hosts, reads no `/proc`, and talks to no HSM.
It may use a bank-provisioned mTLS client identity for its API connection, but never
retrieves the bank's cryptographic key material from a collector. It authenticates
to the bank's own control plane, submits work, watches it, and reads
evidence back. That is what makes it installable: everything that touches the estate stays
inside the bank's security boundary, and the tool an administrator runs from a jump host has
no collection capability to abuse. The API, PostgreSQL, worker, evidence storage and
optional graph/index are owned and operated **inside the bank**. No ZELNX-hosted
database or cloud service is a dependency of this control-plane path. External
cloud/HSM collectors remain separately scoped and unqualified until approved.

Each command prints the endpoint it read (`source: GET /path (HTTP 200)`). An operator can
check any number against the API, and a command whose endpoint does not exist cannot print
something invented.

## 2. Commands, and the endpoints behind them

| command | endpoint | notes |
| --- | --- | --- |
| `version` | `GET /health` | falls back to the local build string and says so |
| `status` | `GET /healthz`, `/readiness/summary`, `/auth/me` | three probes; failures are counted, not averaged away |
| `doctor` | `/healthz/dependencies`, `/healthz/schema`, `/health/worker-fleet`, `/health/connectors`, `/control/health`, `/graph/health`, `/automation/health/platform` | see §4 |
| `login` | `POST /auth/login`, `/auth/login/mfa` | password from private TTY or `--password-stdin`, never `--password` in process arguments; MFA honoured; `--sso` drives the OIDC/SAML browser flow and `--sso-token-file` (`-` = stdin) relays an IdP id_token — the server verifies it, the CLI cannot |
| `logout` | `POST /auth/logout` | revokes, then clears the stored token |
| `service-key issue` | `POST /api-keys` | short-lived machine identity, 30-day lifetime by default; `--no-expiry` names the permanent exception and says so out loud; the raw key is shown exactly once |
| `service-key list / report` | `GET /api-keys`, `/api-keys/rotation/report` | every key with its expiry and rotation state; an empty list prints that identities are created explicitly, never assumed |
| `service-key rotate <id>` | `GET /api-keys`, `POST /api-keys` | mints a replacement copying the old policy first; `--retire` revokes the old key after the replacement exists |
| `service-key revoke <id>` | `DELETE /api-keys/{id}` | fails closed immediately |
| `target list / show` | `GET /collection/targets`, `/{id}` | |
| `target register` | `POST /collection/targets` | no defaults invented (§3) |
| `target update <id>` | `PUT /collection/targets/{id}` | sends only the fields you named; with none it refuses rather than PUTting an empty revision |
| `target authorize / revoke` | `POST /collection/targets/{id}/authorize`, `/revoke` | |
| `jobs list / show / logs` | `GET /jobs`, `/{id}`, `/{id}/logs` | |
| `jobs cancel` | `POST /collection/jobs/{id}/cancel` | collection jobs own cancellation; the generic job API has no cancel |
| `jobs watch` | `GET /jobs/{id}` | source-scan jobs; terminal states only; timeout exits 2 |
| `jobs watch --collection --coverage` | `GET /collection/jobs/{id}`, then `/coverage` | exact collection job and its surface receipts, not a source-scan job |
| `jobs retry <id>` | `POST /jobs/{id}/retry` | a 409 is shown with the server's reason, not retried blindly |
| `jobs evidence / errors / projections <job>` | `GET /collection/jobs/{id}/evidence`, `/errors`, `/projections` | an empty list is printed as empty, with the reminder that it is not proof the estate is empty |
| `collector list / show <id>` | `GET /collection/collectors` | prints how many collectors are production-execution qualified; `show` says the filter happened client-side (it is a catalog, not a per-collector route) |
| `evidence list` | `GET /estate/evidence/evidence/records` | `--target`, `--evidence-type`, `--limit` |
| `evidence show <id>` | `GET /estate/evidence/evidence/records/{id}` | 404 is `evidence_not_in_this_estate`, never an empty record |
| `evidence verify <id>` | `GET …/records/{id}/verify` | recomputes the content address: exit 0 intact, 2 not content-addressed, 1 mismatch |
| `bom <kind>` | `GET /estate/evidence/boms?bom=<KIND>` | SBOM, CBOM, HBOM, NBOM, VBOM, TECHBOM |
| `pqc status` | `GET /estate/evidence/pqc` | per-layer exposure, never summed |
| `pqc blockers` | same, `blockers` field | refuses to invent one if the field is absent |
| `pqc impact` | `POST /estate/evidence/twin/impact` | blast radius from an algorithm, protocol, asset or key size; truncated walks exit 2 |
| `ci gate --scan <id>` | `GET /scans/{id}/gate`, `…/gate.sarif`, `POST /ci/gate` | never recomputes the decision: PASS 0, WARN 2 (with `--fail-on warn`), FAIL 1 |
| `bundle export / verify / import` | `GET` of nine evidence and projection routes | `--encrypt` (AES-256-GCM + scrypt), `verify` byte-checks the files against the manifest, `import` refuses a tar member escaping the target |
| `collect --submit --target/--system` | `POST /collection/jobs` or `/systems/{id}/scan` | submits an exact target/system job; refuses unbound selectors and ignored local collection flags |
| `schedule add/list/enable/disable` | `/estate/evidence/schedules` | selected estate via `--tenant` or `CRYPTOSCAN_TENANT_ID`; server verifies current human authority |
| `tick` | `POST /estate/evidence/tick` | requests an exact-estate projection; incomplete run exits 2 |
| `coverage` / `boms` | `GET /estate/evidence/coverage`, `/boms` | reads the retained bank graph; no terminal database |
| `scope show` | `GET /platform/scope` | |
| `scope snapshot [--label]` | `POST /scope/snapshots` | captures the resolved scope as a named revision; a revision never captured cannot be diffed later |
| `scope snapshots` | `GET /scope/snapshots` | newest first; an empty list means none were captured, not that the scope never changed |
| `scope diff --from --to` | `GET /scope/diff?from=&to=` | verdicts computed by the control plane and rendered here (`+ added`, `- removed`, `~ changed`, `! blocked` — a blocked row is declared but disabled or excluded, never a widening of authority); `current` is the live envelope; an empty diff is not proof the scope was enforced, only that it did not change |
| `assurance records --kind` | `GET /assurance/records` | every retained revision, with `has_more`/`next_offset`; an empty kind is printed as an empty table, not a clean estate |
| `assurance history <kind> <id>` | `GET /assurance/records/{kind}/{id}` | the chain for one exact subject |
| `assurance coverage <register>` | `GET /assurance/registers/{id}/coverage` | counts plus the denominator and completeness basis; **no percentage**, because the denominator is the register |
| `assurance trace <application>` | `GET /assurance/applications/{id}/trace` | resolved paths and unresolved components; `complete`/`runtime_verified` are printed as false |
| `assurance workbook <sample>` | `GET /assurance/samples/{id}/workbook` | the frozen prediction set with blind truth labels; no precision or recall is computed |
| `assurance adapter <id>` | `GET /assurance/adapters/{id}` | `OFFLINE_PROFILE_EXERCISED` or `NOT_QUALIFIED`; live vendor support is printed as NOT SUPPORTED |
| `assurance observations <adapter> <evidence>` | `GET …/supplier-evidence/{id}/observations` | supplier facts, with "no automatic join" and "not independently verified" stated |
| `assurance redis <objectives>` | `GET /assurance/redis-objectives/{id}/qualification` | role × scenario matrix, accepted flags, unqualified roles |
| `assurance decisions` | `GET /assurance/operator-decisions` | section counts and the server's own `uncertainty` string |
| `assurance launch · engagement · pilot` | `GET /assurance/launch/operations`, `…/engagements/{id}/status`, `…/pilots/{id}/status` | the launch payload is printed verbatim; it is not summarised into a verdict |
| `assurance collection <job>` | `GET /assurance/collections/{job}` | partial progress; an unfinished phase is not a failed one |
| `explain finding <id>` | `GET /findings/{id}`, `/verify` | reports `NOT_JOINABLE` for the estate half: a finding has a file path, not an asset id |
| `ci scan --path <dir>` | `POST /devsecops/sbom/scan` | the path is resolved **on the control plane**, and `--gate` needs a scan id |
| `explain asset / system / node` | `/estate/evidence/why/{id}?fact_type=`, `/risk/systems/{id}/explain`, `/graph/explain` | every answer names its source |
| `report generate` | `/scans/{id}/report`, `.html`, `.pdf` | streamed to a file, sha256 printed |
| `twin status / snapshot / diff` | `/estate/evidence/twin`, `/twin/snapshot`, `/twin/compare` | remote mode; never opens a local database |
| `scan --path <absolute> --dry-run` | `POST /scans/preflight` | exact path on the bank control plane; read-only admission preview, no job or collection |
| `scan --path <absolute>` | `POST /scans/preflight`, then `/scans/trigger` | exact approval and isolation preview first; submits only after ADMITTED, then requires a queued job receipt; not Git-branch attested |
| `scan --system <id>` | `POST /systems/{id}/scan` | requires a queued job receipt, not a synchronous report |
| `scan --target <id>` | `POST /collection/jobs` | requires `--target-revision`; watch with `--collection` |
| `scan` (no target) | *(refused)* | a generic estate projection is not a collection job |
| `scan --manifest <file>` | *(refused)* | no silent dropping of target, policy or collector fields (§5) |
| `capture submit` | `POST /performance/captures/import` | submits the body **exactly as signed** — this CLI holds no signing key; the control plane verifies the signature and refuses unsigned or tampered envelopes |
| `capture receipt` | `GET /performance/captures/{receipt_id}` | the signed server receipt for one exact submission |
| `capture trust-anchor` | `GET /performance/captures/trust-anchor` | which key signed the receipts, and whether the capture-signing key is configured yet |
| `verify-installation` | *(local)* | hashes files against a release manifest and checks its Ed25519 signature (`--public-key`), §6 |
| `collect` (no `--submit`) | *(refused in installed CLI)* | network collection belongs in bank-hosted collectors, not the operator terminal |

## 3. What the CLI refuses, on purpose

A refusal exits `3` and names the closest endpoints that *do* exist:

| command | why it refuses |
| --- | --- |
| `target register` without the authorisation fields | `not_before`, `allowed_operations`, owner and environment have no safe default; a target registered with "everything, already valid" is an authorisation nobody granted |
| `scan --target` without `--target-revision` | the control plane refuses a job whose target changed since the operator read it |
| `pqc blockers` when the payload has no `blockers` | the per-layer exposure is printed instead, and the exit code is 2 |

## 4. `doctor`

Every line is a probe with a state, and the states are not collapsed:

- `OK` — the probe answered with a success verdict;
- `WARN` — degraded, or authorised-not-available (a 403/404/501 on a dependency);
- `NOT_OBSERVED` — a 200 with no status field. A silent probe is **not** a pass;
- `FAIL` — an error, or an unreachable server.

`READY` means these probes answered. It does not mean a scan has run or that estate coverage
is complete, and the command says so beneath its own verdict. The clock check is deliberately
`NOT_OBSERVED`: the server does not report its clock, so comparing it would be a guess.

## 5. Scan manifests

`cryptoscan scan --manifest payments.yaml` currently **refuses without reading or
submitting the file**. The API has no atomic target/scope/policy manifest admission
contract. The previous CLI could drop unsupported fields and still execute a generic
estate projection; that is not a safe bank scan. A versioned, signed manifest admission
endpoint and collector-plan receipt remain work to build.

## 6. Installation integrity, and what it can claim

`scripts/release_manifest.py` emits the manifest (`sha256` per shipped file, excluding
bytecode) and can sign it with an Ed25519 key:

```bash
$ python scripts/release_manifest.py --generate-key ./release-keys
$ python scripts/release_manifest.py --root /opt/cryptoscan -o release.json \
      --sign-key ./release-keys/cryptoscan-release.key
wrote release.json (412 files, signed ed25519:4e7c7a44c7b8303e)

$ cryptoscan verify-installation --manifest release.json --root /opt/cryptoscan \
      --public-key ./release-keys/cryptoscan-release.pub
signature  VALID
verdict    MATCH
```

`cryptoscan verify-installation` answers two questions and keeps them apart. Do the files
match the manifest (exit 0 match / 2 mismatch or missing)? And is the manifest authentic
(`VALID` with a trusted key, `SIGNED_UNVERIFIED` without one, `SIGNATURE_KEY_MISMATCH` or
`INVALID` — both exit 1 — when it does not check out). The signature covers every member
except itself, as canonical JSON, so a rewritten hash list is detectable; the same verifier
serves `bundle verify`, so the two cannot drift apart.

What it does not do: prove the key belongs to the vendor. A signature verified against a
public key that arrived in the same envelope as the manifest proves nothing, which is why
`--public-key` is a separate argument and why a signed-but-unchecked manifest reads
`SIGNED_UNVERIFIED` rather than `VALID`. No signing time, certificate chain or revocation is
checked.

## 7. Authentication

| mechanism | how | when |
| --- | --- | --- |
| session token | `cryptoscan login` → `POST /auth/login` → stored `0600` at `~/.config/cryptoscan/config.json` (or `$CRYPTOSCAN_CONFIG`) | human operator, preferred |
| MFA | `--mfa-code`, or a refusal that asks for one | accounts with a second factor |
| SSO (browser) | `login --sso` → `GET /auth/sso/status`, then `GET /auth/oidc/authorize` or `GET /auth/saml/login` | the sign-in URL is printed (browser launch attempted, never assumed). The session that flow creates belongs to the **browser**; a CLI session comes from pasting an IdP-issued id_token (OIDC → `POST /auth/oidc`, verified by the control plane, not by the CLI) or the token the completed SAML response shows (confirmed live via `/auth/me` before anything is stored). `--sso-token-file <path>` (`-` = stdin) is the non-interactive relay; a token is never accepted in process arguments |
| API key | `--api-key` / `CRYPTOSCAN_API_KEY` → `x-api-key` | machine/CI use, because the platform supports it |
| mTLS | `--client-cert`, `--client-key`, `--ca` | bank TLS termination; enforced at the transport |

Environment overrides the config file (that is how CI supplies a credential). Both are sent
when both are configured; the server decides, not the client. Remote control planes
require HTTPS with certificate verification; plaintext HTTP requires explicit local
development mode on loopback. `login` accepts the bank's `--ca`, `--client-cert` and
`--client-key` so the later session uses the same trusted transport. `--insecure`
additionally requires loopback and a separate lab opt-in, never a bank-network TLS bypass.

Credentials are stored as `0600`; `doctor` reports `PRIVATE` / `TOO_OPEN` for the file rather
than assuming it.

## 8. Job model, not synchronous scanning

A submission succeeds only with a durable queued **job ID**. A scan ID or a synchronous
projection is not accepted as a queued job. The command prints the exact HTTP status and
watch line. `cryptoscan jobs watch <id>` polls for real
state transitions only and returns non-zero on `FAILED`/`CANCELLED`, and 2 — not 0 — on
timeout. Progress percentages are not printed: the platform does not expose per-collector
progress on these endpoints, and a fabricated bar is worse than none.

## 9. Known divergences (not hidden)

- Installed `scan`, `collect --submit`, `schedule`, `tick`, `coverage` and `boms`
  now use the bank API. In-process collection handlers remain reachable only to
  injected test/service callers. `serve` is the bank-server daemon, not an
  administrator-workstation command; without explicit PostgreSQL it refuses.
  Some older twin subcommands still require that server-side database contract
  and need API-backed operator equivalents.
- `cryptoscan status` reports health and identity, not estate coverage. `coverage`
  reads the retained matrix from the bank API and exits incomplete when it is unknown.
- No interactive TUI, no `--format table|json|yaml` matrix; `--json` covers automation.

## 10. Verification

`services/api/tests/unit/test_cli_control_plane.py` pins the properties, not the
wiring: an unconfigured client refuses before opening a connection; exact source dry-run
requests a no-write admission preview; `scan --target` without a revision never reaches
the server; the refusals in
§3 exit 3 and name their closest route; a 401 exits 1 with the login hint and a 5xx exits 2
without being read as an empty estate; `doctor` reports `NOT_OBSERVED` for a silent probe;
`twin status` never opens a local database; the session token is never echoed and is stored
`0600`; both credentials are sent when both are configured. A fake transport answers every
request, so the suite opens no socket.

`services/api/tests/unit/test_release_manifest.py` (4 tests) closes the manifest loop: the
generator refuses an empty manifest, `verify-installation` accepts what the generator
produced, and a file tampered with after the manifest is reported as a mismatch.
