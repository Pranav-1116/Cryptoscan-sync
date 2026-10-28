# 97 — The operator CLI: a control-plane client, not a scanner

Status: implemented and tested. `cryptoscan` now has two modes in one entry point — the
existing **in-process** operator (the database is on this host) and the new **control-plane
client** (the control plane and the collectors are inside the bank, the terminal is a jump
host). Remote mode is selected by control-plane flags, never by silence.

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

The CLI enumerates no hosts, reads no `/proc`, talks to no HSM and holds no private key.
It authenticates to the bank's own control plane, submits work, watches it, and reads
evidence back. That is what makes it installable: everything that touches the estate stays
inside the bank's security boundary, and the tool an administrator runs from a jump host has
no collection capability to abuse.

Each command prints the endpoint it read (`source: GET /path (HTTP 200)`). An operator can
check any number against the API, and a command whose endpoint does not exist cannot print
something invented.

## 2. Commands, and the endpoints behind them

| command | endpoint | notes |
| --- | --- | --- |
| `version` | `GET /health` | falls back to the local build string and says so |
| `status` | `GET /healthz`, `/readiness/summary`, `/auth/me` | three probes; failures are counted, not averaged away |
| `doctor` | `/healthz/dependencies`, `/healthz/schema`, `/health/worker-fleet`, `/health/connectors`, `/control/health`, `/graph/health`, `/automation/health/platform` | see §4 |
| `login` | `POST /auth/login`, `/auth/login/mfa` | session token, MFA honoured |
| `logout` | `POST /auth/logout` | revokes, then clears the stored token |
| `target list / show` | `GET /collection/targets`, `/{id}` | |
| `target register` | `POST /collection/targets` | no defaults invented (§3) |
| `target update <id>` | `PUT /collection/targets/{id}` | sends only the fields you named; with none it refuses rather than PUTting an empty revision |
| `target authorize / revoke` | `POST /collection/targets/{id}/authorize`, `/revoke` | |
| `jobs list / show / logs` | `GET /jobs`, `/{id}`, `/{id}/logs` | |
| `jobs cancel` | `POST /collection/jobs/{id}/cancel` | collection jobs own cancellation; the generic job API has no cancel |
| `jobs watch` | `GET /jobs/{id}` | terminal states only; a timeout is exit 2, not success |
| `jobs watch --coverage` | `GET /collection/jobs/{id}/coverage` | printed when the job settles: `surfaces`, `basis`, `limits`; no percentage |
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
| `collect --submit` | `POST /collection/jobs`, `/systems/{id}/scan`, `/estate/evidence/scan` | hands the work to the control plane; prints "no collection happened in this process" |
| `scope show` | `GET /platform/scope` | |
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
| `scan --dry-run` | `GET /estate/evidence/plan` | prints the plan, issues no write |
| `scan --system <id>` | `POST /systems/{id}/scan` | |
| `scan --target <id>` | `POST /collection/jobs` | requires `--target-revision` |
| `scan` (no target) | `POST /estate/evidence/scan` | estate discovery run |
| `scan --manifest <file>` | as above | JSON or YAML (§5) |
| `verify-installation` | *(local)* | hashes files against a release manifest and checks its Ed25519 signature (`--public-key`), §6 |
| `collect` (no `--submit`) | *(local collection)* | the one in-process mode; it prints, on stderr, that this process is the collector |

## 3. What the CLI refuses, on purpose

A refusal exits `3` and names the closest endpoints that *do* exist:

| command | why it refuses |
| --- | --- |
| `scope diff` | no scope-to-scope diff route exists; snapshot compare and coverage are the closest |
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

`cryptoscan scan --manifest payments.yaml` reads `scope.name`, `collectors.{static,runtime,…}`
and maps them onto the estate scan request (`scope`, `planes`). **Anything the API cannot
express is printed as NOT sent** — silently dropping `policy.profile` would let an operator
believe a policy applied to a run that never saw it. JSON needs nothing extra; YAML needs
PyYAML, and the command says so if it is missing.

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
| API key | `--api-key` / `CRYPTOSCAN_API_KEY` → `x-api-key` | machine/CI use, because the platform supports it |
| mTLS | `--client-cert`, `--client-key`, `--ca` | bank TLS termination; enforced at the transport |

Environment overrides the config file (that is how CI supplies a credential). Both are sent
when both are configured; the server decides, not the client. `--insecure` exists for a lab
and the command says which mode it used.

Credentials are stored as `0600`; `doctor` reports `PRIVATE` / `TOO_OPEN` for the file rather
than assuming it.

## 8. Job model, not synchronous scanning

Submitting returns an id (`job_id`, `scan_id` or `identifier`, whichever the endpoint
returned) and the command prints the watch line. `cryptoscan jobs watch <id>` polls for real
state transitions only and returns non-zero on `FAILED`/`CANCELLED`, and 2 — not 0 — on
timeout. Progress percentages are not printed: the platform does not expose per-collector
progress on these endpoints, and a fabricated bar is worse than none.

## 9. Known divergences (not hidden)

- The older in-process commands (`scan` without control-plane flags, `collect`, `tick`,
  `serve`, `coverage`, `boms`, `schedule`) still open the local database, and `collect`
  performs network collection **in the CLI's own process**. That contradicts the boundary in
  §1 and is the main remaining work: `collect` should become a submission to the control
  plane, with the in-process path retained only as a single-node development mode.
- `cryptoscan status` reports health and identity, not estate coverage. Coverage lives in the
  estate coverage endpoints and the in-process `coverage` command.
- No interactive TUI, no `--format table|json|yaml` matrix; `--json` covers automation.

## 10. Verification

`services/api/tests/unit/test_cli_control_plane.py` (41 tests) pins the properties, not the
wiring: an unconfigured client refuses before opening a connection; `scan --dry-run` issues
only a GET; `scan --target` without a revision never reaches the server; the four refusals in
§3 exit 3 and name their closest route; a 401 exits 1 with the login hint and a 5xx exits 2
without being read as an empty estate; `doctor` reports `NOT_OBSERVED` for a silent probe;
`twin status` never opens a local database; the session token is never echoed and is stored
`0600`; both credentials are sent when both are configured. A fake transport answers every
request, so the suite opens no socket.

`services/api/tests/unit/test_release_manifest.py` (4 tests) closes the manifest loop: the
generator refuses an empty manifest, `verify-installation` accepts what the generator
produced, and a file tampered with after the manifest is reported as a mismatch.
