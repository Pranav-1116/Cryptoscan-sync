# 182 — Security Control Integration, live

**Status:** built in this guide.
**Layer:** `services/cbom/cbom/security_controls/` (imported as `cbom.security_controls`).
**Harness:** `scripts/cbom_security_controls_live.py` — 11 points, `L-01 … L-11`, 44 probes.
**Artifacts:** `docs/bank-environment/182-security-controls-live.{json,md}`.
**Evidence API:** `POST /security-controls/snapshots`, `GET /security-controls/{findings,verify}`.
**Database:** revision `0133` — `security_control_snapshots`, `security_control_findings`.
**Positioning sentence (use verbatim):**

> CryptoScan integrates with the bank's existing network and security controls to build an
> evidence-backed cryptographic and security estate model.

Guide 181 built the contract and proved it against well-formed fixtures. That is a
specification test, and it was necessary — but nothing in a fixture ever answers `401`, nothing
in a fixture ever shows a client 140 requests in a minute, and no fixture has a process list
from three hours before the alert it is meant to explain.

This guide is about the four things that only appear when the layer is pointed at a real
estate: **failing reads**, **immutable evidence**, **windows that do not line up**, and
**correlation that owes an answer to a clock**. It changes no part of guide 181's specification;
it removes the three places where guide 181 was implicitly assuming.

---

## 1. What guide 181 could not do, and what changed

| Guide 181 | Guide 182 |
| --- | --- |
| adapters declared `endpoints` as documentation | `drivers.py` executes them, and a dialect with no driver is refused by name (`NO_LIVE_DRIVER`) |
| a read either worked or raised | a read is a *state*: `OK`, `PARTIAL_READ`, `AUTH_FAILED`, `RATE_LIMITED`, `BAD_RESPONSE`, `UNREACHABLE`, `REFUSED` |
| evidence was a list in a test run | `EvidenceStore` — append-only, hash-chained, idempotent by content digest, with `verify()` and `retain()` |
| HSM, KMS, PKI and NETWORK were named as *deferred* | four **facades** over the platform's existing collectors, in the registry, reading no device themselves |
| a rate limit was compared with a traffic row the caller supplied | `observation.py` reads the limiter's own counters and applies the limiter's own window arithmetic |
| correlation took five lists | `resolver.py` supplies them from the estate, tenant-scoped, with a time window |

## 2. A read that failed is not a read that was empty

`HttpTransport` sends `GET` and `HEAD` and refuses everything else **at the transport**, not
only in the adapter's declaration — the second lock is on the code path that actually sends
bytes (`L-01`). TLS is required: a plaintext base URL or `verify=False` raises.

Above it, `BaseDriver.fetch()` reads the sections a dialect declares and returns each section's
own outcome:

```text
state = worst_state(sections) ... unless some sections answered, in which case PARTIAL_READ
```

That last line is the whole point. A device that answered one endpoint of five has been *partly*
read; calling that `OK` presents a device nobody finished reading as read, and calling it a
failure throws away the one section that arrived. `failed_sections` names the rest (`L-03`).

The constructor lives on the base, and only on the base. Guide 182 shipped this module with a
mix of dataclass and plain subclasses, which meant every `@dataclass` driver silently replaced
`__init__` — a driver that cannot be handed a transport is a driver that cannot be used. The
harness now constructs all nine dialects (`L-02`), and `driver_for` refuses an option the class
does not accept rather than letting it vanish into `**options`.

## 3. Evidence has to be able to disagree with you

`EvidenceStore` keeps, per tenant:

```text
<root>/<tenant>/index.jsonl            one line per snapshot: sequence, digest, previous_hash, entry_hash
<root>/<tenant>/snapshots/<sha>.json   the body, content-addressed
<root>/<tenant>/tombstones.jsonl       retention decisions, never the index
```

* **idempotent** — `content_digest` excludes the volatile fields, so a retried collection finds
  the existing digest and returns `duplicate: true`. A retry is not a revision.
* **verifiable** — `verify()` re-walks the chain and recomputes each body's digest. It
  distinguishes `SEQUENCE_GAP` (a record was deleted), `CHAIN_BROKEN`, `ENTRY_ALTERED` and
  `BODY_ALTERED` (a record or a body was edited) — `L-04`.
* **retained, not truncated** — `retain()` removes bodies past the window and writes a
  tombstone for each. The index is never rewritten, so "this existed and was purged" stays
  distinguishable from "this never existed".
* **tenant-bounded** — a tenant is one path segment; `../escape` is refused
  (`TENANT_NOT_A_SLUG`), because an evidence store that can be written outside its root is not
  one.

At the API, the same chain is a database: revision `0133` adds `security_control_snapshots`
(sequence, digest, `previous_hash`, `entry_hash`, the body's location and the worst section
state) and `security_control_findings` (control, subject, state, fact classes, evidence ids,
`expected` beside `observed`). The body lives in the store, not in the row: a device
configuration is megabytes, and a row is the wrong place for it.

## 4. Who may say "the platform observed this"

`POST /security-controls/snapshots` accepts a **machine** identity: a certificate-backed agent
identity when `CRYPTOSCAN_REQUIRE_AGENT_IDENTITY` is set (reusing
`api.routers.ingestion._require_bound_identity`, so the signature must be the key bound to that
machine), otherwise a service API key.

A **user session token is refused with its own error code**, `user_token_not_accepted` — not a
generic `401`. The distinction matters: a browser session cannot assert that the platform read a
firewall, and an operator debugging a 403 needs to see "wrong kind of credential" rather than
"your login expired".

Every stored snapshot is written to the audit chain by `UserRepository.audit` with the collector
identity, the digest, the sequence and the finding count. Reads are ordinary authenticated
routes through the tenant scope, so a finding is only visible to the tenant that owns its
snapshot.

A finding is checked before it is stored (`_validate` in the router):

* `state` must be one this layer reports;
* `facts` must be drawn from `CONFIGURED`, `OBSERVED`, `RUNTIME_OBSERVED`, `INFERRED` — and at
  least one;
* a claim (`CONFIGURED`, `OBSERVED`, `WITHIN_LIMIT`, `OVER_LIMIT`) with **no evidence ids** is
  refused as `FINDING_WITHOUT_EVIDENCE`.

## 5. Rate limits: the window is part of the answer

Guide 181 compared a configured limit with a traffic row a caller supplied, and treated the
window as given. Two errors lived in that:

**The numbers came from the fixture.** `observation.py` now reads the gateway's counters
(`CounterAPI`), the access log (`AccessLog`, through the same read-only file transport as a
sensor, counting only a route and a timestamp) or the limiter's own violation records
(`LimitViolations`). When no source can answer, the audit reports
`OBSERVATION_SOURCE_UNAVAILABLE` — it does not report zero traffic.

**The window was assumed.** A fixed counter and a sliding counter permit *different traffic at
the same configured rate*:

| model | permits over a 60s window | why |
| --- | --- | --- |
| `FIXED`, aligned sample | `N` | one closed counter window |
| `FIXED`, unaligned sample | up to `2N` | a full allowance at the end of one window and another at the start of the next is legal |
| `SLIDING` | `N` | *N* in **any** rolling window, ever |

`WindowModel.expected()` computes the bound the limiter itself would honour, and
`comparability()` refuses to compare intervals that are not the same interval:

* a sample shorter than the policy window, that is not one of the counter's own closed windows,
  is a **fragment** — it can be the quiet half as easily as the busy one;
* a sample counted under a different window model permits different traffic.

Both become `INCOMPARABLE_WINDOW`, not `OVER_LIMIT` (`L-07`, `L-08`). A verdict the data cannot
support is the one thing an audit must never print. The states are deliberately kept apart:

| state | meaning |
| --- | --- |
| `NOT_CONFIGURED` | an API carried traffic and **no policy is attached to it** — a decision the bank has not made |
| `POLICY_NOT_ATTACHED` | a policy exists (enabled or not) and protects nothing |
| `INCOMPARABLE_WINDOW` | the observation does not describe the policy's interval |
| `OVER_LIMIT` / `WITHIN_LIMIT` | the two numbers, side by side, with the derivation |
| `UNKNOWN` | a reading nobody could take |

`observation_report()` closes every audit with the sentence that matters: *a limit nobody
measured is not a limit that held.*

## 6. Correlation owes an answer to a clock

An inventory is a statement about a **moment**. An IDS alert at 09:14 correlated against a
process list captured at 06:00 is not a fact: the process may have restarted, the library may
have been upgraded, the key may have rotated.

`resolver.py` supplies the five hops from the estate — tenant-scoped, read-only, from tables that
already hold them:

| hop | source |
| --- | --- |
| source IP → host | `RuntimeFinding.hostname`, else a `HardwareAsset` |
| host → process | `RuntimeFinding` (hostname, `process_name`) |
| process → API | `RuntimeFinding.extra["api"]` where a collector recorded one |
| API/process → crypto library | `RuntimeFinding.extra["library"]` (joined on the API when it is known, on the process when it is not, and the row says which) |
| library → HSM/KMS key | `PaymentKey` |

Every hop carries the moment its evidence was captured and is classified `IN_WINDOW`, `STALE`,
`AFTER_EVENT` or `UNKNOWN_TIME`. A stale hop is **named** (`STALE_EVIDENCE` in `unresolved`) and
the answer is `trustworthy: false`; under `strict=True` the path stops where the evidence stops
instead of being extended by it (`L-10`). The hop that the estate does not record — *API →
library*, as a first-class edge — is not invented: the resolver uses the process as the join and
records `joined_on` so a reader can see the step that was taken.

## 7. HSM, KMS, PKI and NETWORK: facades, not a second architecture

Guide 181 named these four `DEFERRED`, which was honest: the platform already reads them
(`hsm_pkcs11`, `kms_collectors` + `kmip`, `certificate_chain`, `nbom_graph`), and re-collecting
them here would have been the second architecture the specification forbids.

What was missing was the **shape**. A facade parses nothing, decides nothing and duplicates no
rule: it calls the existing function and translates the answer into assets, crypto metadata,
relationships, events and health. Delete `facade.py` and no analysis is lost — which is the test
for whether a facade is a facade.

Two consequences worth naming:

* **relations come from the model, not from convenience.** A certificate chain emits
  `CERTIFICATE ISSUED_BY CERTIFICATE_AUTHORITY` and `CERTIFICATE_AUTHORITY SIGNED_BY
  CERTIFICATE_AUTHORITY`. `BACKED_BY` was the tempting choice and is wrong: its targets are
  accelerators, HSMs, KMSs and TPMs, so a chain claim written that way would be refused as
  `UNKNOWN_RELATION` — and it was, in review (`L-06`).
* **an observed event carries a handshake, never a request.** `NetworkFacade` keeps an
  allow-list of event fields and records every other field it saw as `FIELD_NOT_COLLECTED`. A
  body, a cookie or an authorization header that reached a sensor stops there (`L-06`).

The register of the four is not a claim of coverage: `read_only_audit()` now reports
`device_controls` and `facade_controls` separately, so a reviewer can see that HSM is read
through a facade and not through a vendor dialect of its own (`L-05`).

## 8. What is still not proven

* **Real devices.** Every read in the harness goes through a recorded transport. The dialects
  are exercised; the devices are not. A first live read per vendor is a field task, and the
  `read` block of `live_snapshot()` is what an engineer carries into it.
* **The Python/PostgreSQL RLS split.** Revision `0133` applies the tenant policy on PostgreSQL
  and is a no-op on SQLite, exactly as `0132` is. The database suite covers the policy; the
  harness only checks the tables and their columns.
* **Which windows the bank's limiters actually use.** The window model is read from the device
  (`window_mode`), never guessed — so a device whose export omits it is audited as `FIXED`,
  which is what a `FIXED` default means and why the field is in the finding.

## 9. Build decisions recorded

1. **A flat `drivers.py`, not a `drivers/` package** (continuing guide 181's decision #2: a
   vendor is a row, not a file). Nine dialects share one `fetch()`; a package would invite nine
   copies of it.
2. **Facades instead of four new collectors** — see §7. The alternative was re-reading devices
   the platform already reads, which the positioning sentence forbids in one line.
3. **The chain in the database, the body in the store.** The API stores sequence, digest and the
   two hashes because those are what an auditor queries; it stores `body_location` rather than
   the body because a snapshot is megabytes.
4. **`INCOMPARABLE_WINDOW` as a state of its own.** Folding it into `UNKNOWN` would have hidden
   that data arrived; folding it into `OVER_LIMIT` would have manufactured a breach.
5. **A resolver that reports the clock.** `trustworthy` is a separate key from `answerable`,
   because "the platform found a path" and "the path describes this moment" are different
   claims.

## 10. Harness

```bash
python scripts/cbom_security_controls_live.py --check          # 11 points, 44 probes
python scripts/cbom_security_controls_live.py --json out.json --md out.md
```

Result at the time of writing: **11 pass · 0 partial · 0 fail / 44 probes**
(`docs/bank-environment/182-security-controls-live.md`).
