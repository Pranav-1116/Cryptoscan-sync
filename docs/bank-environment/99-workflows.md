# 99 — The workflows this build is made of, and what "built" means for each

**Status:** descriptive, not aspirational. Every row below was checked against a route,
a caller and a test at commit `0d11f042`; nothing here is marked *built* because it was
planned. Where a workflow is half-built, the half that is missing is named.

**What this document is for.** You asked for workflows to be "real, wired workflow —
routes → screen/CLI → tests, not stubs". That sentence needs a definition before it can
be checked, so §1 defines it, and every later section is that definition applied to one
workflow.

---

## 1. What counts as a workflow here

A workflow in this product is not a screen and not an endpoint. It is a **loop an operator
or a machine can complete end to end**, and it has five parts. If any part is missing, the
workflow is not built — it is a capability with a hole, and the hole is what this document
lists.

| Part | The question it answers | Where it lives |
|---|---|---|
| **1. A route** | can this step be done through the API at all? | `services/api/api/routers/*.py`, one OpenAPI operation each |
| **2. An actor** | who is allowed, and is that authority current? | `Depends(get_current_user)` + the role/permission check inside the route; sessions, not permanent keys |
| **3. A write with a receipt** | what row is created, and what proves it? | append-only revision with `payload_sha256` + `previous_sha256`, or a work row with a `proof` fixed at open |
| **4. A caller** | can a human reach it? | a console route in `frontend/src/pages/` **and/or** a CLI subcommand in `services/api/api/cli_remote.py` |
| **5. A test** | is the behaviour pinned? | `services/api/tests/unit/*` for the route, `frontend/src/**/*.test.tsx` for the screen |

Two consequences follow, and they are why this document exists:

* **An endpoint with no caller is not automatically a defect** — but it is a capability an
  operator cannot use, and it is counted as such (574 of 1197 endpoints have a console
  caller, i.e. 48.0%; 755 are referenced by a test, 63.1%).
* **A caller with no test is not evidence of anything.** Test references are counted, not
  judged: a route reached once by a smoke call counts the same as one with twenty
  behavioural tests.

Every workflow below also carries a **refusal list**: the questions it is *not* allowed to
answer, printed to the operator at the moment they would otherwise assume it does. That is
not decoration — it is the part that stops a plausible number from becoming a false claim.

---

## 2. The four workflows you asked for

This is the current state of each, with the commit that landed it.

| # | Workflow | State | What is wired | What is still missing |
|---|---|---|---|---|
| 1 | **Content-addressed evidence** | **Built** `018f25b5` | `EVIDENCE I` ids: `"ev-" + sha256(json{evidence_type,target,layer,source,collector_name,facts}, sort_keys)[:16]`; `evidence show` / `evidence verify` read the record and recompute the address; duplicate observations collapse to one record | records whose id was *supplied* by a caller (not derived) report `not content-addressed` on verify — honest, but it means older/hand-written rows are outside the guarantee |
| 2 | **`REMEDIATE` — the loop's break** | **Built** `e0f6a972` | the twin opens work from a real conflict, a coverage loss and a simulation blocker; each item's `proof` is fixed at open; `reconcile` closes `PROVEN` only by naming the observation and evidence id that closed it | a `HUMAN`-proof item can only be closed by a person's assertion; nothing in the product executes a fix |
| 3 | **The assurance surface** | **Partial** — screens `f6704c51`, CLI `0d11f042` | 7 screens (5 new), 13 CLI read subcommands, 7 typed console callers; 13 of 61 endpoints have a console caller | the 48 remaining routes are almost all *writes* (`registers`, `relationships`, `samples/{id}/approve`, `signers`, `remediation-changes`, `remediation-tasks`) — each needs a form carrying a reason, an actor and an expected revision |
| 4 | **Signed manifests and bundles** | **Built** `e50c4a8c` | Ed25519 over canonical JSON of every member except `signature`; `release_manifest.py --sign-key`; `bundle export --sign-key` / `bundle verify --public-key`; `verify-installation` prints `MANIFEST_UNSIGNED` when nothing was signed | a signature proves origin and integrity, never authenticity: `VALID` requires a caller-supplied trusted key, and the document's own embedded key is never treated as evidence |

**The order those four were built in matters.** Evidence addressing came first because a
proof that cannot be recomputed is not a proof; `REMEDIATE` second because a loop that
never opens work cannot demonstrate a fix; signing last because signing a manifest whose
`limits` block was rewritten after signing would have produced a *valid signature over a
false document*. Each of the first three is a precondition for the next one being
checkable rather than assertable.

---

## 3. The seven evidence-assurance workflows

`services/api/api/routers/assurance.py` opens with the sentence *"Seven evidence-assurance
workflows; bounded metadata/bytes, no live acquisition."* They are the ways this product
turns an **assertion** into something a bank can audit. They share one append-only store
(`AssuranceRevision`: `kind`, `subject_id`, `revision`, `payload`, `payload_sha256`,
`previous_sha256`, `created_by`), which is why one screen can show all of them.

| Workflow | The question it answers | Routes (prefix `/api/v1/assurance`) | Screen | CLI |
|---|---|---|---|---|
| **1. Registered coverage** | what did the owner declare exists, and what is currently observed against it? | `POST/PUT /registers`, `PUT /registers/{id}/observations/{target}`, `GET /registers/{id}/coverage` | `/assurance-coverage` | `assurance coverage` |
| **2. Relationships and trace** | is there an evidence-traceable link from a deployment to a package to a crypto fact? | `POST /relationships`, `POST /relationships/{id}/approve`, `GET /applications/{id}/trace` | `/assurance-trace` | `assurance trace` |
| **3. Accuracy sampling** | are the engine's predictions right, on a frozen sample, judged by the domain owner? | `POST /samples`, `…/approve`, `GET /samples/{id}/workbook`, `…/reviews`, `…/repeat`, `…/regressions`, `POST /regressions/{id}/results` | `/assurance-sampling` | `assurance workbook` |
| **4. Adapters and supplier evidence** | has *this exact offline profile* been exercised, on evidence we still trust? | `POST/PUT /adapters`, `…/qualifications`, `GET /adapters/{id}`, `GET …/supplier-evidence/{eid}/observations`, `POST /supplier-evidence`, `…/approve`, `…/reject`, `POST/GET /evidence-blobs` | `/assurance-qualification` | `assurance adapter`, `assurance observations` |
| **5. Infrastructure qualification** | does this deployment of Redis meet its recovery objectives, role by role? | `POST/PUT /redis-objectives`, `…/measurements`, `POST /redis-measurements/{id}/review`, `GET …/qualification` | `/assurance-qualification` | `assurance redis` |
| **6. Operator decisions and remediation** | which conditions are open, who owns them, and what proves them closed? | `GET /operator-decisions`, `POST /remediation-changes`, `…/approve`, `…/report-complete`, `…/verify`, `…/revoke`, `POST /remediation-tasks`, `GET /workloads/jobs/{id}` | `/operator-decisions` | `assurance decisions` |
| **7. Launch readiness** | has an independent party accepted anything, and are the operating duties actually held? | `POST /launch/engagements`, `…/approve`, `…/withdraw`, `…/reports`, `POST /launch/findings/{id}/plan`, `…/approve`, `…/report-complete`, `POST /launch/assignments`, `…/acknowledge`, `…/exercises`, `…/review-exercise`, `POST/GET /launch/pilots`, `GET /launch/operations` | `/launch-readiness` | `assurance launch`, `assurance engagement`, `assurance pilot` |

### 3.1 The shape every one of the seven shares

```
register / propose            →  a revision exists, with a hash chain
separate human approves       →  a second revision, by a different person
server recomputes on read     →  a report that re-derives its own numbers
operator reads the basis      →  the screen prints the basis string, not just the number
```

Four rules fall out, and each one is a test somewhere in the tree:

1. **The actor is a person with current authority, not a key.** Sessions expire; a
   permanently valid API key as primary human authentication is refused by design.
2. **Approval is a second write by a different human**, not a boolean flipped on the first
   record. `approach` and `review` are separate rows keyed to different `created_by`.
3. **Nothing is recomputed client-side.** The console renders what the server returned; the
   CLI prints what the server returned. If a number is absent, the screen shows the absence.
4. **Freshness is a receipt, not a promise.** A `coverage_observation` is re-checked against
   the SQL receipt that produced it, and a `409` means the retained coverage disagrees with
   the current receipt — record a new observation rather than reusing the old one.

### 3.2 What each of the seven refuses to say

This is the part that matters more than the routes. Verbatim from the screens and the CLI:

| Workflow | Refuses | Why |
|---|---|---|
| Registered coverage | any whole-bank percentage | the denominator is the owner's register, not discovered assets: `whole_bank_verified: false`, `denominator_basis: REGISTERED_TARGETS_ONLY_NOT_DISCOVERED_ASSETS` |
| Trace | "this is a call graph" | a resolved path is an evidence chain; `deployed_verified` and `invocation_verified` are `false` on every path the API returns, and unresolved components are listed rather than dropped |
| Sampling | precision / recall before a review | the workbook is the question, not the answer; `UNREVIEWED` renders as `UNREVIEWED` |
| Adapters | "the vendor integration works" | `live_vendor_supported: false`, always; `OFFLINE_PROFILE_EXERCISED` means one offline JSON profile passed its cases against this build's engine fingerprint |
| Supplier evidence | "we verified the supplier" | `automatic_identity_joins: false`, `independent_truth_verified: false` — the bytes are the supplier's statement |
| Infrastructure | "infrastructure is qualified" | a cell is accepted only for a reviewed, current measurement against the exact approved objective revision; `local_sentinel_promotion_is_deployment_qualification: false` |
| Operator decisions | "reported complete means resolved" | completion is a citation of an independent observation; a human-proof item is never auto-closed |
| Launch readiness | "we have been assessed" | a signature proves origin and integrity, not independence, accreditation or certification |

---

## 4. The twin's lifecycle: twelve phases and one loop

`services/api/api/estate_lifecycle.py` reports the loop from spec 94 §2 phase by phase,
because a diagram that draws all twelve boxes the same colour lets a reader assume the loop
closes.

```
DISCOVER → IDENTIFY → EVIDENCE → NORMALIZE → CORRELATE → MODEL → SNAPSHOT
   → MONITOR → DRIFT → SIMULATE → REMEDIATE → RE-DISCOVER →
```

Each phase returns exactly one of four states, and they are not interchangeable:

| State | Means | Example |
|---|---|---|
| `CONNECTED` | the phase runs, and its output is what the next phase reads | `EVIDENCE` → `estate_observations.py` writes the record `NORMALIZE` reads |
| `PARTIAL` | it runs, but the hand-off is missing, and the gap is named | `MONITOR`: a schedule re-runs discovery **only if one was created and enabled**; nothing creates one for you |
| `NOT_CONNECTED` | the capability exists somewhere but nothing carries it into the loop | `REMEDIATE` was this until work began opening from the twin's own findings |
| `NOT_STARTED` | nothing has ever run | an empty estate — *"no observation has ever been recorded"* is not *"the loop is broken"* |

`loop_closed` is computed, never asserted: it is true only when every phase is `CONNECTED`,
so the day the last hand-off lands the field flips by itself. `first_break` names the
earliest phase that is not connected — the one worth building next.

### 4.1 `REMEDIATE`, the phase that was missing (commit `e0f6a972`)

Before it, a real conflict, a coverage loss and a simulation blocker were all *visible*, and
each expected an operator to open a ticket somewhere else. Nothing could then say whether
the estate moved because of that ticket, so `RE_DISCOVER` could compare two observations and
never attribute the difference to anything.

What was built is deliberately narrow:

* **Opening work is a proposal, not an action.** `propose()` reads what the twin already
  holds and returns candidates; it writes only with `persist=True`, so a dry run can be read
  before anything lands in someone's queue.
* **The key is the claim**: `"rem-" + sha256(source|subject|claim)[:16]`, so re-proposing
  refreshes the same item instead of filing a second ticket for the same disagreement.
* **The proof is written down when the work opens**, not when it closes:

| Source | Proof | Closed when |
|---|---|---|
| `COVERAGE_DISPUTE` | exactly **one** current value remains for the field | a later observation holds one current value — never "the value I wanted won"; this module has no opinion on which plane is right |
| `COLLECTOR_STATUS` | the same plane reports `COMPLETE` / `OK` / `COLLECTED` on a later run | that run exists |
| `SIMULATION` blocker | `HUMAN` | a person asserts it — never automatic, and the item says so |

* **Closure is a citation.** `reconcile()` moves an item to `PROVEN` only when it can name
  the observation row *and* the evidence id that closed it. No current value →
  `PROOF_UNAVAILABLE` ("the fact is no longer asserted" is not "it was fixed"). An
  unchanged world stays `STILL_OPEN` with the attempt counted.

### 4.2 What is still open in the loop

* `RE_DISCOVER` is `PARTIAL`: a new observation does walk the pipeline again and is compared
  with the one before it, **but nothing connects that observation to the remediation that
  caused it** — the fix still shows up as an unexplained change.
* `MONITOR` is `PARTIAL`: monitoring is a schedule that exists and is enabled; a schedule
  whose last run failed is not monitoring, and the phase says so.
* `first_break` currently points at whichever of those two is earlier for the estate being
  read. That is the next thing worth building.

---

## 5. The CLI workflow: the operator's half

The CLI is **not the scanner**. It is the bank's control-plane client: it asks, it submits,
it never collects. That distinction is enforced by what the command does when it cannot do
something.

```
cryptoscan <command>  →  source: <METHOD> <path> (HTTP n)  →  exit code
```

| Exit | Meaning |
|---|---|
| `0` | the read/write succeeded and printed its source |
| `1` | an error, a failed gate, or a bad signature |
| `2` | incomplete — file mismatch, missing signature, or a capability that cannot finish the job it was asked for |
| `3` | refused: the capability does not exist, and the refusal names the closest real endpoints |

Two behaviours are worth calling out because they are the difference between a client and a
stub:

* **A refusal names what does exist.** `scope diff` refuses because there is no
  scope-to-scope diff route, and prints `estate/evidence/twin/compare` and
  `collection/jobs/{id}/coverage` as the closest real endpoints, rather than diffing two
  JSON exports and calling it an authorisation comparison.
* **A wired command says where the work happened.** `ci scan --path /srv/src` states that
  the path is resolved **on the control plane** — the most likely misunderstanding about
  that command is that it scanned your laptop. `explain finding` returns `NOT_JOINABLE`
  because a finding carries a file path and the twin is keyed by asset id, and it says so
  instead of guessing an asset from a path.

The assurance workflows (§3) each have a read subcommand — `assurance records`, `history`,
`coverage`, `trace`, `workbook`, `adapter`, `observations`, `redis`, `decisions`, `launch`,
`engagement`, `pilot`, `collection` — so an operator can see what the engine holds without
opening a browser. Their *writes* stay in the console, because a write needs a reason, an
actor and an expected revision, and a form is a better place for that than a flag.

---

## 6. The signed-artifact workflow

```
build → manifest (with limits) → sign → distribute → verify → import
```

* **Signed bytes** = canonical JSON (sorted keys, compact separators, UTF-8) of every member
  **except** `signature`. Anything rewritten after signing invalidates the signature — which
  is why `scripts/release_manifest.py` rewrites `limits` *before* signing, not after.
* **Ed25519**; the block is `{schema, alg, key_id, public_key, signature, covers}`.
* **Verdicts** are a closed set: `VALID`, `INVALID`, `UNSIGNED`, `SIGNED_UNVERIFIED`,
  `SIGNATURE_KEY_MISMATCH`, `SIGNATURE_MALFORMED`.

| Verdict | Means |
|---|---|
| `VALID` | checked against the key **you** supplied and trust |
| `SIGNED_UNVERIFIED` | there is a signature, but no trusted key was supplied to check it against |
| `SIGNATURE_KEY_MISMATCH` | signed, but by a different key than the one you trust |
| `UNSIGNED` | nothing was signed; `verify-installation` displays this as `MANIFEST_UNSIGNED` |

The embedded public key in the document is **never** evidence: anyone can sign a document
with their own key and paste the matching public key beside it. A malformed or unreadable
key is a verdict (`SIGNATURE_MALFORMED`), not a traceback.

---

## 7. What is not built, and the shape of the remaining work

The remaining work is not "more endpoints". It is the missing half of specific loops:

| Missing | Why it is a workflow gap, not a feature request |
|---|---|
| The 48 assurance **write** routes with no screen | each is a workflow step a human performs (approve, withdraw, reject, qualify, sign); without a form, the workflow can only be completed with `curl` |
| `RE_DISCOVER` attribution | without it, a fix cannot be shown to be a fix; the estate moves and nobody can say why |
| A `MONITOR` schedule that the product creates | monitoring today is a schedule an operator must create and keep alive |
| Scope revision diff | the platform enforces an authorised scope but cannot diff two revisions of it |
| Real hardware and vendor behaviour | not measurable from source at all: HSM firmware, ADC images, and whether an approval workflow matches a regulator's expectation need a deployment and an auditor |
| Signed releases in CI | `.github/workflows/**` are empty in this checkout; the signing code exists and is tested, the lane that would run it does not |

**Four things no number in this document can measure**: correctness against a real bank
estate, vendor hardware behaviour, whether a screen is *usable*, and whether an approval
workflow matches a regulator's expectation. They are absent from every count here, and
anyone quoting these numbers should say so.

---

## 8. How to check any claim above

```bash
# the measured surface: 1197 endpoints, 574 with a console caller, 755 test-referenced
python scripts/audit_build_status.py

# the seven assurance workflows, as the CLI sees them
cryptoscan assurance --help

# the loop, phase by phase, with first_break
cryptoscan twin status

# a signature verdict that depends on a key you supplied
cryptoscan verify-installation --manifest release.json --public-key trusted.pem
```

```bash
# the tests that pin the workflows in this document
pytest services/api/tests/unit/test_cli_control_plane.py        # 87
pytest services/api/tests/unit/test_estate_remediation.py       # 14
pytest services/api/tests/unit/test_release_manifest.py         # 9
pytest services/api/tests/unit/test_assurance_workflows.py     # 37
npx vitest run src/pages/AssuranceScreens.test.tsx              # 7
```

If a claim in this document and a command above disagree, the command is right.
