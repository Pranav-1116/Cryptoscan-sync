# Per-collector authority — 6 questions, 11 planes

`cryptoscan.collector-authority/2` · generated 2026-11-01T15:45:36.453417+00:00 · **11 proven · 0 partial · 0 gap** · **66 of 66 cells probed**

**PROBED** now means the drill sent a request that had to be refused for that question — and a request that had to be allowed — through `POST /api/v1/collectors/authorize`, and watched both. **ABSENT** means the expected refusal did not happen. There is no cite-only column left: a mechanism that exists but does not refuse is not a control.

| Plane | WHO | WHAT | WHICH revision | WHEN | HOW LONG | PERMISSION | Verdict |
|---|---|---|---|---|---|---|---|
| `NETWORK` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `RUNTIME` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `STATIC` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `PKI` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `CLOUD` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `KUBERNETES` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `CMDB` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `KMS` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `HSM` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `HARDWARE` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |
| `VENDOR` | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |

Per question, across the planes:

| Question | Probed | Not proven for |
|---|---|---|
| who — who is asking (authenticated principal and role) | 11 | — |
| what_target — what may be touched (scope admission, not a free-form string) | 11 | — |
| which_revision — which approved revision of that scope (pinned, not re-read) | 11 | — |
| when — when it is allowed (window start and expiry) | 11 | — |
| how_long — how long and how much (runtime and traffic budget) | 11 | — |
| permission — which permission the route demands | 11 | — |

## How each question is answered

| Question | Mechanism | Refusal code |
|---|---|---|
| who | the session gate resolves the principal and its durable roles; an authorize call with no session is a 401 | `401` |
| what_target | a per-plane validator: a wildcard, a CIDR and a target of the wrong kind are refused before anything is collected | `TARGET_REFUSED` |
| which_revision | `collector_authorities.revision`; a stale or unnamed revision is refused, and a re-approval makes the old one stale | `STALE_REVISION`, `NO_APPROVAL`, `REVOKED` |
| when | the approval window `[approved_at, expires_at)` | `OUTSIDE_WINDOW` |
| how_long | a rolling window budget on the descriptor, charged under a compare-and-set so two collectors cannot spend the same unit | `EXHAUSTED` |
| permission | the plane's own permission from `PERMISSION_MATRIX`, not the route's | `PERMISSION_DENIED` |

## Plane by plane

### `NETWORK` — PROVEN

- **Target used:** `bank.example:443` · **permission:** `scan.trigger` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `RUNTIME` — PROVEN

- **Target used:** `app01.corp.example` · **permission:** `runtime.ingest` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `STATIC` — PROVEN

- **Target used:** `acme/payments-api@9f2c1ab` · **permission:** `scan.trigger` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `PKI` — PROVEN

- **Target used:** `inventory:pki-prod-01` · **permission:** `certificates.manage` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `CLOUD` — PROVEN

- **Target used:** `aws:account:123456789012/region:eu-west-1` · **permission:** `scan.manage` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `KUBERNETES` — PROVEN

- **Target used:** `cluster:prod-eu/namespace:payments` · **permission:** `scan.trigger` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `CMDB` — PROVEN

- **Target used:** `cmdb:CI0004711` · **permission:** `scan.trigger` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `KMS` — PROVEN

- **Target used:** `kms:arn:aws:kms:eu-west-1:123456789012:key/abc` · **permission:** `crypto.ingest` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `HSM` — PROVEN

- **Target used:** `hsm:payments-luna-01` · **permission:** `hardware.ingest` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `HARDWARE` — PROVEN

- **Target used:** `host:web01.corp.example` · **permission:** `hardware.ingest` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

### `VENDOR` — PROVEN

- **Target used:** `vendor:acme-signing` · **permission:** `assurance.manage` · **approved revision:** 1

| Question | State | Expected | Observed |
|---|---|---|---|
| who | PROBED | 401 without a session | `401` |
| what_target | PROBED | TARGET_REFUSED for every widening target | `{"*": ["TARGET_REFUSED"], "0.0.0.0/0": ["TARGET_REFUSED"], "10.0.0.0/8": ["TARGET_REFUSED"]}` |
| which_revision | PROBED | STALE_REVISION for a stale or unnamed revision | `{"stale": ["STALE_REVISION"], "unnamed": ["STALE_REVISION"]}` |
| when | PROBED | OUTSIDE_WINDOW | `["OUTSIDE_WINDOW"]` |
| how_long | PROBED | EXHAUSTED | `{"first_allowed": true, "remaining": 0, "second": ["EXHAUSTED"]}` |
| permission | PROBED | PERMISSION_DENIED | `["PERMISSION_DENIED"]` |

## The negative control

With the authority's decision function replaced by one that allows every collection, **11 of 66 cells** still report PROBED — who: 11, what_target: 0, which_revision: 0, when: 0, how_long: 0, permission: 0. Everything except `who` goes quiet, which is what a control should do: the matrix is measuring the gate and not the drill's optimism.

## The one gap left, named

- **Collector handlers gated:** 0 (`services/api/api/estate_discovery.py::_collect`).
- every plane's collector passes through _collect(); the gate is served by POST /collectors/authorize and exercised in every cell of this matrix, and calling it from _collect() (with the estate job's principal, roles and the descriptor revision) is the remaining work

## What this does not prove

- Every cell is a request the drill sent to POST /collectors/authorize, so the matrix measures the decision, not the outcome of a real collection: the probes stop short of opening a socket, reading a provider API or touching a CMDB.
- Each plane's collector still reaches its data through its own handler (api.estate_discovery._collect). The gate is exercised there by this drill and is not yet called from it — that single call site is the wiring the next pass needs, and it is why `wiring.wired` is false rather than implied.
- Approvals are platform-level rows with a 30-day window in this run; a per-estate approval is a supported column, not a tested path.
- The budget is a rolling window on the descriptor, checked under a compare-and-set. The drill spends it from one process: two collectors racing for the last unit is covered by the CAS, not by this matrix.

**The verdict this matrix supports:** every one of the eleven collector planes now answers all six questions through one code path, and every answer is a refusal the drill watched happen. What is not yet true is that the collectors call it: they still pass their own admission on the way to the data, so the authority is a gate in front of the door rather than in the doorframe. Closing that is one call site, and until it exists a bank should read this matrix as "the authority exists and refuses" rather than "the collector obeys it".
