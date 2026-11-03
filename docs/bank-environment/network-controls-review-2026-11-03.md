# The controls review, as received

Six questions, sent 2026-11-03: *"how to handle my product — IDS, IPS, firewall, rate
limit, request sending, etc."* Kept in substance and numbered, because the answers in
[`171-controls.md`](171-controls.md) refer to these numbers. Where the review names a
shape (an IPS "in the path", a rate limit "at the edge") that shape exists in the code
under the same name.

## 1. IDS and IPS

**As asked.** Are they one appliance type with a flag, or two things?

**Answer.** Two kinds, because they can do two different jobs. An **IPS is in the path**
and can drop a packet; an **IDS sees a copy** and can only say what it saw. The model
carries both as asset kinds (`IDS`, `IPS`) with a deployment `mode` — `INLINE`, `TAP`,
`SPAN` — and refuses the three drawings that make a network look safer than it is:

| drawn as | refusal |
|---|---|
| an IDS that blocks | `IDS_CANNOT_BLOCK` |
| a tap that blocks | `SENSOR_CANNOT_BLOCK_OFF_PATH` |
| an inline sensor with nothing behind it | `INLINE_WITHOUT_DOWNSTREAM` |

An IPS *deployed* as a tap is a legal, common misconfiguration, so it is not refused — it
is reported as `IPS_NOT_INLINE` and it appears on no route. The type table enforces the
same distinction: `PROTECTS` starts at `IPS`, `WAF`, `FIREWALL`, `SERVICE_MESH` and never
at `IDS`, so `IDS PROTECTS CARDHOLDER` is a `TYPE_MISMATCH`.

## 2. Firewall

**As asked.** How is a rule set handled — as an attribute, a list of strings, or a thing
that can be evaluated?

**Answer.** A policy on the device, evaluated in order, first match wins, and the answer
is deliberately **one evidence class below an observation**:

```
fw-01 rule 1 allows TCP:8443 to 10.10.1.5 — a matching rule, not an observed packet
no rule matched; fw-01 falls to its default deny
```

`CONFIGURED`, with the caveat attached. A rule that names no port is refused
(`RULE_WITHOUT_SERVICE`) because "allow the payments subnet" is a sentence, not a rule.
`filter_verdict()` answers *would this flow be allowed*, never *was it* — that second
question needs a capture or a probe, and it is a different class on purpose.

## 3. Rate limits

**As asked.** How does a rate limit fit — is it protection, capacity, or both?

**Answer.** Neither: it is an **availability control**, and it is modelled as a policy
node with a number *and a behaviour* — `limit`, `window_seconds`, `scope` (client, IP,
key, tenant, global), `burst`, `on_exceed` (reject, drop, shape, log-only) and
`fail_open` — joined to the device that enforces it (`ENFORCES`) and to what it limits
(`LIMITS`). It is never folded into "protection" language, and the failures are findings,
not refusals:

| finding | what it means |
|---|---|
| `LIMIT_FAIL_OPEN` | when the limiter cannot decide, traffic passes |
| `LIMIT_LOG_ONLY` | the count is recorded and nothing is refused |
| `LIMIT_NOT_ENFORCED` | traffic above the limit was never refused |
| `NO_LIMIT_RECORDED` | an endpoint is reachable through a device and no limit was read |

A limit of zero, a window of zero, or a scope nobody has is refused (`INVALID_RATE_LIMIT`,
`UNKNOWN_RATE_SCOPE`, `UNKNOWN_RATE_ACTION`) — those are mistakes, not configurations.

## 4. Request sending

**As asked.** *"Request sending etc."* — the part that is about us rather than the bank.

**Answer.** A probe is a decision before it is a packet, and the decision is checked in
this order, because permission comes before budget:

```
method → allowlist → budget → concurrency → backoff → interval → dry run → SEND
```

Each stop has its own code (`METHOD_NOT_SAFE`, `TARGET_NOT_ALLOWED`, `BUDGET_EXHAUSTED`,
`CONCURRENCY_EXHAUSTED`, `BACKOFF_REQUIRED`, `INTERVAL_NOT_ELAPSED`, `DRY_RUN`). The
allowlist is a list of ranges, host:port pairs and suffixes (`10.10.0.0/16`,
`203.0.113.9:443`, `*.bank.example`) and it must parse: `EMPTY_ALLOWLIST` refuses "scan
whatever resolves", `ALLOWLIST_INVALID` refuses an entry that does not parse.

## 5. Evidence for every decision

**As asked.** What stops a quiet "we couldn't reach it" from reading as "there is nothing
there"?

**Answer.** Every decision becomes a record — `EVID-PROBE-001`, collector `probe-gate`,
`sha256:…` of the decision body — and a sent request is `NETWORK_OBSERVED` while a refusal
is `CONFIGURED`, because a decision is not an observation. `probe_ledger()` returns the
records and a statement:

```
3 decision(s): 1 sent, 2 refused (METHOD_NOT_SAFE 1, TARGET_NOT_ALLOWED 1)
```

So "we did not probe that segment" is a checkable fact with a collector and a hash behind
it, rather than an omission.

## 6. One graph

**As asked.** Do these five things join the estate the rest of the platform already has?

**Answer.** Yes, as three relations and three kinds in the same graph — `INSPECTS`,
`ENFORCES`, `LIMITS`; `IDS`, `IPS`, `RATE_LIMIT` — with `TECH-IDS-001`, `TECH-IPS-001`
and `TECH-RL-001` beside every other id. `INSPECTS` is deliberately **not** a forwarding
relation: a route that does not cross a tap is still a route, and that is the whole point
of the distinction.

---

Measured by guide 171 (`docs/bank-environment/171-controls.md`,
`cryptoscan.cbom-controls-guide/1`, **9 pass · 0 partial · 0 fail**, 53 probes) over the
bank's own path: a WAF, an inline IPS, an API gateway and the payments application, with
an IDS tap beside it, a second IPS bought for prevention and deployed as a tap, a firewall
whose rule set allows one service and denies by default, and a limiter configured to
reject at 100 rps, deployed fail-open, and observed at 250.
