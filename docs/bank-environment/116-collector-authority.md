# Per-collector authority — six questions, eleven planes

`cryptoscan.collector-authority/1` · generated 2026-11-01T02:37:32.758902+00:00 · **0 proven · 1 partial · 10 gap**

**PROBED** means the drill executed the control and watched it refuse. **CITED** means the mechanism is present in that plane's own code path, with the citation checked to resolve. **ABSENT** means nothing answers the question for that plane. A citation is not a probe, and the table keeps them apart.

| Plane | WHO | WHAT | WHICH revision | WHEN | HOW LONG | PERMISSION | Verdict |
|---|---|---|---|---|---|---|---|
| `NETWORK` | c | **P** | c | c | **P** | — | **PARTIAL** |
| `RUNTIME` | c | c | c | — | — | — | **GAP** |
| `STATIC` | c | c | — | c | — | — | **GAP** |
| `PKI` | c | — | — | c | — | c | **GAP** |
| `CLOUD` | c | — | — | — | c | — | **GAP** |
| `KUBERNETES` | c | — | — | — | — | — | **GAP** |
| `CMDB` | c | — | — | — | — | — | **GAP** |
| `KMS` | c | — | — | — | — | — | **GAP** |
| `HSM` | c | — | — | — | — | — | **GAP** |
| `HARDWARE` | c | c | — | c | — | — | **GAP** |
| `VENDOR` | c | — | — | — | — | — | **GAP** |

Per question across the eleven planes:

| Question | Probed | Cited | Absent for |
|---|---|---|---|
| who — who is asking (authenticated principal and role) | 0 | 11 | — |
| what_target — what may be touched (scope admission, not a free-form string) | 1 | 3 | `CLOUD`, `CMDB`, `HSM`, `KMS`, `KUBERNETES`, `PKI`, `VENDOR` |
| which_revision — which approved revision of that scope (pinned, not re-read) | 0 | 2 | `CLOUD`, `CMDB`, `HARDWARE`, `HSM`, `KMS`, `KUBERNETES`, `PKI`, `STATIC`, `VENDOR` |
| when — when it is allowed (window start and expiry) | 0 | 4 | `CLOUD`, `CMDB`, `HSM`, `KMS`, `KUBERNETES`, `RUNTIME`, `VENDOR` |
| how_long — how long and how much (runtime and traffic budget) | 1 | 1 | `CMDB`, `HARDWARE`, `HSM`, `KMS`, `KUBERNETES`, `PKI`, `RUNTIME`, `STATIC`, `VENDOR` |
| permission — which permission the route demands | 0 | 1 | `CLOUD`, `CMDB`, `HARDWARE`, `HSM`, `KMS`, `KUBERNETES`, `NETWORK`, `RUNTIME`, `STATIC`, `VENDOR` |

## The probes that ran

### `network_admission` — proven

the target is validated before any probe is sent: a subnet sweep and a loopback target are both refused with 422

```
{
  "cidr": {
    "target": "10.0.0.0/8",
    "refused": true,
    "status": 422,
    "reason": "probe_target[0]: malformed probe hostname: '10.0.0.0/8'"
  },
  "loopback": {
    "target": "127.0.0.1:443",
    "refused": true,
    "status": 422,
    "reason": "probe_target[0]: refusing to probe 127.0.0.1 \u2014 loopback/metadata/multicast/reserved blocked"
  }
}
```

### `network_budget` — proven

the traffic budget is charged per window and refuses the connection that would exceed it, rather than reporting the overspend afterwards

```
{
  "no_scope": {
    "refused": true,
    "reason": "no approved scope \u2014 there is no budget to spend"
  },
  "first": {
    "connections_used": 1,
    "refused": false
  },
  "second": {
    "refused": true,
    "reason": "traffic budget spent: 1/1 connections used in this window"
  }
}
```

## Plane by plane

### `NETWORK` — PARTIAL

- **Entry:** POST /api/v1/network/crypto-observe
- **Reading:** the only plane that reaches the network itself, and the only one with admission and a traffic budget as first-class controls

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/routers/network.py:13 |
| what_target | PROBED | the target is validated before any probe is sent: a subnet sweep and a loopback target are both refused with 422 |
| which_revision | CITED | services/api/api/network_collect.py:161 |
| when | CITED | services/api/api/security/network_budget.py:75 |
| how_long | PROBED | the traffic budget is charged per window and refuses the connection that would exceed it, rather than reporting the overspend afterwards |
| permission | ABSENT | — |

### `RUNTIME` — GAP

- **Entry:** POST /api/v1/runtime/crypto-events
- **Reading:** ingest of agent-produced events; the target is whatever the agent sends

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/routers/runtime_crypto.py:28 |
| what_target | CITED | services/api/api/routers/runtime_crypto.py:227 |
| which_revision | CITED | services/api/api/routers/runtime_crypto.py:101 |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `STATIC` — GAP

- **Entry:** POST /api/v1/scans (source scan)
- **Reading:** target is a repository reference; the scan admission path applies

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/routers/scans.py:11 |
| what_target | CITED | services/api/api/routers/estate_graph.py:537 |
| which_revision | ABSENT | — |
| when | CITED | services/api/api/routers/estate_graph.py:2214 |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `PKI` — GAP

- **Entry:** certificate inventory sync
- **Reading:** reads certificate rows already in the inventory

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | CITED | services/api/api/routers/certificates.py:52 |
| how_long | ABSENT | — |
| permission | CITED | services/api/api/routers/certificates.py:135 |

### `CLOUD` — GAP

- **Entry:** POST /api/v1/cloud/... discover
- **Reading:** reads provider APIs with a configured credential, not a per-request target

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_cloud.py:106 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | CITED | services/api/api/routers/cloud.py:230 |
| permission | ABSENT | — |

### `KUBERNETES` — GAP

- **Entry:** cluster adapter

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `CMDB` — GAP

- **Entry:** CMDB adapter

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `KMS` — GAP

- **Entry:** KMS adapter

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `HSM` — GAP

- **Entry:** HSM adapter

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `HARDWARE` — GAP

- **Entry:** host evidence intake

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/routers/host_evidence.py:18 |
| what_target | CITED | services/api/api/host_collect.py:80 |
| which_revision | ABSENT | — |
| when | CITED | services/api/api/routers/host_evidence.py:111 |
| how_long | ABSENT | — |
| permission | ABSENT | — |

### `VENDOR` — GAP

- **Entry:** vendor questionnaire / attestation

| Question | State | Where |
|---|---|---|
| who | CITED | services/api/api/estate_discovery.py:1248 |
| what_target | ABSENT | — |
| which_revision | ABSENT | — |
| when | ABSENT | — |
| how_long | ABSENT | — |
| permission | ABSENT | — |

## What this does not prove

- A CITED cell proves the mechanism is present in the plane's code path, not that it refuses the specific request an attacker would send. Only two questions are probed end to end (network target admission, network traffic budget).
- The matrix reads the modules a plane *names*; a mechanism imported from a shared module counts for the plane that imports it, which is right for coverage and wrong for a per-plane guarantee.
- Five planes (KUBERNETES, CMDB, KMS, HSM, VENDOR) are catalogue adapters with no dedicated route in this checkout; their cells are citations against the shared discovery path, which is precisely the uniformity gap the review named.

**The verdict this matrix supports:** authority is *not* uniform per collector. On the network plane, five of the six questions are answered and two are proven by refusal. On the catalogue planes, the same controls exist as shared code but nothing binds them to the individual collector, and no plane carries a per-target revision pin of its own. The gap is specific: a per-plane authority descriptor — target, revision, window, budget, permission — evaluated at collection time, rather than five mechanisms that each plane may or may not import.
