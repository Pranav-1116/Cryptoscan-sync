# TLS termination paths: three relationships, never one attribute

`cryptoscan.cbom-termination-paths-guide/1` · generated 2026-11-02T18:42:53.810227+00:00 · **5 pass · 0 partial · 0 fail** · 32 probes

Review item 9, drawn exactly as the review draws it:

```
Client ──TLS1.3 AES-256-GCM──▶ External LB
External LB ──TLS1.2 AES-128-GCM──▶ API Gateway
API Gateway ──TLS1.3 AES-256-GCM──▶ Payments API
```

Three cryptographic relationships. Not one *Payments API = AES-256*. The middle hop is weaker than both ends, and it is the hop a reviewer needs to see.

`cbom.termination_paths` keeps them apart:

| hop | relationship | TLS | bulk | evidence |
|---|---|---|---|---|
| 1 | Client → External LB | 1.3 | AES-256-GCM | NET-9281 |
| 2 | External LB → API Gateway | 1.2 | AES-128-GCM | NET-9282 |
| 3 | API Gateway → Payments API | 1.3 | AES-256-GCM | NET-9283 |

1. **hops are chained, not collected** — a hop that connects to nothing is a gap, reported rather than bridged by invention;
2. **one relationship per hop**, with its own version, suite, algorithms and evidence;
3. **the change between adjacent hops is the finding** — a version downgrade, a bulk-cipher change, or a suite change at the same version. Versions are compared by their bulk cipher, because a TLS 1.3 suite names two algorithms and a TLS 1.2 suite four;
4. **the merged claim is refused explicitly** — the union is computed so the claim can be seen, then rejected with the reason that no hop negotiates that set;
5. **pass-through hops are named** — a tunnelling middlebox is `PASSES_THROUGH` and its algorithms belong to the endpoints.

`3 cryptographic relationship(s) across 1 path(s); 1 version downgrade(s); the path is not collapsed into one attribute` — weakest hop: `path 1 hop 2: TLS 1.2 after TLS 1.3`.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `three_relationships` | is one path three facts, or one attribute? | **PASS** | 7, 0 failing |
| `the_change` | does the path show where it weakens? | **PASS** | 7, 0 failing |
| `the_merge` | is the naive collapse visible and refused? | **PASS** | 5, 0 failing |
| `gaps` | what is refused rather than bridged? | **PASS** | 6, 0 failing |
| `the_document` | can a reviewer see the weak hop in the output? | **PASS** | 7, 0 failing |

## `three_relationships` — PASS

*is one path three facts, or one attribute?* (review 9)

- **PASS** `the-path-is-chained-not-collected` — Client → External LB → API Gateway → Payments API
- **PASS** `three-hops-are-three-relationships` — 3 cryptographic relationship(s) across 1 path(s); 4 change(s) between adjacent hops
- **PASS** `each-hop-keeps-its-own-tls-version` — 1.3, 1.2, 1.3
- **PASS** `each-hop-keeps-its-own-suite` — ECDHE-RSA-AES128-GCM-SHA256
- **PASS** `the-middle-hop-owns-aes-128-and-nobody-else-does` — the bulk cipher belongs to the hop that negotiated it
- **PASS** `every-relationship-carries-its-own-evidence` — NET-9281, NET-9282, NET-9283
- **PASS** `a-relationship-statement-names-its-hop` — External LB → API Gateway is its own relationship: TLS 1.2 AES-128-GCM, SHA-256, ECDHE, RSA

## `the_change` — PASS

*does the path show where it weakens?* (review 9)

- **PASS** `the-downgrade-in-the-middle-is-named` — TLS 1.2 after TLS 1.3
- **PASS** `the-upgrade-after-the-downgrade-is-named-too` — a path can weaken and recover in the same breath
- **PASS** `the-bulk-cipher-change-is-what-is-reported` — comparing whole suites would report a change on every hop
- **PASS** `a-same-version-hop-with-a-new-suite-is-a-suite-change` — TLS 1.3 → TLS 1.3 with a different suite is still a change
- **PASS** `every-version-spelling-ranks-the-same` — [["TLS_VERSION_UPGRADE"], ["TLS_VERSION_UPGRADE"], ["TLS_VERSION_UPGRADE"], ["TLS_VERSION_UPGRADE"]]
- **PASS** `an-unparseable-version-does-not-invent-a-downgrade` — SSLV3 is not ranked below TLS 1.3; it is not ranked at all
- **PASS** `the-summary-names-the-weakest-hop` — path 1 hop 2: TLS 1.2 after TLS 1.3

## `the_merge` — PASS

*is the naive collapse visible and refused?* (review 9 / 17)

- **PASS** `the-union-is-computed-so-it-can-be-seen` — AES-256-GCM, SHA-384, AES-128-GCM, SHA-256, ECDHE, RSA
- **PASS** `the-merged-claim-is-refused` — collapsing this path would claim AES-256-GCM, SHA-384, AES-128-GCM, SHA-256, ECDHE, RSA for every node on it; no hop negotiates that set, so the claim describes no hop
- **PASS** `the-refusal-says-why-it-describes-nothing` — a union of three hops is a description of no hop
- **PASS** `a-single-hop-cannot-differ-from-itself` — collapsing this path would claim AES-128-GCM, SHA-256, ECDHE, RSA for every node on it; no hop negotiates that set, so the claim describes no hop
- **PASS** `there-is-nothing-to-collapse-without-a-path` — there is no path to collapse

## `gaps` — PASS

*what is refused rather than bridged?* (review 9 / 12)

- **PASS** `a-hop-with-no-connector-is-a-gap-not-a-path` — 2 path(s), 2 gap(s)
- **PASS** `the-gap-says-the-chain-was-not-invented` — no other recorded hop connects to this one, so its position on the path is unknown; the chain is not invented around it
- **PASS** `a-hop-with-no-suite-is-refused` — a hop with no negotiated suite is not a cryptographic relationship
- **PASS** `a-hop-with-no-evidence-is-refused` — a hop with no evidence id cannot be shown on a path
- **PASS** `a-hop-with-no-start-node-is-refused` — a hop needs the node it starts from
- **PASS** `a-tunnelling-hop-passes-through-and-terminates-nothing` — a middlebox that tunnels TLS owns no suite on that hop

## `the_document` — PASS

*can a reviewer see the weak hop in the output?* (review 9 / 12)

- **PASS** `one-component-per-path-hop-and-algorithm` — 8 component(s), one per path, hop and algorithm; a suite on one hop is never written as another hop's property
- **PASS** `the-component-names-its-hop-version-and-evidence` — {"cryptoscan:evidence_id": "NET-9282", "cryptoscan:from": "External LB", "cryptoscan:tls_version": "1.2", "cryptoscan:to": "API Gateway"}
- **PASS** `no-component-names-an-application` — the path names hops, not the application behind them
- **PASS** `every-algorithm-edge-belongs-to-a-hop` — no algorithm edge starts at an application, a system or a host
- **PASS** `the-hops-are-ordered-by-precedes-edges` — the order is data, not an assumption about the list
- **PASS** `every-edge-is-network-observed-with-evidence` — a hop with no evidence never becomes an edge
- **PASS** `the-estate-chain-builds-the-path-from-the-same-hops` — the chain and the standalone path agree on the same hops

## What this does not prove

- the path is built from the hops the collector reported, in the order it reported them. A missing hop is a gap, not a guess — but a collector that silently skips a proxy produces a complete-looking path with the wrong topology
- a hop is attributed to the node that observed it, not to the node that terminated it. Without a probe from the far side, 'External LB → API Gateway' is the LB's view of that connection
- the version comparison ranks TLS 1.0 to 1.3. A suite downgrade within one version is reported as a bulk-cipher change, which is the fact, but it does not say whether the change was allowed by policy — that comparison is a separate, reviewable decision
- PASSES_THROUGH depends on the collector saying so. A middlebox that terminates and re-originates without declaring it looks like a terminator, and its algorithms are then attributed one hop too far
- the merged claim is refused, not repaired. A downstream tool that unions the components it receives can still produce the claim this module refuses
- nothing here covers mTLS identity, pinned certificates or session resumption: those are properties of the relationship this module does not model
