# Network topology as relationships that carry their own evidence

`cryptoscan.cbom-topology-guide/1` · generated 2026-11-03T01:08:21.122283+00:00 · **5 pass · 0 partial · 0 fail** · 25 probes

Review item 12: every relationship needs `evidence_id`, `observed_at`, `source` and `confidence` — otherwise the topology is fiction. Here the fourth is derived from the first three, and an edge that cannot carry all four is not drawn.

```
claim ──▶ evidence_id · observed_at · source ──▶ confidence (derived)
                                              └─ no evidence ⇒ refused, not drawn
```

14 relationship(s) across 7 kind(s) and 10 node(s)

Audit: the topology is internally honest: every edge carries provenance and no claim outruns its evidence

| kind | what it may claim | typical confidence |
|---|---|---|
| `CONNECTS_TO` | a connection was made | `OBSERVED` |
| `ROUTES_TO` | a path was declared or observed | `DECLARED` |
| `TERMINATES_TLS` | this device terminated the handshake | `OBSERVED` |
| `RE_ENCRYPTS` | decrypt **and** a new handshake downstream | `OBSERVED`, gate |
| `PASSTHROUGH` | one session continued | `OBSERVED`, gate |
| `PROTECTED_BY` | a device sits in front | `DECLARED` |
| `USES_CERTIFICATE` | this endpoint presented this certificate | `OBSERVED` |
| `USES_HSM` / `USES_KMS` | an inventory binding | `DECLARED` |

| field | source |
|---|---|
| `evidence_id` | required — an uncited edge is fiction |
| `observed_at` | required — an observation without a moment is a claim |
| `source` | required — the collector or register that produced it |
| `confidence` | **derived** from the evidence class, never supplied |

Observed share: 0.71 · unused kinds: RE_ENCRYPTS, PASSTHROUGH

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_vocabulary` | is every relationship one of the nine, with its provenance? | **PASS** | 5, 0 failing |
| `confidence` | who decides how strongly an edge is asserted? | **PASS** | 5, 0 failing |
| `the_two_gates` | which claims need more than one observation, and is that enforced? | **PASS** | 5, 0 failing |
| `the_audit` | can the topology be read back and found honest? | **PASS** | 5, 0 failing |
| `from_observations` | does the topology come from evidence rather than from wishes? | **PASS** | 5, 0 failing |

## `the_vocabulary` — PASS

*is every relationship one of the nine, with its provenance?* (review 12)

- **PASS** `the-nine-kinds-are-the-whole-vocabulary` — CONNECTS_TO, ROUTES_TO, TERMINATES_TLS, RE_ENCRYPTS, PASSTHROUGH, PROTECTED_BY, USES_CERTIFICATE, USES_HSM, USES_KMS
- **PASS** `a-kind-outside-the-vocabulary-is-refused` — MAGIC is not a relationship
- **PASS** `every-written-edge-carries-the-four-required-fields` — 14 edge(s), each with evidence, time, source and confidence
- **PASS** `the-kinds-present-and-absent-are-both-named` — used ['CONNECTS_TO', 'PROTECTED_BY', 'ROUTES_TO', 'TERMINATES_TLS', 'USES_CERTIFICATE', 'USES_HSM', 'USES_KMS']; unused 2
- **PASS** `the-topology-states-what-an-edge-does-not-mean` — 4 stated limit(s)

## `confidence` — PASS

*who decides how strongly an edge is asserted?* (review 12)

- **PASS** `confidence-is-derived-from-the-evidence-class` — 10 observed, 4 declared
- **PASS** `a-handshake-behind-an-edge-makes-it-observed` — network observations stay observed
- **PASS** `an-inventory-binding-is-declared-not-observed` — four declared edges, four declared confidences
- **PASS** `a-claim-that-calls-itself-observed-is-corrected-and-flagged` — the caller may under-claim, never over-claim
- **PASS** `an-edge-with-no-evidence-is-not-drawn` — an uncited relationship is fiction

## `the_two_gates` — PASS

*which claims need more than one observation, and is that enforced?* (review 12)

- **PASS** `re-encryption-without-two-handshakes-is-refused` — re-encryption needs two handshakes in one path — a decrypt and a new encrypt — and one hop cannot show both
- **PASS** `re-encryption-with-a-decrypt-and-a-new-encrypt-is-written` — two handshakes, one path
- **PASS** `passthrough-without-a-session-identifier-is-refused` — a scanner sees two handshakes and cannot tell the difference
- **PASS** `passthrough-with-the-same-session-on-both-hops-is-written` — TLS-SESS-9 continued
- **PASS** `neither-gate-is-satisfied-by-the-chain-guide-s-assembled-evidence` — the estate contains no re-encryption claim, so none is drawn

## `the_audit` — PASS

*can the topology be read back and found honest?* (review 12)

- **PASS** `an-honest-topology-audits-clean-and-says-so` — the topology is internally honest: every edge carries provenance and no claim outruns its evidence
- **PASS** `a-terminating-device-s-tls-read-as-the-application-s-is-a-finding` — a load balancer's TLS 1.3 never becomes the application's property
- **PASS** `a-node-that-appears-only-because-an-edge-names-it-is-flagged` — an unnamed node is a hole in the inventory
- **PASS** `the-audit-refuses-a-document-that-is-not-a-topology` — a foreign document is rejected, not audited
- **PASS** `the-summary-reports-the-observed-share-and-the-unused-kinds` — observed share 0.71

## `from_observations` — PASS

*does the topology come from evidence rather than from wishes?* (review 12)

- **PASS** `hops-and-certificates-become-claims-with-their-own-evidence` — 12 relationship(s) derived from 4 hop(s), 2 certificate presentation(s) and key bindings
- **PASS** `an-observation-that-saw-nothing-derives-no-claim` — a hop with no evidence id produces nothing
- **PASS** `a-certificate-presentation-becomes-a-use-edge` — two presentations, two edges
- **PASS** `an-hsm-and-a-kms-binding-are-two-kinds-not-one` — HSM-1 and KMS-1 are different questions
- **PASS** `a-claim-with-one-end-missing-is-refused` — half an edge is not an edge

## What this does not prove

- the topology contains what was collected. A device nobody probed is absent, and absence is not the same as disconnected
- `CONNECTS_TO` is reachability observed by an authorized scanner, not an approved flow: no firewall policy, no proxy configuration and no ACL is read here
- `PASSTHROUGH` rests on the same session identifier appearing on both hops in one collector's view. It is stronger than a guess and weaker than a packet capture, and it says nothing about what the device inspects
- `PROTECTED_BY` is a position in a path. A WAF that sits in front of an application may inspect nothing, and this model cannot tell
- confidence describes the evidence, not the certainty of the network's behaviour: an `OBSERVED` edge was observed once, and a once-observed path can be decommissioned the same afternoon
- the nine kinds are fixed. A relationship that does not fit them is refused rather than given a new name, so the vocabulary cannot drift into one kind per collector
