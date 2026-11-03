# Endpoint → certificate → key → signature → issuer → trust chain

`cryptoscan.certificate-chain-guide/1` · generated 2026-11-03T01:04:03.157983+00:00 · **5 pass · 0 partial · 0 fail** · 29 probes

Review item 9: the certificate was already a record; the missing piece is the **chain** — which certificate signed which, where the path stops, and whether the stop is an anchor or a hole.

```
endpoint ──USES_CERTIFICATE──▶ leaf ──SIGNED_BY──▶ intermediate ──▶ root
   OBSERVED                    │                     │
                               └── key · signature · validity · SAN · problems
```

5 certificate(s) assembled into 5 path(s): 4 anchored, 1 incomplete. The paths are assembled from names and key identifiers; no signature was verified

Expiring: CERT-SOON · incomplete: CERT-ORPHAN · quantum-vulnerable keys: 5

| state | meaning |
|---|---|
| `VALID` | more than 30 days left |
| `EXPIRING` | 30 days or fewer |
| `EXPIRED` | past `notAfter` |
| `NOT_YET_VALID` | before `notBefore` |
| `UNKNOWN` | no expiry recorded — a collection gap, not a pass |

| resolution | meaning |
|---|---|
| `ANCHORED` | the path reached a declared (or self-signed CA) root |
| `INCOMPLETE` | the named issuer is not in the inventory |
| `LOOP` | the issuer name is ambiguous or the path closes on itself |
| `UNRESOLVED` | nothing above this certificate is known |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_hop` | does one certificate answer the review's whole chain question? | **PASS** | 6, 0 failing |
| `the_chain` | is a path a path, or a claim that the path is trusted? | **PASS** | 6, 0 failing |
| `what_the_chain_finds` | does the chain turn into PKI findings a team can act on? | **PASS** | 5, 0 failing |
| `the_edges` | does the chain become topology without inventing an edge? | **PASS** | 6, 0 failing |
| `shape` | do the refusals say what the chain will not do? | **PASS** | 6, 0 failing |

## `the_hop` — PASS

*does one certificate answer the review's whole chain question?* (review 9)

- **PASS** `one-certificate-carries-every-field-the-review-names` — CERT-9281 · ECDSA P-256 · ECDSA-SHA256 · CN=BANK-ICA-01 · VALID
- **PASS** `the-endpoint-it-was-observed-on-travels-with-it` — an endpoint, a source and a time on every hop
- **PASS** `validity-is-a-state-with-a-number-not-a-boolean` — valid for 59 more day(s)
- **PASS** `revocation-is-unknown-and-says-so` — no OCSP and no CRL is consulted here
- **PASS** `the-certificate-key-never-becomes-the-application-s-algorithm` — ECDSA / ECDSA-SHA256 describes the certificate on payments.bank.example:443. A certificate's pub…
- **PASS** `no-private-material-is-stored` — NOT_STORED

## `the_chain` — PASS

*is a path a path, or a claim that the path is trusted?* (review 9)

- **PASS** `the-leaf-resolves-to-a-root-through-its-intermediate` — CERT-9281 (leaf) → CERT-ICA1 → CERT-ROOT: anchored, matched by AUTHORITY_KEY_ID, ISSUER_NAME
- **PASS** `the-issuer-is-matched-by-key-id-first-and-name-second` — AUTHORITY_KEY_ID, ISSUER_NAME
- **PASS** `an-anchored-path-is-called-anchored-and-never-trusted` — a shape, not a trust decision
- **PASS** `a-certificate-whose-issuer-is-absent-is-a-hole` — CN=PARTNER-CA-01
- **PASS** `an-unconfirmed-root-is-listed-as-an-unconfirmed-anchor` — declaring CERT-ROOT removes it from the unconfirmed list
- **PASS** `the-chain-states-that-no-signature-was-verified` —  The paths are assembled from names and key identifiers; no signature was verified

## `what_the_chain_finds` — PASS

*does the chain turn into PKI findings a team can act on?* (review 9)

- **PASS** `an-expiring-certificate-is-a-state-with-a-date` — expires in 17 day(s)
- **PASS** `a-1024-bit-key-and-a-sha1-signature-are-both-reported` — WEAK_KEY, WEAK_SIGNATURE, QUANTUM_VULNERABLE
- **PASS** `quantum-exposure-is-marked-per-certificate-without-a-verdict` — 5 certificate(s) depend on a broken-by-Shor assumption
- **PASS** `the-summary-names-what-is-expiring-and-what-is-incomplete` — expiring ['CERT-SOON'] · incomplete ['CERT-ORPHAN']
- **PASS** `a-missing-expiry-is-a-collection-gap-not-a-pass` — an absent notAfter is unknown

## `the_edges` — PASS

*does the chain become topology without inventing an edge?* (review 9 / 12 boundary)

- **PASS** `every-edge-carries-evidence-source-and-confidence` — 4 edge(s); an OBSERVED edge also carries its time
- **PASS** `a-certificate-presented-by-an-endpoint-is-an-observed-edge` — payments.bank.example:443
- **PASS** `a-signature-edge-is-assembled-and-says-it-was-not-verified` — 3 assembled edge(s)
- **PASS** `a-missing-issuer-is-a-hole-rather-than-a-drawn-edge` — 4 evidence-backed relationship(s) from the chain; 1 missing issuer(s) are reported as holes rather than drawn as edges; 2 presentation(s) had no observation time and were not written
- **PASS** `a-presentation-with-no-observation-time-is-not-written` — an OBSERVED edge without a moment is a claim, not evidence
- **PASS** `an-edge-is-not-duplicated-once-per-descendant` — 4 unique edge(s)

## `shape` — PASS

*do the refusals say what the chain will not do?* (review 9)

- **PASS** `a-certificate-with-no-reference-is-refused` — a chain cannot cite a certificate it cannot name
- **PASS** `a-certificate-with-no-evidence-is-refused` — an uncited hop is not evidence
- **PASS** `a-non-certificate-is-refused-rather-than-coerced` — 1 certificate(s) assembled into 1 path(s): 1 incomplete. The paths are assembled from names and key identifiers; no signature was verified
- **PASS** `the-chain-refuses-a-document-that-is-not-a-chain` — a foreign document is rejected, not drawn
- **PASS** `two-certificates-sharing-a-public-key-are-reported` — one key, two certificates
- **PASS** `every-claim-the-chain-cannot-make-is-stated` — 4 stated limit(s)

## What this does not prove

- the chain is assembled from subject/issuer names and key identifiers. No signature is verified, no path-length constraint is enforced and no policy is consulted, so `ANCHORED` describes a shape and never a trust decision
- trust is a property of the relying party's store, which this inventory does not read. A certificate that chains to the bank's root may still be rejected by a client that does not carry that root
- revocation is unknown on every row: no OCSP response and no CRL is consulted, and a missing answer is not a good answer
- a certificate whose issuer is absent from the inventory stops the path. That is a collection gap — usually a missing intermediate — and the guide reports the missing subject rather than treating the last hop as a root
- the key-size and signature floors are the model's own, chosen to be explainable rather than to match any particular regulator's table
- two certificates sharing a public key are reported, not explained: key reuse can be a deliberate staging certificate or a mistake, and telling them apart needs the PKI's own records
