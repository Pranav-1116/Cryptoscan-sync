# Adversarial CBOM: the five blockers, attacked

`cryptoscan.cbom-adversarial-guide/1` · generated 2026-11-02T18:46:19.019272+00:00 · **5 pass · 0 partial · 0 fail** · 30 probes

Every probe here takes the attacker's side: hand the pipeline the most convenient possible input and check that it is not believed.

```
input:  {"class": "RUNTIME_OBSERVED", "layer": "imported", "evidence_id": "V-1"}
output: class=IMPORTED, observed=False
        the event claims RUNTIME_OBSERVED, but its origin is imported (IMPORTED); an imported or vendor-declared source cannot observe, so the weaker class is kept
```

One of the five was a real hole when this guide attacked it: an event that named an imported or vendor origin while **claiming** `RUNTIME_OBSERVED` was promoted as runtime usage. `usage_evidence.normalize_event` now makes the origin win in both directions, and records the downgrade on the event instead of silently reclassifying it.

| blocker | what is attacked | outcome |
|---|---|---|
| evidence spoofing | an imported document claiming an observation | `IMPORTED`, downgrade recorded, no promotion |
| false attribution | a library that supports four algorithms | four candidates, zero assets |
| weak promotion | a vendor claiming runtime use and quantum readiness | candidate only; the handoff classifies the algorithm itself |
| secret leakage | key records carrying material | refused before storage, `private_material: NOT STORED` |
| signature/hash confusion | a certificate's ECDSA-SHA256 | `CERTIFICATE_ONLY`, `application_operation_proven: false`, roles kept apart |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `evidence_spoofing` | can an imported document call itself an observation? | **PASS** | 7, 0 failing |
| `false_attribution` | does a supporting library become an inventory of usage? | **PASS** | 6, 0 failing |
| `weak_promotion` | can a declaration be promoted into an observation? | **PASS** | 5, 0 failing |
| `secret_leakage` | can a collector be talked into storing key material? | **PASS** | 6, 0 failing |
| `signature_hash` | are hashes, signatures and key exchanges kept apart? | **PASS** | 6, 0 failing |

## `evidence_spoofing` — PASS

*can an imported document call itself an observation?* (review 21 / 4)

- **PASS** `an-imported-origin-is-never-an-observation` — 7 import spellings, all IMPORTED
- **PASS** `a-vendor-origin-is-downgraded-to-a-declaration` — vendor → VENDOR_DECLARED, vendor_declaration → VENDOR_DECLARED
- **PASS** `the-downgrade-is-recorded-not-silent` — the event claims RUNTIME_OBSERVED, but its origin is sbom (IMPORTED); an imported or vendor-declared source cannot observe, so the weaker class is kept
- **PASS** `an-evidence-id-does-not-launder-an-imported-source` — a plausible evidence id on an imported event is still an import
- **PASS** `a-real-runtime-event-is-not-downgraded` — the guard protects the collector it exists to protect
- **PASS** `a-spoofed-event-cannot-promote-a-capability` — 0 CBOM asset(s) promoted from evidence, 1 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `a-spoofed-estate-produces-an-empty-document` — the chain never sees a claimed class, only the collector's

## `false_attribution` — PASS

*does a supporting library become an inventory of usage?* (review 21 / 6)

- **PASS** `a-library-does-not-become-every-algorithm-it-supports` — 0 CBOM asset(s) promoted from evidence, 4 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `a-candidate-is-not-usage` — AES-128-GCM=NOT_OBSERVED, AES-256-GCM=NOT_OBSERVED, RSA-2048=NOT_OBSERVED, ECDSA-P256=NOT_OBSERVED
- **PASS** `the-candidate-lists-what-would-promote-it` — a reviewer can see the evidence that would make it an asset
- **PASS** `a-component-with-no-evidence-id-contributes-nothing` — the component has no evidence id, so its capabilities cannot be attributed to a document
- **PASS** `a-capability-only-estate-has-an-empty-document` — capabilities are reported, never written as fact
- **PASS** `the-document-says-how-many-it-left-out` — the exclusion is in the document, not only in a log

## `weak_promotion` — PASS

*can a declaration be promoted into an observation?* (review 21 / 5)

- **PASS** `a-vendor-declaration-never-reaches-runtime` — 0 CBOM asset(s) promoted from evidence, 1 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `an-observation-with-no-evidence-id-is-refused` — a claim nobody can point at cannot promote anything
- **PASS** `a-vendor-quantum-claim-is-ignored-and-the-algorithm-is-classified` — vendor said POST_QUANTUM; the handoff says QUANTUM_SENSITIVE (REGISTRY_SHOR)
- **PASS** `a-declared-class-promotes-to-a-declared-level-never-runtime` — VENDOR_DECLARED → CAPABILITY
- **PASS** `the-quantum-verdict-is-never-taken-from-the-document` — a vendor cannot certify its own migration

## `secret_leakage` — PASS

*can a collector be talked into storing key material?* (review 21 / 12)

- **PASS** `every-material-bearing-field-is-refused` — 7 of 7 refused, e.g. this record carries private_key; a CBOM stores key references and properties, never key material
- **PASS** `the-record-states-that-nothing-is-stored` — NOT STORED
- **PASS** `the-metadata-that-is-allowed-is-the-metadata-a-bank-needs` — key_ref=HSM://partition-01/key/PAY-SIGN-001, algorithm=RSA, key_size=2048, purpose=SIGNATURE
- **PASS** `an-unexpected-field-is-refused-rather-than-kept` — unexpected key metadata field(s): opaque_blob
- **PASS** `the-chain-refuses-a-key-record-carrying-material` — the row carries private_key; a CBOM stores key references, never material
- **PASS** `no-material-reaches-the-document` — the exported document is checked for the value, not for the field name

## `signature_hash` — PASS

*are hashes, signatures and key exchanges kept apart?* (review 21 / 3)

- **PASS** `a-certificate-is-its-own-category` — ECDSA-SHA256
- **PASS** `a-certificate-does-not-prove-an-application-operation` — ECDSA / ECDSA-SHA256 describes the certificate on payments.bank.example:443. A certificate's public key does not prove the application behind it performs that algorithm
- **PASS** `a-certificate-never-promotes-the-application-to-its-algorithm` — 0 CBOM asset(s) promoted from evidence, 1 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `a-suite-says-which-algorithm-plays-which-role` — {"AES-256-GCM": "BULK", "ECDHE": "KEY_EXCHANGE", "RSA": "SIGNATURE", "SHA-384": "HASH"}
- **PASS** `a-hash-is-never-counted-as-a-signature` — SHA-384 in a TLS 1.3 suite is a hash and nothing else
- **PASS** `an-unknown-suite-produces-no-fact-rather-than-a-guess` — a suite the table does not know yields nothing

## What this does not prove

- the guard is about the origin an event names, not about the class string. A caller that supplies its own evidence id and names a genuinely observing layer is believed, because the platform cannot audit a collector it did not write
- an imported *document* is still parsed for capabilities, and a capability is reported. What cannot happen is a capability becoming usage, which is a different claim from 'the document was ignored'
- the secret guard is a field-name and vocabulary check, not a secret scanner. A key material pasted into a free-text field named 'note' would pass, which is why the KMS collector also refuses unknown fields
- the certificate category says what the certificate contains. It cannot say whether the endpoint is still served by that certificate, which needs a probe
- these probes attack the modules directly. An attacker with write access to the platform's own collector output does not need any of this — provenance, not classification, is what stops that
