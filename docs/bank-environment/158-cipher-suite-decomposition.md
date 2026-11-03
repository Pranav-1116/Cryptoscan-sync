# A cipher suite is four decisions, and TLS 1.3 names only two

`cryptoscan.cipher-suite-guide/1` · generated 2026-11-03T01:00:11.835358+00:00 · **5 pass · 0 partial · 0 fail** · 24 probes

Review item 8: a suite string is not a description. `TLS_AES_256_GCM_SHA384` names an AEAD and a hash; the key exchange and the signature are decided by the handshake, and an inventory that flattens the suite into a list of names cannot answer a migration question.

```
KEY_EXCHANGE · AUTHENTICATION · ENCRYPTION · HASH
     ↑ group        ↑ signature        ↑ AEAD         ↑ PRF
     └── NAMED_IN_SUITE ─┬─ NEGOTIATED ─┬─ NOT_NAMED (unknown, never RSA) ──┘
```

5 handshake(s) decomposed into four dimensions; 3 carry at least one dimension the suite does not name and the handshake did not report

| rating | what it means |
|---|---|
| `STRONG` | AEAD bulk cipher, ≥128-bit key, ephemeral key exchange |
| `ACCEPTABLE` | AEAD and ≥128-bit, but no forward secrecy |
| `WEAK` | CBC mode or a bulk key below 128 bits |
| `BROKEN` | RC4, 3DES/DES, NULL, EXPORT or anonymous key exchange |
| `UNKNOWN` | the identifier names a mode this table does not model |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `four_dimensions` | does one suite string become four decisions with their evidence? | **PASS** | 5, 0 failing |
| `strength` | does the decomposition answer why a suite is weak? | **PASS** | 5, 0 failing |
| `algorithm_facts` | can the decomposition feed the CBOM without a second vocabulary? | **PASS** | 5, 0 failing |
| `frontier` | which of the four decisions does a PQC migration touch? | **PASS** | 4, 0 failing |
| `batch_and_shape` | does a batch of handshakes produce a usable, honest report? | **PASS** | 5, 0 failing |

## `four_dimensions` — PASS

*does one suite string become four decisions with their evidence?* (review 8)

- **PASS** `a-tls12-suite-names-all-four-dimensions` — ECDHE-RSA-AES128-GCM-SHA256: key_exchange=ECDHE (named_in_suite), authentication=RSA (named_…
- **PASS** `a-tls13-suite-names-two-and-takes-the-rest-from-the-handshake` — X25519 and ECDSA-P256 arrive from the handshake, not the suite
- **PASS** `every-dimension-records-where-its-answer-came-from` — named_in_suite for the AEAD and hash, negotiated for the other two
- **PASS** `a-missing-key-exchange-is-unknown-and-not-rsa` — a TLS 1.3 suite does not name key exchange; without the negotiated group the answer is unknown, not RSA
- **PASS** `the-certificate-key-can-supply-the-authentication` — the certificate's key is named as the source

## `strength` — PASS

*does the decomposition answer why a suite is weak?* (review 8 / 11)

- **PASS** `an-aead-suite-under-an-ephemeral-group-is-strong` — an AEAD bulk cipher under an ephemeral key exchange
- **PASS** `no-forward-secrecy-caps-the-rating-without-breaking-it` — the certificate key protects the session: no forward secrecy
- **PASS** `cbc-mode-is-weak-and-says-why` — ); weak — no forward secrecy was established by the named method
- **PASS** `a-token-that-must-not-be-enabled-is-broken-not-weak` — RC4 must not be enabled
- **PASS** `an-unrecognised-suite-is-unknown-and-says-so` — this suite is not in the token table, so its strength is unknown

## `algorithm_facts` — PASS

*can the decomposition feed the CBOM without a second vocabulary?* (review 8 / 9)

- **PASS** `the-facts-use-the-roles-the-cbom-already-knows` — BULK=AES-256-GCM, HASH=SHA-384, KEY_EXCHANGE=X25519, SIGNATURE=ECDSA-P256
- **PASS** `handshake-facts-are-marked-as-not-coming-from-the-suite` — the suite names the AEAD and the hash; the handshake names the rest
- **PASS** `an-absent-dimension-produces-no-fact-at-all` — two facts from a suite that names two things
- **PASS** `facts-carry-the-evidence-and-the-endpoint-they-came-from` — NET-1 on every fact
- **PASS** `no-fact-claims-a-quantum-verdict` — quantum relevance is the handoff's job, not this model's

## `frontier` — PASS

*which of the four decisions does a PQC migration touch?* (review 8 / 15 boundary)

- **PASS** `the-migration-frontier-names-the-dimensions-to-replace` — 2 of 4 dimension(s) are quantum-relevant
- **PASS** `a-symmetric-bulk-cipher-is-not-flagged-as-quantum-critical` — AES-256-GCM needs a bigger key at most, not a new primitive
- **PASS** `an-unknown-dimension-asks-for-evidence-before-a-plan` — a migration plan built on an unknown dimension would be a guess
- **PASS** `the-frontier-counts-what-is-quantum-relevant` — 2 of 4 dimension(s) are quantum-relevant

## `batch_and_shape` — PASS

*does a batch of handshakes produce a usable, honest report?* (review 8)

- **PASS** `a-batch-decomposes-every-endpoint-and-counts-the-ratings` — 5 handshake(s) decomposed into four dimensions; 3 carry at least one dimension the suite does not name and the handshake did not report
- **PASS** `a-row-with-no-suite-is-refused-not-decomposed` — 1 handshake(s) decomposed into four dimensions; 1 carry at least one dimension the suite does not name and the handshake did not report; 1 refused
- **PASS** `a-non-row-is-refused` — a string is not a handshake
- **PASS** `the-model-states-what-one-handshake-cannot-prove` — 4 stated limit(s)
- **PASS** `nothing-in-the-output-calls-anything-an-attack` — a weak suite is a configuration fact

## What this does not prove

- one negotiated suite is one handshake. It is not the endpoint's configured set, and it is not proof that a stronger suite could not be negotiated
- the group, the signature algorithm and the certificate come from the handshake or the certificate. When a collector records only the suite, those dimensions stay unknown — deliberately, because the usual guess (no key-exchange token means RSA) is wrong for TLS 1.3
- forward secrecy is a property of the method named, not of the implementation: a correct ECDHE suite in a defective stack is still defective
- the strength ladder is explainable rather than scored: AEAD, bulk key size, mode and whether the suite names a token that must not be enabled. A reviewer can disagree with one rating without distrusting the rest
- a legacy identifier the token table does not model is reported as unknown rather than mapped to the nearest mode. `AES128` with no mode token is read as CBC because that is what the identifier means in TLS 1.2, and it is noted as such
- nothing here decides quantum status: `frontier()` says which dimensions are quantum-relevant and leaves the verdict to the PQC handoff
