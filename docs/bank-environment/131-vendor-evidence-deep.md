# Vendor evidence, second pass: closing the five gaps

`cryptoscan.vendor-evidence-guide/2` · generated 2026-11-02T14:02:05.707293+00:00 · as of 2026-11-02 · **7 pass · 0 partial · 0 fail**

Guide 130 ended with five things it could not prove, and said so. This artifact is the work that closes them, and it is deliberately harder to satisfy than the first: a PDF is actually inflated and parsed, a cipher suite is actually decomposed, and the second identity axis is exercised with a negative control that would light every capability if the gate were a sentence instead of code.

| What guide 130 could not prove | What this artifact does instead |
|---|---|
| vendor documents were fixtures | a questionnaire — text, Markdown table or PDF text layer — is read with a line number and a line hash per field |
| identity had one axis | `crypto_profile_version` is a second axis, and an unobserved profile leaves the answer `PARTIAL_MATCH` instead of `MATCHED` |
| reconciliation was string-exact | an alias table resolves `AES256`, `aes_256` and `Dilithium3` while keeping `AES-128` and `AES-256-GCM` as different statements |
| `USAGE_OBSERVED` was a word | a session transcript becomes claims with one citation per session, and a hybrid group is post-quantum use in the wild |
| there were no vendor→vendor edges | a sub-vendor chain with depth, path, evidence and cycle refusal, and direct exposure counted apart from inherited exposure |

Two further rows exist because the evidence had not yet reached the document: the existing `VbomGenerator` now accepts evidence-bearing rows, and every partial answer is enumerated in a ledger that cannot render it as a pass.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `algorithm_identity` | does the VBOM tell two spellings of one algorithm from two algorithms? | **PASS** | 7, 0 failing |
| `profile_axis` | when a vendor versions its crypto profile apart from its firmware, does the gate still hold? | **PASS** | 5, 0 failing |
| `document_extraction` | is a vendor questionnaire read, or still a fixture? | **PASS** | 6, 0 failing |
| `runtime_usage` | does USAGE_OBSERVED exist as evidence, or only as a word? | **PASS** | 7, 0 failing |
| `sub_vendor_chains` | can the estate answer 'which systems depend on Vendor-X, including through the vendors it embeds?' | **PASS** | 4, 0 failing |
| `vbom_integration` | does the evidence reach the VBOM document, and does the PQC tick keep its qualification? | **PASS** | 3, 0 failing |
| `partial_ledger` | is 'some, but not all' a state, or a rounding error? | **PASS** | 4, 0 failing |

## `algorithm_identity` — PASS

*does the VBOM tell two spellings of one algorithm from two algorithms?* (review item 15)

- **PASS** `one-algorithm-four-spellings` — 4 spellings -> ['AES-256']; 'AES256' normalised=True
- **PASS** `a-size-is-not-a-spelling` — AES-128 against AES-256 -> DIFFERENT_PARAMETER: same family, 128 against 256 bits
- **PASS** `a-missing-mode-is-less-specific-not-wrong` — AES-256 against AES-256-GCM -> LESS_SPECIFIC, so it reconciles PARTIAL, not CONFLICT
- **PASS** `two-families-and-two-modes-are-never-merged` — 3DES/AES-256 -> DIFFERENT_ALGORITHM, AES-256-GCM/AES-256-CBC -> DIFFERENT_MODE
- **PASS** `the-pre-standard-pqc-name-resolves` — Dilithium3 -> ML-DSA-65 (pqc=True); KYBER768 -> ML-KEM-768
- **PASS** `an-unknown-name-is-flagged-not-invented` — FOO-256 parses by shape with recognised=False; summary names ['FOO-256'] as outside the alias table
- **PASS** `the-reconciler-uses-the-table-and-records-it` — vendor=AES256 runtime=AES-256 -> AGREE on ['AES-256'], normalisation recorded=True

## `profile_axis` — PASS

*when a vendor versions its crypto profile apart from its firmware, does the gate still hold?* (review item 7/8)

- **PASS** `firmware-agrees-and-the-profile-does-not` — firmware 8.4.0/8.4.0 but profile 3.0/3.1 -> VERSION_MISMATCH on axis crypto_profile: declared crypto profile 3.0, deployed 3.1: the firmware versions may agree while the crypto profile does not
- **PASS** `an-unobserved-profile-leaves-the-answer-partial` — profile 3.1 declared, none observed -> PARTIAL_MATCH ({'product_version': 'EXACT', 'crypto_profile': 'UNVERIFIED'}); the declaration cannot be quoted as a full match
- **PASS** `matched-needs-both-axes` — both axes agree -> MATCHED {'product_version': 'EXACT', 'crypto_profile': 'MATCH'}
- **PASS** `a-firmware-mismatch-is-not-blamed-on-the-profile` — declared 8.2.1 profile 3.0 against deployed 8.4.0 profile 3.1 -> VERSION_MISMATCH on axis product_version
- **PASS** `the-axis-is-what-withholds-the-capability` — with the profile axis replaced by a constant MATCH the same document lights 3 capability(ies) (AES-256, RSA-3072, ML-DSA-65) on an appliance whose profile differs — so the refusal is the gate, not this paragraph

## `document_extraction` — PASS

*is a vendor questionnaire read, or still a fixture?* (review item 9)

- **PASS** `a-questionnaire-is-read-with-a-citation-per-field` — 8 field(s) with line numbers and line hashes; version from line 3, profile 3.1
- **PASS** `a-pdf-text-layer-is-read` — 322 bytes of PDF -> version 8.4.0, 3 canonical algorithm(s)
- **PASS** `an-encrypted-or-scanned-document-is-refused-with-its-reason` — three refusals rather than an empty string: encrypted (no text layer), scanned (no text layer, OCR or a text copy needed), not-a-PDF
- **PASS** `a-missing-version-stays-unknown` — missing=['version'] -> applicability UNKNOWN, so the document is filed and cannot be quoted
- **PASS** `extraction-is-not-approval` — evidence_type=IMPORTED, requires_review=True — a machine read it, a person has not confirmed it
- **PASS** `a-document-with-no-vendor-cannot-become-a-declaration` — no vendor -> refused rather than attached to whatever supplier is nearest

## `runtime_usage` — PASS

*does USAGE_OBSERVED exist as evidence, or only as a word?* (review item 6)

- **PASS** `a-session-becomes-a-claim-with-one-citation-per-session` — 12 sessions -> AES-256-GCM with 12 citation(s), status RUNTIME_OBSERVED_ONLY, confidence MEDIUM
- **PASS** `a-hybrid-group-means-post-quantum-was-actually-used` — group x25519mlkem768 -> ['ML-KEM-768']: key establishment, observed, not declared
- **PASS** `an-unknown-suite-is-named-not-guessed` — TLS_MYSTERY_SHA256 -> known=False, primitives=[], reason: only a hash name was recognised, which does not identify the suite
- **PASS** `payload-and-key-material-are-refused-by-name` — a record carrying 'payload' or 'premaster_secret' is refused at ingestion — this reader holds metadata only
- **PASS** `one-session-and-forty-sessions-are-different-statements` — 1 session -> LOW, 40 -> HIGH for the same algorithm
- **PASS** `an-empty-transcript-is-not-an-all-clear` — no sessions were observed, so nothing is known about production use — an empty transcript is not evidence of absence
- **PASS** `runtime-evidence-reaches-the-claim-flags` — the grouped capability reports RUNTIME_OBSERVED_ONLY: observed at runtime, declared by nobody — a finding about the estate

## `sub_vendor_chains` — PASS

*can the estate answer 'which systems depend on Vendor-X, including through the vendors it embeds?'* (review item 11/12)

- **PASS** `a-sub-vendor-edge-carries-its-path-and-evidence` — Vendor-X -> Vendor-Z at depth 1, cited by VE-8af66ef1f9ee
- **PASS** `a-cycle-is-refused-rather-than-followed` — two vendors that embed each other -> 1 cycle reported, expansion stops at ['Vendor-Z']
- **PASS** `direct-and-indirect-exposure-are-counted-separately` — 1 appliance bought directly, 1 reached through Vendor-Z; Vendor-X: 1 appliance(s) bought directly, 1 more reached through 1 sub-vendor(s); 2 system(s) in total, of which 1 critical
- **PASS** `a-vendor-cannot-embed-itself` — a self-edge is refused at construction rather than producing a depth-2 chain back to the same supplier

## `vbom_integration` — PASS

*does the evidence reach the VBOM document, and does the PQC tick keep its qualification?* (review item 13)

- **PASS** `claims-feed-the-existing-generator-with-their-evidence` — 7 row(s) in the vendor block; the first carries applicability MATCHED, status DECLARED_ONLY and 1 evidence id(s)
- **PASS** `pqc-coverage-and-evidence-backed-coverage-are-different-numbers` — 2 post-quantum tick(s), 1 backed by observation (['ML-KEM-768']), 1 resting on a declaration (['ML-DSA-65'])
- **PASS** `the-document-cannot-print-one-green-number` — the generator's own summary reports 2 of 7 row(s) post-quantum ready (28.6%); the evidence-backed count is 1 — both numbers stay in the output on purpose

## `partial_ledger` — PASS

*is 'some, but not all' a state, or a rounding error?* (review item 8/15)

- **PASS** `partials-are-enumerated-not-summarised` — 2 of 3 answers are partial and each appears with its reason; counts {'MATCHED': 1, 'PARTIAL': 1, 'PARTIAL_MATCH': 1}
- **PASS** `no-partial-can-be-rendered-as-a-pass` — every entry carries renderable_as_pass=False and dropped=0 — a partial is neither rounded up to green nor deleted
- **PASS** `a-clean-run-says-that-nothing-is-partial` — none of 2 answer(s) is partial
- **PASS** `the-check-fails-on-a-partial-as-well-as-on-a-failure` — this artifact's --check exits 2 on FAIL and 1 on PARTIAL, so a partial row cannot be mistaken for a green artefact

## What this does not prove

- no vendor was contacted. The questionnaire is written by this file and the PDF is built by this file, so what is graded is the reader, not a vendor's paperwork
- the PDF reader handles text layers only: encrypted files and scanned pages are refused with a reason, and object-stream or font-encoding edge cases are not implemented
- the alias table is finite and hand-written. A name outside it is carried verbatim and flagged; nothing is guessed, and a bank's own spelling has to be added deliberately
- the session transcript is a fixture shaped like a TLS session log. A live connector (a tap on the payment path, a PKCS#11 audit log) is still required to produce it, and that connector is where the metadata-only rule has to be enforced a second time
- sub-vendor edges are supplied by the bank from SBOMs and contracts; nothing here discovers that a vendor embeds another vendor's library
- runtime claims prove a primitive was exercised. They do not prove which application did it: application attribution still comes from the dependency records in guide 130

## What is still missing

1. **Vendor paperwork is still synthetic.** The reader is real; the document is not. A bank's first action with this module is to run it over the questionnaire it actually received, and to reject anything the extraction cannot cite.
2. **No live runtime connector.** The transcript format is defined and the decoder is graded; producing the transcript from a payment path needs a tap or an audit-log reader, and that is the next piece of work rather than a parser tweak.
3. **Brand new algorithm families.** The alias table knows the names in use today. A name it does not know is flagged, never resolved, so a new family is a code change rather than a silent mis-match.
4. **Sub-vendor discovery.** Edges are asserted from SBOMs and contracts; transitive discovery from a vendor's own SBOM is not implemented.
5. **Application attribution of runtime use.** A session proves a primitive was used; which application used it still comes from the dependency records.

## How to run it

```bash
python scripts/vendor_evidence_deep.py --as-of 2026-11-02 \
--json docs/bank-environment/131-vendor-evidence-deep.json \
--md docs/bank-environment/131-vendor-evidence-deep.md
python scripts/vendor_evidence_deep.py --check    # non-zero on FAIL or PARTIAL
```

