# Vendor evidence: a declaration is not a deployment

`cryptoscan.vendor-evidence-guide/1` · generated 2026-11-02T13:44:09.511747+00:00 · as of 2026-11-02 · **9 pass · 0 partial · 0 fail**

The VBOM's dangerous shortcut is one sentence long: *the vendor says product X supports ML-DSA, therefore the payment system uses ML-DSA*. It is wrong in three separate ways, and this artifact is the answer to each of them.

1. **A capability is not a usage.** `CAPABILITY_DECLARED` comes from a vendor document, `CAPABILITY_OBSERVED` from the bank's own collector and `USAGE_OBSERVED` from a configuration or a running session. Three events, three evidence types, and no path from the first to the third except through the second.
2. **A declaration has a version, and the bank has another.** A crypto profile written for firmware 8.2.1 does not describe an 8.4.0 appliance. The verdict is computed — `MATCHED`, `PARTIAL_MATCH`, `VERSION_MISMATCH`, `PRODUCT_MISMATCH`, `DEPLOYMENT_UNVERIFIED`, `EXPIRED`, `SUPERSEDED`, `UNKNOWN` — and the capability flags follow it.
3. **Sources disagree, and the disagreement is the finding.** Vendor 3.0.13, SBOM 3.0.11, runtime 3.0.11 is a `CONFLICT`, not a value. Collapsing it to the newest or the loudest source is how a BOM becomes a plausible document.

The module under test is `services/vendor_intel/vendor_intel/vendor_evidence.py`; it is pure Python over plain dataclasses, so every verdict below is computed from the declarations, deployments and evidence handed to it.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `evidence_vocabulary` | does the evidence model distinguish a vendor claim from a bank fact? | **PASS** | 4, 0 failing |
| `version_applicability` | does a vendor document for one product version stay attached to that version? | **PASS** | 6, 0 failing |
| `due_diligence` | is vendor due diligence a structured record or a status field? | **PASS** | 5, 0 failing |
| `lifecycle` | does the product lifecycle drive the crypto migration answer? | **PASS** | 4, 0 failing |
| `dependency_chains` | can the estate answer 'which bank systems depend on this vendor product?' — for hardware and for software? | **PASS** | 4, 0 failing |
| `capability_evidence` | does one capability row show what is declared, what is observed and what is used? | **PASS** | 5, 0 failing |
| `freshness` | does old vendor evidence still look current on the dashboard? | **PASS** | 5, 0 failing |
| `reconciliation` | when the vendor, the SBOM, the CBOM and the runtime disagree, does the VBOM pick a winner? | **PASS** | 5, 0 failing |
| `vendor_risk` | is a vendor risk rating explainable, or a colour somebody typed? | **PASS** | 4, 0 failing |

## `evidence_vocabulary` — PASS

*does the evidence model distinguish a vendor claim from a bank fact?* (review item 6)

- **PASS** `eight-evidence-types-and-no-shortcut` — the vocabulary is closed and ordered: UNKNOWN < INFERRED < DECLARED < IMPORTED < CONFIGURED < OBSERVED < NETWORK_OBSERVED < RUNTIME_OBSERVED — a vendor claim never outranks the bank's own observation
- **PASS** `a-declaration-does-not-become-an-observation` — a vendor document alone yields DECLARED_ONLY with confidence LOW — it cannot reach CONFIRMED because nothing in the bank's estate was read
- **PASS** `the-drift-vocabulary-separates-the-three-events` — CAPABILITY_DECLARED, CAPABILITY_OBSERVED and USAGE_OBSERVED are three events with three definitions, so a dashboard cannot collapse them into one green tick
- **PASS** `an-evidence-row-cannot-be-anonymous` — a claim with no citation is refused at construction: evidence must name the record it came from, and the row carries a stable VE- identifier

## `version_applicability` — PASS

*does a vendor document for one product version stay attached to that version?* (review item 7/8)

- **PASS** `declared-8-2-1-against-deployed-8-4-0-is-a-mismatch` — 8.2.1 versus 8.4.0 -> VERSION_MISMATCH: declared 8.2.1, deployed 8.4.0: a different generation, so the declared crypto inventory does not travel
- **PASS** `a-mismatched-declaration-lights-no-capability` — 4 declared capabilities are carried with the verdict and none of them is counted as a vendor capability of this appliance
- **PASS** `the-version-verdict-has-four-distinct-answers` — exact=8.2.1->MATCHED, patch 8.2.1->8.2.2 PARTIAL_MATCH, minor 8.3.0->8.4.0 VERSION_MISMATCH, and 8.10 > 8.9 because versions compare as numbers rather than strings
- **PASS** `a-product-or-vendor-mismatch-is-not-a-version-mismatch` — four different refusals for four different reasons: wrong product, wrong vendor, unversioned deployment and unversioned document — none of them silently MATCHED
- **PASS** `superseded-and-expired-documents-are-refused-even-at-the-right-version` — a document replaced by a newer one is SUPERSEDED and an old one is EXPIRED, both before any capability is quoted — the version matches and the claim is still refused
- **PASS** `the-gate-is-what-withholds-the-capability` — with the applicability gate replaced by a constant MATCHED the same 8.2.1 document lights every capability on the 8.4.0 appliance — so the refusal above is the gate doing the work, not a phrase in this paragraph

## `due_diligence` — PASS

*is vendor due diligence a structured record or a status field?* (review item 9)

- **PASS** `twenty-two-sections-and-no-implicit-zero` — 22 sections are listed; a section that is missing is named rather than scored as zero: vendor_identity, product, product_version, contract, support_lifecycle, end_of_life, …
- **PASS** `an-empty-record-is-incomplete-with-reasons` — an empty record scores 0.0% and blocks approval for 6 stated reasons, e.g. the last review is unknown: no verification date, so the age of this evidence is unknown
- **PASS** `a-complete-current-review-passes-and-a-stale-one-does-not` — all 22 sections present, review 365 days old -> COMPLETE, 0 blocker(s)
- **PASS** `the-same-record-with-a-2024-review-is-blocked` — every section is still on file, and the record is 813 days old, so approval is blocked and the age is stated
- **PASS** `an-unknown-review-status-is-refused` — a review status outside the five the model accepts raises rather than being stored

## `lifecycle` — PASS

*does the product lifecycle drive the crypto migration answer?* (review item 10)

- **PASS** `six-lifecycle-states` — the ladder runs CURRENT -> SUPPORTED -> MAINTENANCE -> END_OF_SUPPORT -> END_OF_LIFE -> RETIRED
- **PASS** `dates-override-a-stale-declared-state` — the record still says SUPPORTED while support ended on 2025-06-30: the effective state is END_OF_SUPPORT and the drift is reported
- **PASS** `end-of-life-is-not-end-of-support` — past both dates the product is END_OF_LIFE, not merely END_OF_SUPPORT, and the record is flagged unsupported
- **PASS** `lifecycle-is-an-input-to-risk-not-a-label` — the same product state appears as its own risk factor with 25 points, so an EOL appliance raises the vendor score instead of sitting beside it as decoration

## `dependency_chains` — PASS

*can the estate answer 'which bank systems depend on this vendor product?' — for hardware and for software?* (review item 11/12)

- **PASS** `vendor-product-to-asset-to-application-to-system` — Vendor-X HSM-X500 -> 3 appliance(s) -> 4 application(s) -> 3 service(s) -> ['Card Authorization']; the other vendor's appliance is not counted
- **PASS** `counts-are-per-level-and-never-summed` — three appliances and four applications is not seven of anything — each level is counted on its own, which is the number a risk committee can act on
- **PASS** `no-recorded-deployment-is-not-no-dependency` — a vendor with no recorded appliance says so explicitly, so an empty result cannot be read as an all-clear
- **PASS** `an-end-of-life-sdk-reaches-applications-containers-and-systems` — SDK 4.2 -> 3 applications, 7 containers, 2 systems and 1 critical service — the version filter excludes the 4.1 deployment, which is a different exposure

## `capability_evidence` — PASS

*does one capability row show what is declared, what is observed and what is used?* (review item 13)

- **PASS** `six-verification-flags-not-one-boolean` — AES-256 shows vendor_declared, bank_observed, production_usage, version_matched and evidence_fresh separately; the single status is CONFIRMED, and a UI does not have to infer it
- **PASS** `runtime-evidence-outranks-a-declaration` — a capability the vendor declared and a running session exercised is CORROBORATED at HIGH confidence — the one combination that justifies the word verified
- **PASS** `the-capability-record-carries-all-eighteen-fields` — every field the review listed is present, including the applicability verdict and the evidence list, and the record holds no key material of any kind
- **PASS** `a-bank-observation-the-vendor-never-declared-is-still-recorded` — AES-128 observed on the appliance and never declared is recorded at MEDIUM as BANK_OBSERVED_ONLY — it is a finding about the estate, not a gap in the VBOM
- **PASS** `the-vbom-row-carries-the-evidence-not-just-a-boolean` — the existing `VbomGenerator` row shape gains the evidence type, the applicability verdict, the verification status and both evidence ids — so a VBOM row can be defended one at a time (ML-DSA-65: ML-DSA is a post-quantum construction)

## `freshness` — PASS

*does old vendor evidence still look current on the dashboard?* (review item 14)

- **PASS** `a-2024-questionnaire-in-2026-is-stale-with-its-age` — last verified 2024-08-11, 813 days ago -> EXPIRED: last verified 2024-08-11, 813 days ago — more than twice the review window, so it cannot support a current claim
- **PASS** `three-freshness-states-plus-unknown` — FRESH inside one review window, STALE inside two, EXPIRED beyond that, and UNKNOWN when there is no date at all — a missing date is not treated as fresh
- **PASS** `stale-evidence-emits-its-own-event` — an old document produces VENDOR_EVIDENCE_STALE beside the claim rather than quietly supporting a current answer: VENDOR_DOCUMENT_EXPIRED, VENDOR_EVIDENCE_STALE
- **PASS** `an-expired-document-is-filed-as-expired` — an out-of-date document raises VENDOR_DOCUMENT_EXPIRED, not a version mismatch: the event names the reason, so the reviewer is not sent to compare versions that already agree
- **PASS** `an-undated-evidence-row-cannot-be-fresh` — a claim with no observation date reports UNKNOWN freshness, so 'PQC ready' can never rest on a row nobody can date

## `reconciliation` — PASS

*when the vendor, the SBOM, the CBOM and the runtime disagree, does the VBOM pick a winner?* (review item 15)

- **PASS** `three-sources-that-disagree-stay-three-rows` — OpenSSL: vendor 3.0.13, SBOM 3.0.11, runtime 3.0.11 -> CONFLICT; every row is kept and the conflict is the finding
- **PASS** `a-source-capability-and-a-runtime-cipher-do-not-collapse` — CBOM says AES-256 is supported while the runtime exercised AES-128-GCM: both rows survive, the stronger source is named for triage, and neither overwrites the other
- **PASS** `agreement-single-source-and-silence-are-three-answers` — AGREE (two sources, same value), SINGLE_SOURCE (one source, not corroboration) and UNKNOWN (nobody stated it) are distinguished, because a single source is not corroboration
- **PASS** `a-less-specific-value-is-partial-not-a-contradiction` — vendor '3.0' against SBOM '3.0.11' is one source saying less, not two sources disagreeing — the difference between PARTIAL and CONFLICT is precision
- **PASS** `a-declared-row-and-an-observed-row-are-one-answer` — the vendor row and the observation row group into one CONFIRMED capability with both evidence ids attached, instead of two rows a reader has to reconcile by hand

## `vendor_risk` — PASS

*is a vendor risk rating explainable, or a colour somebody typed?* (review item 16)

- **PASS** `a-critical-rating-is-a-factor-list` — CRITICAL (100/100) from 11 named factors, each with points and a reason: product_lifecycle +25, pqc_capability +20, critical_systems_affected +15, crypto_dependency +15, …
- **PASS** `a-clean-vendor-scores-zero-and-says-why` — a current product with PQC, a verified deployment, an SBOM and supply-chain evidence scores LOW because no factor applies — the score is computed, not typed
- **PASS** `silence-scores-differently-from-a-refusal` — a vendor that states no PQC position scores 20 with the factor marked UNKNOWN; one that declares none scores 30
- **PASS** `the-same-inputs-produce-the-same-rating` — the score is a pure function of its factors: two runs with the same inputs are identical, so a rating can be reproduced in front of a regulator

## What this does not prove

- no vendor was contacted and no vendor document was parsed from PDF: the declarations here are fixtures shaped like the fields the review named, so the module is graded, not a vendor's paperwork
- applicability is computed from vendor, product, version and revision. A vendor that versions its crypto profile separately from its firmware version would need a second identity axis this model does not have
- a PATCH-level difference is PARTIAL_MATCH by design; whether the vendor's advisory says the crypto inventory changed inside a patch is a judgement this module hands to a reviewer rather than guessing
- freshness needs a date on the evidence. A questionnaire that arrives undated is UNKNOWN, which blocks a claim rather than ageing gracefully into a false green
- reconciliation compares string forms of a value. Two sources that name the same thing differently ('AES-256' and 'AES256') will conflict until a normaliser sits in front of it
- the dependency chains are assembled from records the bank supplies: appliance to application comes from configuration evidence, application to service from the service register, and neither is discovered by this module
- container counts come from the SBOM import, so a container that ships the component without naming it would be missed
- risk weights are this artifact's stated weights, visible in the module; a bank with its own risk framework can read the factors and reweight them without changing the evidence

## What is still missing, in the review's own order

1. **Vendor documents are fixtures.** Nothing here parses a vendor's PDF or questionnaire; the extraction step is `vendor_intel/docs_extract.py`, and a real procurement run needs a reviewer to confirm what was extracted.
2. **One identity axis.** Product/version/revision covers an appliance whose crypto profile follows its firmware. A vendor that versions the profile separately needs `profile_version` as a second axis, which is a schema change, not a parser tweak.
3. **Semantic algorithm matching.** Reconciliation is string-exact by design. An alias table (`AES256`, `RSA-3072`, `rsa3072`) belongs in front of it before this is pointed at real SBOMs.
4. **Runtime usage evidence.** `USAGE_OBSERVED` needs a session or a proxy that watches the call. Configurations prove intent; only runtime proves production use.
5. **Vendor→vendor chains.** A cryptography SDK that embeds a second vendor's library is a sub-vendor edge this model does not carry yet.

## How to run it

```bash
python scripts/vendor_evidence.py --as-of 2026-11-02 \
--json docs/bank-environment/130-vendor-evidence-and-vbom.json \
--md docs/bank-environment/130-vendor-evidence-and-vbom.md
python scripts/vendor_evidence.py --check    # non-zero when a row is not PASS
```

