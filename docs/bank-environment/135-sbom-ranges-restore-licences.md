# Three gaps, closed by measurement

`cryptoscan.sbom-gaps-guide/1` · generated 2026-11-02T16:54:52.207446+00:00 · as of 2026-11-02 · **5 pass · 0 partial · 0 fail** · 33 probes

Guide 134 ended with a list of things it had not proven. Three of those entries are now code, and this artifact is where they are measured:

1. **Advisory ranges.** Matching was exact-string equality, so an advisory that says `<3.0.13` or `^5.0.0` never applied. `devsecops/version_ranges.py` implements ordering per ecosystem and the constraint syntax feeds carry; a range it cannot read is `UNKNOWN`, never "assessed and clean".
2. **Restore.** A backup nobody restored is a hope. `backup_artifact` reads its own copy back, and `restore_drill` restores into a *fresh* store and verifies byte identity, the manifest digest, the signature, and that one flipped byte is caught.
3. **Licence states.** The review's seven values are now produced per component, so "declared" can never render as "approved" and the summary says how many nobody has reviewed.

The comparator is exercised by 12 ordering cases and 22 constraint cases, including the ones the previous "split on dots" comparator got backwards.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `version_ordering` | is 1.0.0-rc1 older than 1.0.0, in every ecosystem? | **PASS** | 4, 0 failing |
| `constraint_syntax` | can the platform read the ranges a feed actually writes? | **PASS** | 4, 0 failing |
| `advisory_matching` | does an advisory range apply, or only an exact version string? | **PASS** | 9, 0 failing |
| `restore_drill` | has a restore ever actually been run, or only configured? | **PASS** | 8, 0 failing |
| `license_states` | does the licence report ever render a detection as an approval? | **PASS** | 8, 0 failing |

## `version_ordering` — PASS

*is 1.0.0-rc1 older than 1.0.0, in every ecosystem?* (review item 10 (range depth))

- **PASS** `the-ordering-the-old-comparator-got-backwards` — 12 ordering case(s) hold, including a release candidate before its release and a dev release before its prereleases
- **PASS** `each-ecosystem-gets-its-own-comparator` — npm→semver, pip→pep440, maven→maven, nuget→generic, gem→generic, composer→semver, cargo→semver, debian→generic
- **PASS** `an-unreadable-version-raises-instead-of-sorting-arbitrarily` — 'not-a-version' is not a semantic version
- **PASS** `the-platform-has-one-comparator` — container_scan.version_compare delegates to version_ranges: the container matcher and the SBOM matcher share one engine, and the ecosystem decides whether 1.0.0-rc1 is a prerelease (npm) or a package revision (Debian)

## `constraint_syntax` — PASS

*can the platform read the ranges a feed actually writes?* (review item 10 (range depth))

- **PASS** `the-constraint-syntax-advisory-feeds-carry` — 22 constraint case(s) hold across caret, tilde, x-range, comparator sets, PEP 440 compatible release, Maven intervals, unions and exact pins
- **PASS** `an-unreadable-constraint-is-invalid-not-empty` — INVALID: 'bogus.1' is not a semantic version
- **PASS** `a-constraint-explains-itself` — ^1.2.3 (npm) decomposes to [('>=', '1.2.3'), ('<', '2')]
- **PASS** `one-unreadable-range-does-not-hide-a-match` — matched on the readable range and kept ['>=bogus'] as unevaluable

## `advisory_matching` — PASS

*does an advisory range apply, or only an exact version string?* (review item 10)

- **PASS** `an-exact-version-list-still-matches` — MATCHED via purl+version
- **PASS** `a-comparator-range-matches-the-version-inside-it` — MATCHED via purl+range: 1 advisory match(es): CVE-2
- **PASS** `a-version-outside-the-range-is-a-real-non-match` — ASSESSED_NO_MATCH: assessed against osv 2026-11-01 with purl+version matching and nothing matched
- **PASS** `a-caret-is-read-the-way-npm-reads-it` — jose 5.2.3 in ^5.0.0 -> MATCHED (comparator semver)
- **PASS** `the-purl-decides-which-comparator-applies` — pypi component compared with the PEP 440 comparator (pep440)
- **PASS** `a-prerelease-is-not-inside-a-range-that-starts-at-the-release` — 2.0.0-rc1 against >=2.0.0 -> ASSESSED_NO_MATCH: the old comparator would have matched this
- **PASS** `an-introduced-fixed-window-is-understood` — MATCHED: the container scanner's advisory shape is read by the same engine
- **PASS** `an-advisory-range-nobody-can-read-is-unknown` — UNKNOWN rather than a clean result: 1 advisory range(s) could not be interpreted for generic: >=three: 'three' contains no version numbers
- **PASS** `a-clean-answer-still-carries-the-feed-and-the-method` — ASSESSED_NO_MATCH against osv 2026-11-01 by purl+range

## `restore_drill` — PASS

*has a restore ever actually been run, or only configured?* (review item 8)

- **PASS** `a-backup-is-read-back-and-compared` — 534 byte(s) copied to the backup store and read back identical
- **PASS** `the-drill-restores-into-a-fresh-store-not-the-primary` — restored 534 byte(s) from the backup into a fresh store; bytes identical, digest MATCH, signature VALID, a flipped byte was detected
- **PASS** `the-restored-artifact-still-verifies` — digest MATCH, signature VALID — a restore that only checks presence would pass a corrupted file
- **PASS** `a-flipped-byte-is-caught-so-the-check-is-not-a-rubber-stamp` — one byte of the restored artifact was inverted and verification returned TAMPERED
- **PASS** `without-a-secret-the-signature-check-is-reported-as-absent` — no secret supplied -> signature_check null rather than an invented VALID
- **PASS** `a-corrupted-backup-fails-the-drill` — a backup whose bytes were altered -> FAILED (digest MISMATCH)
- **PASS** `the-drill-runs-over-every-artifact` — 1 of 1 artifact(s) restored and verified
- **PASS** `an-empty-backup-proves-nothing-and-says-so` — the backup store holds no artifacts, so the drill proves nothing

## `license_states` — PASS

*does the licence report ever render a detection as an approval?* (review item 12)

- **PASS** `a-declared-licence-is-not-an-approval` — openssl declares Apache-2.0 -> DECLARED: nothing has reviewed it
- **PASS** `only-a-policy-decision-produces-accepted-or-rejected` — MIT on the allowed list -> POLICY_ACCEPTED; GPL-3.0 forbidden -> POLICY_REJECTED
- **PASS** `a-component-with-no-licence-is-unknown` — no declaration, no detection -> UNKNOWN
- **PASS** `declaration-and-detection-disagreeing-is-a-conflict` — declared Apache-2.0, detected GPL-3.0-only -> CONFLICT
- **PASS** `a-detection-without-a-declaration-is-DETECTED-not-approved` — document silent, detector found MIT -> DETECTED
- **PASS** `the-vocabulary-is-the-reviews-seven-states` — DECLARED, DETECTED, UNKNOWN, CONFLICT, POLICY_ACCEPTED, POLICY_REJECTED, REQUIRES_REVIEW
- **PASS** `the-summary-says-how-many-nobody-reviewed` — 4 component(s): 1 approved by policy, 1 rejected, 0 awaiting review, 1 declared but unreviewed, 1 unknown — a declaration is not an approval, and this list is not legal advice
- **PASS** `the-licence-endpoint-returns-the-states` — /sbom/license returns `states`, `state_rows` and `state_statement` beside the policy verdict

## What this does not prove

- the comparator is a library, not a package manager: it does not resolve dependency graphs and it cannot know that a vendor's build rewrote a version string before it was recorded
- advisory matching is still against a supplied feed. Which advisory is true for a given build is the feed vendor's claim, not the platform's
- the restore drill runs against the configured artifact store. It proves the backup target holds a restorable copy; it does not prove the backup is in a different failure domain (that is an operational control, not code)
- licence states are a vocabulary and a policy lookup. Which licences a bank accepts remains a legal decision this code must not make
- the seven licence states are reported per component; obligations that depend on distribution model (SaaS versus shipped binary) are outside this artefact

## How to run it

```bash
python scripts/sbom_gaps.py --as-of 2026-11-02 \
--json docs/bank-environment/135-sbom-ranges-restore-licences.json \
--md docs/bank-environment/135-sbom-ranges-restore-licences.md
python scripts/sbom_gaps.py --check   # non-zero on FAIL or PARTIAL
```

