# The gate stops believing the document

`cryptoscan.sbom-gate-evidence-guide/1` · generated 2026-11-02T17:19:43.039470+00:00 · as of 2026-11-02 · **5 pass · 0 partial · 0 fail** · 26 probes

Guide 136 closed the durability, archive and licence gaps. What it left, and what this artifact measures, is the part where the platform still took a document's word:

1. **The gate counted CVEs in the document.** A feed in, six states out, and the verdict decided on what was *assessed* — with the document's own count reported beside it, so neither number can be quoted alone.
2. **VEX was advisory.** Every statement is re-validated when the gate runs: a lapsed or unjustified `NOT_AFFECTED` suppresses nothing and the finding returns with the reason.
3. **A signature named itself.** The manifest now records algorithm, key id, version, status, trust anchor, signed and verified times, revocation, and the three claims the ladder supports — and a revoked key refuses to sign.
4. **Nothing said what produced the artifact.** Commit, build, builder, pipeline and digest are recorded with every missing link named.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `gate_evidence` | does the gate pass a component nobody ever assessed? | **PASS** | 6, 0 failing |
| `vex_suppression` | can an expired or unjustified VEX still hide a critical finding? | **PASS** | 5, 0 failing |
| `signature_evidence` | does a stored signature say what it actually proves? | **PASS** | 5, 0 failing |
| `build_provenance` | can the artifact say what produced it, and what is missing? | **PASS** | 5, 0 failing |
| `api_exposure` | can a caller reach these answers through the API? | **PASS** | 5, 0 failing |

## `gate_evidence` — PASS

*does the gate pass a component nobody ever assessed?* (review item 10)

- **PASS** `a-document-with-no-cve-entries-is-not-an-assessment` — no vulnerability feed was consulted: the document's own entries are the only thing counted, and an absent entry is not an all-clear
- **PASS** `the-same-document-fails-when-a-feed-is-consulted` — 1 assessed critical finding(s) remain open (allowed: 0)
- **PASS** `the-document-count-and-the-assessed-count-are-both-reported` — 0 document entr(ies), 1 assessed open
- **PASS** `a-stale-feed-is-not-an-all-clear` — 0 of 1 component(s) assessed; 0 open finding(s) (0 critical, 0 high), 0 suppressed by a current VEX statement, 0 whose VEX statement lapsed or is invalid
- **PASS** `a-policy-can-make-unassessed-a-blocker` — 1 of 1 component(s) have no vulnerability posture from a current feed — not assessed is not clean
- **PASS** `the-documents-own-claim-still-counts-without-a-feed` — 1 document entry gated

## `vex_suppression` — PASS

*can an expired or unjustified VEX still hide a critical finding?* (review item 11)

- **PASS** `a-current-justified-statement-suppresses-the-finding` — 1 of 1 component(s) assessed; 0 open finding(s) (0 critical, 0 high), 1 suppressed by a current VEX statement, 0 whose VEX statement lapsed or is invalid
- **PASS** `a-lapsed-statement-suppresses-nothing-and-says-why` — EXPIRED
- **PASS** `free-text-is-not-a-justification` — NOT_AFFECTED needs a justification from the closed list (VULNERABLE_CODE_NOT_PRESENT, VULNERABLE_CODE_NOT_IN_EXECUTE_PATH, …); free text is not a justification
- **PASS** `an-unreviewed-statement-is-not-a-statement` — INVALID
- **PASS** `a-statement-about-another-component-suppresses-nothing` — the finding stayed open: a VEX statement is scoped to one component

## `signature_evidence` — PASS

*does a stored signature say what it actually proves?* (review item 9)

- **PASS** `the-manifest-records-the-signing-identity` — HMAC-SHA256 key hmac-2026-11 v3 (ACTIVE), anchor bank-kms:sbom-signing
- **PASS** `hmac-claims-authenticity-and-not-non-repudiation` — signed and verified: AUTHENTIC: tenants/platform/78a9003e-2083-4c1a-94e8-d4a18f7b4183.cdx.json — integrity yes, authenticity yes, non-repudiation no
- **PASS** `the-evidence-block-is-covered-by-the-signature` — the manifest is signed after the evidence block is written, so editing it breaks the HMAC
- **PASS** `a-revoked-key-refuses-to-sign` — a revoked key stops producing signatures instead of writing one a verifier must discount
- **PASS** `an-unsigned-artifact-says-so` — UNSIGNED: the digest may be intact and nothing vouches for it

## `build_provenance` — PASS

*can the artifact say what produced it, and what is missing?* (review item 7)

- **PASS** `the-manifest-records-commit-build-digest-and-sbom` — build BUILD-2026-1102-0091 from 9f2c1ab4d7 produced sha256:aaaaaaaaaaaa…; never observed running, so provenance stops at the artifact
- **PASS** `a-chain-without-an-observation-is-not-called-complete` — complete also requires an observation: provenance stops at the artifact
- **PASS** `the-missing-links-are-named-not-omitted` — 2 gap(s): source_commit is not a commit hash, so the build cannot be traced to a tree
- **PASS** `a-build-that-names-no-artifact-digest-says-so` — 2 gap(s): the build names no artifact digest
- **PASS** `a-scan-with-no-build-supplied-does-not-invent-one` — no commit, no build id and no provenance block: the manifest says nothing rather than something that looks auditable

## `api_exposure` — PASS

*can a caller reach these answers through the API?* (review item 10 / 9 / 7)

- **PASS** `the-gate-route-accepts-a-feed-and-vex-statements` — /sbom/{artifact_id}/gate takes `feed`, `advisories`, `vex` and `as_of`
- **PASS** `the-gate-uses-the-assessment-not-only-the-document` — the gate blocks on assessed critical findings and reports the document count beside them
- **PASS** `the-verify-route-returns-the-signature-evidence` — /sbom/{artifact_id}/verify answers which claims the signature supports
- **PASS** `both-scan-routes-record-the-build-identity` — a commit supplied to /sbom/scan or /binary/scan reaches the manifest
- **PASS** `no-new-untyped-route-was-added` — the untyped-response inventory is untouched by this change

## What this does not prove

- the gate's assessment is only as good as the feed handed to it: which advisory is true for a build is the feed vendor's claim, and this code carries it rather than deciding it
- VEX is re-validated at evaluation time, not at authoring time. A statement that was valid when written and has since lapsed still suppresses nothing, but a statement with a wrong justification is only caught if it is outside the closed list
- the signature ladder reports what an HMAC can claim, and HMAC can never claim non-repudiation. Moving to Ed25519/ECDSA is a key-management change this code supports but does not perform
- key status and trust anchor are configuration: the platform cannot know that a key was revoked until an operator says so, and it cannot verify an anchor it was told to trust
- build provenance records what a caller supplied. A CI system that lies about its commit produces a complete-looking chain, which is why the manifest also carries the signature evidence over it
- the unassessed count is a statement about components, not about reachability: a component can be assessed, matched and still not be exploitable in this deployment
