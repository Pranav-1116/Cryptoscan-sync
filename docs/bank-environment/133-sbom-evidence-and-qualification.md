# SBOM evidence: a qualification matrix that runs, and a chain that ends in a pod

`cryptoscan.sbom-evidence-guide/1` · generated 2026-11-02T16:21:14.130132+00:00 · as of 2026-11-02 · **10 pass · 0 partial · 0 fail**

The review beside this file lists nineteen items. Its sharpest observation is that *recognised filename ≠ complete compatibility with every format revision* — so this artifact starts by running the parsers instead of describing them — and it found three real defects on the first attempt.

## The parser qualification matrix (item 3)

`cryptoscan.sbom-parser-qualification/1` · **15 pass · 0 partial · 0 need a fix** · qualified: **True**

15 of 15 parser case(s) pass; 0 are partial and 0 need a fix. Every ecosystem the review listed is production-qualified against the revisions exercised here.

| Ecosystem | Manifest | Lockfile | Revisions exercised | Verdict |
|---|---|---|---|---|
| dotnet | App.csproj | packages.lock.json | csproj PackageReference; NuGet lock file v1 | **PASS** |
| go | go.mod | go.sum | go modules | **PASS** |
| maven | pom.xml | — | pom.xml | **PASS** |
| npm | package.json | package-lock.json | lockfileVersion 1; lockfileVersion 2; lockfileVersion 3; manifest only | **PASS** |
| php | composer.json | composer.lock | composer lock | **PASS** |
| python | Pipfile, pyproject.toml, requirements.txt | Pipfile.lock, poetry.lock | pip requirements; poetry lock; pipenv lock v2 | **PASS** |
| ruby | Gemfile | Gemfile.lock | bundler lock | **PASS** |
| rust | Cargo.toml | Cargo.lock | Cargo.lock v1 (no version field); Cargo.lock v2 (version = 3 header) | **PASS** |

### Every case, with what it proved

| Case | Revision | Verdict | Result |
|---|---|---|---|
| `npm_lockfile_v1` | lockfileVersion 1 | **PASS** | 2 expected component(s) found from package-lock.json with scope resolved |
| `npm_lockfile_v2` | lockfileVersion 2 | **PASS** | 2 expected component(s) found from package-lock.json with scope resolved |
| `npm_lockfile_v3` | lockfileVersion 3 | **PASS** | 2 expected component(s) found from package-lock.json with scope resolved |
| `npm_declared_range_is_not_a_version` | manifest only | **PASS** | 1 expected component(s) found from the manifest with scope declared |
| `python_requirements` | pip requirements | **PASS** | 1 expected component(s) found from the manifest with scope declared |
| `python_poetry_lock` | poetry lock | **PASS** | 1 expected component(s) found from poetry.lock with scope resolved |
| `python_pipfile_lock` | pipenv lock v2 | **PASS** | 1 expected component(s) found from Pipfile.lock with scope resolved |
| `maven_pom` | pom.xml | **PASS** | 1 expected component(s) found from the manifest with scope declared |
| `go_mod_and_sum` | go modules | **PASS** | 1 expected component(s) found from go.sum with scope resolved |
| `rust_cargo_lock_v1` | Cargo.lock v1 (no version field) | **PASS** | 1 expected component(s) found from Cargo.lock with scope resolved |
| `rust_cargo_lock_v2` | Cargo.lock v2 (version = 3 header) | **PASS** | 1 expected component(s) found from Cargo.lock with scope resolved |
| `dotnet_csproj` | csproj PackageReference | **PASS** | 1 expected component(s) found from the manifest with scope declared |
| `dotnet_packages_lock` | NuGet lock file v1 | **PASS** | 1 expected component(s) found from packages.lock.json with scope resolved |
| `ruby_gemfile_lock` | bundler lock | **PASS** | 1 expected component(s) found from Gemfile.lock with scope resolved |
| `php_composer_lock` | composer lock | **PASS** | 1 expected component(s) found from composer.lock with scope resolved |

Three defects were found and fixed in this commit:

1. **`.csproj` was never dispatched.** `_parse_manifest` looked the parser up by exact filename, and the `.NET` parser was registered under the key `csproj`, which no filename equals — so a project file with two `PackageReference` entries produced an empty SBOM that looked perfectly valid. Parsers registered under an extension now dispatch by suffix.
2. **An npm range was silently pinned.** `jose: "^5.0.0"` was read as version `5.0.0` with the caret discarded, which is exactly the confusion review item 2 says the SBOM must keep visible. The reader now carries `raw_spec` verbatim and a `version_constraint` (`EXACT`, `RANGE`, `ANY`, `NON_VERSION`), so `git+https://…` no longer lands in a version field at all.
3. **`pyproject.toml` and `Pipfile` were never read as manifests.** Poetry and pipenv projects whose only declaration is `pyproject.toml` produced a *valid-looking empty SBOM*: the file was recognised (the lockfile readers used it to attribute direct dependencies) but no reader ever produced a component from it, so "no dependencies" and "dependencies we cannot see" were the same answer. Both files now have manifest readers, covering PEP 621 `[project]` dependencies, `[project.optional-dependencies]` extras, Poetry groups, and Pipfile `[packages]`/`[dev-packages]`, with markers and extras stripped and the specifier preserved.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `parser_qualification` | which ecosystem and lockfile generation is actually production-qualified? | **PASS** | 7, 0 failing |
| `deployment_identity` | does a component in an SBOM become 'deployed', or only 'described'? | **PASS** | 7, 0 failing |
| `build_provenance` | can the running pod be traced back to a commit and a build record? | **PASS** | 6, 0 failing |
| `storage_durability` | can production evidence quietly land in a temporary directory? | **PASS** | 4, 0 failing |
| `signing_ladder` | which of integrity, authenticity and non-repudiation does a signature actually support? | **PASS** | 9, 0 failing |
| `vulnerability_status` | does '0 vulnerabilities' mean clean, or that nobody looked? | **PASS** | 7, 0 failing |
| `vex_and_licence` | does a VEX statement expire and name an owner, and is a detected licence ever mistaken for an approval? | **PASS** | 8, 0 failing |
| `crypto_promotion` | does a crypto-capable component become 'used' without evidence? | **PASS** | 6, 0 failing |
| `history_and_diff` | does a diff say what changed, or what it means? | **PASS** | 5, 0 failing |
| `input_safety` | can an imported SBOM or a hostile document change the estate? | **PASS** | 6, 0 failing |

## `parser_qualification` — PASS

*which ecosystem and lockfile generation is actually production-qualified?* (review item 3)

- **PASS** `every-case-is-executed-not-asserted` — 15 case(s) written to disk and scanned by `scan_source`; 15 pass, 0 partial, 0 need a fix
- **PASS** `a-pyproject-only-project-is-not-an-empty-sbom` — pyproject.toml alone (PEP 621 + poetry group) -> ['bandit', 'cryptography', 'requests']; before this reader existed the same tree yielded zero components, indistinguishable from a project with no dependencies
- **PASS** `csproj-dispatch-reaches-the-parser` — App.csproj -> ['bouncycastle.cryptography', 'newtonsoft.json']; before this fix the same file produced no package at all because the parser was keyed 'csproj' and looked up by filename
- **PASS** `a-caret-survives-the-manifest-reader` — jose ^5.0.0 carried as RANGE, so a range cannot be read as a pin
- **PASS** `the-lockfile-generations-are-exercised-separately` — 11 revision(s) exercised, Cargo.lock v1 (no version field), Cargo.lock v2 (version = 3 header), NuGet lock file v1, bundler lock, composer lock, go modules, …
- **PASS** `an-ecosystem-with-one-bad-case-is-not-qualified` — 8 ecosystem(s) scored; qualified=True — one FIX anywhere would flip that to False, which is the point of a matrix
- **PASS** `the-matrix-is-an-artifact-not-a-unit-test` — 15 of 15 parser case(s) pass; 0 are partial and 0 need a fix. Every ecosystem the review listed is production-qualified against the revisions exercised here.

## `deployment_identity` — PASS

*does a component in an SBOM become 'deployed', or only 'described'?* (review item 5/6)

- **PASS** `a-component-in-a-sbom-bound-to-a-digest-and-observed-is-in-production` — openssl 3.0.13 is present in payments-api-prod (PRODUCTION) — cited to OBS-2026-1102-01
- **PASS** `an-uploaded-document-is-not-a-deployment` — the same component in a document bound to no digest -> PRESENT_IN_SBOM_ONLY: the review's 'exists somewhere in an uploaded SBOM'
- **PASS** `a-digest-nobody-observed-running-is-not-deployed` — bound digest, no observation -> PRESENT_IN_ARTIFACT
- **PASS** `a-mutable-tag-is-refused-as-identity` — `payments-api:latest` is refused outright rather than flagged, because a tag is a pointer and evidence needs an address
- **PASS** `a-digest-qualified-reference-parses-into-an-identity` — ghcr.io/bank/payments-api@sha256:aaaaaaaaaaaa… parsed as an immutable identity
- **PASS** `a-pinned-reference-that-contradicts-its-record-is-refused` — the reference pins sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb and the r
- **PASS** `a-component-that-is-not-in-the-sbom-is-a-different-answer` — an absent component is NOT_IN_SBOM: a statement about the inventory, not about the estate

## `build_provenance` — PASS

*can the running pod be traced back to a commit and a build record?* (review item 7)

- **PASS** `the-chain-runs-from-commit-to-running-pod` — build BUILD-2026-1102-0091 from 9f2c1ab4d7 produced sha256:aaaaaaaaaaaa…; observed running in PRODUCTION
- **PASS** `a-build-with-no-record-has-every-gap-named` — 4 gap(s): build_id is empty; … no SBOM is bound to this build, or the bound SBOM is a different one
- **PASS** `an-unattributable-commit-breaks-the-chain` — source_commit is not a commit hash, so the build cannot be traced to a tree
- **PASS** `a-sbom-of-a-different-artifact-is-not-this-builds-sbom` — the SBOM describes a different artifact than the build produced
- **PASS** `a-sbom-that-predates-the-build-is-refused` — the SBOM predates the build it is attached to
- **PASS** `provenance-without-an-observation-stops-at-the-artifact` — build BUILD-2026-1102-0091 from 9f2c1ab4d7 produced sha256:aaaaaaaaaaaa…; never observed running, so provenance stops at the artifact

## `storage_durability` — PASS

*can production evidence quietly land in a temporary directory?* (review item 8)

- **PASS** `production-with-no-store-is-refused-not-degraded` — PRODUCTION with SBOM_STORAGE_DIR unset -> REFUSE: no artifact store is configured, and falling back to temporary storage would leave evidence for a production run with no durable home
- **PASS** `a-durable-store-without-backup-retention-or-integrity-is-still-refused` — 3 refusal(s): no backup target is configured, so a restore cannot be demonstrated
- **PASS** `a-configured-durable-store-with-dr-and-retention-passes` — production evidence storage is configured and durable
- **PASS** `ephemeral-storage-is-allowed-only-where-the-record-does-not-depend-on-it` — dev -> ALLOW (EPHEMERAL_OK); the same call in PRODUCTION is REFUSE

## `signing_ladder` — PASS

*which of integrity, authenticity and non-repudiation does a signature actually support?* (review item 9)

- **PASS** `a-hash-gives-integrity-and-nothing-else` — SHA-256 -> integrity yes, authenticity no: a digest proves the bytes did not change, not who produced them
- **PASS** `hmac-gives-authenticity-within-a-shared-secret` — HMAC-SHA256 -> authenticity yes, non-repudiation no: anyone holding the key could have signed it
- **PASS** `an-anchored-asymmetric-key-earns-non-repudiation` — NON_REPUDIABLE: SBOM-9182 — integrity yes, authenticity yes, non-repudiation yes
- **PASS** `an-unanchored-key-proves-possession-not-identity` — key ed-unknown is not anchored to a trust anchor this verifier knows (['bank-root-ca']), so the signature proves possession rather than identity
- **PASS** `a-revoked-key-invalidates-everything-it-signed` — REVOKED_KEY: SBOM-9182 is signed by a revoked key
- **PASS** `rotation-keeps-an-old-signature-valid-and-says-so` — NON_REPUDIABLE: SBOM-9182 — integrity yes, authenticity yes, non-repudiation yes; the key was rotated to ed-2026 after signing, and the signature remains valid for its signing date
- **PASS** `an-expired-key-fails-even-when-it-is-anchored` — EXPIRED_KEY: SBOM-9182 is signed by an expired key
- **PASS** `no-signature-is-its-own-verdict` — UNSIGNED: the digest may be intact and nothing vouches for it
- **PASS** `an-unknown-algorithm-cannot-be-treated-as-a-signature` — 'ROT13' is not an algorithm this verifier knows; an unknown algorithm cannot be treated as

## `vulnerability_status` — PASS

*does '0 vulnerabilities' mean clean, or that nobody looked?* (review item 10)

- **PASS** `a-match-carries-the-feed-the-method-and-the-advisory` — MATCHED against osv 2026-11-01 by purl+version: 1 advisory match(es): CVE-2024-6119
- **PASS** `zero-matches-is-assessed-and-says-so` — ASSESSED_NO_MATCH: assessed against osv 2026-11-01 with purl+version matching and nothing matched
- **PASS** `zero-matches-from-a-stale-feed-is-not-an-all-clear` — STALE_FEED: the feed is 62 days old (limit 7); a zero-match result from a stale feed is not an all-clear
- **PASS** `a-component-with-no-identifier-cannot-be-matched` — the component has no purl, so a version-range match would be a guess against a name
- **PASS** `no-feed-is-not-assessed-rather-than-clean` — no vulnerability feed was consulted, so this component has no vulnerability posture — which is not the same as having none
- **PASS** `a-feed-that-cannot-be-dated-yields-unknown` — the feed states no update time, so its currency cannot be established
- **PASS** `the-vocabulary-is-closed-and-six-state` — NOT_ASSESSED, ASSESSED_NO_MATCH, MATCHED, UNKNOWN, STALE_FEED, INSUFFICIENT_IDENTIFIER

## `vex_and_licence` — PASS

*does a VEX statement expire and name an owner, and is a detected licence ever mistaken for an approval?* (review item 11/12)

- **PASS** `a-vex-statement-names-a-reviewer-a-reason-and-an-expiry` — CURRENT: CVE-2024-6119 on openssl is NOT_AFFECTED until 2027-01-01
- **PASS** `an-expired-vex-statement-stops-suppressing-the-finding` — EXPIRED: the NOT_AFFECTED assessment for CVE-2024-6119 on openssl lapsed on 2026-01-01 and no longer suppresses the finding
- **PASS** `free-text-is-not-a-justification` — 3 problem(s): NOT_AFFECTED needs a justification from the closed list (VULNERABLE_CODE_NOT_PRESENT, VULNERABLE_CODE_NOT_IN_EXECUTE_PATH, …); free text is not a justification
- **PASS** `a-statement-cannot-expire-before-it-was-made` — the statement expires before it was assessed
- **PASS** `a-detected-licence-is-not-an-approval` — declared and detected Apache-2.0 -> REQUIRES_REVIEW: Apache-2.0 is known and no policy decision exists for it; the scanner reports, it does not approve
- **PASS** `a-declared-and-detected-conflict-is-its-own-state` — the package declares MIT and the scanner detected GPL-3.0; neither is a decision, and the difference is a question for legal
- **PASS** `only-a-policy-decision-produces-accepted-or-rejected` — MIT -> POLICY_ACCEPTED, GPL-3.0 -> POLICY_REJECTED, both from a policy and neither from a scanner
- **PASS** `no-licence-is-unknown-not-permissive` — no licence was declared or detected, so nothing can be accepted

## `crypto_promotion` — PASS

*does a crypto-capable component become 'used' without evidence?* (review item 13)

- **PASS** `an-inventory-row-starts-at-capability-and-says-so` — openssl 3.0.13 is inventoried as crypto-capable. That is a capability claim about a package, not a statement that any application uses it
- **PASS** `static-evidence-raises-the-rung-by-one` — openssl: static evidence shows the code path calls AES-256-GCM; still not a statement about traffic
- **PASS** `a-skipped-rung-stops-the-ladder` — STATIC_OBSERVED has no evidence while RUNTIME_OBSERVED does: the ladder cannot skip a rung, so the candidate stops at CAPABILITY until STATIC_OBSERVED is evidenced
- **PASS** `the-ladder-reaches-network-with-four-kinds-of-evidence` — STATIC_OBSERVED -> RUNTIME_OBSERVED -> NETWORK_OBSERVED; openssl: network evidence shows TLS_AES_256_GCM_SHA384 on the wire
- **PASS** `every-rung-cites-what-it-came-from` — SBOM; file:src/tls/conn.go#L142; session:S-1; pcap:payments-api-2026-11-02#42
- **PASS** `an-observation-outside-the-ladder-is-refused` — 'OBSERVED' is not a rung on the promotion ladder; expected one of ('CAPABILITY', 'STATIC_OBSERVED', 

## `history_and_diff` — PASS

*does a diff say what changed, or what it means?* (review item 15/16)

- **PASS** `every-kind-of-movement-is-named` — 5 change(s): ARTIFACT_CHANGED, DEPENDENCY_CHANGED, PACKAGE_ADDED, PACKAGE_REMOVED, VERSION_CHANGED
- **PASS** `a-version-bump-does-not-decide-its-own-crypto-impact` — 3 change(s) with crypto_impact UNKNOWN because nothing observed the new version: the alternative is a diff that reads like a conclusion
- **PASS** `a-change-carries-the-artifact-release-and-deployment-it-happened-to` — openssl 3.0.11 -> 3.0.13 on ghcr.io/bank/payments-api release BUILD-2026-1102-0091 in ['PRODUCTION']
- **PASS** `observed-runtime-and-network-evidence-close-the-question` — with runtime and network evidence the same change reads RUNTIME_EVIDENCE_PRESENT / OBSERVED / OBSERVED
- **PASS** `the-diff-itself-carries-an-evidence-id` — DIF-322ecf17ee2b — recomputable from the change set, so two runs over the same snapshots are the same finding

## `input_safety` — PASS

*can an imported SBOM or a hostile document change the estate?* (review item 17)

- **PASS** `an-import-may-not-overwrite-an-observed-fact` — the imported document would replace deployment_identity='payments-api-prod' with 'attacker-prod'; an imported SBOM is untrusted input and may not overwrite an observed fact
- **PASS** `an-accepted-import-is-labelled-untrusted-and-cannot-override` — 1 row(s) marked IMPORTED with a content hash 931e4a2b18cd…, may_override False
- **PASS** `a-deep-graph-hits-the-depth-limit` — dependency depth 201 exceeds the 64 limit
- **PASS** `a-cyclic-graph-is-refused-rather-than-recursed` — 1 cycle(s) found iteratively, so a hostile graph cannot exhaust the stack before it reaches the limit
- **PASS** `a-hundred-megabyte-file-is-refused-by-its-size` — 104857600 bytes exceeds the 8000000-byte limit
- **PASS** `an-ordinary-document-passes-the-budget` — 2 component(s), depth 2, no cycles — inside the budget

## What this does not prove

- the parser matrix runs the readers this repository has, against files this repository generates. A bank's exporter will produce shapes nobody wrote a case for, and the honest answer then is an unqualified ecosystem, not a guess
- the qualification cases are small files. They prove the readers parse the shape; they do not prove throughput against a 50,000-component real SBOM
- deployment observations are supplied by the platform integration. The chain is graded here; producing the observation from Kubernetes needs a cluster
- the signing ladder verifies the claims a key algorithm can support. Key custody, HSM-backed signing and certificate chain validation are outside this module
- licence states are a vocabulary and a policy lookup. Which licences a bank accepts is a legal decision this code must not make
- the promotion ladder requires evidence of each rung. Producing static, runtime and network evidence at bank scale needs the collectors named in guides 130-132

## What is still missing, in the review's order

1. **Deployment correlation needs a cluster.** The chain is graded; the observation that feeds it comes from a Kubernetes or agent integration that is not in this artifact.
2. **Binary and container format breadth.** The readers here are source-ecosystem readers; binary/firmware and archive formats need their own qualification matrix.
3. **HA/DR for the artifact store.** The policy refuses unsafe production storage; proving a restore works is an operational drill, not a unit test.
4. **Vulnerability feed depth.** Matching is purl+version against a supplied advisory set; range parsing per ecosystem (npm semver, PEP 440, Maven ranges) is the next step, and until then `INSUFFICIENT_IDENTIFIER` is the honest answer more often than a bank will like.
5. **SBOM to Digital Twin edges.** Every edge in this artifact carries an evidence id; wiring those edges into the twin's graph is the integration that still has to land.

## How to run it

```bash
python scripts/sbom_evidence.py --as-of 2026-11-02 \
--json docs/bank-environment/133-sbom-evidence-and-qualification.json \
--md docs/bank-environment/133-sbom-evidence-and-qualification.md
python scripts/sbom_evidence.py --check   # non-zero on FAIL or PARTIAL
```

