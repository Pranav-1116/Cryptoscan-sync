# Process-level runtime tracing: the chain is the evidence

`cryptoscan.cbom-process-tracing-guide/1` · generated 2026-11-02T18:20:46.898356+00:00 · **5 pass · 0 partial · 0 fail** · 24 probes

The review's item 7, and the chain it asks for is the whole point:

```
payments-api -> PID 9182 -> OpenSSL 3.0.13 -> EVP_EncryptInit_ex
             -> AES-256-GCM (key_size=256, mode=GCM)
             -> 2026-11-02 10:42:11 -> RUNTIME-92821
```

`cbom.process_tracing` keeps every link:

1. **A partial chain is a claim.** Missing application, pid, operation, algorithm, evidence id or timestamp → refused, with the missing link named.
2. **The provider version is data, not decoration.** `OpenSSL` without a version is kept and marked uncomparable, because "which version" is the whole question.
3. **Correlation reports, never resolves.** SBOM 3.0.11 against runtime 3.0.13 is a `VERSION_MISMATCH` with both evidence ids; `RUNTIME_ONLY` and `SBOM_ONLY` are named separately.
4. **The asset is runtime-confirmed** and carries the chain in `cryptoscan:` properties — and writes no quantum verdict, because that belongs to the PQC handoff.
5. **The twin gets the chain as edges**, each `RUNTIME_OBSERVED` with its evidence id, plus the direct application → algorithm shortcut.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_chain` | is a runtime trace the whole chain, or a claim about one? | **PASS** | 5, 0 failing |
| `the_provider` | does the tracer separate 'OpenSSL' from 'OpenSSL 3.0.13'? | **PASS** | 4, 0 failing |
| `correlation` | does the twin say which provider version the process loaded? | **PASS** | 5, 0 failing |
| `the_asset` | does a runtime observation become a runtime-confirmed asset? | **PASS** | 5, 0 failing |
| `the_twin` | does the chain reach the digital twin as evidenced relationships? | **PASS** | 5, 0 failing |

## `the_chain` — PASS

*is a runtime trace the whole chain, or a claim about one?* (review 7)

- **PASS** `the-review-chain-is-kept-whole` — application:payments-api → process:payments-api/9182 → provider:OpenSSL@3.0.13 → operation:EVP_EncryptInit_ex → algorithm:AES-256-GCM
- **PASS** `the-parameters-survive-the-chain` — {"key_size": 256, "mode": "GCM"}
- **PASS** `a-trace-without-a-process-is-refused` — a runtime trace is missing pid
- **PASS** `an-unparseable-timestamp-is-refused-not-replaced` — a timestamp that cannot be parsed is not a timestamp
- **PASS** `the-summary-counts-processes-not-operations` — two PIDs, three operations

## `the_provider` — PASS

*does the tracer separate 'OpenSSL' from 'OpenSSL 3.0.13'?* (review 7)

- **PASS** `a-provider-is-what-it-was-seen-doing` — OpenSSL 3.0.13 was observed performing AES-256-GCM in 1 process(es)
- **PASS** `operations-are-counted-per-provider` — a provider that encrypts and decrypts is one provider with two operations
- **PASS** `an-unversioned-provider-says-it-cannot-be-compared` — OpenSSL (version not reported) was observed performing AES-256-GCM in 1 process(es); without a version it cannot be compared with an SBOM
- **PASS** `the-provider-version-is-not-invented` — provider_version stays null when the collector did not report it

## `correlation` — PASS

*does the twin say which provider version the process loaded?* (review 7 / 8)

- **PASS** `the-review-version-mismatch-is-reported-not-resolved` — 1 provider correlation(s): VERSION_MISMATCH=1; a version mismatch is reported, not resolved
- **PASS** `both-sides-keep-their-evidence` — RUNTIME-92821, SBOM-1
- **PASS** `an-agreeing-provider-is-a-match` — the loaded provider matches the declared version
- **PASS** `runtime-only-and-sbom-only-are-both-named` — 2 provider correlation(s): RUNTIME_ONLY=1, SBOM_ONLY=1
- **PASS** `an-unversioned-runtime-provider-cannot-match` — the runtime provider version was not reported, so agreement with the SBOM cannot be established

## `the_asset` — PASS

*does a runtime observation become a runtime-confirmed asset?* (review 7)

- **PASS** `repeated-operations-are-one-asset-with-a-count` — 1 runtime-confirmed crypto asset(s) from 2 evidence reference(s); every one carries the process and provider chain
- **PASS** `a-different-process-is-a-different-asset` — the process is part of the asset identity
- **PASS** `the-asset-is-runtime-confirmed-with-the-chain-attached` — runtime/payments-api/9182/EVP_EncryptInit_ex/AES-256-GCM/OpenSSL/3.0.13
- **PASS** `an-asset-with-no-parameters-claims-no-parameter-set` — an empty parameter object would read as 'known to be empty'
- **PASS** `the-asset-writes-no-quantum-verdict` — the PQC handoff owns that decision, not the collector

## `the_twin` — PASS

*does the chain reach the digital twin as evidenced relationships?* (review 7 / 20)

- **PASS** `the-graph-walks-the-whole-chain` — 5 runtime relationship(s) across 5 node(s); every edge is RUNTIME_OBSERVED and carries its evidence id
- **PASS** `the-shortcut-exists-for-the-obvious-question` — which applications encrypt with AES-256-GCM, without walking four edges
- **PASS** `every-edge-is-observed-and-carries-evidence` — repeat observations merge their evidence ids
- **PASS** `nodes-are-typed-by-their-prefix` — the twin can filter by kind
- **PASS** `the-route-exists-typed-and-role-gated` — POST /cbom/runtime-traces

## What this does not prove

- the platform reads traces; it does not install the tracer. A process that never called a hooked operation produces no trace, which is indistinguishable from a process that did not run crypto — only coverage of the tracing tells them apart
- pid identifies a process instance, not an application version. Two deployments of payments-api look alike unless the collector also reports a build id or image digest, which this module does not require
- a provider version is only as good as the collector's lookup: a statically linked library or a vendored copy may report the wrong version, and the correlation would then be confidently wrong
- correlation matches on library name. 'OpenSSL' vs 'openssl' is normalised, but 'BoringSSL' and 'OpenSSL' are different providers and a fork that renames itself will read as RUNTIME_ONLY
- component identity is (application, process, provider, operation, algorithm, parameters). An operation repeated across two hosts is one asset with a count, so per-host provenance needs the host property, not the component
- runtime traces prove an operation happened; they do not prove which key, which purpose or which data. Key-level runtime evidence is the KMS collector's job
- the graph is a projection for one submission, not a stored twin. Persisting it, and diffing successive runtime states for drift, is not in this increment
