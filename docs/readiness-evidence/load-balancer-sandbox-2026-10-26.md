# Load-balancer / ADC sandbox — built and measured, 2026-10-26

**Verdict: bank-scoped LB fixture generation, validation, normal config collection, configured drift, dashboard and a narrow actual isolated TLS witness are built. Full automatic LB discovery/correlation and all 35 live scenarios are not accepted.**

Implementation: [`tools/banking_sandbox/load_balancers`](../../tools/banking_sandbox/load_balancers/). [Runbook](../../tools/banking_sandbox/docs/load-balancers.md). [Requirements](../bank-environment/91-load-balancer-adc-master-prompt-addendum.md).

## What is now built

- Fifteen LB/ADC roles across the portfolio, profile-selected subsets for each bank, separate listener/SNI/backend/session identities, public certificate stores and opaque software/HSM key references.
- All **35 additional LB cases per bank**, not replacements for the original 35 estate cases.
- Independent TLS assets for re-encryption; one backend-terminated session for passthrough; supported capability distinct from configured preference and actual negotiation.
- Three client/upstream mTLS requirement combinations, HA/DR members and differing certificates/policies/firmware, SNI-to-certificate maps, multiple domains, redirect metadata, HSM key relationships and partial visibility.
- Structurally different explicit/inherited/environment/indirect/missing/conflicting/stale/vendor configuration templates; all five requested configuration filenames.
- Separate NBOM, CBOM, SBOM (CycloneDX + SPDX), TechBOM, HBOM and VBOM projections; imported stale CBOM/runtime-provider conflict artifacts and a real inert OCI layout.
- Public certificate-chain/key-size/curve/fingerprint/SAN/validity verification; no private-key exports. Synthetic certificate signatures are Ed25519; SHA-1 drift is a declaration only.
- A six-leg WAF → LB → API gateway → mesh → service → database path with separate hop evidence, configured drift snapshots with preserved baseline and manifest chaining, and a bank/LB/case/hop dashboard.
- Hidden modeled truth and a harness-only comparator for supplied actual normalized results. It never fabricates product observations from truth.

## 150-bank validation and actual config collection

Command: `generate_sandbox.py --banks 150 --scale small --profile worst-case-bank`, default seed, default simulated epoch, all feature flags true and all complexities high. This is **not** the earlier 150-bank mixed estate and is not a same-workload performance comparison.

| Measure | Result |
|---|---:|
| Banks | 150 |
| Base estate systems | 2,961 |
| Base estate applications | 5,922 |
| LB/ADC logical role instances | 1,639 |
| Additional LB scenarios | 5,250 |
| Declared LB TLS-session assets | 7,650 |
| LB public certificates | 4,189 |
| LB SBOM documents | 3,278 |
| All public hashes checked | 45,213 |
| All SBOM/CBOM document schemas checked | 36,827 |
| LB SBOM/CBOM documents in that total | 11,078 |
| Normal configuration files scanned | 26,250 |
| Collector errors | 0 |
| Files with at least one finding | 2,700 |

The configuration collection called the unchanged `scanner.registry.language_scanners.scan_file`, using only the five generated config filenames, in the existing Landlock/seccomp child. The actual guard receipt records **oracle read denied and socket creation denied**. Parent collection wall was **14.113 s**, child CPU **14.054 s**, child peak RSS **90,576 KiB**. These are single operational samples, **not calibrated benchmarks, end-to-end queue/API latency or production capacity claims**. Other tests/generation may run concurrently.

**No numeric config accuracy claim:** most files produce no findings. The 2,700 nonempty files are not recall; inherited/environment/JSON/other representations may be unresolved or unsupported. Empty output is not NO CRYPTO. Accuracy remains null until a complete adapter/oracle and predeclared acceptance targets are qualified. Raw findings are retained outside Git; the published summary contains bounded examples and hashes. Normal core detection logic was not changed to improve these results.

[Generation counts](load-balancer-sandbox-2026-10-26/generation-150.json), [full validation](load-balancer-sandbox-2026-10-26/validation-150.json), [collection receipt](load-balancer-sandbox-2026-10-26/config-collection-150.json), [findings summary](load-balancer-sandbox-2026-10-26/config-findings-summary.json).

## Actual isolated TLS witness

The fixed `lb-live` command successfully ran **five actual normal-collector handshakes** inside separate user/network/private-mount namespaces. Only `lo` existed. Parent namespace identities remained unchanged. Landlock denied an existing outside sentinel read. Private keys were created only in an **8 MiB private tmpfs**, not the parent filesystem, and disappeared with the child mount namespace. No application data was sent, inspected or decrypted.

| Session | Actual protocol / cipher | Public key | Termination owner from controlled topology |
|---|---|---|---|
| Termination external | TLS1.3 / TLS_AES_256_GCM_SHA384 | EC P-256 | LB |
| Re-encryption external | TLS1.3 / TLS_AES_256_GCM_SHA384 | EC P-256 | LB |
| Re-encryption internal | TLS1.2 / ECDHE-RSA-AES128-GCM-SHA256 | RSA-2048 | Backend |
| Passthrough end-to-end | TLS1.3 / TLS_AES_256_GCM_SHA384 | RSA-2048 | Backend, not forwarding LB |
| Drift external | TLS1.2 / ECDHE-RSA-AES128-GCM-SHA256 | RSA-2048 | Changed LB endpoint |

The external/internal re-encryption certificates have different fingerprints and the passthrough fingerprint matches the backend public certificate. The baseline/drift external certificate fingerprints, public-key algorithms, protocol and negotiated cipher differ. The TCP forwarder relays opaque TLS bytes without application-payload parsing. Public leaf DER and SPKI are retained in the final receipt; no private keys are retained. Full peer chain is not exposed by this handshaker. SNI is a client-request parameter, not a fabricated server-side capture. ALPN remains null because this discovery client does not offer it. TLS1.3 group, handshake signature and mTLS state remain UNKNOWN. Peer authentication is not verified.

**This does not prove a new automatic architecture detector:** hop/termination ownership is supplied by the controlled topology and checked by the harness. The existing normal handshaker supplies negotiated TLS/certificate observations. Positive mTLS, HSM signing, PQC, legacy TLS, a normal runtime-agent pipeline and full-estate automatic attribution are unexecuted. The witness is separate from the 150-bank fixture graph; it is not scored as 150 live banks.

[Final actual receipt](load-balancer-sandbox-2026-10-26/live-namespace.json), [earlier successful receipt](load-balancer-sandbox-2026-10-26/live-namespace-earlier.json). The TLS handshaker has a **pre-existing user working-tree edit**, preserved and **not published by this increment**. The measured and published-parent hashes are recorded in [source provenance](load-balancer-sandbox-2026-10-26/source-provenance.json); clean-published-checkout live requalification remains pending.

## Tests, failures and dashboard

**104 focused tests passed** (51 original sandbox tests + 53 LB tests). They cover all 35 linked LB cases, mTLS requirement combinations, separate-hop certificates/versions/ciphers, passthrough attribution, independent path evidence, key/HSM links, SNI and public-PKI checks, configuration variants, oracle separation, missing/partial/invalid scoring, copy-on-write drift, actual guarded configuration collection and the actual namespace-isolated witness. Unit observations synthesized to exercise the scorer are explicitly not product accuracy measurements. Ruff, formatting, compilation and dashboard JavaScript syntax checks also passed. The entire repository suite was not rerun.

The first new live attempt failed because a nonexistent sentinel could not establish read denial; the second failed because an already-wrapped socket's old descriptor was queried. Both are retained as failed receipts, not acceptance evidence. The corrected code uses an existing outside sentinel and captures the source endpoint before wrapping. An initial configuration attempt failed due to missing `structlog`; dependencies were installed, a fresh estate was used, and no failed pre-guard receipt was called a pass. An intermediate scale attempt was interrupted by a schema/code revision; its collection failed explicitly, and a fresh final-v2 estate was generated and fully validated. Nothing was relabeled as a successful historical run.

The **live preview on port 8080** now serves the final 150-bank fixture explorer, including an LB/case selector and independent-hop details. It serves only public data. No browser visual automation was available; HTTP/JS smoke checks are not full visual acceptance. The new documentation and source are additive/scoped; all existing workspace file bytes, symlinks, modes and deletions were preserved.

## Remaining acceptance work

1. Qualify full normal-product configuration import, architecture classification and end-to-end per-hop/owner/certificate/HSM/BOM correlation; do not count harness-provided topology as detector output.
2. Execute positive mTLS per hop, SNI selection, real HA failover/standby probing, external-only visibility, legacy handshakes, cloud/Kubernetes/mesh/database proxies, HSM operations and remaining mandatory live cases in authorized isolation.
3. Supply actual normalized facts to the hidden comparator. Match case/bank/path/hop/time, preserve unknowns, and agree positive/negative populations and thresholds before reporting accuracy or FPR.
4. Validate installed-versus-loaded-versus-executed runtime evidence through the normal runtime agent, not simulated provider exports.
5. Perform calibrated repeatable load/concurrency/queue/DB/API measurements and independent boundary/source/license review. No SLA or production-capacity conclusion is implied.
