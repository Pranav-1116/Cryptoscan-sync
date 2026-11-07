# Built load-balancer / ADC sandbox

This is implemented code, not just the [requirements addendum](../../../docs/bank-environment/91-load-balancer-adc-master-prompt-addendum.md). Generation now includes bank-scoped LB nodes, listeners, separate cryptographic sessions, public certificates, key references, HA clusters, configurations, all six BOM projections and hidden scenario expectations. **Fixture coverage does not imply normal CryptoScan end-to-end attribution/correlation acceptance.**

## Run it

From the repository root, using the existing scanner dependencies plus `cryptography`, `jsonschema` and `referencing`:

```bash
.venv/bin/python generate_sandbox.py --banks 10 --scale small \
  --profile worst-case-bank --output /home/user/.cache/lb-estate
.venv/bin/python -m tools.banking_sandbox.cli validate \
  --root /home/user/.cache/lb-estate --full-schemas
.venv/bin/python -m tools.banking_sandbox.cli lb-scan \
  --root /home/user/.cache/lb-estate --output /home/user/.cache/lb-config-results
.venv/bin/python -m tools.banking_sandbox.cli serve \
  --root /home/user/.cache/lb-estate --host 0.0.0.0 --port 8080
```

`lb-scan` stages **only the five named configuration-file types** from `public/load_balancers` into the guarded existing source-collector harness. It calls the normal `scanner.registry.language_scanners.scan_file` with no detector modifications. The child denies sockets and oracle reads, and labels findings `STATIC_OBSERVED / CONFIGURATION_NOT_NEGOTIATION`. Empty findings are not proof of absent crypto. Numeric detector accuracy for these configuration variants is **not yet qualified**; `accuracy=null` is deliberate. Source scanning remains available through the original `scan` command. Use a fresh estate for each staged scan.

## What is generated

Every bank contains all **35 additional LB scenarios**, separate from the original banking-estate cases. Each bank has ten core LB role instances, with additional cloud/Kubernetes, payment, multi-site and DR roles selected by archetype. The complete portfolio represents all fifteen requested roles. Instances are logical LB/ADC roles linked to existing bank system IDs, not claims that each is a newly running machine.

```text
public/load_balancers/<bank>/
  inventory.json             # LB nodes, HA clusters and supporting path nodes
  policies.json              # modern, mixed and legacy capability declarations
  environment.json           # explicit synthetic template environment, never host secrets
  policies/modern.conf       # resolvable inherited-policy example
  cases.jsonl                # 35 linked cases/listeners, not expected answers
  hops.jsonl                 # per-hop transport, termination owner, configured crypto
  certificates.jsonl         # certificate metadata, chain refs and opaque key refs
  certificates/*.pem         # public certificates only
  keys.jsonl                 # synthetic HSM key references, no key bytes
  evidence.jsonl             # configured facts with source/time/target/provenance
  drift.json                 # controlled configured drift plan
  oci/                       # real but inert OCI layout; not a deployable bank image
  <case>/{nginx.conf,haproxy.cfg,envoy.yaml,gateway.yaml,loadbalancer.json}

public/{nbom,cbom,sbom,techbom,hbom,vbom}/<bank>-loadbalancers.jsonl
public/cbom/<bank>-loadbalancers-stale.jsonl
public/runtime/<bank>-loadbalancers.jsonl
public/hsm/<bank>-loadbalancers.jsonl
control/ground_truth/<bank>-loadbalancers.jsonl
```

Configuration files are **inert lab templates**, not deployment-ready nginx/HAProxy/Envoy resources. References such as `CERT-REF:...`, `LB-KEY-...` and `HSM-KEY-...` never contain private keys. Eight configurations differ structurally: explicit, inherited, environment-driven, indirect, missing, conflicting, stale and vendor-declared. The structured config records unresolved/missing/conflicting values explicitly; hop models are synthetic declarations and do not claim that CryptoScan resolved them. No cloud API, Kubernetes apply, public IP connection or real vendor device is involved.

The certificate metadata is checked against actual PEM fingerprints, key sizes/curves, SANs, validity and CA-chain signatures. Fixture signatures are **Ed25519**. SHA-1 drift is a separate declaration, **not** a falsely labeled SHA-1-signed PEM. Synthetic HSM key/certificate relationships include RSA-3072 key refs and lifecycle/signing capability; operations are not executed. Every software LB has CycloneDX and SPDX SBOMs; only the designated containerized example has an actual inert image layout/digest. Package inventory is not runtime proof.

## Hop semantics

- **Termination:** client → LB TLS session plus a separately configured HTTP backend leg. TLS findings belong to transport/LB ownership, not application-level crypto.
- **Re-encryption:** independent external TLS1.3/AES-256-GCM and internal TLS1.2/AES-128-GCM assets, with different certificate references and evidence IDs. They cannot share a crypto-asset identity.
- **Passthrough:** one end-to-end TLS session terminates at the backend; forwarding edges pass unchanged TLS through the LB. The listener does not own a terminating certificate/private-key reference. Do not count forwarding as a second negotiation.
- **mTLS:** independent client/backend requirements include all `(true,true)`, `(true,false)` and `(false,true)` combinations. These are configured requirements, not observed client authentication.
- **Full path:** the API-gateway case has six independently evidenced TLS legs through WAF, LB, gateway, mesh, service and database. Other NBOM edges bind to their exact session IDs, including passthrough forwarding.
- **Capabilities:** mixed policy can enable AES-128-CBC while preferring AES-GCM. All fixture `negotiated` fields remain null; the fixture model never converts support to an observation.
- **HA/DR:** per-member firmware, certificate refs, TLS policies, active/standby or active/active states, stale/synchronized certificate examples and primary/DR differences are preserved.
- **Partial visibility:** unseen internal negotiation remains UNKNOWN. Different scopes, HA members and times are not collapsed into a conflict.

## Actual live witness (no host-network fallback)

```bash
.venv/bin/python -m tools.banking_sandbox.cli lb-live \
  --output /home/user/.cache/lb-live-results
```

This fixed test requires Linux user/network/mount namespaces, `unshare`, `mount`, `ip`, Landlock ABI ≥2, OpenSSL-backed Python and cryptography. It creates a fresh user/network/private-mount namespace with **only loopback**, verifies namespace separation and interface closure, and mounts a bounded **8 MiB private tmpfs** for ephemeral keys. No arbitrary target or QEMU arguments exist. A Landlock read allowlist excludes the oracle/harness/home, and an existing outside sentinel actually tests read denial. CPU/address-space/core limits and a 40-second parent deadline apply. No VM/security-certification claim is made; the host kernel and trusted lab code remain part of the boundary.

The actual topology uses Python TLS servers and an opaque TCP forwarder, with the **unchanged normal CryptoScan TLS handshaker** probing:

1. TLS termination at an EC/P-256 LB endpoint.
2. Re-encryption with external TLS1.3/AES-256-GCM/EC and internal TLS1.2/ECDHE-RSA-AES128-GCM/RSA-2048.
3. Pass-through with the backend certificate, distinct from the frontend certificate.
4. An actual changed endpoint using TLS1.2/RSA/AES-128-GCM instead of the baseline TLS1.3/EC/AES-256-GCM.

Only handshakes are generated; **no application data is sent, inspected or decrypted**. The passthrough forwarder relays opaque TLS bytes without parsing payload. Public certificate parameters, endpoints, times, cipher/version and SNI inputs are recorded. TLS1.3 key-exchange group, handshake signature and mTLS state remain UNKNOWN where the existing handshaker cannot expose them. This collector does not offer ALPN; a null negotiated ALPN is retained. Discovery does **not** verify peer authentication.

**Termination ownership comes from the controlled lab topology, not an invented architecture detector.** This is not a full-estate automatic correlation result. Positive mTLS handshakes, HSM signing, legacy TLS, PQC, real ADC appliances and the normal runtime-agent pipeline are not exercised. Private keys remain in child tmpfs and disappear with its mount namespace; receipts contain no private keys. Isolation failure returns failure, never a host-network scan.

## Drift and hidden-harness comparison

```bash
.venv/bin/python -m tools.banking_sandbox.cli drift \
  --root /home/user/.cache/lb-estate --output /home/user/.cache/lb-estate-drift
.venv/bin/python -m tools.banking_sandbox.cli lb-compare \
  --root /home/user/.cache/lb-estate --results /path/to/actual-normalized-lb-observations.jsonl \
  --output /home/user/.cache/lb-comparison.json
```

Drift copies the estate, changes TLS capabilities and a public certificate/key reference for the same SNI domains, records previous/current fingerprints and affected services, updates configurations/provenance/hidden modeled certificate expectations, and chains the manifest. **Configured drift does not invent changed negotiated crypto.** The separate live witness provides actual protocol/cipher/certificate change evidence for its fixed endpoints, not for every bank.

`lb-compare` runs only in the harness. Input rows identify `bank_id`, `case_id`, `lb_id`, `hop_id`, `path_id`, `crypto_asset_id`, `termination_point`, `backend_target`, disposition, evidence ID/type and timestamp. Evaluated parameters include modeled certificate ID/fingerprint/public-key algorithm/key size/curve/signature, normalized version/cipher and `mtls_required`. Map actual raw observations through independently supplied public identities; **do not copy expected values from truth into product results**. Raw TLS strings/algorithm identifiers must be normalized by the supplying adapter; the fixed live witness has its own IDs and is not automatically scored as the whole estate.

The report gives TP/FP/FN, precision/recall and separate attribution/certificate/crypto-parameter/hop-correlation correctness, unknown and missing counts. Missing/failed/partial observations do not become true negatives or SAFE; cross-bank/case and duplicate-hop observations are rejected. FPR is null until a negative-session population is agreed. Per-dimension accuracy uses evaluated correct/incorrect values; check missing/unknown counts alongside it. Unit-test predictions are scorer tests only and are never published as product accuracy.

## Validation and remaining qualification

```bash
.venv/bin/pytest -q tools/banking_sandbox/test_sandbox.py \
  tools/banking_sandbox/load_balancers/test_load_balancers.py
```

See the new measured readiness document for actual run sizes, receipts, failures and source provenance. The prior published TLS handshaker already had a separate user working-tree edit; this increment preserves it and binds the measured source hash rather than silently publishing that edit. Full normal-product LB discovery/correlation, all 35 live cases, positive mTLS/HSM operations and production load capacity remain separate acceptance work.
