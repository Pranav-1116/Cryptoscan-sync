# 92 — Runtime Cryptography Scan Engine

Status: **building** on `arena/bb4b80dd-cryproscan`.
Companion to [`67-network-crypto-discovery-engine.md`](67-network-crypto-discovery-engine.md).

## 1. The question this engine answers

Static scanning answers *"what crypto is present / configured / referenced?"*
Runtime scanning answers a stronger question:

> **Which cryptographic operations are actually happening in the running bank
> environment, which process/device performs them, and with which exact
> algorithm, key size, mode, parameters and purpose?**

"Could be used" (static) and "was observed operating" (runtime) are different
facts and are never merged.

## 2. Architecture

```text
                    BANK PRODUCTION ENVIRONMENT
                              │
                     ┌────────▼────────┐
                     │ Runtime Scope   │
                     │ + Authorization │
                     └────────┬────────┘
          ┌───────────────────┼────────────────────┐
          ▼                   ▼                    ▼
     HOST RUNTIME        APPLICATION RUNTIME    NETWORK RUNTIME
          │                   │                    │
    Linux / Windows / VM   JVM / .NET / Go /    TLS / mTLS / VPN /
    container / K8s        Rust / OpenSSL       SSH observation
          └───────────────────┼────────────────────┘
                              ▼
                     CRYPTO OBSERVATION
          ┌───────────────────┼────────────────────┐
          ▼                   ▼                    ▼
       HSM/KMS             DATABASE             DEVICES
       PKCS#11             TDE / TLS            VPN / IPsec / SSH
          └───────────────────┼────────────────────┘
                              ▼
                       EVIDENCE ENGINE
                              ▼
                     CRYPTO NORMALIZER
                              ▼
                ┌─────────────┼─────────────┐
               CBOM         NBOM         TechBOM
```

## 3. Runtime scope comes first

Instrumentation is more sensitive than reading files, so nothing is attached
implicitly. A runtime target is authorized explicitly:

```yaml
target:
  host: payments-prod-01
  application: payments-api
  process: payments-api
  collection_window:
    from: 2026-10-25T02:00:00Z
    to:   2026-10-25T02:30:00Z
  runtime_methods:            # approved instrumentation only
    - CRYPTO_API_TRACE
    - PROCESS_TELEMETRY
  network_scope: [10.20.10.15:443]
  data_restrictions:          # enforced, not aspirational
    - NO_PLAINTEXT
    - NO_PRIVATE_KEYS
    - NO_CUSTOMER_DATA
```

An observation outside the host/application/process set, outside the window, or
from an unapproved method is **rejected**, not stored-and-flagged.

## 4. Collector: what is running

```text
PID 1842 · payments-api · /opt/payments/payment-api · sha256:abc123…
libraries: libssl.so.3, libcrypto.so.3 · container: sha256:def456…
```

The collector binds every later crypto observation to that identity, so crypto
from another process is never attributed to the payment application.

## 5. Crypto framework identification → adapter

```text
            Runtime Crypto Engine
        ┌───────────┼────────────┐
     OpenSSL      JVM/JCE      .NET CNG
     BoringSSL    BouncyCastle System.Security
        │            │             │
        ├── Go       ├── Rust      ├── PKCS#11 / HSM
        ├── KMS      ├── DB audit  ├── VPN / SSH telemetry
```

Each adapter declares where the operation becomes visible and therefore what it
can and cannot report. An adapter that only sees `EVP_CipherInit_ex` cannot
report a tag length; it says `UNKNOWN` instead of guessing.

## 6. The observation hierarchy (never promote a lower level)

```text
Level 1  known crypto API instrumentation      (EVP_*, JCE, AesGcm, Go crypto/*)
Level 2  known framework instrumentation       (framework-level hooks)
Level 3  HSM / KMS / database audit telemetry  (approved operation logs)
Level 4  TLS / network observation             (negotiated session parameters)
Level 5  approved binary/runtime instrumentation
Level 6  UNKNOWN                               (custom crypto, blind spots)
```

A Level 6 result is reported as Level 6. Presenting an inference as a Level 1
observation would be a false provenance claim.

## 7. Event shape

```json
{
  "event_type": "CRYPTO_OPERATION",
  "host": "payments-prod-01",
  "application": "payments-api",
  "process": "payments-api",
  "pid": 1842,
  "executable_digest": "sha256:…",
  "container_digest": "sha256:…",
  "crypto_provider": "OpenSSL",
  "algorithm": "AES",
  "key_size": 256,
  "mode": "GCM",
  "operation": "ENCRYPT",
  "nonce_length": 96,
  "tag_length": 128,
  "timestamp": "…",
  "evidence_type": "RUNTIME_OBSERVED"
}
```

**No plaintext. No private key. No secret key. No customer payload.**
Parameters that the adapter did not supply are `UNKNOWN`, never filled in.

## 8. Operations are typed, not "crypto found"

`ENCRYPT · DECRYPT · SIGN · VERIFY · HASH · MAC · KEY_AGREEMENT ·
KEY_DERIVATION · KEY_GENERATION · KEY_WRAP · KEY_UNWRAP · TLS_HANDSHAKE`

## 9. Algorithm families and the parameters each can carry

| Family | Observable parameters |
|---|---|
| AES-GCM | key size, mode, nonce length, tag length, operation |
| AES-CBC | key size, mode, IV length, operation |
| AES-CTR | key size, mode, counter/IV metadata, operation |
| RSA | key size, padding (PSS/PKCS#1), hash, operation |
| ECDSA | curve, hash, operation |
| ECDH | curve, operation (`KEY_AGREEMENT`) |
| Hash | digest length, operation (`HASH`) |
| HMAC | hash, key size, operation (`MAC`) |
| KDF | KDF name, hash, output length, salt/info *presence* only |
| TLS | version, suite, KEX, group, certificate, mTLS |

## 10. HSM / KMS / database

* **HSM (PKCS#11 audit)** — operation, algorithm, hash, key *reference*, device,
  caller. Never the private key. Evidence `HSM_OBSERVED` (Level 3).
* **KMS audit** — key reference, operation, algorithm, caller identity. Correlate
  application → identity → key → algorithm → operation.
* **Database** — TDE / TLS telemetry where the engine exposes it; the transport
  fact and the storage fact stay separate.
* **VPN / SSH** — negotiated IKE/ESP and KEX/host-key/cipher/MAC where telemetry
  or approved observation exposes the session.

## 11. Containers and Kubernetes

```text
crypto event → process → container → image digest → deployment → application
```

A runtime CBOM entry therefore reads:

```text
AES-256-GCM · application: payments-api · pod: payments-api-7d9…
container: payments · image: sha256:… · evidence: RUNTIME_OBSERVED
```

## 12. Hardware acceleration is not an algorithm

AES-NI/ARM crypto extensions do not tell you AES-128 vs AES-256. The algorithm
is attributed at the crypto API/provider level; CPU flags are context only.

## 13. Custom cryptography

`custom_crypto()` with no observable API is Level 6 → `UNKNOWN`. The engine
never upgrades it to Level 1 because a binary "looks like" it does AES.

## 14. Static vs runtime

| Static | Runtime |
|---|---|
| reads source/binaries/config | observes execution |
| reads packages | observes crypto API calls |
| reads certificates | observes negotiated sessions |
| "could be used" | "was observed being used" |
| snapshot-oriented | time/window-oriented |

```text
STATIC  → "what cryptography is present / configured / referenced?"
              └──────────────┐
                         CORRELATION
              ┌──────────────┘
RUNTIME → "what cryptography actually operated?"
```

## 15. What this engine will not do

* attach to processes without an approved runtime scope;
* record plaintext, keys, IVs, nonces, salts or customer data;
* infer key size, padding or mode that the adapter did not report;
* present a network TLS fact as application crypto (see spec 67 §27);
* claim a distributed runtime fleet where only one node exists.
