# Master-prompt addendum — Load balancer / ADC cryptography

**Status: required scope, not an implementation or acceptance receipt.** Append this section to the synthetic banking-estate master prompt. It supplements, rather than replaces, the existing requirements. The synthetic
banking-estate lab that once implemented this scope has been removed from the
product: nothing here is implemented or accepted, and the earlier measurements
were taken against that lab, not against a customer estate.

All existing constraints continue to apply: entirely local synthetic lab, no real bank/customer/production connectivity, no exported private keys or credentials, normal CryptoScan collectors/imports, no core changes merely to pass tests, hidden truth inaccessible to CryptoScan, and no promotion of configuration or simulation to live observation.

---

## LOAD BALANCER / ADC CRYPTOGRAPHY

The synthetic banking estate **MUST** contain realistic load-balancer and ADC architectures.

Create multiple types of synthetic load-balancer roles:

1. Internet-facing load balancer
2. Internal load balancer
3. API load balancer
4. Application load balancer
5. TCP load balancer
6. TLS-terminating load balancer
7. TLS pass-through load balancer
8. TLS re-encryption load balancer
9. Active/standby load-balancer pair
10. Multi-site load-balancer cluster
11. Data-center load balancer
12. Kubernetes ingress/load-balancer
13. Synthetic cloud load balancer
14. Payment-zone load balancer
15. DR-site load balancer

Every bank must have a realistic subset of these depending on its architecture profile.

## LOAD BALANCER TOPOLOGY

Create topologies such as:

```text
Internet
   |
   v
WAF
   |
   v
External Load Balancer
   |
   v
API Gateway
   |
   v
Application
```

Also create:

```text
Client
   |
   | TLS
   v
Load Balancer
   |
   | TLS
   v
Application
```

This represents TLS termination + TLS re-encryption.

Also create:

```text
Client
   |
   | TLS
   v
Load Balancer
   |
   | TCP/TLS passthrough
   v
Application
```

The scanner must distinguish these architectures.

## LOAD BALANCER TLS TERMINATION

Create load balancers where TLS terminates at the load balancer.

Example:

```text
Client
   |
   | TLS 1.3
   | AES-256-GCM
   | X25519
   v
[LOAD BALANCER]
   |
   | HTTP or internal protocol
   v
[APPLICATION]
```

The external network scan must identify:

- endpoint
- port
- TLS version
- negotiated cipher
- key exchange
- certificate
- certificate public-key algorithm
- certificate key size/curve
- certificate signature algorithm
- SNI
- ALPN where observable
- mTLS status

The scanner **MUST NOT** incorrectly attribute the external TLS cipher as application-level cryptography.

## TLS RE-ENCRYPTION

Create:

```text
Client
   |
   | TLS 1.3
   | AES-256-GCM
   v
[External Load Balancer]
   |
   | TLS 1.2
   | AES-128-GCM
   v
[Internal Application]
```

This is a **mandatory test case**.

CryptoScan must identify **TWO independent cryptographic hops**:

- **HOP 1:** Client → Load Balancer
- **HOP 2:** Load Balancer → Application

**Do NOT merge them.**

Example expected result:

| Parameter | External | Internal |
|---|---|---|
| TLS version | TLS 1.3 | TLS 1.2 |
| Cipher | AES-256-GCM | AES-128-GCM |
| Key exchange | X25519 | ECDHE |
| Certificate public key | ECDSA P-256 | RSA-2048 |

The system must represent these as separate network crypto assets.

## TLS PASSTHROUGH

Create:

```text
Client
   |
   | TLS
   v
[LOAD BALANCER]
   |
   | TLS unchanged
   v
[APPLICATION]
```

The load balancer should not terminate TLS.

CryptoScan should identify:

```text
LOAD BALANCER:
    TCP/TLS passthrough

APPLICATION:
    TLS endpoint
```

The scanner must not incorrectly attribute the certificate to the load balancer if the TLS session terminates at the backend.

## LOAD BALANCER CERTIFICATE STORE

Each TLS-terminating load balancer must have synthetic:

- certificate
- certificate chain
- private-key reference **ONLY**
- key algorithm
- key size
- curve
- signature algorithm
- SAN
- issuer
- validity
- certificate fingerprint
- certificate rotation metadata

**IMPORTANT: Never expose or export actual private keys.**

Use synthetic key references such as `LB-KEY-000123` instead of private-key material.

## LOAD BALANCER CRYPTO POLICIES

Create synthetic policies such as:

### Modern

- TLS 1.2+
- TLS 1.3
- AES-GCM
- ChaCha20-Poly1305
- ECDHE
- X25519
- P-256

### Legacy

- TLS 1.0
- TLS 1.1
- RSA key exchange
- 3DES
- AES-CBC
- SHA-1
- weak DH groups

### Mixed

- TLS 1.3 preferred
- TLS 1.2 enabled
- strong + legacy cipher suites

The mixed configuration is especially important.

Example:

```text
Supported:
TLS 1.3
TLS 1.2
AES-256-GCM
AES-128-GCM
AES-128-CBC

Negotiated:
TLS 1.3
AES-256-GCM
```

CryptoScan must report:

```text
SUPPORTED:
AES-128-CBC exists

NEGOTIATED:
AES-256-GCM was observed
```

It must **NOT** report AES-128-CBC as currently negotiated.

## LOAD BALANCER mTLS

Create all three architectures:

```text
Client
   |
   | mTLS
   v
Load Balancer
   |
   | mTLS
   v
Application
```

```text
Client
   |
   | mTLS
   v
Load Balancer
   |
   | TLS
   v
Application
```

```text
Client
   |
   | TLS
   v
Load Balancer
   |
   | mTLS
   v
Application
```

CryptoScan must identify the crypto state independently for every hop.

## LOAD BALANCER CLUSTERS

Create HA pairs, such as `LB-01` and `LB-02`, with:

- active/standby
- active/active
- different certificates
- synchronized certificates
- stale certificate on standby
- different TLS policies
- different firmware
- different crypto configuration

Create scenarios where:

```text
LB-01:
TLS 1.3

LB-02:
TLS 1.2
```

The scanner must be able to detect configuration drift.

## LOAD BALANCER + HSM

Create synthetic architecture:

```text
Load Balancer
      |
      | PKCS#11 / synthetic HSM integration
      v
HSM
```

The load balancer should reference:

- HSM ID
- key reference
- certificate
- signing capability
- key algorithm
- key size
- key lifecycle

**Do NOT expose private-key material.**

Example:

```text
LB:
    payments-lb-01

Certificate:
    payments.bank.test

Key:
    HSM-KEY-00981

Algorithm:
    RSA-3072

HSM:
    HSM-PAYMENT-01
```

CryptoScan must correlate:

```text
Load Balancer
   ↓
Certificate
   ↓
HSM key reference
   ↓
Crypto asset
```

## LOAD BALANCER + SBOM

Every software-based synthetic load balancer must have:

- SBOM
- component inventory
- crypto-library inventory
- version
- container image where applicable
- image digest
- configuration

Example:

```text
Load Balancer:
    synthetic-nginx-lb

SBOM:
    nginx
    OpenSSL
    libcrypto
    libssl
```

**SBOM presence MUST NOT automatically mean those algorithms are being used.**

CryptoScan must correlate:

```text
SBOM
   ↓
software capability

Configuration
   ↓
configured TLS policy

Network
   ↓
negotiated TLS crypto

Runtime
   ↓
actual crypto operation, where observable
```

## LOAD BALANCER + STATIC ANALYSIS

Generate synthetic configuration files such as:

- `nginx.conf`
- `haproxy.cfg`
- `envoy.yaml`
- `gateway.yaml`
- `loadbalancer.json`

Include:

- TLS minimum version
- TLS maximum version
- cipher policy
- certificate reference
- private-key reference
- trusted CA
- client certificate requirement
- mTLS
- upstream TLS
- SNI
- ALPN
- protocol configuration

Create configurations where crypto is:

1. Explicit
2. Inherited
3. Environment-driven
4. Referenced indirectly
5. Missing
6. Conflicting
7. Stale
8. Vendor-declared

## LOAD BALANCER + NETWORK SCAN

The network scanner must test:

```text
External endpoint:
    LB public/synthetic address

Internal endpoint:
    LB backend address
```

For each observed TLS session capture:

- source
- destination
- port
- protocol
- TLS version
- negotiated cipher
- key exchange
- signature algorithm where observable
- certificate
- certificate fingerprint
- certificate public key
- curve
- mTLS state
- SNI
- ALPN
- timestamp
- evidence ID

**Do not inspect application payload. Do not decrypt application traffic.**

## LOAD BALANCER CRYPTO PATH GRAPH

Generate a graph such as:

```text
Internet
   |
   | TLS 1.3
   | AES-256-GCM
   | X25519
   v
[WAF]
   |
   v
[External Load Balancer]
   |
   | TLS 1.2
   | AES-128-GCM
   | ECDHE-RSA
   v
[API Gateway]
   |
   | mTLS TLS 1.3
   | AES-256-GCM
   v
[Service Mesh]
   |
   v
[Payments API]
   |
   | TLS
   v
[Database]
```

The sandbox must make this graph discoverable through separate evidence sources.

## LOAD BALANCER DRIFT

Create baseline:

```text
LB-01:
TLS 1.3
AES-256-GCM
ECDSA P-256
```

Then inject drift:

```text
TLS 1.2 enabled
AES-128-CBC enabled
RSA-2048 certificate
SHA-1 certificate
```

CryptoScan must identify:

- changed configuration
- changed certificate
- changed cipher capability
- changed negotiated crypto
- affected services
- previous state
- current state
- evidence
- timestamp

## LOAD BALANCER TEST SCENARIOS

**MANDATORY scenarios:**

1. TLS termination
2. TLS passthrough
3. TLS re-encryption
4. mTLS termination
5. mTLS re-encryption
6. Different external/internal TLS versions
7. Different external/internal certificates
8. Different external/internal cipher suites
9. Load balancer using HSM
10. Load balancer using software keys
11. HA load balancer pair
12. Certificate drift between HA nodes
13. Legacy TLS configuration
14. Strong configuration
15. Mixed cipher configuration
16. Supported-vs-negotiated difference
17. Stale certificate
18. Expired certificate
19. Multiple certificates/SNI
20. Multiple domains on one LB
21. HTTP → HTTPS redirect
22. TLS passthrough to Kubernetes ingress
23. LB → service mesh mTLS
24. LB → database proxy
25. LB → API gateway → service
26. Primary/DR load balancer with different crypto
27. Cloud-like synthetic load balancer
28. Containerized load balancer
29. Vendor-declared crypto inconsistent with network evidence
30. SBOM inconsistent with runtime library
31. Network evidence inconsistent with stale CBOM
32. Certificate public key differs from application crypto
33. HSM-backed signing
34. Multiple backend services with different TLS policies
35. Partial visibility where only external LB is observable

These 35 load-balancer cases are **additional** to the original 35 banking-estate difficult cases. They must not replace or silently reduce that earlier coverage.

## EXPECTED TRUTH

For every load balancer create hidden test-harness truth:

- termination point
- backend target
- TLS configuration
- actual negotiated crypto
- certificate
- HSM relationship
- SBOM components
- runtime crypto
- network crypto
- expected evidence type
- expected CryptoScan correlation

**CryptoScan itself must NOT receive this truth.**

The test harness compares:

```text
EXPECTED:
    external TLS = AES-256-GCM

OBSERVED:
    CryptoScan external TLS result
```

Then calculates:

- precision
- recall
- false positives
- false negatives
- attribution accuracy
- certificate accuracy
- crypto parameter accuracy
- hop correlation accuracy

## Evidence and acceptance safeguards inherited from the master prompt

- Synthetic public addresses and domains are labels, not permission to contact outside networks. Any live endpoints must run inside the explicitly isolated local lab.
- Preserve separate identities for bank, load balancer, HA member, listener/SNI, backend, network path, hop and evidence source. Do not infer backend/application cryptography solely from an external session.
- Re-encryption involves two independent TLS sessions and crypto assets. Passthrough has a backend TLS termination point; do not invent load-balancer TLS termination or duplicate an unchanged session into two independently negotiated sessions.
- Configuration, supported capability, vendor declarations, SBOM inventory, runtime operation and network negotiation remain distinct evidence classes. Missing backend visibility remains UNKNOWN, not plaintext, SAFE, or NO CRYPTO.
- Record observable fields with provenance. Unobservable key exchange, handshake signature, ALPN or mTLS state must remain UNKNOWN rather than being guessed from cipher/certificate names or an unauthenticated discovery handshake. Certificate signature and TLS handshake signature are distinct parameters.
- Hidden expected values for fixture-only scenarios are modeled expectations, not actual observations. Record actual negotiated crypto only when a live execution receipt supports it. Never populate product observations from hidden truth.
- Drift in a configured capability is not automatically a change in negotiated crypto. A SHA-1 certificate declaration is not a SHA-1-signed public certificate; actual certificate and negotiation changes require their own evidence.
- Compare observations with the matching bank, listener, hop, backend, SNI and time window. Retain previous/current states and source evidence; do not merge different HA nodes, epochs or scopes into one asset.
- Report failed, partial and missing observations separately from false negatives and true negatives. Use explicit denominators; undefined metrics remain UNKNOWN/null, not perfect scores. Partial visibility cannot establish unseen-hop accuracy.
- No application-payload inspection or traffic decryption is authorized. Private-key references may be exported; private-key material may not.
- This addendum establishes requirements only. Passing implementation and acceptance require separately recorded normal-collector results and hidden-harness comparisons; existing sandbox measurements do not certify these new cases.
