# The NBOM review, as received

Twenty-two points, sent 2026-11-03, on the depth of the network BOM. Kept verbatim in
substance and numbered as received, because the answers in
[`169-nbom.md`](169-nbom.md) refer to these numbers. Where the review names a shape
(`TERMINATES_TLS`, `SERVICE-9281`, `NEGOTIATED`) that shape exists in the code under the
same name.

## 1. Network endpoint → actual asset identity

**Current.** You have network observations such as IP, port, protocol, TLS, certificate,
cipher.

**Missing.** You need stable identity beyond `10.10.10.20:443`, because the same IP can
host multiple services, multiple virtual hosts, multiple certificates, multiple
applications, load balancers, containers, Kubernetes ingress.

**Target.**

```
IP:Port → Network Endpoint → Service → Application → Business System
```

Need canonical IDs: `NET-ENDPOINT-001`, `SERVICE-9281`, `APPLICATION-1827`, `SYSTEM-1001`.

## 2. NBOM → Application dependency

One of the biggest missing pieces. Current: `Endpoint → TLS observation`. Target:

```
Network Endpoint → Service → Application → System
```

```
payments.bank.example:443 → Payments API → Payment Processing Application → Payments System
```

The relationship must not be inferred simply because names match. It needs evidence such
as DNS, SNI, deployment metadata, Kubernetes ingress, API gateway configuration, load
balancer configuration, service registry, runtime observation, collector evidence.

## 3. Load balancer dependency is too shallow

```
Client → External LB → API Gateway → Application
```

And three different cryptographic dependency graphs:

TLS termination:

```
Client ↓ TLS 1.3 AES-256-GCM   LB ↓ HTTP   Application
```

TLS re-encryption:

```
Client ↓ TLS 1.3 AES-256-GCM   LB ↓ TLS 1.2 AES-128-GCM   Application
```

TLS passthrough:

```
Client ↓ TLS   LB ↓ TLS   Application
```

NBOM needs to explicitly represent `TERMINATES_TLS`, `RE_ENCRYPTS`, `PASSTHROUGH`,
`ROUTES_TO`.

## 4. Network → certificate dependency

```
Endpoint → Certificate → Public Key → Algorithm → Key Size / Curve
         → Signature Algorithm → Issuer / CA
```

```
payments.bank.example:443 → CERT-001 → ECDSA P-256 → ECDSA-SHA256
                          → Intermediate CA → Root CA
```

Then connect the certificate to the actual application / LB using evidence.

## 5. Network → CBOM dependency

```
Network Endpoint → Negotiated TLS → Cipher Suite → Crypto Assets
```

```
payments.bank.example:443 → TLS 1.3 → TLS_AES_256_GCM_SHA384 → AES-256-GCM, SHA-384
```

And separately: `ECDHE / X25519`, `ECDSA / P-256`.

Do **not** treat the cipher suite as one opaque crypto asset.

## 6. Supported vs negotiated dependency

```
Server supports: TLS 1.2, TLS 1.3          Negotiated: TLS 1.3
Supported: AES-128-GCM, AES-256-GCM, ChaCha20    Negotiated: AES-256-GCM
```

NBOM should represent `SUPPORTED`, `CONFIGURED`, `NEGOTIATED`, `OBSERVED` separately.
Otherwise the dependency graph can falsely report *"Application uses AES-128"* when
AES-128 was only supported but never negotiated.

## 7. NBOM → runtime dependency

```
Network → Endpoint → Application → Process → Runtime crypto
```

```
443/TLS → Payments API → PID 1821 → OpenSSL → AES-256-GCM
```

Then `NETWORK_OBSERVED` can be distinguished from `RUNTIME_OBSERVED`: network TLS
AES-256-GCM does not prove the application's internal encryption also uses AES-256-GCM.

## 8. NBOM → HSM/KMS dependency

```
Network Endpoint → Application → Crypto Operation → HSM/KMS → Key Metadata
```

```
Payment API → RSA signing → HSM-001 → Key-REF-8271
```

Only metadata: `key_ref`, `algorithm`, `key_size`, `purpose`, `status`, `HSM/KMS`. Never
`private key`, `secret`, `session key`, `plaintext`.

## 9. Network → database dependency

```
Application → Database Endpoint → TLS → Certificate → Crypto
```

```
Payments API → PostgreSQL → 5432 → TLS 1.3 → AES-256-GCM
```

Then distinguish `DB TLS` from `DB TDE`, because they are completely different
cryptographic dependencies.

## 10. Service mesh dependency

```
Internet → LB → API Gateway → Service Mesh → Payments API → Auth Service → DB
```

Capture: mTLS, TLS version, cipher, certificate, trust domain, CA, sidecar/proxy, service
identity.

```
Payments API ↓ mTLS   Envoy sidecar ↓   Auth Service
```

The sidecar may perform TLS, not the application itself. That distinction must exist in
the dependency graph.

## 11. API gateway dependency

```
Client → WAF → LB → API Gateway → Service
```

The gateway should expose TLS termination, mTLS, certificate, cipher policy, upstream
TLS, SNI, ALPN, routing, backend. Then `API Gateway ↓ ROUTES_TO Payments API`, with
evidence.

## 12. WAF dependency

```
Internet → WAF → LB
```

and `WAF ↓ PROTECTS Application`. If the WAF terminates TLS —

```
Client ↓ TLS   WAF ↓ HTTP/TLS   LB
```

— that must be represented separately.

## 13. SSH dependency

```
SSH Endpoint → Host → SSH Server → KEX → Host Key → Cipher → MAC
```

```
server-001:22 → SSH → X25519 → Ed25519 → ChaCha20-Poly1305
```

Then connect `SSH Endpoint → Host → Application/System`.

## 14. VPN / IPsec dependency

```
VPN Gateway → Tunnel → IKE → Encryption → Integrity → DH Group
           → Certificate / PSK metadata → Network Zone
```

```
Branch → IPsec VPN → IKEv2 → AES-256 → SHA-256 → DH Group 19 → Payment Network
```

This should feed NBOM + CBOM + Digital Twin.

## 15. Network topology dependency

Move from an endpoint list to a **network graph**:

```
Internet → WAF-01 → LB-01 → API-GW-01 → MESH-01 → PAYMENTS-API → DB-01 → HSM-01
```

Every edge: `source`, `target`, `relationship`, `protocol`, `port`, `evidence`,
`timestamp`, `confidence`.

## 16. Evidence-backed relationship model

The core improvement. Not `LB-01 → Payments API` alone, but:

```
source: LB-01
relationship: ROUTES_TO
target: Payments API
evidence_id: EVID-92821
evidence_type: CONFIGURED
collector: LB-CONFIG-01
observed_at: timestamp
confidence: HIGH
first_seen: timestamp
last_seen: timestamp
```

This is what makes an NBOM useful for a bank.

## 17. Network dependency lifecycle

`FIRST_SEEN`, `ACTIVE`, `CHANGED`, `SUPERSEDED`, `REMOVED`, `UNKNOWN`. If `LB-01 →
Payments API` was active yesterday and today `LB-01 → New Payments API`, that becomes a
network dependency drift event.

## 18. NBOM → digital twin

```
Network Evidence → Network Assets → Network Relationships → Digital Twin
```

The twin should know: who connects to whom, how, which protocol, which TLS, which
certificate, which crypto, which application, which business system, which HSM/KMS. NBOM
becomes a **network projection**, not an independent database.

## 19. Network → vendor dependency

```
Load Balancer → Vendor → Product → Firmware → Crypto capability
```

```
Vendor X → LB Product 9000 → Firmware 8.2 → LB-001 → TLS termination → Payments API
```

This connects NBOM with VBOM.

## 20. Network → hardware dependency

```
Network Endpoint → Network Device → Physical / Virtual Hardware
```

```
10.10.1.20:443 → LB-001 → Hardware-9281 → Firmware 8.4
```

This connects NBOM with HBOM.

## 21. Coverage must propagate through dependencies

```
Expected endpoints: 500   Observed: 420   Unavailable: 50   Unknown: 30
```

The system must say `NBOM Coverage = PARTIAL`, and downstream: `CBOM network evidence
coverage = PARTIAL`, `Digital Twin network completeness = PARTIAL`. Never silently treat
unavailable network assets as nonexistent.

## 22. Biggest missing dependency chain

```
BUSINESS SYSTEM → APPLICATION → PROCESS → SERVICE → ENDPOINT → WAF → LB
                → API GATEWAY → SERVICE MESH → DATABASE → HSM/KMS
                → CRYPTO ASSET → VENDOR
```

With network-specific relationships: `CONNECTS_TO`, `ROUTES_TO`, `TERMINATES_TLS`,
`RE_ENCRYPTS`, `PASSTHROUGH`, `PROTECTS`, `AUTHENTICATES`, `USES_CERTIFICATE`, `USES_HSM`,
`USES_KMS`. And evidence on every edge.

---

A second read of the same text found nine things the first pass had answered only in
prose — the ids the review asks for, routes rather than edges, `CONFIGURED` as a state of
its own, the runtime/network comparison as an operation, evidence records on network
edges, exposure, the vendor's capability, history, and coverage per segment. Each is now
built, and guide 170 (`docs/bank-environment/170-nbom-gaps.md`,
**11 pass · 0 partial · 0 fail**) measures it.
