# Network Crypto Discovery Engine — Cryptographic Network Intelligence

> **Status:** Design spec stored 2026-10-27 · Step-by-step build in progress on `arena/bb4b80dd-cryproscan`  
> **Purpose:** Network scan at same depth as static/runtime, but for **network-la actual-a entha endpoint/system/device enna protocol, TLS version, cipher, certificate, key exchange, authentication, service exposure use pannudhu** — not a generic port scanner.

Yes. **Network scan**-um static/runtime madhiri same depth-la design panna vendum. Aana important difference:

- **Static scan** → files/config/source-la enna crypto irukku?
- **Runtime scan** → process actually enna crypto operation pannudhu?
- **Network scan** → network-la actual-a **entha endpoint/system/device enna protocol, TLS version, cipher, certificate, key exchange, authentication, service exposure** use pannudhu?

CryptoScan-ku network scanner should be a **Cryptographic Network Intelligence / Network Crypto Discovery Engine**, generic port scanner mattum illa.

---

## 1. Network Scan oda main purpose

Bank network-la:

```text
Client
   ↓
Load Balancer
   ↓
API Gateway
   ↓
Application
   ↓
Database
   ↓
HSM / KMS
```

Network scan answer panna vendiya questions:

```text
1. Enna hosts reachable?
2. Enna ports/services exposed?
3. Enna protocol?
4. TLS use pannudha?
5. TLS version enna?
6. Cipher suite enna?
7. Key exchange enna?
8. Server certificate enna?
9. Certificate public-key algorithm enna?
10. Certificate key size / curve enna?
11. Signature algorithm enna?
12. mTLS enabled-aa?
13. SSH enna KEX/cipher/MAC use pannudhu?
14. VPN/IPsec enna crypto use pannudhu?
15. Weak/deprecated crypto irukka?
16. Same endpoint different paths-la different crypto use pannudha?
17. Asset → service → application mapping enna?
18. Evidence exact-a enna prove pannudhu?
```

---

## 2. High-level architecture

```text
                 BANK NETWORK
                      │
             Scope + Authorization
                      │
          ┌───────────┴───────────┐
          │                       │
     Network Discovery      Approved Targets
          │                       │
          └───────────┬───────────┘
                      ↓
              Service Discovery
                      ↓
              Protocol Detection
                      ↓
        ┌─────────────┼──────────────┐
        ↓             ↓              ↓
       TLS           SSH           IPsec/VPN
        ↓             ↓              ↓
 Cipher/Cert       KEX/MAC       IKE/ESP
        │             │              │
        └─────────────┼──────────────┘
                      ↓
             Crypto Observation
                      ↓
              Evidence Engine
                      ↓
             Crypto Normalizer
                      ↓
        ┌─────────────┼──────────────┐
        ↓             ↓              ↓
      CBOM          NBOM          TechBOM
                      ↓
             Risk / Policy Engine
                      ↓
                  Dashboard
```

---

## 3. First: Network scope

Bank network-na direct-a:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

nu scan panna koodadhu.

CryptoScan should have **explicit approved scope**.

Example:

```yaml
target:
  name: payments-prod
  type: network
  destinations:
    - 10.20.10.15:443
    - 10.20.10.16:443
    - 10.20.20.10:8443
  protocols:
    - TLS
  allowed_operations:
    - CONNECT
    - TLS_HANDSHAKE
    - CERTIFICATE_READ
  traffic_budget:
    max_connections: 20
    max_bytes: 10485760
  valid_until: 2026-10-25T18:00:00Z
```

Meaning: **"Indha exact destination, indha exact port, indha exact protocol, indha exact time window mattum observe pannu."**

---

## 4. Network discovery

Possible sources:

### A. Bank-provided inventory (best)
CMDB / Asset inventory / DNS / Load balancer inventory / Kubernetes / Cloud / NMS

### B. Approved active discovery
`host → approved probe → response`

### C. Passive observation
SPAN/TAP / PCAP metadata / telemetry / LB logs / proxy logs / firewall flow logs

Distinguish: `ACTIVE_OBSERVED | PASSIVE_OBSERVED | CONFIG_IMPORTED | DECLARED | UNKNOWN`

---

## 5. Port/service discovery

Port number ≠ protocol. `8443 ≠ automatically HTTPS`. Detect protocol from actual response/handshake where authorized.

---

## 6. TLS network scanning

Observe: `TLS version, Cipher suite, Key exchange, Authentication, Server certificate, Chain, Signature algorithm, Public-key algorithm/size, Curve, Supported versions/ciphers, ALPN, SNI, mTLS`

Example:

```json
{
  "host": "10.20.10.15",
  "port": 443,
  "protocol": "TLS",
  "tls_version": "TLS1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "key_exchange": "ECDHE",
  "named_group": "X25519",
  "certificate_public_key": "ECDSA",
  "certificate_curve": "P-256",
  "certificate_signature": "ECDSA-SHA256",
  "mutual_tls": false,
  "evidence_type": "NETWORK_OBSERVED"
}
```

---

## 7. TLS cipher suite decomposition

`TLS_AES_256_GCM_SHA384` → TLS 1.3 / AES-256-GCM / X25519 / certificate ECDSA P-256 / SHA-384

---

## 8. TLS 1.2

`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` → TLS 1.2 / ECDHE / RSA / AES-256-GCM / SHA-384 — then evaluate `TLS<1.2, weak cipher, RSA<2048, weak sig, deprecated hash, weak DH`.

---

## 9. Certificate discovery

Public cert fields: Subject/Issuer/Validity/Public Key/Signature/SAN/Key Usage/EKU. **Public key ≠ private key — never need private key.**

---

## 10. Certificate chain

Root → Intermediate → Leaf; CBOM must understand full trust chain.

---

## 11. mTLS

Detect: mTLS enabled, client cert requested/accepted, server+client cert metadata, CA chain. NO private key / plaintext / customer data.

---

## 12. SSH network scan

`22/tcp` → `KEX: curve25519-sha256 | Host key: ssh-ed25519 | Cipher: chacha20-poly1305 | MAC: implicit/AEAD` vs weak `diffie-hellman-group14-sha1 / ssh-rsa / aes128-cbc / hmac-sha1`.

---

## 13. IPsec / VPN

IKE Phase 1 (Auth/Enc/Integrity/DH) + ESP (Enc/Integrity) normalized, e.g. IKEv2 / AES-256-GCM / AEAD / DH19 / Certificate.

---

## 14. Network devices

Router/Firewall/LB/ADC/VPN-GW/Proxy/API-GW/WAF/SD-WAN — read-only, crypto props: TLS/SSH/IPsec/IKE/SNMP/certs/mgmt-plane/VPN/mTLS.

---

## 15. Load Balancer

TLS may terminate at LB. Must identify **External TLS → LB → Internal TLS → Application** as crypto hop graph.

---

## 16. API Gateway

Observe separately: `Client→Gateway | Gateway→Service | Service→Service` (different TLS/cipher/cert/mTLS/trust).

---

## 17. Service Mesh

Correlate Service → Pod → Sidecar → TLS session → Certificate → Crypto params. Sidecar crypto ≠ app crypto.

---

## 18. Database network crypto

Network = transport crypto (TLS version/cipher/cert/mTLS). DB collector = TDE/column encryption. Runtime = actual op.

---

## 19. Kafka / MQ

Transport encryption ≠ Message encryption. Network observes TLS/mTLS/cipher/cert/SASL.

---

## 20. Kubernetes network

Correlate IP/Port/Service/Namespace/Pod/Container/Image/Ingress/Gateway/Certificate/TLS.

---

## 21. Cloud network endpoints

LB/API-GW/Ingress/Private Endpoint/VPN GW/KMS — Cloud API declaration ≠ network observation.

---

## 22. Passive observation

TAP/SPAN → metadata-only sensor → TLS/SSH/IPsec metadata → CryptoScan. Store timestamp/src/dst/protocol/port/TLS version/cipher/fingerprint/JA3/handshake, never payload/password/private key/customer data. `No observed traffic ≠ No crypto → NOT_OBSERVED`.

---

## 23. Active vs passive evidence

`NETWORK_ACTIVE_OBSERVED | NETWORK_PASSIVE_OBSERVED | NETWORK_CONFIGURED | CERTIFICATE_OBSERVED | VENDOR_DECLARED | IMPORTED | UNKNOWN`

---

## 24. Network evidence record

```json
{
  "evidence_type": "NETWORK_ACTIVE_OBSERVED",
  "target": { "host": "10.20.10.15", "port": 443 },
  "protocol": "TLS",
  "tls_version": "TLS1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "key_exchange": { "algorithm": "X25519" },
  "certificate": {
    "fingerprint_sha256": "sha256:...",
    "public_key_algorithm": "ECDSA",
    "curve": "P-256",
    "signature_algorithm": "ECDSA-SHA256"
  },
  "mtls": false,
  "timestamp": "...",
  "scanner_version": "...",
  "scope_revision": "...",
  "evidence_id": "..."
}
```

---

## 25. Network crypto graph

```
Internet Client —TLS1.3/AES-256-GCM/X25519→ WAF —TLS1.2/AES-256-GCM/ECDHE-RSA→ API Gateway —mTLS/TLS1.3→ Payments Service —TLS1.3→ PostgreSQL
```

---

## 26. Static + Runtime + Network correlation

Static (source/config/deps/binaries) + Runtime (processes/HSM/KMS/ops) + Network (endpoints/TLS/SSH/IPsec/mTLS) → Evidence → Normalization → Correlation → CBOM/NBOM/TechBOM → Risk/Policy → PQC/Drift → Dashboard. Each layer is a distinct fact.

---

## 27. Don't mix layers

`TLS AES-256-GCM` = transport encryption, not proof that application uses `AES-256` internally. Keep separate: `NETWORK ≠ APPLICATION ≠ RUNTIME ≠ STORAGE ≠ HSM/KMS`.

---

## 28. Network scan output to CBOM

CBOM assets like `TLS_AES_256_GCM_SHA384, X25519, ECDSA P-256, RSA-2048, SHA-256` with context `{system, service, endpoint, host, port, protocol, role, algorithm, key size, curve, mode, certificate, evidence ID, timestamp, evidence type, confidence}`.

---

## 29. Network scan limitations

Cannot prove from network alone: internal AES, private key size not exposed, HSM/KMS internals, DB TDE, storage encryption, offline ops, unused ciphers, never-observed traffic, custom payload. Return `UNKNOWN`, not `SAFE`.

---

## 30. Safety architecture

Authorization → Exact destination/port/protocol/operation → Traffic budget → Observation → Evidence. STOP on unexpected destination/port, scope expired, unauthorized protocol, budget exceeded, degradation, IDS/SOC incident, secret exposure, integrity failure, wrong-estate access. `IDS alert → STOP/ESCALATE/CORRELATE`, never disable IDS.

---

## 31. Final CryptoScan architecture

```
                         ZELNX CRYPTOSCAN
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ↓                  ↓                  ↓
        STATIC SCAN        RUNTIME SCAN       NETWORK SCAN
             │                  │                  │
       Source/config        Processes          Endpoints
       Dependencies         Libraries          TLS
       Binaries             Crypto APIs        SSH
       Containers           HSM/KMS            IPsec
       Kubernetes           Runtime ops        VPN
       Cloud                Frameworks         mTLS
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ↓
                       EVIDENCE ENGINE
                                ↓
                     NORMALIZATION ENGINE
                                ↓
                      CORRELATION ENGINE
                                ↓
              ┌─────────────────┼─────────────────┐
              ↓                 ↓                 ↓
             CBOM              NBOM             TechBOM
              │                 │                 │
              └─────────────────┼─────────────────┘
                                ↓
                        POLICY / RISK
                                ↓
                     PQC READINESS / DRIFT
                                ↓
                         THREAT INTELLIGENCE
                                ↓
                            DASHBOARD
```

---

## Build steps

Status legend: **[done]** shipped on `arena/bb4b80dd-cryproscan`, **[partial]**, **[open]**.

1. **Spec file** — this document. **[done]**
2. **Step 1 scope model** — explicit approved scope with `destinations, protocols, allowed_operations, traffic_budget, valid_until` (fail-closed). **[done]** — `GET/PUT /api/v1/network/crypto-scope`, `POST …/validate`; `api/security/network_scope.py::check_scope` is the single decision used by observation *and* the legacy scan/due/SSH paths (CIDR sweeps are refused under a scope).
3. **Step 2 discovery taxonomy** — bank inventory / approved active / passive → evidence taxonomy. **[partial]** — `POST …/crypto-scope/import` (CMDB/LB/K8s/cloud/firewall/DNS) produces `CONFIG_IMPORTED` candidates with provenance and zero probing; `POST …/crypto-passive` ingests metadata-only sensor rows under a strict field whitelist. Kubernetes/cloud auto-discovery is **open**.
4. **Steps 3-5** — service discovery + TLS observation schema + cipher decomposition. **[done]** for TLS (`POST …/crypto-observe`, evidence schema `cryptoscan.network-evidence/1`), **[partial]** for service discovery (registry-based naming, no fingerprinting of unknown services).
5. **Steps 6-9** — cert chain/mTLS, SSH, IPsec. **[done]** certificate chain/trust, mTLS as *not required* vs unobservable, SSH host-key/KEX, and IPsec IKEv2 SA_INIT with full payload walking — SA proposals, KE group, NOTIFY refusals (`NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`) and ESP proposals when the responder volunteers them → `NETWORK_ACTIVE_OBSERVED` evidence plus `ike-*`/`esp-*` CBOM roles. **[open]** — IKEv1, and ESP/PFS *in use* (those are negotiated in IKE_AUTH, which CryptoScan deliberately never performs, so they stay `NOT_OBSERVED`).
6. **Steps 10-12** — LB/API-gw/mesh hop graph + correlation engine separation. **[done]** — `POST …/crypto-path` returns a `attribution` block: declared-or-inferred hop roles, segment kinds (client→edge, edge→internal, mesh sidecar path, service→data), TLS termination verdicts derived only from *differing observed certificate fingerprints* (`PASS_THROUGH` vs `TERMINATES_AND_REORIGINATES` vs `UNDETERMINED`), and sidecar crypto explicitly labelled as not-application crypto. `POST …/crypto-correlate` joins STATIC + RUNTIME + NETWORK on service/host/endpoint identity and compares only same-artifact facts (declared vs negotiated TLS version, configured vs presented fingerprint, mTLS policy vs observed requirement); everything else is `NOT_COMPARABLE` with a reason. **[open]** — automatic hop discovery from Kubernetes/cloud APIs (hops are still declared or inventory-imported).
7. **Remaining** — policy, dashboard, safety guards. **[done]** — traffic budget metering (`GET …/crypto-budget`, rolling 24 h), 24/7 scope-bound worker (`/network/crypto-watch` start/stop/status/tick), transport CBOM projection (`GET …/crypto-cbom`), message-layer crypto (`POST …/message-layer-observe`, `GET …/message-layer-evidence` — SASL ≠ message encryption, payload crypto `DECLARED` or `UNKNOWN` only), and a tamper-evident evidence hash chain (`GET …/crypto-evidence/integrity`, `GET …/crypto-evidence/chained`) that detects modified, deleted or re-ordered records. **[open]** — external anchoring/signature for the chain (it is currently `local-database-only`), distributed scheduling, and policy packs over the correlated estate.

Each step adds API + scanner + normalizer + CBOM/NBOM mapping with `UNKNOWN≠SAFE` honesty.
