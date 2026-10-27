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
4. **Steps 3-5** — service discovery + TLS observation schema + cipher decomposition. **[done]** for TLS (`POST …/crypto-observe`, evidence schema `cryptoscan.network-evidence/1`) and for protocol detection (§5): `discovery/protocol_detector.py` asks the endpoint what it speaks instead of trusting the port — TLS ClientHello, SSH banner prefix, PostgreSQL/MySQL SSL question, MongoDB/Redis/Kafka/TLS-prefix starters — and returns `{detected, detection_method: TLS_HANDSHAKE|BANNER|SSL_REQUEST|HANDSHAKE_PACKET|NO_RESPONSE, confidence, service_guess, port_matches_protocol, attempts[], limitations[]}`. `POST …/crypto-probe` runs detect → observe in one approved operation, and re-checks scope **per detected protocol**, so a TLS approval never silently authorises an SSH banner grab (`scope_refusals[]`).
5. **Steps 6-9** — cert chain/mTLS, SSH, IPsec. **[done]** certificate chain/trust, mTLS as *not required* vs unobservable, SSH host-key/KEX, and IPsec IKEv2 SA_INIT with full payload walking — SA proposals, KE group, NOTIFY refusals (`NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`) and ESP proposals when the responder volunteers them → `NETWORK_ACTIVE_OBSERVED` evidence plus `ike-*`/`esp-*` CBOM roles. **[done]** for SSH transport (§12) and database transport (§18) projections: `inventory/protocol_evidence.py` turns an approved SSH handshake into `ssh.negotiated={}`, `negotiation_status=NOT_NEGOTIATED`, `algorithms_offered{kex,host_keys,ciphers,macs}`, `host_keys[]` (public key only) plus `policy_issues`, and a database TLS attempt into `observation_status=TLS_HANDSHAKE|TLS_REFUSED`, `database.transport{tls_negotiated,ssl_supported}` with `tde`, `column_encryption` and `runtime_operations` pinned to `NOT_OBSERVED` (`DB_TRANSPORT_TLS_NOT_OFFERED`, limitation `DATABASE_OUT_OF_REACH`) — transport crypto is never reported as table/TDE crypto (§18, §27). **[open]** — IKEv1, and ESP/PFS *in use* (those are negotiated in IKE_AUTH, which CryptoScan deliberately never performs, so they stay `NOT_OBSERVED`).
6. **Steps 10-12** — LB/API-gw/mesh hop graph + correlation engine separation. **[done]** — `POST …/crypto-path` returns a `attribution` block: declared-or-inferred hop roles, segment kinds (client→edge, edge→internal, mesh sidecar path, service→data), TLS termination verdicts derived only from *differing observed certificate fingerprints* (`PASS_THROUGH` vs `TERMINATES_AND_REORIGINATES` vs `UNDETERMINED`), and sidecar crypto explicitly labelled as not-application crypto. `POST …/crypto-correlate` joins STATIC + RUNTIME + NETWORK on service/host/endpoint identity and compares only same-artifact facts (declared vs negotiated TLS version, configured vs presented fingerprint, mTLS policy vs observed requirement); everything else is `NOT_COMPARABLE` with a reason. **[done]** for Kubernetes: `POST …/crypto-correlate`'s sibling `POST …/kubernetes-correlate` maps Ingress/Service/Pod manifests to endpoints, annotates them only with matched observation evidence, marks sidecar containers, and keeps declared TLS as `NETWORK_CONFIGURED` / unobserved hops as `UNKNOWN`. **[open]** — live Kubernetes/cloud API discovery (manifests are still supplied or imported).
7. **Remaining** — policy, dashboard, safety guards. **[done]** — traffic budget metering (`GET …/crypto-budget`, rolling 24 h), 24/7 scope-bound worker (`/network/crypto-watch` start/stop/status/tick), transport CBOM projection (`GET …/crypto-cbom`), message-layer crypto (`POST …/message-layer-observe`, `GET …/message-layer-evidence` — SASL ≠ message encryption, payload crypto `DECLARED` or `UNKNOWN` only), and a tamper-evident evidence hash chain (`GET …/crypto-evidence/integrity`, `GET …/crypto-evidence/chained`) that detects modified, deleted or re-ordered records. Safety STOP (§30): `GET …/crypto-safety` + `POST …/crypto-stop` engage a tenant-local kill switch — every active path (probe, observe, IPsec, SSH, watch tick) returns `409 network_observation_stopped` while passive metadata ingest and config import keep working (`distributed:false`), so an IDS alert means STOP/ESCALATE, never disabling the IDS. Frontend: `Network.tsx` carries the safety switch, a detection panel (protocol, mismatches, attempts) and the SSH/database evidence views. **[open]** — external anchoring/signature for the chain (it is currently `local-database-only`), distributed scheduling, and policy packs over the correlated estate.

Each step adds API + scanner + normalizer + CBOM/NBOM mapping with `UNKNOWN≠SAFE` honesty.

## Section-by-section status

`done` = implemented and tested on `arena/bb4b80dd-cryproscan`; `partial` = implemented with a named
limit; `open` = not built. "Done" never means "proves everything" — §29 lists what a network scan
cannot see, and every response carries its own limitations.

| § | Capability | Status | Where / limit |
|---|---|---|---|
| 1 | Purpose: who speaks what, TLS version, cipher, cert, KEX, auth, exposure | done | `POST /network/crypto-observe`, `POST /network/crypto-probe` |
| 2 | Scope → discovery → protocol → TLS/SSH/IPsec → evidence → normalize → CBOM/NBOM/TechBOM → risk → dashboard | done | router + inventory modules + `Network.tsx` |
| 3 | Explicit approved scope (destinations/ports/protocols/operations/budget/valid_until) | done | `api/security/network_scope.py`, CIDR sweeps refused |
| 4 | Discovery sources: inventory / approved active / passive | partial | import + passive + approved active; **open**: live CMDB/K8s/cloud collectors |
| 5 | Port ≠ protocol, detect from the response | done | `discovery/protocol_detector.py`, `port_matches_protocol` |
| 6 | TLS observation (version, suite, KEX, group, cert, ALPN, SNI, mTLS) | done | `probing/tls_handshaker.py` → evidence |
| 7 | TLS 1.3 cipher decomposition | done | `decomposition{}` on every record |
| 8 | TLS 1.2 decomposition (KEX / auth / bulk / PRF) | done | same, per-record |
| 9 | Certificate discovery (public key only) | done | `certificates/cert_extractor.py` |
| 10 | Full chain root → intermediate → leaf | done | `chain_order.py`, `chain_validator.py` |
| 11 | mTLS: required vs not requested | done | `mutual_tls` + `mtls_evidence` |
| 12 | SSH KEX / host key / cipher / MAC | done | `probing/ssh_kex.py`, offer ≠ negotiation |
| 13 | IPsec / IKE / ESP | partial | IKEv2 SA_INIT, notifies, KE; **open**: IKEv1 and ESP/PFS *in use* (IKE_AUTH) |
| 14 | Routers / firewalls / LB / VPN / SD-WAN crypto, read-only | done | `inventory/network_devices.py`, `POST /network/device-inventory`, no write path, credentials rejected |
| 15 | Load balancer: external vs internal TLS, pass-through vs re-origination | done | `build_crypto_path` + attribution on `/network/crypto-path` |
| 16 | API gateway / service-mesh hops | done | hop roles, declared or inventory-imported |
| 17 | Service mesh sidecar ≠ application crypto | done | sidecar labelled in K8s correlation and hop attribution |
| 18 | Database transport vs TDE | done | `inventory/protocol_evidence.py` (`DB_TRANSPORT_TLS_NOT_OFFERED`, TDE `NOT_OBSERVED`) |
| 19 | Kafka / MQ: transport vs message encryption | done | `inventory/message_layer.py`, `POST /network/message-layer-observe` |
| 20 | Kubernetes ingress/service/pod correlation | done | `POST /network/kubernetes-correlate` |
| 21 | Cloud endpoints (LB / API GW / private endpoint / KMS) | partial | `POST /network/cloud-correlate` from caller-supplied metadata; **open**: read-only cloud API collectors |
| 22 | Passive TAP/SPAN metadata-only | done | `POST /network/crypto-passive`, strict field whitelist, `NOT_OBSERVED ≠ NO_CRYPTO` |
| 23 | Evidence taxonomy (7 values) | done | `cryptoscan.network-evidence/1` |
| 24 | Evidence record (target, protocol, params, cert, mTLS, scope revision) | done | `inventory/network_evidence.py` |
| 25 | Network crypto graph (path, not a list) | done | `POST /network/crypto-path` |
| 26 | Static + Runtime + Network correlation | done | `POST /network/crypto-correlate`, same-artifact comparisons only |
| 27 | NETWORK ≠ APPLICATION ≠ RUNTIME ≠ STORAGE ≠ HSM | done | every asset/finding carries its layer; cross-role comparisons refused |
| 28 | CBOM / NBOM / TechBOM with context + evidence ID | done | `POST /network/crypto-nbom` (CycloneDX 1.5), `GET /network/crypto-cbom` |
| 29 | Explicit limitations; UNKNOWN is a valid result | done | per-record `limitations[]`, report-level limitations, coverage gaps |
| 30 | Safety: scope, budget, stop, escalation, never disable IDS | done | `api/security/network_safety.py`, `POST /network/crypto-stop` (local, `distributed:false`) |
| 31 | Policy / risk, PQC readiness, drift, dashboard | partial | `POST /network/crypto-risk` (baseline pack + PQC), `GET /network/scan-drifts`; **open**: threat-intelligence enrichment, external chain anchoring |

Still open, in priority order: live cloud/Kubernetes collectors (the current paths accept
caller-supplied metadata), IKEv1, ESP/PFS *in use*, hash-chain anchoring outside the local
database, and distributed scheduling (both safety and the chain are single-node today).
