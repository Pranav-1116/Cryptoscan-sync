# NBOM review — network coverage, discovery states, topology

*Review received 2026-11-02. Saved verbatim in substance; each numbered item is the
reviewer's, and the "what this increment does" line is ours.*

Scope: the Network BOM (`GET /api/v1/cbom/nbom`), its collection path, and the
projections it feeds (CBOM, digital twin). The review's overall verdict is that the
collection path and the negative logic are right, and that the maturity gap is in
**coverage**, **discovery states**, **topology** and **change**.

---

## 1. What is already implemented

The collection path is real:

```
Authorized network collector
        ↓
Network observation
        ↓
Persisted probe record
        ↓
Recent-run ledger
        ↓
NBOM
        ↓
/nbom UI
```

Documented API: `GET /api/v1/cbom/nbom`, and it **does not perform a scan** — it
builds the estate view from stored network observations. That is the correct
architecture: `SCAN → OBSERVATION → STORE → NBOM PROJECTION`, never
`GET /nbom → start network scan`.

## 2. Listener discovery is good

An NBOM can represent `partner-gateway.bank.example:443` with endpoint, protocol,
port, TLS version, negotiated cipher, certificate and observation time. Already
useful.

## 3. Negative logic is very good

The strongest part of the current design: `timeout → UNKNOWN / NOT OBSERVED`, never
`plaintext`. Likewise, modern TLS observed ≠ all weak TLS disabled — that needs a
separate, authorized capability-enumeration operation.

## 4. Biggest NBOM weakness: "observed endpoint" is not "complete network inventory"

Critical. If an estate has 10,000 endpoints and 6,500 are observed, the NBOM must
not imply it is the bank's complete network. It must say:

```
expected 10,000 · attempted 8,000 · observed 6,500 · failed 1,000
unauthorized 500 · coverage 65% · status PARTIAL
```

This should become a first-class NBOM coverage model.

## 5. An estate network coverage matrix

| Target | Expected | Attempted | Observed | Status |
|---|---|---|---|---|
| External endpoints | 120 | 120 | 118 | PARTIAL |
| Internal LB | 25 | 25 | 25 | COMPLETE |
| API gateways | 40 | 40 | 37 | PARTIAL |
| DB endpoints | 80 | 60 | 54 | PARTIAL |
| HSM network interfaces | 8 | 8 | 8 | COMPLETE |
| VPN gateways | 12 | 10 | 9 | PARTIAL |

It should connect to the existing collection-coverage architecture.

## 6. TLS discovery is one of the strongest NBOM capabilities

Protocol negotiation is parsed rather than packets searched: ClientHello →
ServerHello → Certificate → negotiated parameters → evidence, yielding TLS 1.3,
AES-256-GCM, X25519, ECDSA-P256, ECDSA-SHA256. CycloneDX's discovery lifecycle
concept is consistent with point-in-time network discovery rather than a permanent
runtime truth.

## 7. Supported vs configured vs negotiated must be three states

`SUPPORTED`, `CONFIGURED`, `NEGOTIATED` — e.g. supported TLS 1.2 and 1.3,
configured TLS 1.2+, negotiated TLS 1.3. "TLS 1.2 supported" does not mean "TLS 1.2
in use", and "TLS 1.3 negotiated" does not prove it is the only supported protocol.
This should be enforced in the data model.

## 8. Cipher suite decomposition should be first-class

`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` → protocol TLS 1.2, key exchange ECDHE,
authentication RSA, encryption AES-256-GCM, hash SHA-384.
`TLS_AES_256_GCM_SHA384` → protocol TLS 1.3, encryption AES-256-GCM, hash SHA-384,
key exchange X25519 *separately evidenced from the selected group*.

## 9. Certificate inventory needs deeper correlation

Endpoint → certificate → public key → algorithm → key size/curve → signature
algorithm → issuer → validity → trust chain, e.g. CERT-9281 with ECDSA P-256,
ECDSA-SHA256, issuer BANK-ICA-01, expiry, SAN. Better evidence for CBOM and PKI
intelligence.

## 10. Load balancers are a major gap

The NBOM should understand Internet → WAF → External LB → API Gateway → service
mesh → application, not just "443 open".

## 11. TLS termination / re-encryption must be represented

Client —TLS 1.3/AES-256-GCM→ External LB —TLS 1.2/AES-128-GCM→ API Gateway —
TLS 1.3/AES-256-GCM→ Payments API: three network crypto observations, not
"Payments API → AES-256-GCM", because the first hop belongs to the LB.

## 12. Network topology is incomplete

Relationships: `CONNECTS_TO`, `ROUTES_TO`, `TERMINATES_TLS`, `RE_ENCRYPTS`,
`PASSTHROUGH`, `PROTECTED_BY`, `USES_CERTIFICATE`, `USES_HSM`, `USES_KMS`. Every
relationship needs `evidence_id`, `observed_at`, `source`, `confidence` — otherwise
the topology is fiction.

## 13. SSH needs more depth

SSH version, KEX, host-key algorithm, cipher, MAC, server host key — and the
difference between *advertised* and *negotiated*.

## 14. VPN/IPsec needs its own collector

IKEv1/IKEv2, IPsec/ESP with encryption, integrity, DH group, authentication,
certificate, tunnel, peer — flowing into NBOM → CBOM → PQC analysis.

## 15. Passive observation is a major future capability

SPAN/TAP → passive sensor → protocol metadata → TLS/SSH/IKE parser → observation.
Never store payloads by default; store source, destination, port, protocol, TLS
version, cipher, certificate fingerprint, SNI, ALPN, timestamp, evidence.

## 16. NBOM → CBOM is a major opportunity

`payments.bank.example:443` with TLS 1.3 / AES-256-GCM / X25519 / ECDSA-P256 becomes
CBOM evidence with `source: NETWORK_OBSERVED`. It must **not** become "Payments API
internally uses AES-256-GCM" without runtime or static evidence — network evidence
proves the negotiated transport crypto.

## 17. NBOM → digital twin is incomplete

Network observation → endpoint identity → network asset → application/service →
system → business system, every relationship evidence-backed. Not
"same hostname = same application".

## 18. NBOM should become change-driven

`OBSERVE → NORMALIZE → HASH → COMPARE → CHANGE?` applied to network state:
TLS 1.3 → TLS 1.2, AES-256 → AES-128, new certificate → a
`NETWORK_CRYPTO_REGRESSION` finding carrying before, after, endpoint,
evidence_before, evidence_after, timestamp, affected systems, severity, and what is
*not* proven.

## 19. Attack detection becomes possible — as correlated pattern

TLS downgrade + certificate mutation + new endpoint + new process is a
`CORRELATED_PATTERN` at `SUSPICIOUS_ACTIVITY`, never "attack detected"; compromise,
attribution and intent stay unproven.

## 20. NBOM needs network asset identity

Not `IP:port` — IPs change. Stable identity from asset id, hostname, service
identity, certificate fingerprint, SNI, interface, device id, collector source,
environment, location. E.g. `NET-001928`, type `LOAD_BALANCER`, hostname
`ext-lb-prod-01`, IPs `10.20.1.10`/`10.20.1.11`, cert `CERT-9281`, environment
`PRODUCTION`, zone `DMZ`.

## 21. Historical NBOM needs improvement

Keep snapshots and compare: endpoint added/removed, port changed, certificate
changed, TLS version changed, cipher changed, SNI changed, ALPN changed, trust path
changed. `TLS 1.3 / AES-256` on 2026-11-01 against `TLS 1.2 / AES-128` on 2026-11-02
is a `CRYPTOGRAPHIC_REGRESSION` — a strong signal, not a conclusion.

---

## Where the code stands

| Item | State before this round | Owner |
|---|---|---|
| 1–3 collection path, negative logic | implemented, documented | `cbom.nbom`, `routers/cbom.py` |
| 4, 5 coverage model and matrix | **done in this round** | guide 153 (`cbom.nbom_coverage`) |
| 6 TLS negotiation evidence | implemented | `network_scanner`, `cbom.usage_collectors` |
| 7 supported/configured/negotiated | **done in this round** | guide 154 (`cbom.tls_state`) |
| 8 suite decomposition | **done in this round** | guide 158 (`cbom.cipher_suite`); parsing stays in `usage_collectors` |
| 9 certificate correlation | **done in this round** | guide 159 (`cbom.certificate_chain`) |
| 10, 11 fronting hops and termination | implemented | guides 148, 149 (`network_assets`, `termination_paths`) |
| 12 topology with evidence | **done in this round** | guide 160 (`cbom.topology`); `usage_graph` keeps the graph-engine edges |
| 13 SSH depth | not implemented | open |
| 14 VPN/IPsec | not implemented | open |
| 15 passive observation | not implemented | open (privacy contract required) |
| 16 NBOM → CBOM | implemented | guide 148 |
| 17 NBOM → twin | implemented | guide 152 |
| 18, 21 change and snapshots | **done in this round** | guide 155 (`cbom.nbom_history`) |
| 19 correlated pattern | **done in this round** | guide 157 (`cbom.network_patterns`) |
| 20 network asset identity | **done in this round** | guide 156 (`cbom.network_identity`) |

The "call made here" line for each of the new guides lives in the guide itself; this
file is the review as received, plus the ownership table above.
