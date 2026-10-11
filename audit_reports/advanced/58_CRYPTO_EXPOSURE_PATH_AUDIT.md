# 58_CRYPTO_EXPOSURE_PATH_AUDIT.md
## ZELNX CryptoScan — Cryptographic Exposure Path Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of exposure path tracing capabilities — from Internet through network, application, dependencies to cryptographic implementation  
**Scope:** Complete exposure path tracing — Internet → Network → Endpoint → Application → Dependency → Crypto Implementation → Weak Algorithm

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX trace a complete exposure path from Internet to weak cryptography?"*

**Answer:** **NO** — ZELNX can trace **fragments** but **not complete end-to-end exposure paths**.

| Path Segment | Traceable? | Score |
|--------------|------------|-------|
| Internet → Network Edge | ✅ Yes | 8/10 |
| Network Edge → Load Balancer | ⚠️ Partial | 4/10 |
| Load Balancer → Application | ❌ No | 1/10 |
| Application → Code Function | ❌ No | 1/10 |
| Code Function → Crypto API | ❌ No | 1/10 |
| Crypto API → Algorithm | ✅ Yes | 8/10 |
| Algorithm → Key Size/Mode | ✅ Yes | 8/10 |
| Application → Library | ⚠️ Partial | 4/10 |
| Library → Algorithm | ⚠️ Partial | 4/10 |
| Certificate → TLS Endpoint | ❌ No | 2/10 |
| Certificate → Application | ❌ No | 2/10 |
| Network Flow → Crypto | ❌ No | 1/10 |
| Application → Certificate | ❌ No | 2/10 |
| Application → Key | ❌ No | 1/10 |
| Data Flow → Crypto | ❌ No | 1/10 |

**Overall: 2.5/10** — Can trace fragments but not complete exposure paths

---

## 1. EXPOSURE PATH MODEL — CURRENT STATE

### 1.1 Current Tracing Capabilities

| Path Segment | Traceable? | Method |
|--------------|------------|--------|
| **Internet → Network Edge** | ✅ | Network scanner active probe |
| **Network Edge → TLS Endpoint** | ✅ | Network scan probe result |
| **TLS Endpoint → Certificate** | ✅ | Certificate chain extraction |
| **Certificate → Algorithm/Key** | ✅ | X.509 parsing |
| **Network Probe → Cipher Suite** | ✅ | ServerHello parsing |
| **Cipher Suite → Algorithm** | ✅ | IANA registry mapping |
| **Source Code → Algorithm** | ✅ | AST parsing |
| **Source Code → Key Size/Mode** | ✅ | AST + extractors |
| **Binary → Algorithm** | ⚠️ Partial | Strings + disassembly |
| **Container → Algorithm** | ✅ | Layer scan + SBOM |
| **Cloud Config → Algorithm** | ✅ | Cloud API |
| **Runtime → Algorithm** | ⚠️ Partial | LD_PRELOAD / eBPF |

### 1.2 Broken Paths — Cannot Trace

| Broken Path | Missing Link |
|-------------|--------------|
| **Internet → Load Balancer → App** | LB → App mapping missing |
| **Load Balancer → TLS Termination** | LB → TLS config not linked |
| **TLS Termination → App Code** | TLS config → App code not linked |
| **App Code → Crypto Function** | Code → Crypto function not traced |
| **Crypto Function → Library** | Function → Library not traced |
| **Library → Algorithm Implementation** | Library → Algorithm not traced |
| **Certificate → TLS Endpoint** | Cert → Endpoint mapping missing |
| **Certificate → Application** | Cert → App mapping missing |
| **Network Flow → Crypto** | Flow → Crypto not traced |
| **Application → Certificate** | App → Cert mapping missing |
| **Application → Key** | App → Key mapping missing |
| **Data Flow → Crypto** | Data flow → Crypto not traced |
| **Container → Host Crypto** | Container → Host crypto not linked |
| **K8s Service → Pod Crypto** | Service → Pod crypto not linked |
| **Service Mesh → Crypto** | Mesh crypto not traced |

---

## 2. REQUIRED EXPOSURE PATH MODEL

### 2.1 Complete Exposure Path (Required)

```
Internet
    ↓ (DNS, BGP, routing)
Network Edge (DNS, CDN, WAF)
    ↓ (TCP/TLS)
Edge Termination (CDN, WAF, ALB, NLB)
    ↓ (TLS termination, certificate)
TLS Termination Point (certificate, cipher suite, protocol)
    ↓ (backend connection, mTLS, plaintext)
Backend Network (VPC, subnet, security groups)
    ↓ (network path, segmentation)
Application Load Balancer / API Gateway
    ↓ (routing, TLS termination, mTLS)
Application Service (K8s Service, Service Mesh)
    ↓ (service mesh, mTLS, sidecar)
Application Pod/Container (K8s Pod, Container)
    ↓ (container runtime, host)
Application Process (runtime, PID, user)
    ↓ (process tree, loaded libraries)
Code Execution (function, library, crypto API)
    ↓ (call stack, library)
Crypto Library (OpenSSL, BoringSSL, BouncyCastle, etc.)
    ↓ (algorithm implementation)
Cryptographic Algorithm (RSA, ECDSA, AES, ChaCha20, etc.)
    ↓ (key size, mode, padding, parameters)
Cryptographic Parameters (key size, mode, padding, curve)
    ↓ (key material, key management)
Key Material (generation, storage, rotation, HSM/KMS)
    ↓ (key hierarchy, HSM, KMS, key policies)
Key Management (generation, storage, rotation, HSM/KMS)
    ↓ (key hierarchy, policies)
Key Policy (rotation, expiry, access control, audit)
```

---

## 3. CURRENT GRAPH CAPABILITIES VS REQUIRED

### 3.1 Current Graph Edges (What Exists)

| Edge | From → To | Source |
|------|-----------|--------|
| `USES` | System → CryptoAsset | `system_assets` table |
| `CALLS` | System → System | `system_dependencies` (CALLS) |
| `IMPORTS` | System → System | `system_dependencies` (IMPORTS) |
| `SUPPORTS` | System → BusinessProcess | `system_business_process` |
| `OWNED_BY` | System → BusinessOwner | `systems.owner` |
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` |
| `SECURED_BY` | System → Certificate | `certificate_usage` |
| `DEPLOYED_ON` | System → CloudResource | `cloud_accounts.system_id` |
| `CONNECTS_TO` | System → NetworkResource | `network_inventory.system_id` |

### 3.2 Missing Edges for Exposure Paths

| Missing Edge | From → To | Needed For |
|--------------|-----------|------------|
| `TERMINATES_AT` | NetworkEdge → TLS Endpoint | TLS termination mapping |
| `HOSTS` | LoadBalancer → Application | LB → App mapping |
| `TERMINATES_TLS` | LB/Proxy → Certificate | TLS termination cert |
| `ROUTES_TO` | Network Device → Application | Network path to app |
| `DEPLOYS` | Container → Host | Container → Host |
| `RUNS` | Process → Host | Process → Host |
| `LOADS` | Process → Library | Runtime library loading |
| `EXECUTES` | Process → Function | Function execution |
| `CALLS` | Function → Crypto API | Code-level call tracing |
| `USES` | Function → Library | Function → Library |
| `IMPLEMENTS` | Library → Algorithm | Library crypto implementation |
| `TERMINATES_TLS` | TLS Endpoint → Certificate | Cert → Endpoint |
| `USES_CERT` | Application → Certificate | App → Cert |
| `USES_KEY` | Application → Key | App → Key |
| `ENCRYPTS` | Key → Data | Key → Data |
| `SIGNS` | Key → Artifact | Signing chain |
| `VALIDATES` | TrustStore → Certificate | Trust validation |
| `NEGOTIATES` | Client ↔ Server | TLS negotiation |
| `CARRIES` | Network Flow → Protocol | Data flow crypto |
| `ROUTES` | Network Device → Flow | Network topology |

---

## 4. EXPOSURE PATH QUERIES — IMPOSSIBLE

### 4.1 Impossible Queries

| Query | Possible? | Missing Links |
|-------|-----------|---------------|
| "Trace RSA-2048 from Internet to source code line" | ❌ | 7+ missing links |
| "Show all paths where TLS 1.0 terminates at RSA-2048 cert" | ❌ | LB→App, TLS→Cert, App→Code |
| "Trace certificate from ACM to K8s pod to source code" | ❌ | ACM→ALB, ALB→Pod, Pod→Code |
| "Show all data flows using TLS 1.0" | ❌ | Flow→Crypto missing |
| "Find all apps using RSA-2048 exposed to Internet" | ❌ | Internet→App missing |
| "Trace key from HSM to application to algorithm" | ❌ | HSM→Key→App→Algorithm |
| "Show certificate chain from root to leaf to application" | ❌ | Root→Leaf→App missing |
| "Find all TLS 1.0 endpoints with RSA-2048 certs" | ⚠️ Partial | Network→Cert OK, App missing |

---

## 5. EXPOSURE PATH RECONSTRUCTION — CURRENT LIMITS

### 5.1 What CAN Be Reconstructed (Fragments)

| Fragment | Reconstructable? | Method |
|----------|------------------|--------|
| Internet → TLS Endpoint | ✅ | Network scan |
| TLS Endpoint → Certificate | ✅ | Probe result |
| Certificate → Algorithm/Key | ✅ | X.509 parsing |
| Source Code → Algorithm | ✅ | AST parsing |
| Source Code → Key Size/Mode | ✅ | AST + extractors |
| Container → Algorithm | ✅ | Layer scan + SBOM |
| Cloud Config → Algorithm | ✅ | Cloud API |
| Runtime → Algorithm | ⚠️ Partial | LD_PRELOAD / eBPF |

### 5.2 What CANNOT Be Reconstructed

| Path | Why Impossible |
|------|----------------|
| Internet → Load Balancer → Application | No LB→App mapping |
| Load Balancer → TLS Certificate | No LB→Cert link |
| Application → TLS Configuration | No App→TLS config link |
| Application Code → Crypto Function | No Code→Function→Crypto edges |
| Crypto Function → Library | No Function→Library edges |
| Library → Algorithm Implementation | No Library→Algorithm edges |
| Certificate → Application | No Cert→App link |
| Network Flow → Crypto Algorithm | No Flow→Crypto edges |
| Data Flow → Encryption | No Data→Crypto edges |
| Key → Application | No Key→App link |
| HSM → Key → Application | No HSM→Key→App chain |

---

## 6. REQUIRED DATA MODEL FOR EXPOSURE PATHS

### 6.1 Required Node Types

| Node Type | Current | Needed |
|-----------|---------|--------|
| **NetworkEdge** | ❌ | DNS, CDN, WAF, ALB, NLB, CloudFront |
| **LoadBalancer** | ❌ | ALB, NLB, CloudFront, Cloudflare, F5 |
| **TLS Termination Point** | ❌ | Where TLS terminates (cert, cipher, protocol) |
| **Application Service** | ❌ | K8s Service, ECS Service, Cloud Run |
| **Application Pod/Container** | ❌ | K8s Pod, ECS Task, Container |
| **Application Process** | ❌ | Runtime process, PID, user |
| **Code File** | ❌ | Source file, path, language |
| **Function/Method** | ❌ | Function name, class, line |
| **Crypto API Call** | ❌ | API name, parameters, location |
| **Crypto Library** | ⚠️ Partial | Library name, version, provider |
| **Crypto Algorithm Implementation** | ❌ | Specific implementation in library |
| **Key Material** | ❌ | Key ID, type, size, storage (HSM/KMS/file) |
| **Key Hierarchy** | ❌ | Root → Intermediate → Leaf keys |
| **Key Policy** | ❌ | Rotation, expiry, access control |
| **HSM/KMS** | ⚠️ Partial | Hardware/Cloud KMS |
| **Network Flow** | ❌ | Source → Dest, protocol, encryption |
| **Data Store** | ❌ | Database, queue, cache, object store |
| **Data Flow** | ❌ | Data → Encryption → Transit → Storage |

---

### 6.2 Required Edge Types

| Edge Type | From → To | Purpose |
|-----------|-----------|---------|
| `RESOLVES_TO` | DNS → NetworkEdge | DNS resolution |
| `TERMINATES_AT` | NetworkEdge → TLS Termination | TLS termination point |
| `HOSTS` | LoadBalancer → Application Service | LB hosts service |
| `TERMINATES_TLS` | LoadBalancer → Certificate | TLS cert on LB |
| `ROUTES_TO` | NetworkDevice → Application Service | Network path |
| `DEPLOYS` | Container → Host | Container deployment |
| `RUNS_ON` | Process → Host | Process hosting |
| `LOADS` | Process → Library | Library loading |
| `EXECUTES` | Process → Function | Function execution |
| `CALLS` | Function → Crypto API | Crypto API invocation |
| `USES` | Function → Library | Library usage |
| `IMPLEMENTS` | Library → Algorithm | Library provides algorithm |
| `TERMINATES_TLS` | TLS Endpoint → Certificate | Cert at endpoint |
| `USES_CERTIFICATE` | Application → Certificate | App uses cert |
| `USES_KEY` | Application → Key | App uses key |
| `ENCRYPTS` | Key → Data | Key encrypts data |
| `SIGNS` | Key → Artifact | Signing chain |
| `VALIDATES` | TrustStore → Certificate | Trust validation |
| `NEGOTIATES` | Client ↔ Server | TLS handshake |
| `CARRIES` | Network Flow → Protocol | Data flow crypto |
| `ROUTES` | Network Device → Flow | Network topology |

---

## 7. EXPOSURE PATH RECONSTRUCTION — TEST CASES

### 7.1 Test Case 1: Internet → RSA-2048 in Payment API

**Expected Path:**
```
Internet
  → DNS (payment.api.com)
  → CloudFront (CDN)
    → ALB (arn:aws:elasticloadbalancing:...)
      → TLS Termination (cert: ACM arn:aws:acm:..., cipher: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        → Target Group
          → K8s Service (payment-api)
            → K8s Pod (payment-api-abc123)
              → Container (payment-api:v1.2.3)
                → Process (java -jar payment.jar)
                  → Function (CryptoUtil.generateKeyPair())
                    → Crypto API (KeyPairGenerator.getInstance("RSA"))
                      → Library (OpenJDK 11 / SunRSA)
                        → Algorithm (RSA)
                          → Key Size (2048)
```

**Current ZELNX:** Can only trace fragments 1-2 and 8-10.

### 7.2 Test Case 2: Certificate Expiry → Business Impact

**Expected Path:**
```
ACM Certificate (arn:aws:acm:...)
  → Expires in 14 days
  → Used by ALB (arn:aws:elasticloadbalancing:...)
    → Routes to Target Group
      → K8s Service (payment-api)
        → Business Process (Customer Payments)
          → Business Owner (VP Payments)
            → Revenue at Risk: $2M/day
```

**Current ZELNX:** Can trace Cert → ALB (if scanned), but ALB → Business Process broken.

### 7.3 Test Case 3: TLS 1.0 Exposure → Data Flow

**Expected Path:**
```
Internet
  → Legacy Client (TLS 1.0 only)
    → ALB (supports TLS 1.0)
      → TLS 1.0 Negotiation (cipher: TLS_RSA_WITH_AES_256_CBC_SHA)
        → Target Group
          → K8s Service (legacy-api)
            → Process (legacy Java app)
              → Data Flow: Customer PII → TLS 1.0 → Database
                → Encryption: AES-256-CBC (weak mode)
                  → Key: RSA-2048 (quantum vulnerable)
                    → Data at Risk: 500K customer records
```

**Current ZELNX:** Cannot trace data flow to crypto.

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Implement NetworkEdge & LoadBalancer Nodes** — DNS, CDN, WAF, ALB, NLB, CloudFront
2. **Add TERMINATES_AT / TERMINATES_TLS Edges** — NetworkEdge → TLS Termination → Certificate
3. **Add HOSTS / DEPLOYS Edges** — LoadBalancer → Application Service, Container → Host
4. **Add Application Service / Pod / Process Nodes** — K8s Service, Pod, Process

### P1 — High

5. **Add Code-Level Nodes** — CodeFile, Function, CryptoAPICall
6. **Add Code-Level Edges** — DEFINES, CALLS, USES, IMPLEMENTS
7. **Add Library → Algorithm Edge** — IMPLEMENTS (Library → Algorithm)
8. **Add Certificate → Application Edge** — USES_CERTIFICATE
9. **Add Key → Application Edge** — USES_KEY

### P2 — Medium

10. **Add Network Flow Nodes** — NetworkFlow, DataStore, DataFlow
11. **Add Data Flow Edges** — CARRIES (Flow → Protocol), ENCRYPTS (Key → Data)
12. **Add Key Hierarchy Nodes** — RootKey, IntermediateKey, LeafKey, KeyPolicy
12. **Add HSM/KMS Nodes** — HSM, KMS, KeyHierarchy, KeyPolicy
13. **Add Data Flow Edges** — CARRIES (Flow → Protocol), ENCRYPTS (Key → Data)

### P3 — Enhancement

14. **Exposure Path Query API** — `GET /exposure/path?from=internet&to=algorithm`
15. **Exposure Path Visualization** — Interactive path visualization
16. **Exposure Path Alerting** — Alert on new critical paths
15. **Exposure Path Simulation** — "What if this edge fails?"

---

## 8. VERDICT

**ZELNX cannot trace complete exposure paths.** It captures fragments (Internet→TLS, Source→Algorithm, Container→Algorithm) but the critical middle links (Network→Application, Application→Code, Code→Library, Library→Algorithm, Certificate→Application) are missing.

| Path Segment | Traceable? |
|--------------|------------|
| Internet → Network Edge | ✅ |
| Network Edge → TLS Endpoint | ✅ |
| TLS Endpoint → Certificate | ✅ |
| Certificate → Algorithm | ✅ |
| Network Edge → Load Balancer | ❌ |
| Load Balancer → Application | ❌ |
| Application → Code Function | ❌ |
| Code Function → Crypto API | ❌ |
| Crypto API → Algorithm | ✅ |
| Application → Library | ❌ |
| Library → Algorithm | ❌ |
| Certificate → Application | ❌ |
| Application → Key | ❌ |
| Data Flow → Crypto | ❌ |

**To fix:** 8-12 weeks for complete exposure path model with all node types, edge types, and query/visualization capabilities.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph Edges | `services/graph_engine/graph_engine/core/engine.py` (edge types) |
| Graph Builder | `services/api/api/graph_builder.py` |
| Network Scanner Probes | `services/network_scanner/network_scanner/core/scanner.py` |
| Certificate Intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
| Protocol Engine | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| Source Scanner | `services/scanner/scanner/core/scanner.py` |
| Binary Engine | `services/universal_crypto/universal_crypto/binary_engine.py` |
| Runtime Engine | `services/universal_crypto/universal_crypto/runtime_engine.py` |
| Cloud Scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Container Scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Graph Query API | `services/api/api/routers/graph.py` |
| Graph Engine Blast Radius | `services/graph_engine/graph_engine/core/engine.py:blast_radius()` |
| Graph Engine Vendor Chain | `services/graph_engine/graph_engine/core/engine.py:vendor_chain()` |
| Graph Engine Business Impact | `services/graph_engine/graph_engine/core/engine.py:business_impact()` |
| CryptoAsset Model | `services/database/db/models/crypto_asset.py` |
| SystemAsset Link | `services/database/db/models/system_asset.py` |
| CertificateUsage | `services/database/db/models/certificate_usage.py` |
| NetworkInventory Model | `services/database/db/models/network_inventory.py` |
| CloudAccount Model | `services/database/db/models/cloud_account.py` |
| SystemDependency | `services/database/db/models/system_dependency.py` |
---

## UPDATE ADDENDUM — Round 19 (2026-10-10): exposure path query API built

**P3 #14 (exposure path query API) is now code.**
`GET /exposure/paths` (`services/api/api/routers/exposure.py`) walks the
persisted graph — entry-candidate systems → `system_dependencies` edges
→ `system_assets` links → crypto assets — and returns bounded paths
with the asset's registry designation:

- Entry candidates are cloud-hosted (`cloud_provider` set) or
  remote-target systems (`http(s)://`, `git@`, `ssh://` scan targets).
  The response says so explicitly: the platform does not scan network
  topology, so "entry" is a heuristic over metadata, not verified
  reachability.
- Filters: `algorithm=` (paths ending at that algorithm) and `min_rank=`
  (designation floor: 4=DISALLOWED, 3=DEPRECATED, 1=ALLOWED).
- Bounds: depth ≤ 4 hops, ≤ 100 paths, cycle-free, ranked by
  weakest designation then depth.

What this is NOT (the P0–P2 items): NetworkEdge/LoadBalancer/K8s/Pod
nodes, DNS→CDN→WAF→ALB chains, code-level DEFINES/CALLS edges, and
network-flow nodes all require discovery sources the platform does not
have (runtime topology, k8s APIs). They stay open as deployment-scoped
work; the query API is deliberately built over what is actually
persisted so it never fabricates hops.

Tests: `services/api/tests/unit/test_round19_risk_exposure_ownership.py`
(exposure block: 4 tests — chain shape, algorithm filter, empty case,
island exclusion).

## Round 27 update (2026-10-10) — exposure graph re-verified

* **Exposure path queries — shipped (round 19):** bounded
  entry→dependency→crypto walks at `GET /exposure/paths`, plus
  graph-layer certificate exposure and blast-radius/reachability
  surfaces. These run over the *persisted* system dependency graph.
* **NetworkEdge / LoadBalancer / TERMINATES_AT / HOSTS-DEPLOYS edges
  and K8s Service/Pod/Process nodes (P0 #1–4) — still open,
  product-scoped:** the platform does not ingest network or Kubernetes
  topology; DNS/CDN/WAF/ALB→target-group→workload chains need a live
  topology feed (cloud API / K8s API discovery). This is the same
  standing gap as 47's deployment-topology links and 57's verified
  entry surface. Tracked in 00_ROUND_STATUS.

## Round 31 addendum (2026-10-11) — declared topology ingestion BUILT

The round-27 note "the platform does not ingest network or Kubernetes
topology" now has its ingestion surface:

- `POST /network/topology` declares the chain the report named —
  DNS → CDN → WAF → load balancer → system (node kinds dns/cdn/waf/
  load_balancer/k8s_service/pod/ip_range/service; relations RESOLVES_
  TO/PROXIES_TO/ROUTES_TO/PEERS_WITH; system links TERMINATES_AT/
  HOSTS). Total validation before persistence: unknown kinds,
  dangling edge endpoints, self-edges, duplicate names, and CYCLES
  are rejected whole — a rejected document leaves the stored topology
  untouched. Full-replace semantics (the document IS the topology).
- Every node/edge carries `source: "declared"` — an operator
  declaration (or a future cloud/K8s discovery job writing the same
  surface), never presented as a scanned surface.
- Graph: `GraphEngine.build` renders the declared hops as first-class
  DNSRecord/CDN/WAF/LoadBalancer/... nodes with the chain edges and
  system links, `declared_source` preserved on every node.
- Exposure: `GET /exposure/paths` — a system a declared chain fronts
  is an entry candidate with reason "declared topology: <kind>
  <name>" and its chains attached (plus a `declared_topology_entries`
  count), instead of the cloud/remote heuristic alone.
- Queries: `GET /network/topology`, `GET /network/topology/paths?
  system_id=` (the declared chains, hop by hop, with relations).
- Migrations 0083 (topology_nodes/topology_edges); tests in
  `services/api/tests/unit/test_topology_api.py` (validation, cycles,
  chains, ingest, graph rendering, exposure integration, idempotent
  re-declare).
- STILL open, unchanged in kind: live discovery (cloud API / K8s API
  feeds), DNS/CDN/WAF inventory scans — the sources; this round built
  the sink they will write into.
