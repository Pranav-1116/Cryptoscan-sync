# 🚀 CRYPTOSCAN PLATFORM — PART 3 (MONTHS 7-9)
## Intelligence Phase: Runtime Scanning + Cloud Discovery + Dependency Graph + Business Context

---

## 📋 PART 3 OBJECTIVE

**Add runtime visibility and business intelligence:**
- Add **network/runtime scanning** (live TLS sessions, API crypto, certificates)
- Add **cloud configuration scanning** (AWS KMS, Azure Key Vault, GCP CloudKMS, S3 encryption)
- Build **full dependency graph** (system → system → crypto → vendor)
- Add **business context enrichment** (revenue impact, customer count, regulatory scope inheritance)
- Implement **reachability analysis** (blast radius: if this crypto fails, what breaks?)
- Add **certificate inventory** (X.509 certificates, expiry tracking, chain validation)
- Build **drift detection v2.0** (configuration drift, not just code drift)

**NOT in scope for Part 3:**
- ❌ AI/ML features (still deferred)
- ❌ OT/ICS scanning (Part 4)
- ❌ Crypto agility scoring (Part 4)
- ❌ Migration planning automation (Part 4-5)
- ❌ Vendor crypto scanning (Part 4)

---

# 🗺️ MONTH 7: RUNTIME & NETWORK SCANNING

---

## WEEK 25-26: NETWORK TLS SCANNER

### 🎯 Goal
Discover crypto in live network traffic (TLS sessions, certificates)

### 📐 Architecture — Network TLS Scanner

```
┌─────────────────────────────────────────────────────────────┐
│           NETWORK TLS SCANNER v1.0                          │
│           (Active Probing + Passive Observation)            │
└─────────────────────────────────────────────────────────────┘

TWO MODES:

1. ACTIVE PROBING (outbound scan)
   → CryptoScan initiates TLS handshake to target endpoints
   → Captures: TLS version, cipher suites, certificates
   → Use case: Scan public-facing services, APIs

2. PASSIVE OBSERVATION (network tap)
   → CryptoScan observes live traffic (read-only)
   → No interference with production
   → Use case: Internal service mesh, east-west traffic

DEPLOYMENT MODELS:

┌──────────────────────────────────────────────────────────────┐
│ DEPLOYMENT MODEL A: ACTIVE PROBE                            │
│                                                              │
│ CryptoScan ──TLS Handshake──▶ Target Endpoint              │
│                                (api.payment.example.com:443) │
│                                                              │
│ What happens:                                                │
│   1. CryptoScan opens TCP connection to target:443          │
│   2. Sends ClientHello (TLS handshake start)                │
│   3. Receives ServerHello + Certificate + ServerKeyExchange │
│   4. Does NOT complete handshake (closes after cert received)│
│   5. Extracts: TLS version, cipher suite, certificate chain │
│                                                              │
│ Security: Read-only, no data sent (safe for production)     │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ DEPLOYMENT MODEL B: PASSIVE TAP (Service Mesh)              │
│                                                              │
│  Service A ──mTLS──▶ Istio Sidecar ──TLS──▶ Service B      │
│                           │                                  │
│                           │ (mirror traffic metadata)        │
│                           ▼                                  │
│                      CryptoScan                              │
│                      Observer                                │
│                                                              │
│ What happens:                                                │
│   1. Istio/Linkerd/Consul configured to mirror TLS metadata │
│   2. CryptoScan receives: TLS version, cipher, cert info    │
│   3. No decryption of actual data (privacy-safe)            │
│   4. Builds map of service-to-service crypto                │
│                                                              │
│ Integration: Envoy access logs, Istio telemetry             │
└──────────────────────────────────────────────────────────────┘

ACTIVE PROBING LOGIC:

┌──────────────────────────────────────────────────────────────┐
│ ACTIVE TLS PROBE ALGORITHM                                  │
│                                                              │
│ INPUT: Target endpoint (hostname:port)                      │
│                                                              │
│ STEP 1: DNS RESOLUTION                                       │
│   ip_addresses = resolve_dns(hostname)                      │
│   IF no IP resolved:                                         │
│     LOG error, SKIP endpoint                                │
│                                                              │
│ STEP 2: TCP CONNECTION                                       │
│   TRY:                                                       │
│     socket = connect(ip_address, port, timeout=5s)          │
│   EXCEPT ConnectionRefused:                                  │
│     finding = {status: "PORT_CLOSED"}                       │
│     RETURN finding                                           │
│   EXCEPT Timeout:                                            │
│     finding = {status: "TIMEOUT"}                           │
│     RETURN finding                                           │
│                                                              │
│ STEP 3: TLS HANDSHAKE (partial)                             │
│                                                              │
│   # Use Python ssl module or OpenSSL library                │
│   context = ssl.create_default_context()                   │
│   context.check_hostname = False  # We just want cert       │
│   context.verify_mode = ssl.CERT_NONE  # Accept any cert    │
│                                                              │
│   TRY:                                                       │
│     tls_socket = context.wrap_socket(                       │
│       socket,                                                │
│       server_hostname=hostname,                             │
│       do_handshake_on_connect=True                          │
│     )                                                        │
│                                                              │
│     # Handshake complete — extract details                  │
│     tls_version = tls_socket.version()                      │
│       → "TLSv1.3", "TLSv1.2", "TLSv1.1", etc               │
│                                                              │
│     cipher = tls_socket.cipher()                            │
│       → Returns: (cipher_name, tls_version, secret_bits)    │
│       → Example: ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)│
│                                                              │
│     certificate_chain = tls_socket.getpeercert_chain()      │
│       → List of X.509 certificates (leaf to root)           │
│                                                              │
│   EXCEPT ssl.SSLError as e:                                 │
│     finding = {                                              │
│       status: "TLS_ERROR",                                  │
│       error: str(e),                                         │
│       error_type: classify_ssl_error(e)                     │
│         → "PROTOCOL_VERSION_MISMATCH" (old TLS)             │
│         → "CIPHER_SUITE_MISMATCH"                           │
│         → "CERTIFICATE_VERIFY_FAILED"                       │
│     }                                                        │
│     RETURN finding                                           │
│                                                              │
│ STEP 4: PARSE CIPHER SUITE                                  │
│                                                              │
│   # Cipher format: "ECDHE-RSA-AES256-GCM-SHA384"            │
│   cipher_name = cipher[0]                                    │
│   parts = cipher_name.split('-')                            │
│                                                              │
│   # Extract components                                       │
│   key_exchange = parts[0]  # ECDHE, DHE, RSA, etc          │
│   auth_algorithm = parts[1] if len(parts) > 1 else None    │
│     # RSA, ECDSA, etc                                        │
│   encryption_algo = parts[2] if len(parts) > 2 else None   │
│     # AES256, AES128, CHACHA20, etc                         │
│   mode = parts[3] if len(parts) > 3 else None              │
│     # GCM, CBC, etc                                          │
│   mac_algorithm = parts[4] if len(parts) > 4 else None     │
│     # SHA384, SHA256, etc                                    │
│                                                              │
│   # TLS 1.3 cipher format is different:                     │
│   # "TLS_AES_256_GCM_SHA384" (no key exchange in name)     │
│   IF cipher_name.startswith("TLS_"):                        │
│     # TLS 1.3 format                                         │
│     encryption_algo = parts[1] + parts[2]  # AES_256        │
│     mode = parts[3]  # GCM                                   │
│     mac_algorithm = parts[4]  # SHA384                      │
│     key_exchange = "ECDHE"  # TLS 1.3 only uses ECDHE       │
│                                                              │
│ STEP 5: PARSE CERTIFICATE CHAIN                             │
│                                                              │
│   certificates = []                                          │
│                                                              │
│   FOR cert_der IN certificate_chain:                        │
│     cert = parse_x509_certificate(cert_der)                │
│     certificates.append({                                    │
│       "subject": cert.subject.rfc4514_string(),            │
│         # "CN=api.payment.example.com,O=Example Corp"      │
│       "issuer": cert.issuer.rfc4514_string(),              │
│         # "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert" │
│       "serial_number": hex(cert.serial_number),            │
│       "not_before": cert.not_valid_before.isoformat(),     │
│       "not_after": cert.not_valid_after.isoformat(),       │
│       "signature_algorithm": cert.signature_algorithm_oid.dotted_string,│
│         # "1.2.840.113549.1.1.11" = sha256WithRSAEncryption│
│       "public_key_algorithm": cert.public_key().algorithm, │
│         # RSA, EC, Ed25519, etc                             │
│       "public_key_size": cert.public_key().key_size,       │
│         # 2048, 256 (for EC), etc                           │
│       "san": extract_san(cert),                            │
│         # Subject Alternative Names                         │
│         # ["api.payment.example.com", "www.example.com"]   │
│       "key_usage": extract_key_usage(cert),                │
│         # ["digitalSignature", "keyEncipherment"]           │
│       "extended_key_usage": extract_extended_key_usage(cert),│
│         # ["serverAuth", "clientAuth"]                      │
│       "is_ca": cert.extensions.get_extension_for_class(    │
│                  x509.BasicConstraints).value.ca,          │
│       "fingerprint_sha256": cert.fingerprint(SHA256()).hex()│
│     })                                                       │
│                                                              │
│ STEP 6: VALIDATE CERTIFICATE CHAIN                          │
│                                                              │
│   chain_validation = {                                       │
│     "is_valid": False,                                      │
│     "errors": []                                             │
│   }                                                          │
│                                                              │
│   # Check 1: Expiration                                      │
│   leaf_cert = certificates[0]                               │
│   now = datetime.now(UTC)                                    │
│   IF now < leaf_cert.not_before:                            │
│     chain_validation.errors.append("CERT_NOT_YET_VALID")   │
│   IF now > leaf_cert.not_after:                             │
│     chain_validation.errors.append("CERT_EXPIRED")         │
│                                                              │
│   # Check 2: Hostname match                                  │
│   IF NOT hostname_matches_cert(hostname, leaf_cert):        │
│     chain_validation.errors.append("HOSTNAME_MISMATCH")     │
│                                                              │
│   # Check 3: Chain of trust                                  │
│   TRY:                                                       │
│     verify_certificate_chain(certificates, trusted_roots)   │
│     chain_validation.is_valid = True                        │
│   EXCEPT ChainVerificationError as e:                       │
│     chain_validation.errors.append(str(e))                  │
│                                                              │
│ STEP 7: CHECK REVOCATION STATUS (OCSP/CRL)                  │
│                                                              │
│   revocation_status = {                                      │
│     "method": None,                                          │
│     "status": "UNKNOWN"                                      │
│   }                                                          │
│                                                              │
│   # Try OCSP first (faster)                                  │
│   IF leaf_cert has OCSP responder URL:                      │
│     ocsp_response = check_ocsp(leaf_cert, issuer_cert)     │
│     revocation_status.method = "OCSP"                       │
│     revocation_status.status = ocsp_response.status         │
│       # "GOOD", "REVOKED", "UNKNOWN"                        │
│                                                              │
│   # Fallback to CRL                                          │
│   ELSE IF leaf_cert has CRL distribution point:            │
│     crl = download_crl(leaf_cert.crl_distribution_points)  │
│     IF leaf_cert.serial_number IN crl.revoked_certs:       │
│       revocation_status.method = "CRL"                      │
│       revocation_status.status = "REVOKED"                  │
│     ELSE:                                                    │
│       revocation_status.status = "GOOD"                     │
│                                                              │
│ STEP 8: CREATE NETWORK FINDING                              │
│                                                              │
│   finding = {                                                │
│     finding_id: UUID.randomUUID(),                          │
│     scanner_id: "network-tls-scanner-v1.0",                │
│     scan_timestamp: NOW(),                                   │
│                                                              │
│     source: {                                                │
│       type: "NETWORK_ENDPOINT",                             │
│       endpoint: f"{hostname}:{port}",                       │
│       ip_address: ip_address,                               │
│       protocol: "TLS"                                        │
│     },                                                       │
│                                                              │
│     crypto: {                                                │
│       tls_version: tls_version,                             │
│       cipher_suite: cipher_name,                            │
│       key_exchange_algorithm: key_exchange,                 │
│       authentication_algorithm: auth_algorithm,             │
│       encryption_algorithm: encryption_algo,                │
│       encryption_mode: mode,                                │
│       mac_algorithm: mac_algorithm,                         │
│       key_size: cipher[2],  # secret_bits                   │
│       purpose: "NETWORK_ENCRYPTION"                         │
│     },                                                       │
│                                                              │
│     certificates: certificates,                             │
│     chain_validation: chain_validation,                     │
│     revocation_status: revocation_status,                   │
│                                                              │
│     metadata: {                                              │
│       confidence: "HIGH",  # Live verification              │
│       scan_method: "ACTIVE_PROBE"                           │
│     }                                                        │
│   }                                                          │
│                                                              │
│ STEP 9: CLOSE CONNECTION                                     │
│   tls_socket.close()                                         │
│   socket.close()                                             │
│                                                              │
│ STEP 10: RETURN FINDING                                      │
│   RETURN finding                                             │
└──────────────────────────────────────────────────────────────┘

TARGET DISCOVERY (WHERE TO SCAN):

┌──────────────────────────────────────────────────────────────┐
│ ENDPOINT DISCOVERY METHODS                                   │
│                                                              │
│ METHOD 1: Configuration File                                │
│   YAML file: config/network-scan-targets.yaml              │
│   ---                                                        │
│   targets:                                                   │
│     - endpoint: "api.payment.example.com:443"               │
│       system_id: "payment-api-prod"                         │
│       scan_frequency: "daily"                               │
│     - endpoint: "internal-api.example.com:8443"             │
│       system_id: "internal-service"                         │
│       scan_frequency: "hourly"                              │
│                                                              │
│ METHOD 2: Service Discovery Integration                     │
│   Query Kubernetes API:                                     │
│     kubectl get services --all-namespaces                   │
│     FOR EACH service with type=LoadBalancer:                │
│       external_ip = service.status.loadBalancer.ingress[0].ip│
│       port = service.spec.ports[0].port                     │
│       endpoint = f"{external_ip}:{port}"                    │
│       → Add to scan queue                                    │
│                                                              │
│ METHOD 3: Service Mesh Discovery                            │
│   Query Istio:                                              │
│     istioctl proxy-config endpoints <pod> -o json          │
│     Extract all HTTPS endpoints                             │
│     → Add to scan queue                                      │
│                                                              │
│ METHOD 4: DNS Zone Transfer (internal DNS)                  │
│   Query internal DNS for all A/AAAA records                │
│   FOR EACH record:                                          │
│     TRY connecting to :443, :8443, common TLS ports         │
│     IF TLS handshake succeeds → scan                        │
└──────────────────────────────────────────────────────────────┘

SCAN JOB SCHEDULING:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: network_scan_targets                                 │
│                                                              │
│ target_id          UUID PK                                   │
│ endpoint           VARCHAR(200)   api.example.com:443        │
│ system_id          UUID FK        → systems                 │
│ scan_frequency     VARCHAR(50)    HOURLY, DAILY, WEEKLY     │
│ last_scan_time     TIMESTAMP                                 │
│ next_scan_time     TIMESTAMP                                 │
│ enabled            BOOLEAN                                   │
│ created_at         TIMESTAMP                                 │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ NETWORK SCAN SCHEDULER                                       │
│                                                              │
│ RUNS: Every 1 minute (cron job)                             │
│                                                              │
│ ALGORITHM:                                                   │
│   now = NOW()                                                │
│   due_targets = SELECT * FROM network_scan_targets          │
│                 WHERE enabled = true                         │
│                 AND next_scan_time <= now;                   │
│                                                              │
│   FOR EACH target IN due_targets:                           │
│     # Create scan job                                        │
│     job = {                                                  │
│       job_type: "NETWORK_TLS_SCAN",                         │
│       target_endpoint: target.endpoint,                     │
│       system_id: target.system_id                           │
│     }                                                        │
│     INSERT INTO scan_jobs (...);                            │
│                                                              │
│     # Update next scan time                                 │
│     next_time = calculate_next_scan_time(                   │
│       now, target.scan_frequency                            │
│     )                                                        │
│     UPDATE network_scan_targets                             │
│     SET next_scan_time = next_time,                         │
│         last_scan_time = now                                │
│     WHERE target_id = target.target_id;                     │
└──────────────────────────────────────────────────────────────┘
```

### 📊 Certificate Inventory

```
┌──────────────────────────────────────────────────────────────┐
│ CERTIFICATE INVENTORY DATABASE                               │
│                                                              │
│ TABLE: certificates                                          │
│                                                              │
│ certificate_id        UUID PK                                │
│ fingerprint_sha256    VARCHAR(64) UNIQUE  # Key for dedup    │
│ subject               TEXT                                   │
│ issuer                TEXT                                   │
│ serial_number         VARCHAR(100)                           │
│ not_before            TIMESTAMP                              │
│ not_after             TIMESTAMP                              │
│ signature_algorithm   VARCHAR(100)                           │
│ public_key_algorithm  VARCHAR(50)    RSA, EC, Ed25519        │
│ public_key_size       INT            2048, 256, etc          │
│ san                   TEXT[]         Subject Alternative Names│
│ key_usage             TEXT[]                                 │
│ extended_key_usage    TEXT[]                                 │
│ is_ca                 BOOLEAN                                │
│ is_self_signed        BOOLEAN                                │
│ issuer_cert_id        UUID FK        → certificates (chain)  │
│ certificate_pem       TEXT           Full PEM-encoded cert   │
│                                                              │
│ # Compliance tracking                                        │
│ days_until_expiry     INT GENERATED  (not_after - now)       │
│ expiry_status         VARCHAR(20)    VALID, EXPIRING_SOON,  │
│                                      EXPIRED                 │
│ revocation_status     VARCHAR(20)    GOOD, REVOKED, UNKNOWN │
│ revocation_checked_at TIMESTAMP                              │
│                                                              │
│ first_seen            TIMESTAMP                              │
│ last_seen             TIMESTAMP                              │
│ created_at            TIMESTAMP                              │
│ updated_at            TIMESTAMP                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: certificate_usages                                    │
│ (Where is each certificate used?)                           │
│                                                              │
│ usage_id              UUID PK                                │
│ certificate_id        UUID FK → certificates                │
│ endpoint              VARCHAR(200)  api.example.com:443      │
│ system_id             UUID FK → systems                     │
│ usage_type            VARCHAR(50)   TLS_SERVER, TLS_CLIENT, │
│                                     CODE_SIGNING, etc        │
│ first_observed        TIMESTAMP                              │
│ last_observed         TIMESTAMP                              │
└──────────────────────────────────────────────────────────────┘

CERTIFICATE DEDUPLICATION:

When network scan finds certificate:
  fingerprint = SHA-256(certificate_der)
  existing_cert = SELECT * FROM certificates
                  WHERE fingerprint_sha256 = fingerprint
  
  IF existing_cert:
    # Update usage
    INSERT INTO certificate_usages (
      certificate_id, endpoint, system_id, usage_type
    ) VALUES (existing_cert.certificate_id, ...)
    ON CONFLICT (certificate_id, endpoint) DO UPDATE
      SET last_observed = NOW()
    
    UPDATE certificates
    SET last_seen = NOW()
    WHERE certificate_id = existing_cert.certificate_id
  
  ELSE:
    # New certificate
    INSERT INTO certificates (...)
    INSERT INTO certificate_usages (...)

EXPIRY MONITORING:

CRON JOB (daily):
  expiring_certs = SELECT * FROM certificates
                   WHERE days_until_expiry <= 30
                   AND days_until_expiry > 0
                   ORDER BY days_until_expiry ASC;
  
  FOR EACH cert IN expiring_certs:
    usages = SELECT * FROM certificate_usages
             WHERE certificate_id = cert.certificate_id;
    
    systems_affected = [usage.system_id for usage in usages]
    
    alert = {
      type: "CERTIFICATE_EXPIRING",
      severity: "HIGH" if days < 7 else "MEDIUM",
      message: f"Certificate expires in {cert.days_until_expiry} days",
      certificate: cert.subject,
      systems_affected: systems_affected,
      endpoints: [usage.endpoint for usage in usages]
    }
    
    send_alert(alert)
```

### ✅ Week 25-26 Deliverable

**Network TLS scanner that:**
1. Active TLS probing (connect to endpoints, extract crypto config)
2. Certificate chain extraction and validation
3. Certificate inventory database (deduped by fingerprint)
4. Certificate expiry monitoring and alerts
5. OCSP/CRL revocation checking
6. Cipher suite parsing (TLS 1.2 and 1.3 formats)
7. Endpoint discovery (config file, K8s service discovery)
8. Scheduled scanning (hourly, daily, weekly)
9. Certificate usage tracking (which systems use which certs)

**Testing:**
- Configure target: api.payment.example.com:443
- Run network scan
- Verify: TLS 1.2, cipher suite extracted (ECDHE-RSA-AES256-GCM-SHA384)
- Verify: Certificate chain stored (3 certs: leaf, intermediate, root)
- Verify: Certificate expiry calculated (90 days remaining)
- Verify: OCSP status checked (GOOD)
- Dashboard shows: Certificate inventory page
- Alert: Certificate expiring in 25 days → email sent

---

## WEEK 27-28: RUNTIME eBPF AGENT (OPTIONAL — ADVANCED)

### 🎯 Goal
Observe crypto usage in running processes (zero instrumentation)

### 📐 Architecture — eBPF Runtime Agent

```
┌─────────────────────────────────────────────────────────────┐
│           eBPF RUNTIME CRYPTO AGENT v1.0                    │
│           (Kernel-Level Observation — No Code Changes)      │
└─────────────────────────────────────────────────────────────┘

WHAT IS eBPF:
  → Extended Berkeley Packet Filter
  → Allows running sandboxed programs in Linux kernel
  → Used by: Cilium, Falco, Pixie, etc.
  → Zero overhead tracing (production-safe)

USE CASE:
  → Discover which crypto APIs are ACTUALLY CALLED in production
  → Catch crypto usage missed by static analysis
  → Verify runtime behavior matches source code

HOW IT WORKS:

┌──────────────────────────────────────────────────────────────┐
│ eBPF CRYPTO TRACING ARCHITECTURE                            │
│                                                              │
│   Application Process (payment-api)                         │
│         │                                                    │
│         │ Calls: SSL_write(ssl, data, len)                 │
│         ▼                                                    │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  libssl.so (OpenSSL library)                        │  │
│   │  ┌──────────────────────────────────────────────┐   │  │
│   │  │  SSL_write() function                        │   │  │
│   │  │  ▲                                            │   │  │
│   │  │  │ eBPF probe attached here (uprobe)         │   │  │
│   │  └──┼──────────────────────────────────────────────┘  │  │
│   └─────┼───────────────────────────────────────────────── ┘  │
│         │                                                    │
│         ▼                                                    │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  eBPF PROGRAM (runs in kernel)                      │  │
│   │                                                      │  │
│   │  WHEN SSL_write() called:                           │  │
│   │    process_id = get_current_pid_tgid()              │  │
│   │    process_name = get_current_comm()                │  │
│   │    timestamp = ktime_get_ns()                       │  │
│   │                                                      │  │
│   │    # Read SSL context (first argument)              │  │
│   │    ssl_ctx = (SSL*) PT_REGS_PARM1(ctx)             │  │
│   │    cipher = SSL_get_current_cipher(ssl_ctx)         │  │
│   │    cipher_name = SSL_CIPHER_get_name(cipher)        │  │
│   │    tls_version = SSL_get_version(ssl_ctx)           │  │
│   │                                                      │  │
│   │    # Send event to userspace                        │  │
│   │    event = {                                         │  │
│   │      pid: process_id,                               │  │
│   │      process: process_name,                         │  │
│   │      timestamp: timestamp,                          │  │
│   │      function: "SSL_write",                         │  │
│   │      cipher: cipher_name,                           │  │
│   │      tls_version: tls_version                       │  │
│   │    }                                                 │  │
│   │    bpf_perf_event_output(ctx, &events, event)       │  │
│   └─────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│                     ▼                                       │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  USERSPACE COLLECTOR (CryptoScan Agent)             │  │
│   │                                                      │  │
│   │  Reads events from eBPF ring buffer                 │  │
│   │  Aggregates: cipher usage frequency                 │  │
│   │  Detects: unexpected ciphers, downgrades            │  │
│   │  Sends findings to CryptoScan platform              │  │
│   └─────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

PROBE POINTS (FUNCTIONS TO HOOK):

OpenSSL:
  - SSL_CTX_new() → TLS context creation
  - SSL_set_cipher_list() → Cipher suite configuration
  - SSL_connect() / SSL_accept() → Handshake
  - SSL_read() / SSL_write() → Data transfer
  - EVP_EncryptInit_ex() → Symmetric encryption
  - RSA_sign() → RSA signing
  - ECDSA_sign() → ECDSA signing

Java (JVM):
  - sun.security.ssl.SSLSocketImpl.startHandshake()
  - javax.crypto.Cipher.init()
  - javax.crypto.Cipher.doFinal()
  - java.security.Signature.initSign()

Python:
  - _ssl._SSLSocket.do_handshake()
  - cryptography.hazmat.primitives.ciphers.Cipher.__init__()

DEPLOYMENT:

┌──────────────────────────────────────────────────────────────┐
│ eBPF AGENT DEPLOYMENT (Kubernetes DaemonSet)                │
│                                                              │
│ apiVersion: apps/v1                                          │
│ kind: DaemonSet                                              │
│ metadata:                                                    │
│   name: cryptoscan-ebpf-agent                               │
│ spec:                                                        │
│   selector:                                                  │
│     matchLabels:                                             │
│       app: cryptoscan-ebpf-agent                            │
│   template:                                                  │
│     spec:                                                    │
│       hostPID: true   # Access to host processes            │
│       hostNetwork: true                                      │
│       containers:                                            │
│       - name: agent                                          │
│         image: cryptoscan/ebpf-agent:v1.0                   │
│         securityContext:                                     │
│           privileged: true  # Required for eBPF             │
│         volumeMounts:                                        │
│         - name: sys                                          │
│           mountPath: /sys                                    │
│         - name: debugfs                                      │
│           mountPath: /sys/kernel/debug                       │
│       volumes:                                               │
│       - name: sys                                            │
│         hostPath:                                            │
│           path: /sys                                         │
│       - name: debugfs                                        │
│         hostPath:                                            │
│           path: /sys/kernel/debug                            │
└──────────────────────────────────────────────────────────────┘

AGENT LOGIC:

┌──────────────────────────────────────────────────────────────┐
│ eBPF AGENT RUNTIME FLOW                                     │
│                                                              │
│ ON STARTUP:                                                  │
│   1. Load eBPF program into kernel                          │
│      bpf_program = load_bpf("crypto_tracer.o")              │
│                                                              │
│   2. Attach uprobes to crypto libraries                     │
│      FOR EACH library IN [libssl.so, libcrypto.so, ...]:   │
│        IF library exists on system:                         │
│          attach_uprobe(library, "SSL_write", bpf_program)   │
│          attach_uprobe(library, "SSL_read", bpf_program)    │
│          ...                                                 │
│                                                              │
│   3. Attach kprobes to syscalls (if needed)                 │
│      attach_kprobe("sys_sendto", bpf_program)  # Network I/O│
│                                                              │
│ RUNTIME LOOP:                                                │
│   WHILE agent running:                                       │
│     events = read_bpf_events(timeout=1s)                    │
│                                                              │
│     FOR event IN events:                                    │
│       # Aggregate crypto usage                              │
│       key = (event.process, event.cipher, event.tls_version)│
│       crypto_stats[key].count += 1                          │
│       crypto_stats[key].last_seen = event.timestamp         │
│                                                              │
│       # Detect anomalies                                     │
│       IF event.tls_version == "TLSv1.0":                    │
│         alert = {                                            │
│           type: "RUNTIME_CRYPTO_ANOMALY",                   │
│           severity: "HIGH",                                  │
│           message: "TLS 1.0 observed in production",        │
│           process: event.process,                           │
│           pid: event.pid                                     │
│         }                                                    │
│         send_alert_to_platform(alert)                       │
│                                                              │
│   EVERY 60 seconds:                                          │
│     # Send aggregated stats to CryptoScan platform          │
│     findings = []                                            │
│     FOR (process, cipher, version), stats IN crypto_stats:  │
│       finding = {                                            │
│         scanner_id: "ebpf-runtime-agent-v1.0",              │
│         source: {                                            │
│           type: "RUNTIME_PROCESS",                          │
│           process_name: process,                            │
│           hostname: os.hostname()                           │
│         },                                                   │
│         crypto: {                                            │
│           tls_version: version,                             │
│           cipher_suite: cipher,                             │
│           purpose: "NETWORK_ENCRYPTION"                     │
│         },                                                   │
│         metadata: {                                          │
│           confidence: "VERIFIED",  # Runtime observation    │
│           observation_count: stats.count,                   │
│           observation_window: "60s",                        │
│           last_seen: stats.last_seen                        │
│         }                                                    │
│       }                                                      │
│       findings.append(finding)                               │
│                                                              │
│     POST /api/scans/runtime-findings                        │
│       Body: findings                                         │
│                                                              │
│     crypto_stats.clear()  # Reset for next window           │
└──────────────────────────────────────────────────────────────┘

BENEFITS:

✅ Zero instrumentation (no code changes)
✅ Production-safe (read-only observation)
✅ Catches dynamic crypto selection (config-driven)
✅ Verifies actual runtime behavior
✅ Detects downgrade attacks
✅ Process-level attribution

LIMITATIONS:

⚠️ Requires Linux kernel 4.18+ (eBPF features)
⚠️ Requires privileged access (security consideration)
⚠️ Limited to userspace crypto libraries (can't see hardware crypto)
⚠️ Symbol resolution required (works best with debug symbols)

ALTERNATIVE (If eBPF not available):

Use LD_PRELOAD shim:
  → Inject shim library that wraps OpenSSL functions
  → Log crypto calls
  → Less intrusive than eBPF but requires app restart
```

### ✅ Week 27-28 Deliverable

**Runtime eBPF agent (optional advanced feature):**
1. eBPF program that hooks OpenSSL functions
2. Userspace collector agent
3. Kubernetes DaemonSet deployment
4. Runtime crypto usage aggregation
5. Anomaly detection (unexpected TLS versions, weak ciphers)
6. Integration with CryptoScan platform (sends findings via API)
7. Dashboard shows runtime-verified crypto usage

**Testing:**
- Deploy eBPF agent to test Kubernetes cluster
- Run payment-api (uses OpenSSL for HTTPS)
- eBPF agent observes: TLS 1.3, AES-256-GCM cipher
- Findings sent to CryptoScan platform
- Dashboard shows: "Runtime Verified" badge on AES-256-GCM asset
- Test downgrade: Force TLS 1.0 in config
- eBPF agent detects, sends alert within 60 seconds

**Note:** If eBPF is too complex for initial delivery, defer to later phase. Network TLS scanner (Week 25-26) is higher priority.

---

# 🗺️ MONTH 8: CLOUD CONFIGURATION SCANNING

---

## WEEK 29-30: AWS CLOUD SCANNER

### 🎯 Goal
Discover crypto configuration in AWS services (KMS, S3, RDS, etc.)

### 📐 Architecture — AWS Cloud Scanner

```
┌─────────────────────────────────────────────────────────────┐
│           AWS CLOUD SCANNER v1.0                            │
│           (Read-Only IAM Role — No Modifications)           │
└─────────────────────────────────────────────────────────────┘

DEPLOYMENT MODEL:

┌──────────────────────────────────────────────────────────────┐
│ AWS ACCOUNT SETUP                                            │
│                                                              │
│ 1. Create IAM Role: CryptoScanReadOnly                      │
│    Trust Policy: Allow CryptoScan AWS account to assume     │
│    Permissions: Read-only access to crypto-related services │
│                                                              │
│ 2. IAM Policy: CryptoScanPolicy                             │
│    {                                                         │
│      "Version": "2012-10-17",                               │
│      "Statement": [                                          │
│        {                                                     │
│          "Effect": "Allow",                                 │
│          "Action": [                                         │
│            "kms:ListKeys",                                  │
│            "kms:DescribeKey",                               │
│            "kms:GetKeyPolicy",                              │
│            "kms:GetKeyRotationStatus",                      │
│            "s3:GetBucketEncryption",                        │
│            "s3:GetEncryptionConfiguration",                 │
│            "s3:ListBuckets",                                │
│            "rds:DescribeDBInstances",                       │
│            "rds:DescribeDBClusters",                        │
│            "elasticloadbalancing:DescribeLoadBalancers",    │
│            "elasticloadbalancing:DescribeListeners",        │
│            "elasticloadbalancing:DescribeSSLPolicies",      │
│            "acm:ListCertificates",                          │
│            "acm:DescribeCertificate",                       │
│            "cloudfront:ListDistributions",                  │
│            "cloudfront:GetDistributionConfig",              │
│            "apigateway:GetRestApis",                        │
│            "apigateway:GetStages",                          │
│            "secretsmanager:ListSecrets",                    │
│            "secretsmanager:DescribeSecret",                 │
│            "ssm:DescribeParameters",                        │
│            "ec2:DescribeInstances",                         │
│            "ec2:DescribeVolumes",                           │
│            "lambda:ListFunctions",                          │
│            "lambda:GetFunction"                             │
│          ],                                                  │
│          "Resource": "*"                                     │
│        }                                                     │
│      ]                                                       │
│    }                                                         │
│                                                              │
│ 3. CryptoScan Assumes Role:                                 │
│    aws sts assume-role \                                     │
│      --role-arn arn:aws:iam::123456789:role/CryptoScanReadOnly \│
│      --role-session-name cryptoscan-scan-session            │
└──────────────────────────────────────────────────────────────┘

AWS SERVICE SCANNING:

┌──────────────────────────────────────────────────────────────┐
│ SERVICE 1: AWS KMS (Key Management Service)                 │
│                                                              │
│ WHAT: Managed encryption keys                               │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   1. List all KMS keys:                                     │
│      kms = boto3.client('kms', region_name=region)          │
│      response = kms.list_keys()                             │
│      key_ids = [key['KeyId'] for key in response['Keys']]  │
│                                                              │
│   2. For each key, get details:                             │
│      FOR key_id IN key_ids:                                 │
│        key_metadata = kms.describe_key(KeyId=key_id)        │
│        key_policy = kms.get_key_policy(KeyId=key_id,        │
│                                        PolicyName='default') │
│        rotation_status = kms.get_key_rotation_status(       │
│                                        KeyId=key_id)         │
│                                                              │
│   3. Extract crypto details:                                │
│      finding = {                                             │
│        source: {                                             │
│          type: "AWS_KMS_KEY",                               │
│          resource_arn: key_metadata['Arn'],                 │
│          region: region,                                     │
│          account_id: extract_account(arn)                   │
│        },                                                    │
│        crypto: {                                             │
│          key_spec: key_metadata['KeySpec'],                 │
│            # "SYMMETRIC_DEFAULT" (AES-256)                  │
│            # "RSA_2048", "RSA_3072", "RSA_4096"             │
│            # "ECC_NIST_P256", "ECC_NIST_P384",              │
│            # "ECC_SECG_P256K1"                              │
│          key_usage: key_metadata['KeyUsage'],               │
│            # "ENCRYPT_DECRYPT", "SIGN_VERIFY"               │
│          encryption_algorithms: key_metadata.get(           │
│            'EncryptionAlgorithms', []),                     │
│            # ["SYMMETRIC_DEFAULT", "RSAES_OAEP_SHA_256"]    │
│          signing_algorithms: key_metadata.get(              │
│            'SigningAlgorithms', []),                        │
│            # ["RSASSA_PSS_SHA_256", "ECDSA_SHA_256"]        │
│          origin: key_metadata['Origin'],                    │
│            # "AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM"          │
│          key_state: key_metadata['KeyState'],               │
│            # "Enabled", "Disabled", "PendingDeletion"       │
│          multi_region: key_metadata.get('MultiRegion', False),│
│          purpose: "KEY_MANAGEMENT"                          │
│        },                                                    │
│        metadata: {                                           │
│          rotation_enabled: rotation_status['KeyRotationEnabled'],│
│          creation_date: key_metadata['CreationDate'],       │
│          key_manager: key_metadata['KeyManager'],           │
│            # "AWS" (AWS-managed) or "CUSTOMER" (CMK)        │
│          confidence: "VERIFIED"  # Direct API query         │
│        },                                                    │
│        policy: json.loads(key_policy['Policy']),            │
│        tags: key_metadata.get('Tags', [])                   │
│      }                                                       │
│                                                              │
│   4. Map to algorithm:                                      │
│      IF key_spec == "SYMMETRIC_DEFAULT":                    │
│        algorithm = "AES-256-GCM"  # AWS KMS uses AES-GCM    │
│      ELSE IF key_spec == "RSA_2048":                        │
│        algorithm = "RSA-2048"                               │
│      ELSE IF key_spec == "ECC_NIST_P256":                   │
│        algorithm = "ECDSA-P256"                             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ SERVICE 2: S3 BUCKET ENCRYPTION                             │
│                                                              │
│ WHAT: Server-side encryption for object storage             │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   s3 = boto3.client('s3')                                   │
│   buckets = s3.list_buckets()['Buckets']                   │
│                                                              │
│   FOR bucket IN buckets:                                    │
│     TRY:                                                     │
│       encryption = s3.get_bucket_encryption(                │
│         Bucket=bucket['Name']                               │
│       )                                                      │
│       rules = encryption['ServerSideEncryptionConfiguration']['Rules']│
│                                                              │
│       FOR rule IN rules:                                    │
│         sse_algorithm = rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']│
│         kms_key_id = rule['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID')│
│                                                              │
│         finding = {                                          │
│           source: {                                          │
│             type: "AWS_S3_BUCKET",                          │
│             bucket_name: bucket['Name'],                    │
│             region: get_bucket_region(bucket['Name'])       │
│           },                                                 │
│           crypto: {                                          │
│             encryption_type: sse_algorithm,                 │
│               # "AES256" (SSE-S3 — AWS-managed)             │
│               # "aws:kms" (SSE-KMS — customer-managed)      │
│               # "aws:kms:dsse" (Dual-layer encryption)      │
│             kms_key_arn: kms_key_id if kms_key_id else None,│
│             algorithm: "AES-256" if sse_algorithm=="AES256" │
│                        else "KMS-managed",                  │
│             purpose: "DATA_AT_REST_ENCRYPTION"              │
│           },                                                 │
│           metadata: {                                        │
│             bucket_encryption: "DEFAULT"  # Applied by default│
│           }                                                  │
│         }                                                    │
│                                                              │
│     EXCEPT ClientError as e:                                │
│       IF e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':│
│         # Bucket has NO encryption!                         │
│         finding = {                                          │
│           source: {type: "AWS_S3_BUCKET", ...},             │
│           crypto: {                                          │
│             encryption_type: "NONE",                        │
│             algorithm: None,                                │
│             purpose: "DATA_AT_REST_ENCRYPTION"              │
│           },                                                 │
│           compliance_issue: "NO_ENCRYPTION"  # Flag         │
│         }                                                    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ SERVICE 3: RDS DATABASE ENCRYPTION                          │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   rds = boto3.client('rds', region_name=region)             │
│   db_instances = rds.describe_db_instances()['DBInstances'] │
│                                                              │
│   FOR db IN db_instances:                                   │
│     finding = {                                              │
│       source: {                                              │
│         type: "AWS_RDS_INSTANCE",                           │
│         db_instance_id: db['DBInstanceIdentifier'],         │
│         engine: db['Engine'],  # mysql, postgres, etc       │
│         engine_version: db['EngineVersion']                 │
│       },                                                     │
│       crypto: {                                              │
│         storage_encrypted: db['StorageEncrypted'],          │
│         kms_key_id: db.get('KmsKeyId'),                     │
│         algorithm: "AES-256-XTS" if db['StorageEncrypted'] else None,│
│           # AWS RDS uses AES-256-XTS for storage            │
│         tde_enabled: check_tde(db),  # Transparent Data Encryption│
│         ssl_enabled: db.get('CACertificateIdentifier') is not None,│
│         purpose: "DATABASE_ENCRYPTION"                      │
│       },                                                     │
│       metadata: {                                            │
│         encryption_at_rest: db['StorageEncrypted'],         │
│         encryption_in_transit: db.get('CACertificateIdentifier') is not None│
│       }                                                      │
│     }                                                        │
│                                                              │
│     IF NOT db['StorageEncrypted']:                          │
│       finding.compliance_issue = "NO_ENCRYPTION_AT_REST"    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ SERVICE 4: ELB/ALB TLS POLICIES                             │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   elbv2 = boto3.client('elbv2', region_name=region)         │
│   load_balancers = elbv2.describe_load_balancers()['LoadBalancers']│
│                                                              │
│   FOR lb IN load_balancers:                                 │
│     listeners = elbv2.describe_listeners(                   │
│       LoadBalancerArn=lb['LoadBalancerArn']                 │
│     )['Listeners']                                           │
│                                                              │
│     FOR listener IN listeners:                              │
│       IF listener['Protocol'] == 'HTTPS' or listener['Protocol'] == 'TLS':│
│         ssl_policy = listener.get('SslPolicy', 'DEFAULT')   │
│         certificates = listener.get('Certificates', [])     │
│                                                              │
│         # Get SSL policy details                            │
│         policy_details = elbv2.describe_ssl_policies(       │
│           Names=[ssl_policy]                                │
│         )['SslPolicies'][0]                                 │
│                                                              │
│         finding = {                                          │
│           source: {                                          │
│             type: "AWS_ELB_LISTENER",                       │
│             load_balancer_arn: lb['LoadBalancerArn'],       │
│             listener_arn: listener['ListenerArn']           │
│           },                                                 │
│           crypto: {                                          │
│             ssl_policy_name: ssl_policy,                    │
│             protocols: policy_details.get('SslProtocols', []),│
│               # ["TLSv1.2", "TLSv1.3"]                      │
│             ciphers: policy_details.get('Ciphers', []),     │
│               # [{Name: "ECDHE-RSA-AES256-GCM-SHA384", Priority: 1}]│
│             certificate_arns: [cert['CertificateArn']       │
│                                for cert in certificates],   │
│             purpose: "LOAD_BALANCER_TLS"                    │
│           },                                                 │
│           metadata: {                                        │
│             min_tls_version: min(policy_details['SslProtocols']),│
│             max_tls_version: max(policy_details['SslProtocols'])│
│           }                                                  │
│         }                                                    │
│                                                              │
│         # Check for weak TLS                                │
│         IF "TLSv1" IN policy_details['SslProtocols'] or     │
│            "TLSv1.1" IN policy_details['SslProtocols']:     │
│           finding.compliance_issue = "WEAK_TLS_VERSION"     │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ SERVICE 5: ACM CERTIFICATES                                 │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   acm = boto3.client('acm', region_name=region)             │
│   certificates = acm.list_certificates()['CertificateSummaryList']│
│                                                              │
│   FOR cert_summary IN certificates:                         │
│     cert_arn = cert_summary['CertificateArn']               │
│     cert = acm.describe_certificate(CertificateArn=cert_arn)['Certificate']│
│                                                              │
│     finding = {                                              │
│       source: {                                              │
│         type: "AWS_ACM_CERTIFICATE",                        │
│         certificate_arn: cert_arn,                          │
│         region: region                                       │
│       },                                                     │
│       crypto: {                                              │
│         domain_name: cert['DomainName'],                    │
│         subject_alternative_names: cert.get('SubjectAlternativeNames', []),│
│         signature_algorithm: cert.get('SignatureAlgorithm'),│
│         key_algorithm: cert.get('KeyAlgorithm'),            │
│           # "RSA-2048", "EC_prime256v1", etc                │
│         not_before: cert['NotBefore'],                      │
│         not_after: cert['NotAfter'],                        │
│         status: cert['Status'],                             │
│           # "ISSUED", "PENDING_VALIDATION", "EXPIRED", etc  │
│         in_use: len(cert.get('InUseBy', [])) > 0,          │
│         used_by: cert.get('InUseBy', []),                   │
│           # ARNs of resources using this cert               │
│         purpose: "TLS_CERTIFICATE"                          │
│       },                                                     │
│       metadata: {                                            │
│         days_until_expiry: (cert['NotAfter'] - now).days,   │
│         renewal_eligibility: cert.get('RenewalEligibility'),│
│         type: cert.get('Type')  # "AMAZON_ISSUED" or "IMPORTED"│
│       }                                                      │
│     }                                                        │
│                                                              │
│     # Link to certificate inventory (from network scanner)  │
│     # Match by domain name or serial number                 │
└──────────────────────────────────────────────────────────────┘

MULTI-REGION SCANNING:

┌──────────────────────────────────────────────────────────────┐
│ AWS MULTI-REGION ORCHESTRATION                              │
│                                                              │
│ AWS has resources in multiple regions:                      │
│   us-east-1, us-west-2, eu-west-1, ap-southeast-1, etc.    │
│                                                              │
│ SCAN ALGORITHM:                                              │
│   ec2 = boto3.client('ec2', region_name='us-east-1')       │
│   all_regions = [r['RegionName'] for r in                  │
│                  ec2.describe_regions()['Regions']]         │
│                                                              │
│   FOR region IN all_regions:                                │
│     LOG f"Scanning AWS region: {region}"                    │
│                                                              │
│     # Scan each service in this region                      │
│     findings = []                                            │
│     findings.extend(scan_kms_keys(region))                  │
│     findings.extend(scan_s3_buckets(region))                │
│     findings.extend(scan_rds_instances(region))             │
│     findings.extend(scan_load_balancers(region))            │
│     findings.extend(scan_acm_certificates(region))          │
│     findings.extend(scan_api_gateways(region))              │
│     findings.extend(scan_cloudfront_distributions())  # Global│
│                                                              │
│     # Send findings to CryptoScan platform                  │
│     POST /api/scans/cloud-findings                          │
│       Body: {                                                │
│         cloud_provider: "AWS",                              │
│         account_id: get_account_id(),                       │
│         region: region,                                      │
│         findings: findings                                   │
│       }                                                      │
└──────────────────────────────────────────────────────────────┘

CONFIGURATION:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: cloud_accounts                                        │
│                                                              │
│ account_id         UUID PK                                   │
│ cloud_provider     VARCHAR(50)    AWS, AZURE, GCP            │
│ account_identifier VARCHAR(200)   AWS account ID, Azure sub │
│ role_arn           TEXT           arn:aws:iam::123:role/... │
│ credentials        JSONB          Encrypted credentials      │
│ enabled            BOOLEAN                                   │
│ scan_frequency     VARCHAR(50)    DAILY, WEEKLY              │
│ last_scan_time     TIMESTAMP                                 │
│ next_scan_time     TIMESTAMP                                 │
│ regions            TEXT[]         Regions to scan            │
│ created_at         TIMESTAMP                                 │
└──────────────────────────────────────────────────────────────┘

SCHEDULER:

CRON (daily):
  cloud_accounts = SELECT * FROM cloud_accounts
                   WHERE enabled = true
                   AND next_scan_time <= NOW()
  
  FOR account IN cloud_accounts:
    job = {
      job_type: "CLOUD_SCAN",
      cloud_provider: account.cloud_provider,
      account_id: account.account_identifier,
      role_arn: account.role_arn,
      regions: account.regions
    }
    INSERT INTO scan_jobs (...)
```

### ✅ Week 29-30 Deliverable

**AWS cloud scanner that:**
1. Scans 6 AWS services (KMS, S3, RDS, ELB/ALB, ACM, API Gateway)
2. Multi-region support (all AWS regions)
3. IAM role-based authentication (read-only, secure)
4. Detects: KMS key specs, S3 encryption config, RDS encryption, ALB TLS policies, ACM certificates
5. Flags compliance issues (no encryption, weak TLS, expiring certs)
6. Integrates with certificate inventory (links ACM certs to network findings)
7. Dashboard shows cloud crypto inventory

**Testing:**
- Configure AWS account in CryptoScan
- Run cloud scan
- Verify: 47 KMS keys found (AES-256, RSA-2048, EC-P256)
- Verify: 128 S3 buckets scanned, 12 have no encryption → flagged
- Verify: 8 RDS instances, all encrypted → PASS
- Verify: 4 ALBs, 1 uses TLSv1.0 → compliance issue flagged
- Verify: 15 ACM certificates, 2 expiring in 20 days → alert
- Dashboard shows: AWS crypto inventory by region

---

## WEEK 31-32: AZURE & GCP CLOUD SCANNERS

### 🎯 Goal
Same cloud scanning capability for Azure and GCP

### 📐 Architecture — Azure Scanner (Brief)

```
Similar pattern to AWS, different APIs:

AZURE SERVICES:
  1. Azure Key Vault
     → List vaults, list keys/secrets/certificates
     → Get key properties (algorithm, key size, enabled)
  
  2. Azure Storage Accounts
     → Get encryption settings (Microsoft-managed vs customer-managed)
  
  3. Azure SQL Database
     → Transparent Data Encryption (TDE) status
  
  4. Azure Application Gateway
     → SSL policies, certificates
  
  5. Azure Front Door
     → TLS version, cipher suites

AUTHENTICATION:
  → Service Principal with Reader role
  → Azure SDK for Python (azure-identity, azure-mgmt-*)

EXAMPLE (Azure Key Vault):
  from azure.identity import DefaultAzureCredential
  from azure.keyvault.keys import KeyClient
  
  credential = DefaultAzureCredential()
  vault_url = "https://myvault.vault.azure.net"
  client = KeyClient(vault_url=vault_url, credential=credential)
  
  keys = client.list_properties_of_keys()
  FOR key IN keys:
    key_details = client.get_key(key.name)
    finding = {
      source: {
        type: "AZURE_KEY_VAULT_KEY",
        vault_name: "myvault",
        key_name: key.name
      },
      crypto: {
        key_type: key_details.key.kty,  # "RSA", "EC", "RSA-HSM"
        key_size: key_details.key.n.bit_length() if RSA else None,
        curve: key_details.key.crv if EC else None,
        operations: key_details.key.key_ops,  # ["encrypt", "decrypt"]
        enabled: key_details.properties.enabled,
        purpose: "KEY_MANAGEMENT"
      }
    }
```

### 📐 Architecture — GCP Scanner (Brief)

```
GCP SERVICES:
  1. Cloud KMS
     → List key rings, list keys
     → Get key version, algorithm
  
  2. Cloud Storage Buckets
     → Get encryption configuration (Google-managed vs CMEK)
  
  3. Cloud SQL
     → Encryption at rest status
  
  4. Cloud Load Balancing
     → SSL policies, certificates

AUTHENTICATION:
  → Service Account with Cloud Asset Viewer role
  → Google Cloud Client Libraries

EXAMPLE (Cloud KMS):
  from google.cloud import kms
  
  client = kms.KeyManagementServiceClient()
  parent = f"projects/{project_id}/locations/global"
  
  key_rings = client.list_key_rings(request={"parent": parent})
  FOR key_ring IN key_rings:
    keys = client.list_crypto_keys(request={"parent": key_ring.name})
    FOR key IN keys:
      primary_version = client.get_crypto_key_version(
        request={"name": key.primary.name}
      )
      
      finding = {
        source: {
          type: "GCP_KMS_KEY",
          key_ring: key_ring.name,
          key_name: key.name
        },
        crypto: {
          algorithm: key.version_template.algorithm.name,
            # "GOOGLE_SYMMETRIC_ENCRYPTION" (AES-256-GCM)
            # "RSA_SIGN_PSS_2048_SHA256"
            # "EC_SIGN_P256_SHA256"
          protection_level: key.version_template.protection_level.name,
            # "SOFTWARE", "HSM"
          purpose: key.purpose.name,
            # "ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT"
          rotation_period: key.rotation_period.seconds if key.rotation_period else None
        }
      }
```

### ✅ Week 31-32 Deliverable

**Azure + GCP cloud scanners:**
1. Azure scanner (Key Vault, Storage, SQL, App Gateway, Front Door)
2. GCP scanner (Cloud KMS, Storage, SQL, Load Balancing)
3. Multi-cloud dashboard view (AWS + Azure + GCP in one inventory)
4. Service principal / service account setup documentation
5. Findings feed into same crypto_assets table (deduplication works cross-cloud)

**Testing:**
- Configure Azure subscription + GCP project
- Run cloud scans
- Verify: Azure Key Vault keys detected
- Verify: GCP KMS keys detected
- Dashboard shows: Multi-cloud view (filter by AWS/Azure/GCP)
- Compliance check: CMEK (customer-managed encryption keys) vs default encryption

---

# 🗺️ MONTH 9: DEPENDENCY GRAPH + BUSINESS CONTEXT

---

## WEEK 33-34: DEPENDENCY GRAPH ENGINE

### 🎯 Goal
Build full dependency graph (system → system → crypto)

### 📐 Architecture — Dependency Graph v2.0

```
┌─────────────────────────────────────────────────────────────┐
│         DEPENDENCY GRAPH ENGINE v2.0                        │
│         (Neo4j Graph Database — Real Relationships)         │
└─────────────────────────────────────────────────────────────┘

UPGRADE FROM PART 2:
  Month 6: Simple relational DB (asset_system_links)
  Month 9: Full graph database (Neo4j)

WHY GRAPH DATABASE:
  → Efficient graph traversal (find all downstream systems in <100ms)
  → Native relationship queries (Cypher query language)
  → Scales to millions of nodes and relationships
  → Perfect for: "If this crypto breaks, what else breaks?"

GRAPH DATA MODEL:

┌──────────────────────────────────────────────────────────────┐
│ NODE TYPES                                                   │
│                                                              │
│ (:CryptoAsset)                                              │
│   Properties: asset_id, algorithm, key_size, confidence     │
│                                                              │
│ (:System)                                                    │
│   Properties: system_id, name, environment, criticality     │
│                                                              │
│ (:BusinessProcess)                                           │
│   Properties: process_id, name, revenue_daily, customer_count│
│                                                              │
│ (:BusinessOwner)                                             │
│   Properties: owner_id, name, email, role                   │
│                                                              │
│ (:ComplianceScope)                                           │
│   Properties: scope_id, standard_name, version              │
│                                                              │
│ (:Certificate)                                               │
│   Properties: cert_id, subject, issuer, not_after           │
│                                                              │
│ (:CloudResource)                                             │
│   Properties: resource_id, cloud_provider, resource_type    │
│                                                              │
│ (:Vendor)                                                    │
│   Properties: vendor_id, name, criticality                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ RELATIONSHIP TYPES                                           │
│                                                              │
│ (:System)-[:USES]->(:CryptoAsset)                           │
│   Properties: usage_type, first_seen, last_seen            │
│                                                              │
│ (:System)-[:CALLS]->(:System)                               │
│   Properties: protocol, frequency, data_classification      │
│                                                              │
│ (:System)-[:SUPPORTS]->(:BusinessProcess)                   │
│   Properties: sla_tier, availability_requirement            │
│                                                              │
│ (:System)-[:OWNED_BY]->(:BusinessOwner)                     │
│                                                              │
│ (:System)-[:MUST_COMPLY_WITH]->(:ComplianceScope)           │
│                                                              │
│ (:System)-[:SECURED_BY]->(:Certificate)                     │
│   Properties: endpoint, tls_version                         │
│                                                              │
│ (:System)-[:DEPLOYED_ON]->(:CloudResource)                  │
│                                                              │
│ (:System)-[:DEPENDS_ON_VENDOR]->(:Vendor)                   │
│   Properties: dependency_type, contract_end_date            │
│                                                              │
│ (:CryptoAsset)-[:PROTECTED_BY]->(:CryptoAsset)              │
│   Example: Session key protected by master key              │
└──────────────────────────────────────────────────────────────┘

GRAPH POPULATION:

┌──────────────────────────────────────────────────────────────┐
│ GRAPH BUILDER ALGORITHM                                      │
│                                                              │
│ TRIGGERED: After each scan completes                        │
│                                                              │
│ INPUT: Scan results (crypto_assets, systems, etc.)         │
│                                                              │
│ STEP 1: CREATE CRYPTO ASSET NODES                           │
│   FOR EACH crypto_asset IN new_scan:                        │
│     MERGE (a:CryptoAsset {asset_id: asset.asset_id})       │
│     SET a.algorithm = asset.algorithm,                      │
│         a.key_size = asset.key_size,                        │
│         a.confidence = asset.confidence,                    │
│         a.compliance_status = asset.compliance_status,      │
│         a.last_seen = NOW()                                 │
│                                                              │
│ STEP 2: CREATE SYSTEM NODES                                 │
│   FOR EACH system IN systems_table:                         │
│     MERGE (s:System {system_id: system.system_id})         │
│     SET s.name = system.name,                               │
│         s.environment = system.environment,                 │
│         s.criticality = system.criticality_tier,            │
│         s.updated_at = NOW()                                │
│                                                              │
│ STEP 3: CREATE USES RELATIONSHIPS                           │
│   FOR EACH asset_system_link:                               │
│     MATCH (a:CryptoAsset {asset_id: link.asset_id})        │
│     MATCH (s:System {system_id: link.system_id})           │
│     MERGE (s)-[r:USES]->(a)                                 │
│     SET r.usage_type = link.link_type,                      │
│         r.last_seen = NOW()                                 │
│                                                              │
│ STEP 4: CREATE SYSTEM-TO-SYSTEM RELATIONSHIPS               │
│   # From service mesh telemetry or manual config            │
│   FOR EACH service_call IN service_mesh_data:               │
│     MATCH (s1:System {name: service_call.source})          │
│     MATCH (s2:System {name: service_call.destination})     │
│     MERGE (s1)-[r:CALLS]->(s2)                              │
│     SET r.protocol = service_call.protocol,                 │
│         r.frequency = service_call.request_count,           │
│         r.last_observed = NOW()                             │
│                                                              │
│ STEP 5: CREATE BUSINESS CONTEXT NODES & RELATIONSHIPS       │
│   FOR EACH business_process:                                │
│     MERGE (bp:BusinessProcess {process_id: bp.process_id}) │
│     SET bp.name = bp.name,                                  │
│         bp.revenue_daily = bp.revenue_daily,                │
│         bp.customer_count = bp.customer_count               │
│                                                              │
│   FOR EACH system IN bp.systems:                            │
│     MATCH (s:System {system_id: system})                   │
│     MATCH (bp:BusinessProcess {process_id: bp.process_id}) │
│     MERGE (s)-[:SUPPORTS]->(bp)                             │
│                                                              │
│ STEP 6: CREATE OWNER RELATIONSHIPS                          │
│   FOR EACH system:                                           │
│     MERGE (owner:BusinessOwner {email: system.business_owner})│
│     MATCH (s:System {system_id: system.system_id})         │
│     MERGE (s)-[:OWNED_BY]->(owner)                          │
│                                                              │
│ STEP 7: CREATE COMPLIANCE RELATIONSHIPS                     │
│   FOR EACH system:                                           │
│     FOR scope IN system.compliance_scopes:                  │
│       MERGE (cs:ComplianceScope {standard_name: scope})    │
│       MATCH (s:System {system_id: system.system_id})       │
│       MERGE (s)-[:MUST_COMPLY_WITH]->(cs)                   │
└──────────────────────────────────────────────────────────────┘

SERVICE MESH INTEGRATION (Istio Example):

┌──────────────────────────────────────────────────────────────┐
│ ISTIO TELEMETRY → DEPENDENCY GRAPH                          │
│                                                              │
│ Istio publishes metrics about service-to-service calls:     │
│                                                              │
│ QUERY Prometheus (Istio metrics):                           │
│   istio_requests_total{                                     │
│     source_workload="payment-api",                          │
│     destination_workload="customer-db"                      │
│   }                                                          │
│                                                              │
│ RESULT:                                                      │
│   payment-api calls customer-db                             │
│   Protocol: gRPC                                             │
│   Request count: 150,000/day                                │
│                                                              │
│ CREATE RELATIONSHIP:                                         │
│   MATCH (s1:System {name: "payment-api"})                   │
│   MATCH (s2:System {name: "customer-db"})                   │
│   MERGE (s1)-[r:CALLS]->(s2)                                │
│   SET r.protocol = "gRPC",                                  │
│       r.frequency = 150000,                                 │
│       r.data_source = "istio-telemetry"                     │
│                                                              │
│ AUTOMATION:                                                  │
│   CryptoScan queries Istio metrics every hour               │
│   Updates graph with new/changed relationships              │
└──────────────────────────────────────────────────────────────┘

REACHABILITY QUERIES:

┌──────────────────────────────────────────────────────────────┐
│ QUERY 1: Blast Radius (Downstream Impact)                  │
│                                                              │
│ QUESTION: If RSA-2048 in payment-api fails, what breaks?   │
│                                                              │
│ CYPHER QUERY:                                                │
│   MATCH (a:CryptoAsset {algorithm: "RSA-2048"})            │
│   <-[:USES]-(s:System {name: "payment-api"})               │
│   MATCH path = (s)-[:CALLS*1..5]->(downstream:System)      │
│   RETURN DISTINCT downstream.name,                          │
│                   downstream.criticality,                   │
│                   length(path) as hops                      │
│   ORDER BY hops;                                             │
│                                                              │
│ RESULT:                                                      │
│   ┌──────────────────┬─────────────┬──────┐                │
│   │ System           │ Criticality │ Hops │                │
│   ├──────────────────┼─────────────┼──────┤                │
│   │ order-service    │ TIER-1      │ 1    │                │
│   │ inventory-api    │ TIER-2      │ 1    │                │
│   │ shipping-service │ TIER-2      │ 2    │                │
│   │ email-service    │ TIER-3      │ 2    │                │
│   └──────────────────┴─────────────┴──────┘                │
│                                                              │
│   INTERPRETATION:                                            │
│   → 4 downstream systems affected                           │
│   → 2 are TIER-1 or TIER-2 (critical)                      │
│   → Blast radius: HIGH                                       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ QUERY 2: Business Impact (Revenue at Risk)                 │
│                                                              │
│ QUESTION: What revenue is at risk if this crypto fails?    │
│                                                              │
│ CYPHER QUERY:                                                │
│   MATCH (a:CryptoAsset {asset_id: "crypto-asset-123"})     │
│   <-[:USES]-(s:System)                                      │
│   MATCH (s)-[:CALLS*0..5]->(downstream:System)             │
│   MATCH (downstream)-[:SUPPORTS]->(bp:BusinessProcess)     │
│   RETURN SUM(bp.revenue_daily) as total_revenue_at_risk,   │
│          SUM(bp.customer_count) as total_customers_at_risk, │
│          COLLECT(DISTINCT bp.name) as affected_processes    │
│                                                              │
│ RESULT:                                                      │
│   {                                                          │
│     total_revenue_at_risk: 4800000,  # $4.8M/day            │
│     total_customers_at_risk: 3200000,                       │
│     affected_processes: [                                    │
│       "Payment Processing",                                 │
│       "Order Fulfillment",                                  │
│       "Customer Authentication"                             │
│     ]                                                        │
│   }                                                          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ QUERY 3: Compliance Scope Inheritance                      │
│                                                              │
│ QUESTION: If payment-api uses this crypto, what compliance  │
│           scopes apply (including inherited)?               │
│                                                              │
│ CYPHER QUERY:                                                │
│   MATCH (a:CryptoAsset {asset_id: "crypto-asset-123"})     │
│   <-[:USES]-(s:System)                                      │
│   MATCH (s)-[:CALLS*0..5]->(downstream:System)             │
│   MATCH (downstream)-[:MUST_COMPLY_WITH]->(cs:ComplianceScope)│
│   RETURN COLLECT(DISTINCT cs.standard_name) as scopes       │
│                                                              │
│ RESULT:                                                      │
│   scopes: ["PCI-DSS-4.0", "DORA", "SWIFT-CSP", "SOC2"]    │
│                                                              │
│ INTERPRETATION:                                              │
│   This crypto must meet ALL 4 compliance standards          │
│   (most restrictive wins)                                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ QUERY 4: Shortest Path to Vendor Dependency                │
│                                                              │
│ QUESTION: Does this crypto dependency chain reach external  │
│           vendors? (supply chain risk)                      │
│                                                              │
│ CYPHER QUERY:                                                │
│   MATCH (a:CryptoAsset {asset_id: "crypto-asset-123"})     │
│   <-[:USES]-(s:System)                                      │
│   MATCH path = shortestPath(                                │
│     (s)-[:CALLS*1..10]->(vendor_sys:System)                │
│     -[:DEPENDS_ON_VENDOR]->(:Vendor)                        │
│   )                                                          │
│   RETURN path, length(path) as hops                         │
│                                                              │
│ RESULT:                                                      │
│   path: (payment-api)-[:CALLS]->(payment-gateway)          │
│         -[:CALLS]->(stripe-api)                             │
│         -[:DEPENDS_ON_VENDOR]->(Stripe Inc.)                │
│   hops: 3                                                    │
│                                                              │
│ INTERPRETATION:                                              │
│   Crypto change impacts vendor integration (coordinate)     │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 33-34 Deliverable

**Dependency graph system:**
1. Neo4j graph database deployment
2. Graph data model (8 node types, 9 relationship types)
3. Graph population from existing data (systems, assets, service mesh)
4. Istio/service mesh integration (auto-discover CALLS relationships)
5. Cypher query library (blast radius, business impact, compliance inheritance)
6. Graph visualization in dashboard (interactive graph view)
7. Reachability analysis API

**Testing:**
- Populate graph with 50 systems, 200 crypto assets, 10 business processes
- Query: Blast radius of RSA-2048 in payment-api → 12 downstream systems
- Query: Revenue at risk → $4.8M/day
- Query: Compliance inheritance → [PCI, DORA, SWIFT, SOC2]
- Dashboard: Interactive graph view (click asset → highlights all connected systems)
- Graph query performance: <100ms for 5-hop traversal

---

## WEEK 35-36: BUSINESS CONTEXT ENRICHMENT

### 🎯 Goal
Add business metadata to every crypto asset (who owns it, why it matters)

### 📐 Architecture — Business Context System

```
┌─────────────────────────────────────────────────────────────┐
│         BUSINESS CONTEXT ENRICHMENT ENGINE                  │
└─────────────────────────────────────────────────────────────┘

NEW TABLES:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: business_processes                                    │
│                                                              │
│ process_id           UUID PK                                 │
│ process_name         VARCHAR(200)   "Payment Processing"     │
│ process_description  TEXT                                    │
│ process_type         VARCHAR(50)    REVENUE_GENERATING,     │
│                                     CUSTOMER_FACING, etc     │
│ revenue_daily        DECIMAL        4800000.00  # $4.8M/day │
│ customer_count       INT            3200000                  │
│ transaction_volume   INT            150000  # txns/day       │
│ sla_uptime           DECIMAL        99.99  # %               │
│ data_classifications TEXT[]         [PAN, PII, PHI]          │
│ business_owner_id    UUID FK        → business_owners       │
│ executive_sponsor    VARCHAR(100)   "CFO"                    │
│ created_at           TIMESTAMP                                │
│ updated_at           TIMESTAMP                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: business_owners                                       │
│                                                              │
│ owner_id             UUID PK                                 │
│ name                 VARCHAR(200)   "Sarah Chen"             │
│ email                VARCHAR(200)   sarah.chen@example.com   │
│ role                 VARCHAR(100)   "VP of Payments"         │
│ department           VARCHAR(100)   "Finance"                │
│ phone                VARCHAR(50)                             │
│ slack_id             VARCHAR(100)   "@sarah.chen"            │
│ escalation_contact   VARCHAR(200)   Manager email            │
│ created_at           TIMESTAMP                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: system_business_process_map                           │
│ (Which systems support which processes)                     │
│                                                              │
│ map_id               UUID PK                                 │
│ system_id            UUID FK → systems                      │
│ process_id           UUID FK → business_processes           │
│ role                 VARCHAR(50)    PRIMARY, SUPPORTING      │
│ created_at           TIMESTAMP                                │
└──────────────────────────────────────────────────────────────┘

ENRICHMENT ALGORITHM:

┌──────────────────────────────────────────────────────────────┐
│ BUSINESS CONTEXT ENRICHMENT                                  │
│                                                              │
│ FOR EACH crypto_asset:                                       │
│                                                              │
│   # Find direct systems using this asset                    │
│   direct_systems = SELECT s.* FROM systems s                │
│                    JOIN asset_system_links asl              │
│                      ON s.system_id = asl.system_id         │
│                    WHERE asl.asset_id = crypto_asset.asset_id│
│                                                              │
│   # Find transitive systems (via graph)                     │
│   CYPHER:                                                    │
│     MATCH (a:CryptoAsset {asset_id: asset.asset_id})       │
│     <-[:USES]-(s:System)                                    │
│     MATCH (s)-[:CALLS*0..5]->(downstream:System)           │
│     RETURN COLLECT(DISTINCT downstream.system_id)           │
│                                                              │
│   all_systems = direct_systems + transitive_systems         │
│                                                              │
│   # Find business processes                                 │
│   business_processes = SELECT bp.* FROM business_processes bp│
│                        JOIN system_business_process_map map │
│                          ON bp.process_id = map.process_id  │
│                        WHERE map.system_id IN all_systems   │
│                                                              │
│   # Aggregate business impact                               │
│   business_context = {                                       │
│     total_revenue_at_risk: SUM(bp.revenue_daily),          │
│     total_customers_at_risk: SUM(bp.customer_count),        │
│     total_transaction_volume: SUM(bp.transaction_volume),  │
│     min_sla_uptime: MIN(bp.sla_uptime),                    │
│     affected_processes: [bp.process_name for bp in ...],    │
│     data_classifications: UNION(bp.data_classifications),   │
│     business_owners: DISTINCT([s.business_owner for s in ...]),│
│     executive_sponsors: DISTINCT([bp.executive_sponsor ...])│
│   }                                                          │
│                                                              │
│   # Store in crypto_assets table                            │
│   UPDATE crypto_assets                                       │
│   SET business_context = business_context                   │
│   WHERE asset_id = crypto_asset.asset_id;                   │
└──────────────────────────────────────────────────────────────┘

DASHBOARD VIEWS:

┌──────────────────────────────────────────────────────────────┐
│ CRYPTO ASSET DETAIL PAGE (Enhanced with Business Context)   │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  ASSET: AES-256-GCM in payment-api                     │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  [Crypto Details] [Evidence] [Dependencies] [Business]│  │
│ │                                                        │  │
│ │  --- BUSINESS IMPACT TAB ---                          │  │
│ │                                                        │  │
│ │  REVENUE AT RISK                                       │  │
│ │  $4.8M per day                                         │  │
│ │  🔴 CRITICAL — Revenue-generating process              │  │
│ │                                                        │  │
│ │  CUSTOMERS AFFECTED                                    │  │
│ │  3.2 million active customers                          │  │
│ │                                                        │  │
│ │  BUSINESS PROCESSES (3)                                │  │
│ │  • Payment Processing ($2.1M/day)                      │  │
│ │  • Order Fulfillment ($1.9M/day)                       │  │
│ │  • Customer Authentication ($800K/day)                 │  │
│ │                                                        │  │
│ │  DATA CLASSIFICATIONS                                  │  │
│ │  • PAN (Payment Card Data) — PCI-DSS required          │  │
│ │  • PII (Personally Identifiable Info)                  │  │
│ │                                                        │  │
│ │  BUSINESS OWNERS (2)                                   │  │
│ │  • Sarah Chen (VP Payments) sarah.chen@example.com    │  │
│ │  • Mike Johnson (Director Engineering)                 │  │
│ │                                                        │  │
│ │  EXECUTIVE SPONSORS                                    │  │
│ │  • CFO (Finance approval required for changes)         │  │
│ │  • CTO (Technical approval)                            │  │
│ │                                                        │  │
│ │  SLA REQUIREMENTS                                      │  │
│ │  Minimum uptime: 99.99% (4.3 min downtime/month max)  │  │
│ │  → Crypto migration must be zero-downtime             │  │
│ │                                                        │  │
│ │  TRANSACTION VOLUME                                    │  │
│ │  150,000 transactions/day                              │  │
│ │  → Performance testing required before migration      │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

PRIORITIZATION DASHBOARD:

┌──────────────────────────────────────────────────────────────┐
│ CRYPTO RISK PRIORITIZATION (Business-Driven)                │
│                                                              │
│ Sort by: [Revenue Impact ▼] [Customer Impact] [Compliance]  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ Rank│ Asset        │ Status │Revenue Risk│Customers│Fix│ │
│ ├─────┼──────────────┼────────┼────────────┼─────────┼───┤ │
│ │ 1   │ RSA-2048     │ FAIL   │ $4.8M/day  │ 3.2M    │P0 │ │
│ │     │ payment-api  │ PCI    │            │         │   │ │
│ ├─────┼──────────────┼────────┼────────────┼─────────┼───┤ │
│ │ 2   │ DES          │ FAIL   │ $2.1M/day  │ 1.8M    │P0 │ │
│ │     │ auth-service │ CRITICAL│           │         │   │ │
│ ├─────┼──────────────┼────────┼────────────┼─────────┼───┤ │
│ │ 3   │ TLS 1.0      │ WARN   │ $1.2M/day  │ 900K    │P1 │ │
│ │     │ api-gateway  │ DORA   │            │         │   │ │
│ └─────┴──────────────┴────────┴────────────┴─────────┴───┘ │
│                                                              │
│ SORTING LOGIC:                                               │
│   priority_score = (                                         │
│     revenue_at_risk * 0.4 +                                 │
│     customer_count * 0.0001 +  # Normalize to similar scale │
│     compliance_severity_score * 0.3 +                       │
│     technical_severity_score * 0.3                          │
│   )                                                          │
│                                                              │
│   ORDER BY priority_score DESC                              │
└──────────────────────────────────────────────────────────────┘

ALERT ENRICHMENT:

BEFORE (Month 1-8):
  "CRITICAL: RSA-2048 deprecated in system payment-api"

AFTER (Month 9 — Business Context):
  "CRITICAL: RSA-2048 deprecated in Payment Processing system
   
   Business Impact:
   • Revenue at Risk: $4.8M/day
   • Customers Affected: 3.2M
   • Business Processes: Payment Processing, Order Fulfillment
   • Data: PAN (PCI-DSS scope)
   
   Business Owner: Sarah Chen (VP Payments)
   Executive Sponsor: CFO
   
   Action Required: Migrate to ML-KEM-768 (PQC)
   Estimated Effort: 6 weeks (requires CFO approval for downtime window)
   
   [View Full Impact Analysis] [Create Migration Plan]"

STAKEHOLDER COMMUNICATION:

When compliance issue found:
  1. Security team alerted (technical details)
  2. Business owner alerted (business impact + remediation timeline)
  3. Executive sponsor alerted (if revenue > $1M/day at risk)
  
  EXAMPLE EMAIL TO BUSINESS OWNER:
    To: sarah.chen@example.com
    Subject: Action Required: Crypto Risk in Payment Processing
    
    Hi Sarah,
    
    CryptoScan detected a cryptographic compliance issue in the
    Payment Processing system (payment-api), which you own.
    
    ISSUE:
    RSA-2048 is deprecated for key exchange under NSA CNSA 2.0.
    Deadline: 2025-01-01 (347 days remaining)
    
    BUSINESS IMPACT:
    • Revenue at Risk: $4.8M/day
    • Customers Affected: 3.2 million
    • Business Process: Payment Processing (TIER-1 critical)
    • Compliance: PCI-DSS, DORA, SWIFT-CSP
    
    REQUIRED ACTION:
    Migrate to post-quantum crypto (ML-KEM-768) before deadline.
    Estimated effort: 6 weeks engineering + 2 week testing.
    
    CFO approval required (revenue impact + potential downtime).
    
    NEXT STEPS:
    1. Review full impact analysis: [Link to dashboard]
    2. Schedule kickoff meeting with security team
    3. Get CFO approval for project funding
    
    Questions? Reply to this email or Slack @security-team
    
    - CryptoScan Platform
```

### ✅ Week 35-36 Deliverable

**Business context system:**
1. `business_processes` table (revenue, customers, SLA)
2. `business_owners` table (name, email, role, department)
3. `system_business_process_map` table (linkage)
4. Business context enrichment algorithm (propagates impact metrics)
5. Enhanced asset detail page (Business Impact tab)
6. Prioritization dashboard (sort by revenue/customer impact)
7. Stakeholder-aware alerting (alerts business owners + exec sponsors)
8. Business-friendly alert templates

**Testing:**
- Create business process: "Payment Processing", revenue=$2.1M/day, 1.8M customers
- Link to systems: payment-api, payment-gateway
- Run enrichment
- View crypto asset → Business Impact tab shows: $2.1M/day revenue at risk
- Compliance issue detected → email sent to Sarah Chen (business owner) AND CFO
- Dashboard prioritization: RSA-2048 issue ranked #1 (highest revenue impact)

---

# 🎯 MONTH 7-9 COMPLETE END-TO-END FLOW SUMMARY

```
┌──────────────────────────────────────────────────────────────┐
│         PART 3 COMPLETE: MONTHS 7-9 DELIVERABLE              │
│         Full Visibility + Intelligence + Business Context    │
└──────────────────────────────────────────────────────────────┘

COMPLETE VISIBILITY ACROSS ALL LAYERS:

1. SOURCE CODE (Month 4-6)
   → 4 languages (Java, Python, JS, C#)
   → Static analysis

2. BINARIES & CONTAINERS (Month 5)
   → Docker images, JAR files
   → Library fingerprinting

3. NETWORK/RUNTIME (Month 7)
   → Live TLS sessions
   → Certificate inventory
   → (Optional) eBPF runtime tracing

4. CLOUD INFRASTRUCTURE (Month 8)
   → AWS KMS, S3, RDS, ELB, ACM
   → Azure Key Vault, Storage, SQL
   → GCP Cloud KMS, Storage, SQL

FULL DEPENDENCY INTELLIGENCE:

5. DEPENDENCY GRAPH (Month 9)
   → Neo4j graph database
   → System → System relationships
   → Crypto → System → Business Process chains
   → Vendor dependencies

6. BUSINESS CONTEXT (Month 9)
   → Revenue at risk calculations
   → Customer impact analysis
   → Business owner identification
   → Executive sponsor tracking

EXAMPLE END-TO-END SCENARIO:

Developer pushes code to payment-api (Java + Python microservices)
  ↓
CryptoScan scans:
  • Source code (Java + Python scanners)
  • Docker container (payment-api:v2.1.0)
  • Cloud config (AWS KMS keys, RDS encryption)
  ↓
Findings:
  • Source: AES-256-GCM in Payment.java:247
  • Binary: Same AES in payment-api.jar (compiled)
  • Container: OpenSSL 3.0.2 library
  • Cloud: AWS KMS key (AES-256) used by RDS
  ↓
Deduplication:
  • 4 raw findings → 2 unique assets:
    1. AES-256-GCM (application-level crypto) — VERIFIED confidence
    2. OpenSSL 3.0.2 library — HIGH confidence
  ↓
Graph population:
  • (payment-api)-[:USES]->(AES-256-GCM)
  • (payment-api)-[:CALLS]->(customer-db)
  • (payment-api)-[:SUPPORTS]->(Payment Processing)
  • (Payment Processing)-[:OWNED_BY]->(Sarah Chen)
  ↓
Business context enrichment:
  • Revenue at risk: $2.1M/day
  • Customers affected: 1.8M
  • Compliance scopes: PCI-DSS, DORA
  • Business owner: Sarah Chen (VP Payments)
  • Executive sponsor: CFO
  ↓
Network scan (scheduled hourly):
  • Probes api.payment.example.com:443
  • Detects: TLS 1.3, AES-256-GCM cipher
  • Certificate: expires in 45 days (ACM-managed)
  • Links to same crypto asset (runtime verification)
  ↓
Policy engine:
  • AES-256-GCM → PASS (all rules)
  • Certificate expiring soon → WARN (45 days)
  ↓
Dashboard shows:
  • Crypto asset: AES-256-GCM
  • Confidence: VERIFIED (source + binary + runtime + cloud)
  • Business impact: $2.1M/day revenue, 1.8M customers
  • Compliance: PASS
  • Warning: Certificate expires in 45 days
  ↓
Alert sent to:
  • Sarah Chen (business owner): "Certificate expiring"
  • Security team: "Renew certificate for payment-api"
  ↓
Blast radius query:
  • User clicks "View Dependencies" on dashboard
  • Graph shows: payment-api → customer-db → reporting-api → 4 downstream systems
  • Total systems affected: 7
  • Total revenue at risk if crypto fails: $4.8M/day

RESULT:
  ✅ Full crypto inventory across all layers
  ✅ Unified view (deduplication working)
  ✅ Business context (who cares, why it matters)
  ✅ Dependency intelligence (blast radius known)
  ✅ Compliance posture (policy engine determines)
  ✅ Stakeholder communication (business owners alerted)
  ✅ Audit-ready evidence (CBOM export + evidence chain)
```

# CryptoScan Platform — Part 3: Production-Level Folder & File Structure

```
cryptoscan-platform/
│
│  [All Part 1 + Part 2 structure remains — Part 3 additions below]
│
├── services/
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: NETWORK TLS SCANNER
│   │   (Python — active probing + certificate inventory)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── network_scanner/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   ├── Makefile
│   │   │
│   │   ├── network_scanner/
│   │   │   ├── __init__.py
│   │   │   ├── main.py                              # CLI entrypoint
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scanner.py                       # Main TLS scan orchestrator
│   │   │   │   ├── scheduler.py                     # Cron-based scan scheduler
│   │   │   │   └── scan_context.py                  # NetworkScanContext dataclass
│   │   │   │
│   │   │   ├── probing/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── active_prober.py                 # Active TLS handshake probe
│   │   │   │   ├── tcp_connector.py                 # TCP connection with timeout
│   │   │   │   ├── tls_handshaker.py                # TLS handshake execution
│   │   │   │   ├── cipher_suite_parser.py           # Parse TLS 1.2/1.3 cipher names
│   │   │   │   └── ssl_error_classifier.py          # Classify SSL error types
│   │   │   │
│   │   │   ├── passive/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── service_mesh_observer.py         # Istio/Envoy telemetry receiver
│   │   │   │   ├── envoy_log_parser.py              # Parse Envoy access logs
│   │   │   │   └── istio_telemetry_client.py        # Query Istio metrics
│   │   │   │
│   │   │   ├── certificates/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cert_extractor.py                # Extract cert chain from TLS
│   │   │   │   ├── cert_parser.py                   # Parse X.509 DER/PEM certs
│   │   │   │   ├── chain_validator.py               # Validate cert chain of trust
│   │   │   │   ├── hostname_matcher.py              # Verify hostname matches cert
│   │   │   │   ├── ocsp_checker.py                  # OCSP revocation check
│   │   │   │   ├── crl_checker.py                   # CRL revocation check
│   │   │   │   └── san_extractor.py                 # Extract Subject Alt Names
│   │   │   │
│   │   │   ├── discovery/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── config_file_loader.py            # Load YAML target config
│   │   │   │   ├── kubernetes_discoverer.py         # Query K8s services API
│   │   │   │   ├── service_mesh_discoverer.py       # Istio endpoint discovery
│   │   │   │   └── dns_discoverer.py                # DNS zone transfer discovery
│   │   │   │
│   │   │   ├── inventory/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── certificate_inventory.py         # Cert dedup + storage
│   │   │   │   ├── certificate_deduplicator.py      # SHA-256 fingerprint dedup
│   │   │   │   ├── expiry_monitor.py                # Monitor cert expiry
│   │   │   │   └── usage_tracker.py                 # Track cert → system links
│   │   │   │
│   │   │   ├── alerts/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── expiry_alerter.py                # Alert on cert expiry
│   │   │   │   └── templates/
│   │   │   │       ├── cert_expiring_7days.html
│   │   │   │       ├── cert_expiring_7days.txt
│   │   │   │       ├── cert_expiring_30days.html
│   │   │   │       └── cert_expiring_30days.txt
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── network_finding.py               # NetworkFinding dataclass
│   │   │   │   ├── certificate.py                   # Certificate dataclass
│   │   │   │   ├── tls_config.py                    # TLSConfig dataclass
│   │   │   │   └── enums.py                         # RevocationStatus, ExpiryStatus
│   │   │   │
│   │   │   └── config/
│   │   │       ├── __init__.py
│   │   │       ├── settings.py                      # NetworkScanner config
│   │   │       └── scan_targets.yaml                # Default scan targets config
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_active_prober.py
│   │       │   ├── test_cipher_suite_parser.py
│   │       │   ├── test_cert_parser.py
│   │       │   ├── test_chain_validator.py
│   │       │   ├── test_hostname_matcher.py
│   │       │   ├── test_ocsp_checker.py
│   │       │   ├── test_certificate_deduplicator.py
│   │       │   └── test_expiry_monitor.py
│   │       ├── integration/
│   │       │   ├── test_full_tls_scan.py            # Probe real endpoint
│   │       │   ├── test_cert_inventory_flow.py      # Scan → cert stored
│   │       │   ├── test_expiry_alert_fired.py       # Cert <30 days → alert
│   │       │   └── test_kubernetes_discovery.py     # K8s service discovery
│   │       └── fixtures/
│   │           ├── test_certificates/
│   │           │   ├── valid_leaf.pem
│   │           │   ├── valid_intermediate.pem
│   │           │   ├── valid_root.pem
│   │           │   ├── expired_cert.pem
│   │           │   └── self_signed.pem
│   │           └── scan_targets/
│   │               └── test_targets.yaml
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: eBPF RUNTIME AGENT
│   │   (C + Python — kernel-level crypto observation)
│   │   [OPTIONAL — Advanced]
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── ebpf_agent/
│   │   │
│   │   ├── pyproject.toml                           # Python collector deps
│   │   ├── poetry.lock
│   │   ├── Makefile                                 # make build-bpf, make deploy
│   │   │
│   │   ├── bpf/                                     # eBPF C programs (kernel side)
│   │   │   ├── crypto_tracer.c                      # Main eBPF program
│   │   │   ├── openssl_probes.c                     # OpenSSL uprobe definitions
│   │   │   ├── java_probes.c                        # JVM crypto probes
│   │   │   ├── python_probes.c                      # Python ssl probes
│   │   │   ├── events.h                             # Shared event structures
│   │   │   └── Makefile                             # Compile .c → .o BPF object
│   │   │
│   │   ├── agent/                                   # Python userspace collector
│   │   │   ├── __init__.py
│   │   │   ├── main.py                              # Agent entrypoint
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── agent.py                         # Main agent loop
│   │   │   │   ├── bpf_loader.py                    # Load eBPF program into kernel
│   │   │   │   └── uprobe_attacher.py               # Attach uprobes to libraries
│   │   │   │
│   │   │   ├── collectors/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── event_collector.py               # Read from eBPF ring buffer
│   │   │   │   ├── crypto_aggregator.py             # Aggregate cipher usage stats
│   │   │   │   └── anomaly_detector.py              # Detect TLS downgrades, weak ciphers
│   │   │   │
│   │   │   ├── library_discovery/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── library_finder.py                # Find libssl.so on system
│   │   │   │   └── symbol_resolver.py               # Resolve function offsets
│   │   │   │
│   │   │   ├── reporter/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── platform_reporter.py             # POST findings to CryptoScan API
│   │   │   │   └── finding_builder.py               # Build RawFinding from eBPF event
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── bpf_event.py                     # BPFEvent dataclass
│   │   │   │   └── runtime_finding.py               # RuntimeFinding dataclass
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py                      # Agent config
│   │   │
│   │   ├── deploy/
│   │   │   ├── daemonset.yaml                       # K8s DaemonSet manifest
│   │   │   ├── rbac.yaml                            # K8s RBAC for agent
│   │   │   └── configmap.yaml                       # Agent config as ConfigMap
│   │   │
│   │   ├── ld_preload/                              # Alternative: LD_PRELOAD shim
│   │   │   ├── crypto_shim.c                        # OpenSSL wrapper shim
│   │   │   └── Makefile
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── unit/
│   │       │   ├── test_crypto_aggregator.py
│   │       │   ├── test_anomaly_detector.py
│   │       │   └── test_finding_builder.py
│   │       └── integration/
│   │           ├── test_openssl_probe.py            # Start OpenSSL app → events captured
│   │           └── test_tls_downgrade_detection.py  # TLS 1.0 → alert fired
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: CLOUD SCANNER
│   │   (Python — AWS, Azure, GCP configuration scanning)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── cloud_scanner/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   ├── Makefile
│   │   │
│   │   ├── cloud_scanner/
│   │   │   ├── __init__.py
│   │   │   ├── main.py                              # CLI entrypoint
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── orchestrator.py                  # Multi-cloud scan orchestrator
│   │   │   │   ├── scheduler.py                     # Cloud scan scheduler (daily/weekly)
│   │   │   │   └── result_submitter.py              # Submit findings to platform API
│   │   │   │
│   │   │   ├── aws/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── iam_role_assumer.py          # STS assume-role logic
│   │   │   │   │   └── session_manager.py           # boto3 session per region
│   │   │   │   │
│   │   │   │   ├── scanners/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── kms_scanner.py               # AWS KMS key scanning
│   │   │   │   │   ├── s3_scanner.py                # S3 bucket encryption scanning
│   │   │   │   │   ├── rds_scanner.py               # RDS encryption scanning
│   │   │   │   │   ├── elb_scanner.py               # ELB/ALB TLS policy scanning
│   │   │   │   │   ├── acm_scanner.py               # ACM certificate scanning
│   │   │   │   │   ├── api_gateway_scanner.py       # API Gateway TLS scanning
│   │   │   │   │   ├── cloudfront_scanner.py        # CloudFront TLS scanning
│   │   │   │   │   ├── secretsmanager_scanner.py    # Secrets Manager scanning
│   │   │   │   │   └── lambda_scanner.py            # Lambda env encryption
│   │   │   │   │
│   │   │   │   ├── mappers/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── kms_key_spec_mapper.py       # Map KMS key spec → algorithm
│   │   │   │   │   ├── s3_sse_mapper.py             # Map SSE type → algorithm
│   │   │   │   │   └── ssl_policy_mapper.py         # Map ELB SSL policy → TLS config
│   │   │   │   │
│   │   │   │   └── region_coordinator.py            # Multi-region scan coordination
│   │   │   │
│   │   │   ├── azure/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── service_principal_auth.py    # Azure service principal auth
│   │   │   │   │   └── credential_manager.py        # DefaultAzureCredential wrapper
│   │   │   │   │
│   │   │   │   ├── scanners/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── key_vault_scanner.py         # Azure Key Vault scanning
│   │   │   │   │   ├── storage_scanner.py           # Azure Storage encryption
│   │   │   │   │   ├── sql_scanner.py               # Azure SQL TDE scanning
│   │   │   │   │   ├── app_gateway_scanner.py       # App Gateway SSL policies
│   │   │   │   │   └── front_door_scanner.py        # Front Door TLS scanning
│   │   │   │   │
│   │   │   │   └── subscription_coordinator.py      # Multi-subscription coordination
│   │   │   │
│   │   │   ├── gcp/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── service_account_auth.py      # GCP service account auth
│   │   │   │   │   └── credential_manager.py        # Google credentials wrapper
│   │   │   │   │
│   │   │   │   ├── scanners/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── cloud_kms_scanner.py         # GCP Cloud KMS scanning
│   │   │   │   │   ├── gcs_scanner.py               # GCS bucket encryption
│   │   │   │   │   ├── cloud_sql_scanner.py         # Cloud SQL encryption
│   │   │   │   │   └── load_balancer_scanner.py     # Cloud LB SSL policies
│   │   │   │   │
│   │   │   │   └── project_coordinator.py           # Multi-project coordination
│   │   │   │
│   │   │   ├── common/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── finding_builder.py               # Build CloudFinding from raw API data
│   │   │   │   ├── compliance_checker.py            # Check cloud crypto compliance
│   │   │   │   └── resource_tagger.py               # Tag resources with system mappings
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cloud_finding.py                 # CloudFinding dataclass
│   │   │   │   ├── kms_key_finding.py               # KMSKeyFinding dataclass
│   │   │   │   ├── certificate_finding.py           # CloudCertFinding dataclass
│   │   │   │   └── enums.py                         # CloudProvider, ResourceType enums
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py                      # Cloud scanner config
│   │   │
│   │   ├── iam_policies/                            # Reference IAM policy templates
│   │   │   ├── aws_cryptoscan_policy.json           # AWS IAM policy JSON
│   │   │   ├── azure_cryptoscan_role.json           # Azure custom role definition
│   │   │   └── gcp_cryptoscan_role.yaml             # GCP custom role definition
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── aws/
│   │       │   │   ├── test_kms_scanner.py
│   │       │   │   ├── test_s3_scanner.py
│   │       │   │   ├── test_rds_scanner.py
│   │       │   │   ├── test_elb_scanner.py
│   │       │   │   └── test_acm_scanner.py
│   │       │   ├── azure/
│   │       │   │   ├── test_key_vault_scanner.py
│   │       │   │   └── test_storage_scanner.py
│   │       │   └── gcp/
│   │       │       ├── test_cloud_kms_scanner.py
│   │       │       └── test_gcs_scanner.py
│   │       └── integration/
│   │           ├── test_aws_full_scan.py            # Real AWS (sandbox) full scan
│   │           ├── test_aws_no_encryption_flagged.py # S3 no encrypt → compliance fail
│   │           ├── test_aws_weak_tls_flagged.py      # TLS 1.0 ELB → flagged
│   │           ├── test_azure_scan.py
│   │           └── test_gcp_scan.py
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: DEPENDENCY GRAPH ENGINE
│   │   (Python — Neo4j graph database + Cypher queries)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── graph_engine/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   ├── Makefile
│   │   │
│   │   ├── graph_engine/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py                        # Main graph engine orchestrator
│   │   │   │   └── sync_coordinator.py              # Keep graph in sync with PG
│   │   │   │
│   │   │   ├── connection/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── neo4j_driver.py                  # Neo4j driver factory
│   │   │   │   ├── session_manager.py               # Neo4j session context manager
│   │   │   │   └── health_check.py                  # Neo4j connection health probe
│   │   │   │
│   │   │   ├── builders/                            # Graph population
│   │   │   │   ├── __init__.py
│   │   │   │   ├── node_builder.py                  # Create/MERGE graph nodes
│   │   │   │   ├── relationship_builder.py          # Create/MERGE relationships
│   │   │   │   ├── crypto_asset_syncer.py           # Sync crypto_assets → graph
│   │   │   │   ├── system_syncer.py                 # Sync systems → graph
│   │   │   │   ├── business_process_syncer.py       # Sync biz processes → graph
│   │   │   │   ├── certificate_syncer.py            # Sync certs → graph
│   │   │   │   ├── cloud_resource_syncer.py         # Sync cloud resources → graph
│   │   │   │   └── vendor_syncer.py                 # Sync vendors → graph
│   │   │   │
│   │   │   ├── service_mesh/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── istio_client.py                  # Query Prometheus Istio metrics
│   │   │   │   ├── service_call_extractor.py        # Extract CALLS relationships
│   │   │   │   └── mesh_poller.py                   # Poll mesh every hour
│   │   │   │
│   │   │   ├── queries/                             # Cypher query library
│   │   │   │   ├── __init__.py
│   │   │   │   ├── blast_radius.py                  # Downstream impact traversal
│   │   │   │   ├── business_impact.py               # Revenue + customer risk calc
│   │   │   │   ├── compliance_inheritance.py        # Compliance scope inheritance
│   │   │   │   ├── vendor_dependency.py             # Shortest path to vendor
│   │   │   │   ├── crypto_inventory.py              # Find all crypto for a system
│   │   │   │   └── reachability.py                  # General reachability queries
│   │   │   │
│   │   │   ├── schemas/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── node_schemas.py                  # Node label + property definitions
│   │   │   │   ├── relationship_schemas.py          # Relationship type definitions
│   │   │   │   └── constraints.py                   # Neo4j constraint definitions
│   │   │   │
│   │   │   ├── migrations/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── migrator.py                      # Run Neo4j schema migrations
│   │   │   │   └── versions/
│   │   │   │       ├── 0001_create_constraints.cypher
│   │   │   │       ├── 0002_create_indexes.cypher
│   │   │   │       └── 0003_add_business_process_nodes.cypher
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── graph_node.py                    # GraphNode base dataclass
│   │   │   │   ├── graph_relationship.py            # GraphRelationship dataclass
│   │   │   │   ├── blast_radius_result.py           # BlastRadiusResult dataclass
│   │   │   │   └── business_impact_result.py        # BusinessImpactResult dataclass
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py                      # Neo4j connection config
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py                          # Neo4j test fixture (test DB)
│   │       ├── unit/
│   │       │   ├── test_blast_radius_query.py
│   │       │   ├── test_business_impact_query.py
│   │       │   ├── test_compliance_inheritance_query.py
│   │       │   ├── test_vendor_dependency_query.py
│   │       │   └── test_node_builder.py
│   │       └── integration/
│   │           ├── test_full_graph_population.py    # Populate from PG → verify graph
│   │           ├── test_blast_radius_traversal.py   # 5-hop traversal < 100ms
│   │           ├── test_istio_integration.py        # Istio metrics → CALLS edges
│   │           └── test_graph_sync.py               # PG change → graph updated
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: BUSINESS CONTEXT ENGINE
│   │   (Python — revenue/customer enrichment)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── business_context/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   ├── Makefile
│   │   │
│   │   ├── business_context/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── enricher.py                      # Main enrichment orchestrator
│   │   │   │   └── enrichment_runner.py             # Run enrichment after each scan
│   │   │   │
│   │   │   ├── aggregators/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── revenue_aggregator.py            # Sum revenue across affected systems
│   │   │   │   ├── customer_aggregator.py           # Sum customer counts
│   │   │   │   ├── transaction_aggregator.py        # Sum transaction volumes
│   │   │   │   ├── sla_aggregator.py                # Find minimum SLA uptime
│   │   │   │   └── compliance_scope_aggregator.py   # Union all compliance scopes
│   │   │   │
│   │   │   ├── prioritization/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── priority_scorer.py               # Calculate priority_score
│   │   │   │   └── risk_ranker.py                   # Rank assets by business risk
│   │   │   │
│   │   │   ├── alerts/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── stakeholder_alerter.py           # Route alerts to right people
│   │   │   │   ├── business_owner_notifier.py       # Notify business owners
│   │   │   │   ├── executive_notifier.py            # Notify exec sponsors
│   │   │   │   └── templates/
│   │   │   │       ├── business_owner_alert.html    # Business owner email
│   │   │   │       ├── business_owner_alert.txt
│   │   │   │       ├── executive_alert.html         # CFO/CTO email
│   │   │   │       └── executive_alert.txt
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── business_context.py              # BusinessContext dataclass
│   │   │   │   ├── business_process.py              # BusinessProcess dataclass
│   │   │   │   ├── business_owner.py                # BusinessOwner dataclass
│   │   │   │   └── priority_score.py                # PriorityScore dataclass
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_revenue_aggregator.py
│   │       │   ├── test_customer_aggregator.py
│   │       │   ├── test_priority_scorer.py
│   │       │   └── test_stakeholder_alerter.py
│   │       └── integration/
│   │           ├── test_full_enrichment.py          # Scan → enrich → verify context
│   │           ├── test_owner_alert_sent.py         # Compliance issue → owner email
│   │           └── test_exec_alert_threshold.py     # Revenue > $1M → exec alert
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: DATABASE
│   │   (New tables for Part 3)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── database/                                    # EXTENDED from Part 1 + 2
│   │   ├── migrations/
│   │   │   └── versions/
│   │   │       ├── [Part 1+2 migrations 0001-0016]              # Unchanged
│   │   │       │
│   │   │       ├── 0017_create_network_scan_targets_table.py    # NEW
│   │   │       ├── 0018_create_certificates_table.py            # NEW
│   │   │       ├── 0019_create_certificate_usages_table.py      # NEW
│   │   │       ├── 0020_create_cloud_accounts_table.py          # NEW
│   │   │       ├── 0021_create_business_processes_table.py      # NEW
│   │   │       ├── 0022_create_business_owners_table.py         # NEW
│   │   │       ├── 0023_create_system_business_process_map.py   # NEW
│   │   │       ├── 0024_add_business_context_to_assets.py       # NEW: JSONB column
│   │   │       └── 0025_create_vendors_table.py                 # NEW
│   │   │
│   │   ├── db/
│   │   │   ├── models/
│   │   │   │   ├── [Part 1+2 models]                            # Unchanged
│   │   │   │   ├── network_scan_target.py                       # NEW ORM model
│   │   │   │   ├── certificate.py                               # NEW ORM model
│   │   │   │   ├── certificate_usage.py                         # NEW ORM model
│   │   │   │   ├── cloud_account.py                             # NEW ORM model
│   │   │   │   ├── business_process.py                          # NEW ORM model
│   │   │   │   ├── business_owner.py                            # NEW ORM model
│   │   │   │   ├── system_business_process_map.py               # NEW ORM model
│   │   │   │   └── vendor.py                                    # NEW ORM model
│   │   │   │
│   │   │   └── repositories/
│   │   │       ├── [Part 1+2 repositories]                      # Unchanged
│   │   │       ├── network_scan_target_repository.py            # NEW
│   │   │       ├── certificate_repository.py                    # NEW
│   │   │       ├── certificate_usage_repository.py              # NEW
│   │   │       ├── cloud_account_repository.py                  # NEW
│   │   │       ├── business_process_repository.py               # NEW
│   │   │       ├── business_owner_repository.py                 # NEW
│   │   │       └── vendor_repository.py                         # NEW
│   │   │
│   │   └── tests/
│   │       ├── unit/
│   │       │   ├── test_certificate_repository.py               # NEW
│   │       │   ├── test_cloud_account_repository.py             # NEW
│   │       │   └── test_business_process_repository.py          # NEW
│   │       └── integration/
│   │           ├── test_cert_dedup_query.py                     # NEW
│   │           └── test_business_context_join.py                # NEW
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: REST API
│   │   (New endpoints for Part 3)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── api/                                         # EXTENDED from Part 1 + 2
│   │   ├── api/
│   │   │   ├── routers/
│   │   │   │   ├── [Part 1+2 routers]                           # Unchanged
│   │   │   │   ├── certificates.py                              # NEW: /api/certificates
│   │   │   │   ├── network_scans.py                             # NEW: /api/network-scans
│   │   │   │   ├── cloud_scans.py                               # NEW: /api/cloud-scans
│   │   │   │   ├── graph.py                                     # NEW: /api/graph/*
│   │   │   │   ├── business_context.py                          # NEW: /api/business-context
│   │   │   │   ├── reachability.py                              # NEW: /api/reachability
│   │   │   │   └── runtime.py                                   # NEW: POST /api/scans/runtime-findings
│   │   │   │
│   │   │   ├── schemas/
│   │   │   │   ├── [Part 1+2 schemas]                           # Unchanged
│   │   │   │   ├── certificate_schemas.py                       # NEW
│   │   │   │   ├── network_scan_schemas.py                      # NEW
│   │   │   │   ├── cloud_scan_schemas.py                        # NEW
│   │   │   │   ├── graph_schemas.py                             # NEW
│   │   │   │   ├── business_context_schemas.py                  # NEW
│   │   │   │   └── reachability_schemas.py                      # NEW
│   │   │   │
│   │   │   └── webhooks/
│   │   │       ├── [Part 1+2 webhooks]                          # Unchanged
│   │   │       ├── ecr_webhook_handler.py                       # NEW: ECR push events
│   │   │       ├── acr_webhook_handler.py                       # NEW: Azure CR events
│   │   │       └── gcr_webhook_handler.py                       # NEW: GCR push events
│   │   │
│   │   └── tests/
│   │       └── integration/
│   │           ├── [Part 1+2 tests]                             # Unchanged
│   │           ├── test_certificates_endpoints.py               # NEW
│   │           ├── test_graph_endpoints.py                      # NEW
│   │           ├── test_reachability_endpoints.py               # NEW
│   │           └── test_runtime_findings_endpoint.py            # NEW
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: SCAN WORKER
│   │   (Extended pipeline for Part 3)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── worker/                                      # EXTENDED from Part 1 + 2
│   │   ├── worker/
│   │   │   ├── pipeline/
│   │   │   │   ├── [Part 1+2 stages]                            # Unchanged
│   │   │   │   ├── stage_network_scan.py                        # NEW: TLS probe stage
│   │   │   │   ├── stage_cloud_scan.py                          # NEW: Cloud config stage
│   │   │   │   ├── stage_cert_inventory.py                      # NEW: Update cert inventory
│   │   │   │   ├── stage_graph_sync.py                          # NEW: Sync to Neo4j
│   │   │   │   └── stage_business_enrich.py                     # NEW: Business context
│   │   │   │
│   │   │   └── pipeline/
│   │   │       └── pipeline_runner.py                           # UPDATED: add new stages
│   │   │
│   │   └── tests/
│   │       └── integration/
│   │           ├── [Part 1+2 tests]                             # Unchanged
│   │           └── test_full_p3_pipeline.py                     # NEW: end-to-end Part 3
│   │
│   │
│   └── ── ── ── ── ── ── ── ── ── ── ──
│       UPDATED SERVICE: WEB DASHBOARD
│       (New pages for Part 3)
│   ── ── ── ── ── ── ── ── ── ── ── ──
│
│   └── dashboard/
│       └── src/
│           ├── pages/
│           │   ├── [Part 1+2 pages]                             # Unchanged
│           │   ├── CertificateInventory.tsx                     # NEW: /certificates
│           │   ├── CertificateDetail.tsx                        # NEW: /certificates/{id}
│           │   ├── NetworkScanList.tsx                          # NEW: /network-scans
│           │   ├── CloudInventory.tsx                           # NEW: /cloud
│           │   ├── CloudInventoryDetail.tsx                     # NEW: /cloud/{account}
│           │   ├── DependencyGraph.tsx                          # NEW: /graph (interactive)
│           │   ├── BlastRadius.tsx                              # NEW: /graph/blast-radius
│           │   ├── BusinessImpact.tsx                           # NEW: /business-impact
│           │   ├── PrioritizationDashboard.tsx                  # NEW: /prioritize
│           │   └── RuntimeObservations.tsx                      # NEW: /runtime
│           │
│           ├── components/
│           │   ├── [Part 1+2 components]                        # Unchanged
│           │   │
│           │   ├── certificates/
│           │   │   ├── CertificateTable.tsx                     # NEW
│           │   │   ├── CertificateDetailCard.tsx                # NEW
│           │   │   ├── ExpiryStatusBadge.tsx                    # NEW: VALID/EXPIRING/EXPIRED
│           │   │   ├── ExpiryCountdown.tsx                      # NEW: X days remaining
│           │   │   ├── CertificateChainView.tsx                 # NEW: chain visualization
│           │   │   └── RevocationStatusBadge.tsx                # NEW: GOOD/REVOKED/UNKNOWN
│           │   │
│           │   ├── network/
│           │   │   ├── TlsConfigCard.tsx                        # NEW: TLS version + cipher
│           │   │   ├── CipherSuiteDisplay.tsx                   # NEW
│           │   │   └── NetworkScanSchedule.tsx                  # NEW: scan frequency config
│           │   │
│           │   ├── cloud/
│           │   │   ├── CloudProviderBadge.tsx                   # NEW: AWS/Azure/GCP badge
│           │   │   ├── CloudResourceTable.tsx                   # NEW
│           │   │   ├── KmsKeyCard.tsx                           # NEW: KMS key display
│           │   │   ├── S3EncryptionStatus.tsx                   # NEW
│           │   │   ├── MultiCloudFilter.tsx                     # NEW: filter by provider
│           │   │   └── RegionSelector.tsx                       # NEW
│           │   │
│           │   ├── graph/
│           │   │   ├── DependencyGraphCanvas.tsx                # NEW: D3/vis.js graph
│           │   │   ├── GraphNodeTooltip.tsx                     # NEW: hover details
│           │   │   ├── BlastRadiusHighlighter.tsx               # NEW: highlight path
│           │   │   ├── GraphLegend.tsx                          # NEW: node type legend
│           │   │   └── GraphFilters.tsx                         # NEW: filter by node type
│           │   │
│           │   ├── business/
│           │   │   ├── BusinessImpactTab.tsx                    # NEW: asset detail tab
│           │   │   ├── RevenueAtRiskCard.tsx                    # NEW: $X/day display
│           │   │   ├── CustomersAffectedCard.tsx                # NEW
│           │   │   ├── BusinessProcessList.tsx                  # NEW
│           │   │   ├── BusinessOwnerCard.tsx                    # NEW
│           │   │   └── ExecutiveSponsorBadge.tsx                # NEW
│           │   │
│           │   └── prioritization/
│           │       ├── PriorityRankTable.tsx                    # NEW: ranked by risk
│           │       ├── PriorityScoreBadge.tsx                   # NEW: P0/P1/P2
│           │       └── SortBySelector.tsx                       # NEW: sort by revenue/customers
│           │
│           ├── hooks/
│           │   ├── [Part 1+2 hooks]                             # Unchanged
│           │   ├── useCertificates.ts                           # NEW
│           │   ├── useNetworkScans.ts                           # NEW
│           │   ├── useCloudInventory.ts                         # NEW
│           │   ├── useGraph.ts                                  # NEW: graph data + queries
│           │   ├── useBlastRadius.ts                            # NEW: blast radius query
│           │   └── useBusinessContext.ts                        # NEW
│           │
│           ├── api/
│           │   ├── [Part 1+2 api]                               # Unchanged
│           │   ├── certificates.api.ts                          # NEW
│           │   ├── network_scans.api.ts                         # NEW
│           │   ├── cloud.api.ts                                 # NEW
│           │   ├── graph.api.ts                                 # NEW
│           │   └── business_context.api.ts                      # NEW
│           │
│           └── types/
│               ├── [Part 1+2 types]                             # Unchanged
│               ├── certificate.types.ts                         # NEW
│               ├── network_scan.types.ts                        # NEW
│               ├── cloud.types.ts                               # NEW
│               ├── graph.types.ts                               # NEW
│               └── business_context.types.ts                    # NEW
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED INFRASTRUCTURE
│   (Neo4j + updated monitoring)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── infra/
│   ├── [Part 1+2 infra]                                         # Unchanged
│   │
│   ├── neo4j/                                                   # NEW
│   │   ├── neo4j.conf                                           # Neo4j configuration
│   │   ├── init/
│   │   │   └── 01_create_constraints.cypher                     # Initial schema
│   │   └── plugins/
│   │       └── apoc.jar                                         # APOC plugin for Neo4j
│   │
│   ├── prometheus/
│   │   └── prometheus.yml                                       # UPDATED: add Istio scrape
│   │
│   └── monitoring/
│       └── grafana/
│           └── dashboards/
│               ├── [Part 1+2 dashboards]                        # Unchanged
│               ├── network_scan_metrics.json                    # NEW
│               ├── cloud_scan_metrics.json                      # NEW
│               ├── certificate_expiry_dashboard.json            # NEW
│               └── graph_query_performance.json                 # NEW
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED DOCKER FILES
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── .docker/
│   ├── [Part 1+2 dockerfiles]                                   # Unchanged
│   ├── network_scanner/
│   │   └── Dockerfile                                           # NEW
│   ├── ebpf_agent/
│   │   └── Dockerfile                                           # NEW (privileged container)
│   ├── cloud_scanner/
│   │   └── Dockerfile                                           # NEW
│   ├── graph_engine/
│   │   └── Dockerfile                                           # NEW
│   └── business_context/
│       └── Dockerfile                                           # NEW
│
├── docker-compose.yml                                           # UPDATED: add neo4j + new services
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED SCRIPTS
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── scripts/
│   ├── [Part 1+2 scripts]                                       # Unchanged
│   ├── setup_aws_iam.sh                                         # NEW: create IAM role + policy
│   ├── setup_azure_service_principal.sh                         # NEW
│   ├── setup_gcp_service_account.sh                             # NEW
│   ├── seed_network_targets.py                                  # NEW: add scan targets
│   ├── seed_business_processes.py                               # NEW: add biz context
│   ├── seed_business_owners.py                                  # NEW: add owners
│   ├── run_cloud_scan.py                                        # NEW: trigger cloud scan
│   ├── run_network_scan.py                                      # NEW: trigger TLS scan
│   ├── populate_graph.py                                        # NEW: sync data to Neo4j
│   └── blast_radius_query.py                                    # NEW: CLI blast radius query
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   KUBERNETES MANIFESTS
│   (Part 3 introduces K8s-native components)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── k8s/
│   ├── ebpf-agent/
│   │   ├── daemonset.yaml                                       # eBPF agent DaemonSet
│   │   ├── rbac.yaml                                            # ClusterRole + binding
│   │   ├── configmap.yaml                                       # Agent config
│   │   └── serviceaccount.yaml
│   │
│   ├── network-scanner/
│   │   ├── deployment.yaml
│   │   ├── cronjob.yaml                                         # Scheduled TLS scans
│   │   └── configmap.yaml                                       # scan_targets.yaml
│   │
│   ├── cloud-scanner/
│   │   ├── deployment.yaml
│   │   ├── cronjob.yaml                                         # Daily cloud scans
│   │   └── secret.yaml                                          # Cloud credentials (sealed)
│   │
│   └── neo4j/
│       ├── statefulset.yaml                                     # Neo4j StatefulSet
│       ├── service.yaml
│       └── persistentvolumeclaim.yaml
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED DOCUMENTATION
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
└── docs/
    ├── [Part 1+2 docs]                                          # Unchanged
    │
    ├── user-guide/
    │   ├── [Part 1+2 guides]                                    # Unchanged
    │   ├── certificate-inventory.md                             # NEW
    │   ├── network-scanning.md                                  # NEW
    │   ├── cloud-scanning.md                                    # NEW
    │   ├── dependency-graph.md                                  # NEW
    │   ├── blast-radius-analysis.md                             # NEW
    │   ├── business-impact.md                                   # NEW
    │   └── prioritization-dashboard.md                          # NEW
    │
    ├── admin-guide/
    │   ├── [Part 1+2 guides]                                    # Unchanged
    │   ├── aws-iam-setup.md                                     # NEW
    │   ├── azure-service-principal-setup.md                     # NEW
    │   ├── gcp-service-account-setup.md                         # NEW
    │   ├── kubernetes-ebpf-deployment.md                        # NEW
    │   ├── neo4j-setup.md                                       # NEW
    │   ├── network-scan-targets-config.md                       # NEW
    │   └── business-context-setup.md                            # NEW
    │
    ├── architecture/
    │   ├── [Part 1+2 docs]                                      # Unchanged
    │   ├── network-scanner-design.md                            # NEW
    │   ├── ebpf-agent-design.md                                 # NEW
    │   ├── cloud-scanner-design.md                              # NEW
    │   ├── graph-data-model.md                                  # NEW: node/rel types
    │   ├── business-context-design.md                           # NEW
    │   └── multi-layer-visibility.md                            # NEW: all scan layers
    │
    └── decisions/
        ├── [Part 1+2 ADRs]                                      # Unchanged
        ├── ADR-010-neo4j-for-dependency-graph.md                # NEW
        ├── ADR-011-active-vs-passive-tls-scanning.md            # NEW
        ├── ADR-012-ebpf-vs-ld-preload.md                        # NEW
        └── ADR-013-multi-cloud-iam-strategy.md                  # NEW
```

---

## Part 3 Structure Summary

```
NEW SERVICES ADDED (5):
  ├── network_scanner/      → TLS active probing + cert inventory
  ├── ebpf_agent/           → Kernel-level runtime crypto observation
  ├── cloud_scanner/        → AWS + Azure + GCP config scanning
  ├── graph_engine/         → Neo4j dependency graph + Cypher queries
  └── business_context/     → Revenue/customer enrichment + prioritization

NEW INFRASTRUCTURE:
  ├── neo4j/                → Graph database (replaces simple asset_system_links)
  └── k8s/                  → Kubernetes manifests (eBPF DaemonSet, CronJobs)

NEW DATABASE TABLES (Part 3):
  ├── network_scan_targets   → Endpoints to scan + schedule
  ├── certificates           → X.509 cert inventory (deduped by fingerprint)
  ├── certificate_usages     → Cert → system → endpoint links
  ├── cloud_accounts         → AWS/Azure/GCP account config
  ├── business_processes     → Revenue, customers, SLA per process
  ├── business_owners        → Owner name, email, role, escalation
  ├── system_business_process_map → System ↔ business process links
  └── vendors                → External vendor dependencies

KEY DESIGN DECISIONS:
  ├── Neo4j runs ALONGSIDE PostgreSQL (not replacing it)
  │   PG = evidence records (immutable, auditable)
  │   Neo4j = relationship graph (queryable, traversable)
  │
  ├── eBPF agent is OPTIONAL
  │   Network TLS scanner covers most use cases
  │   eBPF adds runtime verification where K8s available
  │
  ├── Cloud scanner produces same RawFinding schema
  │   Same evidence pipeline handles cloud findings
  │   Same deduplication works cross-cloud
  │
  └── Business context enrichment runs AFTER deduplication
      Assets already unified → enrich once, not per-finding
```