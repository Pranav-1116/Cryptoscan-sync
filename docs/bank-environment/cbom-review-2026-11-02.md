# CBOM review — usage proof, evidence classes, conflicts

*Received 2026-11-02. Saved verbatim as the requirement document for guide 139.*

```
What you already have
Your current architecture explicitly treats CBOM as a first-class BOM, separate from SBOM, HBOM, NBOM, VBOM and TechBOM.

Your documented APIs include:
GET/POST CBOM scan
/api/v1/cbom/scan/{scan_id}

/api/v1/cbom/system/{system_id}

/api/v1/cbom/portfolio

and the UI surfaces include:
/cbom
/crypto-assets
/findings
/evidence

You also have content-addressed CBOM pins, which is a very good foundation for immutable evidence and historical comparison.
2. Crypto discovery itself is strong
The current CBOM model can represent things such as:
Algorithm
Key size
Mode
Purpose
Library
Location
Provenance
Evidence

For example:
System:
payment-signing-service

Crypto:
RSA

Key size:
2048

Location:
src/signing.py:42

Evidence:
finding ID

Provenance:
recorded finding

This is already useful for cryptographic governance.

The current example also shows a CycloneDX-style cryptographic asset:
RSA-2048

assetType:
algorithm

OID:
1.2.840.113549.1.1.1

primitive:
pke

algorithm:
RSA

parameterSetIdentifier:
2048

So the CBOM isn't simply:
RSA
AES
SHA

It has structured cryptographic properties.
3. Biggest strength: you don't automatically equate crypto detection with compromise
This is correct:
RSA-2048 detected
        ≠
RSA-2048 compromised

And:
AES detected
        ≠
AES-256-GCM actually used

Your documentation explicitly maintains that distinction.

This is exactly the right direction.
4. But your biggest CBOM weakness is still usage proof
This is the single biggest improvement I would make.

Currently you can get:
Source
 ↓
Crypto finding
 ↓
CBOM

But a production-grade CryptoScan CBOM needs:
Source
   ↓
Static evidence
   ↓
Config evidence
   ↓
SBOM/library evidence
   ↓
Runtime evidence
   ↓
Network evidence
   ↓
HSM/KMS evidence
   ↓
Certificate evidence
   ↓
Correlation
   ↓
CBOM

So instead of:
AES-256-GCM
confidence: HIGH

you want:
AES-256-GCM

Capability:
YES

Static:
OBSERVED

Runtime:
OBSERVED

Network:
OBSERVED

HSM:
NOT_OBSERVED

Evidence:
EVID-001
EVID-021
EVID-089

Confidence:
VERY_HIGH

That is the difference between a crypto inventory and a cryptographic intelligence platform.
5. You need stronger evidence classifications
Your entire CryptoScan architecture already uses evidence concepts, so CBOM should fully adopt them.

I recommend every crypto asset supporting:
OBSERVED
STATIC_OBSERVED
RUNTIME_OBSERVED
NETWORK_OBSERVED
CONFIGURED
IMPORTED
VENDOR_DECLARED
INFERRED
UNKNOWN

For example:
OpenSSL
SBOM:
OpenSSL 3.0.13
        ↓
CAPABILITY

Source
EVP_aes_256_gcm()
        ↓
STATIC_OBSERVED

Runtime
AES-256-GCM operation
        ↓
RUNTIME_OBSERVED

Network
TLS_AES_256_GCM_SHA384
        ↓
NETWORK_OBSERVED

Now CBOM can say:
AES-256-GCM
----------------
Capability      YES
Static          YES
Runtime         YES
Network         YES

That's extremely powerful.
6. Don't let SBOM create false CBOM assets
This is critical.

Suppose:
SBOM:

OpenSSL 3.0.13

OpenSSL supports:
AES
RSA
ECDSA
ECDH
SHA
HMAC
...

You must not generate:
AES-128 USED
AES-256 USED
RSA-2048 USED
ECDSA-P256 USED

just because OpenSSL supports them.

Instead:
OpenSSL 3.0.13
        ↓
Crypto-capable library
        ↓
Candidate algorithms

Then evidence can promote them.

This aligns with your existing six-BOM architecture, which explicitly says a package indicating crypto capability does not prove actual algorithm invocation.
7. Runtime CBOM is the biggest technical gap
This is where I would invest heavily.

Your target architecture should eventually support:
Application
   ↓
Process
   ↓
Crypto provider
   ↓
Crypto operation
   ↓
Algorithm
   ↓
Parameters

Example:
payments-api
PID 9182
OpenSSL 3.0.13

operation:
EVP_EncryptInit_ex

algorithm:
AES-256-GCM

key size:
256

mode:
GCM

timestamp:
2026-11-02 10:42:11

evidence:
RUNTIME-92821

Then:
CBOM

contains a runtime-confirmed crypto asset.

This should be one of your highest-priority improvements.
8. Network CBOM correlation needs improvement
Your network layer can observe things such as:
TLS 1.3
AES-256-GCM
X25519
ECDSA-P256

But that needs to be correlated to the correct system.

For example:
Internet
 ↓
WAF
 ↓
External LB
 ↓
API Gateway
 ↓
Payments API

If network observes:
TLS_AES_256_GCM_SHA384

the CBOM should say:
Network crypto asset:
AES-256-GCM

Endpoint:
payments.bank.example:443

Observed on:
External LB

Evidence:
NET-9281

Hop:
Internet → External LB

Not:
Payments API uses AES-256-GCM

unless the evidence actually proves that.

This distinction is very important in your LB/TLS architecture.
9. TLS termination needs special CBOM handling
Example:
Client
  |
TLS1.3
AES-256-GCM
  |
External LB
  |
TLS1.2
AES-128-GCM
  |
API Gateway
  |
TLS1.3
AES-256-GCM
  |
Payments API

Your CBOM should show three separate cryptographic relationships.

Not one:
Payments API = AES-256

Instead:
PATH 1
Client → LB
TLS1.3
AES-256-GCM

PATH 2
LB → API Gateway
TLS1.2
AES-128-GCM

PATH 3
API Gateway → Payments
TLS1.3
AES-256-GCM

This is one of the areas where CryptoScan can become significantly better than normal CBOM tooling.
10. Certificate crypto should become a separate evidence category
For every certificate:
Certificate
 ↓
Public-key algorithm
 ↓
Key size / curve
 ↓
Signature algorithm
 ↓
Issuer
 ↓
Validity
 ↓
Endpoint

Example:
cert-9281

Public key:
ECDSA P-256

Signature:
ECDSA-SHA256

SAN:
payments.bank.example

Endpoint:
443

Observed:
External LB

But don't confuse:
certificate public key

with:
application cryptographic operations

For example:
ECDSA P-256 certificate

doesn't prove the application is performing ECDSA signatures internally.
11. HSM/KMS correlation is currently too weak
For your bank product, this is a major gap.

You need:
Application
   ↓
HSM/KMS
   ↓
Key metadata
   ↓
Crypto operation

Example:
Payments API
     |
     | USES_HSM
     ↓
HSM-01
     |
     ↓
Key reference:
PAY-SIGN-001

Algorithm:
RSA

Key size:
2048

Operation:
SIGN

Evidence:
HSM-EVID-001

The CBOM should distinguish:
HSM capability

from:
HSM configured key

from:
actual HSM operation

Again:
supported RSA-4096
≠
RSA-4096 key exists
≠
RSA-4096 actually used

12. Key metadata model needs strengthening
For banking, CBOM should eventually support:
key_id/reference
algorithm
key_size
curve
purpose
usage
key_type
provider
location
HSM/KMS
creation_time
rotation_time
status
certificate
owner
application
system
evidence

But never store private keys or secret material.

For example:
key_ref:
HSM://partition-01/key/PAY-SIGN-001

algorithm:
RSA

size:
2048

purpose:
SIGN

private_material:
NOT STORED

13. Crypto purpose needs to become first-class
Don't just store:
AES-256

Store:
AES-256
purpose:
DATA_AT_REST

or:
AES-256-GCM
purpose:
TLS

or:
RSA-2048
purpose:
DIGITAL_SIGNATURE

or:
ECDH P-256
purpose:
KEY_AGREEMENT

Potential purposes:
ENCRYPTION
DECRYPTION
SIGNATURE
VERIFICATION
KEY_AGREEMENT
KEY_WRAPPING
HASHING
MAC
KDF
TLS
MTLS
SSH
VPN
DATABASE_TLS
DATABASE_TDE
BACKUP_ENCRYPTION
TOKEN_SIGNING
PAYMENT_SIGNING
HSM_OPERATION
KMS_OPERATION

This will make PQC migration much more useful.
14. PQC readiness is not the same as CBOM
This is another important architectural distinction.

CBOM tells you:
what cryptography exists

PQC analysis tells you:
what cryptography needs migration
what depends on it
what blocks migration

So:
CBOM
 ↓
Crypto inventory
 ↓
PQC engine ↓
Migration assessment

Don't put all PQC decision logic directly into CBOM generation.
15. Your current quantumVulnerable approach needs richer semantics
Your example has:
quantumVulnerable: null

That is actually good because it doesn't invent a conclusion.

But eventually I would replace a simple boolean-style model with something like:
PQC_STATUS:

NOT_ASSESSED
CLASSICAL_ONLY
QUANTUM_SENSITIVE
QUANTUM_RESISTANT
HYBRID
TRANSITIONAL
UNKNOWN

And separate:
algorithm_class
quantum_risk
migration_priority
migration_status

Example:
RSA-2048

algorithm_class:
PUBLIC_KEY

quantum_status:
QUANTUM_SENSITIVE

migration_priority:
HIGH

migration_status:
NOT_STARTED
16. CBOM conflict resolution is a major missing feature
This should be a core CryptoScan feature.

Suppose you receive:
SBOM:
OpenSSL 3.0.13

Container:
OpenSSL 3.0.13

Runtime:
OpenSSL 3.0.11

Vendor:
OpenSSL 3.0.13

Static:
AES-256-GCM

Runtime:
AES-128-GCM

Network:
AES-256-GCM

Don't collapse this into:
OpenSSL 3.0.13
AES-256-GCM

Instead:
┌───────────────┬──────────────┬───────────────┐
│ Source        │ Fact         │ Evidence      │
├───────────────┼──────────────┼───────────────┤
│ SBOM          │ 3.0.13       │ Imported      │
│ Container     │ 3.0.13       │ Observed      │
│ Runtime       │ 3.0.11       │ Runtime       │
│ Vendor        │ 3.0.13       │ Declared      │
└───────────────┴──────────────┴───────────────┘

Then:
CONFLICT:
runtime_version != artifact_version

This is exactly what your Evidence Graph/Digital Twin architecture should solve.
17. CBOM should have evidence confidence
I recommend something like:
UNKNOWN
LOW
MEDIUM
HIGH
VERY_HIGH

But confidence must be deterministically calculated, not AI-generated.

Example:
SBOM capability:
LOW

Static source:
MEDIUM

Configuration:
MEDIUM

Runtime:
HIGH

Network:
HIGH

Runtime + Network + Static:
VERY_HIGH

And the UI should show why.
18. CBOM needs coverage
This is extremely important.

Suppose:
100 applications

but CryptoScan only inspected:
62 applications

and found:
12 RSA assets

You cannot say:
The bank has 12 RSA assets.

You should say:
12 RSA assets discovered
62/100 applications inspected
Coverage: 62%

And:
CBOM completeness:
PARTIAL

Your existing architecture already has the concept of explicit coverage and UNKNOWN/PARTIAL instead of pretending missing evidence means nothing exists. That should be applied directly to CBOM.
19. Empty CBOM handling is already conceptually correct
Your docs correctly say an empty CBOM does not necessarily mean:
No cryptography exists.

It could mean:
No crypto detected
OR
No crypto inventory ingested
OR
Relevant paths unsupported/excluded

and it must be reconciled with scan coverage/errors.

Keep this behavior.

This is one of the most important correctness principles in the whole product.
20. CBOM → Digital Twin is the next major step
Your final architecture should become:
                     EVIDENCE
                        │
        ┌───────────────┼────────────────┐
        │               │                │
       SBOM           STATIC           NETWORK
        │               │                │
        └───────────────┼────────────────┘
                        │
                     RUNTIME
                        │
                      HSM / KMS
                        │
                     ▼
               ┌────────────────┐
               │  CRYPTO GRAPH  │
               └───────┬────────┘
                       │
                       ▼
                     CBOM
                       │
                       ▼
                DIGITAL TWIN
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        DRIFT         PQC        THREAT
      ANALYSIS      MIGRATION   INTELLIGENCE

That is the architecture I would target.
21. CBOM security blockers
🔴 Evidence spoofing
Imported CBOM/SBOM/vendor data must never automatically become:
OBSERVED

It should stay:
IMPORTED

until independently verified.
🔴 False crypto attribution
Don't automatically attribute:
OpenSSL

to every algorithm it supports.
🔴 Secret leakage
CBOM collectors must never store:
private keys
session keys
plaintext
secret key material
customer payloads

Only metadata/key references.
🔴 Weak evidence promotion
Don't allow:
VENDOR_DECLARED

to become:
RUNTIME_OBSERVED

without evidence.
🔴 Signature/hash confusion
Your documentation already correctly distinguishes hashes, HMACs and signatures. Keep those contracts separate.
```
