# 47_UNIFIED_ASSET_IDENTITY_AUDIT.md
## ZELNX CryptoScan — Unified Asset Identity Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of all asset identity mechanisms across all discovery sources and BOMs  
**Scope:** Complete identity model across Organization, Tenant, Business Unit, Owner, Application, Service, Repository, Host, VM, Container, Pod, Cluster, Network, Device, Hardware, Cloud Resource, Database, API, Certificate, Cryptographic Component, Package, Library, Vendor

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX recognize that the same asset discovered from AWS, Kubernetes, source code and network scanning is actually the SAME asset?"*

**Answer: NO** — ZELNX has **no unified asset identity model**. Assets discovered from different sources receive completely different identifiers with no linking mechanism.

| Identity Aspect | Status | Score |
|-----------------|--------|-------|
| Canonical IDs | ❌ Missing | 0/10 |
| Cross-Source Linking | ❌ Missing | 0/10 |
| Alias Management | ⚠️ Partial | 3/10 |
| UUID Consistency | ❌ Inconsistent | 2/10 |
| External ID Mapping | ⚠️ Partial | 3/10 |
| Cloud Resource IDs | ⚠️ Partial | 4/10 |
| Hostname Relationships | ⚠️ Partial | 3/10 |
| Repository Relationships | ✅ Good | 7/10 |
| Ownership Relationships | ✅ Good | 7/10 |

**Overall: 2.5/10** — No unified identity model exists.

---

## 1. IDENTITY MODEL INVENTORY

### 1.1 Current Identity Mechanisms by Source

| Source | Primary Identifier | Format | Scope |
|--------|-------------------|--------|-------|
| **Source Code Scanner** | `finding_id` + `evidence_id` | UUID v4 | Per finding |
| **Binary Scanner** | `finding_id` + `content_hash` | UUID v4 + SHA-256 | Per binary finding |
| **Container Scanner** | `scan_id` + layer digest | UUID + SHA-256 | Per layer |
| **Kubernetes Scanner** | `resource_uid` + `namespace/name` | K8s UID | Per resource |
| **Network Scanner** | `endpoint_hash` (host:port) | SHA-256(host:port) | Per endpoint |
| **Cloud Scanner (AWS)** | `arn` / `resource_id` | AWS ARN | Per resource |
| **Cloud Scanner (Azure)** | `resource_id` | Azure Resource ID | Per resource |
| **Cloud Scanner (GCP)** | `resource_name` | GCP resource name | Per resource |
| **Certificate Scanner** | `certificate_fingerprint` (SHA-256) | SHA-256(DER) | Per certificate |
| **Hardware Scanner** | `asset_id` (host:serial) | host:serial | Per device |
| **Vendor Scanner** | `vendor_id` + `product_id` | UUID + string | Per product |

**Critical Finding:** **12 different identifier schemes** with zero overlap.

---

## 2. ENTITY IDENTITY ANALYSIS

### 2.1 Canonical Identity Coverage

| Entity Type | Canonical ID | Aliases | External IDs | Cloud IDs | Hostname | Repo Link | Owner Link |
|-------------|--------------|---------|--------------|-----------|----------|-----------|------------|
| **Organization** | `tenant_id` (UUID) | name, slug | N/A | N/A | N/A | N/A | N/A |
| **Tenant** | `tenant_id` (UUID) | name, slug | N/A | N/A | N/A | N/A | N/A |
| **Business Unit** | `business_unit_id` (UUID) | name | N/A | N/A | N/A | N/A | `owner_id` |
| **Owner** | `user_id` / `business_owner_id` | email, name | SCIM ID, SSO sub | N/A | N/A | N/A | N/A |
| **Application** | `system_id` (UUID) | name | N/A | N/A | N/A | `repo_configuration_id` | `owner_id` |
| **Service** | `system_id` (UUID) | name | N/A | Cloud ARN/ID | N/A | `repo_configuration_id` | `owner_id` |
| **Repository** | `repo_configuration_id` | URL, name | Git remote URL | N/A | N/A | N/A | `owner_id` |
| **Host** | `hostname` / `asset_id` | FQDN, IP | Cloud instance ID | Instance ID | ✅ Primary | N/A | `owner_id` |
| **VM** | Cloud instance ID | Name, tags | Cloud instance ID | ✅ Primary | N/A | N/A | `owner_id` |
| **Container** | Layer digest / Image ID | Image name:tag | Image digest | N/A | N/A | Dockerfile repo | `owner_id` |
| **Pod** | K8s UID | namespace/name | N/A | N/A | Node name | N/A | `owner_id` |
| **Cluster** | Cluster name / ARN | Name, region | Cluster ARN/ID | N/A | N/A | N/A | `owner_id` |
| **Network** | `endpoint_hash` | host:port | N/A | Load balancer ARN | ✅ Primary | N/A | `owner_id` |
| **Device** | `asset_id` (host:serial) | Hostname, MAC | Cloud instance ID | N/A | ✅ Primary | N/A | `owner_id` |
| **Hardware (HSM/TPM)** | `asset_id` | Serial, model | N/A | N/A | Hostname | N/A | `owner_id` |
| **Cloud Resource** | Cloud ARN/ID | Name, tags | Cloud ARN/ID | ✅ Primary | N/A | N/A | `owner_id` |
| **Database** | Cloud ARN/ID | Identifier, endpoint | Cloud ARN/ID | ✅ Primary | Endpoint host | N/A | `owner_id` |
| **API** | `system_id` + path | OpenAPI title | API Gateway ARN | N/A | Hostname | Repo | `owner_id` |
| **Certificate** | `certificate_fingerprint` (SHA-256) | Subject, serial | N/A | ACM cert ARN | CN/SAN | N/A | `owner_id` |
| **Crypto Component** | `evidence_id` / `finding_id` | Algorithm+location | N/A | KMS key ARN | N/A | File path | `owner_id` |
| **Package/Library** | `library_fingerprint` | Name, version | Package manager ID | N/A | N/A | Lockfile repo | `owner_id` |
| **Vendor** | `vendor_id` (UUID) | Name, domain | Website, support URL | Marketplace ID | N/A | N/A | `owner_id` |

---

## 3. CROSS-SOURCE IDENTITY LINKING

### 3.1 Current Linking Mechanisms

| Link Type | Mechanism | Coverage |
|-----------|-----------|----------|
| **System ↔ Repository** | `RepoConfiguration.system_id` + `RepoConfiguration.url` | ✅ Explicit |
| **System ↔ Assets** | `SystemAsset` link table | ✅ Explicit |
| **System ↔ Dependencies** | `SystemDependency` table | ✅ Explicit |
| **System ↔ Business Processes** | `SystemBusinessProcess` table | ✅ Explicit |
| **System ↔ Owner** | `System.owner` + `BusinessOwner` | ✅ Explicit |
| **System ↔ Certificates** | `CertificateUsage` table | ✅ Explicit |
| **System ↔ Cloud** | `CloudAccount.system_id` | ✅ Explicit |
| **System ↔ Network** | `NetworkInventory.system_id` | ✅ Explicit |
| **System ↔ Hardware** | `CryptoHardwareLink` (manual) | ⚠️ Manual only |
| **System ↔ Vendor** | `VendorDependency` (manual) | ⚠️ Manual only |

### 3.2 Missing Cross-Source Links

| Missing Link | Example | Impact |
|--------------|---------|--------|
| **AWS EC2 ↔ K8s Node** | Same physical host | Cannot correlate cloud + k8s view |
| **K8s Pod ↔ Container Image** | Pod runs container | Cannot trace runtime to image |
| **Container Image ↔ Source Repo** | Image built from repo | Cannot trace binary to source |
| **Network Endpoint ↔ K8s Service** | Service exposes pod | Cannot correlate network + k8s |
| **Cloud LB ↔ Backend Pods** | LB → Target Group → Pods | Cannot trace traffic path |
| **Certificate ↔ K8s Secret** | Cert stored in secret | Cannot trace cert lifecycle |
| **Cloud KMS Key ↔ App Usage** | App uses KMS key | Cannot trace key usage |
| **HSM Key ↔ App Usage** | App uses HSM key | Cannot trace key usage |
| **Vendor Lib ↔ Source Import** | Code imports vendor lib | Cannot trace vendor risk |
| **SBOM Component ↔ Source Import** | SBOM lists component | Cannot trace to source code |

---

## 4. IDENTIFIER SCHEMES ANALYSIS

### 4.1 Identifier Formats by Source

| Source | Identifier | Format | Example |
|--------|------------|--------|---------|
| **Source Scanner** | `finding_id` | UUID v4 | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| **Source Scanner** | `evidence_id` | UUID v4 | `f1e2d3c4-b5a6-9870-fedc-ba9876543210` |
| **Binary Scanner** | `content_hash` | SHA-256 hex | `a1b2c3d4e5f67890...` |
| **Container** | Layer digest | `sha256:abc123...` | `sha256:abc123def456...` |
| **Kubernetes** | Resource UID | Kubernetes UID | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| **Kubernetes** | namespace/name | `namespace/name` | `production/payment-api` |
| **Network** | Endpoint hash | SHA-256(host:port) | `a1b2c3d4e5f6...` |
| **AWS** | ARN | `arn:aws:service:region:account:resource` | `arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0` |
| **Azure** | Resource ID | `/subscriptions/.../resourceGroups/.../providers/...` | `/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1` |
| **GCP** | Resource name | `projects/project/locations/location/resource` | `projects/my-project/locations/us-central1/instances/vm1` |
| **Certificate** | Fingerprint (SHA-256) | `sha256:abc123...` | `sha256:abc123def456...` |
| **Hardware** | asset_id | `host:serial` | `host1:ABC123XYZ` |
| **Vendor** | vendor_id | UUID v4 | `v1e2d3c4-b5a6-9870-fedc-ba9876543210` |

**Critical:** **12 completely different identifier formats** with no translation layer.

---

### 4.2 UUID Usage Consistency

| Table | Primary Key | Format | Consistent |
|-------|-------------|--------|------------|
| `scans` | `id` | UUID v4 (String 36) | ✅ |
| `evidence_records` | `id` | UUID v4 (String 36) | ✅ |
| `crypto_assets` | `id` | UUID v4 (String 36) | ✅ |
| `systems` | `id` | UUID v4 (String 36) | ✅ |
| `users` | `id` | UUID v4 (String 36) | ✅ |
| `tenants` | `id` | UUID v4 (String 36) | ✅ |
| `baselines` | `id` | UUID v4 (String 36) | ✅ |
| `crypto_library_fingerprints` | `id` | UUID v4 (String 36) | ✅ |
| `network_inventory` | `id` | UUID v4 (String 36) | ✅ |
| `cloud_accounts` | `id` | UUID v4 (String 36) | ✅ |
| `certificates` | `id` | UUID v4 (String 36) | ✅ |
| `vendors` | `id` | UUID v4 (String 36) | ✅ |
| `hardware_live` | `asset_id` | String (host:serial) | ❌ Different |
| `network_inventory` | `id` | UUID v4 (String 36) | ✅ |
| `crypto_library_fingerprints` | `id` | UUID v4 (String 36) | ✅ |
| `technology_bom_snapshots` | `version` | Integer | ❌ Different |

**Critical:** `hardware_live.asset_id` uses `host:serial` format; `technology_bom_snapshots` uses integer version.

---

## 5. ALIAS MANAGEMENT

### 5.1 Current Alias Support

| Entity | Alias Support | Implementation |
|--------|---------------|----------------|
| **System** | ✅ `name` + `slug` | `System.name`, `System.slug` |
| **User** | ✅ `email`, `display_name` | `User.email`, `User.display_name` |
| **Tenant** | ✅ `name`, `slug` | `Tenant.name`, `Tenant.slug` |
| **Certificate** | ⚠️ Subject, SAN, Serial | Certificate fields only |
| **Certificate** | ❌ External aliases | No alias table |
| **System** | ❌ External aliases | No alias table |
| **Asset** | ❌ External aliases | No alias table |
| **Certificate** | ❌ Cloud ARN alias | No mapping |
| **Network Endpoint** | ❌ Hostname aliases | No CNAME/DNS alias tracking |

### 5.2 Missing Alias Infrastructure

| Missing | Needed For |
|---------|------------|
| **Global Alias Table** | Map any identifier → canonical ID |
| **Certificate SAN Tracking** | Track all SANs as aliases |
| **Cloud Resource ARN Mapping** | ARN → canonical ID |
| **Hostname/CNAME Tracking** | DNS aliases → canonical host |
| **K8s Resource Name Aliases** | namespace/name → canonical |
| **Container Image Tag Aliases** | Tags → digest canonical ID |

---

## 6. EXTERNAL ID MAPPING

### 6.1 Cloud Resource ID Mapping

| Cloud | Resource Type | External ID | Mapped to Internal |
|-------|---------------|-------------|-------------------|
| **AWS** | EC2 Instance | `i-1234567890abcdef0` | ❌ Not mapped |
| **AWS** | RDS Instance | `db-1234567890abcdef0` | ❌ Not mapped |
| **AWS** | ALB | `arn:aws:elasticloadbalancing:...` | ❌ Not mapped |
| **AWS** | ACM Certificate | `arn:aws:acm:...:certificate/uuid` | ❌ Not mapped |
| **AWS** | KMS Key | `arn:aws:kms:...:key/uuid` | ❌ Not mapped |
| **Azure** | VM | `/subscriptions/.../virtualMachines/vm1` | ❌ Not mapped |
| **Azure** | Key Vault | `/subscriptions/.../vaults/kv1` | ❌ Not mapped |
| **GCP** | Compute Instance | `projects/proj/zones/zone/instances/vm1` | ❌ Not mapped |
| **GCP** | Cloud SQL | `projects/proj/instances/db1` | ❌ Not mapped |
| **GCP** | Cloud KMS Key | `projects/proj/locations/loc/keyRings/kr/cryptoKeys/key` | ❌ Not mapped |

**Critical:** Zero cloud resource ID → internal ID mapping.

---

## 6. HOSTNAME & REPOSITORY RELATIONSHIPS

### 7.1 Hostname Relationships

| Relationship | Tracked | Mechanism |
|--------------|---------|-----------|
| **Host ↔ FQDN** | ✅ | `NetworkInventory.endpoint` |
| **Host ↔ IP** | ✅ | `NetworkInventory.endpoint` (host:port) |
| **Host ↔ CNAME** | ❌ | No DNS tracking |
| **Host ↔ Cloud Instance** | ❌ | No mapping |
| **Host ↔ K8s Node** | ❌ | No mapping |
| **Host ↔ Container Host** | ❌ | No mapping |
| **Host ↔ Hardware Asset** | ⚠️ Manual | `CryptoHardwareLink` (manual) |

### 7.2 Repository Relationships

| Relationship | Tracked | Mechanism |
|--------------|---------|-----------|
| **Repo ↔ System** | ✅ | `RepoConfiguration.system_id` |
| **Repo ↔ Scan** | ✅ | `Scan.target_location` |
| **Repo ↔ Assets** | ⚠️ Indirect | Via `SystemAsset` → `System` → `RepoConfiguration` |
| **Repo ↔ Container Image** | ❌ | No Dockerfile→Image tracking |
| **Repo ↔ Container Runtime** | ❌ | No tracking |
| **Repo ↔ K8s Manifests** | ⚠️ Partial | K8s scanner reads manifests |
| **Repo ↔ SBOM** | ⚠️ Partial | SBOM import links to repo |

---

## 8. OWNERSHIP RELATIONSHIPS

### 8.1 Current Ownership Model

| Entity | Owner Field | Owner Type | Multi-Owner |
|--------|-------------|------------|-------------|
| **System** | `owner` (string) | BusinessOwner email | ❌ Single |
| **System** | `business_unit` (string) | BusinessUnit name | ❌ Single |
| **System** | `criticality` | Enum | N/A |
| **BusinessOwner** | `email`, `name` | User reference | N/A |
| **BusinessUnit** | `name` | String | N/A |
| **Certificate** | `owner` (string) | String | ❌ Single |
| **CertificateUsage** | `system_id` + `certificate_id` | Link table | ✅ Multi |
| **CryptoAsset** | Via `SystemAsset` | System owner | Indirect |
| **Vendor** | `criticality` | Enum | N/A |
| **Hardware** | Via `CryptoHardwareLink` | Manual declaration | ❌ Single |

### 8.2 Missing Ownership Features

| Missing | Impact |
|---------|--------|
| **Multi-owner per asset** | Cannot represent shared ownership |
| **Ownership history** | No audit trail of ownership changes |
| **Delegated ownership** | Cannot delegate to team |
| **Ownership by environment** | Cannot have different owners per env |
| **Technical vs Business owner separation** | Single owner field |

---

## 8. THE "SAME ASSET" TEST

### 8.1 Test Scenario: Payment API

**Asset:** Payment Processing API

| Discovery Source | Identifier Assigned | Internal ID |
|------------------|---------------------|-------------|
| **Source Code Scan** | `finding_id: uuid-1` + `evidence_id: uuid-a` | `CryptoAsset.id = uuid-asset-1` |
| **Container Scan** | Layer digest `sha256:abc123` | `ContainerScan.layer_digest` |
| **K8s Scan** | K8s UID `k8s-uid-123` + `namespace/name` | `NetworkInventory.id = uuid-net-1` |
| **Network Scan** | Endpoint hash `sha256:payment.api.com:443` | `NetworkInventory.id = uuid-net-2` |
| **Cloud Scan (AWS)** | ALB ARN `arn:aws:elasticloadbalancing:...` | `CloudAccount.resource_id` |
| **Cloud Scan (AWS)** | Target Group ARN | `CloudAccount.resource_id` |
| **Cloud Scan (AWS)** | ACM Certificate ARN | `Certificate.id = uuid-cert-1` |
| **K8s Scan** | Service UID `k8s-svc-uid-456` | `NetworkInventory.id = uuid-net-3` |
| **K8s Scan** | Pod UID `k8s-pod-uid-789` | `NetworkInventory.id = uuid-net-4` |
| **Source Code** | Repo URL `github.com/org/payment-api` | `RepoConfiguration.url` |

**Result: 11 DIFFERENT IDENTIFIERS for the SAME logical asset.**

### 8.2 Can ZELNX Link Them?

| Link | Exists? | Mechanism |
|------|---------|-----------|
| Source Code Asset ↔ Container Image | ❌ | No Dockerfile→Image tracking |
| Container Image ↔ K8s Pod | ❌ | No image→pod tracking |
| K8s Pod ↔ K8s Service | ✅ | K8s ownerReferences (but not in ZELNX) |
| K8s Service ↔ Network Endpoint | ❌ | No Service↔Endpoint mapping |
| Network Endpoint ↔ Cloud ALB | ❌ | No ALB↔Endpoint mapping |
| Cloud ALB ↔ Target Group | ❌ | No ALB↔TargetGroup mapping |
| Target Group ↔ K8s Pods | ❌ | No TargetGroup↔Pod mapping |
| Cloud ACM Cert ↔ Network Cert | ❌ | No Cert ARN ↔ Fingerprint mapping |
| Source Code Repo ↔ K8s Manifests | ⚠️ Partial | K8s scanner reads manifests |
| Source Code Repo ↔ Container Image | ❌ | No Dockerfile→Image tracking |

**Score: 1/10 links exist.**

---

## 9. CANONICAL ID DESIGN (WHAT'S NEEDED)

### 9.1 Required Canonical Identity Model

```python
# Required canonical identity service:
class CanonicalAsset:
    canonical_id: UUID                    # Single source of truth
    asset_type: AssetType                 # SYSTEM, HOST, CONTAINER, CERT, etc.
    primary_name: str                     # Human-readable primary name
    aliases: List[AssetAlias]             # All known identifiers
    asset_class: AssetClass               # APPLICATION, INFRASTRUCTURE, DATA, etc.
    owner_chain: List[OwnerRef]           # Technical → Business → Executive
    source_evidence: List[SourceEvidence] # All discovery sources
    relationships: List[AssetRelationship] # Links to other canonical assets
    lifecycle_state: LifecycleState       # DISCOVERED → ACTIVE → RETIRED
    created_at, updated_at: DateTime
```

### 9.2 Required Alias Model

```python
class AssetAlias:
    alias_type: AliasType                 # HOSTNAME, ARN, ARN, K8S_UID, CERT_FINGERPRINT, etc.
    alias_value: str                      # The actual identifier
    source: DiscoverySource               # SCANNER, CLOUD_API, K8S_API, NETWORK_PROBE, etc.
    confidence: ConfidenceLevel           # HIGH, MEDIUM, LOW
    first_seen, last_seen: DateTime
    is_primary: bool                      # Is this the preferred identifier
```

### 9.3 Required Cross-Source Linking

```python
class AssetRelationship:
    source_canonical_id: UUID
    target_canonical_id: UUID
    relationship_type: RelationshipType   # RUNS_ON, HOSTS, EXPOSES, USES, DEPENDS_ON, etc.
    evidence: List[EvidenceRef]           # What proves this relationship
    confidence: ConfidenceLevel
    discovered_by: DiscoverySource
    first_seen, last_seen: DateTime
```

---

## 10. VERDICT

**ZELNX CANNOT recognize that the same asset discovered from AWS, Kubernetes, source code, and network scanning is the same asset.**

| Capability | Status |
|------------|--------|
| Canonical ID per asset | ❌ Missing |
| Cross-source linking | ❌ 1/10 links exist |
| Alias management | ❌ No alias table |
| External ID mapping | ❌ Zero cloud ID mapping |
| Hostname relationships | ❌ No CNAME/DNS tracking |
| Repository relationships | ⚠️ Partial (only System↔Repo) |
| Ownership chains | ⚠️ Single owner only |
| Canonical ID service | ❌ Missing |
| Alias resolution | ❌ Missing |
| Cross-source correlation | ❌ Missing |

**Root Cause:** No canonical identity service exists. Each discovery source creates its own identifiers with no unification layer.

**Effort to Fix:** 6-8 weeks for canonical identity service + alias resolution + cross-source linking + migration of existing data.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| System model | `services/database/db/models/system.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| SystemAsset link | `services/database/db/models/system_asset.py` |
| SystemDependency | `services/database/db/models/system_dependency.py` |
| RepoConfiguration | `services/database/db/models/repo_configuration.py` |
| CloudAccount | `services/database/db/models/cloud_account.py` |
| NetworkInventory | `services/database/db/models/network_inventory.py` |
| Certificate | `services/database/db/models/certificate.py` |
| CertificateUsage | `services/database/db/models/certificate_usage.py` |
| HardwareLive | `services/database/db/models/hardware_live.py` |
| CryptoHardwareLink | `services/database/db/models/cascade_extensions.py` |
| VendorDependency | `services/database/db/models/cascade_extensions.py` |
| NetworkInventory | `services/database/db/models/network_inventory.py` |
| CryptoLibraryFingerprint | `services/database/db/models/crypto_library_fingerprint.py` |
| EvidenceRecord | `services/database/db/models/evidence_record.py` |
| Scanner output | `services/scanner/scanner/models/raw_finding.py` |
| Network scan | `services/network_scanner/network_scanner/core/scanner.py` |
| Cloud scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Container scanner | `services/container_scanner/container_scanner/core/scanner.py` |