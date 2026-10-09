# 75_CREDENTIAL_SCOPE_AUDIT.md
## ZELNX CryptoScan — Credential Scope Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of credential requirements, scopes, and least-privilege enforcement across all discovery surfaces  
**Scope:** Complete credential scope audit — AWS, Azure, GCP, Kubernetes, Git, Network, Containers, Databases, HSM, Network Devices, Vendor APIs

---

## EXECUTIVE SUMMARY

**Core Question:** *"What permissions does CryptoScan actually need? Are credentials least-privilege?"*

**Answer:** **PARTIAL** — Credential scopes are defined per surface but **enforcement relies on external IAM/RBAC**, not internal validation. **No credential scoping audit, rotation, or automated least-privilege enforcement.**

| Credential Aspect | Status | Score |
|-------------------|--------|-------|
| **Scope Definition** | ✅ Defined per surface | 8/10 |
| **Least Privilege Enforcement** | ❌ External only | 3/10 |
| **Credential Rotation** | ❌ Manual only | 2/10 |
| **Scope Validation** | ❌ Missing | 1/10 |
| **Credential Audit** | ⚠️ Partial | 4/10 |
| **Emergency Access** | ❌ Missing | 1/10 |
| **Break-Glass Procedures** | ❌ Missing | 1/10 |
| **Credential Expiry** | ⚠️ Partial | 4/10 |
| **Scope Drift Detection** | ❌ Missing | 1/10 |
| **Break-Glass Audit** | ❌ Missing | 1/10 |

**Overall: 3.2/10** — Scopes defined but not enforced, audited, or rotated

---

## 1. CREDENTIAL SCOPE DEFINITIONS BY SURFACE

### 1.1 Source Repositories (Git)

**File:** `services/scanner/scanner/git/git_client.py`

| Credential Type | Scope | Permissions | Rotation |
|-----------------|-------|-------------|----------|
| **GitHub PAT** | Repository | `repo` (read), `read:org` (optional) | Manual |
| **GitLab PAT** | Project/Group | `read_repository`, `read_api` | Manual |
| **Bitbucket App Password** | Repository | `repository:read` | Manual |
| **SSH Key** | Repository | Read-only deploy key | Manual |

**Scope Definition:** `repo` (read) + optional `read:org` for organization discovery

**Gap:** No validation that PAT has only `repo` scope (not `admin:repo_hook`, `delete_repo`, etc.)

---

### 1.2 Cloud APIs

#### 1.2.1 AWS

**File:** `services/cloud_scanner/cloud_scanner/aws/scanners/`

| Service | Required Permissions | Least Privilege Policy |
|---------|---------------------|------------------------|
| **KMS** | `kms:ListKeys`, `DescribeKey`, `GetKeyPolicy` | `kms:ListKeys`, `DescribeKey`, `GetKeyPolicy` |
| **S3** | `GetBucketEncryption`, `GetBucketPolicy`, `GetBucketVersioning`, `GetBucketLocation` | `s3:GetBucketEncryption`, `GetBucketPolicy`, `GetBucketVersioning`, `GetBucketLocation` |
| **RDS** | `DescribeDBInstances`, `DescribeDBClusters`, `ListTagsForResource` | `rds:DescribeDBInstances`, `DescribeDBClusters`, `ListTagsForResource` |
| **DynamoDB** | `DescribeTable`, `DescribeGlobalTable`, `ListTables` | `dynamodb:DescribeTable`, `DescribeGlobalTable`, `ListTables` |
| **Secrets Manager** | `ListSecrets`, `DescribeSecret` | `secretsmanager:ListSecrets`, `DescribeSecret` |
| **ACM** | `ListCertificates`, `DescribeCertificate` | `acm:ListCertificates`, `DescribeCertificate` |
| **IAM** | `ListRoles`, `GetRole`, `GetRolePolicy`, `ListAttachedRolePolicies` | `iam:ListRoles`, `GetRole`, `GetRolePolicy`, `ListAttachedRolePolicies` |
| **CloudTrail** | `LookupEvents` (optional) | `cloudtrail:LookupEvents` |
| **Config** | `DescribeConfigRules`, `GetComplianceDetailsByConfigRule` | `config:DescribeConfigRules`, `GetComplianceDetailsByConfigRule` |

**Minimal IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
        "s3:GetBucketEncryption", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetBucketLocation",
        "rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:ListTagsForResource",
        "dynamodb:DescribeTable", "dynamodb:DescribeGlobalTable", "dynamodb:ListTables",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "acm:ListCertificates", "acm:DescribeCertificate",
        "iam:ListRoles", "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "cloudtrail:LookupEvents",
        "config:DescribeConfigRules", "config:GetComplianceDetailsByConfigRule"
      ],
      "Resource": "*"
    }
  ]
}
```

**Gap:** No validation that credentials match this exact policy.

---

#### 1.2.2 Azure

**File:** `services/cloud_scanner/cloud_scanner/azure/scanners/`

| Service | Required Permissions | Least Privilege Role |
|---------|---------------------|---------------------|
| **Key Vault** | `Microsoft.KeyVault/vaults/keys/read`, `secrets/read`, `certificates/read` | **Key Vault Reader** (built-in) |
| **Storage** | `Microsoft.Storage/storageAccounts/read`, `blobServices/containers/read` | **Storage Account Contributor** (too broad) → Custom role needed |
| **SQL** | `Microsoft.Sql/servers/read`, `databases/read` | **SQL DB Contributor** (too broad) → Custom role needed |
| **Key Vault Certificates** | `Microsoft.KeyVault/vaults/certificates/read` | **Key Vault Reader** |

**Minimal Custom Role:**
```json
{
  "Name": "CryptoScanReader",
  "IsCustom": true,
  "Description": "CryptoScan read-only access",
  "Actions": [
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.KeyVault/vaults/certificates/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/databases/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": []
}
```

---

#### 1.2.3 GCP

**File:** `services/cloud_scanner/cloud_scanner/gcp/scanners/`

| Service | Required Permissions | Least Privilege Role |
|---------|---------------------|---------------------|
| **Cloud KMS** | `cloudkms.keyRings.list`, `cryptoKeys.list`, `cryptoKeys.get` | **Cloud KMS Viewer** (`roles/cloudkms.viewer`) |
| **Cloud Storage** | `storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy` | **Storage Object Viewer** (`roles/storage.objectViewer`) + custom |
| **Cloud SQL** | `cloudsql.instances.list`, `cloudsql.instances.get`, `cloudsql.databases.list` | **Cloud SQL Viewer** (`roles/cloudsql.viewer`) |
| **Secret Manager** | `secretmanager.secrets.list`, `secretmanager.versions.access` | **Secret Manager Viewer** (`roles/secretmanager.viewer`) |

---

### 1.3 Kubernetes

**File:** `services/container_scanner/container_scanner/core/scanner.py`

| Resource | Verbs | Recommended Role |
|----------|-------|------------------|
| `namespaces` | `get`, `list`, `watch` | Custom ClusterRole |
| `pods` | `get`, `list`, `watch` | |
| `secrets` | `get`, `list` (metadata only) | |
| `configmaps` | `get`, `list` | |
| `ingresses` | `get`, `list` | |
| `ingresses.networking.k8s.io` | `get`, `list` | |
| `certificates.cert-manager.io` | `get`, `list` | |
| `certificaterequests.cert-manager.io` | `get`, `list` | |

**Minimal ClusterRole:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cryptoscan-reader
rules:
- apiGroups: [""]
  resources: ["namespaces", "pods", "secrets", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["cert-manager.io"]
  resources: ["certificates", "certificaterequests"]
  verbs: ["get", "list"]
```

---

### 1.4 Network Scanning

**File:** `services/network_scanner/network_scanner/core/scanner.py`

| Target | Credential | Scope |
|--------|------------|-------|
| TLS/SSL | None (anonymous) | None |
| StartTLS (SMTP/IMAP/POP3) | Optional auth | `AUTH PLAIN` / `LOGIN` (read-only) |
| SSH | Optional key | `ssh-rsa` public key auth (no password) |
| SNMP | Community string | `readonly` community |
| NETCONF/RESTCONF | API credentials | Read-only API user |

---

### 1.4 Containers

**File:** `services/container_scanner/container_scanner/core/scanner.py`

| Operation | Credential | Scope |
|-----------|------------|-------|
| `docker save` / `podman save` | None (local) | None |
| Registry pull (if needed) | Registry credentials | `repository:read` |
| SBOM generation | None | None |

---

### 1.5 Databases

**File:** `services/cloud_scanner/cloud_scanner/*/scanners/`

| Database | Credential | Minimal Permissions |
|----------|------------|---------------------|
| **RDS/Aurora** | IAM auth or DB user | `rds:DescribeDBInstances`, `rds:DescribeDBClusters` |
| **Cloud SQL** | IAM auth or DB user | `cloudsql.instances.get`, `cloudsql.databases.list` |
| **Cosmos DB** | Azure AD or Key | `Microsoft.DocumentDB/databaseAccounts/readMetadata` |
| **Cosmos DB** | Key | `Microsoft.DocumentDB/databaseAccounts/readMetadata` |

---

### 1.5 HSM

**File:** `services/cbom/cbom/hsm_pkcs11.py`

| Operation | Credential | Scope |
|-----------|------------|-------|
| PKCS#11 Session | User PIN | `CKF_RW_SESSION = FALSE` (read-only session) |
| HSM Admin | SO PIN | **NOT USED** |

**Required:** `CKF_RW_SESSION = FALSE` enforced in code.

---

### 1.6 Network Devices

| Protocol | Credential | Scope |
|-----------|------------|-------|
| SNMP v2c | Community string | `readonly` community |
| SNMP v3 | User + Auth/Priv | `readonly` view |
| SSH | SSH key / password | Read-only commands |
| NETCONF/RESTCONF | API credentials | Read-only API user |
| SSH/Telnet CLI | SSH key / password | Read-only command allowlist |

---

### 1.6 Vendor APIs

**File:** `services/vendor_intel/`

| Vendor | Credential Type | Scope |
|--------|-----------------|-------|
| Various | API Key / OAuth | Varies by vendor |
| **Gap:** | No standardized scope definition | ❌ |

---

### 1.7 Network Devices

| Protocol | Credential | Scope |
|----------|------------|-------|
| SNMP v2c | Community string | `readonly` community |
| SNMP v3 | User + Auth/Priv | `readonly` view |
| SSH | SSH key / password | Read-only command allowlist |
| NETCONF/RESTCONF | API credentials | Read-only API user |
| SSH/Telnet CLI | SSH key / password | Read-only command allowlist |

---

## 2. CREDENTIAL MANAGEMENT — CURRENT STATE

### 2.1 Credential Storage

| Credential Type | Storage | Encryption | Rotation |
|-----------------|---------|------------|----------|
| Cloud API Keys | Environment variables / Config file | ❌ Plaintext in config | Manual |
| Git PATs | Environment variables / Config | ❌ Plaintext | Manual |
| Kubernetes | Kubeconfig file | ❌ Plaintext | Manual |
| Database | IAM auth / DB user | ❌ Plaintext in config | Manual |
| HSM | PIN in config/env | ❌ Plaintext | Manual |
| Network Devices | Config file / env | ❌ Plaintext | Manual |
| Vendor APIs | Config file / env | ❌ Plaintext | Manual |
| HSM PIN | Config/env | ❌ Plaintext | Manual |

**Critical Gap:** **No encrypted credential store**, **no Vault integration**, **no rotation automation**.

---

### 2.2 Credential Validation — MISSING

| Validation | Implemented? |
|------------|--------------|
| Credential format validation | ✅ Basic format |
| Scope validation (least privilege) | ❌ No |
| Credential expiry checking | ❌ No |
| Credential rotation reminders | ❌ No |
| Least privilege validation | ❌ No |
| Credential scope drift detection | ❌ No |
| Unused credential detection | ❌ No |

---

## 3. CREDENTIAL ROTATION — MANUAL ONLY

### 3.1 Current Rotation Process

| Credential Type | Rotation Process | Frequency | Automation |
|-----------------|------------------|-----------|------------|
| Cloud API Keys | Manual (console/cli) | 90 days (recommended) | ❌ None |
| Git PATs | Manual (settings) | 90 days | ❌ None |
| Kubernetes | Manual (kubeconfig) | 90 days | ❌ None |
| Database | Manual (DB admin) | 90 days | ❌ None |
| HSM PIN | Manual (HSM admin) | 1 year | ❌ None |
| Network Devices | Manual (device admin) | 1 year | ❌ None |
| Vendor APIs | Manual (vendor portal) | Varies | ❌ None |

**Gap:** **Zero automation** for credential rotation.

---

## 4. CREDENTIAL SCOPE VALIDATION — MISSING

### 4.1 Scope Validation — MISSING

| Validation | Implemented? |
|------------|-------------|
| Credential has only required scopes | ❌ No |
| Credential has no excess permissions | ❌ No |
| Credential matches least-privilege policy | ❌ No |
| Credential scope matches scanner requirements | ❌ No |
| Credential scope drift detection | ❌ No |

---

### 4.2 Required Scope Validation

```python
# Required but missing:
class CredentialScopeValidator:
    def validate_aws_credentials(self, credentials, required_policy):
        # 1. Simulate API calls with credentials
        # 2. Verify only allowed actions succeed
        # 3. Verify denied actions fail
        # 4. Report excess permissions
        pass
    
    def validate_azure_credentials(self, credentials, required_role):
        # Check role assignment matches exactly
        # Verify no additional roles assigned
        pass
    
    def validate_gcp_credentials(self, credentials, required_roles):
        # Check IAM roles match exactly
        pass
    
    def validate_kubernetes_credentials(self, kubeconfig, required_rules):
        # Verify RBAC rules match exactly
        pass
```

---

## 5. CREDENTIAL AUDIT — PARTIAL

### 5.1 Current Audit Capabilities

| Audit Capability | Implemented? |
|-----------------|--------------|
| Credential inventory | ❌ No centralized inventory |
| Credential scope audit | ❌ No |
| Credential expiry tracking | ❌ No |
| Credential rotation history | ❌ No |
| Credential usage analytics | ❌ No |
| Unused credential detection | ❌ No |
| Over-privileged credential detection | ❌ No |
| Credential scope drift | ❌ No |

---

### 5.2 Required Audit Capabilities

| Audit Capability | Needed |
|-------------------|--------|
| Credential inventory dashboard | ✅ |
| Scope compliance report | ✅ |
| Expiry dashboard | ✅ |
| Rotation compliance report | ✅ |
| Over-privileged credential report | ✅ |
| Unused credential report | ✅ |
| Scope drift alerts | ✅ |
| Rotation compliance tracking | ✅ |

---

## 5. EMERGENCY ACCESS — MISSING

### 5.1 Break-Glass Procedures — MISSING

| Emergency Scenario | Procedure | Status |
|-------------------|-----------|--------|
| Scanner credential expired | Manual regeneration | ❌ Documented only |
| Cloud credential revoked | Manual regeneration | ❌ Documented only |
| HSM PIN lost | HSM admin reset | ❌ Documented only |
| Network device creds lost | Device admin reset | ❌ Documented only |
| Vendor API key compromised | Manual revocation | ❌ Documented only |
| Emergency scan needed | Manual credential provision | ❌ Documented only |

---

### 5.2 Break-Glass Audit — MISSING

| Audit Requirement | Implemented? |
|-------------------|--------------|
| Break-glass access log | ❌ |
| Break-glass approval workflow | ❌ |
| Break-glass time-bound access | ❌ |
| Break-glass audit trail | ❌ |
| Break-glass notification | ❌ |

---

## 6. CREDENTIAL EXPIRY — PARTIAL

### 6.1 Expiry Tracking

| Credential Type | Expiry Tracking | Alerting |
|-----------------|-----------------|----------|
| Cloud API Keys | ❌ No | ❌ |
| Git PATs | ❌ No | ❌ |
| Kubernetes | ❌ No | ❌ |
| Database | ❌ No | ❌ |
| HSM PIN | ❌ No | ❌ |
| Network Devices | ❌ No | ❌ |
| Vendor APIs | ❌ No | ❌ |

---

### 5.2 Required Expiry Management

| Feature | Needed |
|---------|---------|
| Expiry dashboard | ✅ |
| Expiry alerts (30/14/7/1 day) | ✅ |
| Auto-rotation scheduling | ✅ |
| Expiry grace period | ✅ |
| Expired credential blocking | ✅ |

---

## 5. SCOPE DRIFT DETECTION — MISSING

### 5.1 Scope Drift Scenarios

| Drift Scenario | Example | Detected? |
|----------------|---------|-----------|
| Cloud admin adds extra IAM policy | Admin adds `s3:PutObject` to CryptoScan role | ❌ |
| Azure admin adds extra role | Adds `Storage Blob Data Contributor` | ❌ |
| GCP admin adds extra role | Adds `Cloud KMS Admin` | ❌ |
| K8s admin adds cluster-admin | Adds `cluster-admin` ClusterRoleBinding | ❌ |
| DB admin grants extra GRANT | Grants `INSERT`, `UPDATE` on tables | ❌ |
| HSM admin enables RW session | Changes session to `CKF_RW_SESSION=TRUE` | ❌ |
| Network device admin adds write command | Adds `configure terminal` to allowlist | ❌ |

---

### 4.2 Required Drift Detection

```python
class CredentialScopeDriftDetector:
    def detect_aws_drift(self, current_policies, baseline_policy):
        # Compare current IAM policies vs baseline
        # Detect added/removed permissions
        pass
    
    def detect_azure_drift(self, current_roles, baseline_role):
        # Compare role assignments vs baseline
        pass
    
    def detect_gcp_drift(self, current_roles, baseline_roles):
        # Compare IAM roles vs baseline
        pass
    
    def detect_kubernetes_drift(self, current_bindings, baseline_bindings):
        # Compare RBAC bindings vs baseline
        pass
    
    def detect_hsm_drift(self, session_flags):
        # Check CKF_RW_SESSION flag
        pass
```

---

## 5. BREAK-GLASS PROCEDURES — MISSING

### 5.1 Break-Glass Scenarios

| Scenario | Current Process | Automated? |
|-----------|-----------------|------------|
| Cloud credential expired | Manual regeneration | ❌ |
| Credential revoked | Manual regeneration | ❌ |
| HSM PIN lost | HSM admin reset | ❌ |
| Network device creds lost | Device admin reset | ❌ |
| Vendor API key compromised | Manual revocation | ❌ |
| Emergency scan needed | Manual provisioning | ❌ |

---

### 5.2 Required Break-Glass System

```python
class BreakGlassSystem:
    def request_emergency_credential(self, surface, reason, requester):
        # 1. Validate requester authorization
        # 2. Generate temporary credential (1-4 hours)
        # 3. Audit log: requester, reason, duration, approver
        # 4. Auto-expiry with cleanup
        # 4. Notification to security team
        pass
    
    def approve_emergency_access(self, request_id, approver):
        # Multi-party approval for critical surfaces
        pass
    
    def revoke_emergency_access(self, credential_id):
        # Immediate revocation
        # Audit log
        pass
```

---

## 6. BREAK-GLASS AUDIT — MISSING

| Audit Requirement | Implemented? |
|-------------------|--------------|
| Break-glass access log | ❌ |
| Break-glass approval workflow | ❌ |
| Break-glass time-bound access | ❌ |
| Break-glass audit trail | ❌ |
| Break-glass notification | ❌ |

---

## 7. RECOMMENDATIONS

### P0 — Critical

1. **Implement Credential Vault** — HashiCorp Vault / AWS Secrets Manager / Azure Key Vault
2. **Implement Scope Validation** — Automated least-privilege validation per surface
3. **Implement Credential Rotation Automation** — Automated 90-day rotation with alerts
4. **Implement Scope Drift Detection** — Continuous drift monitoring with alerts

### P1 — High

4. **Implement Credential Vault Integration** — HashiCorp Vault / AWS Secrets Manager
5. **Implement Scope Drift Detection** — Continuous monitoring with alerts
5. **Implement Credential Rotation Automation** — 90-day auto-rotation with alerts
6. **Implement Credential Expiry Dashboard** — Expiry dashboard with alerts

### P2 — Medium

8. **Implement Break-Glass System** — Emergency access with audit trail
8. **Implement Credential Audit Dashboard** — Inventory, scope, expiry, rotation
9. **Implement Scope Drift Alerts** — Real-time drift alerts
9. **Implement Break-Glass Audit Trail** — Full audit trail for emergency access

### P3 — Enhancement

12. **Credential Analytics** — Usage patterns, optimization recommendations
12. **Predictive Rotation** — ML-based rotation scheduling
13. **Credential Sharing** — Secure credential sharing between teams
13. **Credential Analytics** — Usage analytics, optimization recommendations

---

## 6. VERDICT

**Credential scopes are defined but not enforced, validated, rotated, or audited.** Relies entirely on external IAM/RBAC with no internal validation.

| Credential Capability | Status |
|----------------------|--------|
| Scope Definition | ✅ Defined |
| Least Privilege Enforcement | ❌ External only |
| Credential Rotation | ❌ Manual only |
| Scope Validation | ❌ Missing |
| Credential Audit | ⚠️ Partial |
| Emergency Access | ❌ Missing |
| Break-Glass Procedures | ❌ Missing |
| Credential Expiry | ❌ No tracking |
| Scope Drift Detection | ❌ Missing |
| Break-Glass Audit | ❌ Missing |

**To fix:** 6-8 weeks for vault integration, scope validation, rotation automation, drift detection, break-glass system, and audit dashboard.

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| AWS Scanner Permissions | `services/cloud_scanner/cloud_scanner/aws/scanners/` |
| Azure Scanner | `services/cloud_scanner/cloud_scanner/azure/scanners/` |
| GCP Scanner | `services/cloud_scanner/cloud_scanner/gcp/scanners/` |
| K8s Scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| HSM PKCS#11 | `services/cbom/cbom/hsm_pkcs11.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Settings | `services/api/api/config/settings.py` |
| Database Models | `services/database/db/models/` (APIKey, User, etc.) |
| Docker Compose | `docker-compose.yml` (env vars) |
| Settings | `services/api/api/config/settings.py` |