# 🚀 CRYPTOSCAN PLATFORM — PART 1 (MONTHS 1-3)
## Foundation Phase: Core Discovery & Evidence Pipeline

---

## 📋 PART 1 OBJECTIVE

**Build the foundational intelligence infrastructure:**
- Prove we can **discover crypto in code** (static analysis)
- Prove we can **store findings with integrity** (evidence chain)
- Prove we can **detect drift** (baseline vs current state)
- Deliver **one working end-to-end flow**: code commit → finding → alert

**NOT in scope for Part 1:**
- ❌ AI/ML features
- ❌ Cloud/container scanning (static code only)
- ❌ Network/runtime scanning
- ❌ Full policy engine (basic rules only)
- ❌ Business context enrichment
- ❌ Graph database (simple relational DB only)

---

# 🗺️ MONTH 1: CORE SCANNING ENGINE + EVIDENCE FOUNDATION

---

## WEEK 1-2: STATIC CODE SCANNER — SINGLE LANGUAGE PROOF

### 🎯 Goal
Build a working static scanner for **Java only** that can:
1. Parse Java source code into AST (Abstract Syntax Tree)
2. Detect cryptographic API calls
3. Extract algorithm parameters with confidence

### 📐 Architecture — Scanner Component

```
┌─────────────────────────────────────────────────────────────────┐
│                    STATIC SCANNER v0.1                          │
│                    (Java Only - CLI Tool)                       │
└─────────────────────────────────────────────────────────────────┘

INPUT: Path to Java source directory or Git repo URL

PROCESS:

┌──────────────────────────────────────────────────────────────┐
│ STEP 1: SOURCE FILE DISCOVERY                                │
│                                                              │
│ Walk directory tree                                          │
│ Filter: *.java files only                                    │
│ Exclude: test directories, generated code (configurable)     │
│ Output: List of file paths                                   │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 2: AST PARSING (per file)                              │
│                                                              │
│ Technology Choice: Eclipse JDT (Java Development Tools)     │
│ WHY: Battle-tested, understands all Java versions,          │
│      open source, no external service dependency            │
│                                                              │
│ For each .java file:                                        │
│   → Parse into CompilationUnit (AST root)                   │
│   → Handle parse errors gracefully (log, skip, continue)    │
│   → Extract: package, imports, class declarations           │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 3: CRYPTO PATTERN DETECTION                            │
│                                                              │
│ AST Visitor Pattern Implementation:                         │
│                                                              │
│ Visit each MethodInvocation node in AST                     │
│ IF method matches crypto pattern:                           │
│    → Extract details                                         │
│                                                              │
│ PATTERN LIBRARY (Week 1 minimal set):                       │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PATTERN 1: javax.crypto.Cipher                         │  │
│ │                                                        │  │
│ │ MATCH:                                                 │  │
│ │   Cipher.getInstance(String transformation)           │  │
│ │                                                        │  │
│ │ EXTRACT:                                               │  │
│ │   → transformation parameter                           │  │
│ │   → Parse format: "Algorithm/Mode/Padding"            │  │
│ │   → Example: "AES/GCM/NoPadding"                      │  │
│ │     → algorithm = AES                                  │  │
│ │     → mode = GCM                                       │  │
│ │     → padding = NoPadding                             │  │
│ │                                                        │  │
│ │ HANDLE VARIATIONS:                                     │  │
│ │   → "AES" only → mode=default, padding=default        │  │
│ │   → "DES/ECB/PKCS5Padding"                            │  │
│ │   → Variable passed (can't determine at parse time)   │  │
│ │     → Mark as: algorithm=UNKNOWN, confidence=LOW      │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PATTERN 2: java.security.MessageDigest                │  │
│ │                                                        │  │
│ │ MATCH:                                                 │  │
│ │   MessageDigest.getInstance(String algorithm)         │  │
│ │                                                        │  │
│ │ EXTRACT:                                               │  │
│ │   → algorithm parameter                                │  │
│ │   → Examples: "MD5", "SHA-1", "SHA-256", "SHA-512"   │  │
│ │   → purpose = HASHING (deterministic)                 │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PATTERN 3: javax.crypto.KeyGenerator                  │  │
│ │                                                        │  │
│ │ MATCH:                                                 │  │
│ │   KeyGenerator.getInstance(String algorithm)          │  │
│ │   kg.init(int keysize)                                │  │
│ │                                                        │  │
│ │ EXTRACT:                                               │  │
│ │   → algorithm parameter                                │  │
│ │   → key size from init() call (if present)            │  │
│ │   → Link init() to getInstance() via data flow       │  │
│ │     (SIMPLE: same variable name in same method)       │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PATTERN 4: java.security.Signature                    │  │
│ │                                                        │  │
│ │ MATCH:                                                 │  │
│ │   Signature.getInstance(String algorithm)             │  │
│ │                                                        │  │
│ │ EXTRACT:                                               │  │
│ │   → algorithm parameter                                │  │
│ │   → Parse format: "SHA256withRSA"                     │  │
│ │     → hash_algorithm = SHA-256                         │  │
│ │     → signing_algorithm = RSA                          │  │
│ │   → purpose = SIGNING (deterministic)                 │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PATTERN 5: Hardcoded Keys/Secrets Detection           │  │
│ │                                                        │  │
│ │ MATCH:                                                 │  │
│ │   SecretKeySpec constructor with byte[] or String     │  │
│ │                                                        │  │
│ │ DETECT:                                                │  │
│ │   → String literals in SecretKeySpec constructor      │  │
│ │   → Byte arrays initialized with literal values       │  │
│ │   → Flag as: HARDCODED_KEY (critical finding)         │  │
│ │   → Extract: key length, algorithm                    │  │
│ │   → DO NOT extract the actual key value (security)    │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 4: CONTEXT EXTRACTION                                  │
│                                                              │
│ For each crypto API call found:                             │
│                                                              │
│ EXTRACT FILE CONTEXT:                                       │
│   → file_path (relative to repo root)                       │
│   → line_number (exact line of crypto call)                 │
│   → column_number (for precision)                           │
│   → containing_method_name                                   │
│   → containing_class_name (fully qualified)                 │
│                                                              │
│ EXTRACT CODE CONTEXT:                                       │
│   → code_snippet (5 lines before, call line, 5 after)      │
│   → variable_name (if stored in variable)                   │
│   → is_in_try_catch (error handling present?)              │
│                                                              │
│ EXTRACT CONFIDENCE INDICATORS:                              │
│   → confidence = HIGH if:                                    │
│     - Algorithm is string literal (not variable)            │
│     - Call is direct (not via reflection)                   │
│   → confidence = MEDIUM if:                                  │
│     - Algorithm from local variable (traceable)             │
│   → confidence = LOW if:                                     │
│     - Algorithm from parameter/field (can't determine)      │
│     - Reflection used                                        │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 5: RAW FINDING OBJECT CREATION                         │
│                                                              │
│ Create RawFinding object:                                    │
│                                                              │
│ {                                                            │
│   finding_id: UUID.randomUUID(),                            │
│   scan_timestamp: ISO-8601 timestamp,                       │
│   scanner_id: "static-java-scanner-v0.1",                  │
│   scanner_version: "0.1.0",                                 │
│                                                              │
│   source: {                                                  │
│     type: "SOURCE_CODE",                                     │
│     language: "JAVA",                                        │
│     file_path: "src/main/Payment.java",                     │
│     line_number: 247,                                        │
│     column_number: 12,                                       │
│     method_name: "encryptCardData",                          │
│     class_name: "com.example.PaymentProcessor",             │
│     code_snippet: "...<5 lines context>..."                 │
│   },                                                         │
│                                                              │
│   crypto: {                                                  │
│     api_type: "CIPHER_INSTANCE",                            │
│     algorithm: "DES",                                        │
│     mode: "ECB",                                             │
│     padding: "PKCS5Padding",                                │
│     key_size: null,  // not determinable from getInstance   │
│     purpose: "ENCRYPTION"  // inferred from Cipher.class    │
│   },                                                         │
│                                                              │
│   metadata: {                                                │
│     confidence: "HIGH",                                      │
│     confidence_reason: "algorithm from string literal",     │
│     library: "javax.crypto",                                │
│     is_hardcoded_key: false                                 │
│   },                                                         │
│                                                              │
│   git_context: {  // if scanned from Git repo               │
│     commit_hash: "a1b2c3d4...",                             │
│     commit_author: "john.developer",                         │
│     commit_timestamp: "2024-01-15T08:22:00Z",               │
│     branch: "main",                                          │
│     repository_url: "https://github.com/org/repo"           │
│   }                                                          │
│ }                                                            │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 6: OUTPUT                                               │
│                                                              │
│ WEEK 1-2 OUTPUT FORMAT: JSON file                          │
│                                                              │
│ scan-results-{timestamp}.json:                              │
│ {                                                            │
│   "scan_id": "uuid",                                         │
│   "scan_start": "timestamp",                                 │
│   "scan_end": "timestamp",                                   │
│   "scanner_version": "0.1.0",                               │
│   "scan_target": {                                           │
│     "type": "GIT_REPOSITORY",                               │
│     "url": "...",                                            │
│     "commit": "..."                                          │
│   },                                                         │
│   "statistics": {                                            │
│     "files_scanned": 247,                                    │
│     "files_with_crypto": 12,                                │
│     "total_findings": 34,                                    │
│     "high_confidence": 28,                                   │
│     "medium_confidence": 4,                                  │
│     "low_confidence": 2                                      │
│   },                                                         │
│   "findings": [                                              │
│     { RawFinding object 1 },                                │
│     { RawFinding object 2 },                                │
│     ...                                                      │
│   ]                                                          │
│ }                                                            │
│                                                              │
│ VALIDATION:                                                  │
│ → Output must be valid JSON schema                          │
│ → Each finding must have all required fields                │
│ → Timestamps must be ISO-8601                               │
│ → UUIDs must be valid v4                                    │
└──────────────────────────────────────────────────────────────┘

OUTPUT: JSON file of findings
```

### ✅ Week 1-2 Deliverable

**Executable scanner that:**
1. Takes a Git repo URL or local directory as input
2. Scans all Java files
3. Detects 5 crypto patterns (Cipher, MessageDigest, KeyGenerator, Signature, hardcoded keys)
4. Produces JSON output with findings
5. Runs in <5 minutes for a 10,000-file repo

**Testing methodology:**
- Create 10 test Java files with known crypto calls
- Run scanner
- Verify: 100% detection rate for string-literal algorithms
- Verify: Correct line numbers, algorithms, modes
- Verify: Hardcoded key detection works
- Verify: Graceful handling of parse errors

---

## WEEK 3: EVIDENCE HASHING & INTEGRITY CHAIN

### 🎯 Goal
Ensure every finding is **tamper-proof** and **auditable**

### 📐 Architecture — Evidence Chain

```
┌─────────────────────────────────────────────────────────────┐
│           EVIDENCE INTEGRITY PIPELINE                       │
│           (Runs AFTER scanner produces findings)            │
└─────────────────────────────────────────────────────────────┘

INPUT: RawFinding objects from scanner

PROCESS:

┌──────────────────────────────────────────────────────────────┐
│ STEP 1: CANONICAL SERIALIZATION                             │
│                                                              │
│ WHY: Hash must be identical for identical findings          │
│                                                              │
│ For each RawFinding:                                         │
│                                                              │
│ 1. Sort all JSON keys alphabetically                        │
│    (prevents hash change from key reordering)               │
│                                                              │
│ 2. Remove scanner runtime metadata:                         │
│    - Remove: finding_id (will be regenerated)              │
│    - Remove: scan_timestamp (time doesn't affect content)   │
│    - Keep: Everything else (algo, file, line, etc)         │
│                                                              │
│ 3. Serialize to canonical JSON:                             │
│    - No whitespace                                           │
│    - UTF-8 encoding                                          │
│    - Deterministic float formatting                         │
│                                                              │
│ Example:                                                     │
│ Input:                                                       │
│   { "algorithm": "DES", "line": 247, "file": "Pay.java" }  │
│ Canonical:                                                   │
│   {"algorithm":"DES","file":"Pay.java","line":247}          │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 2: CONTENT HASHING                                     │
│                                                              │
│ Algorithm: SHA-256 (FIPS 180-4 compliant)                   │
│ WHY SHA-256:                                                 │
│   - Industry standard for integrity                          │
│   - 256-bit output = collision resistant                     │
│   - Fast computation                                         │
│   - No known practical attacks                              │
│                                                              │
│ Compute:                                                     │
│   content_hash = SHA-256(canonical_json_bytes)              │
│                                                              │
│ Output format: Lowercase hexadecimal (64 characters)        │
│                                                              │
│ Example:                                                     │
│   content_hash = "a1b2c3d4e5f6...64chars"                   │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 3: EVIDENCE RECORD CREATION                            │
│                                                              │
│ Create EvidenceRecord:                                       │
│                                                              │
│ {                                                            │
│   evidence_id: UUID.randomUUID(),  // NEW unique ID         │
│   content_hash: "a1b2c3...",       // from Step 2            │
│   created_at: ISO-8601 timestamp,                           │
│                                                              │
│   finding: {                                                 │
│     // FULL original RawFinding object                      │
│   },                                                         │
│                                                              │
│   integrity: {                                               │
│     hash_algorithm: "SHA-256",                              │
│     canonical_form: "sorted-json-utf8",                     │
│     hash_includes: ["finding"],                             │
│     hash_excludes: ["evidence_id", "created_at"]            │
│   },                                                         │
│                                                              │
│   provenance: {                                              │
│     scanner_id: "static-java-scanner-v0.1",                │
│     scanner_version: "0.1.0",                               │
│     scan_session_id: "uuid-of-scan-run",                    │
│     operator: "CI/CD" or "manual-user-X"                    │
│   }                                                          │
│ }                                                            │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 4: CHAIN HASH (Blockchain-style Linking)               │
│                                                              │
│ PURPOSE: Detect if anyone deletes/reorders findings         │
│                                                              │
│ ALGORITHM:                                                   │
│                                                              │
│ For finding N in sequence:                                   │
│                                                              │
│   chain_hash[N] = SHA-256(                                  │
│     content_hash[N] +                                        │
│     chain_hash[N-1]                                          │
│   )                                                          │
│                                                              │
│ For first finding (N=0):                                     │
│   chain_hash[0] = SHA-256(                                  │
│     content_hash[0] +                                        │
│     scan_session_id                                          │
│   )                                                          │
│                                                              │
│ Add to EvidenceRecord:                                       │
│   {                                                          │
│     ...existing fields...,                                   │
│     chain: {                                                 │
│       position: N,                                           │
│       chain_hash: "x1y2z3...",                              │
│       previous_hash: "a1b2c3..." or null if first           │
│     }                                                        │
│   }                                                          │
│                                                              │
│ VERIFICATION (later):                                        │
│   For any evidence record N:                                 │
│     1. Recompute content_hash from finding                  │
│     2. Recompute chain_hash from content + previous         │
│     3. Compare to stored chain_hash                         │
│     4. If mismatch → TAMPER DETECTED                        │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 5: EVIDENCE MANIFEST                                   │
│                                                              │
│ Create ScanManifest (one per scan session):                 │
│                                                              │
│ {                                                            │
│   manifest_id: UUID,                                         │
│   scan_session_id: UUID,                                     │
│   created_at: timestamp,                                     │
│                                                              │
│   summary: {                                                 │
│     total_findings: 34,                                      │
│     first_chain_hash: "...",  // chain_hash[0]              │
│     last_chain_hash: "...",   // chain_hash[33]             │
│     manifest_hash: SHA-256(all_evidence_ids_sorted)         │
│   },                                                         │
│                                                              │
│   evidence_records: [                                        │
│     { evidence_id, content_hash, chain_hash },              │
│     ... all 34 findings                                      │
│   ],                                                         │
│                                                              │
│   integrity_proof: {                                         │
│     algorithm: "SHA-256-chain",                             │
│     verification_instructions: "..."                         │
│   }                                                          │
│ }                                                            │
│                                                              │
│ MANIFEST HASH (final):                                       │
│   manifest_hash = SHA-256(entire_manifest_canonical)        │
│   Store in: manifest.summary.self_hash                      │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 6: STORAGE                                              │
│                                                              │
│ OUTPUT FILES (for now — DB comes in Month 2):               │
│                                                              │
│ 1. evidence-records-{scan_id}.json                          │
│    → All EvidenceRecord objects                             │
│                                                              │
│ 2. manifest-{scan_id}.json                                  │
│    → ScanManifest object                                     │
│                                                              │
│ 3. verification-script.sh                                    │
│    → Standalone script that:                                 │
│      - Takes evidence-records.json as input                  │
│      - Recomputes all content hashes                        │
│      - Recomputes chain hashes                              │
│      - Verifies manifest hash                               │
│      - Outputs: PASS or FAIL with details                   │
│                                                              │
│ WHY VERIFICATION SCRIPT:                                     │
│   Proves to auditors that evidence is tamper-proof          │
│   Can run independently of CryptoScan platform              │
│   Demonstrates cryptographic integrity to regulators        │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 3 Deliverable

**Evidence integrity system that:**
1. Takes RawFindings from scanner
2. Produces EvidenceRecords with content hashes
3. Creates blockchain-style chain hash linking
4. Generates ScanManifest with overall integrity proof
5. Includes standalone verification script

**Testing:**
- Scan test repo → produces evidence records
- Run verification script → PASS
- Manually modify one finding in JSON → verification script → FAIL (detected)
- Delete one finding from JSON → verification script → FAIL (chain broken)
- Reorder findings → verification script → FAIL (manifest hash mismatch)

---

## WEEK 4: DATABASE FOUNDATION

### 🎯 Goal
Build the storage layer for evidence records with queryability

### 📐 Architecture — Initial Database

```
┌─────────────────────────────────────────────────────────────┐
│              DATABASE DESIGN — MONTH 1 MVP                  │
│              PostgreSQL 15+ (JSONB support)                 │
└─────────────────────────────────────────────────────────────┘

DESIGN PRINCIPLE:
→ Start simple (relational + JSONB for flexibility)
→ Optimize for: write performance, integrity, basic queries
→ NOT optimized for: complex graph queries (that's Month 3+)

TABLES:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: scans                                                 │
│ (One record per scan session)                               │
├──────────────────┬───────────────────────────────────────────┤
│ COLUMN           │ TYPE          │ DESCRIPTION              │
├──────────────────┼───────────────┼──────────────────────────┤
│ scan_id          │ UUID PK       │ Unique scan identifier   │
│ scan_start       │ TIMESTAMP     │ When scan started        │
│ scan_end         │ TIMESTAMP     │ When scan completed      │
│ scanner_id       │ VARCHAR(100)  │ Which scanner ran        │
│ scanner_version  │ VARCHAR(20)   │ Scanner version          │
│ target_type      │ VARCHAR(50)   │ GIT_REPO, LOCAL_DIR, etc │
│ target_location  │ TEXT          │ Repo URL or path         │
│ target_commit    │ VARCHAR(40)   │ Git commit hash (if Git) │
│ target_branch    │ VARCHAR(100)  │ Git branch (if Git)      │
│ operator         │ VARCHAR(100)  │ Who/what triggered scan  │
│ statistics       │ JSONB         │ {files_scanned: N, ...}  │
│ manifest_hash    │ VARCHAR(64)   │ SHA-256 of manifest      │
│ status           │ VARCHAR(20)   │ COMPLETED, FAILED, etc   │
│ created_at       │ TIMESTAMP     │ Record creation time     │
└──────────────────┴───────────────┴──────────────────────────┘

INDEXES:
  → PRIMARY KEY (scan_id)
  → INDEX ON (scan_start DESC) for recent scans query
  → INDEX ON (target_location) for "scans of this repo" query
  → INDEX ON (target_commit) for "findings at this commit"

┌──────────────────────────────────────────────────────────────┐
│ TABLE: evidence_records                                      │
│ (One record per crypto finding)                             │
├──────────────────┬───────────────────────────────────────────┤
│ COLUMN           │ TYPE          │ DESCRIPTION              │
├──────────────────┼───────────────┼──────────────────────────┤
│ evidence_id      │ UUID PK       │ Unique evidence ID       │
│ scan_id          │ UUID FK       │ → scans.scan_id          │
│ content_hash     │ VARCHAR(64)   │ SHA-256 of finding       │
│ chain_position   │ INT           │ Position in chain (0..N) │
│ chain_hash       │ VARCHAR(64)   │ Blockchain-style hash    │
│ previous_hash    │ VARCHAR(64)   │ Chain link (NULL if 0)   │
│                  │               │                          │
│ -- EXTRACTED FIELDS (for fast queries without JSONB parse) │
│ algorithm        │ VARCHAR(50)   │ AES, RSA, DES, SHA-256   │
│ key_size         │ INT           │ 128, 256, 2048, etc      │
│ purpose          │ VARCHAR(50)   │ ENCRYPTION, HASHING, etc │
│ confidence       │ VARCHAR(20)   │ HIGH, MEDIUM, LOW        │
│ file_path        │ TEXT          │ Source file location     │
│ line_number      │ INT           │ Line in source file      │
│ class_name       │ TEXT          │ Fully qualified class    │
│ method_name      │ VARCHAR(200)  │ Method containing crypto │
│ is_hardcoded_key │ BOOLEAN       │ Critical flag            │
│                  │               │                          │
│ -- FULL DATA (immutable)                                    │
│ finding_data     │ JSONB         │ Complete RawFinding JSON │
│ provenance       │ JSONB         │ Scanner metadata         │
│                  │               │                          │
│ created_at       │ TIMESTAMP     │ Record creation time     │
│ updated_at       │ TIMESTAMP     │ Last update (rare)       │
└──────────────────┴───────────────┴──────────────────────────┘

INDEXES:
  → PRIMARY KEY (evidence_id)
  → FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
  → INDEX ON (scan_id, chain_position) for chain verification
  → INDEX ON (content_hash) for dedup detection
  → INDEX ON (algorithm) for "all RSA findings" queries
  → INDEX ON (is_hardcoded_key) WHERE is_hardcoded_key = true
  → GIN INDEX ON (finding_data) for JSONB queries

CONSTRAINTS:
  → UNIQUE (scan_id, chain_position) — position per scan
  → CHECK (chain_position >= 0)
  → CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW'))

┌──────────────────────────────────────────────────────────────┐
│ TABLE: verification_log                                      │
│ (Audit trail of integrity verifications)                    │
├──────────────────┬───────────────────────────────────────────┤
│ verification_id  │ UUID PK       │ Unique verification run  │
│ scan_id          │ UUID FK       │ Which scan verified      │
│ verified_at      │ TIMESTAMP     │ When verification ran    │
│ verified_by      │ VARCHAR(100)  │ System or user           │
│ result           │ VARCHAR(20)   │ PASS, FAIL               │
│ details          │ JSONB         │ {errors: [], ...}        │
└──────────────────┴───────────────┴──────────────────────────┘

INDEXES:
  → PRIMARY KEY (verification_id)
  → INDEX ON (scan_id, verified_at DESC)
```

### 📊 Database Loader Logic

```
┌──────────────────────────────────────────────────────────────┐
│          DATABASE LOADER COMPONENT                           │
│          (Reads JSON output from Week 3, loads to DB)        │
└──────────────────────────────────────────────────────────────┘

INPUT:
  → evidence-records-{scan_id}.json
  → manifest-{scan_id}.json

PROCESS:

┌──────────────────────────────────────────────────────────────┐
│ STEP 1: VERIFY INTEGRITY BEFORE LOADING                     │
│                                                              │
│ Run verification:                                            │
│   1. Recompute content_hash for each finding                │
│   2. Verify chain_hash linkage                              │
│   3. Verify manifest_hash                                   │
│                                                              │
│ IF verification FAILS:                                       │
│   → ABORT load                                               │
│   → Log error                                                │
│   → Alert operator                                           │
│   → DO NOT write corrupted data to DB                       │
│                                                              │
│ IF verification PASSES:                                      │
│   → Proceed to Step 2                                        │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 2: TRANSACTION-SAFE LOAD                               │
│                                                              │
│ BEGIN TRANSACTION;                                           │
│                                                              │
│ -- Insert scan record                                        │
│ INSERT INTO scans (                                          │
│   scan_id, scan_start, scan_end, scanner_id,                │
│   scanner_version, target_type, target_location,            │
│   target_commit, target_branch, operator,                   │
│   statistics, manifest_hash, status                         │
│ ) VALUES (...from manifest...);                             │
│                                                              │
│ -- Insert all evidence records (bulk insert for performance)│
│ FOR EACH evidence_record IN evidence_records_array:          │
│                                                              │
│   -- Extract fields from finding_data JSONB for columns     │
│   algorithm = finding_data->>'crypto'->'algorithm'          │
│   key_size = finding_data->>'crypto'->'key_size'            │
│   ...etc                                                     │
│                                                              │
│   INSERT INTO evidence_records (                             │
│     evidence_id, scan_id, content_hash,                     │
│     chain_position, chain_hash, previous_hash,              │
│     algorithm, key_size, purpose, confidence,               │
│     file_path, line_number, class_name, method_name,        │
│     is_hardcoded_key,                                        │
│     finding_data, provenance,                                │
│     created_at                                               │
│   ) VALUES (...);                                            │
│                                                              │
│ END FOR;                                                     │
│                                                              │
│ COMMIT;                                                      │
│                                                              │
│ WHY TRANSACTION:                                             │
│   → All-or-nothing: either full scan loads or nothing       │
│   → Prevents partial data in DB if load fails               │
│   → Maintains referential integrity (scan ↔ evidence)       │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 3: POST-LOAD VERIFICATION                              │
│                                                              │
│ After successful load:                                       │
│                                                              │
│ 1. Count check:                                              │
│    DB_count = SELECT COUNT(*) FROM evidence_records         │
│                WHERE scan_id = {this_scan};                  │
│    IF DB_count != manifest.total_findings:                  │
│      → ALERT: count mismatch!                                │
│                                                              │
│ 2. Chain verification from DB:                               │
│    FOR position 0 TO N:                                      │
│      SELECT content_hash, chain_hash, previous_hash         │
│      FROM evidence_records                                   │
│      WHERE scan_id = X AND chain_position = position        │
│      ORDER BY chain_position;                                │
│                                                              │
│      Recompute chain_hash                                    │
│      IF computed != stored:                                  │
│        → ALERT: chain broken in DB!                          │
│                                                              │
│ 3. Insert verification record:                               │
│    INSERT INTO verification_log (                            │
│      scan_id, verified_at, verified_by,                     │
│      result, details                                         │
│    ) VALUES (                                                │
│      {scan_id}, NOW(), 'db-loader-v0.1',                    │
│      'PASS', '{}'                                            │
│    );                                                        │
└──────────────────────────────────────────────────────────────┘

OUTPUT: Scan data loaded and verified in PostgreSQL
```

### ✅ Week 4 Deliverable

**Database system that:**
1. Stores scan metadata and evidence records
2. Maintains integrity proofs in database
3. Supports basic queries (by algorithm, by file, by scan)
4. Transaction-safe loading
5. Post-load verification

**Testing:**
- Load evidence from Week 3 → DB insert succeeds
- Query: `SELECT * FROM evidence_records WHERE algorithm = 'DES'` → returns correct findings
- Query: `SELECT * FROM evidence_records WHERE is_hardcoded_key = true` → returns hardcoded key findings
- Verify chain in DB → PASS
- Attempt to manually UPDATE an evidence record → verify chain → FAIL (detected)

---

# 🗺️ MONTH 2: NORMALIZATION + BASIC POLICY ENGINE + DRIFT DETECTION

---

## WEEK 5: NORMALIZATION ENGINE

### 🎯 Goal
Convert scanner-specific algorithm names to canonical CBOM format

### 📐 Architecture — Normalization

```
┌─────────────────────────────────────────────────────────────┐
│              NORMALIZATION ENGINE v1.0                      │
│              (Runs between DB load and policy check)        │
└─────────────────────────────────────────────────────────────┘

TRIGGERED: After evidence_records inserted into DB

PROCESS:

┌──────────────────────────────────────────────────────────────┐
│ NORMALIZATION RULES DATABASE                                │
│                                                              │
│ TABLE: normalization_rules                                  │
│                                                              │
│ ┌────────────────────┬─────────────────────────────────┐   │
│ │ raw_pattern        │ normalized_output               │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "DES"              │ {algo:"DES", keysize:56,        │   │
│ │                    │  mode:"ECB", type:"symmetric"}  │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "AES/GCM/NoPadding"│ {algo:"AES", mode:"GCM",        │   │
│ │                    │  padding:"none", type:"symm"}   │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "AES"              │ {algo:"AES", mode:"default",    │   │
│ │                    │  padding:"default", ...}        │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "SHA-256"          │ {algo:"SHA2", variant:"256",    │   │
│ │                    │  output_bits:256, type:"hash"}  │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "SHA256withRSA"    │ {hash_algo:"SHA2-256",          │   │
│ │                    │  signing_algo:"RSA",            │   │
│ │                    │  type:"signature"}              │   │
│ ├────────────────────┼─────────────────────────────────┤   │
│ │ "RSA"              │ {algo:"RSA", type:"asymmetric", │   │
│ │                    │  keysize:null, purpose:null}    │   │
│ └────────────────────┴─────────────────────────────────┘   │
│                                                              │
│ RULES MANAGED AS:                                            │
│   → YAML files in Git repository                            │
│   → Version controlled                                       │
│   → Loaded into DB at platform start                        │
│   → Human-reviewed before deployment                        │
└──────────────────────────────────────────────────────────────┘

NORMALIZATION ALGORITHM:

┌──────────────────────────────────────────────────────────────┐
│ FOR EACH evidence_record in evidence_records table:         │
│                                                              │
│   raw_algorithm = evidence_record.algorithm                 │
│                                                              │
│   -- STEP 1: Exact match lookup                             │
│   normalized = LOOKUP(normalization_rules, raw_algorithm)   │
│                                                              │
│   IF found:                                                  │
│     → Use normalized output                                  │
│     → Confidence = HIGH                                      │
│                                                              │
│   -- STEP 2: Pattern matching (if exact fails)              │
│   ELSE IF raw_algorithm matches "*/*/":                     │
│     → Parse as "algorithm/mode/padding"                     │
│     → Normalize each component separately                   │
│     → Combine into normalized form                          │
│     → Confidence = MEDIUM                                    │
│                                                              │
│   -- STEP 3: Unknown algorithm                              │
│   ELSE:                                                      │
│     → Mark as: algorithm = UNKNOWN                           │
│     → Store raw_algorithm in metadata                       │
│     → Confidence = LOW                                       │
│     → Flag for human review                                 │
│                                                              │
│   -- STEP 4: Enrich with standard metadata                  │
│   Add:                                                       │
│     → IANA algorithm ID (if applicable)                     │
│     → NIST designation (if applicable)                      │
│     → CycloneDX CBOM component type                         │
│     → Algorithm family (symmetric, asymmetric, hash, etc)   │
│                                                              │
│   -- STEP 5: Store normalized form                          │
│   UPDATE evidence_records                                    │
│   SET normalized_crypto = {                                  │
│     algorithm: "AES",                                        │
│     mode: "GCM",                                             │
│     padding: "none",                                         │
│     key_size: 256,  // if determinable                      │
│     algorithm_family: "symmetric",                           │
│     standard_name: "AES-256-GCM",                           │
│     iana_id: "aes256-gcm",                                  │
│     nist_designation: "APPROVED",                            │
│     cbom_component_type: "cryptographic-asset",             │
│     normalization_confidence: "HIGH",                        │
│     normalization_version: "1.0"                             │
│   }                                                          │
│   WHERE evidence_id = ...;                                   │
│                                                              │
│ END FOR;                                                     │
└──────────────────────────────────────────────────────────────┘

OUTPUT: evidence_records table updated with normalized_crypto JSONB
```

### 📊 Normalized Data Structure

```
evidence_record.normalized_crypto = {
  
  // CORE IDENTIFICATION
  "algorithm": "AES",              // Canonical name
  "algorithm_family": "symmetric", // symmetric/asymmetric/hash/kdf/mac
  "standard_name": "AES-256-GCM",  // Full standard designation
  
  // PARAMETERS
  "mode": "GCM",                   // null if N/A
  "padding": "none",               // null if N/A
  "key_size": 256,                 // bits, null if not applicable/known
  "iv_size": 96,                   // bits, null if N/A
  "tag_size": 128,                 // bits (for AEAD), null if N/A
  
  // PURPOSE (inferred from API)
  "purpose": "encryption",         // encryption/signing/hashing/key-exchange
  
  // STANDARDS MAPPING
  "iana_id": "aes256-gcm",         // IANA registry identifier
  "nist_designation": "APPROVED",  // APPROVED/ALLOWED/DEPRECATED/DISALLOWED
  "fips_status": "FIPS-197",       // FIPS standard compliance
  
  // CBOM INTEGRATION
  "cbom_component_type": "cryptographic-asset",
  "cbom_algorithm_ref": "urn:ietf:crypto:aes:gcm:256",
  
  // NORMALIZATION METADATA
  "normalization_confidence": "HIGH",  // HIGH/MEDIUM/LOW
  "normalization_version": "1.0",      // Rule version used
  "normalization_timestamp": "2024-01-15T...",
  "raw_input": "AES/GCM/NoPadding"    // Original scanner output
}
```

### ✅ Week 5 Deliverable

**Normalization system that:**
1. Converts 20+ common Java crypto API calls to canonical form
2. Stores normalized data in `evidence_records.normalized_crypto`
3. Handles unknown algorithms gracefully (mark for review)
4. Version-controlled normalization rules (YAML)
5. Adds NIST/IANA/CBOM metadata

**Testing:**
- Scan repo with 10 different crypto APIs
- Run normalization
- Verify: "DES", "AES/GCM/NoPadding", "SHA-256", "SHA256withRSA" all normalized correctly
- Verify: Unknown algorithm "CustomCrypto" marked as UNKNOWN, flagged for review
- Query: `SELECT * FROM evidence_records WHERE normalized_crypto->>'nist_designation' = 'APPROVED'`

---

## WEEK 6-7: BASIC POLICY ENGINE

### 🎯 Goal
Deterministic compliance checking against simple rules

### 📐 Architecture — Policy Engine v1.0

```
┌─────────────────────────────────────────────────────────────┐
│              POLICY ENGINE v1.0 (Deterministic)             │
│              NO AI — Pure Rule Evaluation                   │
└─────────────────────────────────────────────────────────────┘

POLICY RULE STRUCTURE:

┌──────────────────────────────────────────────────────────────┐
│ RULE DEFINITION (YAML format)                               │
│                                                              │
│ Example: rules/month2/forbidden-algorithms.yaml             │
│                                                              │
│ ---                                                          │
│ rule_id: "BASELINE-001"                                     │
│ rule_name: "Forbidden Cryptographic Algorithms"             │
│ version: "1.0"                                              │
│ effective_date: "2024-01-01"                                │
│ severity: "CRITICAL"                                         │
│ standard_reference: "Internal Security Baseline"            │
│                                                              │
│ description: >                                               │
│   DES, 3DES, RC4, MD5, SHA-1 are forbidden for new code.   │
│   These algorithms are cryptographically broken.             │
│                                                              │
│ condition:                                                   │
│   type: "ALGORITHM_IN_LIST"                                 │
│   parameters:                                                │
│     algorithm_list:                                          │
│       - "DES"                                                │
│       - "3DES"                                               │
│       - "RC4"                                                │
│       - "MD5"                                                │
│       - "SHA-1"                                              │
│                                                              │
│ evaluation:                                                  │
│   IF normalized_crypto.algorithm IN algorithm_list:         │
│     result: FAIL                                             │
│     message: "Algorithm {algorithm} is forbidden"           │
│   ELSE:                                                      │
│     result: PASS                                             │
│                                                              │
│ remediation: >                                               │
│   Replace with approved alternative:                        │
│   DES/3DES → AES-256-GCM                                    │
│   RC4 → ChaCha20-Poly1305                                   │
│   MD5/SHA-1 → SHA-256 or SHA-512                           │
│ ---                                                          │
└──────────────────────────────────────────────────────────────┘

MORE RULE EXAMPLES:

┌──────────────────────────────────────────────────────────────┐
│ RULE: Minimum Key Size                                      │
│                                                              │
│ rule_id: "BASELINE-002"                                     │
│ condition:                                                   │
│   type: "KEY_SIZE_MINIMUM"                                  │
│   parameters:                                                │
│     algorithm: "RSA"                                         │
│     minimum_key_size: 2048                                   │
│                                                              │
│ evaluation:                                                  │
│   IF algorithm == "RSA" AND key_size < 2048:                │
│     result: FAIL                                             │
│   ELSE:                                                      │
│     result: PASS                                             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ RULE: Approved Modes for AES                                │
│                                                              │
│ rule_id: "BASELINE-003"                                     │
│ condition:                                                   │
│   type: "ALGORITHM_MODE_WHITELIST"                          │
│   parameters:                                                │
│     algorithm: "AES"                                         │
│     approved_modes: ["GCM", "CCM", "CTR"]                   │
│     forbidden_modes: ["ECB", "CBC"]                         │
│                                                              │
│ evaluation:                                                  │
│   IF algorithm == "AES":                                    │
│     IF mode IN forbidden_modes:                             │
│       result: FAIL (critical)                               │
│     ELSE IF mode IN approved_modes:                         │
│       result: PASS                                           │
│     ELSE:                                                    │
│       result: WARN (unknown mode)                           │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ RULE: Hardcoded Keys                                        │
│                                                              │
│ rule_id: "BASELINE-004"                                     │
│ severity: "CRITICAL"                                         │
│                                                              │
│ condition:                                                   │
│   type: "BOOLEAN_FLAG"                                      │
│   parameters:                                                │
│     field: "is_hardcoded_key"                               │
│     forbidden_value: true                                    │
│                                                              │
│ evaluation:                                                  │
│   IF is_hardcoded_key == true:                              │
│     result: FAIL                                             │
│     message: "Hardcoded cryptographic key detected"         │
└──────────────────────────────────────────────────────────────┘

POLICY ENGINE EXECUTION:

┌──────────────────────────────────────────────────────────────┐
│ TRIGGERED: After normalization completes (Week 5)           │
│                                                              │
│ FOR EACH evidence_record:                                    │
│                                                              │
│   applicable_rules = []                                      │
│                                                              │
│   -- STEP 1: Determine applicable rules                     │
│   FOR EACH rule IN policy_rules:                            │
│     IF rule applies to this evidence:                       │
│       (based on algorithm, purpose, etc)                    │
│       applicable_rules.append(rule)                          │
│                                                              │
│   -- STEP 2: Evaluate each rule                             │
│   policy_results = []                                        │
│                                                              │
│   FOR EACH rule IN applicable_rules:                        │
│                                                              │
│     -- Execute rule condition logic                         │
│     result = EVALUATE_RULE(rule, evidence_record)           │
│                                                              │
│     policy_result = {                                        │
│       rule_id: rule.rule_id,                                │
│       rule_name: rule.rule_name,                            │
│       rule_version: rule.version,                           │
│       evaluation_result: "PASS" | "FAIL" | "WARN",         │
│       severity: rule.severity,                              │
│       message: "...",                                        │
│       remediation: rule.remediation,                         │
│       evaluated_at: timestamp,                              │
│       evaluated_by: "policy-engine-v1.0",                   │
│       evidence_used: [evidence_id],                          │
│       determination_method: "deterministic-rule-eval"       │
│     }                                                        │
│                                                              │
│     policy_results.append(policy_result)                     │
│                                                              │
│   -- STEP 3: Aggregate overall status                       │
│   overall_status = "PASS"                                    │
│   IF any FAIL in policy_results:                            │
│     overall_status = "FAIL"                                  │
│   ELSE IF any WARN in policy_results:                       │
│     overall_status = "WARN"                                  │
│                                                              │
│   -- STEP 4: Store results                                  │
│   UPDATE evidence_records                                    │
│   SET                                                        │
│     policy_evaluation = {                                    │
│       overall_status: overall_status,                        │
│       rules_evaluated: policy_results,                       │
│       evaluation_timestamp: NOW(),                           │
│       policy_version: "1.0"                                  │
│     },                                                       │
│     compliance_status = overall_status                      │
│   WHERE evidence_id = ...;                                   │
│                                                              │
│ END FOR;                                                     │
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA ADDITION:

ALTER TABLE evidence_records ADD COLUMN policy_evaluation JSONB;
ALTER TABLE evidence_records ADD COLUMN compliance_status VARCHAR(20);

CREATE INDEX idx_compliance_status ON evidence_records(compliance_status);
CREATE INDEX idx_policy_fail ON evidence_records((policy_evaluation->>'overall_status')) 
  WHERE (policy_evaluation->>'overall_status') = 'FAIL';
```

### 📊 Rule Evaluation Example

```
EXAMPLE EVALUATION:

Evidence Record:
  algorithm: "DES"
  key_size: 56
  mode: "ECB"
  purpose: "encryption"
  file_path: "Payment.java"
  line_number: 247

Applicable Rules:
  1. BASELINE-001 (Forbidden Algorithms)
  2. BASELINE-003 (Approved Modes — but only for AES, so N/A)

Evaluation of BASELINE-001:
  Condition: algorithm IN ["DES", "3DES", "RC4", "MD5", "SHA-1"]
  Evidence.algorithm = "DES"
  "DES" IN list? YES
  Result: FAIL
  Severity: CRITICAL
  Message: "Algorithm DES is forbidden"
  Remediation: "Replace DES with AES-256-GCM"

Final Policy Evaluation:
{
  "overall_status": "FAIL",
  "rules_evaluated": [
    {
      "rule_id": "BASELINE-001",
      "rule_name": "Forbidden Cryptographic Algorithms",
      "rule_version": "1.0",
      "evaluation_result": "FAIL",
      "severity": "CRITICAL",
      "message": "Algorithm DES is forbidden",
      "remediation": "Replace DES with AES-256-GCM",
      "evaluated_at": "2024-01-15T10:00:00Z",
      "evaluated_by": "policy-engine-v1.0",
      "evidence_used": ["evidence-uuid-123"],
      "determination_method": "deterministic-rule-eval"
    }
  ],
  "evaluation_timestamp": "2024-01-15T10:00:00Z",
  "policy_version": "1.0"
}

Compliance Status: "FAIL"
```

### ✅ Week 6-7 Deliverable

**Policy engine that:**
1. Loads rules from YAML files (version controlled)
2. Evaluates 4 basic rules:
   - Forbidden algorithms
   - Minimum RSA key size
   - Approved AES modes
   - Hardcoded key detection
3. Stores evaluation results in `evidence_records.policy_evaluation`
4. Sets `compliance_status` field (PASS/WARN/FAIL)
5. Purely deterministic (no interpretation, no AI)

**Testing:**
- Scan test repo with DES → policy eval → FAIL (forbidden algorithm)
- Scan test repo with AES-ECB → policy eval → FAIL (forbidden mode)
- Scan test repo with RSA-1024 → policy eval → FAIL (key too small)
- Scan test repo with hardcoded key → policy eval → FAIL
- Scan test repo with AES-256-GCM → policy eval → PASS
- Query: `SELECT * FROM evidence_records WHERE compliance_status = 'FAIL'`

---

## WEEK 8: DRIFT DETECTION — BASELINE SNAPSHOT

### 🎯 Goal
Detect when crypto configuration changes between scans

### 📐 Architecture — Drift Detection v1.0

```
┌─────────────────────────────────────────────────────────────┐
│              DRIFT DETECTION SYSTEM v1.0                    │
│              (Baseline Comparison Engine)                   │
└─────────────────────────────────────────────────────────────┘

CONCEPT:

Drift = Current State - Approved Baseline State

APPROVED BASELINE:
  → A scan that has been human-reviewed and approved
  → Represents the "known good" crypto configuration
  → One baseline per system/repo/environment

DRIFT EVENT:
  → When current scan differs from baseline
  → Types: NEW crypto, REMOVED crypto, CHANGED crypto, DEGRADED crypto

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: baselines                                             │
│                                                              │
│ baseline_id       UUID PK                                    │
│ system_identifier VARCHAR(200)  -- repo URL or system name  │
│ environment       VARCHAR(50)   -- prod, staging, dev        │
│ approved_scan_id  UUID FK       -- → scans.scan_id          │
│ approved_by       VARCHAR(100)  -- Who approved it          │
│ approved_at       TIMESTAMP     -- When approved            │
│ status            VARCHAR(20)   -- ACTIVE, SUPERSEDED        │
│ notes             TEXT          -- Human notes               │
│ created_at        TIMESTAMP                                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: drift_events                                          │
│                                                              │
│ drift_id          UUID PK                                    │
│ baseline_id       UUID FK       -- → baselines              │
│ current_scan_id   UUID FK       -- → scans                  │
│ detected_at       TIMESTAMP                                  │
│ drift_type        VARCHAR(50)   -- NEW, REMOVED, CHANGED... │
│ severity          VARCHAR(20)   -- CRITICAL, HIGH, MEDIUM…  │
│ drift_details     JSONB         -- What changed             │
│ resolution_status VARCHAR(50)   -- OPEN, ACKNOWLEDGED, ...  │
│ resolved_by       VARCHAR(100)                              │
│ resolved_at       TIMESTAMP                                  │
│ resolution_notes  TEXT                                       │
└──────────────────────────────────────────────────────────────┘

DRIFT DETECTION ALGORITHM:

┌──────────────────────────────────────────────────────────────┐
│ TRIGGERED: After new scan completes and is loaded to DB     │
│                                                              │
│ INPUT:                                                       │
│   → current_scan_id (the scan that just completed)          │
│   → system_identifier (repo URL from scan metadata)         │
│                                                              │
│ STEP 1: Find applicable baseline                            │
│                                                              │
│ baseline = SELECT * FROM baselines                          │
│            WHERE system_identifier = {current_system}       │
│            AND status = 'ACTIVE'                             │
│            LIMIT 1;                                          │
│                                                              │
│ IF no baseline found:                                        │
│   → This is FIRST scan of this system                       │
│   → Prompt: "Approve this scan as baseline?"               │
│   → No drift detection (nothing to compare to)             │
│   → EXIT                                                     │
│                                                              │
│ approved_scan_id = baseline.approved_scan_id                │
│                                                              │
│ STEP 2: Load baseline crypto inventory                      │
│                                                              │
│ baseline_crypto = SELECT                                     │
│   algorithm, mode, key_size, purpose,                       │
│   file_path, line_number                                     │
│ FROM evidence_records                                        │
│ WHERE scan_id = approved_scan_id;                           │
│                                                              │
│ Create baseline fingerprint set:                            │
│ baseline_set = {}                                            │
│ FOR EACH record IN baseline_crypto:                         │
│   fingerprint = hash(algorithm + mode + key_size +          │
│                      file_path + line_number)               │
│   baseline_set[fingerprint] = record                        │
│                                                              │
│ STEP 3: Load current scan crypto inventory                  │
│                                                              │
│ current_crypto = SELECT ... FROM evidence_records           │
│                  WHERE scan_id = current_scan_id;           │
│                                                              │
│ current_set = {}                                             │
│ FOR EACH record IN current_crypto:                          │
│   fingerprint = hash(...)  -- same formula                  │
│   current_set[fingerprint] = record                         │
│                                                              │
│ STEP 4: Detect differences                                  │
│                                                              │
│ drift_events = []                                            │
│                                                              │
│ -- A. Detect NEW crypto (in current, not in baseline)       │
│ new_fingerprints = current_set.keys() - baseline_set.keys() │
│                                                              │
│ FOR EACH fp IN new_fingerprints:                            │
│   record = current_set[fp]                                  │
│   drift_events.append({                                      │
│     drift_type: "NEW_CRYPTO",                               │
│     severity: determine_severity(record),                   │
│     drift_details: {                                         │
│       algorithm: record.algorithm,                           │
│       location: record.file_path + ":" + record.line_number,│
│       baseline_state: "NOT_PRESENT",                        │
│       current_state: record.normalized_crypto,              │
│       message: "New cryptographic call detected"            │
│     }                                                        │
│   })                                                         │
│                                                              │
│ -- B. Detect REMOVED crypto (in baseline, not in current)   │
│ removed_fingerprints = baseline_set.keys() - current_set.keys() │
│                                                              │
│ FOR EACH fp IN removed_fingerprints:                        │
│   record = baseline_set[fp]                                 │
│   drift_events.append({                                      │
│     drift_type: "REMOVED_CRYPTO",                           │
│     severity: "INFO",  -- removal usually good              │
│     drift_details: {                                         │
│       algorithm: record.algorithm,                           │
│       location: record.file_path + ":" + record.line_number,│
│       baseline_state: record.normalized_crypto,             │
│       current_state: "NOT_PRESENT",                         │
│       message: "Cryptographic call removed"                 │
│     }                                                        │
│   })                                                         │
│                                                              │
│ -- C. Detect CHANGED crypto (different algo at same location)│
│ --    (Requires more sophisticated comparison)              │
│ --    For Month 2: Skip this (complex logic)                │
│ --    Just detect NEW and REMOVED                           │
│                                                              │
│ STEP 5: Severity determination                              │
│                                                              │
│ FUNCTION determine_severity(crypto_record):                 │
│   IF crypto_record.compliance_status == "FAIL":             │
│     RETURN "CRITICAL"  -- New non-compliant crypto          │
│   ELSE IF crypto_record.is_hardcoded_key == true:          │
│     RETURN "CRITICAL"  -- New hardcoded key                 │
│   ELSE IF crypto_record.normalized_crypto.nist_designation  │
│            == "DEPRECATED":                                  │
│     RETURN "HIGH"      -- New deprecated algo               │
│   ELSE:                                                      │
│     RETURN "MEDIUM"    -- New crypto, but compliant         │
│                                                              │
│ STEP 6: Store drift events                                  │
│                                                              │
│ FOR EACH event IN drift_events:                             │
│   INSERT INTO drift_events (                                 │
│     baseline_id, current_scan_id, detected_at,              │
│     drift_type, severity, drift_details,                    │
│     resolution_status                                        │
│   ) VALUES (                                                 │
│     baseline.baseline_id,                                    │
│     current_scan_id,                                         │
│     NOW(),                                                   │
│     event.drift_type,                                        │
│     event.severity,                                          │
│     event.drift_details,                                     │
│     'OPEN'                                                   │
│   );                                                         │
│                                                              │
│ STEP 7: Summary                                              │
│                                                              │
│ drift_summary = {                                            │
│   total_drift_events: drift_events.length,                  │
│   critical: count(severity == 'CRITICAL'),                  │
│   high: count(severity == 'HIGH'),                          │
│   medium: count(severity == 'MEDIUM'),                      │
│   info: count(severity == 'INFO'),                          │
│   new_crypto_count: count(drift_type == 'NEW_CRYPTO'),     │
│   removed_crypto_count: count(drift_type == 'REMOVED_CRYPTO')│
│ }                                                            │
│                                                              │
│ RETURN drift_summary                                         │
└──────────────────────────────────────────────────────────────┘
```

### 🔔 Drift Alert Logic (Simple — Month 2)

```
┌──────────────────────────────────────────────────────────────┐
│ DRIFT ALERT TRIGGER                                          │
│                                                              │
│ After drift detection completes:                            │
│                                                              │
│ IF drift_summary.critical > 0:                              │
│   → Send email to: security team                            │
│   → Subject: "CRITICAL crypto drift detected in {system}"   │
│   → Body: drift_summary + link to drift report              │
│                                                              │
│ IF drift_summary.high > 0:                                   │
│   → Send email to: security team                            │
│   → Subject: "HIGH severity crypto drift in {system}"       │
│                                                              │
│ IF drift_summary.medium > 0 OR drift_summary.info > 0:      │
│   → Log to system (no immediate alert)                      │
│   → Include in daily digest email                           │
│                                                              │
│ EMAIL FORMAT (simple text for Month 2):                     │
│                                                              │
│ Subject: CRITICAL crypto drift detected in payment-api      │
│                                                              │
│ Body:                                                        │
│ Drift detected in: payment-api (main branch)                │
│ Baseline scan: 2024-01-01 (approved by alice.security)      │
│ Current scan:  2024-01-15                                    │
│                                                              │
│ Summary:                                                     │
│ - 1 CRITICAL drift event                                     │
│ - 0 HIGH drift events                                        │
│ - 2 MEDIUM drift events                                      │
│                                                              │
│ CRITICAL Events:                                             │
│ 1. NEW_CRYPTO: DES detected in Payment.java:247            │
│    Compliance status: FAIL (forbidden algorithm)            │
│                                                              │
│ View full report: https://cryptoscan.local/drift/{drift_id} │
│                                                              │
│ This is an automated alert from CryptoScan Platform v1.0    │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 8 Deliverable

**Drift detection system that:**
1. Stores approved baseline scans in `baselines` table
2. Compares new scans to baseline
3. Detects NEW and REMOVED crypto
4. Assigns severity (CRITICAL if non-compliant)
5. Stores drift events in `drift_events` table
6. Sends email alerts for CRITICAL/HIGH drift

**Testing:**
- Scan repo → approve as baseline
- Modify code to add DES call → rescan
- Drift detector runs → detects NEW_CRYPTO (DES)
- Severity: CRITICAL (because DES fails policy)
- Email sent to security team
- Query: `SELECT * FROM drift_events WHERE severity = 'CRITICAL' AND resolution_status = 'OPEN'`

---

# 🗺️ MONTH 3: BASIC UI + END-TO-END INTEGRATION + GITHUB INTEGRATION

---

## WEEK 9-10: BASIC WEB DASHBOARD

### 🎯 Goal
Build a minimal web UI to view scans, findings, and drift

### 📐 Architecture — Dashboard v1.0

```
┌─────────────────────────────────────────────────────────────┐
│              WEB DASHBOARD v1.0 (Read-Only MVP)             │
│              Technology: Server-rendered HTML (simple)      │
│              OR: React SPA (if team has React experience)   │
└─────────────────────────────────────────────────────────────┘

PAGES (Minimum Viable):

┌──────────────────────────────────────────────────────────────┐
│ PAGE 1: DASHBOARD HOME                                       │
│                                                              │
│ URL: /                                                       │
│                                                              │
│ DISPLAYS:                                                    │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  CRYPTOSCAN PLATFORM — DASHBOARD                       │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  INVENTORY SUMMARY                                     │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │  Total Scans:     47                             │ │  │
│ │  │  Total Findings:  1,284                          │ │  │
│ │  │  Compliant:       892  (69%)                     │ │  │
│ │  │  Non-Compliant:   392  (31%)                     │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  RECENT SCANS                                          │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │  Scan ID  | System      | Date       | Status   │ │  │
│ │  ├───────────┼─────────────┼────────────┼──────────┤ │  │
│ │  │  abc123   | payment-api | 2024-01-15 | COMPLETE│ │  │
│ │  │  def456   | customer-db | 2024-01-14 | COMPLETE│ │  │
│ │  │  ...                                             │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │  [View All Scans]                                      │  │
│ │                                                        │  │
│ │  OPEN DRIFT EVENTS                                     │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │  🔴 CRITICAL: 3                                  │ │  │
│ │  │  🟠 HIGH:     7                                  │ │  │
│ │  │  🟡 MEDIUM:   12                                 │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │  [View Drift Events]                                   │  │
│ │                                                        │  │
│ │  COMPLIANCE BREAKDOWN (by algorithm)                   │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │  AES:     428 findings  (98% compliant)          │ │  │
│ │  │  RSA:     312 findings  (72% compliant)          │ │  │
│ │  │  SHA-256: 289 findings  (100% compliant)         │ │  │
│ │  │  DES:     34 findings   (0% compliant) ❌         │ │  │
│ │  │  MD5:     21 findings   (0% compliant) ❌         │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ DATA SOURCES (SQL queries):                                 │
│   → Total scans: SELECT COUNT(*) FROM scans                │
│   → Total findings: SELECT COUNT(*) FROM evidence_records  │
│   → Compliant: WHERE compliance_status = 'PASS'            │
│   → Recent scans: ORDER BY scan_start DESC LIMIT 10        │
│   → Drift: SELECT COUNT(*), severity FROM drift_events     │
│            WHERE resolution_status = 'OPEN' GROUP BY ...   │
│   → Algorithm breakdown: GROUP BY algorithm                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PAGE 2: SCAN DETAIL                                          │
│                                                              │
│ URL: /scans/{scan_id}                                       │
│                                                              │
│ DISPLAYS:                                                    │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  SCAN: payment-api-main-2024-01-15                     │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  SCAN METADATA                                         │  │
│ │  Scanner:      static-java-scanner-v0.1                │  │
│ │  Started:      2024-01-15 08:00:00                     │  │
│ │  Completed:    2024-01-15 08:04:32                     │  │
│ │  Duration:     4m 32s                                   │  │
│ │  Target:       https://github.com/org/payment-api      │  │
│ │  Commit:       a1b2c3d4e5f6...                         │  │
│ │  Branch:       main                                     │  │
│ │                                                        │  │
│ │  FINDINGS SUMMARY                                       │  │
│ │  Total:        34 findings                             │  │
│ │  Compliant:    28                                      │  │
│ │  Non-compliant: 6                                      │  │
│ │                                                        │  │
│ │  FINDINGS TABLE (paginated)                            │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ Algo   | Location      | Line | Status | Actions│ │  │
│ │  ├────────┼───────────────┼──────┼────────┼────────┤ │  │
│ │  │ DES    | Payment.java  | 247  | FAIL ❌│ [View] │ │  │
│ │  │ AES-GCM| Auth.java     | 89   | PASS ✅│ [View] │ │  │
│ │  │ SHA-256| Hash.java     | 12   | PASS ✅│ [View] │ │  │
│ │  │ ...                                              │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │  [Export as JSON] [Export as CSV]                     │  │
│ │                                                        │  │
│ │  DRIFT COMPARISON                                      │  │
│ │  Baseline: 2024-01-01 (approved by alice.security)    │  │
│ │  Drift events: 3 (1 CRITICAL, 2 MEDIUM)                │  │
│ │  [View Drift Report]                                   │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ DATA SOURCES:                                                │
│   → SELECT * FROM scans WHERE scan_id = {scan_id}          │
│   → SELECT * FROM evidence_records WHERE scan_id = ...     │
│   → SELECT * FROM drift_events WHERE current_scan_id = ... │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PAGE 3: FINDING DETAIL                                       │
│                                                              │
│ URL: /findings/{evidence_id}                                │
│                                                              │
│ DISPLAYS:                                                    │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  FINDING: DES in payment-api                           │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  CRYPTO DETAILS                                        │  │
│ │  Algorithm:    DES                                     │  │
│ │  Key Size:     56 bits                                 │  │
│ │  Mode:         ECB                                     │  │
│ │  Purpose:      Encryption                              │  │
│ │  Library:      javax.crypto                            │  │
│ │                                                        │  │
│ │  LOCATION                                              │  │
│ │  File:         src/main/Payment.java                   │  │
│ │  Line:         247                                     │  │
│ │  Method:       encryptCardData()                       │  │
│ │  Class:        com.example.PaymentProcessor            │  │
│ │                                                        │  │
│ │  CODE SNIPPET                                          │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ 242:                                             │ │  │
│ │  │ 243:   public String encryptCardData(String pan) {│ │ │
│ │  │ 244:     try {                                   │ │  │
│ │  │ 245:       // Encrypt sensitive card data        │ │  │
│ │  │ 246:       String transformation = "DES";        │ │  │
│ │  │ 247: >>>   Cipher cipher = Cipher.getInstance(   │ │  │
│ │  │ 248:           transformation);                   │ │  │
│ │  │ 249:       cipher.init(Cipher.ENCRYPT_MODE, key);│ │  │
│ │  │ 250:       return cipher.doFinal(pan.getBytes());│ │  │
│ │  │ 251:     } catch (Exception e) {                 │ │  │
│ │  │ 252:       log.error("Encryption failed", e);    │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  COMPLIANCE STATUS                                     │  │
│ │  Overall: FAIL ❌                                      │  │
│ │                                                        │  │
│ │  Failed Rules:                                         │  │
│ │  • BASELINE-001: Forbidden Algorithms (CRITICAL)       │  │
│ │    → DES is cryptographically broken                  │  │
│ │    → Remediation: Replace with AES-256-GCM            │  │
│ │                                                        │  │
│ │  EVIDENCE INTEGRITY                                    │  │
│ │  Content Hash:  a1b2c3d4e5f6...                       │  │
│ │  Chain Hash:    x1y2z3w4v5u6...                       │  │
│ │  Verified:      ✅ Integrity intact                    │  │
│ │  Scanner:       static-java-scanner-v0.1               │  │
│ │  Scan Date:     2024-01-15 08:02:14                   │  │
│ │                                                        │  │
│ │  GIT CONTEXT                                           │  │
│ │  Commit:        a1b2c3d4 (2024-01-14)                 │  │
│ │  Author:        john.developer                         │  │
│ │  Message:       "Add payment encryption"              │  │
│ │  [View on GitHub]                                     │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ DATA SOURCES:                                                │
│   → SELECT * FROM evidence_records WHERE evidence_id = ... │
│   → policy_evaluation JSONB field                           │
│   → finding_data JSONB field                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PAGE 4: DRIFT EVENTS                                         │
│                                                              │
│ URL: /drift                                                  │
│                                                              │
│ DISPLAYS:                                                    │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  DRIFT EVENTS                                          │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  FILTER: [All] [CRITICAL] [HIGH] [MEDIUM] [INFO]      │  │
│ │          [OPEN] [ACKNOWLEDGED] [RESOLVED]              │  │
│ │                                                        │  │
│ │  DRIFT EVENT LIST                                      │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ Severity | System      | Type      | Detected   │ │  │
│ │  ├──────────┼─────────────┼───────────┼────────────┤ │  │
│ │  │ 🔴 CRIT  │ payment-api │ NEW_CRYPTO│ 2024-01-15│ │  │
│ │  │ 🟠 HIGH  │ auth-svc    │ NEW_CRYPTO│ 2024-01-14│ │  │
│ │  │ 🟡 MED   │ payment-api │ NEW_CRYPTO│ 2024-01-15│ │  │
│ │  │ ...                                              │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  Click any row to see details ──────────────────────> │  │
│ │                                                        │  │
│ │  DRIFT DETAIL (when row clicked):                     │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │  Drift Type:     NEW_CRYPTO                      │ │  │
│ │  │  Severity:       CRITICAL                        │ │  │
│ │  │  System:         payment-api                     │ │  │
│ │  │  Detected:       2024-01-15 08:05:00             │ │  │
│ │  │  Status:         OPEN                            │ │  │
│ │  │                                                  │ │  │
│ │  │  Details:                                        │ │  │
│ │  │  Algorithm:      DES                             │ │  │
│ │  │  Location:       Payment.java:247                │ │  │
│ │  │  Baseline State: NOT_PRESENT                     │ │  │
│ │  │  Current State:  PRESENT (non-compliant)         │ │  │
│ │  │                                                  │ │  │
│ │  │  Message:                                        │ │  │
│ │  │  "New cryptographic call detected. This         │ │  │
│ │  │   algorithm (DES) is forbidden by policy."       │ │  │
│ │  │                                                  │ │  │
│ │  │  [Acknowledge] [Mark as False Positive] [Resolve]│ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ DATA SOURCES:                                                │
│   → SELECT * FROM drift_events ORDER BY detected_at DESC   │
│   → Filter by severity, resolution_status                   │
└──────────────────────────────────────────────────────────────┘
```

### 🔧 Technical Implementation (High-Level)

```
TECHNOLOGY STACK (Month 3 MVP):

Backend:
  → Language: Python (Flask) or Node.js (Express)
  → Database: PostgreSQL (already have schema)
  → ORM: SQLAlchemy (Python) or Sequelize (Node)

Frontend:
  → Option A: Server-rendered HTML (Jinja2/EJS templates)
    WHY: Simpler, faster to build for MVP
  → Option B: React SPA
    WHY: Better UX, but more complex

Authentication (Month 3 simple):
  → Basic username/password
  → Stored in DB (hashed with bcrypt)
  → Session-based auth (cookies)
  → NO OAuth/SAML yet (that's later)

API ENDPOINTS (for dashboard):

GET /api/scans
  → Returns list of scans
  → Supports pagination, filtering

GET /api/scans/{scan_id}
  → Returns scan details + findings

GET /api/findings/{evidence_id}
  → Returns full finding detail

GET /api/drift
  → Returns drift events
  → Supports filtering by severity, status

GET /api/stats/summary
  → Returns dashboard summary stats
  → Total scans, findings, compliance %

POST /api/drift/{drift_id}/acknowledge
  → Mark drift event as acknowledged
  → Updates resolution_status

DEPLOYMENT (Month 3 simple):
  → Docker container
  → Runs on single VM or local machine
  → PostgreSQL in separate container
  → docker-compose for orchestration
```

### ✅ Week 9-10 Deliverable

**Web dashboard that:**
1. Shows dashboard home with summary stats
2. Lists all scans with basic filtering
3. Shows scan detail page with findings table
4. Shows finding detail page with code snippet, compliance status, evidence hash
5. Shows drift events page with filtering
6. Allows marking drift events as acknowledged
7. Exports scan results as JSON

**Testing:**
- Navigate to dashboard → see summary stats
- Click scan → see findings list
- Click finding → see full detail with code snippet
- Click drift tab → see drift events
- Click "Acknowledge" on drift → status updates
- Export scan as JSON → valid JSON file downloads

---

## WEEK 11: GITHUB INTEGRATION — WEBHOOK SCANNING

### 🎯 Goal
Automatically trigger scans on code commits

### 📐 Architecture — GitHub Webhook Integration

```
┌─────────────────────────────────────────────────────────────┐
│              GITHUB WEBHOOK INTEGRATION v1.0                │
│              (Auto-scan on push events)                     │
└─────────────────────────────────────────────────────────────┘

SETUP:

1. GitHub App or Webhook Registration
   → In GitHub repo settings: Add webhook
   → Webhook URL: https://cryptoscan.local/webhooks/github
   → Events to subscribe: push, pull_request
   → Secret: shared secret for HMAC verification

2. CryptoScan Webhook Receiver
   → HTTP endpoint that receives GitHub webhook POST

WORKFLOW:

┌──────────────────────────────────────────────────────────────┐
│ GITHUB EVENT: Push to main branch                           │
│                                                              │
│ Developer: git push origin main                             │
│      │                                                       │
│      ▼                                                       │
│ GitHub: Fires webhook                                        │
│      │                                                       │
│      ▼                                                       │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ POST https://cryptoscan.local/webhooks/github            ││
│ │                                                          ││
│ │ Headers:                                                 ││
│ │   X-GitHub-Event: push                                   ││
│ │   X-Hub-Signature-256: sha256=abcd1234... (HMAC)        ││
│ │                                                          ││
│ │ Body (JSON):                                             ││
│ │ {                                                        ││
│ │   "ref": "refs/heads/main",                             ││
│ │   "repository": {                                        ││
│ │     "full_name": "org/payment-api",                     ││
│ │     "clone_url": "https://github.com/org/payment-api",  ││
│ │     "html_url": "https://github.com/org/payment-api"    ││
│ │   },                                                     ││
│ │   "head_commit": {                                       ││
│ │     "id": "a1b2c3d4e5f6...",                            ││
│ │     "message": "Add payment encryption",                ││
│ │     "author": { "name": "John Dev", "email": "..." },   ││
│ │     "timestamp": "2024-01-15T08:00:00Z"                 ││
│ │   },                                                     ││
│ │   "pusher": { "name": "john.developer" }                ││
│ │ }                                                        ││
│ └──────────────────────────────────────────────────────────┘│
│      │                                                       │
│      ▼                                                       │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ CRYPTOSCAN WEBHOOK HANDLER                               ││
│ │                                                          ││
│ │ STEP 1: Verify HMAC signature                           ││
│ │   expected_hmac = HMAC-SHA256(body, webhook_secret)     ││
│ │   received_hmac = X-Hub-Signature-256 header            ││
│ │   IF expected_hmac != received_hmac:                    ││
│ │     REJECT request (security)                            ││
│ │                                                          ││
│ │ STEP 2: Parse webhook payload                           ││
│ │   repo_url = payload.repository.clone_url               ││
│ │   commit_hash = payload.head_commit.id                  ││
│ │   branch = payload.ref (extract after refs/heads/)      ││
│ │   author = payload.head_commit.author.name              ││
│ │                                                          ││
│ │ STEP 3: Check if this repo is configured for scanning   ││
│ │   repo_config = LOOKUP(repo_url in config database)     ││
│ │   IF repo not in allowed list:                          ││
│ │     LOG "Webhook from unconfigured repo"                ││
│ │     RETURN 200 OK (ack but don't scan)                  ││
│ │                                                          ││
│ │ STEP 4: Create scan job                                 ││
│ │   scan_job = {                                          ││
│ │     job_id: UUID,                                       ││
│ │     job_type: "GITHUB_WEBHOOK",                         ││
│ │     target_repo: repo_url,                              ││
│ │     target_commit: commit_hash,                         ││
│ │     target_branch: branch,                              ││
│ │     triggered_by: author,                               ││
│ │     created_at: NOW(),                                  ││
│ │     status: "QUEUED"                                    ││
│ │   }                                                     ││
│ │                                                          ││
│ │   INSERT INTO scan_jobs (...);                          ││
│ │                                                          ││
│ │ STEP 5: Queue scan job for execution                    ││
│ │   PUBLISH to message queue (Redis/RabbitMQ)             ││
│ │   Topic: scan-jobs                                       ││
│ │   Message: scan_job                                      ││
│ │                                                          ││
│ │ STEP 6: Return 200 OK to GitHub                         ││
│ │   (Webhook must respond quickly — scanning happens async)││
│ └──────────────────────────────────────────────────────────┘│
│      │                                                       │
│      ▼                                                       │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ SCAN JOB WORKER (background process)                     ││
│ │                                                          ││
│ │ LOOP:                                                    ││
│ │   job = CONSUME from scan-jobs queue                     ││
│ │                                                          ││
│ │   UPDATE scan_jobs SET status = 'RUNNING' WHERE job_id=..││
│ │                                                          ││
│ │   -- Execute scan                                        ││
│ │   1. Clone Git repo at commit_hash                      ││
│ │      git clone {repo_url} --depth 1 --branch {branch}   ││
│ │      git checkout {commit_hash}                          ││
│ │                                                          ││
│ │   2. Run static scanner (from Week 1-2)                 ││
│ │      scanner.scan(repo_path)                            ││
│ │      → Produces RawFindings                             ││
│ │                                                          ││
│ │   3. Evidence pipeline (from Week 3)                    ││
│ │      evidence_records = create_evidence(findings)       ││
│ │                                                          ││
│ │   4. Load to database (from Week 4)                     ││
│ │      db.insert(scan_record)                             ││
│ │      db.insert(evidence_records)                         ││
│ │                                                          ││
│ │   5. Normalization (from Week 5)                        ││
│ │      normalize_evidence(evidence_records)               ││
│ │                                                          ││
│ │   6. Policy evaluation (from Week 6-7)                  ││
│ │      evaluate_policies(evidence_records)                ││
│ │                                                          ││
│ │   7. Drift detection (from Week 8)                      ││
│ │      detect_drift(scan_id)                              ││
│ │                                                          ││
│ │   8. Alerts (if drift critical)                         ││
│ │      send_drift_alerts()                                ││
│ │                                                          ││
│ │   9. Update job status                                  ││
│ │      UPDATE scan_jobs SET status = 'COMPLETED'          ││
│ │                                                          ││
│ │   10. Cleanup                                            ││
│ │       Delete cloned repo                                ││
│ │                                                          ││
│ │ END LOOP                                                 ││
│ └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA ADDITION:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: scan_jobs                                             │
│                                                              │
│ job_id            UUID PK                                    │
│ job_type          VARCHAR(50)   -- GITHUB_WEBHOOK, MANUAL   │
│ target_repo       TEXT                                       │
│ target_commit     VARCHAR(40)                                │
│ target_branch     VARCHAR(100)                               │
│ triggered_by      VARCHAR(100)                               │
│ status            VARCHAR(20)   -- QUEUED, RUNNING, ...     │
│ scan_id           UUID FK       -- → scans (when complete)  │
│ created_at        TIMESTAMP                                  │
│ started_at        TIMESTAMP                                  │
│ completed_at      TIMESTAMP                                  │
│ error_message     TEXT                                       │
└──────────────────────────────────────────────────────────────┘

CONFIGURATION:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: repo_configurations                                   │
│ (Which repos should be scanned)                             │
│                                                              │
│ config_id         UUID PK                                    │
│ repo_url          TEXT UNIQUE                                │
│ repo_name         VARCHAR(200)                               │
│ enabled           BOOLEAN                                    │
│ scan_on_push      BOOLEAN                                    │
│ scan_on_pr        BOOLEAN                                    │
│ baseline_scan_id  UUID FK       -- approved baseline        │
│ notification_emails TEXT[]       -- who to notify            │
│ created_at        TIMESTAMP                                  │
└──────────────────────────────────────────────────────────────┘
```

### 🔔 GitHub Status Check (Bonus — if time permits)

```
┌──────────────────────────────────────────────────────────────┐
│ GITHUB COMMIT STATUS API                                     │
│ (Post scan results back to GitHub)                          │
│                                                              │
│ After scan completes:                                        │
│                                                              │
│ IF compliance_status == "PASS":                             │
│   POST https://api.github.com/repos/{org}/{repo}/           │
│        statuses/{commit_hash}                                │
│   Body: {                                                    │
│     "state": "success",                                      │
│     "context": "cryptoscan/compliance",                     │
│     "description": "All crypto compliant (34 findings)",    │
│     "target_url": "https://cryptoscan.local/scans/{id}"     │
│   }                                                          │
│                                                              │
│ IF compliance_status == "FAIL":                             │
│   Body: {                                                    │
│     "state": "failure",                                      │
│     "context": "cryptoscan/compliance",                     │
│     "description": "6 non-compliant crypto findings",       │
│     "target_url": "https://cryptoscan.local/scans/{id}"     │
│   }                                                          │
│                                                              │
│ RESULT: GitHub PR/commit shows check status                 │
│   ✅ cryptoscan/compliance — All crypto compliant            │
│   or                                                         │
│   ❌ cryptoscan/compliance — 6 non-compliant findings        │
│                                                              │
│ Developer clicks check → redirected to CryptoScan dashboard │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 11 Deliverable

**GitHub integration that:**
1. Receives GitHub push webhooks
2. Verifies HMAC signature (security)
3. Queues scan jobs
4. Worker processes scan jobs asynchronously
5. Full pipeline runs: scan → normalize → policy → drift → alert
6. Scan results visible in dashboard
7. (Bonus) Posts commit status back to GitHub

**Testing:**
- Configure repo in `repo_configurations`
- Push code to GitHub main branch
- Webhook fires → CryptoScan receives
- Scan job queued → worker picks up
- Scan runs → findings in DB
- Dashboard shows new scan
- If non-compliant → drift alert sent
- GitHub commit shows status check

---

## WEEK 12: MANUAL SCAN TRIGGER + DOCUMENTATION

### 🎯 Goal
Allow manual scan execution + basic user documentation

### 📐 Manual Scan Interface

```
┌─────────────────────────────────────────────────────────────┐
│              MANUAL SCAN TRIGGER                            │
│              (UI + API for on-demand scans)                 │
└─────────────────────────────────────────────────────────────┘

WEB UI PAGE:

┌──────────────────────────────────────────────────────────────┐
│ PAGE: NEW SCAN                                               │
│                                                              │
│ URL: /scans/new                                              │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  START NEW SCAN                                        │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Scan Type:                                            │  │
│ │  ◉ Git Repository                                      │  │
│ │  ○ Local Directory (for testing)                       │  │
│ │                                                        │  │
│ │  Repository URL: [________________________]            │  │
│ │  Example: https://github.com/org/payment-api           │  │
│ │                                                        │  │
│ │  Branch: [main____________] (optional - defaults to main)│ │
│ │                                                        │  │
│ │  Commit: [________________] (optional - defaults to HEAD)│ │
│ │                                                        │  │
│ │  Triggered By: [john.security]  (auto-filled from login)│ │
│ │                                                        │  │
│ │  [Start Scan]                                          │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ On click "Start Scan":                                       │
│   → POST /api/scans/trigger                                 │
│   → Creates scan_job with status QUEUED                     │
│   → Returns job_id                                           │
│   → Redirects to /jobs/{job_id} (job status page)          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PAGE: JOB STATUS                                             │
│                                                              │
│ URL: /jobs/{job_id}                                          │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  SCAN JOB: abc-123-def                                 │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Status: ⏳ RUNNING                                    │  │
│ │  (Auto-refreshes every 5 seconds via JS)               │  │
│ │                                                        │  │
│ │  Target:      https://github.com/org/payment-api       │  │
│ │  Branch:      main                                     │  │
│ │  Commit:      a1b2c3d4                                 │  │
│ │  Triggered:   2024-01-15 10:00:00                      │  │
│ │  Triggered By: john.security                           │  │
│ │                                                        │  │
│ │  Progress:                                             │  │
│ │  ✅ Cloning repository                                 │  │
│ │  ✅ Running static scanner                             │  │
│ │  ⏳ Normalizing findings (284 findings)                │  │
│ │  ⏸️  Policy evaluation (pending)                       │  │
│ │  ⏸️  Drift detection (pending)                         │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ When status = COMPLETED:                                     │
│   → Show summary                                             │
│   → Link to scan results: /scans/{scan_id}                  │
│   → Button: [View Findings]                                 │
│                                                              │
│ When status = FAILED:                                        │
│   → Show error message                                       │
│   → Show logs (if available)                                │
│   → Button: [Retry Scan]                                    │
└──────────────────────────────────────────────────────────────┘

API ENDPOINTS:

POST /api/scans/trigger
  Body: {
    "scan_type": "GIT_REPOSITORY",
    "repo_url": "https://github.com/org/payment-api",
    "branch": "main",
    "commit": null,  // HEAD of branch
    "triggered_by": "john.security"
  }
  Response: {
    "job_id": "uuid",
    "status": "QUEUED",
    "created_at": "2024-01-15T10:00:00Z"
  }

GET /api/jobs/{job_id}
  Response: {
    "job_id": "uuid",
    "status": "RUNNING",
    "progress": {
      "current_stage": "normalizing",
      "stages_complete": 2,
      "total_stages": 5,
      "findings_count": 284
    },
    "scan_id": null,  // will be populated when complete
    "error_message": null
  }

GET /api/jobs/{job_id}/logs
  Response: {
    "logs": [
      "2024-01-15 10:00:01 - Cloning repository...",
      "2024-01-15 10:00:15 - Clone complete",
      "2024-01-15 10:00:16 - Starting static scanner...",
      ...
    ]
  }
```

### 📚 Documentation (Week 12)

```
┌─────────────────────────────────────────────────────────────┐
│              USER DOCUMENTATION v1.0                        │
│              (Delivered as Markdown files in Git repo)      │
└─────────────────────────────────────────────────────────────┘

DOCUMENTATION STRUCTURE:

docs/
├── README.md                    (Overview & quick start)
├── installation.md              (How to deploy CryptoScan)
├── user-guide/
│   ├── dashboard-overview.md    (Dashboard navigation)
│   ├── viewing-scans.md         (How to view scan results)
│   ├── understanding-findings.md(Interpreting crypto findings)
│   ├── drift-detection.md       (Understanding drift events)
│   └── manual-scans.md          (How to trigger manual scans)
├── admin-guide/
│   ├── github-integration.md    (Setup GitHub webhooks)
│   ├── baseline-approval.md     (Approving baseline scans)
│   ├── policy-rules.md          (Understanding policy rules)
│   └── repo-configuration.md    (Configuring repos to scan)
├── architecture/
│   ├── system-overview.md       (High-level architecture)
│   ├── evidence-chain.md        (Evidence integrity design)
│   ├── scanner-design.md        (How static scanner works)
│   └── database-schema.md       (DB schema documentation)
└── api-reference/
    └── rest-api.md              (API endpoint documentation)

SAMPLE: docs/user-guide/understanding-findings.md

# Understanding Crypto Findings

## What is a Crypto Finding?

A **crypto finding** is a detected use of cryptography in your code.
Each finding represents a specific cryptographic API call, such as:
- Encrypting data (AES, DES, etc.)
- Hashing data (SHA-256, MD5, etc.)
- Signing data (RSA, ECDSA, etc.)
- Generating keys

## Finding Detail Page

When you click a finding, you see:

### 1. Crypto Details
- **Algorithm**: The cryptographic algorithm (e.g., AES, RSA, DES)
- **Key Size**: The key length in bits (e.g., 256)
- **Mode**: The mode of operation (e.g., GCM, CBC)
- **Purpose**: What the crypto is used for (encryption, hashing, etc.)

### 2. Location
- **File**: The source code file containing the crypto call
- **Line Number**: The exact line in the file
- **Method**: The function/method containing the crypto call
- **Class**: The class containing the crypto call

### 3. Code Snippet
A snippet of code showing the crypto call in context (5 lines before and after).

### 4. Compliance Status
- **PASS**: The crypto usage is compliant with all applicable policies
- **FAIL**: One or more policy rules failed
- **WARN**: Advisory warnings (not hard failures)

Each failed rule shows:
- Rule ID and name
- Severity (CRITICAL, HIGH, etc.)
- Remediation guidance

### 5. Evidence Integrity
- **Content Hash**: SHA-256 hash of the finding (tamper detection)
- **Chain Hash**: Blockchain-style chain linking (immutability)
- **Verified**: Whether integrity checks passed

## Compliance Rules

CryptoScan evaluates findings against policy rules:

| Rule | Description | Example Failure |
|------|-------------|----------------|
| BASELINE-001 | Forbidden Algorithms | DES, 3DES, RC4, MD5, SHA-1 |
| BASELINE-002 | Minimum RSA Key Size | RSA-1024 (must be ≥2048) |
| BASELINE-003 | Approved AES Modes | AES-ECB (forbidden) |
| BASELINE-004 | Hardcoded Keys | Cryptographic keys in source code |

## What To Do With a Failed Finding

1. **Review**: Understand why it failed
2. **Remediate**: Fix the code (see remediation guidance)
3. **Rescan**: Push code → automatic rescan
4. **Verify**: Check that finding is now PASS

---
```

### ✅ Week 12 Deliverable

**Manual scan system + documentation:**
1. Web UI page to trigger manual scans
2. Job status page with real-time progress
3. API endpoints for triggering and monitoring scans
4. Complete user documentation (Markdown)
5. Admin documentation for setup and configuration
6. Architecture documentation

**Testing:**
- Navigate to /scans/new
- Enter repo URL → click Start Scan
- Redirected to job status page → see real-time progress
- Scan completes → link to scan results
- API: `POST /api/scans/trigger` → returns job_id
- API: `GET /api/jobs/{job_id}` → returns status

---

# 🎯 MONTH 1-3 COMPLETE END-TO-END FLOW SUMMARY

```
┌──────────────────────────────────────────────────────────────┐
│         PART 1 COMPLETE: MONTHS 1-3 DELIVERABLE              │
│         Fully Functional Core Platform                       │
└──────────────────────────────────────────────────────────────┘

DEVELOPER PUSHES CODE:
  ↓
GITHUB FIRES WEBHOOK:
  ↓
CRYPTOSCAN RECEIVES WEBHOOK:
  → Verifies HMAC signature ✅
  → Queues scan job
  ↓
SCAN WORKER PICKS UP JOB:
  → Clones repo at commit
  → Runs static Java scanner
  → Finds: DES, AES-256-GCM, SHA-256, RSA-2048, MD5 (34 findings)
  ↓
EVIDENCE PIPELINE:
  → Creates EvidenceRecords
  → Computes SHA-256 content hashes
  → Creates blockchain-style chain hashes
  → Stores in PostgreSQL with integrity proofs
  ↓
NORMALIZATION:
  → "DES" → {algorithm:"DES", keysize:56, nist:"DEPRECATED"}
  → "AES/GCM/NoPadding" → {algorithm:"AES", mode:"GCM", nist:"APPROVED"}
  → Stores normalized_crypto in DB
  ↓
POLICY ENGINE:
  → Evaluates 4 rules per finding
  → DES → FAIL (BASELINE-001: Forbidden Algorithm)
  → MD5 → FAIL (BASELINE-001: Forbidden Algorithm)
  → AES-GCM → PASS
  → SHA-256 → PASS
  → Overall: 6 failures, 28 passes
  ↓
DRIFT DETECTION:
  → Loads baseline (approved 2024-01-01)
  → Compares current scan to baseline
  → Detects: NEW_CRYPTO (DES at Payment.java:247)
  → Severity: CRITICAL (non-compliant)
  → Creates drift_event record
  ↓
ALERT:
  → Sends email to security team
  → Subject: "CRITICAL crypto drift in payment-api"
  → Body: DES introduced, non-compliant
  → (Bonus) Posts ❌ status to GitHub commit
  ↓
SECURITY TEAM:
  → Receives email alert
  → Logs into CryptoScan dashboard
  → Sees drift event with full details
  → Clicks finding → sees code snippet
  → Sees remediation: "Replace DES with AES-256-GCM"
  ↓
DEVELOPER:
  → Sees GitHub PR check failure
  → Clicks link → redirected to CryptoScan
  → Sees DES failure
  → Fixes code: DES → AES-256-GCM
  → Pushes fix
  ↓
CRYPTOSCAN (AUTO):
  → Receives webhook
  → Rescans automatically
  → DES no longer present
  → All findings PASS
  → Drift resolved
  → Posts ✅ status to GitHub
  ↓
EVERYONE HAPPY:
  → Code is compliant
  → Drift detected and resolved in <1 hour
  → Full audit trail preserved in immutable evidence chain
  → Business can prove compliance

TOTAL TIME: Commit → Detection → Fix → Verification = <1 hour
```

# CryptoScan Platform — Part 1: Production-Level Folder & File Structure

```
cryptoscan-platform/
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                          # Main CI pipeline
│   │   ├── scanner-tests.yml               # Scanner unit/integration tests
│   │   ├── db-migration.yml                # Auto-run migrations on merge
│   │   └── docker-build.yml                # Build & push Docker images
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── CODEOWNERS
│   └── dependabot.yml                      # Dependency update automation
│
├── .docker/
│   ├── scanner/
│   │   └── Dockerfile                      # Static scanner container
│   ├── api/
│   │   └── Dockerfile                      # REST API container
│   ├── worker/
│   │   └── Dockerfile                      # Scan job worker container
│   ├── dashboard/
│   │   └── Dockerfile                      # Web dashboard container
│   └── nginx/
│       ├── Dockerfile
│       └── nginx.conf                      # Reverse proxy config
│
├── docker-compose.yml                      # Local dev: all services
├── docker-compose.prod.yml                 # Production overrides
├── docker-compose.test.yml                 # Test environment
│
├── .env.example                            # Environment variable template
├── .env.test                               # Test environment vars (no secrets)
├── .gitignore
├── .editorconfig
├── Makefile                                # Developer shortcuts (make scan, make test, etc.)
├── README.md
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   SERVICE 1: SCANNER ENGINE
│   (Python — static analysis of Java source code)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── services/
│   │
│   ├── scanner/
│   │   │
│   │   ├── pyproject.toml                  # Python project config (PEP 517)
│   │   ├── poetry.lock                     # Locked dependencies
│   │   ├── setup.cfg                       # Package metadata
│   │   ├── Makefile                        # Service-level shortcuts
│   │   │
│   │   ├── scanner/                        # Main Python package
│   │   │   │
│   │   │   ├── __init__.py
│   │   │   ├── main.py                     # CLI entrypoint (argparse)
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scanner.py              # Orchestrates full scan pipeline
│   │   │   │   ├── file_discovery.py       # Walk dirs, filter *.java files
│   │   │   │   └── scan_context.py         # ScanContext dataclass (metadata for run)
│   │   │   │
│   │   │   ├── parsers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── java_parser.py          # Calls Eclipse JDT via subprocess/jpype
│   │   │   │   ├── ast_visitor.py          # Visits AST nodes, calls detectors
│   │   │   │   └── parse_error_handler.py  # Graceful parse error handling + logging
│   │   │   │
│   │   │   ├── detectors/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base_detector.py        # Abstract BaseDetector class
│   │   │   │   ├── cipher_detector.py      # Pattern 1: Cipher.getInstance()
│   │   │   │   ├── message_digest_detector.py   # Pattern 2: MessageDigest.getInstance()
│   │   │   │   ├── key_generator_detector.py    # Pattern 3: KeyGenerator.getInstance()
│   │   │   │   ├── signature_detector.py        # Pattern 4: Signature.getInstance()
│   │   │   │   ├── hardcoded_key_detector.py    # Pattern 5: SecretKeySpec hardcoded
│   │   │   │   └── detector_registry.py         # Registers all detectors, loads dynamically
│   │   │   │
│   │   │   ├── extractors/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── algorithm_extractor.py       # Parse "AES/GCM/NoPadding" → components
│   │   │   │   ├── context_extractor.py         # Extract file, line, method, class name
│   │   │   │   ├── snippet_extractor.py         # Extract ±5 lines code snippet
│   │   │   │   └── confidence_calculator.py     # HIGH/MEDIUM/LOW confidence logic
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── raw_finding.py               # RawFinding dataclass (Pydantic model)
│   │   │   │   ├── scan_result.py               # ScanResult dataclass
│   │   │   │   ├── git_context.py               # GitContext dataclass
│   │   │   │   └── enums.py                     # ApiType, Purpose, Confidence enums
│   │   │   │
│   │   │   ├── git/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── git_client.py                # Clone repo, get commit metadata
│   │   │   │   └── git_context_extractor.py     # Extract commit hash, author, branch
│   │   │   │
│   │   │   ├── output/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── json_writer.py               # Write scan-results-{ts}.json
│   │   │   │   ├── json_schema.py               # JSON schema validation (jsonschema)
│   │   │   │   └── schema/
│   │   │   │       └── scan_result_schema.json  # JSON Schema v7 for output validation
│   │   │   │
│   │   │   └── config/
│   │   │       ├── __init__.py
│   │   │       ├── scanner_config.py            # ScannerConfig (exclude dirs, etc.)
│   │   │       └── defaults.py                  # Default exclusion patterns
│   │   │
│   │   ├── jdt/                                 # Eclipse JDT wrapper (Java-side)
│   │   │   ├── CryptoASTParser.java             # Main Java AST parser
│   │   │   ├── ASTVisitorImpl.java              # JDT ASTVisitor implementation
│   │   │   ├── FindingSerializer.java           # Serialize findings to JSON
│   │   │   ├── pom.xml                          # Maven build for JDT component
│   │   │   └── build/                           # Compiled JAR output (gitignored)
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py                      # pytest fixtures
│   │       │
│   │       ├── unit/
│   │       │   ├── detectors/
│   │       │   │   ├── test_cipher_detector.py
│   │       │   │   ├── test_message_digest_detector.py
│   │       │   │   ├── test_key_generator_detector.py
│   │       │   │   ├── test_signature_detector.py
│   │       │   │   └── test_hardcoded_key_detector.py
│   │       │   ├── extractors/
│   │       │   │   ├── test_algorithm_extractor.py
│   │       │   │   ├── test_context_extractor.py
│   │       │   │   └── test_confidence_calculator.py
│   │       │   └── models/
│   │       │       └── test_raw_finding.py
│   │       │
│   │       ├── integration/
│   │       │   ├── test_full_scan_pipeline.py   # Scan test repo → verify findings
│   │       │   ├── test_git_clone_scan.py        # Clone real repo → scan
│   │       │   └── test_output_validation.py     # JSON output matches schema
│   │       │
│   │       └── fixtures/
│   │           ├── java_samples/                # Known Java files for testing
│   │           │   ├── CipherSamples.java       # Cipher.getInstance() examples
│   │           │   ├── MessageDigestSamples.java
│   │           │   ├── KeyGeneratorSamples.java
│   │           │   ├── SignatureSamples.java
│   │           │   ├── HardcodedKeySamples.java
│   │           │   ├── CompliantSamples.java     # Should all PASS
│   │           │   ├── ParseErrorSample.java     # Intentionally broken Java
│   │           │   └── UnknownAlgoSamples.java  # Unknown/custom algorithms
│   │           └── expected_outputs/
│   │               ├── cipher_expected.json
│   │               └── hardcoded_key_expected.json
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 2: EVIDENCE ENGINE
│   │   (Python — hashing, chain, manifest)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── evidence/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── evidence/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── pipeline.py                  # Orchestrates evidence creation pipeline
│   │   │   │   └── session.py                   # EvidenceSession (groups findings per scan)
│   │   │   │
│   │   │   ├── hashing/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── canonical_serializer.py      # Sort keys, remove metadata, UTF-8
│   │   │   │   ├── content_hasher.py            # SHA-256 content hash per finding
│   │   │   │   └── chain_hasher.py              # Blockchain-style chain hash linking
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── evidence_record.py           # EvidenceRecord Pydantic model
│   │   │   │   ├── scan_manifest.py             # ScanManifest Pydantic model
│   │   │   │   └── integrity_proof.py           # IntegrityProof dataclass
│   │   │   │
│   │   │   ├── verification/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── verifier.py                  # Main verification logic
│   │   │   │   ├── chain_verifier.py            # Verify chain hash linkage
│   │   │   │   ├── content_verifier.py          # Recompute & compare content hashes
│   │   │   │   └── manifest_verifier.py         # Verify manifest hash
│   │   │   │
│   │   │   ├── storage/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── file_writer.py               # Write evidence-records-{id}.json
│   │   │   │   └── manifest_writer.py           # Write manifest-{id}.json
│   │   │   │
│   │   │   └── scripts/
│   │   │       └── verification_script_generator.py  # Generate standalone verify.sh
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_canonical_serializer.py
│   │       │   ├── test_content_hasher.py
│   │       │   ├── test_chain_hasher.py
│   │       │   └── test_verifier.py
│   │       └── integration/
│   │           ├── test_full_evidence_pipeline.py
│   │           ├── test_tamper_detection.py      # Modify finding → verify FAIL
│   │           ├── test_deletion_detection.py    # Delete finding → verify FAIL
│   │           └── test_reorder_detection.py     # Reorder → manifest FAIL
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 3: DATABASE + LOADER
│   │   (Python — DB schema, migrations, loader)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── database/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── migrations/                          # Alembic DB migrations
│   │   │   ├── env.py                           # Alembic environment
│   │   │   ├── script.py.mako                   # Migration template
│   │   │   ├── alembic.ini
│   │   │   └── versions/
│   │   │       ├── 0001_create_scans_table.py
│   │   │       ├── 0002_create_evidence_records_table.py
│   │   │       ├── 0003_create_verification_log_table.py
│   │   │       ├── 0004_add_normalized_crypto_column.py
│   │   │       ├── 0005_add_policy_evaluation_column.py
│   │   │       ├── 0006_create_baselines_table.py
│   │   │       ├── 0007_create_drift_events_table.py
│   │   │       ├── 0008_create_scan_jobs_table.py
│   │   │       └── 0009_create_repo_configurations_table.py
│   │   │
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── connection/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py                    # SQLAlchemy engine factory
│   │   │   │   ├── session.py                   # Session factory, context manager
│   │   │   │   └── health_check.py              # DB connection health probe
│   │   │   │
│   │   │   ├── models/                          # SQLAlchemy ORM models
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base.py                      # DeclarativeBase
│   │   │   │   ├── scan.py                      # Scan ORM model
│   │   │   │   ├── evidence_record.py           # EvidenceRecord ORM model
│   │   │   │   ├── verification_log.py          # VerificationLog ORM model
│   │   │   │   ├── baseline.py                  # Baseline ORM model
│   │   │   │   ├── drift_event.py               # DriftEvent ORM model
│   │   │   │   ├── scan_job.py                  # ScanJob ORM model
│   │   │   │   └── repo_configuration.py        # RepoConfiguration ORM model
│   │   │   │
│   │   │   ├── repositories/                    # Data access layer (Repository pattern)
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base_repository.py           # Abstract BaseRepository
│   │   │   │   ├── scan_repository.py           # CRUD for scans table
│   │   │   │   ├── evidence_repository.py       # CRUD for evidence_records
│   │   │   │   ├── verification_repository.py   # CRUD for verification_log
│   │   │   │   ├── baseline_repository.py       # CRUD for baselines
│   │   │   │   ├── drift_repository.py          # CRUD for drift_events
│   │   │   │   ├── job_repository.py            # CRUD for scan_jobs
│   │   │   │   └── repo_config_repository.py    # CRUD for repo_configurations
│   │   │   │
│   │   │   └── loader/
│   │   │       ├── __init__.py
│   │   │       ├── evidence_loader.py           # Load evidence JSON → PostgreSQL
│   │   │       ├── pre_load_verifier.py         # Verify integrity before load
│   │   │       ├── bulk_inserter.py             # Bulk INSERT with transaction
│   │   │       └── post_load_verifier.py        # Verify chain in DB after load
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py                      # DB test fixtures (test DB setup/teardown)
│   │       ├── unit/
│   │       │   ├── test_scan_repository.py
│   │       │   ├── test_evidence_repository.py
│   │       │   └── test_bulk_inserter.py
│   │       └── integration/
│   │           ├── test_evidence_loader.py       # Load → query → verify counts
│   │           ├── test_transaction_safety.py    # Partial fail → full rollback
│   │           └── test_chain_in_db.py           # Chain verification from DB
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 4: NORMALIZATION ENGINE
│   │   (Python — canonical algorithm mapping)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── normalization/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── normalization/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py                    # Main normalization orchestrator
│   │   │   │   └── processor.py                 # Processes one evidence_record
│   │   │   │
│   │   │   ├── rules/                           # Rule loading & management
│   │   │   │   ├── __init__.py
│   │   │   │   ├── rule_loader.py               # Load YAML rules from disk
│   │   │   │   ├── rule_validator.py            # Validate YAML rule schema
│   │   │   │   └── rule_registry.py             # In-memory registry of loaded rules
│   │   │   │
│   │   │   ├── matchers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── exact_matcher.py             # Exact string match lookup
│   │   │   │   ├── pattern_matcher.py           # "algo/mode/padding" parsing
│   │   │   │   └── fallback_handler.py          # UNKNOWN + flag for review
│   │   │   │
│   │   │   ├── enrichers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── nist_enricher.py             # Add NIST designation
│   │   │   │   ├── iana_enricher.py             # Add IANA algorithm ID
│   │   │   │   ├── cbom_enricher.py             # Add CycloneDX CBOM fields
│   │   │   │   └── family_enricher.py           # Add algorithm family classification
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── normalization_rule.py        # NormalizationRule Pydantic model
│   │   │   │   └── normalized_crypto.py         # NormalizedCrypto output model
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py                  # Normalization config (rule paths, etc.)
│   │   │
│   │   ├── rule_definitions/                    # YAML normalization rules (version controlled)
│   │   │   ├── README.md                        # How to add/modify rules
│   │   │   ├── symmetric/
│   │   │   │   ├── aes.yaml                     # AES variants normalization
│   │   │   │   ├── des.yaml                     # DES normalization
│   │   │   │   ├── 3des.yaml                    # 3DES normalization
│   │   │   │   └── rc4.yaml                     # RC4 normalization
│   │   │   ├── asymmetric/
│   │   │   │   ├── rsa.yaml                     # RSA normalization
│   │   │   │   └── ecdsa.yaml                   # ECDSA normalization
│   │   │   ├── hashing/
│   │   │   │   ├── sha1.yaml                    # SHA-1 normalization
│   │   │   │   ├── sha2.yaml                    # SHA-256, SHA-512 normalization
│   │   │   │   └── md5.yaml                     # MD5 normalization
│   │   │   └── signature/
│   │   │       └── signature_combos.yaml        # SHA256withRSA etc.
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_exact_matcher.py
│   │       │   ├── test_pattern_matcher.py
│   │       │   ├── test_nist_enricher.py
│   │       │   └── test_rule_loader.py
│   │       └── integration/
│   │           ├── test_full_normalization.py    # 20+ algorithms → verify output
│   │           └── test_unknown_algorithm.py     # Unknown → UNKNOWN + flagged
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 5: POLICY ENGINE
│   │   (Python — deterministic rule evaluation)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── policy/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── policy/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py                    # Main policy evaluation orchestrator
│   │   │   │   └── evaluator.py                 # Evaluates one finding against rules
│   │   │   │
│   │   │   ├── rules/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── rule_loader.py               # Load YAML rules
│   │   │   │   ├── rule_validator.py            # Validate rule YAML schema
│   │   │   │   └── rule_registry.py             # Registry of active rules
│   │   │   │
│   │   │   ├── conditions/                      # Condition evaluators
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base_condition.py            # Abstract BaseCondition
│   │   │   │   ├── algorithm_in_list.py         # ALGORITHM_IN_LIST evaluator
│   │   │   │   ├── key_size_minimum.py          # KEY_SIZE_MINIMUM evaluator
│   │   │   │   ├── algorithm_mode_whitelist.py  # ALGORITHM_MODE_WHITELIST evaluator
│   │   │   │   ├── boolean_flag.py              # BOOLEAN_FLAG evaluator
│   │   │   │   └── condition_factory.py         # Creates correct condition from rule type
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── policy_rule.py               # PolicyRule Pydantic model
│   │   │   │   ├── policy_result.py             # PolicyResult per rule evaluation
│   │   │   │   └── policy_evaluation.py         # PolicyEvaluation (aggregated results)
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py
│   │   │
│   │   ├── rule_definitions/                    # YAML policy rules (version controlled)
│   │   │   ├── README.md
│   │   │   ├── baseline/
│   │   │   │   ├── BASELINE-001-forbidden-algorithms.yaml
│   │   │   │   ├── BASELINE-002-minimum-rsa-key-size.yaml
│   │   │   │   ├── BASELINE-003-approved-aes-modes.yaml
│   │   │   │   └── BASELINE-004-hardcoded-keys.yaml
│   │   │   └── _schema/
│   │   │       └── rule_schema.yaml             # JSON Schema for validating rule YAML
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── conditions/
│   │       │   │   ├── test_algorithm_in_list.py
│   │       │   │   ├── test_key_size_minimum.py
│   │       │   │   ├── test_algorithm_mode_whitelist.py
│   │       │   │   └── test_boolean_flag.py
│   │       │   └── test_evaluator.py
│   │       └── integration/
│   │           ├── test_des_fails_baseline_001.py
│   │           ├── test_rsa_1024_fails_baseline_002.py
│   │           ├── test_aes_ecb_fails_baseline_003.py
│   │           ├── test_hardcoded_key_fails_baseline_004.py
│   │           └── test_aes_256_gcm_passes_all.py
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 6: DRIFT DETECTOR
│   │   (Python — baseline comparison engine)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── drift/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── drift/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── detector.py                  # Main drift detection orchestrator
│   │   │   │   └── comparator.py                # Compare baseline vs current sets
│   │   │   │
│   │   │   ├── fingerprinting/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── fingerprinter.py             # Create fingerprint per finding
│   │   │   │   └── inventory_builder.py         # Build fingerprint set from scan
│   │   │   │
│   │   │   ├── classifiers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── drift_type_classifier.py     # NEW_CRYPTO, REMOVED_CRYPTO
│   │   │   │   └── severity_calculator.py       # CRITICAL/HIGH/MEDIUM/INFO logic
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── drift_event.py               # DriftEvent Pydantic model
│   │   │   │   └── drift_summary.py             # DriftSummary (counts per severity)
│   │   │   │
│   │   │   └── alerts/
│   │   │       ├── __init__.py
│   │   │       ├── alert_dispatcher.py          # Routes alerts to correct channel
│   │   │       ├── email_alerter.py             # SMTP email sender
│   │   │       └── alert_templates/
│   │   │           ├── critical_drift.html      # HTML email template (CRITICAL)
│   │   │           ├── critical_drift.txt       # Plain text fallback
│   │   │           ├── high_drift.html
│   │   │           └── high_drift.txt
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_fingerprinter.py
│   │       │   ├── test_comparator.py
│   │       │   ├── test_severity_calculator.py
│   │       │   └── test_email_alerter.py
│   │       └── integration/
│   │           ├── test_new_crypto_detection.py  # Add DES → detect NEW_CRYPTO
│   │           ├── test_removed_crypto_detection.py
│   │           └── test_critical_alert_fired.py  # CRITICAL → email sent
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 7: REST API
│   │   (Python FastAPI — serves dashboard + webhooks)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── api/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── main.py                          # FastAPI app factory
│   │   │   ├── dependencies.py                  # DI: DB session, auth, etc.
│   │   │   │
│   │   │   ├── routers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scans.py                     # GET /api/scans, GET /api/scans/{id}
│   │   │   │   ├── findings.py                  # GET /api/findings/{evidence_id}
│   │   │   │   ├── drift.py                     # GET /api/drift, POST /api/drift/{id}/acknowledge
│   │   │   │   ├── jobs.py                      # GET /api/jobs/{id}, GET /api/jobs/{id}/logs
│   │   │   │   ├── stats.py                     # GET /api/stats/summary
│   │   │   │   ├── webhooks.py                  # POST /webhooks/github (inbound)
│   │   │   │   ├── baselines.py                 # GET/POST /api/baselines
│   │   │   │   └── trigger.py                   # POST /api/scans/trigger
│   │   │   │
│   │   │   ├── schemas/                         # Pydantic request/response schemas
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scan_schemas.py
│   │   │   │   ├── finding_schemas.py
│   │   │   │   ├── drift_schemas.py
│   │   │   │   ├── job_schemas.py
│   │   │   │   ├── stats_schemas.py
│   │   │   │   └── webhook_schemas.py
│   │   │   │
│   │   │   ├── middleware/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth_middleware.py           # Session auth check
│   │   │   │   ├── request_id_middleware.py     # Inject X-Request-ID header
│   │   │   │   └── logging_middleware.py        # Request/response logging
│   │   │   │
│   │   │   ├── security/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── hmac_verifier.py             # Verify GitHub webhook HMAC signature
│   │   │   │   ├── auth.py                      # Username/password auth logic
│   │   │   │   └── session_manager.py           # Session creation/validation
│   │   │   │
│   │   │   ├── github/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── webhook_handler.py           # Parse + validate GitHub webhook
│   │   │   │   ├── payload_parser.py            # Extract repo URL, commit, branch
│   │   │   │   └── status_poster.py             # POST commit status back to GitHub
│   │   │   │
│   │   │   └── config/
│   │   │       ├── __init__.py
│   │   │       └── settings.py                  # API config (Pydantic Settings)
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py                      # TestClient fixtures
│   │       ├── unit/
│   │       │   ├── test_hmac_verifier.py
│   │       │   └── test_payload_parser.py
│   │       └── integration/
│   │           ├── test_scans_endpoints.py
│   │           ├── test_findings_endpoints.py
│   │           ├── test_drift_endpoints.py
│   │           ├── test_webhook_endpoint.py     # Fake webhook → job queued
│   │           ├── test_trigger_endpoint.py
│   │           └── test_stats_endpoint.py
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   SERVICE 8: SCAN WORKER
│   │   (Python — background job processor)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── worker/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── worker/
│   │   │   ├── __init__.py
│   │   │   ├── main.py                          # Worker process entrypoint
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── job_consumer.py              # Consume from Redis/RabbitMQ queue
│   │   │   │   ├── job_executor.py              # Execute full scan pipeline per job
│   │   │   │   └── job_logger.py                # Per-job structured logging
│   │   │   │
│   │   │   ├── pipeline/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── pipeline_runner.py           # Orchestrate all pipeline stages
│   │   │   │   ├── stage_clone.py               # Stage 1: Clone repo
│   │   │   │   ├── stage_scan.py                # Stage 2: Run scanner
│   │   │   │   ├── stage_evidence.py            # Stage 3: Evidence pipeline
│   │   │   │   ├── stage_load.py                # Stage 4: Load to DB
│   │   │   │   ├── stage_normalize.py           # Stage 5: Normalization
│   │   │   │   ├── stage_policy.py              # Stage 6: Policy evaluation
│   │   │   │   ├── stage_drift.py               # Stage 7: Drift detection
│   │   │   │   └── stage_alert.py               # Stage 8: Send alerts
│   │   │   │
│   │   │   ├── workspace/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── workspace_manager.py         # Create/cleanup temp dirs per job
│   │   │   │   └── repo_cloner.py               # git clone with depth=1, cleanup
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py                  # Worker config (queue URL, concurrency)
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_pipeline_runner.py
│   │       │   └── test_workspace_manager.py
│   │       └── integration/
│   │           ├── test_full_pipeline_job.py    # Full job → all stages → DB verified
│   │           └── test_failed_stage_handling.py # Stage fails → job marked FAILED
│   │
│   │
│   └── ── ── ── ── ── ── ── ── ── ── ──
│       SERVICE 9: WEB DASHBOARD
│       (React — frontend SPA)
│   ── ── ── ── ── ── ── ── ── ── ── ──
│
│   └── dashboard/
│       │
│       ├── package.json
│       ├── package-lock.json
│       ├── tsconfig.json                        # TypeScript config
│       ├── vite.config.ts                       # Vite bundler config
│       ├── tailwind.config.ts                   # Tailwind CSS config
│       ├── postcss.config.js
│       ├── .eslintrc.json
│       ├── .prettierrc
│       │
│       ├── public/
│       │   ├── favicon.ico
│       │   └── logo.svg
│       │
│       └── src/
│           ├── main.tsx                         # React app entrypoint
│           ├── App.tsx                          # Root component + router
│           │
│           ├── pages/
│           │   ├── DashboardHome.tsx            # PAGE 1: Summary stats
│           │   ├── ScanList.tsx                 # List all scans
│           │   ├── ScanDetail.tsx               # PAGE 2: Scan detail + findings
│           │   ├── FindingDetail.tsx            # PAGE 3: Finding detail + snippet
│           │   ├── DriftEvents.tsx              # PAGE 4: Drift events list
│           │   ├── NewScan.tsx                  # Trigger manual scan
│           │   ├── JobStatus.tsx                # Real-time job progress
│           │   └── Login.tsx                    # Login page
│           │
│           ├── components/
│           │   ├── layout/
│           │   │   ├── AppShell.tsx             # Sidebar + header wrapper
│           │   │   ├── Sidebar.tsx              # Navigation sidebar
│           │   │   ├── Header.tsx               # Top header bar
│           │   │   └── PageHeader.tsx           # Per-page header + breadcrumbs
│           │   │
│           │   ├── scans/
│           │   │   ├── ScanTable.tsx            # Paginated scans table
│           │   │   ├── ScanStatusBadge.tsx      # COMPLETED/FAILED badge
│           │   │   └── ScanMetaCard.tsx         # Scan metadata display card
│           │   │
│           │   ├── findings/
│           │   │   ├── FindingsTable.tsx         # Paginated findings table
│           │   │   ├── ComplianceStatusBadge.tsx # PASS/FAIL/WARN badge
│           │   │   ├── CodeSnippet.tsx           # Syntax-highlighted code display
│           │   │   ├── CryptoDetails.tsx         # Algorithm, mode, key size display
│           │   │   ├── PolicyResults.tsx         # Failed/passed rules list
│           │   │   └── EvidenceIntegrity.tsx     # Hash display + verified badge
│           │   │
│           │   ├── drift/
│           │   │   ├── DriftEventTable.tsx       # Drift events table
│           │   │   ├── DriftSeverityBadge.tsx    # CRITICAL/HIGH/MEDIUM/INFO badge
│           │   │   ├── DriftDetail.tsx           # Expanded drift event detail
│           │   │   └── DriftFilters.tsx          # Severity + status filter bar
│           │   │
│           │   ├── stats/
│           │   │   ├── SummaryCards.tsx          # Total scans/findings/compliance cards
│           │   │   ├── AlgorithmBreakdown.tsx    # Algorithm compliance table
│           │   │   └── DriftSummaryCard.tsx      # Open drift events by severity
│           │   │
│           │   └── shared/
│           │       ├── LoadingSpinner.tsx
│           │       ├── ErrorBoundary.tsx
│           │       ├── EmptyState.tsx
│           │       ├── Pagination.tsx
│           │       ├── ConfirmModal.tsx
│           │       └── ExportButton.tsx          # JSON/CSV export
│           │
│           ├── hooks/
│           │   ├── useScans.ts                   # Fetch scans data
│           │   ├── useFindings.ts                # Fetch findings data
│           │   ├── useDrift.ts                   # Fetch drift events
│           │   ├── useJobStatus.ts               # Poll job status (5s interval)
│           │   ├── useStats.ts                   # Fetch summary stats
│           │   └── useAuth.ts                    # Auth state management
│           │
│           ├── api/
│           │   ├── client.ts                     # Axios instance (base URL, auth headers)
│           │   ├── scans.api.ts                  # API calls for scans endpoints
│           │   ├── findings.api.ts               # API calls for findings endpoints
│           │   ├── drift.api.ts                  # API calls for drift endpoints
│           │   ├── jobs.api.ts                   # API calls for job endpoints
│           │   ├── stats.api.ts                  # API calls for stats endpoint
│           │   └── auth.api.ts                   # Login/logout API calls
│           │
│           ├── types/
│           │   ├── scan.types.ts                 # TypeScript interfaces for scans
│           │   ├── finding.types.ts              # TypeScript interfaces for findings
│           │   ├── drift.types.ts                # TypeScript interfaces for drift
│           │   ├── job.types.ts                  # TypeScript interfaces for jobs
│           │   └── stats.types.ts               # TypeScript interfaces for stats
│           │
│           ├── store/
│           │   ├── index.ts                      # Zustand store root
│           │   ├── authStore.ts                  # Auth state
│           │   └── uiStore.ts                    # UI state (sidebar open, filters)
│           │
│           ├── utils/
│           │   ├── formatters.ts                 # Date, hash, algorithm formatters
│           │   ├── severity.ts                   # Severity → color/icon mapping
│           │   └── compliance.ts                 # Compliance status helpers
│           │
│           └── tests/
│               ├── setup.ts                      # vitest setup
│               ├── components/
│               │   ├── FindingsTable.test.tsx
│               │   ├── CodeSnippet.test.tsx
│               │   └── DriftEventTable.test.tsx
│               └── hooks/
│                   └── useJobStatus.test.ts
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   SHARED LIBRARIES
│   (Shared Python code across services)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── shared/
│   │
│   ├── shared_models/                       # Shared Pydantic models (pip installable)
│   │   ├── pyproject.toml
│   │   ├── shared_models/
│   │   │   ├── __init__.py
│   │   │   ├── finding.py                   # RawFinding shared model
│   │   │   ├── evidence.py                  # EvidenceRecord shared model
│   │   │   └── enums.py                     # Shared enums (Algorithm, Confidence, etc.)
│   │   └── tests/
│   │       └── test_shared_models.py
│   │
│   ├── shared_config/                       # Shared config utilities
│   │   ├── pyproject.toml
│   │   ├── shared_config/
│   │   │   ├── __init__.py
│   │   │   ├── base_settings.py             # Base Pydantic Settings class
│   │   │   └── env_loader.py                # .env file loading
│   │   └── tests/
│   │       └── test_env_loader.py
│   │
│   └── shared_logging/                      # Structured logging setup
│       ├── pyproject.toml
│       ├── shared_logging/
│       │   ├── __init__.py
│       │   ├── logger_factory.py            # Create structured JSON logger
│       │   └── context.py                   # Request ID, scan ID log context
│       └── tests/
│           └── test_logger_factory.py
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   INFRASTRUCTURE
│   (PostgreSQL, Redis, deployment config)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── infra/
│   │
│   ├── postgres/
│   │   ├── init/
│   │   │   ├── 01_create_databases.sql      # Create cryptoscan DB + test DB
│   │   │   └── 02_create_extensions.sql     # Enable: uuid-ossp, pgcrypto
│   │   ├── postgres.conf                    # PostgreSQL config (tuning params)
│   │   └── pg_hba.conf                      # Auth config
│   │
│   ├── redis/
│   │   └── redis.conf                       # Redis config (persistence, maxmemory)
│   │
│   ├── nginx/
│   │   ├── nginx.conf                       # Main nginx config
│   │   └── sites/
│   │       └── cryptoscan.conf              # CryptoScan site config
│   │
│   └── monitoring/
│       ├── prometheus/
│       │   └── prometheus.yml               # Metrics scrape config
│       └── grafana/
│           └── dashboards/
│               └── cryptoscan_overview.json # Grafana dashboard JSON
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   SCRIPTS
│   (Operational scripts)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── scripts/
│   ├── dev_setup.sh                         # Bootstrap local dev environment
│   ├── run_migrations.sh                    # Run Alembic migrations
│   ├── seed_test_data.sh                    # Load test data into dev DB
│   ├── approve_baseline.py                  # CLI: approve scan as baseline
│   ├── verify_evidence.py                   # CLI: standalone evidence verifier
│   ├── trigger_scan.py                      # CLI: trigger manual scan
│   └── export_findings.py                   # CLI: export findings to CSV/JSON
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   DOCUMENTATION
│   (All docs in Markdown)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
└── docs/
    ├── README.md                            # Documentation index
    ├── user-guide/
    │   ├── dashboard-overview.md
    │   ├── viewing-scans.md
    │   ├── understanding-findings.md
    │   ├── drift-detection.md
    │   └── manual-scans.md
    ├── admin-guide/
    │   ├── installation.md
    │   ├── github-integration.md
    │   ├── baseline-approval.md
    │   ├── policy-rules.md
    │   └── repo-configuration.md
    ├── architecture/
    │   ├── system-overview.md
    │   ├── evidence-chain.md
    │   ├── scanner-design.md
    │   ├── service-map.md
    │   └── database-schema.md
    ├── api-reference/
    │   └── rest-api.md
    └── decisions/                           # Architecture Decision Records (ADRs)
        ├── ADR-001-postgresql-over-nosql.md
        ├── ADR-002-eclipse-jdt-for-parsing.md
        ├── ADR-003-sha256-for-evidence-hash.md
        └── ADR-004-python-for-services.md
```

---

## Key Design Decisions Explained

```
MONOREPO STRUCTURE — WHY:
  ├── All 9 services in one repo
  ├── Shared libraries (shared/) importable by all services
  ├── Single CI/CD pipeline
  └── Atomic commits across service boundaries

SERVICE BOUNDARY — WHY SPLIT:
  ├── scanner/      → Has Java dependency (JDT) — isolated
  ├── evidence/     → Pure crypto logic — testable in isolation
  ├── database/     → DB logic only — mockable in other services
  ├── normalization/ → Rules change frequently — deploy independently
  ├── policy/       → Rules change frequently — deploy independently
  ├── drift/        → Alert logic — isolated from scan logic
  ├── api/          → HTTP boundary — own auth, rate limiting
  ├── worker/       → Background jobs — scales independently
  └── dashboard/    → Frontend — separate deployment

EACH SERVICE HAS:
  ├── pyproject.toml   (own dependencies)
  ├── Own test suite   (unit + integration)
  ├── Own Dockerfile   (own container)
  └── Own config       (settings.py via env vars)

RULE DEFINITIONS IN VERSION CONTROL:
  ├── normalization/rule_definitions/   → YAML normalization rules
  └── policy/rule_definitions/          → YAML policy rules
      WHY: Rules are business logic
           Reviewed via Pull Request
           Full audit trail in Git history
           Rollback via git revert
```