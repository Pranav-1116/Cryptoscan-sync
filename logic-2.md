# 🚀 CRYPTOSCAN PLATFORM — PART 2 (MONTHS 4-6)
## Expansion Phase: Multi-Language Support + Binary Scanning + Advanced Policy + CBOM Export

---

## 📋 PART 2 OBJECTIVE

**Expand scanning capabilities and standardize output:**
- Add **3 more languages** (Python, JavaScript/TypeScript, C#)
- Add **binary/container scanning** (Docker images, JARs, compiled binaries)
- Implement **advanced policy engine** with real compliance standards (PCI-DSS subset, NIST)
- Generate **CBOM exports** (CycloneDX format for industry interoperability)
- Add **deduplication across scan types** (source + binary = one asset)
- Build **simple dependency tracking** (which systems use which crypto)

**NOT in scope for Part 2:**
- ❌ Network/runtime scanning (that's Part 3)
- ❌ Cloud scanning (that's Part 3)
- ❌ Full dependency graph (that's Part 3)
- ❌ AI features (deferred)
- ❌ Business context enrichment (Part 3)
- ❌ OT/ICS scanning (Part 4)

---

# 🗺️ MONTH 4: MULTI-LANGUAGE STATIC SCANNING

---

## WEEK 13-14: PYTHON STATIC SCANNER

### 🎯 Goal
Build static scanner for Python cryptography (same evidence pipeline)

### 📐 Architecture — Python Scanner

```
┌─────────────────────────────────────────────────────────────┐
│              PYTHON STATIC SCANNER v1.0                     │
│              (Plugs into existing evidence pipeline)        │
└─────────────────────────────────────────────────────────────┘

TECHNOLOGY CHOICE: Python AST (built-in ast module)

WHY:
  → Python's ast module parses Python code into AST
  → Built-in, no external dependencies
  → Handles all Python 3.x syntax
  → Similar pattern to Java scanner (AST visitor)

CRYPTO LIBRARIES TO DETECT:

1. cryptography (most common Python crypto library)
2. PyCryptodome / PyCrypto (legacy but still used)
3. hashlib (built-in hashing)
4. hmac (built-in HMAC)
5. secrets (secure random — flag if misused)

DETECTION PATTERNS:

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 1: cryptography library — Symmetric Encryption      │
│                                                              │
│ PYTHON CODE:                                                 │
│   from cryptography.hazmat.primitives.ciphers import (      │
│       Cipher, algorithms, modes                             │
│   )                                                          │
│   cipher = Cipher(                                           │
│       algorithms.AES(key),                                   │
│       modes.GCM(iv)                                          │
│   )                                                          │
│                                                              │
│ AST DETECTION:                                               │
│   → Find Import nodes: from cryptography.hazmat...          │
│   → Find Call nodes: Cipher(...)                            │
│   → Inspect arguments:                                       │
│     - algorithms.AES → algorithm = AES                       │
│     - modes.GCM → mode = GCM                                 │
│   → Extract key size from AES() if literal                  │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "AES"                                           │
│   mode: "GCM"                                                │
│   key_size: determine from len(key) if traceable           │
│   purpose: "ENCRYPTION"                                      │
│   library: "cryptography"                                    │
│   confidence: HIGH (if algorithms/modes are literals)       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 2: cryptography library — Hashing                   │
│                                                              │
│ PYTHON CODE:                                                 │
│   from cryptography.hazmat.primitives import hashes         │
│   digest = hashes.Hash(hashes.SHA256())                     │
│                                                              │
│ AST DETECTION:                                               │
│   → Find Call: hashes.Hash(...)                             │
│   → Argument: hashes.SHA256() → algorithm = SHA-256         │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "SHA-256"                                       │
│   purpose: "HASHING"                                         │
│   library: "cryptography"                                    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 3: hashlib (built-in Python hashing)                │
│                                                              │
│ PYTHON CODE:                                                 │
│   import hashlib                                             │
│   h = hashlib.sha256()                                       │
│   OR                                                         │
│   h = hashlib.new('md5')                                     │
│                                                              │
│ AST DETECTION:                                               │
│   → Find Call: hashlib.sha256() → algorithm = SHA-256       │
│   → Find Call: hashlib.new('md5') → algorithm = MD5         │
│   → Find Call: hashlib.md5() → algorithm = MD5              │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: extracted from method name or argument         │
│   purpose: "HASHING"                                         │
│   library: "hashlib"                                         │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 4: PyCryptodome (legacy library)                    │
│                                                              │
│ PYTHON CODE:                                                 │
│   from Crypto.Cipher import AES                             │
│   cipher = AES.new(key, AES.MODE_ECB)                       │
│                                                              │
│ AST DETECTION:                                               │
│   → Find Import: from Crypto.Cipher import AES              │
│   → Find Call: AES.new(...)                                 │
│   → Argument 2: AES.MODE_ECB → mode = ECB                   │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "AES"                                           │
│   mode: "ECB"                                                │
│   library: "PyCryptodome"                                    │
│   purpose: "ENCRYPTION"                                      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 5: Hardcoded Keys (Python-specific)                 │
│                                                              │
│ PYTHON CODE:                                                 │
│   key = b'1234567890abcdef'  # Bad: hardcoded key           │
│   cipher = Cipher(algorithms.AES(key), ...)                 │
│                                                              │
│ AST DETECTION:                                               │
│   → Find Assign node: key = ...                             │
│   → If RHS is Constant (bytes or str literal):             │
│     → Check if used in crypto API call                      │
│     → Flag as HARDCODED_KEY                                 │
│                                                              │
│ ENTROPY ANALYSIS (advanced):                                 │
│   → If string/bytes has high entropy (looks random):        │
│     → Likely a hardcoded secret                             │
│   → Entropy threshold: >4.5 bits/byte                       │
│                                                              │
│ EXTRACT:                                                     │
│   is_hardcoded_key: true                                     │
│   key_length: len(key) * 8 (in bits)                        │
│   severity: CRITICAL                                         │
└──────────────────────────────────────────────────────────────┘

SCANNER ARCHITECTURE:

┌──────────────────────────────────────────────────────────────┐
│ PYTHON SCANNER EXECUTION FLOW                               │
│                                                              │
│ INPUT: Python source directory or Git repo                  │
│                                                              │
│ STEP 1: FILE DISCOVERY                                      │
│   Walk directory tree                                        │
│   Filter: *.py files                                         │
│   Exclude: __pycache__, .venv, tests (configurable)         │
│                                                              │
│ STEP 2: AST PARSING (per file)                              │
│   FOR EACH .py file:                                         │
│     source_code = read_file(file_path)                      │
│     TRY:                                                     │
│       tree = ast.parse(source_code, filename=file_path)     │
│     EXCEPT SyntaxError:                                      │
│       LOG error (invalid Python syntax)                     │
│       SKIP file                                              │
│                                                              │
│ STEP 3: CRYPTO PATTERN DETECTION                            │
│   visitor = CryptoASTVisitor()                              │
│   visitor.visit(tree)                                        │
│   findings = visitor.findings                                │
│                                                              │
│   CryptoASTVisitor class (extends ast.NodeVisitor):         │
│     def visit_Import(self, node):                           │
│       # Track crypto library imports                        │
│       IF node.module in CRYPTO_MODULES:                     │
│         self.imported_crypto_modules.add(node.module)       │
│                                                              │
│     def visit_Call(self, node):                             │
│       # Detect crypto API calls                             │
│       IF is_crypto_call(node):                              │
│         finding = extract_crypto_details(node)              │
│         self.findings.append(finding)                        │
│                                                              │
│ STEP 4: CONTEXT EXTRACTION                                  │
│   FOR EACH finding:                                          │
│     file_path = relative_path                               │
│     line_number = node.lineno                                │
│     column_number = node.col_offset                         │
│     function_name = find_containing_function(node)          │
│     class_name = find_containing_class(node)                │
│     code_snippet = extract_snippet(source_code, line_number)│
│                                                              │
│ STEP 5: RAW FINDING OBJECT                                  │
│   Create RawFinding (same schema as Java scanner):          │
│   {                                                          │
│     finding_id: UUID,                                        │
│     scanner_id: "static-python-scanner-v1.0",               │
│     scanner_version: "1.0.0",                               │
│     source: {                                                │
│       type: "SOURCE_CODE",                                   │
│       language: "PYTHON",                                    │
│       file_path: "payment/crypto_utils.py",                 │
│       line_number: 42,                                       │
│       function_name: "encrypt_card_data",                   │
│       class_name: "PaymentProcessor"                        │
│     },                                                       │
│     crypto: {                                                │
│       api_type: "CIPHER_INIT",                              │
│       algorithm: "AES",                                      │
│       mode: "GCM",                                           │
│       key_size: 256,                                         │
│       purpose: "ENCRYPTION",                                 │
│       library: "cryptography"                                │
│     },                                                       │
│     metadata: {                                              │
│       confidence: "HIGH",                                    │
│       is_hardcoded_key: false                               │
│     }                                                        │
│   }                                                          │
│                                                              │
│ STEP 6: OUTPUT                                               │
│   Same JSON format as Java scanner                          │
│   Feeds into SAME evidence pipeline (Week 3 Month 1)        │
└──────────────────────────────────────────────────────────────┘
```

### 🔧 Integration with Existing Pipeline

```
┌──────────────────────────────────────────────────────────────┐
│ SCANNER REGISTRY PATTERN                                     │
│ (Allows multiple scanners to coexist)                       │
│                                                              │
│ DATABASE SCHEMA UPDATE:                                      │
│                                                              │
│ ALTER TABLE scans ADD COLUMN scanner_language VARCHAR(50);  │
│   → Values: "JAVA", "PYTHON", "JAVASCRIPT", "CSHARP", etc   │
│                                                              │
│ ALTER TABLE evidence_records ADD COLUMN source_language VARCHAR(50);│
│                                                              │
│ SCAN JOB WORKER UPDATE:                                      │
│                                                              │
│ WHEN processing scan job:                                    │
│                                                              │
│   repo_languages = detect_languages_in_repo(repo_path)      │
│     → Scan for: *.java, *.py, *.js, *.cs files              │
│     → Return: ["JAVA", "PYTHON"]                            │
│                                                              │
│   FOR EACH language IN repo_languages:                       │
│     scanner = get_scanner_for_language(language)            │
│     findings = scanner.scan(repo_path)                       │
│     load_findings_to_db(findings, language)                 │
│                                                              │
│ SCANNER REGISTRY:                                            │
│   {                                                          │
│     "JAVA": JavaStaticScanner(),                            │
│     "PYTHON": PythonStaticScanner(),                        │
│     "JAVASCRIPT": JavaScriptStaticScanner(),  # Week 15-16  │
│     "CSHARP": CSharpStaticScanner()           # Week 15-16  │
│   }                                                          │
│                                                              │
│ RESULT: Multi-language repos scanned with all applicable scanners│
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 13-14 Deliverable

**Python scanner that:**
1. Parses Python AST using built-in ast module
2. Detects 5 crypto patterns (cryptography lib, hashlib, PyCryptodome, hmac, hardcoded keys)
3. Extracts algorithm, mode, key size, purpose
4. Produces RawFindings in same schema as Java scanner
5. Integrates with existing evidence pipeline
6. Multi-language scan job worker (Java + Python)

**Testing:**
- Create test Python repo with AES-GCM, SHA-256, MD5, hardcoded key
- Run scanner → detects all 4 patterns
- Findings loaded to DB with source_language = "PYTHON"
- Normalization works (same rules apply)
- Policy engine works (forbidden MD5 detected)
- Dashboard shows Python findings alongside Java findings

---

## WEEK 15-16: JAVASCRIPT/TYPESCRIPT + C# SCANNERS

### 🎯 Goal
Add 2 more language scanners (JavaScript/TypeScript, C#)

### 📐 Architecture — JavaScript/TypeScript Scanner

```
┌─────────────────────────────────────────────────────────────┐
│         JAVASCRIPT/TYPESCRIPT STATIC SCANNER v1.0           │
└─────────────────────────────────────────────────────────────┘

TECHNOLOGY CHOICE: 
  → Babel parser (for JavaScript)
  → TypeScript Compiler API (for TypeScript)
  → OR: tree-sitter (universal parser — supports both)

RECOMMENDED: tree-sitter
  WHY: 
    → Parses both JS and TS
    → Fast, battle-tested
    → Used by GitHub, Atom
    → Language-agnostic (useful for future languages)

CRYPTO LIBRARIES TO DETECT:

1. crypto (Node.js built-in)
2. Web Crypto API (browser)
3. crypto-js (popular library)
4. bcrypt / bcryptjs
5. jsonwebtoken (JWT signing)
6. node-forge

DETECTION PATTERNS:

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 1: Node.js crypto module                            │
│                                                              │
│ JAVASCRIPT CODE:                                             │
│   const crypto = require('crypto');                         │
│   const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);│
│                                                              │
│ AST DETECTION:                                               │
│   → Find require('crypto')                                   │
│   → Find call: crypto.createCipheriv(...)                   │
│   → Argument 1: 'aes-256-gcm' → parse algorithm             │
│     → algorithm = AES                                        │
│     → key_size = 256                                         │
│     → mode = GCM                                             │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "AES"                                           │
│   key_size: 256                                              │
│   mode: "GCM"                                                │
│   purpose: "ENCRYPTION"                                      │
│   library: "crypto (Node.js built-in)"                      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 2: crypto.createHash (hashing)                      │
│                                                              │
│ JAVASCRIPT CODE:                                             │
│   const hash = crypto.createHash('sha256');                 │
│   OR                                                         │
│   const hash = crypto.createHash('md5');  // Bad!           │
│                                                              │
│ AST DETECTION:                                               │
│   → Find call: crypto.createHash(...)                       │
│   → Argument: string literal → algorithm                    │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "SHA-256" or "MD5"                             │
│   purpose: "HASHING"                                         │
│   library: "crypto"                                          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 3: jsonwebtoken (JWT signing)                       │
│                                                              │
│ JAVASCRIPT CODE:                                             │
│   const jwt = require('jsonwebtoken');                      │
│   const token = jwt.sign(payload, secret, {                │
│     algorithm: 'HS256'                                       │
│   });                                                        │
│                                                              │
│ AST DETECTION:                                               │
│   → Find require('jsonwebtoken')                            │
│   → Find call: jwt.sign(...)                                │
│   → Extract options object → algorithm field                │
│     → 'HS256' → HMAC with SHA-256                           │
│     → 'RS256' → RSA signature with SHA-256                  │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "HMAC-SHA256" or "RSA-SHA256"                  │
│   purpose: "SIGNING" (specifically JWT)                     │
│   library: "jsonwebtoken"                                    │
│   use_case: "JWT"                                            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 4: bcrypt (password hashing)                        │
│                                                              │
│ JAVASCRIPT CODE:                                             │
│   const bcrypt = require('bcrypt');                         │
│   const hash = await bcrypt.hash(password, 10);            │
│                                                              │
│ AST DETECTION:                                               │
│   → Find require('bcrypt')                                   │
│   → Find call: bcrypt.hash(...)                             │
│   → Argument 2: saltRounds (10 = work factor)               │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "bcrypt"                                        │
│   work_factor: 10                                            │
│   purpose: "PASSWORD_HASHING"                                │
│   library: "bcrypt"                                          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 5: Hardcoded secrets in JS                          │
│                                                              │
│ JAVASCRIPT CODE:                                             │
│   const secret = '1234567890abcdef';  // Bad!               │
│   const token = jwt.sign(payload, secret, {algorithm: 'HS256'});│
│                                                              │
│ AST DETECTION:                                               │
│   → Find variable declaration with string literal           │
│   → If variable name matches: secret, key, password, token  │
│   → AND variable is used in crypto call                     │
│   → Flag as HARDCODED_SECRET                                │
│                                                              │
│ ENTROPY CHECK:                                               │
│   → If string entropy > 4.5 bits/char → likely secret       │
│                                                              │
│ EXTRACT:                                                     │
│   is_hardcoded_key: true                                     │
│   severity: CRITICAL                                         │
└──────────────────────────────────────────────────────────────┘

TYPESCRIPT-SPECIFIC HANDLING:

  → TypeScript is superset of JavaScript
  → Same AST patterns apply
  → Additional check: Type annotations might reveal crypto usage
  
  EXAMPLE:
    const cipher: crypto.Cipher = crypto.createCipheriv(...);
    → Type annotation confirms crypto usage
```

### 📐 Architecture — C# Scanner

```
┌─────────────────────────────────────────────────────────────┐
│              C# STATIC SCANNER v1.0                         │
└─────────────────────────────────────────────────────────────┘

TECHNOLOGY CHOICE: Roslyn (Microsoft's C# compiler platform)

WHY:
  → Official Microsoft parser
  → Full semantic analysis (not just syntax)
  → Understands .NET framework types
  → Same technology used by Visual Studio

CRYPTO LIBRARIES TO DETECT:

1. System.Security.Cryptography (.NET built-in)
2. BouncyCastle (popular third-party)
3. NSec (modern crypto library)

DETECTION PATTERNS:

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 1: System.Security.Cryptography — Symmetric         │
│                                                              │
│ C# CODE:                                                     │
│   using System.Security.Cryptography;                       │
│   var aes = Aes.Create();                                   │
│   aes.Mode = CipherMode.GCM;                                │
│   aes.KeySize = 256;                                         │
│                                                              │
│ ROSLYN DETECTION:                                            │
│   → Find using directive: System.Security.Cryptography      │
│   → Find object creation: Aes.Create()                      │
│   → Find property assignment: aes.Mode = CipherMode.GCM     │
│   → Find property assignment: aes.KeySize = 256             │
│                                                              │
│ SEMANTIC ANALYSIS (Roslyn advantage):                       │
│   → Roslyn knows Aes.Create() returns AesManaged or AesCryptoServiceProvider│
│   → Can trace aes variable through method                   │
│   → Can resolve Mode and KeySize even if set later          │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "AES"                                           │
│   mode: "GCM"                                                │
│   key_size: 256                                              │
│   purpose: "ENCRYPTION"                                      │
│   library: "System.Security.Cryptography"                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 2: DES / TripleDES (legacy, forbidden)              │
│                                                              │
│ C# CODE:                                                     │
│   var des = DES.Create();                                   │
│   OR                                                         │
│   var des = new DESCryptoServiceProvider();                 │
│                                                              │
│ ROSLYN DETECTION:                                            │
│   → Find: DES.Create() or new DESCryptoServiceProvider()    │
│   → Type system knows this is DES                           │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "DES"                                           │
│   purpose: "ENCRYPTION"                                      │
│   library: "System.Security.Cryptography"                   │
│   compliance_note: "DES is forbidden — instant FAIL"        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 3: SHA / MD5 hashing                                │
│                                                              │
│ C# CODE:                                                     │
│   using (var sha256 = SHA256.Create())                      │
│   {                                                          │
│       byte[] hash = sha256.ComputeHash(data);               │
│   }                                                          │
│                                                              │
│ ROSLYN DETECTION:                                            │
│   → Find: SHA256.Create() or MD5.Create()                   │
│   → Type: SHA256 or MD5                                     │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "SHA-256" or "MD5"                             │
│   purpose: "HASHING"                                         │
│   library: "System.Security.Cryptography"                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 4: RSA signature                                    │
│                                                              │
│ C# CODE:                                                     │
│   using (var rsa = RSA.Create(2048))                        │
│   {                                                          │
│       byte[] signature = rsa.SignData(data,                 │
│           HashAlgorithmName.SHA256,                          │
│           RSASignaturePadding.Pkcs1);                       │
│   }                                                          │
│                                                              │
│ ROSLYN DETECTION:                                            │
│   → Find: RSA.Create(2048) → key_size = 2048                │
│   → Find: rsa.SignData(...)                                 │
│   → Argument: HashAlgorithmName.SHA256 → hash = SHA-256     │
│   → Argument: RSASignaturePadding.Pkcs1 → padding = PKCS1   │
│                                                              │
│ EXTRACT:                                                     │
│   algorithm: "RSA"                                           │
│   key_size: 2048                                             │
│   hash_algorithm: "SHA-256"                                  │
│   padding: "PKCS1"                                           │
│   purpose: "SIGNING"                                         │
│   library: "System.Security.Cryptography"                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PATTERN 5: Hardcoded keys in C#                             │
│                                                              │
│ C# CODE:                                                     │
│   byte[] key = new byte[] { 0x01, 0x02, 0x03, ... };  // Bad│
│   var aes = Aes.Create();                                   │
│   aes.Key = key;                                             │
│                                                              │
│ ROSLYN DETECTION:                                            │
│   → Find: new byte[] { ... } with literal values            │
│   → If assigned to crypto object .Key property              │
│   → Flag as HARDCODED_KEY                                   │
│                                                              │
│ STRING KEYS:                                                 │
│   const string secretKey = "1234567890abcdef";              │
│   → If high entropy + used in crypto → HARDCODED_KEY        │
│                                                              │
│ EXTRACT:                                                     │
│   is_hardcoded_key: true                                     │
│   key_length: len(byte_array) * 8                           │
│   severity: CRITICAL                                         │
└──────────────────────────────────────────────────────────────┘

ROSLYN SCANNER ARCHITECTURE:

┌──────────────────────────────────────────────────────────────┐
│ C# SCANNER EXECUTION FLOW                                   │
│                                                              │
│ INPUT: C# source directory                                  │
│                                                              │
│ STEP 1: PROJECT/SOLUTION PARSING                            │
│   IF .sln file exists:                                       │
│     solution = MSBuildWorkspace.Open(solution_path)         │
│     projects = solution.Projects                            │
│   ELSE:                                                      │
│     Find all .csproj files                                   │
│     Load each as separate project                           │
│                                                              │
│ STEP 2: COMPILE TO GET SEMANTIC MODEL                       │
│   FOR EACH project:                                          │
│     compilation = project.GetCompilationAsync()             │
│     → This gives full semantic model (types, symbols, etc)  │
│                                                              │
│ STEP 3: SYNTAX TREE ANALYSIS                                │
│   FOR EACH document IN project.Documents:                   │
│     syntax_tree = document.GetSyntaxTreeAsync()             │
│     semantic_model = compilation.GetSemanticModel(tree)     │
│                                                              │
│ STEP 4: CRYPTO PATTERN DETECTION                            │
│   walker = CryptoSyntaxWalker(semantic_model)               │
│   walker.Visit(syntax_tree.GetRoot())                       │
│   findings = walker.findings                                │
│                                                              │
│   CryptoSyntaxWalker (extends CSharpSyntaxWalker):         │
│     override VisitObjectCreationExpression(node):           │
│       IF node.Type is crypto type (Aes, DES, etc):         │
│         finding = extract_crypto_details(node, semantic_model)│
│         findings.append(finding)                             │
│                                                              │
│     override VisitInvocationExpression(node):               │
│       IF method is crypto method (Create, ComputeHash, etc):│
│         finding = extract_crypto_details(node, semantic_model)│
│         findings.append(finding)                             │
│                                                              │
│ STEP 5: SEMANTIC ENRICHMENT (Roslyn power)                  │
│   FOR EACH finding:                                          │
│     Use semantic_model to:                                   │
│       → Resolve exact type (not just text matching)         │
│       → Trace variable data flow (key size set elsewhere)   │
│       → Identify inherited crypto classes                   │
│       → Detect crypto wrapped in custom classes             │
│                                                              │
│ STEP 6: RAW FINDING OBJECT                                  │
│   Same schema as Java/Python scanners                       │
│   language: "CSHARP"                                         │
│   library: "System.Security.Cryptography" or "BouncyCastle" │
└──────────────────────────────────────────────────────────────┘
```

### 🔧 Multi-Language Coordination

```
┌──────────────────────────────────────────────────────────────┐
│ LANGUAGE DETECTION LOGIC                                     │
│                                                              │
│ FUNCTION detect_languages_in_repo(repo_path):               │
│                                                              │
│   languages = []                                             │
│                                                              │
│   IF exists(*.java) OR exists(*.jar):                       │
│     languages.append("JAVA")                                 │
│                                                              │
│   IF exists(*.py):                                           │
│     languages.append("PYTHON")                               │
│                                                              │
│   IF exists(*.js) OR exists(*.ts) OR exists(package.json):  │
│     languages.append("JAVASCRIPT")                           │
│                                                              │
│   IF exists(*.cs) OR exists(*.csproj) OR exists(*.sln):     │
│     languages.append("CSHARP")                               │
│                                                              │
│   RETURN languages                                           │
│                                                              │
│ EXAMPLE POLYGLOT REPO:                                       │
│   payment-api/                                               │
│   ├── backend/ (Java)                                        │
│   ├── scripts/ (Python)                                      │
│   ├── frontend/ (TypeScript)                                 │
│   └── services/ (C#)                                         │
│                                                              │
│   → Detected languages: ["JAVA", "PYTHON", "JAVASCRIPT", "CSHARP"]│
│   → All 4 scanners run                                       │
│   → Findings merged in single scan record                   │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 15-16 Deliverable

**JavaScript/TypeScript + C# scanners:**
1. JavaScript scanner using tree-sitter (Node crypto, jwt, bcrypt, crypto-js)
2. TypeScript scanner (same as JS, handles TS syntax)
3. C# scanner using Roslyn (System.Security.Cryptography, BouncyCastle)
4. Language detection logic (auto-detect languages in repo)
5. Multi-scanner coordination (all applicable scanners run per scan job)
6. All findings feed into same evidence pipeline

**Testing:**
- Test JS repo: Node crypto, jwt, bcrypt → all detected
- Test TS repo: Same patterns in TypeScript → detected
- Test C# repo: AES, DES, RSA, MD5 → all detected
- Test polyglot repo: Java + Python + JS + C# → all scanners run, findings merged
- Dashboard shows findings from all 4 languages
- Policy engine evaluates all languages with same rules
- Drift detection works across languages

---

# 🗺️ MONTH 5: BINARY & CONTAINER SCANNING + DEDUPLICATION

---

## WEEK 17-18: DOCKER CONTAINER SCANNER

### 🎯 Goal
Scan Docker images for crypto libraries in binaries

### 📐 Architecture — Container Scanner

```
┌─────────────────────────────────────────────────────────────┐
│           DOCKER CONTAINER SCANNER v1.0                     │
│           (Library Fingerprinting Approach)                 │
└─────────────────────────────────────────────────────────────┘

APPROACH: Library Identification via Known Hashes

WHY NOT FULL BINARY DISASSEMBLY (Month 5):
  → Disassembly is complex, slow, error-prone
  → Most crypto comes from known libraries (OpenSSL, BouncyCastle, etc)
  → We can fingerprint known library versions
  → Full disassembly deferred to later phase

TECHNOLOGY STACK:

1. Container image extraction: Skopeo or Docker CLI
2. Filesystem layer unpacking: tar extraction
3. Binary identification: file command + magic bytes
4. Library fingerprinting: SHA-256 hash database
5. Package manager parsing: Read installed packages

WORKFLOW:

┌──────────────────────────────────────────────────────────────┐
│ CONTAINER SCAN EXECUTION FLOW                               │
│                                                              │
│ INPUT: Docker image reference                                │
│   Examples:                                                  │
│     - payment-api:latest                                     │
│     - docker.io/myorg/payment-api:v1.2.3                    │
│     - us-docker.pkg.dev/project/repo/image@sha256:abc123... │
│                                                              │
│ STEP 1: PULL IMAGE (if not local)                           │
│   docker pull {image_reference}                             │
│   OR                                                         │
│   skopeo copy docker://{image} dir:/tmp/image-export        │
│                                                              │
│ STEP 2: EXPORT IMAGE TO FILESYSTEM                          │
│   docker save {image} -o /tmp/image.tar                     │
│   OR (if using skopeo)                                       │
│   Already exported in Step 1                                │
│                                                              │
│ STEP 3: EXTRACT LAYERS                                      │
│   tar -xf /tmp/image.tar -C /tmp/extracted-image/           │
│                                                              │
│   RESULT:                                                    │
│   /tmp/extracted-image/                                      │
│   ├── manifest.json         (image metadata)                │
│   ├── {layer1_id}/                                           │
│   │   └── layer.tar         (filesystem layer)              │
│   ├── {layer2_id}/                                           │
│   │   └── layer.tar                                          │
│   └── ...                                                    │
│                                                              │
│   FOR EACH layer:                                            │
│     tar -xf {layer_id}/layer.tar -C /tmp/layer-{n}/         │
│                                                              │
│ STEP 4: MERGE LAYERS (simulate container filesystem)        │
│   Container uses overlay filesystem — layers stack          │
│   Bottom layer first, each layer can override previous      │
│                                                              │
│   merged_fs = /tmp/merged-container-fs/                     │
│   FOR EACH layer IN order (bottom to top):                  │
│     rsync -a /tmp/layer-{n}/ merged_fs/                     │
│       → Files in upper layers override lower layers         │
│                                                              │
│ STEP 5: PACKAGE MANAGER INVENTORY                           │
│   (Fast path: Use OS package manager metadata)              │
│                                                              │
│   IF exists(merged_fs/var/lib/dpkg/status):  # Debian/Ubuntu│
│     packages = parse_dpkg_status()                          │
│     crypto_packages = filter(packages, is_crypto_related)   │
│     FOR EACH pkg IN crypto_packages:                        │
│       findings.append({                                      │
│         source: "PACKAGE_MANAGER",                          │
│         library: pkg.name,                                   │
│         version: pkg.version,                               │
│         confidence: "HIGH"                                   │
│       })                                                     │
│     EXAMPLE:                                                 │
│       Package: openssl                                       │
│       Version: 3.0.2-0ubuntu1.10                            │
│       → library: "OpenSSL", version: "3.0.2"                │
│                                                              │
│   IF exists(merged_fs/var/lib/rpm/):  # RHEL/CentOS/Fedora │
│     packages = rpm -qa --dbpath merged_fs/var/lib/rpm       │
│     crypto_packages = filter(packages, is_crypto_related)   │
│                                                              │
│   IF exists(merged_fs/lib/apk/db/installed):  # Alpine     │
│     packages = parse_apk_installed()                        │
│     crypto_packages = filter(packages, is_crypto_related)   │
│                                                              │
│   CRYPTO-RELATED PACKAGE NAMES:                             │
│     openssl, libssl, libcrypto, bouncycastle, cryptography, │
│     libsodium, libgcrypt, gnutls, nss, mbedtls, wolfssl     │
│                                                              │
│ STEP 6: BINARY LIBRARY FINGERPRINTING                       │
│   (Catch libraries not installed via package manager)       │
│                                                              │
│   Find all shared libraries:                                │
│     libs = find(merged_fs, -name "*.so*")                   │
│     libs += find(merged_fs, -name "*.dll")                  │
│     libs += find(merged_fs, -name "*.dylib")                │
│                                                              │
│   FOR EACH lib IN libs:                                     │
│     IF is_crypto_library(lib):                              │
│       hash = sha256(lib)                                     │
│       match = lookup_in_fingerprint_db(hash)                │
│       IF match:                                              │
│         findings.append({                                    │
│           source: "BINARY_FINGERPRINT",                     │
│           library: match.library_name,                      │
│           version: match.version,                           │
│           file_path: lib,                                    │
│           confidence: "HIGH"                                 │
│         })                                                   │
│       ELSE:                                                  │
│         # Unknown library — mark for manual review          │
│         findings.append({                                    │
│           source: "UNKNOWN_BINARY",                         │
│           file_path: lib,                                    │
│           hash: hash,                                        │
│           confidence: "LOW"                                  │
│         })                                                   │
│                                                              │
│ STEP 7: CRYPTO LIBRARY FINGERPRINT DATABASE                 │
│                                                              │
│   DATABASE: crypto_library_fingerprints                     │
│   ┌────────────────┬──────────────┬─────────────────────┐  │
│   │ library_name   │ version      │ file_hash (SHA-256) │  │
│   ├────────────────┼──────────────┼─────────────────────┤  │
│   │ OpenSSL        │ 3.0.2        │ a1b2c3d4e5f6...     │  │
│   │ OpenSSL        │ 1.1.1        │ f6e5d4c3b2a1...     │  │
│   │ BouncyCastle   │ 1.70         │ 9876543210ab...     │  │
│   │ libsodium      │ 1.0.18       │ fedcba098765...     │  │
│   │ ...            │ ...          │ ...                 │  │
│   └────────────────┴──────────────┴─────────────────────┘  │
│                                                              │
│   POPULATED BY:                                              │
│     → Download official releases of crypto libraries        │
│     → Compile on standard platforms (Ubuntu, Alpine, etc)   │
│     → Hash resulting .so/.dll files                         │
│     → Store in database                                     │
│                                                              │
│   EXAMPLE:                                                   │
│     Download OpenSSL 3.0.2 source                           │
│     Compile on Ubuntu 22.04                                 │
│     Hash /usr/lib/x86_64-linux-gnu/libssl.so.3              │
│     Store: {OpenSSL, 3.0.2, hash}                           │
│                                                              │
│ STEP 8: JAVA JAR SCANNING (if Java app in container)        │
│                                                              │
│   Find all JAR files:                                        │
│     jars = find(merged_fs, -name "*.jar")                   │
│                                                              │
│   FOR EACH jar IN jars:                                     │
│     unzip jar to temp directory                             │
│     scan_java_classes(temp_directory)                       │
│       → Use same Java scanner from Month 4                  │
│       → Detects crypto usage in compiled .class files       │
│                                                              │
│ STEP 9: PYTHON PACKAGE SCANNING (if Python app)             │
│                                                              │
│   IF exists(merged_fs/usr/local/lib/python*/site-packages/):│
│     site_packages = that directory                          │
│     crypto_packages = [                                      │
│       "cryptography",                                        │
│       "pycryptodome",                                        │
│       "pyOpenSSL",                                           │
│       ...                                                    │
│     ]                                                        │
│     FOR EACH pkg IN crypto_packages:                        │
│       IF exists(site_packages/{pkg}/):                      │
│         version = read_version_from_metadata(pkg)           │
│         findings.append({                                    │
│           source: "PYTHON_PACKAGE",                         │
│           library: pkg,                                      │
│           version: version                                   │
│         })                                                   │
│                                                              │
│ STEP 10: CVE ENRICHMENT                                     │
│   (Leverage existing CVE databases)                         │
│                                                              │
│   FOR EACH library finding:                                 │
│     cves = lookup_cves(library.name, library.version)       │
│     IF cves:                                                 │
│       finding.vulnerabilities = cves                        │
│       finding.severity = max(cve.severity for cve in cves)  │
│                                                              │
│   CVE SOURCES:                                               │
│     → NVD (National Vulnerability Database)                 │
│     → GitHub Security Advisories                            │
│     → OSV (Open Source Vulnerabilities)                     │
│                                                              │
│ STEP 11: CREATE CONTAINER SCAN FINDINGS                     │
│                                                              │
│   FOR EACH library:                                          │
│     finding = {                                              │
│       finding_id: UUID,                                      │
│       scanner_id: "container-scanner-v1.0",                 │
│       source: {                                              │
│         type: "CONTAINER_IMAGE",                            │
│         image_reference: "payment-api:v1.2.3",              │
│         image_digest: "sha256:abc123...",                   │
│         layer_id: "layer-5" (if applicable)                 │
│       },                                                     │
│       crypto: {                                              │
│         library_name: "OpenSSL",                            │
│         library_version: "3.0.2",                           │
│         algorithms_provided: [                              │
│           "AES", "RSA", "SHA-256", "ECDSA", ...             │
│         ],                                                   │
│         purpose: "CRYPTOGRAPHIC_LIBRARY"                    │
│       },                                                     │
│       vulnerabilities: [                                     │
│         {                                                    │
│           cve_id: "CVE-2023-0215",                          │
│           severity: "HIGH",                                  │
│           description: "Use-after-free in BIO_new_NDEF",    │
│           cvss_score: 7.5                                    │
│         }                                                    │
│       ],                                                     │
│       metadata: {                                            │
│         confidence: "HIGH",                                  │
│         detection_method: "PACKAGE_MANAGER"                 │
│       }                                                      │
│     }                                                        │
│                                                              │
│ STEP 12: CLEANUP                                             │
│   Delete /tmp/extracted-image/                              │
│   Delete /tmp/merged-container-fs/                          │
│   Keep only findings JSON                                   │
└──────────────────────────────────────────────────────────────┘
```

### 🔗 Container Registry Integration

```
┌──────────────────────────────────────────────────────────────┐
│ CONTAINER REGISTRY WEBHOOK INTEGRATION                      │
│ (Scan on image push)                                         │
│                                                              │
│ SUPPORTED REGISTRIES:                                        │
│   → Docker Hub                                               │
│   → Amazon ECR (Elastic Container Registry)                 │
│   → Azure Container Registry (ACR)                          │
│   → Google Container Registry (GCR) / Artifact Registry     │
│   → Harbor                                                   │
│   → JFrog Artifactory                                        │
│                                                              │
│ SETUP EXAMPLE: Amazon ECR                                    │
│                                                              │
│   1. Create EventBridge rule:                                │
│      Event pattern: ECR Image Push                           │
│      Target: Lambda → CryptoScan webhook                    │
│                                                              │
│   2. Lambda receives event:                                  │
│      {                                                        │
│        "detail": {                                           │
│          "repository-name": "payment-api",                  │
│          "image-tag": "v1.2.3",                             │
│          "image-digest": "sha256:abc123..."                 │
│        }                                                     │
│      }                                                       │
│                                                              │
│   3. Lambda forwards to CryptoScan:                         │
│      POST https://cryptoscan.local/webhooks/ecr             │
│      Body: ECR event                                         │
│                                                              │
│   4. CryptoScan creates scan job:                           │
│      {                                                       │
│        job_type: "CONTAINER_IMAGE",                         │
│        image_reference: "123456.dkr.ecr.us-east-1.amazonaws.com/payment-api:v1.2.3",│
│        image_digest: "sha256:abc123...",                    │
│        triggered_by: "ECR_PUSH_EVENT"                       │
│      }                                                       │
│                                                              │
│   5. Worker pulls image and scans                           │
│                                                              │
│ RESULT: Every container push → automatic crypto scan        │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 17-18 Deliverable

**Container scanner that:**
1. Pulls and extracts Docker images
2. Identifies crypto libraries via:
   - Package manager metadata (dpkg, rpm, apk)
   - Binary fingerprinting (SHA-256 hash database)
   - Embedded JAR/Python package scanning
3. Enriches with CVE data
4. Produces findings in same schema as source scanners
5. Integrates with container registries (ECR webhook example)
6. Findings feed into evidence pipeline

**Testing:**
- Build test Docker image with: OpenSSL 3.0.2, Python cryptography, Java BouncyCastle
- Push to local registry
- Trigger container scan
- Verify: All 3 libraries detected
- Verify: CVEs detected (if vulnerable versions)
- Dashboard shows container findings
- Policy engine evaluates: vulnerable OpenSSL → FAIL

---

## WEEK 19-20: DEDUPLICATION ENGINE + CROSS-SCANNER CORRELATION

### 🎯 Goal
Merge findings from source + binary scans into unified crypto assets

### 📐 Architecture — Deduplication Engine v2.0

```
┌─────────────────────────────────────────────────────────────┐
│         DEDUPLICATION ENGINE v2.0                           │
│         (Cross-Scanner Asset Unification)                   │
└─────────────────────────────────────────────────────────────┘

PROBLEM:

Same cryptographic asset found by multiple scanners:
  1. Static Java scanner finds: AES-256-GCM in Payment.java:247
  2. Container scanner finds: Java BouncyCastle in payment-api:v1.2.3
  3. These are related (code compiled into container)
  4. Should be ONE asset in inventory, not two

SOLUTION: Deduplication Key + Confidence Merging

DATABASE SCHEMA UPDATE:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: crypto_assets (replaces evidence_records for inventory)│
│                                                              │
│ asset_id           UUID PK        Canonical asset ID         │
│ dedup_key          VARCHAR(64)    Hash for deduplication     │
│ asset_type         VARCHAR(50)    ALGORITHM_USE, LIBRARY, CERT│
│ algorithm          VARCHAR(50)    AES, RSA, etc              │
│ mode               VARCHAR(50)    GCM, CBC, etc              │
│ key_size           INT            256, 2048, etc             │
│ purpose            VARCHAR(50)    ENCRYPTION, SIGNING, etc   │
│ normalized_crypto  JSONB          Full normalized data       │
│                                                              │
│ -- Confidence tracking                                       │
│ confidence         VARCHAR(20)    VERIFIED, HIGH, MEDIUM, LOW│
│ detection_sources  JSONB[]        All scanners that found it │
│                                                              │
│ -- Location tracking (can be multiple)                      │
│ locations          JSONB[]        Source files, containers, etc│
│                                                              │
│ -- Policy & compliance                                       │
│ compliance_status  VARCHAR(20)    PASS, WARN, FAIL           │
│ policy_evaluation  JSONB          Policy engine results      │
│                                                              │
│ -- Timestamps                                                │
│ first_seen         TIMESTAMP      First discovery            │
│ last_seen          TIMESTAMP      Most recent confirmation   │
│ last_updated       TIMESTAMP      Last modification          │
│                                                              │
│ created_at         TIMESTAMP                                 │
│ updated_at         TIMESTAMP                                 │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: asset_evidence_links                                  │
│ (Many-to-many: assets ← → evidence_records)                 │
│                                                              │
│ link_id            UUID PK                                   │
│ asset_id           UUID FK → crypto_assets                  │
│ evidence_id        UUID FK → evidence_records               │
│ link_type          VARCHAR(50)    PRIMARY, SUPPORTING       │
│ created_at         TIMESTAMP                                 │
└──────────────────────────────────────────────────────────────┘

DEDUPLICATION KEY FORMULA:

┌──────────────────────────────────────────────────────────────┐
│ DEDUP KEY CALCULATION                                        │
│                                                              │
│ FUNCTION calculate_dedup_key(finding):                      │
│                                                              │
│   # Normalize location                                       │
│   IF finding.source.type == "SOURCE_CODE":                  │
│     location_key = normalize_file_path(finding.file_path)   │
│       → Remove repo root, keep relative path                │
│       → src/main/Payment.java                               │
│                                                              │
│   ELSE IF finding.source.type == "CONTAINER_IMAGE":         │
│     location_key = "CONTAINER"                              │
│       → Container findings dedup by algorithm only          │
│                                                              │
│   # Build dedup components                                   │
│   components = [                                             │
│     finding.algorithm,                                       │
│     finding.mode or "DEFAULT",                              │
│     finding.key_size or "UNKNOWN",                          │
│     finding.purpose,                                         │
│     location_key                                             │
│   ]                                                          │
│                                                              │
│   # Hash components                                          │
│   canonical = "|".join(sorted(components))                  │
│   dedup_key = SHA-256(canonical)[:16]  # First 16 chars     │
│                                                              │
│   RETURN dedup_key                                           │
│                                                              │
│ EXAMPLES:                                                    │
│                                                              │
│   Finding 1 (Java source):                                  │
│     AES | GCM | 256 | ENCRYPTION | src/main/Payment.java    │
│     dedup_key: "a1b2c3d4e5f6g7h8"                           │
│                                                              │
│   Finding 2 (Container):                                    │
│     AES | GCM | 256 | ENCRYPTION | CONTAINER                │
│     dedup_key: "x9y8z7w6v5u4t3s2"  # Different!             │
│     → Container findings separate asset (library-level)     │
│                                                              │
│   Finding 3 (Python source, same file):                     │
│     AES | GCM | 256 | ENCRYPTION | src/main/Payment.java    │
│     dedup_key: "a1b2c3d4e5f6g7h8"  # SAME as Finding 1!     │
│     → Duplicate! Merge into one asset                       │
└──────────────────────────────────────────────────────────────┘

DEDUPLICATION ALGORITHM:

┌──────────────────────────────────────────────────────────────┐
│ DEDUP PROCESS (runs after evidence pipeline)                │
│                                                              │
│ INPUT: New evidence_record from any scanner                 │
│                                                              │
│ STEP 1: Calculate dedup key                                 │
│   dedup_key = calculate_dedup_key(evidence_record)          │
│                                                              │
│ STEP 2: Check for existing asset                            │
│   existing_asset = SELECT * FROM crypto_assets              │
│                    WHERE dedup_key = {dedup_key}             │
│                    LIMIT 1                                   │
│                                                              │
│ STEP 3A: IF existing asset FOUND → MERGE                    │
│                                                              │
│   # Add new detection source                                │
│   new_source = {                                             │
│     scanner_id: evidence_record.scanner_id,                 │
│     scan_id: evidence_record.scan_id,                       │
│     scan_timestamp: evidence_record.scan_timestamp,         │
│     confidence: evidence_record.confidence                   │
│   }                                                          │
│   existing_asset.detection_sources.append(new_source)       │
│                                                              │
│   # Add new location (if different)                         │
│   new_location = {                                           │
│     type: evidence_record.source.type,                      │
│     file_path: evidence_record.source.file_path,            │
│     line_number: evidence_record.source.line_number,        │
│     container_image: evidence_record.source.image_reference │
│   }                                                          │
│   IF new_location NOT IN existing_asset.locations:          │
│     existing_asset.locations.append(new_location)           │
│                                                              │
│   # Upgrade confidence                                       │
│   new_confidence = calculate_merged_confidence(             │
│     existing_asset.detection_sources                        │
│   )                                                          │
│   existing_asset.confidence = new_confidence                │
│                                                              │
│   # Update timestamps                                        │
│   existing_asset.last_seen = NOW()                          │
│   existing_asset.last_updated = NOW()                       │
│                                                              │
│   # Create evidence link                                     │
│   INSERT INTO asset_evidence_links (                         │
│     asset_id, evidence_id, link_type                        │
│   ) VALUES (                                                 │
│     existing_asset.asset_id,                                │
│     evidence_record.evidence_id,                            │
│     'SUPPORTING'  # Not primary, just additional evidence   │
│   )                                                          │
│                                                              │
│   UPDATE crypto_assets SET ... WHERE asset_id = ...;        │
│                                                              │
│ STEP 3B: IF NO existing asset → CREATE NEW                  │
│                                                              │
│   new_asset = {                                              │
│     asset_id: UUID.randomUUID(),                            │
│     dedup_key: dedup_key,                                    │
│     asset_type: "ALGORITHM_USE",                            │
│     algorithm: evidence_record.normalized_crypto.algorithm, │
│     mode: evidence_record.normalized_crypto.mode,           │
│     key_size: evidence_record.normalized_crypto.key_size,   │
│     purpose: evidence_record.normalized_crypto.purpose,     │
│     normalized_crypto: evidence_record.normalized_crypto,   │
│     confidence: evidence_record.confidence,                 │
│     detection_sources: [                                     │
│       {                                                      │
│         scanner_id: evidence_record.scanner_id,             │
│         scan_id: evidence_record.scan_id,                   │
│         confidence: evidence_record.confidence              │
│       }                                                      │
│     ],                                                       │
│     locations: [                                             │
│       {                                                      │
│         type: evidence_record.source.type,                  │
│         file_path: evidence_record.source.file_path,        │
│         line_number: evidence_record.source.line_number     │
│       }                                                      │
│     ],                                                       │
│     compliance_status: evidence_record.compliance_status,   │
│     policy_evaluation: evidence_record.policy_evaluation,   │
│     first_seen: NOW(),                                       │
│     last_seen: NOW()                                         │
│   }                                                          │
│                                                              │
│   INSERT INTO crypto_assets (...);                          │
│                                                              │
│   INSERT INTO asset_evidence_links (                         │
│     asset_id, evidence_id, link_type                        │
│   ) VALUES (                                                 │
│     new_asset.asset_id,                                     │
│     evidence_record.evidence_id,                            │
│     'PRIMARY'  # This evidence created the asset            │
│   )                                                          │
└──────────────────────────────────────────────────────────────┘

CONFIDENCE UPGRADE LOGIC:

┌──────────────────────────────────────────────────────────────┐
│ CONFIDENCE CALCULATION                                       │
│                                                              │
│ FUNCTION calculate_merged_confidence(detection_sources):    │
│                                                              │
│   scanner_types = set()                                      │
│   FOR source IN detection_sources:                          │
│     scanner_types.add(source.scanner_id.split('-')[0])     │
│       → "static-java-scanner" → "static"                    │
│       → "container-scanner" → "container"                   │
│                                                              │
│   # Confidence matrix                                        │
│   IF "static" IN scanner_types AND "container" IN scanner_types:│
│     RETURN "VERIFIED"                                        │
│       → Same crypto found in source AND compiled container  │
│       → Highest confidence                                   │
│                                                              │
│   ELSE IF "static" IN scanner_types AND "binary" IN scanner_types:│
│     RETURN "HIGH"                                            │
│       → Source + compiled binary                            │
│                                                              │
│   ELSE IF len(scanner_types) >= 2:                          │
│     RETURN "HIGH"                                            │
│       → Multiple different scanner types agree              │
│                                                              │
│   ELSE IF any(source.confidence == "HIGH" for source in ...):│
│     RETURN "HIGH"                                            │
│       → Single scanner, but HIGH confidence                 │
│                                                              │
│   ELSE:                                                      │
│     RETURN "MEDIUM"                                          │
│                                                              │
│ CONFIDENCE LEVELS:                                           │
│   VERIFIED:  Source + Binary/Container confirmation         │
│   HIGH:      Multiple scanners OR single high-conf scanner  │
│   MEDIUM:    Single scanner, medium confidence              │
│   LOW:       Single scanner, low confidence (var algo)      │
└──────────────────────────────────────────────────────────────┘

CROSS-SCANNER CORRELATION EXAMPLE:

┌──────────────────────────────────────────────────────────────┐
│ EXAMPLE: Payment API Scan                                   │
│                                                              │
│ SCAN 1: Static Java Scanner                                 │
│   Finds: AES-256-GCM in Payment.java:247                    │
│   Creates evidence_record_001                                │
│   Dedup key: "abc123"                                        │
│   Creates crypto_asset_001                                   │
│   Confidence: HIGH (static source)                          │
│                                                              │
│ SCAN 2: Container Scanner (same repo, compiled)             │
│   Finds: BouncyCastle 1.70 in payment-api:v1.2.3           │
│   Creates evidence_record_002                                │
│   Dedup key: "def456" (different — library vs usage)       │
│   Creates crypto_asset_002                                   │
│   Confidence: HIGH (fingerprint match)                      │
│                                                              │
│ SCAN 3: Binary JAR Scanner (inside container)               │
│   Scans payment-api.jar from container                      │
│   Finds: AES-256-GCM in compiled Payment.class:247         │
│   Creates evidence_record_003                                │
│   Dedup key: "abc123" (SAME as evidence_record_001!)       │
│   Deduplication engine:                                      │
│     → Finds existing crypto_asset_001                       │
│     → Merges evidence_record_003 into asset_001             │
│     → detection_sources now: [static, binary]               │
│     → Confidence upgraded: HIGH → VERIFIED                  │
│                                                              │
│ RESULT:                                                      │
│   crypto_asset_001:                                          │
│     algorithm: AES-256-GCM                                   │
│     confidence: VERIFIED (source + binary confirmation)     │
│     detection_sources: [static-java, binary-jar]            │
│     locations: [                                             │
│       {type: SOURCE, file: Payment.java, line: 247},        │
│       {type: BINARY, jar: payment-api.jar, class: Payment}  │
│     ]                                                        │
│                                                              │
│   crypto_asset_002:                                          │
│     library: BouncyCastle 1.70                              │
│     confidence: HIGH                                         │
│     detection_sources: [container-scanner]                  │
│     locations: [                                             │
│       {type: CONTAINER, image: payment-api:v1.2.3}          │
│     ]                                                        │
│                                                              │
│ TOTAL: 2 crypto assets (not 3 findings)                     │
└──────────────────────────────────────────────────────────────┘
```

### 📊 Dashboard Update for Deduplication

```
┌──────────────────────────────────────────────────────────────┐
│ DASHBOARD CHANGES FOR ASSET VIEW                            │
│                                                              │
│ NEW PAGE: /assets                                            │
│                                                              │
│ CRYPTO ASSET INVENTORY                                       │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  Total Assets:  1,284 (down from 2,847 raw findings)   │  │
│ │  Verified:      421  (source + binary confirmation)     │  │
│ │  High Conf:     689                                     │  │
│ │  Medium Conf:   174                                     │  │
│ │                                                         │  │
│ │  ASSETS TABLE                                           │  │
│ │  ┌──────────────────────────────────────────────────┐   │  │
│ │  │ Asset | Algo     | Conf     | Sources | Locations│   │  │
│ │  ├───────┼──────────┼──────────┼─────────┼──────────┤   │  │
│ │  │ a001  │ AES-GCM  │ VERIFIED │ 2       │ 2        │   │  │
│ │  │ a002  │ RSA-2048 │ HIGH     │ 1       │ 1        │   │  │
│ │  │ a003  │ DES      │ HIGH     │ 1       │ 1        │   │  │
│ │  │ ...                                               │   │  │
│ │  └──────────────────────────────────────────────────┘   │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ASSET DETAIL PAGE: /assets/{asset_id}                       │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  ASSET: AES-256-GCM in payment-api                     │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  CRYPTO DETAILS                                        │  │
│ │  Algorithm: AES | Mode: GCM | Key Size: 256           │  │
│ │  Purpose: Encryption | Confidence: VERIFIED ✅          │  │
│ │                                                        │  │
│ │  DETECTION SOURCES (2)                                 │  │
│ │  1. Static Java Scanner (scan abc123, 2024-01-15)     │  │
│ │     Confidence: HIGH                                   │  │
│ │  2. Binary JAR Scanner (scan def456, 2024-01-15)      │  │
│ │     Confidence: HIGH                                   │  │
│ │  → Combined: VERIFIED                                  │  │
│ │                                                        │  │
│ │  LOCATIONS (2)                                         │  │
│ │  1. Source Code:                                       │  │
│ │     File: src/main/Payment.java:247                    │  │
│ │     [View Code]                                        │  │
│ │  2. Compiled Binary:                                   │  │
│ │     JAR: payment-api.jar                               │  │
│ │     Class: com.example.Payment (bytecode offset 1247)  │  │
│ │                                                        │  │
│ │  EVIDENCE RECORDS (2)                                  │  │
│ │  • evidence_001 (primary) [View]                       │  │
│ │  • evidence_003 (supporting) [View]                    │  │
│ │                                                        │  │
│ │  COMPLIANCE                                            │  │
│ │  Status: PASS ✅                                        │  │
│ │  (All policy rules passed)                             │  │
│ │                                                        │  │
│ │  TIMELINE                                              │  │
│ │  First Seen:    2024-01-15 08:02:00 (static scan)     │  │
│ │  Last Seen:     2024-01-15 08:15:00 (binary scan)     │  │
│ │  Last Updated:  2024-01-15 08:15:30                    │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 19-20 Deliverable

**Deduplication system that:**
1. Creates `crypto_assets` table (unified inventory)
2. Creates `asset_evidence_links` table (many-to-many)
3. Calculates dedup keys for all findings
4. Merges findings from multiple scanners into single assets
5. Tracks detection sources and locations per asset
6. Upgrades confidence: source + binary = VERIFIED
7. Dashboard shows asset inventory (not raw findings)
8. Asset detail page shows all evidence + sources

**Testing:**
- Scan repo with Java source → creates assets
- Scan container built from same repo → JAR scanner runs
- Verify: AES finding from source + binary = 1 asset (VERIFIED confidence)
- Verify: BouncyCastle library finding = separate asset
- Dashboard asset count < raw finding count (dedup working)
- Asset detail page shows 2 sources for same crypto

---

# 🗺️ MONTH 6: ADVANCED POLICY ENGINE + CBOM EXPORT

---

## WEEK 21-22: ADVANCED POLICY RULES (PCI-DSS + NIST)

### 🎯 Goal
Implement real compliance standards (not just forbidden algos)

### 📐 Architecture — Policy Engine v2.0

```
┌─────────────────────────────────────────────────────────────┐
│           POLICY ENGINE v2.0                                │
│           (Real Compliance Standards)                       │
└─────────────────────────────────────────────────────────────┘

MONTH 1-3: Basic rules (forbidden algorithms, min key size)
MONTH 6: Real compliance frameworks

POLICY RULE STRUCTURE v2.0:

┌──────────────────────────────────────────────────────────────┐
│ RULE DEFINITION SCHEMA (Enhanced)                           │
│                                                              │
│ rules/pci-dss-4.0/requirement-4.2.1.yaml                    │
│                                                              │
│ ---                                                          │
│ rule_id: "PCI-DSS-4.0-R4.2.1"                              │
│ rule_name: "Strong Cryptography for Data in Transit"       │
│ version: "2.0"                                              │
│ effective_date: "2024-03-31"                                │
│ sunset_date: null                                            │
│ severity: "CRITICAL"                                         │
│                                                              │
│ standard:                                                    │
│   name: "PCI-DSS"                                           │
│   version: "4.0"                                             │
│   requirement: "4.2.1"                                       │
│   url: "https://www.pcisecuritystandards.org/document_library/"│
│   citation: "Requirement 4.2.1: Strong cryptography and    │
│              security protocols are implemented to safeguard│
│              PAN during transmission over open, public      │
│              networks."                                      │
│                                                              │
│ applicability:                                               │
│   scope: ["PAN_HANDLING", "PAYMENT_PROCESSING"]            │
│   purpose: ["ENCRYPTION", "KEY_EXCHANGE"]                   │
│   data_classification: ["PAN", "CARDHOLDER_DATA"]           │
│                                                              │
│ condition:                                                   │
│   type: "COMPLEX"                                            │
│   logic:                                                     │
│     ALL_OF:                                                  │
│       - IF purpose == "ENCRYPTION" AND scope == "PAN":      │
│           THEN:                                              │
│             algorithm IN ["AES", "ChaCha20"]                │
│             AND key_size >= 256                             │
│             AND mode IN ["GCM", "CCM", "ChaCha20-Poly1305"] │
│             AND tls_version >= "1.2"                        │
│                                                              │
│       - IF purpose == "KEY_EXCHANGE":                       │
│           THEN:                                              │
│             algorithm IN ["ECDHE", "DHE"]                   │
│             OR (algorithm == "RSA" AND key_size >= 2048)    │
│                                                              │
│       - FORBIDDEN:                                           │
│           algorithm NOT IN ["DES", "3DES", "RC4"]           │
│           tls_version NOT IN ["1.0", "1.1", "SSLv2", "SSLv3"]│
│                                                              │
│ evaluation:                                                  │
│   # Pseudocode evaluation logic                             │
│   FUNCTION evaluate(crypto_asset):                          │
│     IF crypto_asset NOT IN applicability.scope:            │
│       RETURN SKIP  # Rule doesn't apply                     │
│                                                              │
│     violations = []                                          │
│                                                              │
│     IF crypto_asset.purpose == "ENCRYPTION":                │
│       IF crypto_asset.algorithm NOT IN ["AES", "ChaCha20"]:│
│         violations.append("Non-approved algorithm")         │
│       IF crypto_asset.key_size < 256:                       │
│         violations.append("Key size too small")             │
│       IF crypto_asset.mode NOT IN ["GCM", "CCM", ...]:     │
│         violations.append("Non-AEAD mode")                  │
│                                                              │
│     IF crypto_asset.algorithm IN ["DES", "3DES", "RC4"]:   │
│       violations.append("Forbidden algorithm")              │
│                                                              │
│     IF len(violations) > 0:                                  │
│       RETURN FAIL, violations                               │
│     ELSE:                                                    │
│       RETURN PASS                                            │
│                                                              │
│ remediation:                                                 │
│   guidance: |                                                │
│     For PAN encryption:                                     │
│     - Use AES-256-GCM or ChaCha20-Poly1305                 │
│     - Ensure TLS 1.2 or 1.3 for data in transit            │
│     - Use ECDHE or DHE for key exchange                     │
│   links:                                                     │
│     - https://www.pcisecuritystandards.org/pdfs/...        │
│     - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf│
│                                                              │
│ metadata:                                                    │
│   created_by: "alice.security"                              │
│   approved_by: "CISO"                                        │
│   approved_date: "2024-01-01"                               │
│   last_updated: "2024-01-15"                                │
│   review_cycle: "ANNUAL"                                     │
│ ---                                                          │
└──────────────────────────────────────────────────────────────┘

MORE RULE EXAMPLES:

┌──────────────────────────────────────────────────────────────┐
│ RULE: NIST SP 800-131A Rev. 2 (Transitioning to Post-Quantum)│
│                                                              │
│ rules/nist-sp800-131a-r2/rsa-key-size.yaml                  │
│                                                              │
│ rule_id: "NIST-131A-R2-001"                                 │
│ standard:                                                    │
│   name: "NIST SP 800-131A"                                  │
│   version: "Revision 2"                                      │
│                                                              │
│ condition:                                                   │
│   IF algorithm == "RSA":                                    │
│     IF purpose == "SIGNING":                                │
│       key_size >= 2048  # ACCEPTABLE                        │
│     IF purpose == "KEY_EXCHANGE":                           │
│       FAIL  # RSA key transport DISALLOWED                  │
│     IF purpose == "KEY_AGREEMENT":                          │
│       FAIL  # RSA key agreement DISALLOWED                  │
│                                                              │
│ evaluation:                                                  │
│   IF crypto_asset.algorithm == "RSA":                       │
│     IF crypto_asset.purpose == "KEY_EXCHANGE":              │
│       RETURN FAIL, "RSA for key transport disallowed"       │
│     IF crypto_asset.purpose == "SIGNING":                   │
│       IF crypto_asset.key_size < 2048:                      │
│         RETURN FAIL, "RSA signing requires ≥2048 bits"      │
│       IF crypto_asset.key_size >= 2048:                     │
│         RETURN WARN, "RSA acceptable but not recommended for new systems"│
│                                                              │
│ remediation:                                                 │
│   For key exchange: Use ECDHE (P-256, P-384, P-521)        │
│   For signing: Use ECDSA or prepare for ML-DSA (FIPS 204)  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ RULE: NSA CNSA 2.0 (Quantum-Safe Requirements)              │
│                                                              │
│ rules/nsa-cnsa-2.0/quantum-safe-timeline.yaml               │
│                                                              │
│ rule_id: "NSA-CNSA-2.0-001"                                 │
│ standard:                                                    │
│   name: "NSA Commercial National Security Algorithm Suite" │
│   version: "2.0"                                             │
│   effective_date: "2025-01-01"  # Future enforcement        │
│                                                              │
│ condition:                                                   │
│   # Timeline-based evaluation                               │
│   IF current_date >= "2025-01-01":                          │
│     IF purpose == "KEY_EXCHANGE":                           │
│       algorithm MUST BE IN ["ML-KEM-768", "ML-KEM-1024"]   │
│         # Post-quantum key encapsulation                    │
│     IF purpose == "SIGNING":                                │
│       algorithm MUST BE IN ["ML-DSA-65", "ML-DSA-87"]      │
│         # Post-quantum signatures                           │
│   ELSE IF current_date >= "2024-01-01":                     │
│     # Transition period                                     │
│     IF algorithm IN ["RSA", "ECDH", "ECDSA"]:              │
│       RETURN WARN, "Begin transition to PQC"                │
│                                                              │
│ evaluation:                                                  │
│   today = NOW().date()                                       │
│   deadline = "2025-01-01"                                    │
│                                                              │
│   IF crypto_asset.purpose == "KEY_EXCHANGE":                │
│     IF crypto_asset.algorithm NOT IN ["ML-KEM-768", ...]:  │
│       days_until_deadline = (deadline - today).days         │
│       IF days_until_deadline <= 0:                          │
│         RETURN FAIL, "NSA CNSA 2.0 requires PQC"            │
│       ELSE:                                                  │
│         RETURN WARN, f"{days_until_deadline} days until PQC required"│
│                                                              │
│ remediation:                                                 │
│   Implement hybrid mode:                                    │
│     1. Current: ECDHE + ML-KEM (both)                       │
│     2. After 2025-01-01: ML-KEM only                        │
│   FIPS 203 (ML-KEM) libraries: liboqs, BouncyCastle PQC    │
└──────────────────────────────────────────────────────────────┘

POLICY ENGINE v2.0 EXECUTION:

┌──────────────────────────────────────────────────────────────┐
│ ENHANCED POLICY EVALUATION ALGORITHM                        │
│                                                              │
│ INPUT: crypto_asset (from deduplication engine)             │
│                                                              │
│ STEP 1: IDENTIFY APPLICABLE STANDARDS                       │
│                                                              │
│   # From system configuration (new)                         │
│   system = get_system_for_asset(crypto_asset)              │
│   compliance_scopes = system.compliance_scopes              │
│     → Example: ["PCI-DSS-4.0", "NIST-SP800-131A", "NSA-CNSA"]│
│                                                              │
│ STEP 2: LOAD ALL RULES FOR THOSE SCOPES                     │
│                                                              │
│   applicable_rules = []                                      │
│   FOR scope IN compliance_scopes:                           │
│     rules = load_rules_for_standard(scope)                  │
│     applicable_rules.extend(rules)                           │
│                                                              │
│ STEP 3: FILTER BY APPLICABILITY                             │
│                                                              │
│   FOR rule IN applicable_rules:                             │
│     IF NOT rule.applicability_matches(crypto_asset):       │
│       SKIP  # Rule doesn't apply to this asset              │
│                                                              │
│ STEP 4: EVALUATE EACH RULE                                  │
│                                                              │
│   policy_results = []                                        │
│                                                              │
│   FOR rule IN applicable_rules:                             │
│     result = rule.evaluate(crypto_asset)                    │
│       → Returns: (PASS | WARN | FAIL, message, violations)  │
│                                                              │
│     policy_result = {                                        │
│       rule_id: rule.rule_id,                                │
│       standard: rule.standard.name,                         │
│       requirement: rule.standard.requirement,               │
│       result: result.status,                                │
│       severity: rule.severity,                              │
│       message: result.message,                              │
│       violations: result.violations,                         │
│       remediation: rule.remediation,                         │
│       citation: rule.standard.citation,                     │
│       evidence_used: [crypto_asset.asset_id],               │
│       evaluated_at: NOW(),                                   │
│       evaluated_by: "policy-engine-v2.0"                    │
│     }                                                        │
│                                                              │
│     policy_results.append(policy_result)                     │
│                                                              │
│ STEP 5: AGGREGATE STATUS                                    │
│                                                              │
│   overall_status = "PASS"                                    │
│   critical_fails = [r for r in policy_results               │
│                     if r.result == "FAIL" and               │
│                        r.severity == "CRITICAL"]            │
│   high_fails = [r for r in policy_results                   │
│                 if r.result == "FAIL" and                   │
│                    r.severity == "HIGH"]                     │
│   warnings = [r for r in policy_results                     │
│                if r.result == "WARN"]                        │
│                                                              │
│   IF len(critical_fails) > 0:                               │
│     overall_status = "CRITICAL_FAIL"                        │
│   ELSE IF len(high_fails) > 0:                              │
│     overall_status = "FAIL"                                  │
│   ELSE IF len(warnings) > 0:                                │
│     overall_status = "WARN"                                  │
│                                                              │
│ STEP 6: UPDATE ASSET                                        │
│                                                              │
│   UPDATE crypto_assets SET                                   │
│     compliance_status = overall_status,                     │
│     policy_evaluation = {                                    │
│       overall_status: overall_status,                        │
│       rules_evaluated: policy_results,                       │
│       evaluation_timestamp: NOW(),                           │
│       standards_checked: compliance_scopes,                 │
│       critical_failures: len(critical_fails),               │
│       high_failures: len(high_fails),                       │
│       warnings: len(warnings)                                │
│     }                                                        │
│   WHERE asset_id = crypto_asset.asset_id;                   │
└──────────────────────────────────────────────────────────────┘

SYSTEM CONFIGURATION (NEW TABLE):

┌──────────────────────────────────────────────────────────────┐
│ TABLE: systems                                               │
│ (Business context for crypto assets)                        │
│                                                              │
│ system_id           UUID PK                                  │
│ system_name         VARCHAR(200)    payment-api, customer-db│
│ system_description  TEXT                                     │
│ environment         VARCHAR(50)     PRODUCTION, STAGING, etc │
│ criticality_tier    VARCHAR(20)     TIER-1, TIER-2, TIER-3  │
│ compliance_scopes   TEXT[]          [PCI-DSS-4.0, HIPAA, ...]│
│ data_classifications TEXT[]         [PAN, PHI, PII, ...]    │
│ business_owner      VARCHAR(100)    alice.manager@org.com   │
│ technical_owner     VARCHAR(100)    bob.engineer@org.com    │
│ created_at          TIMESTAMP                                │
│ updated_at          TIMESTAMP                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: asset_system_links                                    │
│ (Which assets belong to which systems)                      │
│                                                              │
│ link_id             UUID PK                                  │
│ asset_id            UUID FK → crypto_assets                 │
│ system_id           UUID FK → systems                       │
│ link_type           VARCHAR(50)    DIRECT_USE, DEPENDENCY   │
│ created_at          TIMESTAMP                                │
└──────────────────────────────────────────────────────────────┘

LINKING ASSETS TO SYSTEMS:

┌──────────────────────────────────────────────────────────────┐
│ SYSTEM IDENTIFICATION LOGIC                                  │
│                                                              │
│ DURING SCAN:                                                 │
│                                                              │
│   IF scan_type == "GIT_REPOSITORY":                         │
│     repo_url = scan_job.target_repo                         │
│     system = SELECT * FROM systems                          │
│              WHERE git_repository = repo_url                │
│                                                              │
│   IF scan_type == "CONTAINER_IMAGE":                        │
│     image_name = extract_image_name(image_reference)       │
│     system = SELECT * FROM systems                          │
│              WHERE container_image_pattern LIKE image_name  │
│                                                              │
│   FOR EACH crypto_asset found in scan:                      │
│     INSERT INTO asset_system_links (asset_id, system_id)   │
│     VALUES (crypto_asset.asset_id, system.system_id)        │
│                                                              │
│ RESULT: Assets inherit compliance scopes from their systems │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 21-22 Deliverable

**Advanced policy engine with:**
1. 10+ real compliance rules:
   - PCI-DSS 4.0 Requirement 4.2.1 (strong crypto for PAN)
   - NIST SP 800-131A Rev. 2 (RSA key size, disallowed uses)
   - NSA CNSA 2.0 (quantum-safe timeline)
   - FIPS 140-3 (approved algorithms)
   - HIPAA Security Rule (encryption requirements)
2. `systems` table (business context)
3. `asset_system_links` table (assets ↔ systems)
4. Scope-based rule application (only apply PCI rules to PCI systems)
5. Timeline-based rules (CNSA 2.0 enforcement date)
6. Enhanced policy evaluation results (citations, violations, remediation)

**Testing:**
- Create system: payment-api, compliance_scopes = ["PCI-DSS-4.0"]
- Scan payment-api → detects DES
- Policy engine loads PCI-DSS rules
- DES fails PCI-DSS-4.0-R4.2.1 (forbidden for PAN)
- Dashboard shows: CRITICAL_FAIL with PCI citation
- Create system: internal-tool, compliance_scopes = []
- Same DES code → only baseline rules apply (not PCI)

---

## WEEK 23-24: CBOM EXPORT (CycloneDX Format)

### 🎯 Goal
Generate industry-standard CBOM export for regulatory compliance

### 📐 Architecture — CBOM Generator

```
┌─────────────────────────────────────────────────────────────┐
│           CBOM EXPORT GENERATOR v1.0                        │
│           (CycloneDX 1.5 CBOM Specification)                │
└─────────────────────────────────────────────────────────────┘

WHAT IS CBOM:
  → Cryptography Bill of Materials
  → Standard format for documenting cryptographic assets
  → CycloneDX 1.5+ supports CBOM
  → Used for: compliance reporting, supply chain transparency

CYCLONEDX CBOM STRUCTURE:

┌──────────────────────────────────────────────────────────────┐
│ CYCLONEDX CBOM SCHEMA (JSON)                                │
│                                                              │
│ {                                                            │
│   "bomFormat": "CycloneDX",                                 │
│   "specVersion": "1.5",                                      │
│   "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-...",   │
│   "version": 1,                                              │
│   "metadata": {                                              │
│     "timestamp": "2024-01-15T10:00:00Z",                    │
│     "tools": [                                               │
│       {                                                      │
│         "vendor": "CryptoScan",                             │
│         "name": "CryptoScan Platform",                      │
│         "version": "2.0"                                     │
│       }                                                      │
│     ],                                                       │
│     "component": {                                           │
│       "type": "application",                                │
│       "name": "payment-api",                                │
│       "version": "v1.2.3",                                   │
│       "description": "Payment processing service"           │
│     }                                                        │
│   },                                                         │
│   "components": [                                            │
│     {                                                        │
│       "type": "cryptographic-asset",                        │
│       "bom-ref": "crypto-asset-001",                        │
│       "name": "AES-256-GCM Encryption",                     │
│       "cryptoProperties": {                                  │
│         "assetType": "algorithm",                           │
│         "algorithmProperties": {                            │
│           "primitive": "ae",  // authenticated encryption   │
│           "parameterSetIdentifier": "256",                  │
│           "curve": null,                                     │
│           "executionEnvironment": "software-plain-ram",     │
│           "implementationPlatform": "x86_64",               │
│           "certificationLevel": [],                         │
│           "mode": "gcm",                                     │
│           "padding": "none",                                 │
│           "cryptoFunctions": ["keygen", "encrypt", "decrypt"],│
│           "classicalSecurityLevel": 256,                    │
│           "nistQuantumSecurityLevel": null                  │
│         },                                                   │
│         "oid": "2.16.840.1.101.3.4.1.46"  // AES-256-GCM OID│
│       },                                                     │
│       "properties": [                                        │
│         {                                                    │
│           "name": "cryptoscan:confidence",                  │
│           "value": "VERIFIED"                               │
│         },                                                   │
│         {                                                    │
│           "name": "cryptoscan:first-seen",                  │
│           "value": "2024-01-15T08:00:00Z"                   │
│         },                                                   │
│         {                                                    │
│           "name": "cryptoscan:compliance-status",           │
│           "value": "PASS"                                    │
│         }                                                    │
│       ],                                                     │
│       "evidence": {                                          │
│         "identity": {                                        │
│           "field": "hash",                                   │
│           "confidence": 1.0,                                 │
│           "methods": [                                       │
│             {                                                │
│               "technique": "source-code-analysis",          │
│               "confidence": 0.95,                            │
│               "value": "evidence-hash-abc123..."            │
│             },                                               │
│             {                                                │
│               "technique": "binary-analysis",               │
│               "confidence": 0.95,                            │
│               "value": "evidence-hash-def456..."            │
│             }                                                │
│           ]                                                  │
│         },                                                   │
│         "occurrences": [                                     │
│           {                                                  │
│             "location": "src/main/Payment.java:247"         │
│           },                                                 │
│           {                                                  │
│             "location": "payment-api.jar:Payment.class"     │
│           }                                                  │
│         ]                                                    │
│       }                                                      │
│     },                                                       │
│     {                                                        │
│       "type": "cryptographic-asset",                        │
│       "bom-ref": "crypto-asset-002",                        │
│       "name": "RSA-2048 Signature",                         │
│       "cryptoProperties": {                                  │
│         "assetType": "algorithm",                           │
│         "algorithmProperties": {                            │
│           "primitive": "signature",                         │
│           "parameterSetIdentifier": "2048",                 │
│           "cryptoFunctions": ["keygen", "sign", "verify"],  │
│           "classicalSecurityLevel": 112,                    │
│           "nistQuantumSecurityLevel": 0  // Broken by Shor │
│         },                                                   │
│         "oid": "1.2.840.113549.1.1.1"  // RSA OID           │
│       },                                                     │
│       "properties": [                                        │
│         {                                                    │
│           "name": "cryptoscan:quantum-vulnerable",          │
│           "value": "true"                                    │
│         },                                                   │
│         {                                                    │
│           "name": "cryptoscan:compliance-status",           │
│           "value": "WARN"                                    │
│         },                                                   │
│         {                                                    │
│           "name": "cryptoscan:policy-violation",            │
│           "value": "NSA-CNSA-2.0: Transition to PQC required by 2025"│
│         }                                                    │
│       ]                                                      │
│     },                                                       │
│     {                                                        │
│       "type": "cryptographic-asset",                        │
│       "bom-ref": "crypto-lib-001",                          │
│       "name": "OpenSSL",                                     │
│       "version": "3.0.2",                                    │
│       "cryptoProperties": {                                  │
│         "assetType": "related-crypto-material",             │
│         "relatedCryptoMaterialProperties": {                │
│           "type": "library",                                │
│           "activation": "runtime",                          │
│           "securedBy": {                                     │
│             "mechanism": "code-signing"                     │
│           }                                                  │
│         }                                                    │
│       },                                                     │
│       "externalReferences": [                                │
│         {                                                    │
│           "type": "website",                                │
│           "url": "https://www.openssl.org/"                 │
│         }                                                    │
│       ],                                                     │
│       "properties": [                                        │
│         {                                                    │
│           "name": "cryptoscan:detection-method",            │
│           "value": "package-manager"                        │
│         }                                                    │
│       ]                                                      │
│     }                                                        │
│   ],                                                         │
│   "dependencies": [                                          │
│     {                                                        │
│       "ref": "crypto-asset-001",                            │
│       "dependsOn": ["crypto-lib-001"]  // AES uses OpenSSL │
│     },                                                       │
│     {                                                        │
│       "ref": "crypto-asset-002",                            │
│       "dependsOn": ["crypto-lib-001"]  // RSA uses OpenSSL │
│     }                                                        │
│   ],                                                         │
│   "vulnerabilities": [                                       │
│     {                                                        │
│       "bom-ref": "vuln-001",                                │
│       "id": "CVE-2023-0215",                                │
│       "source": {                                            │
│         "name": "NVD",                                       │
│         "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0215"│
│       },                                                     │
│       "ratings": [                                           │
│         {                                                    │
│           "score": 7.5,                                      │
│           "severity": "high",                                │
│           "method": "CVSSv3",                                │
│           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"│
│         }                                                    │
│       ],                                                     │
│       "description": "Use-after-free in BIO_new_NDEF",      │
│       "affects": [                                           │
│         {                                                    │
│           "ref": "crypto-lib-001"  // OpenSSL 3.0.2         │
│         }                                                    │
│       ]                                                      │
│     }                                                        │
│   ]                                                          │
│ }                                                            │
└──────────────────────────────────────────────────────────────┘

CBOM GENERATOR LOGIC:

┌──────────────────────────────────────────────────────────────┐
│ CBOM GENERATION ALGORITHM                                    │
│                                                              │
│ INPUT: system_id OR scan_id                                 │
│                                                              │
│ STEP 1: LOAD DATA                                            │
│                                                              │
│   IF system_id:                                              │
│     # Generate CBOM for entire system                       │
│     crypto_assets = SELECT * FROM crypto_assets             │
│                     JOIN asset_system_links                  │
│                       ON asset_id = asset_id                 │
│                     WHERE system_id = {system_id};          │
│     system = SELECT * FROM systems WHERE system_id = ...;   │
│     component_name = system.system_name                     │
│                                                              │
│   ELSE IF scan_id:                                           │
│     # Generate CBOM for single scan                         │
│     crypto_assets = SELECT * FROM crypto_assets             │
│                     JOIN asset_evidence_links                │
│                       ON asset_id = asset_id                 │
│                     JOIN evidence_records                    │
│                       ON evidence_id = evidence_id           │
│                     WHERE scan_id = {scan_id};              │
│     scan = SELECT * FROM scans WHERE scan_id = ...;         │
│     component_name = extract_repo_name(scan.target_location)│
│                                                              │
│ STEP 2: BUILD METADATA                                       │
│                                                              │
│   cbom = {                                                   │
│     "bomFormat": "CycloneDX",                               │
│     "specVersion": "1.5",                                    │
│     "serialNumber": f"urn:uuid:{UUID.randomUUID()}",        │
│     "version": 1,                                            │
│     "metadata": {                                            │
│       "timestamp": NOW().isoformat(),                        │
│       "tools": [{                                            │
│         "vendor": "CryptoScan",                             │
│         "name": "CryptoScan Platform",                      │
│         "version": "2.0"                                     │
│       }],                                                    │
│       "component": {                                         │
│         "type": "application",                              │
│         "name": component_name,                             │
│         "version": system.version OR scan.target_commit[:8],│
│         "description": system.system_description OR ""      │
│       }                                                      │
│     }                                                        │
│   }                                                          │
│                                                              │
│ STEP 3: BUILD COMPONENTS (crypto assets)                    │
│                                                              │
│   components = []                                            │
│                                                              │
│   FOR asset IN crypto_assets:                               │
│                                                              │
│     # Map CryptoScan fields to CycloneDX                    │
│     component = {                                            │
│       "type": "cryptographic-asset",                        │
│       "bom-ref": f"crypto-asset-{asset.asset_id}",         │
│       "name": f"{asset.algorithm}-{asset.key_size} {asset.purpose}",│
│       "cryptoProperties": {                                  │
│         "assetType": map_asset_type(asset),                │
│         "algorithmProperties": {                            │
│           "primitive": map_primitive(asset.purpose),        │
│           "parameterSetIdentifier": str(asset.key_size),   │
│           "mode": asset.mode,                               │
│           "padding": asset.normalized_crypto.padding,       │
│           "cryptoFunctions": infer_functions(asset),        │
│           "classicalSecurityLevel": calculate_sec_level(asset),│
│           "nistQuantumSecurityLevel": calculate_pq_level(asset)│
│         },                                                   │
│         "oid": lookup_oid(asset.algorithm, asset.mode)     │
│       },                                                     │
│       "properties": [                                        │
│         {"name": "cryptoscan:confidence",                   │
│          "value": asset.confidence},                        │
│         {"name": "cryptoscan:first-seen",                   │
│          "value": asset.first_seen.isoformat()},            │
│         {"name": "cryptoscan:compliance-status",            │
│          "value": asset.compliance_status}                  │
│       ],                                                     │
│       "evidence": {                                          │
│         "identity": {                                        │
│           "field": "hash",                                   │
│           "confidence": confidence_to_float(asset.confidence),│
│           "methods": build_detection_methods(asset)         │
│         },                                                   │
│         "occurrences": build_occurrences(asset)             │
│       }                                                      │
│     }                                                        │
│                                                              │
│     # Add policy violations as properties                   │
│     IF asset.compliance_status != "PASS":                   │
│       FOR violation IN asset.policy_evaluation.rules_evaluated:│
│         IF violation.result == "FAIL":                      │
│           component.properties.append({                      │
│             "name": "cryptoscan:policy-violation",          │
│             "value": f"{violation.rule_id}: {violation.message}"│
│           })                                                 │
│                                                              │
│     components.append(component)                             │
│                                                              │
│   cbom["components"] = components                           │
│                                                              │
│ STEP 4: BUILD DEPENDENCIES                                   │
│                                                              │
│   # For Month 6: Simple dependency (asset → library)        │
│   dependencies = []                                          │
│                                                              │
│   FOR asset IN crypto_assets:                               │
│     # Find which library provides this crypto               │
│     library = infer_library(asset)  # OpenSSL, BouncyCastle, etc│
│     IF library:                                              │
│       dependencies.append({                                  │
│         "ref": f"crypto-asset-{asset.asset_id}",           │
│         "dependsOn": [f"crypto-lib-{library.name}"]        │
│       })                                                     │
│                                                              │
│   cbom["dependencies"] = dependencies                       │
│                                                              │
│ STEP 5: BUILD VULNERABILITIES                               │
│                                                              │
│   vulnerabilities = []                                       │
│                                                              │
│   # From container scanner CVE data                         │
│   FOR asset IN crypto_assets:                               │
│     IF asset.vulnerabilities:  # From container scan        │
│       FOR cve IN asset.vulnerabilities:                     │
│         vuln = {                                             │
│           "bom-ref": f"vuln-{cve.cve_id}",                  │
│           "id": cve.cve_id,                                  │
│           "source": {                                        │
│             "name": "NVD",                                   │
│             "url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"│
│           },                                                 │
│           "ratings": [{                                      │
│             "score": cve.cvss_score,                        │
│             "severity": cve.severity.lower(),               │
│             "method": "CVSSv3"                              │
│           }],                                                │
│           "description": cve.description,                   │
│           "affects": [{                                      │
│             "ref": f"crypto-asset-{asset.asset_id}"        │
│           }]                                                 │
│         }                                                    │
│         vulnerabilities.append(vuln)                         │
│                                                              │
│   cbom["vulnerabilities"] = vulnerabilities                 │
│                                                              │
│ STEP 6: SIGN CBOM (optional but recommended)                │
│                                                              │
│   # CycloneDX supports JSON Web Signatures                  │
│   cbom_json = json.dumps(cbom, indent=2, sort_keys=True)   │
│   signature = sign_with_platform_key(cbom_json)            │
│                                                              │
│   cbom["signature"] = {                                      │
│     "algorithm": "RS256",                                    │
│     "publicKey": {                                           │
│       "kty": "RSA",                                          │
│       "n": "...",  # Platform public key                    │
│       "e": "AQAB"                                            │
│     },                                                       │
│     "value": signature                                       │
│   }                                                          │
│                                                              │
│ STEP 7: OUTPUT                                               │
│                                                              │
│   RETURN cbom (as JSON string)                              │
└──────────────────────────────────────────────────────────────┘

HELPER FUNCTIONS:

FUNCTION map_primitive(purpose):
  → "ENCRYPTION" → "ae" (authenticated encryption) or "enc"
  → "SIGNING" → "signature"
  → "HASHING" → "hash"
  → "KEY_EXCHANGE" → "kem" or "dh"

FUNCTION calculate_sec_level(asset):
  # Classical security level in bits
  → AES-256 → 256
  → RSA-2048 → 112 (effective security)
  → SHA-256 → 256

FUNCTION calculate_pq_level(asset):
  # NIST post-quantum security level (0-5)
  → RSA, ECDH, ECDSA → 0 (broken by quantum)
  → AES-256 → 3 (Grover reduces to 128-bit security)
  → SHA-256 → 2 (Grover reduces to 128-bit collision)
  → ML-KEM-768 → 3
  → ML-DSA-87 → 5

FUNCTION lookup_oid(algorithm, mode):
  # Map to IANA/NIST OIDs
  OID_TABLE = {
    ("AES", "GCM", 256): "2.16.840.1.101.3.4.1.46",
    ("RSA", null, 2048): "1.2.840.113549.1.1.1",
    ("SHA-256", null, null): "2.16.840.1.101.3.4.2.1",
    ...
  }
  RETURN OID_TABLE.get((algorithm, mode, key_size))
```

### 📤 CBOM Export API

```
┌──────────────────────────────────────────────────────────────┐
│ CBOM EXPORT API ENDPOINTS                                    │
│                                                              │
│ GET /api/cbom/system/{system_id}                            │
│   → Generates CBOM for entire system                        │
│   → Returns: CycloneDX JSON                                 │
│   → Content-Type: application/vnd.cyclonedx+json; version=1.5│
│                                                              │
│ GET /api/cbom/scan/{scan_id}                                │
│   → Generates CBOM for single scan                          │
│   → Returns: CycloneDX JSON                                 │
│                                                              │
│ GET /api/cbom/system/{system_id}?format=xml                │
│   → Same as above, but XML format                           │
│   → Content-Type: application/vnd.cyclonedx+xml; version=1.5│
│                                                              │
│ POST /api/cbom/custom                                        │
│   Body: {                                                    │
│     "asset_ids": ["uuid1", "uuid2", ...],                   │
│     "include_vulnerabilities": true,                        │
│     "include_evidence": true                                │
│   }                                                          │
│   → Generates CBOM for custom asset selection               │
│                                                              │
│ DASHBOARD INTEGRATION:                                       │
│                                                              │
│ System detail page:                                          │
│   [Export CBOM (JSON)] [Export CBOM (XML)]                  │
│                                                              │
│ Scan detail page:                                            │
│   [Export CBOM] ← downloads CycloneDX JSON                  │
│                                                              │
│ Compliance report page:                                      │
│   "Generate PCI-DSS CBOM Evidence Package"                  │
│   → Includes: CBOM + policy evaluation results + evidence   │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 23-24 Deliverable

**CBOM export system:**
1. CycloneDX 1.5 CBOM generator
2. Maps CryptoScan assets to CycloneDX schema
3. Includes: algorithms, libraries, vulnerabilities, evidence, dependencies
4. Supports JSON and XML output
5. Optional CBOM signing (JWS)
6. API endpoints for CBOM export
7. Dashboard export buttons
8. Compliance evidence package (CBOM + policy results)

**Testing:**
- Generate CBOM for payment-api system
- Verify: Valid CycloneDX 1.5 JSON (validate against schema)
- Verify: All crypto assets present
- Verify: Vulnerabilities included (from container scan)
- Verify: Evidence hashes present
- Verify: Policy violations included as properties
- Import CBOM into OWASP Dependency-Track (validate interoperability)
- Sign CBOM → verify signature

---

# 🎯 MONTH 4-6 COMPLETE END-TO-END FLOW SUMMARY

```
┌──────────────────────────────────────────────────────────────┐
│         PART 2 COMPLETE: MONTHS 4-6 DELIVERABLE              │
│         Multi-Language + Binary + Advanced Compliance        │
└──────────────────────────────────────────────────────────────┘

DEVELOPER PUSHES POLYGLOT REPO:
  → Java backend + Python scripts + TypeScript frontend + C# service
  ↓
GITHUB WEBHOOK FIRES:
  ↓
CRYPTOSCAN DETECTS 4 LANGUAGES:
  → Runs: Java scanner, Python scanner, JS scanner, C# scanner
  → 247 findings total (across all languages)
  ↓
CONTAINER PUSH (built from same repo):
  → ECR webhook fires
  → Container scanner runs
  → Detects: OpenSSL 3.0.2, BouncyCastle 1.70, Python cryptography
  → 3 library findings + embedded JAR scan (128 findings)
  ↓
DEDUPLICATION ENGINE:
  → Merges source findings + binary findings
  → AES from Java source + AES from JAR = 1 asset (VERIFIED confidence)
  → Result: 247 + 128 raw findings → 156 unique crypto assets
  ↓
ADVANCED POLICY ENGINE:
  → System: payment-api, scopes: [PCI-DSS-4.0, NSA-CNSA-2.0]
  → Applies 10 compliance rules per asset
  → DES → FAIL (PCI-DSS forbidden)
  → RSA-2048 for key exchange → FAIL (CNSA 2.0)
  → AES-256-GCM → PASS
  → Overall: 12 CRITICAL_FAIL, 34 WARN, 110 PASS
  ↓
CBOM EXPORT:
  → Compliance officer clicks "Export CBOM"
  → CycloneDX 1.5 JSON generated (156 crypto assets)
  → Includes: algorithms, libraries, CVEs, policy violations, evidence
  → Signed with platform key
  → Uploaded to GRC system (Archer/OneTrust)
  → Shared with auditor (proves compliance posture)
  ↓
AUDITOR RECEIVES CBOM:
  → Imports into Dependency-Track
  → Verifies signature (tamper-proof)
  → Reviews policy violations
  → Sees: "RSA-2048 for key exchange in payment-api: NSA CNSA 2.0 violation"
  → Asks: "What's your remediation plan?"
  ↓
SECURITY TEAM:
  → Dashboard shows timeline: "347 days until CNSA 2.0 enforcement"
  → Prioritizes: Replace RSA key exchange with ML-KEM-768 (hybrid mode)
  → Tracks in dashboard: "12 CNSA violations remaining"

TOTAL CAPABILITY:
  → 4 languages scanned (Java, Python, JS, C#)
  → Source + binary correlation (VERIFIED confidence)
  → 10+ real compliance rules (PCI, NIST, NSA)
  → Industry-standard CBOM export (CycloneDX 1.5)
  → Deduplication across 2,000+ findings → 156 assets
  → Full audit trail with evidence integrity
```

# CryptoScan Platform — Part 2: Production-Level Folder & File Structure

```
cryptoscan-platform/
│
│  [All Part 1 structure remains — additions and modifications below]
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   PART 2 ADDITIONS TO EXISTING SERVICES
│   (Modifications to Part 1 services)
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── services/
│   │
│   ├── scanner/                             # EXTENDED from Part 1
│   │   ├── scanner/
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── scanner.py               # UPDATED: orchestrate multi-language
│   │   │   │   ├── file_discovery.py        # UPDATED: multi-language file discovery
│   │   │   │   ├── scan_context.py          # UPDATED: add source_language field
│   │   │   │   └── language_detector.py     # NEW: detect_languages_in_repo()
│   │   │   │
│   │   │   ├── parsers/
│   │   │   │   ├── java_parser.py           # Part 1 (unchanged)
│   │   │   │   ├── ast_visitor.py           # Part 1 (unchanged)
│   │   │   │   ├── parse_error_handler.py   # Part 1 (unchanged)
│   │   │   │   ├── python_parser.py         # NEW: Python ast module parser
│   │   │   │   ├── js_ts_parser.py          # NEW: tree-sitter JS/TS parser
│   │   │   │   └── csharp_parser.py         # NEW: Roslyn via subprocess wrapper
│   │   │   │
│   │   │   ├── detectors/
│   │   │   │   ├── base_detector.py         # Part 1 (unchanged)
│   │   │   │   │
│   │   │   │   ├── java/                    # MOVED: Part 1 Java detectors
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── cipher_detector.py
│   │   │   │   │   ├── message_digest_detector.py
│   │   │   │   │   ├── key_generator_detector.py
│   │   │   │   │   ├── signature_detector.py
│   │   │   │   │   └── hardcoded_key_detector.py
│   │   │   │   │
│   │   │   │   ├── python/                  # NEW: Python detectors
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── cryptography_lib_detector.py   # cryptography lib patterns
│   │   │   │   │   ├── hashlib_detector.py            # hashlib patterns
│   │   │   │   │   ├── pycryptodome_detector.py       # PyCryptodome patterns
│   │   │   │   │   ├── hmac_detector.py               # hmac module patterns
│   │   │   │   │   └── hardcoded_key_detector.py      # Python hardcoded keys
│   │   │   │   │
│   │   │   │   ├── javascript/              # NEW: JavaScript detectors
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── node_crypto_detector.py        # Node.js crypto module
│   │   │   │   │   ├── webcrypto_detector.py          # Web Crypto API
│   │   │   │   │   ├── cryptojs_detector.py           # crypto-js library
│   │   │   │   │   ├── bcrypt_detector.py             # bcrypt/bcryptjs
│   │   │   │   │   ├── jwt_detector.py                # jsonwebtoken
│   │   │   │   │   ├── node_forge_detector.py         # node-forge
│   │   │   │   │   └── hardcoded_secret_detector.py   # JS hardcoded secrets
│   │   │   │   │
│   │   │   │   ├── csharp/                  # NEW: C# detectors
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── system_crypto_detector.py      # System.Security.Cryptography
│   │   │   │   │   ├── bouncycastle_detector.py       # BouncyCastle
│   │   │   │   │   ├── nsec_detector.py               # NSec library
│   │   │   │   │   └── hardcoded_key_detector.py      # C# hardcoded keys
│   │   │   │   │
│   │   │   │   └── detector_registry.py     # UPDATED: register all 4 languages
│   │   │   │
│   │   │   ├── extractors/
│   │   │   │   ├── algorithm_extractor.py   # UPDATED: add JS/TS/C# patterns
│   │   │   │   ├── context_extractor.py     # UPDATED: multi-language context
│   │   │   │   ├── snippet_extractor.py     # Part 1 (unchanged)
│   │   │   │   ├── confidence_calculator.py # Part 1 (unchanged)
│   │   │   │   └── entropy_calculator.py    # NEW: entropy analysis for hardcoded secrets
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── raw_finding.py           # UPDATED: add source_language, library fields
│   │   │   │   ├── scan_result.py           # UPDATED: multi-language stats
│   │   │   │   ├── git_context.py           # Part 1 (unchanged)
│   │   │   │   └── enums.py                 # UPDATED: add PYTHON, JAVASCRIPT, CSHARP
│   │   │   │
│   │   │   └── registry/                    # NEW: Scanner registry system
│   │   │       ├── __init__.py
│   │   │       ├── scanner_registry.py      # Map language → scanner class
│   │   │       └── multi_language_runner.py # Run all applicable scanners per job
│   │   │
│   │   ├── jdt/                             # Part 1 (unchanged)
│   │   │
│   │   ├── roslyn/                          # NEW: C# Roslyn scanner (.NET component)
│   │   │   ├── CryptoRoslynScanner.csproj
│   │   │   ├── Program.cs                   # CLI entry: takes path, outputs JSON
│   │   │   ├── Analyzers/
│   │   │   │   ├── CryptoSyntaxWalker.cs    # CSharpSyntaxWalker implementation
│   │   │   │   ├── SemanticEnricher.cs      # Semantic model enrichment
│   │   │   │   ├── SystemCryptoAnalyzer.cs  # System.Security.Cryptography patterns
│   │   │   │   └── BouncyCastleAnalyzer.cs  # BouncyCastle patterns
│   │   │   ├── Models/
│   │   │   │   ├── RawFinding.cs            # C# finding model (serializes to JSON)
│   │   │   │   └── ScanResult.cs            # C# scan result model
│   │   │   ├── Extractors/
│   │   │   │   ├── ContextExtractor.cs      # Extract file, line, class, method
│   │   │   │   ├── AlgorithmExtractor.cs    # Parse algorithm from Roslyn nodes
│   │   │   │   └── KeySizeExtractor.cs      # Extract key size from semantic model
│   │   │   └── build/                       # Compiled output (gitignored)
│   │   │
│   │   ├── tree_sitter_grammars/            # NEW: tree-sitter grammar files
│   │   │   ├── javascript/                  # JS grammar
│   │   │   └── typescript/                  # TS grammar
│   │   │
│   │   └── tests/
│   │       ├── unit/
│   │       │   ├── detectors/
│   │       │   │   ├── java/                # Part 1 tests (unchanged)
│   │       │   │   ├── python/              # NEW
│   │       │   │   │   ├── test_cryptography_lib_detector.py
│   │       │   │   │   ├── test_hashlib_detector.py
│   │       │   │   │   ├── test_pycryptodome_detector.py
│   │       │   │   │   └── test_hmac_detector.py
│   │       │   │   ├── javascript/          # NEW
│   │       │   │   │   ├── test_node_crypto_detector.py
│   │       │   │   │   ├── test_jwt_detector.py
│   │       │   │   │   ├── test_bcrypt_detector.py
│   │       │   │   │   └── test_hardcoded_secret_detector.py
│   │       │   │   └── csharp/              # NEW
│   │       │   │       ├── test_system_crypto_detector.py
│   │       │   │       └── test_bouncycastle_detector.py
│   │       │   └── test_language_detector.py    # NEW
│   │       │
│   │       ├── integration/
│   │       │   ├── test_full_scan_pipeline.py   # UPDATED: multi-language
│   │       │   ├── test_python_scan.py           # NEW
│   │       │   ├── test_js_ts_scan.py            # NEW
│   │       │   ├── test_csharp_scan.py           # NEW
│   │       │   └── test_polyglot_repo_scan.py    # NEW: Java+Python+JS+C# repo
│   │       │
│   │       └── fixtures/
│   │           ├── java_samples/            # Part 1 (unchanged)
│   │           ├── python_samples/          # NEW
│   │           │   ├── CryptographyLibSamples.py
│   │           │   ├── HashlibSamples.py
│   │           │   ├── PyCryptodome Samples.py
│   │           │   ├── HardcodedKeySamples.py
│   │           │   └── CompliantSamples.py
│   │           ├── javascript_samples/      # NEW
│   │           │   ├── NodeCryptoSamples.js
│   │           │   ├── JwtSamples.js
│   │           │   ├── BcryptSamples.js
│   │           │   ├── TypeScriptSamples.ts
│   │           │   └── HardcodedSecretSamples.js
│   │           ├── csharp_samples/          # NEW
│   │           │   ├── SystemCryptoSamples.cs
│   │           │   ├── DesSamples.cs
│   │           │   ├── RsaSamples.cs
│   │           │   └── HardcodedKeySamples.cs
│   │           └── polyglot_repo/           # NEW: mixed language test repo
│   │               ├── backend/             # Java
│   │               ├── scripts/             # Python
│   │               ├── frontend/            # TypeScript
│   │               └── services/            # C#
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: CONTAINER SCANNER
│   │   (Python — Docker image scanning)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── container_scanner/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   ├── Makefile
│   │   │
│   │   ├── container_scanner/
│   │   │   ├── __init__.py
│   │   │   ├── main.py                          # CLI entrypoint
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scanner.py                   # Main container scan orchestrator
│   │   │   │   └── scan_context.py              # ContainerScanContext dataclass
│   │   │   │
│   │   │   ├── image/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── image_puller.py              # docker pull / skopeo copy
│   │   │   │   ├── image_exporter.py            # docker save → tar file
│   │   │   │   ├── layer_extractor.py           # tar extraction per layer
│   │   │   │   ├── layer_merger.py              # Merge layers → unified filesystem
│   │   │   │   └── image_metadata_parser.py     # Parse manifest.json
│   │   │   │
│   │   │   ├── analyzers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── package_manager/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── base_package_analyzer.py     # Abstract base
│   │   │   │   │   ├── dpkg_analyzer.py             # Debian/Ubuntu dpkg
│   │   │   │   │   ├── rpm_analyzer.py              # RHEL/CentOS rpm
│   │   │   │   │   ├── apk_analyzer.py              # Alpine apk
│   │   │   │   │   └── crypto_package_filter.py     # Filter crypto-related packages
│   │   │   │   │
│   │   │   │   ├── binary/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── shared_library_finder.py     # Find *.so/*.dll/*.dylib
│   │   │   │   │   ├── binary_fingerprinter.py      # SHA-256 hash each binary
│   │   │   │   │   ├── fingerprint_db_lookup.py     # Lookup hash in fingerprint DB
│   │   │   │   │   └── magic_bytes_identifier.py    # Identify file type by magic bytes
│   │   │   │   │
│   │   │   │   ├── embedded/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── jar_scanner.py               # Find + scan JARs in container
│   │   │   │   │   └── python_package_scanner.py    # Scan site-packages in container
│   │   │   │   │
│   │   │   │   └── analyzer_coordinator.py          # Run all analyzers, merge results
│   │   │   │
│   │   │   ├── fingerprint_db/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── fingerprint_database.py          # DB access for fingerprint table
│   │   │   │   ├── fingerprint_updater.py           # Script to add new library hashes
│   │   │   │   └── seed_data/                       # Pre-populated fingerprints
│   │   │   │       ├── openssl_fingerprints.json
│   │   │   │       ├── bouncycastle_fingerprints.json
│   │   │   │       ├── libsodium_fingerprints.json
│   │   │   │       └── mbedtls_fingerprints.json
│   │   │   │
│   │   │   ├── cve/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cve_enricher.py                  # Enrich findings with CVE data
│   │   │   │   ├── nvd_client.py                    # NVD API client
│   │   │   │   ├── osv_client.py                    # OSV API client
│   │   │   │   ├── github_advisory_client.py        # GitHub Advisory API client
│   │   │   │   └── cve_cache.py                     # Cache CVE lookups (Redis)
│   │   │   │
│   │   │   ├── registry/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── registry_webhook_handler.py      # Receive registry push events
│   │   │   │   ├── ecr_handler.py                   # AWS ECR EventBridge events
│   │   │   │   ├── acr_handler.py                   # Azure Container Registry
│   │   │   │   ├── gcr_handler.py                   # Google Container Registry
│   │   │   │   ├── dockerhub_handler.py             # Docker Hub webhooks
│   │   │   │   └── harbor_handler.py                # Harbor webhooks
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── container_finding.py             # ContainerFinding dataclass
│   │   │   │   ├── library_finding.py               # LibraryFinding dataclass
│   │   │   │   ├── cve_finding.py                   # CVEFinding dataclass
│   │   │   │   └── enums.py                         # DetectionMethod, RegistryType enums
│   │   │   │
│   │   │   ├── workspace/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── workspace_manager.py             # Create/cleanup temp dirs
│   │   │   │   └── cleanup_handler.py               # Ensure cleanup on failure
│   │   │   │
│   │   │   └── config/
│   │   │       ├── __init__.py
│   │   │       └── settings.py                      # Container scanner config
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_layer_extractor.py
│   │       │   ├── test_layer_merger.py
│   │       │   ├── test_dpkg_analyzer.py
│   │       │   ├── test_rpm_analyzer.py
│   │       │   ├── test_apk_analyzer.py
│   │       │   ├── test_binary_fingerprinter.py
│   │       │   ├── test_fingerprint_db_lookup.py
│   │       │   ├── test_cve_enricher.py
│   │       │   └── test_jar_scanner.py
│   │       │
│   │       ├── integration/
│   │       │   ├── test_full_container_scan.py       # Pull test image → scan → findings
│   │       │   ├── test_openssl_detection.py         # OpenSSL in Ubuntu image
│   │       │   ├── test_bouncycastle_detection.py    # BouncyCastle in Java image
│   │       │   ├── test_cve_enrichment.py            # Vulnerable OpenSSL → CVE found
│   │       │   └── test_registry_webhook.py          # Fake ECR event → scan queued
│   │       │
│   │       └── fixtures/
│   │           ├── test_images/
│   │           │   ├── Dockerfile.openssl            # Test image: OpenSSL 3.0.2
│   │           │   ├── Dockerfile.java               # Test image: Java + BouncyCastle
│   │           │   └── Dockerfile.python             # Test image: Python + cryptography
│   │           └── sample_webhooks/
│   │               ├── ecr_push_event.json
│   │               ├── dockerhub_push_event.json
│   │               └── harbor_push_event.json
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: DEDUPLICATION ENGINE
│   │   (Python — cross-scanner asset unification)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── deduplication/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── deduplication/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py                        # Main dedup orchestrator
│   │   │   │   └── processor.py                     # Process one evidence_record
│   │   │   │
│   │   │   ├── fingerprinting/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── dedup_key_calculator.py          # calculate_dedup_key() function
│   │   │   │   ├── location_normalizer.py           # Normalize file paths for dedup
│   │   │   │   └── component_builder.py             # Build dedup components list
│   │   │   │
│   │   │   ├── merging/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── asset_merger.py                  # Merge evidence into existing asset
│   │   │   │   ├── asset_creator.py                 # Create new crypto_asset
│   │   │   │   ├── location_tracker.py              # Track unique locations per asset
│   │   │   │   └── detection_source_tracker.py      # Track all scanners per asset
│   │   │   │
│   │   │   ├── confidence/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── confidence_calculator.py         # calculate_merged_confidence()
│   │   │   │   └── confidence_matrix.py             # VERIFIED/HIGH/MEDIUM/LOW matrix
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── crypto_asset.py                  # CryptoAsset Pydantic model
│   │   │   │   ├── asset_evidence_link.py           # AssetEvidenceLink model
│   │   │   │   └── detection_source.py              # DetectionSource dataclass
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_dedup_key_calculator.py
│   │       │   ├── test_location_normalizer.py
│   │       │   ├── test_asset_merger.py
│   │       │   ├── test_asset_creator.py
│   │       │   └── test_confidence_calculator.py
│   │       └── integration/
│   │           ├── test_source_plus_binary_dedup.py # Same algo → 1 asset VERIFIED
│   │           ├── test_no_dedup_different_algo.py  # Different algos → 2 assets
│   │           ├── test_container_library_asset.py  # Library → separate asset
│   │           └── test_confidence_upgrade.py       # static+binary → VERIFIED
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   NEW SERVICE: CBOM EXPORTER
│   │   (Python — CycloneDX 1.5 CBOM generation)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── cbom/
│   │   │
│   │   ├── pyproject.toml
│   │   ├── poetry.lock
│   │   │
│   │   ├── cbom/
│   │   │   ├── __init__.py
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── generator.py                     # Main CBOM generation orchestrator
│   │   │   │   └── context_builder.py               # Build CBOM context (system/scan)
│   │   │   │
│   │   │   ├── builders/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── metadata_builder.py              # Build CycloneDX metadata section
│   │   │   │   ├── component_builder.py             # Build components[] from assets
│   │   │   │   ├── dependency_builder.py            # Build dependencies[] section
│   │   │   │   ├── vulnerability_builder.py         # Build vulnerabilities[] from CVEs
│   │   │   │   └── evidence_builder.py              # Build evidence.identity section
│   │   │   │
│   │   │   ├── mappers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── asset_type_mapper.py             # CryptoScan → CycloneDX assetType
│   │   │   │   ├── primitive_mapper.py              # purpose → CycloneDX primitive
│   │   │   │   ├── security_level_calculator.py     # Classical + PQ security levels
│   │   │   │   ├── oid_lookup.py                    # Algorithm → OID mapping
│   │   │   │   └── confidence_float_mapper.py       # VERIFIED/HIGH/MEDIUM → 0.0-1.0
│   │   │   │
│   │   │   ├── signing/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cbom_signer.py                   # JWS signing of CBOM
│   │   │   │   └── key_manager.py                   # Platform signing key management
│   │   │   │
│   │   │   ├── serializers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── json_serializer.py               # Serialize CBOM to JSON
│   │   │   │   └── xml_serializer.py                # Serialize CBOM to XML
│   │   │   │
│   │   │   ├── validators/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cbom_validator.py                # Validate against CycloneDX schema
│   │   │   │   └── schema/
│   │   │   │       ├── cyclonedx-1.5.schema.json    # CycloneDX JSON schema
│   │   │   │       └── bom-1.5.xsd                  # CycloneDX XML schema
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cbom_document.py                 # Full CBOM document model
│   │   │   │   ├── cbom_component.py                # CycloneDX component model
│   │   │   │   ├── cbom_metadata.py                 # CycloneDX metadata model
│   │   │   │   ├── cbom_vulnerability.py            # CycloneDX vulnerability model
│   │   │   │   └── cbom_dependency.py               # CycloneDX dependency model
│   │   │   │
│   │   │   ├── data/
│   │   │   │   ├── oid_table.json                   # Algorithm → OID mappings
│   │   │   │   └── primitive_map.json               # purpose → CycloneDX primitive
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py
│   │   │
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── conftest.py
│   │       ├── unit/
│   │       │   ├── test_component_builder.py
│   │       │   ├── test_metadata_builder.py
│   │       │   ├── test_vulnerability_builder.py
│   │       │   ├── test_asset_type_mapper.py
│   │       │   ├── test_security_level_calculator.py
│   │       │   ├── test_oid_lookup.py
│   │       │   └── test_cbom_signer.py
│   │       └── integration/
│   │           ├── test_full_cbom_generation.py     # Generate CBOM → validate schema
│   │           ├── test_json_output_valid.py        # Valid CycloneDX 1.5 JSON
│   │           ├── test_xml_output_valid.py         # Valid CycloneDX 1.5 XML
│   │           ├── test_vulnerabilities_included.py # CVEs from container scan
│   │           ├── test_evidence_included.py        # Evidence hashes in CBOM
│   │           └── test_cbom_signature_verify.py    # Sign → verify signature
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: POLICY ENGINE
│   │   (Extended with PCI-DSS, NIST, CNSA rules)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── policy/                              # EXTENDED from Part 1
│   │   ├── policy/
│   │   │   │
│   │   │   ├── core/
│   │   │   │   ├── engine.py                # UPDATED: v2.0 with scope-based eval
│   │   │   │   ├── evaluator.py             # UPDATED: complex conditions, timelines
│   │   │   │   └── scope_resolver.py        # NEW: resolve compliance scopes for asset
│   │   │   │
│   │   │   ├── conditions/
│   │   │   │   ├── base_condition.py        # Part 1 (unchanged)
│   │   │   │   ├── algorithm_in_list.py     # Part 1 (unchanged)
│   │   │   │   ├── key_size_minimum.py      # Part 1 (unchanged)
│   │   │   │   ├── algorithm_mode_whitelist.py  # Part 1 (unchanged)
│   │   │   │   ├── boolean_flag.py          # Part 1 (unchanged)
│   │   │   │   ├── complex_condition.py     # NEW: ALL_OF / ANY_OF / NOT logic
│   │   │   │   ├── timeline_condition.py    # NEW: date-based enforcement rules
│   │   │   │   ├── purpose_condition.py     # NEW: purpose-specific rules
│   │   │   │   └── condition_factory.py     # UPDATED: add new condition types
│   │   │   │
│   │   │   ├── models/
│   │   │   │   ├── policy_rule.py           # UPDATED: add standard, applicability
│   │   │   │   ├── policy_result.py         # UPDATED: add citation, violations
│   │   │   │   └── policy_evaluation.py     # UPDATED: CRITICAL_FAIL status
│   │   │   │
│   │   │   └── config/
│   │   │       └── settings.py              # UPDATED: multi-standard config
│   │   │
│   │   ├── rule_definitions/
│   │   │   ├── baseline/                    # Part 1 rules (unchanged)
│   │   │   │   ├── BASELINE-001-forbidden-algorithms.yaml
│   │   │   │   ├── BASELINE-002-minimum-rsa-key-size.yaml
│   │   │   │   ├── BASELINE-003-approved-aes-modes.yaml
│   │   │   │   └── BASELINE-004-hardcoded-keys.yaml
│   │   │   │
│   │   │   ├── pci-dss-4.0/                 # NEW: PCI-DSS rules
│   │   │   │   ├── requirement-4.2.1-strong-crypto-transit.yaml
│   │   │   │   ├── requirement-4.2.2-inventory.yaml
│   │   │   │   ├── requirement-8.3.2-strong-crypto-auth.yaml
│   │   │   │   └── requirement-12.3.3-crypto-review.yaml
│   │   │   │
│   │   │   ├── nist-sp800-131a-r2/          # NEW: NIST SP 800-131A Rev.2
│   │   │   │   ├── rsa-key-size.yaml
│   │   │   │   ├── rsa-disallowed-uses.yaml
│   │   │   │   ├── dsa-disallowed.yaml
│   │   │   │   ├── ecdsa-approved.yaml
│   │   │   │   └── hash-algorithm-transitions.yaml
│   │   │   │
│   │   │   ├── nsa-cnsa-2.0/                # NEW: NSA CNSA 2.0
│   │   │   │   ├── quantum-safe-key-exchange.yaml
│   │   │   │   ├── quantum-safe-signatures.yaml
│   │   │   │   ├── transition-timeline.yaml
│   │   │   │   └── hybrid-mode-requirement.yaml
│   │   │   │
│   │   │   ├── fips-140-3/                  # NEW: FIPS 140-3
│   │   │   │   ├── approved-algorithms.yaml
│   │   │   │   └── key-size-requirements.yaml
│   │   │   │
│   │   │   ├── hipaa/                       # NEW: HIPAA Security Rule
│   │   │   │   ├── phi-encryption.yaml
│   │   │   │   └── access-control-crypto.yaml
│   │   │   │
│   │   │   └── _schema/
│   │   │       └── rule_schema.yaml         # UPDATED: add standard, applicability
│   │   │
│   │   └── tests/
│   │       ├── unit/
│   │       │   ├── conditions/
│   │       │   │   ├── test_complex_condition.py    # NEW
│   │       │   │   ├── test_timeline_condition.py   # NEW
│   │       │   │   └── test_scope_resolver.py       # NEW
│   │       │   └── test_evaluator.py               # UPDATED
│   │       └── integration/
│   │           ├── test_pci_dss_rules.py            # NEW
│   │           ├── test_nist_sp800_rules.py         # NEW
│   │           ├── test_cnsa_timeline_rules.py      # NEW
│   │           ├── test_scope_based_evaluation.py   # NEW: PCI only on PCI systems
│   │           └── test_des_fails_pci.py            # NEW
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: DATABASE
│   │   (New tables for Part 2)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── database/                            # EXTENDED from Part 1
│   │   ├── migrations/
│   │   │   └── versions/
│   │   │       ├── [Part 1 migrations 0001-0009]    # Unchanged
│   │   │       │
│   │   │       ├── 0010_add_source_language_column.py       # NEW
│   │   │       ├── 0011_create_crypto_assets_table.py       # NEW
│   │   │       ├── 0012_create_asset_evidence_links_table.py # NEW
│   │   │       ├── 0013_create_crypto_lib_fingerprints_table.py # NEW
│   │   │       ├── 0014_create_systems_table.py             # NEW
│   │   │       ├── 0015_create_asset_system_links_table.py  # NEW
│   │   │       └── 0016_add_vulnerabilities_column.py       # NEW
│   │   │
│   │   ├── db/
│   │   │   ├── models/
│   │   │   │   ├── [Part 1 models]                          # Unchanged
│   │   │   │   ├── crypto_asset.py                          # NEW ORM model
│   │   │   │   ├── asset_evidence_link.py                   # NEW ORM model
│   │   │   │   ├── crypto_library_fingerprint.py            # NEW ORM model
│   │   │   │   ├── system.py                                # NEW ORM model
│   │   │   │   └── asset_system_link.py                     # NEW ORM model
│   │   │   │
│   │   │   └── repositories/
│   │   │       ├── [Part 1 repositories]                    # Unchanged
│   │   │       ├── crypto_asset_repository.py               # NEW: CRUD for crypto_assets
│   │   │       ├── asset_evidence_link_repository.py        # NEW
│   │   │       ├── fingerprint_repository.py                # NEW: library fingerprints
│   │   │       ├── system_repository.py                     # NEW: CRUD for systems
│   │   │       └── asset_system_link_repository.py          # NEW
│   │   │
│   │   └── tests/
│   │       ├── unit/
│   │       │   ├── test_crypto_asset_repository.py          # NEW
│   │       │   ├── test_system_repository.py                # NEW
│   │       │   └── test_fingerprint_repository.py           # NEW
│   │       └── integration/
│   │           ├── test_asset_dedup_queries.py              # NEW
│   │           └── test_system_asset_links.py               # NEW
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: REST API
│   │   (New endpoints for Part 2)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── api/                                 # EXTENDED from Part 1
│   │   ├── api/
│   │   │   ├── routers/
│   │   │   │   ├── [Part 1 routers]                         # Unchanged
│   │   │   │   ├── assets.py                                # NEW: /api/assets endpoints
│   │   │   │   ├── systems.py                               # NEW: /api/systems endpoints
│   │   │   │   ├── cbom.py                                  # NEW: /api/cbom endpoints
│   │   │   │   ├── container_scans.py                       # NEW: container scan endpoints
│   │   │   │   └── vulnerability.py                         # NEW: /api/vulnerabilities
│   │   │   │
│   │   │   ├── schemas/
│   │   │   │   ├── [Part 1 schemas]                         # Unchanged
│   │   │   │   ├── asset_schemas.py                         # NEW
│   │   │   │   ├── system_schemas.py                        # NEW
│   │   │   │   ├── cbom_schemas.py                          # NEW
│   │   │   │   └── vulnerability_schemas.py                 # NEW
│   │   │   │
│   │   │   └── github/
│   │   │       ├── webhook_handler.py                       # UPDATED: container webhooks
│   │   │       ├── payload_parser.py                        # Unchanged
│   │   │       └── status_poster.py                         # Unchanged
│   │   │
│   │   └── tests/
│   │       └── integration/
│   │           ├── [Part 1 tests]                           # Unchanged
│   │           ├── test_assets_endpoints.py                 # NEW
│   │           ├── test_systems_endpoints.py                # NEW
│   │           ├── test_cbom_endpoints.py                   # NEW
│   │           └── test_container_scan_endpoint.py          # NEW
│   │
│   │
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │   UPDATED SERVICE: SCAN WORKER
│   │   (Extended pipeline for Part 2)
│   ├── ── ── ── ── ── ── ── ── ── ── ──
│   │
│   ├── worker/                              # EXTENDED from Part 1
│   │   ├── worker/
│   │   │   ├── pipeline/
│   │   │   │   ├── [Part 1 stages]                          # Unchanged
│   │   │   │   ├── stage_language_detect.py                 # NEW: Stage before scan
│   │   │   │   ├── stage_multi_scanner.py                   # NEW: Run all language scanners
│   │   │   │   ├── stage_container_scan.py                  # NEW: Container image scan
│   │   │   │   ├── stage_deduplication.py                   # NEW: After evidence load
│   │   │   │   └── stage_cbom_generate.py                   # NEW: Optional CBOM gen
│   │   │   │
│   │   │   └── pipeline/
│   │   │       └── pipeline_runner.py                       # UPDATED: add new stages
│   │   │
│   │   └── tests/
│   │       └── integration/
│   │           ├── [Part 1 tests]                           # Unchanged
│   │           └── test_multi_language_pipeline.py          # NEW
│   │
│   │
│   └── ── ── ── ── ── ── ── ── ── ── ──
│       UPDATED SERVICE: WEB DASHBOARD
│       (New pages for Part 2)
│   ── ── ── ── ── ── ── ── ── ── ── ──
│
│   └── dashboard/
│       └── src/
│           ├── pages/
│           │   ├── [Part 1 pages]                           # Unchanged
│           │   ├── AssetInventory.tsx                       # NEW: /assets
│           │   ├── AssetDetail.tsx                          # NEW: /assets/{id}
│           │   ├── SystemList.tsx                           # NEW: /systems
│           │   ├── SystemDetail.tsx                         # NEW: /systems/{id}
│           │   └── ComplianceReport.tsx                     # NEW: Compliance by standard
│           │
│           ├── components/
│           │   ├── [Part 1 components]                      # Unchanged
│           │   ├── assets/
│           │   │   ├── AssetTable.tsx                       # NEW
│           │   │   ├── AssetDetailCard.tsx                  # NEW
│           │   │   ├── DetectionSourcesList.tsx             # NEW: all scanners that found it
│           │   │   ├── LocationsList.tsx                    # NEW: all locations
│           │   │   ├── ConfidenceBadge.tsx                  # NEW: VERIFIED/HIGH/MEDIUM
│           │   │   └── EvidenceLinksList.tsx                # NEW: linked evidence records
│           │   │
│           │   ├── systems/
│           │   │   ├── SystemTable.tsx                      # NEW
│           │   │   ├── SystemDetailCard.tsx                 # NEW
│           │   │   ├── ComplianceScopeList.tsx              # NEW
│           │   │   └── SystemAssetMap.tsx                   # NEW: assets in system
│           │   │
│           │   ├── cbom/
│           │   │   ├── CbomExportButton.tsx                 # NEW: JSON/XML export
│           │   │   └── CbomEvidencePackage.tsx              # NEW: full evidence package
│           │   │
│           │   ├── vulnerabilities/
│           │   │   ├── VulnerabilityList.tsx                # NEW
│           │   │   └── CveSeverityBadge.tsx                 # NEW
│           │   │
│           │   └── compliance/
│           │       ├── ComplianceByStandard.tsx             # NEW: PCI/NIST/CNSA view
│           │       └── PolicyCitation.tsx                   # NEW: show standard citation
│           │
│           ├── hooks/
│           │   ├── [Part 1 hooks]                           # Unchanged
│           │   ├── useAssets.ts                             # NEW
│           │   ├── useSystems.ts                            # NEW
│           │   ├── useCbom.ts                               # NEW: trigger CBOM download
│           │   └── useVulnerabilities.ts                    # NEW
│           │
│           ├── api/
│           │   ├── [Part 1 api]                             # Unchanged
│           │   ├── assets.api.ts                            # NEW
│           │   ├── systems.api.ts                           # NEW
│           │   └── cbom.api.ts                              # NEW
│           │
│           └── types/
│               ├── [Part 1 types]                           # Unchanged
│               ├── asset.types.ts                           # NEW
│               ├── system.types.ts                          # NEW
│               └── vulnerability.types.ts                   # NEW
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED SHARED LIBRARIES
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── shared/
│   ├── shared_models/
│   │   ├── shared_models/
│   │   │   ├── finding.py                               # UPDATED: add source_language
│   │   │   ├── evidence.py                              # Part 1 (unchanged)
│   │   │   ├── crypto_asset.py                          # NEW: shared CryptoAsset model
│   │   │   ├── vulnerability.py                         # NEW: shared CVE model
│   │   │   └── enums.py                                 # UPDATED: new language/asset enums
│   │   └── tests/
│   │       └── test_shared_models.py                    # UPDATED
│   │
│   ├── shared_config/                                   # Unchanged
│   └── shared_logging/                                  # Unchanged
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED INFRASTRUCTURE
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── infra/
│   ├── postgres/
│   │   └── init/
│   │       ├── 01_create_databases.sql                  # Unchanged
│   │       ├── 02_create_extensions.sql                 # Unchanged
│   │       └── 03_seed_fingerprints.sql                 # NEW: seed crypto lib fingerprints
│   │
│   ├── redis/                                           # Unchanged
│   ├── nginx/                                           # Unchanged
│   │
│   └── monitoring/
│       └── grafana/
│           └── dashboards/
│               ├── cryptoscan_overview.json             # UPDATED: add asset metrics
│               └── container_scan_metrics.json          # NEW
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED DOCKER FILES
├── ── ── ── ── ── ── ── ── ── ── ──
│
├── .docker/
│   ├── [Part 1 dockerfiles]                             # Unchanged
│   ├── container_scanner/
│   │   └── Dockerfile                                   # NEW: container scanner
│   ├── deduplication/
│   │   └── Dockerfile                                   # NEW: dedup engine
│   └── cbom/
│       └── Dockerfile                                   # NEW: CBOM exporter
│
├── docker-compose.yml                                   # UPDATED: add new services
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED SCRIPTS
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
├── scripts/
│   ├── [Part 1 scripts]                                 # Unchanged
│   ├── update_fingerprint_db.py                         # NEW: add crypto lib hashes
│   ├── scan_container.py                                # NEW: CLI trigger container scan
│   ├── export_cbom.py                                   # NEW: CLI CBOM export
│   ├── manage_systems.py                                # NEW: CLI add/edit systems
│   └── seed_compliance_rules.py                         # NEW: load all rule YAML to DB
│
│
├── ── ── ── ── ── ── ── ── ── ── ── ──
│   UPDATED DOCUMENTATION
├── ── ── ── ── ── ── ── ── ── ── ── ──
│
└── docs/
    ├── [Part 1 docs]                                    # Unchanged
    │
    ├── user-guide/
    │   ├── [Part 1 guides]                              # Unchanged
    │   ├── multi-language-scanning.md                   # NEW
    │   ├── container-scanning.md                        # NEW
    │   ├── crypto-asset-inventory.md                    # NEW
    │   ├── cbom-export.md                               # NEW
    │   └── compliance-standards.md                      # NEW
    │
    ├── admin-guide/
    │   ├── [Part 1 guides]                              # Unchanged
    │   ├── container-registry-integration.md            # NEW
    │   ├── system-configuration.md                      # NEW
    │   ├── fingerprint-db-management.md                 # NEW
    │   └── compliance-rule-authoring.md                 # NEW
    │
    ├── architecture/
    │   ├── [Part 1 docs]                                # Unchanged
    │   ├── multi-language-scanner-design.md             # NEW
    │   ├── container-scanner-design.md                  # NEW
    │   ├── deduplication-design.md                      # NEW
    │   └── cbom-generation-design.md                    # NEW
    │
    └── decisions/
        ├── [Part 1 ADRs]                                # Unchanged
        ├── ADR-005-tree-sitter-for-js-ts.md             # NEW
        ├── ADR-006-roslyn-for-csharp.md                 # NEW
        ├── ADR-007-library-fingerprinting-approach.md   # NEW
        ├── ADR-008-dedup-key-formula.md                 # NEW
        └── ADR-009-cyclonedx-1.5-cbom.md               # NEW
```

---

## Part 2 Structure Summary

```
NEW SERVICES ADDED (4):
  ├── container_scanner/     → Docker image scanning
  ├── deduplication/         → Cross-scanner asset unification
  ├── cbom/                  → CycloneDX 1.5 CBOM generation
  └── roslyn/ (inside scanner/) → C# Roslyn .NET component

EXISTING SERVICES EXTENDED:
  ├── scanner/               → +3 languages (Python, JS/TS, C#)
  ├── policy/                → +5 standards (PCI-DSS, NIST, CNSA, FIPS, HIPAA)
  ├── database/              → +6 new migrations, +5 new ORM models
  ├── api/                   → +5 new routers (assets, systems, cbom, container, vuln)
  ├── worker/                → +4 new pipeline stages
  └── dashboard/             → +5 new pages, +4 new component groups

NEW DATABASE TABLES (Part 2):
  ├── crypto_assets           → Deduplicated asset inventory
  ├── asset_evidence_links    → Many-to-many: assets ↔ evidence
  ├── crypto_library_fingerprints → Binary fingerprint DB
  ├── systems                 → Business context for assets
  └── asset_system_links      → Many-to-many: assets ↔ systems

KEY DESIGN PRINCIPLE:
  All new scanners produce RawFinding (same schema as Part 1)
  Same evidence pipeline handles all scanner types
  Deduplication runs AFTER evidence load, BEFORE policy
  CBOM generation reads from crypto_assets (deduplicated)
  Part 1 evidence integrity chain is fully preserved
```