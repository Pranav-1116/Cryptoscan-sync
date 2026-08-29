"""Remediation template library: language-specific, copy-paste-ready fixes.

Every template carries, per language, a minimal before/after pair (the
weak pattern and its replacement), what to test afterwards, and primary
references (NIST/RFC documents — real URLs only). Effort is a range in
engineer-hours plus a change-risk class; guidance stays deterministic —
these templates advise, they never decide compliance (that is the policy
engine's job alone).

Honesty rules:
  - code snippets show real, idiomatic library calls for well-known
    stacks; where a replacement needs a library the language does not
    ship (e.g. ChaCha20 in the JDK), the snippet says so instead of
    inventing an API;
  - PQC transition templates are checklists, not fabricated FIPS-203
    code — ecosystem library names are listed as pointers;
  - "Create fix branch" produces a payload a developer (or CI) applies —
    CryptoScan never pushes to your repository by itself.
"""

from __future__ import annotations

from typing import Any

_LANGUAGES = ("java", "python", "javascript", "go")

REFERENCES = {
    "sp800-131a": {"label": "NIST SP 800-131A Rev. 2 (algorithm transition)", "url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"},
    "fips197": {"label": "FIPS 197 (AES)", "url": "https://csrc.nist.gov/pubs/fips/197/final"},
    "fips203": {"label": "FIPS 203 (ML-KEM)", "url": "https://csrc.nist.gov/pubs/fips/203/final"},
    "fips204": {"label": "FIPS 204 (ML-DSA)", "url": "https://csrc.nist.gov/pubs/fips/204/final"},
    "fips205": {"label": "FIPS 205 (SLH-DSA)", "url": "https://csrc.nist.gov/pubs/fips/205/final"},
    "rfc8446": {"label": "RFC 8446 (TLS 1.3)", "url": "https://www.rfc-editor.org/rfc/rfc8446"},
    "rfc8439": {"label": "RFC 8439 (ChaCha20-Poly1305)", "url": "https://www.rfc-editor.org/rfc/rfc8439"},
    "owasp-storage": {"label": "OWASP Cryptographic Storage Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"},
    "nist-pqc": {"label": "NIST Post-Quantum Cryptography project", "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"},
    "fips180": {"label": "FIPS 180-4 (SHA-2)", "url": "https://csrc.nist.gov/pubs/fips/180/upd2/final"},
}

_TEMPLATES: dict[str, dict[str, Any]] = {
    "replace-des": {
        "title": "Replace DES with AES-256-GCM",
        "effort_hours": (1, 4), "risk": "medium",
        "testing": [
            "Round-trip fixtures: data encrypted with the old DES key must decrypt, then re-encrypt as AES-GCM",
            "IV uniqueness: GCM forbids reusing a 12-byte IV under the same key — assert fresh IVs per encryption",
            "Ciphertext size and stored-format consumers (DB columns, queues) tolerate the GCM tag",
        ],
        "references": ["sp800-131a", "fips197"],
        "snippets": {
            "java": {"before": 'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");',
                     "after": 'byte[] iv = new byte[12]; // fresh per encryption\nSecureRandom.getInstanceStrong().nextBytes(iv);\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\ncipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));'},
            "python": {"before": "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_CBC)",
                       "after": "import os\nfrom Crypto.Cipher import AES\niv = os.urandom(12)\ncipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)"},
            "javascript": {"before": "const cipher = crypto.createCipheriv('des-cbc', key, iv);",
                           "after": "const iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n// cipher.getAuthTag() must be stored with the ciphertext"},
            "go": {"before": 'block, _ := des.NewCipher(key)\nmode := cipher.NewCBCEncrypter(block, iv)',
                   "after": 'block, _ := aes.NewCipher(aesKey256)\ngcm, _ := cipher.NewGCM(block)\nciphertext := gcm.Seal(nil, make([]byte, 12), plaintext, nil)'},
        },
    },
    "replace-3des": {
        "title": "Replace 3DES (DESede) with AES-256-GCM",
        "effort_hours": (1, 4), "risk": "medium",
        "testing": [
            "Sweet32-style long-lived TLS sessions are gone after the swap — connection rekeying behaves",
            "Data at rest encrypted with 3DES is re-encrypted at migration, not decrypted on the fly forever",
            "168-bit key material handling replaced by 256-bit keys (generation + storage)",
        ],
        "references": ["sp800-131a", "fips197"],
        "snippets": {
            "java": {"before": 'Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");',
                     "after": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // 12-byte IV, 128-bit tag'},
            "python": {"before": "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC)",
                       "after": "from Crypto.Cipher import AES\ncipher = AES.new(aes_key, AES.MODE_GCM, nonce=os.urandom(12))"},
            "javascript": {"before": "const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);",
                           "after": "const cipher = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));"},
            "go": {"before": 'cipher.NewCBCEncrypter(tripleDESBlock, iv)',
                   "after": 'gcm, _ := cipher.NewGCM(aesBlock)\ngcm.Seal(dst, iv12, plaintext, nil)'},
        },
    },
    "replace-rc4": {
        "title": "Replace RC4 with ChaCha20-Poly1305 (or AES-256-GCM)",
        "effort_hours": (2, 6), "risk": "medium",
        "testing": [
            "AEAD now — authenticate associated data where the RC4 stream never did",
            "Keystream bias tests: RC4 output must no longer appear anywhere (grep + runtime assert)",
            "Interop with peers that only speak AES-GCM falls back cleanly",
        ],
        "references": ["sp800-131a", "rfc8439"],
        "snippets": {
            "java": {"before": 'Cipher cipher = Cipher.getInstance("RC4");',
                     "after": '// The JDK does not ship ChaCha20-Poly1305 before Java 11 — Java 11+:\nCipher cipher = Cipher.getInstance("ChaCha20-Poly1305");\n// on older JDKs use AES-256-GCM via the AES/GCM/NoPadding transform'},
            "python": {"before": "from Crypto.Cipher import ARC4\ncipher = ARC4.new(key)",
                       "after": "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\naead = ChaCha20Poly1305(key)\nct = aead.encrypt(nonce12, plaintext, associated_data)"},
            "javascript": {"before": "const cipher = crypto.createCipheriv('rc4', key);",
                           "after": "const aead = crypto.createCipheriv('chacha20-poly1305', key, nonce12);\nconst ct = Buffer.concat([aead.update(plain), aead.final(), aead.getAuthTag()]);"},
            "go": {"before": 'import "golang.org/x/crypto/rc4"\ncipher, _ := rc4.NewCipher(key)',
                   "after": 'import "golang.org/x/crypto/chacha20poly1305"\naead, _ := chacha20poly1305.New(key)\nct := aead.Seal(nil, nonce12, plaintext, nil)'},
        },
    },
    "replace-md5": {
        "title": "Replace MD5 with SHA-256",
        "effort_hours": (1, 3), "risk": "low",
        "testing": [
            "Digest length consumers: MD5 is 16 bytes, SHA-256 is 32 — column widths, parsers, protocol fields",
            "Checksum files/ETags regenerate; cached comparisons invalidate",
            "No security decision (password check, signature) relied on the old digests",
        ],
        "references": ["sp800-131a", "fips180"],
        "snippets": {
            "java": {"before": 'MessageDigest md = MessageDigest.getInstance("MD5");',
                     "after": 'MessageDigest md = MessageDigest.getInstance("SHA-256");'},
            "python": {"before": "import hashlib\ndigest = hashlib.md5(data).hexdigest()",
                       "after": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()"},
            "javascript": {"before": "crypto.createHash('md5').update(data).digest('hex')",
                           "after": "crypto.createHash('sha256').update(data).digest('hex')"},
            "go": {"before": 'import "crypto/md5"\nsum := md5.Sum(data)',
                   "after": 'import "crypto/sha256"\nsum := sha256.Sum256(data)'},
        },
    },
    "replace-sha1": {
        "title": "Replace SHA-1 with SHA-256",
        "effort_hours": (1, 3), "risk": "low",
        "testing": [
            "Signature/certificate paths: SHA-1 certs must be reissued, not just re-hashed",
            "Digest-size dependents (20 → 32 bytes) updated",
            "Legacy peers that demand SHA-1 are inventoried for exception, not silently kept",
        ],
        "references": ["sp800-131a", "fips180"],
        "snippets": {
            "java": {"before": 'MessageDigest md = MessageDigest.getInstance("SHA-1");',
                     "after": 'MessageDigest md = MessageDigest.getInstance("SHA-256");'},
            "python": {"before": "hashlib.sha1(data)",
                       "after": "hashlib.sha256(data)"},
            "javascript": {"before": "crypto.createHash('sha1')",
                           "after": "crypto.createHash('sha256')"},
            "go": {"before": 'import "crypto/sha1"\nsha1.Sum(data)',
                   "after": 'import "crypto/sha256"\nsha256.Sum256(data)'},
        },
    },
    "replace-sslv3": {
        "title": "Disable SSLv3 — require TLS 1.2+ (prefer 1.3)",
        "effort_hours": (2, 8), "risk": "high",
        "testing": [
            "Old clients fail fast with a clear error, not a protocol downgrade",
            "nmap/sslscan shows only TLS 1.2/1.3 enabled after the change",
            "POODLE-style downgrade attempts are refused (no fallback to SSLv3)",
        ],
        "references": ["rfc8446", "sp800-131a"],
        "snippets": {
            "java": {"before": 'SSLContext ctx = SSLContext.getInstance("SSLv3");',
                     "after": 'SSLContext ctx = SSLContext.getInstance("TLSv1.3");\n// or "TLS" with enabledProtocols=TLSv1.2,TLSv1.3'},
            "python": {"before": "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)",
                       "after": "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.minimum_version = ssl.TLSVersion.TLSv1_2"},
            "javascript": {"before": "const server = tls.createServer({ secureProtocol: 'SSLv3_method' }, handler);",
                           "after": "const server = tls.createServer({ minVersion: 'TLSv1.2' }, handler);"},
            "go": {"before": 'tls.Config{MinVersion: tls.VersionSSL30}',
                   "after": 'tls.Config{MinVersion: tls.VersionTLS12, PreferServerCipherSuites: true}'},
        },
    },
    "replace-tls10": {
        "title": "Disable TLS 1.0 — require TLS 1.2+ (prefer 1.3)",
        "effort_hours": (2, 8), "risk": "high",
        "testing": [
            "Traffic capture confirms zero TLS 1.0 handshakes after rollout",
            "BEAST/legacy-cipher suites removed with the protocol floor",
            "Partner/legacy-client inventory reviewed before enforcement",
        ],
        "references": ["rfc8446"],
        "snippets": {
            "java": {"before": 'SSLContext ctx = SSLContext.getInstance("TLSv1");',
                     "after": 'SSLContext ctx = SSLContext.getInstance("TLS");\n// enabledProtocols: TLSv1.2, TLSv1.3 only'},
            "python": {"before": "ctx.minimum_version = ssl.TLSVersion.TLSv1",
                       "after": "ctx.minimum_version = ssl.TLSVersion.TLSv1_2"},
            "javascript": {"before": "tls.createServer({ minVersion: 'TLSv1.0' })",
                           "after": "tls.createServer({ minVersion: 'TLSv1.2' })"},
            "go": {"before": 'tls.Config{MinVersion: tls.VersionTLS10}',
                   "after": 'tls.Config{MinVersion: tls.VersionTLS12}'},
        },
    },
    "replace-tls11": {
        "title": "Disable TLS 1.1 — require TLS 1.2+ (prefer 1.3)",
        "effort_hours": (2, 8), "risk": "high",
        "testing": [
            "Same suite as the TLS 1.0 removal: capture-verified, client inventory first",
        ],
        "references": ["rfc8446"],
        "snippets": {
            "java": {"before": 'SSLContext ctx = SSLContext.getInstance("TLSv1.1");',
                     "after": 'SSLContext ctx = SSLContext.getInstance("TLS"); // TLSv1.2+ only'},
            "python": {"before": "ctx.minimum_version = ssl.TLSVersion.TLSv1_1",
                       "after": "ctx.minimum_version = ssl.TLSVersion.TLSv1_2"},
            "javascript": {"before": "tls.createServer({ minVersion: 'TLSv1.1' })",
                           "after": "tls.createServer({ minVersion: 'TLSv1.2' })"},
            "go": {"before": 'tls.Config{MinVersion: tls.VersionTLS11}',
                   "after": 'tls.Config{MinVersion: tls.VersionTLS12}'},
        },
    },
    "fix-ecb-mode": {
        "title": "Replace ECB mode with an AEAD (GCM)",
        "effort_hours": (1, 4), "risk": "medium",
        "testing": [
            "Known-plaintext pattern test: identical plaintext blocks no longer produce identical ciphertext",
            "GCM IV never repeats under one key (12 bytes, fresh per message)",
            "Padding-oracle error paths removed (GCM needs no padding)",
        ],
        "references": ["fips197", "sp800-131a"],
        "snippets": {
            "java": {"before": 'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");',
                     "after": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\ncipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv12));'},
            "python": {"before": "AES.new(key, AES.MODE_ECB)",
                       "after": "AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))"},
            "javascript": {"before": "crypto.createCipheriv('aes-256-ecb', key, null)",
                           "after": "crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12))"},
            "go": {"before": "cipher.NewECBEncrypter(block)",
                   "after": "gcm, _ := cipher.NewGCM(block)\ngcm.Seal(nil, nonce12, plaintext, nil)"},
        },
    },
    "resize-aes128": {
        "title": "Resize AES-128 keys to AES-256",
        "effort_hours": (1, 3), "risk": "low",
        "testing": [
            "Key rotation path exercised end to end (old data decrypts during transition window)",
            "Key-generation and KMS policy updated to 256-bit so drift cannot reintroduce 128",
        ],
        "references": ["fips197", "nist-pqc"],
        "snippets": {
            "java": {"before": 'KeyGenerator kg = KeyGenerator.getInstance("AES");\nkg.init(128);',
                     "after": 'KeyGenerator kg = KeyGenerator.getInstance("AES");\nkg.init(256);'},
            "python": {"before": "key = os.urandom(16)",
                       "after": "key = os.urandom(32)  # 256-bit"},
            "javascript": {"before": "crypto.generateKeySync('aes', { length: 128 })",
                           "after": "crypto.generateKeySync('aes', { length: 256 })"},
            "go": {"before": "aes.NewCipher(key128)",
                   "after": "aes.NewCipher(key32) // 32 bytes = AES-256"},
        },
    },
    "remove-hardcoded-key": {
        "title": "Remove hardcoded key material — externalize to a KMS/secret manager",
        "effort_hours": (4, 16), "risk": "high",
        "testing": [
            "Secrets scan (this product's own scan) returns zero hardcoded-key findings on the branch",
            "Old key material rotates: the hardcoded value must not remain valid anywhere",
            "Service starts with the secret injected, fails closed without it",
        ],
        "references": ["owasp-storage"],
        "guide": "kms-migration",
        "snippets": {
            "java": {"before": 'byte[] key = "s3cr3t-key-material".getBytes();',
                     "after": '// Fetch at startup from your KMS/secret manager (AWS KMS, Vault, ...):\nbyte[] key = kmsClient.retrieveKey("service/aes-key"); // your client, your call'},
            "python": {"before": 'KEY = b"hardcoded-key-bytes"',
                       "after": 'import os\nKEY = os.environ["AES_KEY_B64"]  # injected by the secret manager, never committed'},
            "javascript": {"before": 'const KEY = Buffer.from("hardcoded-key", "utf8");',
                           "after": '// read from your secret manager at boot; fail closed if absent\nconst KEY = await secrets.get("service/aes-key");'},
            "go": {"before": 'var key = []byte("hardcoded-key")',
                   "after": '// fetch from KMS/secret manager at startup; env fallback is local-dev only\nkey, err := kms.FetchKey(ctx, "service/aes-key")'},
        },
    },
    "plan-rsa-pqc": {
        "title": "Plan RSA → PQC hybrid migration (ML-KEM / ML-DSA)",
        "effort_hours": (40, 120), "risk": "high",
        "testing": [
            "Hybrid handshake interop: classical-only peers still complete while hybrid peers prefer ML-KEM",
            "Certificate/policy tooling accepts the hybrid certificate chains",
            "Performance budget: ML-KEM encapsulation fits the handshake latency SLO",
        ],
        "references": ["fips203", "fips204", "nist-pqc"],
        "guide": "pqc-hybrid",
        "snippets": {
            "java": {"before": 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
                     "after": "// No JDK ML-KEM yet — checklist: inventory RSA call sites,\n// adopt a FIPS-203 library, run hybrid (RSA+ML-KEM) handshakes, then retire RSA."},
            "python": {"before": "from cryptography.hazmat.primitives.asymmetric import rsa",
                       "after": "# Checklist: inventory rsa.generate_private_key call sites; pick a FIPS-203\n# ML-KEM library; negotiate hybrid key exchange; migrate certificates."},
            "javascript": {"before": "crypto.generateKeyPairSync('rsa')",
                           "after": "// Checklist: inventory RSA generation; choose a FIPS-203 library;\n// enable hybrid key exchange where the protocol allows it."},
            "go": {"before": 'rsa.GenerateKey(rand.Reader, 2048)',
                   "after": "// Checklist: inventory rsa.GenerateKey call sites; adopt a FIPS-203\n// ML-KEM package; run hybrid handshakes; rotate certificates."},
        },
    },
    "plan-dsa-pqc": {
        "title": "Plan DSA retirement → ML-DSA",
        "effort_hours": (40, 120), "risk": "high",
        "testing": [
            "Signature verification accepts the new scheme; DSA verification is behind a kill switch",
            "Long-lived signatures (documents, logs) have a re-signing plan before DSA removal",
        ],
        "references": ["fips204", "nist-pqc"],
        "guide": "pqc-hybrid",
        "snippets": {
            "java": {"before": 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");',
                     "after": "// Interim: ECDSA P-256. Target: ML-DSA-65 via a FIPS-204 library."},
            "python": {"before": "from cryptography.hazmat.primitives.asymmetric import dsa",
                       "after": "# Interim: ec.generate_private_key(ec.SECP256R1()). Target: ML-DSA."},
            "javascript": {"before": "crypto.generateKeyPairSync('dsa')",
                           "after": "// Interim: ECDSA P-256. Target: ML-DSA via a FIPS-204 library."},
            "go": {"before": 'dsa.GenerateKey(rand.Reader, dsa.L2048N256)',
                   "after": "// Interim: ecdsa P-256. Target: ML-DSA via a FIPS-204 package."},
        },
    },
    "plan-ecc-pqc": {
        "title": "Plan ECC → PQC hybrid migration",
        "effort_hours": (40, 120), "risk": "high",
        "testing": [
            "Hybrid (X25519+ML-KEM) handshake agrees with both classical and hybrid peers",
            "ECDH/ECDSA call sites inventoried with owners and cutover order",
        ],
        "references": ["fips203", "nist-pqc"],
        "guide": "pqc-hybrid",
        "snippets": {
            "java": {"before": 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");',
                     "after": "// Target: hybrid ECDH+ML-KEM via a FIPS-203 library; keep classical\n// fallback during the transition window."},
            "python": {"before": "from cryptography.hazmat.primitives.asymmetric import ec",
                       "after": "# Target: hybrid ECDH+ML-KEM (FIPS-203 library); classical fallback kept."},
            "javascript": {"before": "crypto.generateKeyPairSync('ec')",
                           "after": "// Target: hybrid key agreement with a FIPS-203 library."},
            "go": {"before": 'ecdh.P256().GenerateKey(rand.Reader)',
                   "after": "// Target: hybrid ECDH+ML-KEM; keep P-256 fallback during migration."},
        },
    },
    "plan-dh-pqc": {
        "title": "Plan finite-field DH → ML-KEM",
        "effort_hours": (40, 120), "risk": "high",
        "testing": [
            "Group negotiation: DH groups removed only after every peer speaks ML-KEM hybrid",
        ],
        "references": ["fips203", "nist-pqc"],
        "guide": "pqc-hybrid",
        "snippets": {
            "java": {"before": 'KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");',
                     "after": "// Target: ML-KEM-768 hybrid key agreement (FIPS-203 library)."},
            "python": {"before": "from cryptography.hazmat.primitives.asymmetric import dh",
                       "after": "# Target: ML-KEM-768 hybrid key agreement (FIPS-203 library)."},
            "javascript": {"before": "crypto.createDiffieHellman(prime, generator)",
                           "after": "// Target: ML-KEM-768 hybrid via a FIPS-203 library."},
            "go": {"before": 'crypto/dh — via ecdh or external groups',
                   "after": "// Target: ML-KEM-768 hybrid via a FIPS-203 package."},
        },
    },
}

_GUIDES: dict[str, dict[str, Any]] = {
    "kms-migration": {
        "title": "Move hardcoded keys to a KMS / secret manager (5 steps)",
        "steps": [
            {"title": "Inventory", "detail": "List every hardcoded key site (the scan's findings) and what each key protects — data, sessions, signatures."},
            {"title": "Provision", "detail": "Create the managed key/secret in your KMS with a rotation policy; grant the service's identity least-privilege access."},
            {"title": "Fetch at boot", "detail": "Replace literals with a startup fetch (fail closed when absent); never log the retrieved material."},
            {"title": "Migrate data", "detail": "Re-encrypt or re-sign existing data under the managed key during a transition window; keep the old key decrypt-only."},
            {"title": "Rotate and remove", "detail": "Rotate the old key material so the hardcoded value is dead, delete it from history where feasible (secret rotation, not just deletion), and re-scan to confirm zero findings."},
        ],
    },
    "pqc-hybrid": {
        "title": "PQC hybrid migration (5 steps)",
        "steps": [
            {"title": "Inventory", "detail": "Map every RSA/ECC/DH call site to its protocol role (key exchange, signature) and owning team — the migration dashboard tracks this."},
            {"title": "Choose parameters", "detail": "Pick FIPS 203 ML-KEM-768 (key exchange) and FIPS 204 ML-DSA-65 (signatures) unless a profile dictates otherwise; document the choice."},
            {"title": "Hybrid first", "detail": "Deploy hybrid classical+PQC handshakes so classical-only peers keep working; never a hard cutover."},
            {"title": "Certificates and policy", "detail": "Issue hybrid certificates, update trust stores and policy packs (CNSA 2.0 timeline awareness) to accept the new schemes."},
            {"title": "Retire classical", "detail": "After telemetry shows ~100% hybrid completion, remove classical-only paths and mark the migration tasks done."},
        ],
    },
    "tls-upgrade": {
        "title": "TLS floor upgrade (4 steps)",
        "steps": [
            {"title": "Measure", "detail": "Capture real client versions for 1–2 weeks; list every client below TLS 1.2."},
            {"title": "Fix the stragglers", "detail": "Upgrade or replace sub-1.2 clients before enforcement — enforcement first breaks partners."},
            {"title": "Enforce", "detail": "Raise the minimum version (TLS 1.2 floor, prefer 1.3) in server config, load balancers, and client libraries."},
            {"title": "Verify", "detail": "External scan confirms only TLS 1.2/1.3; alert on downgrade attempts."},
        ],
    },
}

# verification strings are kept beside the guides they belong to, keyed by step order
_GUIDE_VERIFICATION = {'kms-migration': ['Scan export lists every key site with an owner; nothing unaccounted.', 'Key exists in the KMS with a rotation policy; the service identity can read it, nothing else.', 'Service refuses to start without the secret; logs contain no key material.', 'Old ciphertexts still decrypt; new writes use the managed key.', 'A fresh scan reports zero hardcoded-key findings; the old value fails a decrypt test.'], 'pqc-hybrid': ['Migration dashboard shows every call site mapped to a task.', 'Parameter choice documented and reviewed against your policy pack.', 'Hybrid handshake passes interop tests with a classical-only peer.', 'Hybrid certificates validate in staging trust stores.', 'Telemetry shows ~100% hybrid; classical-only code paths deleted.'], 'tls-upgrade': ['Client-version report exists and is shared with partner teams.', 'No production client remains below TLS 1.2.', 'Config diff shows min TLS 1.2 everywhere (servers, LBs, clients).', 'External scan reports only TLS 1.2/1.3; downgrade alerts fire in test.']}
_GUIDE_REFERENCES = {'kms-migration': ['owasp-storage', 'sp800-131a'], 'pqc-hybrid': ['fips203', 'fips204'], 'tls-upgrade': ['rfc8446', 'sp800-131a']}


def languages() -> list[str]:
    return list(_LANGUAGES)


def template_ids() -> list[str]:
    return sorted(_TEMPLATES)


def snippet_count() -> int:
    return sum(len(t["snippets"]) for t in _TEMPLATES.values())


def guide(name: str) -> dict[str, Any] | None:
    """A multi-step guide with per-step verification and references (None if unknown)."""
    spec = _GUIDES.get(name)
    if spec is None:
        return None
    verifications = _GUIDE_VERIFICATION.get(name, [])
    steps = [
        {
            "order": i,
            "title": step["title"],
            "detail": step["detail"],
            "verification": verifications[i - 1] if i - 1 < len(verifications) else "Confirm the step is complete before moving on.",
        }
        for i, step in enumerate(spec["steps"], start=1)
    ]
    refs = [REFERENCES[k] for k in _GUIDE_REFERENCES.get(name, []) if k in REFERENCES]
    return {"name": name, "title": spec["title"], "steps": steps, "references": refs}


def template_catalog() -> list[dict[str, Any]]:
    return [
        {
            "rule": rule_id,
            "title": spec["title"],
            "languages": sorted(spec["snippets"]),
            "effort_hours": list(spec["effort_hours"]),
            "risk": spec["risk"],
            "guide": spec.get("guide"),
        }
        for rule_id, spec in sorted(_TEMPLATES.items())
    ]


def _references(rule_id: str) -> list[dict[str, str]]:
    return [REFERENCES[key] for key in _TEMPLATES[rule_id]["references"] if key in REFERENCES]


def render(rule_id: str, language: str = "python") -> dict[str, Any] | None:
    """Full rendered template for a rule in one language (None if unknown)."""
    spec = _TEMPLATES.get(rule_id)
    if spec is None:
        return None
    language = (language or "").lower()
    snippet = spec["snippets"].get(language)
    if snippet is None:  # fall back honestly, and say so
        snippet = spec["snippets"]["python"]
        fallback = True
    else:
        fallback = False
    rendered = {
        "rule": rule_id,
        "title": spec["title"],
        "language": language,
        "requested_language_unavailable": fallback,
        "before": snippet["before"],
        "after": snippet["after"],
        "notes": snippet.get("notes"),
        "testing": list(spec["testing"]),
        "references": _references(rule_id),
        "effort_hours": list(spec["effort_hours"]),
        "risk": spec["risk"],
    }
    if spec.get("guide"):
        rendered["guide"] = _GUIDES[spec["guide"]]
    return rendered


def fix_branch_payload(suggestion: dict[str, Any], language: str = "python") -> dict[str, Any]:
    """Everything a developer (or CI script) needs to cut a fix branch.

    CryptoScan does not push to your repository — this payload is applied
    by you: run the printed commands, apply the change, open the PR.
    """
    rule_id = str(suggestion.get("rule") or "manual-review")
    rendered = render(rule_id, language)
    path = str(suggestion.get("file_path") or "unknown")
    line = suggestion.get("line_number") or 0
    algo = suggestion.get("algorithm") or "crypto"
    slug = f"cryptoscan/{rule_id}/{path}".replace("/", "-").lower()[:80]
    commit = f"cryptoscan: {rule_id} — replace {algo} in {path}"[:200]
    pr_body = [
        f"Automated suggestion for **{algo}** at `{path}:{line}`.",
        "",
        f"- Rule: `{rule_id}` ({suggestion.get('category', 'unknown')}, priority {suggestion.get('priority', '?')})",
        f"- Replace with: **{suggestion.get('replace_with', 'review')}**",
    ]
    if rendered:
        pr_body += ["", "```", "before:", rendered["before"], "", "after:", rendered["after"], "```"]
        if rendered["testing"]:
            pr_body += ["", "Test after the change:"] + [f"- {item}" for item in rendered["testing"]]
    pr_body += ["", "_Advisory payload — CryptoScan never pushes branches or opens PRs automatically._",
                 "_Deterministic suggestion from CryptoScan — policy results come only from the policy engine._"]
    return {
        "branch": f"fix/{slug}",
        "commit_message": commit,
        "changes": [
            {
                "file_path": path,
                "line_number": line,
                "before": rendered["before"] if rendered else None,
                "after": rendered["after"] if rendered else None,
            }
        ],
        "pr_title": commit,
        "pr_body": "\n".join(pr_body),
        "commands": [
            f"git checkout -b fix/{slug}",
            f"# apply the change in {path}:{line}",
            "git commit -am " + repr(commit),
            "git push -u origin HEAD",
        ],
        "note": "CryptoScan generates this payload; applying it is a human/CI action, never an automatic push.",
    }
